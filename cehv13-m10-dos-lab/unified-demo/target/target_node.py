"""
Unified Target Node (runs inside isolated Docker container `doslab_u_target`).
Runs:
  1. Backend Web Server on 127.0.0.1:8081 (bounded 30-worker pool)
  2. Edge Reverse Proxy on 0.0.0.0:80 (reads /shared/l7_policy.json live)
  3. L4 Kernel & iptables Shield Guardian (reads /shared/l4_policy.json & /proc/net/tcp)
  4. Telemetry writer -> /shared/metrics.json every 0.4s
"""

import asyncio
import json
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

SHARED_DIR = Path("/shared")
POLICY_L7_FILE = SHARED_DIR / "l7_policy.json"
POLICY_L4_FILE = SHARED_DIR / "l4_policy.json"
METRICS_FILE = SHARED_DIR / "metrics.json"
FORENSICS_FILE = SHARED_DIR / "forensics.jsonl"

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8081
PROXY_PORT = 80

MAX_WORKERS = 30
MAX_PENDING_QUEUE = 10
BACKEND_SOCKET_TIMEOUT = 45.0
DB_SIM_DELAY = 0.08

HEADER_TIMEOUT_SEC = 2.5
MAX_CONN_PER_IP = 8
RATE_WINDOW_SEC = 2.0
RATE_LIMIT_MAX_REQ = 15
VIOLATION_BAN_THRESHOLD = 22
BAN_DURATION_SEC = 15.0

stats_lock = threading.Lock()
active_workers = 0
queued_conns = 0
total_backend_requests = 0


def build_http_response(status: str, body: str, content_type: str = "text/plain") -> bytes:
    raw = body.encode("utf-8")
    hdr = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}; charset=utf-8\r\n"
        f"Content-Length: {len(raw)}\r\n"
        f"Connection: close\r\n"
        f"Cache-Control: no-store\r\n\r\n"
    )
    return hdr.encode("ascii") + raw


def handle_backend_conn(conn: socket.socket):
    global active_workers, queued_conns, total_backend_requests
    with stats_lock:
        queued_conns -= 1
        active_workers += 1
    try:
        conn.settimeout(BACKEND_SOCKET_TIMEOUT)
        buf = bytearray()
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = conn.recv(1024)
            if not chunk:
                return
            buf.extend(chunk)
            if len(buf) > 65536:
                conn.sendall(build_http_response("400 Bad Request", "Header too large"))
                return

        with stats_lock:
            total_backend_requests += 1
            cur_w = active_workers

        req_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        path = req_line.split(" ")[1] if len(req_line.split(" ")) >= 2 else "/"
        if path.startswith("/api/search"):
            time.sleep(DB_SIM_DELAY)
        payload = json.dumps({
            "status": "ok",
            "service": "NovaCloud-UnifiedTarget",
            "active_workers": cur_w,
            "max_workers": MAX_WORKERS,
            "ts": round(time.time(), 3),
        })
        conn.sendall(build_http_response("200 OK", payload, "application/json"))
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        with stats_lock:
            active_workers -= 1


def run_backend_server():
    global queued_conns
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BACKEND_HOST, BACKEND_PORT))
    srv.listen(256)
    print(f"[TARGET BACKEND] Listening on {BACKEND_HOST}:{BACKEND_PORT} (workers={MAX_WORKERS})")
    while True:
        conn, _ = srv.accept()
        with stats_lock:
            if queued_conns >= MAX_PENDING_QUEUE:
                reject = True
            else:
                queued_conns += 1
                reject = False
        if reject:
            try:
                conn.settimeout(0.5)
                conn.sendall(build_http_response("503 Service Unavailable", '{"error":"Backend worker pool saturated"}', "application/json"))
            except OSError:
                pass
            finally:
                conn.close()
            continue
        pool.submit(handle_backend_conn, conn)


def hex_ip_to_str(hex_ip: str) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        return f"{raw[3]}.{raw[2]}.{raw[1]}.{raw[0]}"
    except Exception:
        return "unknown"


def read_kernel_syn_info():
    """Reads /proc/net/tcp for port 80 (0050) SYN_RECV (03) count & per-source-IP breakdown."""
    syn_recv = 0
    established = 0
    syn_by_ip: Dict[str, int] = defaultdict(int)
    try:
        with open("/proc/net/tcp", "r", encoding="ascii") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_addr = parts[1]
                rem_addr = parts[2]
                st = parts[3]
                if local_addr.endswith(":0050"):
                    if st == "03":
                        syn_recv += 1
                        rem_ip = hex_ip_to_str(rem_addr.split(":")[0])
                        syn_by_ip[rem_ip] += 1
                    elif st == "01":
                        established += 1
    except OSError:
        pass

    syncookies = 0
    try:
        with open("/proc/sys/net/ipv4/tcp_syncookies", "r", encoding="ascii") as f:
            syncookies = int(f.read().strip())
    except OSError:
        pass
    return syn_recv, established, syncookies, syn_by_ip


def read_rx_bytes() -> int:
    try:
        with open("/sys/class/net/eth0/statistics/rx_bytes", "r", encoding="ascii") as f:
            return int(f.read().strip())
    except OSError:
        return 0


def run_sh(cmd: str) -> str:
    p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    return p.stdout.strip()


def ensure_l4_chain():
    run_sh(
        "iptables -N L4_SHIELD 2>/dev/null || true; "
        "iptables -C INPUT -p tcp --dport 80 --syn -j L4_SHIELD 2>/dev/null || "
        "iptables -I INPUT 1 -p tcp --dport 80 --syn -j L4_SHIELD"
    )


def flush_l4_chain():
    run_sh("iptables -F L4_SHIELD 2>/dev/null || true")


def block_syn_flooder_ip(ip: str):
    ensure_l4_chain()
    run_sh(
        f"iptables -A L4_SHIELD -s {ip} -m limit --limit 2/sec --limit-burst 4 -j ACCEPT && "
        f"iptables -A L4_SHIELD -s {ip} -j DROP"
    )


def read_l4_dropped_packets() -> int:
    out = run_sh("iptables -L L4_SHIELD -v -n -x 2>/dev/null || true")
    total = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "DROP" and parts[0].isdigit():
            total += int(parts[0])
    return total


@dataclass
class ConnRec:
    conn_id: int
    ip: str
    created_at: float
    task: asyncio.Task
    client_writer: asyncio.StreamWriter
    backend_writer: Optional[asyncio.StreamWriter] = None
    header_complete: bool = False


class UnifiedState:
    def __init__(self):
        SHARED_DIR.mkdir(parents=True, exist_ok=True)
        self.header_timeout = False
        self.conn_limit = False
        self.rate_limit = False

        self.l4_enabled = False
        self.l4_blocked_ips = set()
        self.l4_idle_since = 0.0
        self.l4_dropped_accum = 0
        self.l4_last_chain_drop = 0

        self.next_conn_id = 1
        self.active_records: Dict[int, ConnRec] = {}
        self.active_by_ip: Dict[str, int] = defaultdict(int)
        self.req_ts: Dict[str, deque] = defaultdict(deque)
        self.violations: Dict[str, deque] = defaultdict(deque)
        self.banned_until: Dict[str, float] = {}

        self.total_allowed = 0
        self.total_blocked = 0
        self.cur_sec = int(time.time())
        self.cur_allowed = 0
        self.cur_blocked = 0
        self.last_allowed = 0
        self.last_blocked = 0

        self.forensics = deque(maxlen=35)
        self.last_log_sec: Dict[str, int] = {}
        self.last_rx_bytes = read_rx_bytes()
        self.last_rx_ts = time.time()
        self.rx_kbps = 0.0

        ensure_l4_chain()
        flush_l4_chain()

    def roll_sec(self):
        now_sec = int(time.time())
        if now_sec > self.cur_sec:
            self.last_allowed = self.cur_allowed
            self.last_blocked = self.cur_blocked
            self.cur_allowed = 0
            self.cur_blocked = 0
            self.cur_sec = now_sec

    def log_event(self, ev_type: str, ip: str, detail: str):
        now = time.time()
        sec = int(now)
        key = f"{ev_type}:{ip}"
        if self.last_log_sec.get(key) == sec:
            return
        self.last_log_sec[key] = sec
        entry = {
            "ts": round(now, 2),
            "time": time.strftime("%H:%M:%S", time.localtime(now)),
            "type": ev_type,
            "ip": ip,
            "detail": detail,
        }
        self.forensics.appendleft(entry)
        try:
            with FORENSICS_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rec: Optional[ConnRec] = None):
    try:
        buf = bytearray()
        while True:
            data = await reader.read(8192)
            if not data:
                break
            if rec is not None and not rec.header_complete:
                buf.extend(data)
                if b"\r\n\r\n" in buf or b"\n\n" in buf:
                    rec.header_complete = True
                    buf.clear()
                elif len(buf) > 65536:
                    buf.clear()
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
        pass


def check_rate(state: UnifiedState, ip: str) -> bool:
    now = time.time()
    q = state.req_ts[ip]
    q.append(now)
    cut = now - RATE_WINDOW_SEC
    while q and q[0] < cut:
        q.popleft()
    if len(q) > RATE_LIMIT_MAX_REQ:
        vq = state.violations[ip]
        vq.append(now)
        while vq and vq[0] < now - 5.0:
            vq.popleft()
        if len(vq) >= VIOLATION_BAN_THRESHOLD:
            state.banned_until[ip] = now + BAN_DURATION_SEC
            state.log_event("L7_AUTO_BAN", ip, f"Tạm cách ly {int(BAN_DURATION_SEC)}s do vượt ngưỡng")
        else:
            state.log_event("L7_RATE_LIMIT", ip, f"Chặn 429 ({len(q)} req/{RATE_WINDOW_SEC}s)")
        return True
    return False


def prune_stalled(state: UnifiedState):
    now = time.time()
    seen: Dict[str, int] = defaultdict(int)
    killed = 0
    for rec in list(state.active_records.values()):
        kill = False
        if state.header_timeout and not rec.header_complete and (now - rec.created_at) >= 1.2:
            kill = True
        if state.conn_limit:
            seen[rec.ip] += 1
            if seen[rec.ip] > MAX_CONN_PER_IP:
                kill = True
        if kill:
            killed += 1
            if rec.backend_writer is not None:
                try:
                    rec.backend_writer.close()
                except OSError:
                    pass
            try:
                rec.client_writer.close()
            except OSError:
                pass
            rec.task.cancel()
    if killed:
        state.log_event("L7_SHIELD_FLUSH", "system", f"Ngắt ngay {killed} socket Slowloris đang giữ kết nối")


async def handle_proxy_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, state: UnifiedState):
    state.roll_sec()
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    now = time.time()

    if state.rate_limit and now < state.banned_until.get(ip, 0.0):
        state.cur_blocked += 1
        state.total_blocked += 1
        try:
            writer.write(build_http_response("403 Forbidden", '{"error":"IP quarantined by L7 Shield"}', "application/json"))
            await writer.drain()
        except OSError:
            pass
        writer.close()
        return

    if state.conn_limit and state.active_by_ip[ip] >= MAX_CONN_PER_IP:
        state.cur_blocked += 1
        state.total_blocked += 1
        state.log_event("L7_CONN_LIMIT", ip, f"Chặn 503 (vượt {MAX_CONN_PER_IP} socket/IP)")
        try:
            writer.write(build_http_response("503 Service Unavailable", '{"error":"Max connections per IP exceeded"}', "application/json"))
            await writer.drain()
        except OSError:
            pass
        writer.close()
        return

    cid = state.next_conn_id
    state.next_conn_id += 1
    rec = ConnRec(cid, ip, now, asyncio.current_task(), writer)
    state.active_records[cid] = rec
    state.active_by_ip[ip] += 1
    b_writer = None

    try:
        if state.header_timeout:
            buf = bytearray()
            deadline = time.monotonic() + HEADER_TIMEOUT_SEC
            try:
                while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        raise asyncio.TimeoutError
                    chunk = await asyncio.wait_for(reader.read(2048), timeout=rem)
                    if not chunk:
                        return
                    buf.extend(chunk)
                rec.header_complete = True
            except asyncio.TimeoutError:
                state.roll_sec()
                state.cur_blocked += 1
                state.total_blocked += 1
                state.log_event("L7_SLOWLORIS_DROP", ip, f"Cắt socket giữ header quá {HEADER_TIMEOUT_SEC}s (408)")
                try:
                    writer.write(build_http_response("408 Request Timeout", '{"error":"Slowloris header timeout"}', "application/json"))
                    await writer.drain()
                except OSError:
                    pass
                return

            if state.rate_limit and check_rate(state, ip):
                state.roll_sec()
                state.cur_blocked += 1
                state.total_blocked += 1
                try:
                    writer.write(build_http_response("429 Too Many Requests", '{"error":"Rate limit exceeded"}', "application/json"))
                    await writer.drain()
                except OSError:
                    pass
                return

            b_reader, b_writer = await asyncio.wait_for(asyncio.open_connection(BACKEND_HOST, BACKEND_PORT), timeout=3.0)
            rec.backend_writer = b_writer
            b_writer.write(buf)
            await b_writer.drain()
            state.roll_sec()
            state.cur_allowed += 1
            state.total_allowed += 1
            await asyncio.gather(pipe(reader, b_writer), pipe(b_reader, writer))
            return

        if state.rate_limit and check_rate(state, ip):
            state.roll_sec()
            state.cur_blocked += 1
            state.total_blocked += 1
            try:
                writer.write(build_http_response("429 Too Many Requests", '{"error":"Rate limit exceeded"}', "application/json"))
                await writer.drain()
            except OSError:
                pass
            return

        b_reader, b_writer = await asyncio.wait_for(asyncio.open_connection(BACKEND_HOST, BACKEND_PORT), timeout=3.0)
        rec.backend_writer = b_writer
        state.roll_sec()
        state.cur_allowed += 1
        state.total_allowed += 1
        await asyncio.gather(pipe(reader, b_writer, rec=rec), pipe(b_reader, writer))
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        try:
            writer.write(build_http_response("503 Service Unavailable", '{"error":"Backend unavailable"}', "application/json"))
            await writer.drain()
        except OSError:
            pass
    except asyncio.CancelledError:
        pass
    finally:
        state.active_records.pop(cid, None)
        state.active_by_ip[ip] = max(0, state.active_by_ip[ip] - 1)
        if b_writer is not None:
            try:
                b_writer.close()
            except OSError:
                pass
        try:
            writer.close()
        except OSError:
            pass


async def sync_shared_loop(state: UnifiedState):
    while True:
        state.roll_sec()
        # 1. Read L7 policy
        try:
            if POLICY_L7_FILE.exists():
                p = json.loads(POLICY_L7_FILE.read_text(encoding="utf-8"))
                if p.get("reset"):
                    state.banned_until.clear()
                    state.violations.clear()
                    state.req_ts.clear()
                    state.total_allowed = 0
                    state.total_blocked = 0
                    state.l4_dropped_accum = 0
                    state.l4_last_chain_drop = 0
                    state.l4_blocked_ips.clear()
                    flush_l4_chain()
                    state.forensics.clear()
                    p["reset"] = False
                    POLICY_L7_FILE.write_text(json.dumps(p), encoding="utf-8")
                    state.log_event("ADMIN_RESET", "admin", "Đã reset số liệu và gỡ toàn bộ rule chặn")

                new_ht = bool(p.get("header_timeout", False))
                new_cl = bool(p.get("conn_limit", False))
                new_rl = bool(p.get("rate_limit", False))
                turned_on = (not state.header_timeout and new_ht) or (not state.conn_limit and new_cl)
                if (new_ht != state.header_timeout) or (new_cl != state.conn_limit) or (new_rl != state.rate_limit):
                    state.header_timeout = new_ht
                    state.conn_limit = new_cl
                    state.rate_limit = new_rl
                    state.log_event("L7_POLICY", "admin", f"L7 Shield -> {'ON (HeaderTimeout=2.5s, ConnLimit=8)' if (new_ht or new_cl) else 'OFF'}")
                if turned_on:
                    prune_stalled(state)
        except Exception:
            pass

        # 2. Read L4 policy
        try:
            if POLICY_L4_FILE.exists():
                p4 = json.loads(POLICY_L4_FILE.read_text(encoding="utf-8"))
                new_l4 = bool(p4.get("enabled", False))
                if new_l4 != state.l4_enabled:
                    state.l4_enabled = new_l4
                    run_sh(f"sysctl -w net.ipv4.tcp_syncookies={'1' if new_l4 else '0'} >/dev/null")
                    if not new_l4:
                        state.l4_dropped_accum += read_l4_dropped_packets()
                        state.l4_last_chain_drop = 0
                        state.l4_blocked_ips.clear()
                        flush_l4_chain()
                    state.log_event("L4_POLICY", "admin", f"L4 Defense (SYN Cookies + Firewall) -> {'ON' if new_l4 else 'OFF'}")
        except Exception:
            pass

        syn_recv, established, syncookies, syn_by_ip = read_kernel_syn_info()
        now = time.time()

        # 3. Active L4 IPS Guardian: when L4 defense is ON, drop SYN flooders via iptables
        if state.l4_enabled:
            for src_ip, cnt in syn_by_ip.items():
                if src_ip != "unknown" and cnt >= 8 and src_ip not in state.l4_blocked_ips:
                    block_syn_flooder_ip(src_ip)
                    state.l4_blocked_ips.add(src_ip)
                    state.log_event("L4_FIREWALL_DROP", src_ip, f"Phát hiện {cnt} SYN-RECV → chặn iptables (>2 SYN/s)")
            cur_chain_drop = read_l4_dropped_packets()
            state.l4_last_chain_drop = cur_chain_drop
            # Auto-release temporary iptables rule when flood stops cleanly so next L7 test isn't delayed
            if state.l4_blocked_ips:
                if syn_recv <= 2:
                    if state.l4_idle_since == 0.0:
                        state.l4_idle_since = now
                    elif (now - state.l4_idle_since) >= 4.0:
                        state.l4_dropped_accum += cur_chain_drop
                        state.l4_last_chain_drop = 0
                        state.l4_blocked_ips.clear()
                        state.l4_idle_since = 0.0
                        flush_l4_chain()
                        state.log_event("L4_AUTO_RELEASE", "system", "Luồng SYN Flood đã ngừng → giải phóng rule tạm")
                else:
                    state.l4_idle_since = 0.0
        else:
            state.l4_idle_since = 0.0

        rx_now = read_rx_bytes()
        dt = max(0.1, now - state.last_rx_ts)
        state.rx_kbps = round(((rx_now - state.last_rx_bytes) / 1024.0) / dt, 1)
        state.last_rx_bytes = rx_now
        state.last_rx_ts = now

        with stats_lock:
            cur_w = active_workers
            cur_q = max(0, queued_conns)

        payload = {
            "ts": round(now, 2),
            "l4_syn_recv": syn_recv,
            "l4_established": established,
            "l4_syncookies": syncookies,
            "l4_enabled": state.l4_enabled,
            "l4_blocked_ips": sorted(state.l4_blocked_ips),
            "l4_packets_dropped": state.l4_dropped_accum + state.l4_last_chain_drop,
            "l7_active_workers": cur_w,
            "l7_max_workers": MAX_WORKERS,
            "l7_queued": cur_q,
            "l7_open_sockets": len(state.active_records),
            "l7_shield": {
                "header_timeout": state.header_timeout,
                "conn_limit": state.conn_limit,
                "rate_limit": state.rate_limit,
            },
            "rps_allowed": state.last_allowed,
            "rps_blocked": state.last_blocked,
            "total_allowed": state.total_allowed,
            "total_blocked": state.total_blocked,
            "rx_kbps": state.rx_kbps,
            "ips": [
                {"ip": ip, "conns": c, "banned": now < state.banned_until.get(ip, 0.0)}
                for ip, c in sorted(state.active_by_ip.items())
                if c > 0 or now < state.banned_until.get(ip, 0.0)
            ],
            "forensics": list(state.forensics),
        }
        tmp = SHARED_DIR / "metrics.tmp"
        try:
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(METRICS_FILE)
        except OSError:
            pass

        await asyncio.sleep(0.4)


async def main_async():
    state = UnifiedState()
    srv = await asyncio.start_server(lambda r, w: handle_proxy_conn(r, w, state), "0.0.0.0", PROXY_PORT, backlog=128)
    print(f"[TARGET EDGE PROXY] Listening on 0.0.0.0:{PROXY_PORT} -> {BACKEND_HOST}:{BACKEND_PORT}")
    sync_task = asyncio.create_task(sync_shared_loop(state))
    try:
        await srv.serve_forever()
    finally:
        sync_task.cancel()


if __name__ == "__main__":
    t_backend = threading.Thread(target=run_backend_server, daemon=True)
    t_backend.start()
    asyncio.run(main_async())
