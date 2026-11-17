"""
Multi-Window Presentation UI Server for CEHv13 Module 10 Demo.
Serves 3 clean, dedicated role interfaces simultaneously:
  - http://127.0.0.1:9001  -> Attacker Console
  - http://127.0.0.1:9002  -> Server & Defense Console (L4 + L7 + Wireshark trigger)
  - http://127.0.0.1:9003  -> Legitimate Client View
  - http://127.0.0.1:9000  -> Quick Launcher (or /attacker, /server, /client)
"""

import argparse
import http.server
import json
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SHARED_DIR = BASE_DIR / "shared"
METRICS_FILE = SHARED_DIR / "metrics.json"
PROBE_FILE = SHARED_DIR / "probe.json"
POLICY_L7_FILE = SHARED_DIR / "l7_policy.json"
POLICY_L4_FILE = SHARED_DIR / "l4_policy.json"
WIRESHARK_EXE = r"D:\Cai dat ung dung\WireShark\Wireshark.exe"

state_lock = threading.Lock()
log_lock = threading.Lock()
attack_state = {
    "syn_flood": False,
    "slowloris": False,
}
log_seq = 0
attacker_logs = deque(maxlen=60)
server_logs = deque(maxlen=60)
client_logs = deque(maxlen=60)
seen_forensics = set()
last_logged_l4_drop = 0
last_atk_heartbeat = 0.0
last_srv_heartbeat = 0.0
history_60s = deque(maxlen=60)
probe_history_20 = deque(maxlen=20)
last_hist_sec = 0
last_probe_ts = 0.0
container_ips = {"target": "", "attacker": "", "client": ""}
last_ip_check = 0.0


def push_log(queue: deque, cls: str, text: str, custom_time: str = ""):
    global log_seq
    with log_lock:
        log_seq += 1
        queue.append({
            "id": log_seq,
            "time": custom_time or time.strftime("%H:%M:%S"),
            "cls": cls,
            "text": text,
        })


def snapshot_logs(queue: deque) -> list:
    with log_lock:
        return list(queue)


def run_docker(args_list):
    p = subprocess.run(["docker"] + args_list, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_json_atomic(path: Path, obj: dict):
    SHARED_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj), encoding="utf-8")
    tmp.replace(path)


def read_json_safe(path: Path, default: dict) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def set_syn_flood(enable: bool):
    with state_lock:
        was = attack_state["syn_flood"]
        if enable:
            run_docker(["exec", "doslab_u_attacker", "pkill", "-x", "hping3"])
            run_docker([
                "exec", "doslab_u_attacker", "sh", "-c",
                "iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
            ])
            run_docker(["exec", "-d", "doslab_u_attacker", "hping3", "-S", "-p", "80", "--flood", "target"])
            attack_state["syn_flood"] = True
            push_log(attacker_logs, "cmd", "$ iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
            push_log(attacker_logs, "cmd", "$ hping3 -S -p 80 --flood target")
            push_log(attacker_logs, "warn", "[hping3] flooding TCP [SYN] -> target:80 (raw packet flood active)")
        else:
            run_docker(["exec", "doslab_u_attacker", "pkill", "-x", "hping3"])
            run_docker([
                "exec", "doslab_u_attacker", "sh", "-c",
                "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true"
            ])
            attack_state["syn_flood"] = False
            if was:
                push_log(attacker_logs, "cmd", "$ pkill -x hping3")
                push_log(attacker_logs, "cmd", "$ iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
                push_log(attacker_logs, "ok", "[hping3] SYN flood stopped.")


def set_slowloris(enable: bool):
    with state_lock:
        was = attack_state["slowloris"]
        if enable:
            run_docker(["exec", "doslab_u_attacker", "pkill", "-f", "[s]lowloris_worker.py"])
            run_docker([
                "exec", "-d", "doslab_u_attacker",
                "python3", "/app/slowloris_worker.py", "--host", "target", "--port", "80", "--sockets", "65", "--interval", "1.5"
            ])
            attack_state["slowloris"] = True
            push_log(attacker_logs, "cmd", "$ python3 /app/slowloris_worker.py --host target --port 80 --sockets 65 --interval 1.5")
            push_log(attacker_logs, "warn", "[slowloris] opening 65 partial HTTP GET sockets -> target:80")
        else:
            run_docker(["exec", "doslab_u_attacker", "pkill", "-f", "[s]lowloris_worker.py"])
            attack_state["slowloris"] = False
            if was:
                push_log(attacker_logs, "cmd", "$ pkill -f '[s]lowloris_worker.py'")
                push_log(attacker_logs, "ok", "[slowloris] all worker sockets closed.")


def set_l4_defense(enable: bool):
    write_json_atomic(POLICY_L4_FILE, {"enabled": enable})
    val = "1" if enable else "0"
    run_docker(["exec", "doslab_u_target", "sysctl", "-w", f"net.ipv4.tcp_syncookies={val}"])
    if enable:
        push_log(server_logs, "cmd", "$ sysctl -w net.ipv4.tcp_syncookies=1")
        push_log(server_logs, "cmd", "$ iptables -I INPUT 1 -p tcp --dport 80 --syn -j L4_SHIELD")
        push_log(server_logs, "ok", "[L4 SHIELD] ON: SYN Cookies + per-IP SYN rate-limit (--limit 2/s burst 4 -> DROP)")
    else:
        push_log(server_logs, "cmd", "$ sysctl -w net.ipv4.tcp_syncookies=0")
        push_log(server_logs, "cmd", "$ iptables -F L4_SHIELD")
        push_log(server_logs, "warn", "[L4 SHIELD] OFF (chế độ dễ bị SYN Flood)")


def set_l7_defense(enable: bool):
    write_json_atomic(POLICY_L7_FILE, {
        "header_timeout": enable,
        "conn_limit": enable,
        "rate_limit": enable,
        "reset": False,
    })
    if enable:
        push_log(server_logs, "cmd", "$ edge-proxy --header-timeout 2.5s --conn-limit 8 --rate-limit 12/s")
        push_log(server_logs, "ok", "[L7 SHIELD] ON: pruning slowloris sockets & capping max 8 conn/IP")
    else:
        push_log(server_logs, "cmd", "$ edge-proxy --disable-l7-shield")
        push_log(server_logs, "warn", "[L7 SHIELD] OFF")


def launch_wireshark_live():
    if not Path(WIRESHARK_EXE).exists():
        return False, f"Không tìm thấy {WIRESHARK_EXE}"
    bat_path = BASE_DIR / "OPEN_WIRESHARK_LIVE.bat"
    if bat_path.exists():
        push_log(server_logs, "cmd", '$ docker exec -i doslab_u_target tcpdump -i eth0 -U -s 96 -w - "tcp port 80" | Wireshark.exe -k -i -')
        subprocess.Popen(["cmd", "/c", "start", "", str(bat_path)], shell=False)
        return True, "Đã mở Wireshark Live"
    return False, "Thiếu OPEN_WIRESHARK_LIVE.bat"


def refresh_container_ips():
    rc, out = run_docker([
        "inspect", "-f",
        "{{.Name}}={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        "doslab_u_target", "doslab_u_attacker", "doslab_u_client",
    ])
    if rc == 0 and out:
        parsed = {}
        for line in out.splitlines():
            if "=" in line:
                name, ip = line.split("=", 1)
                clean = name.lstrip("/").replace("doslab_u_", "")
                if clean in ("target", "attacker", "client"):
                    parsed[clean] = ip.strip()
        if parsed:
            container_ips.update(parsed)


def fmt_host_time(ts_val, fallback: str = "") -> str:
    try:
        if ts_val:
            return time.strftime("%H:%M:%S", time.localtime(float(ts_val)))
    except Exception:
        pass
    return fallback or time.strftime("%H:%M:%S")


forensics_host_times = {}


def sync_forensics_to_server_log(m: dict):
    global last_logged_l4_drop
    for ev in reversed(m.get("forensics") or []):
        ev_type = ev.get("type", "")
        ip = ev.get("ip", "")
        detail = ev.get("detail", "")
        orig_time = ev.get("time", "")
        key = (orig_time, ev_type, ip, detail)
        if key in seen_forensics:
            continue
        if len(seen_forensics) > 400:
            seen_forensics.clear()
            forensics_host_times.clear()
        seen_forensics.add(key)
        ev_time = fmt_host_time(ev.get("ts"), "")
        forensics_host_times[key] = ev_time
        if ev_type in ("L4_POLICY", "L7_POLICY", "ADMIN_RESET"):
            continue
        if ev_type == "L4_FIREWALL_DROP":
            push_log(server_logs, "cmd", f"$ iptables -A L4_SHIELD -s {ip} -m limit --limit 2/sec --limit-burst 4 -j ACCEPT && -j DROP", ev_time)
            push_log(server_logs, "err", f"[L4_FIREWALL_DROP] {ip}: {detail}", ev_time)
        elif ev_type == "L4_AUTO_RELEASE":
            push_log(server_logs, "cmd", "$ iptables -F L4_SHIELD", ev_time)
            push_log(server_logs, "ok", f"[L4_AUTO_RELEASE] {detail}", ev_time)
        else:
            cls = "err" if ev_type in ("QUARANTINE", "SLOWLORIS_DROP") else "warn"
            push_log(server_logs, cls, f"[{ev_type}] {ip} -> {detail}", ev_time)


def telemetry_sampler():
    global last_hist_sec, last_probe_ts, last_ip_check
    global last_atk_heartbeat, last_srv_heartbeat, last_logged_l4_drop
    while True:
        now = time.time()
        if now - last_ip_check >= 5.0:
            refresh_container_ips()
            last_ip_check = now
        now_sec = int(now)
        m = read_json_safe(METRICS_FILE, {})
        if now_sec > last_hist_sec:
            history_60s.append({
                "ts": now_sec,
                "syn_recv": m.get("l4_syn_recv", 0),
                "workers": m.get("l7_active_workers", 0),
            })
            last_hist_sec = now_sec
        if m:
            sync_forensics_to_server_log(m)

        with state_lock:
            syn_on = attack_state["syn_flood"]
            slow_on = attack_state["slowloris"]

        if now - last_atk_heartbeat >= 2.1:
            if syn_on:
                push_log(attacker_logs, "warn", f"[hping3] flooding SYN -> target:80 | server_rx={m.get('rx_kbps', 0)} KB/s | target SYN_RECV={m.get('l4_syn_recv', 0)}/128")
            if slow_on:
                push_log(attacker_logs, "warn", f"[slowloris] keeping sockets alive -> open={m.get('l7_open_sockets', 0)}, workers={m.get('l7_active_workers', 0)}/30, rx={m.get('rx_kbps', 0)} KB/s")
            last_atk_heartbeat = now

        cur_drop = int(m.get("l4_packets_dropped", 0) or 0)
        if m.get("l4_enabled") and cur_drop > last_logged_l4_drop and (now - last_srv_heartbeat >= 2.0):
            push_log(server_logs, "ok", f"[KERNEL L4_SHIELD] dropped_syn_pkts={cur_drop:,} | SYN_RECV={m.get('l4_syn_recv', 0)}/128")
            last_logged_l4_drop = cur_drop
            last_srv_heartbeat = now

        p = read_json_safe(PROBE_FILE, {})
        p_ts = float(p.get("ts", 0) or 0)
        if p_ts > last_probe_ts:
            last_probe_ts = p_ts
            ok = bool(p.get("ok", False))
            t_str = fmt_host_time(p_ts, p.get("time_str", ""))
            lat = p.get("latency_ms", 0)
            msg = p.get("message", "")
            code = p.get("status_code", 0)
            probe_history_20.append({
                "ok": ok,
                "time_str": t_str,
                "latency_ms": lat,
                "message": msg,
            })
            if ok:
                push_log(client_logs, "ok", f"$ curl -m 1.8 http://target/api/search?q=user  ->  HTTP {code} OK ({lat} ms)", t_str)
            else:
                push_log(client_logs, "err", f"$ curl -m 1.8 http://target/api/search?q=user  ->  FAIL: {msg} ({lat} ms)", t_str)
        time.sleep(0.35)


TERMINAL_CSS = r"""
    .term-wrap { background: #05080f; border: 1px solid #334155; border-radius: 10px; overflow: hidden; margin-top: 12px; }
    .term-bar { background: #0f172a; padding: 6px 12px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; font-family: Consolas, monospace; font-size: 12px; color: #94a3b8; }
    .term-dots { display: inline-flex; gap: 5px; margin-right: 8px; }
    .term-dots span { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
    .term-body { height: 158px; overflow-y: auto; padding: 8px 10px; font-family: Consolas, 'Courier New', monospace; font-size: 11.8px; line-height: 1.45; color: #cbd5e1; }
    .term-line { white-space: pre-wrap; word-break: break-word; padding: 1px 0; }
    .t-time { color: #64748b; margin-right: 6px; }
    .t-cmd { color: #38bdf8; font-weight: 700; }
    .t-info { color: #94a3b8; }
    .t-warn { color: #fbbf24; }
    .t-ok { color: #4ade80; }
    .t-err { color: #f87171; }
"""

TERMINAL_JS = r"""
    function escHtml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    const _termState = {};
    function renderTerm(elId, rows) {
      const el = document.getElementById(elId);
      if (!el) return;
      const list = rows || [];
      const key = list.length ? `${list[0].id}:${list[list.length - 1].id}:${list.length}` : 'empty';
      if (_termState[elId] === key) return;
      _termState[elId] = key;
      const atBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 32;
      if (!list.length) {
        el.innerHTML = '<div class="term-line t-info">Waiting for container events...</div>';
        return;
      }
      el.innerHTML = list.map(r =>
        `<div class="term-line"><span class="t-time">[${escHtml(r.time)}]</span><span class="t-${escHtml(r.cls || 'info')}">${escHtml(r.text)}</span></div>`
      ).join('');
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
"""


def make_terminal_html(prompt_title: str, term_id: str, height_px: int = 158) -> str:
    return (
        '<div class="term-wrap">'
        '<div class="term-bar"><div><span class="term-dots">'
        '<span style="background:#ef4444;"></span>'
        '<span style="background:#f59e0b;"></span>'
        '<span style="background:#22c55e;"></span>'
        f'</span><b>{prompt_title}</b></div><span>LIVE TERMINAL</span></div>'
        f'<div id="{term_id}" class="term-body" style="height:{height_px}px;"></div>'
        '</div>'
    )


# ==============================================================================
# 1. ATTACKER UI (Port 9001)
# ==============================================================================
ATTACKER_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>ATTACKER Console (:9001)</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { margin: 0; background: #140b0e; color: #f8fafc; padding: 18px; }
    .hdr { border-bottom: 2px solid #7f1d1d; padding-bottom: 10px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .hdr h1 { margin: 0; font-size: 22px; color: #f87171; }
    .badge { padding: 5px 12px; border-radius: 999px; font-weight: 800; font-size: 13px; background: #334155; }
    .badge.atk { background: #dc2626; color: #fff; animation: pulse 1s infinite; }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
    .card { background: #1f1216; border: 1px solid #451a1f; border-radius: 12px; padding: 16px; margin-bottom: 14px; }
    .card h2 { margin: 0 0 6px; font-size: 17px; color: #fca5a5; }
    .card p { margin: 0 0 12px; font-size: 13.5px; color: #cbd5e1; }
    .btn { width: 100%; border: none; padding: 13px; border-radius: 9px; font-size: 15px; font-weight: 800; cursor: pointer; }
    .btn-red { background: #dc2626; color: #fff; }
    .btn-red:hover { background: #ef4444; }
    .btn-active { background: #991b1b; color: #fecaca; border: 2px solid #fca5a5; }
    .btn-gray { background: #334155; color: #fff; margin-top: 4px; }
    .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
    .stat { background: #1c1917; border: 1px solid #44403c; border-radius: 10px; padding: 12px; }
    .stat .lbl { font-size: 12px; color: #a8a29e; text-transform: uppercase; }
    .stat .val { font-size: 22px; font-weight: 800; margin-top: 4px; color: #fbbf24; }
    __TERM_CSS__
  </style>
</head>
<body>
  <div class="hdr">
    <h1>ATTACKER (doslab_u_attacker)</h1>
    <span id="atk-badge" class="badge">ĐANG NGHỈ</span>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="lbl">Mục tiêu</div>
      <div class="val" style="color:#f8fafc;">target:80</div>
    </div>
    <div class="stat">
      <div class="lbl">Băng thông gửi đi</div>
      <div id="atk-bw" class="val">0 KB/s</div>
    </div>
  </div>

  <div class="card">
    <h2>1. Tấn công Tầng 4 — SYN Flood</h2>
    <p>Bắn ồ ạt gói TCP [SYN] bằng <b>hping3</b> để làm tràn hàng đợi bắt tay TCP (SYN-RECV) của Server.</p>
    <button id="btn-syn" class="btn btn-red" onclick="toggle('syn_flood')">▶ BẮT ĐẦU SYN FLOOD (L4)</button>
  </div>

  <div class="card">
    <h2>2. Tấn công Tầng 7 — Slowloris</h2>
    <p>Mở <b>65 socket</b> gửi HTTP header dở dang (~1–2 KB/s) để chiếm sạch Worker Pool ứng dụng, lách qua tường lửa L4.</p>
    <button id="btn-slow" class="btn btn-red" onclick="toggle('slowloris')">▶ BẮT ĐẦU SLOWLORIS (L7)</button>
  </div>

  <button class="btn btn-gray" onclick="stopAll()">⏹ DỪNG TẤT CẢ TẤN CÔNG</button>

  __TERM_BOX__

  <script>
    __TERM_JS__
    let st = { syn_flood: false, slowloris: false };
    async function post(url, body) {
      await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      await tick();
    }
    function toggle(k) {
      const p = {}; p[k] = !st[k];
      post('/api/attack', p);
    }
    function stopAll() { post('/api/attack', { syn_flood: false, slowloris: false }); }

    async function tick() {
      try {
        const d = await (await fetch('/api/status?_=' + Date.now())).json();
        st = d.attack;
        const b = document.getElementById('atk-badge');
        const active = [];
        if (st.syn_flood) active.push('SYN FLOOD');
        if (st.slowloris) active.push('SLOWLORIS');
        if (active.length) {
          b.className = 'badge atk';
          b.textContent = 'ĐANG TẤN CÔNG: ' + active.join(' + ');
        } else {
          b.className = 'badge';
          b.textContent = 'ĐANG NGHỈ';
        }

        const bs = document.getElementById('btn-syn');
        bs.className = 'btn ' + (st.syn_flood ? 'btn-active' : 'btn-red');
        bs.textContent = st.syn_flood ? '⏹ DỪNG SYN FLOOD (Đang chạy...)' : '▶ BẮT ĐẦU SYN FLOOD (L4)';

        const bl = document.getElementById('btn-slow');
        bl.className = 'btn ' + (st.slowloris ? 'btn-active' : 'btn-red');
        bl.textContent = st.slowloris ? '⏹ DỪNG SLOWLORIS (Đang chạy...)' : '▶ BẮT ĐẦU SLOWLORIS (L7)';

        document.getElementById('atk-bw').textContent = (d.metrics.rx_kbps || 0) + ' KB/s';
        renderTerm('atk-term', (d.logs || {}).attacker);
      } catch (e) {}
    }
    setInterval(tick, 500);
    tick();
  </script>
</body>
</html>
"""
ATTACKER_HTML = (
    ATTACKER_HTML
    .replace("__TERM_CSS__", TERMINAL_CSS)
    .replace("__TERM_JS__", TERMINAL_JS)
    .replace("__TERM_BOX__", make_terminal_html("root@doslab_u_attacker:~# (Lệnh & Log tấn công)", "atk-term", 165))
)

# ==============================================================================
# 2. SERVER & DEFENSE UI (Port 9002)
# ==============================================================================
SERVER_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>SERVER & DEFENSE Console (:9002)</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { margin: 0; background: #0b1120; color: #e2e8f0; padding: 18px; }
    .hdr { border-bottom: 2px solid #1e3a8a; padding-bottom: 10px; margin-bottom: 16px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px; }
    .hdr h1 { margin: 0; font-size: 22px; color: #38bdf8; }
    .hdr-btns { display: flex; gap: 8px; }
    .btn-top { border: none; padding: 8px 14px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 13px; }
    .btn-ws { background: #2563eb; color: #fff; }
    .btn-rst { background: #334155; color: #e2e8f0; }
    .wsbar { background: #0f172a; border: 1px solid #1e3a8a; border-radius: 10px; padding: 9px 12px; margin-bottom: 14px; font-size: 12.5px; color: #cbd5e1; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .wschip { background: #1e293b; border: 1px solid #334155; color: #93c5fd; border-radius: 6px; padding: 4px 8px; cursor: pointer; font-family: Consolas, monospace; font-size: 12px; }
    .wschip:hover { border-color: #60a5fa; background: #1e3a8a; color: #fff; }
    .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 14px; }
    @media (max-width: 820px) { .cols { grid-template-columns: 1fr; } }
    .panel { background: #111827; border: 2px solid #1e293b; border-radius: 12px; padding: 16px; }
    .panel.danger { border-color: #ef4444; }
    .panel.shield { border-color: #10b981; }
    .ptitle { font-size: 15px; font-weight: 800; color: #93c5fd; margin-bottom: 10px; display: flex; justify-content: space-between; }
    .bignum { font-size: 32px; font-weight: 800; margin-bottom: 8px; }
    .bar-bg { width: 100%; height: 14px; background: #1e293b; border-radius: 999px; overflow: hidden; margin-bottom: 10px; }
    .bar-fill { height: 100%; width: 0%; transition: width 0.25s; }
    .subinfo { font-size: 13.5px; color: #cbd5e1; margin-bottom: 12px; }
    .def-btn { width: 100%; border: none; padding: 12px; border-radius: 9px; font-size: 14.5px; font-weight: 800; cursor: pointer; margin-bottom: 12px; }
    .def-off { background: #1e293b; color: #94a3b8; border: 1px solid #475569; }
    .def-on { background: #059669; color: #fff; border: 1px solid #34d399; }
    canvas { width: 100%; height: 130px; display: block; background: #090d16; border-radius: 8px; }
    .logpanel { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 10px 14px; }
    .logpanel h3 { margin: 0 0 6px; font-size: 13px; color: #cbd5e1; }
    .logs { max-height: 72px; overflow-y: auto; font-family: Consolas, monospace; font-size: 12px; }
    .logrow { padding: 3px 0; border-bottom: 1px solid #1e293b; }
    __TERM_CSS__
  </style>
</head>
<body>
  <div class="hdr">
    <h1>SERVER MỤC TIÊU & PHÒNG THỦ (doslab_u_target:80)</h1>
    <div class="hdr-btns">
      <button class="btn-top btn-ws" onclick="openWS()">Mở Wireshark Live</button>
      <button class="btn-top btn-rst" onclick="resetAll()">↺ Reset Toàn Bộ</button>
    </div>
  </div>

  <div class="wsbar">
    <b>Wireshark Filter</b> <span style="color:#94a3b8;">(bấm để copy):</span>
    <span class="wschip" onclick="copyWs(this, 'tcp.flags.syn == 1 && tcp.flags.ack == 0')">SYN Flood: tcp.flags.syn == 1 &amp;&amp; tcp.flags.ack == 0</span>
    <span class="wschip" onclick="copyWs(this, 'http || tcp.flags.reset == 1')">Slowloris/RST: http || tcp.flags.reset == 1</span>
    <span id="ws-atk-chip" class="wschip" onclick="copyWs(this, atkFilter)">Chỉ Attacker: tcp.port == 80</span>
    <span id="ws-ips" style="color:#94a3b8;font-size:12px;">Target: ... | Attacker: ... | Client: ...</span>
  </div>

  <div class="cols">
    <!-- L4 Panel -->
    <div id="p-l4" class="panel">
      <div class="ptitle"><span>TẦNG L4: TCP KERNEL &amp; FIREWALL</span><span id="st-l4">CHƯA BẢO VỆ</span></div>
      <div id="num-l4" class="bignum" style="color:#f59e0b;">SYN-RECV: 0 / 128</div>
      <div class="bar-bg"><div id="bar-l4" class="bar-fill" style="background:#f59e0b;"></div></div>
      <div id="sub-l4" class="subinfo">SYN Cookies: OFF | Gói SYN đã chặn (iptables): 0</div>
      <button id="btn-l4" class="def-btn def-off" onclick="toggleL4()">🛡️ PHÒNG THỦ L4 (SYN Cookies + Firewall): TẮT</button>
      <canvas id="c-l4" width="520" height="130"></canvas>
    </div>

    <!-- L7 Panel -->
    <div id="p-l7" class="panel">
      <div class="ptitle"><span>TẦNG L7: REVERSE PROXY &amp; WORKER POOL</span><span id="st-l7">CHƯA BẢO VỆ</span></div>
      <div id="num-l7" class="bignum" style="color:#a855f7;">Workers: 0 / 30</div>
      <div class="bar-bg"><div id="bar-l7" class="bar-fill" style="background:#a855f7;"></div></div>
      <div id="sub-l7" class="subinfo">Socket giữ kết nối: 0 | Đã chặn ở Proxy: 0</div>
      <button id="btn-l7" class="def-btn def-off" onclick="toggleL7()">🛡️ PHÒNG THỦ L7 (Header Timeout 2.5s + Max 8 Conn): TẮT</button>
      <canvas id="c-l7" width="520" height="130"></canvas>
    </div>
  </div>

  <div class="logpanel">
    <h3>NHẬT KÝ CHẶN &amp; PHÁP CHỨNG (Forensics Event Log)</h3>
    <div id="logs" class="logs">Chưa có sự kiện chặn...</div>
  </div>

  __TERM_BOX__

  <script>
    __TERM_JS__
    let curL4 = false, curL7 = false, atkFilter = 'tcp.port == 80';
    async function post(url, body) {
      await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body || {}) });
      await tick();
    }
    function toggleL4() { post('/api/defense', { l4_enabled: !curL4 }); }
    function toggleL7() { post('/api/defense', { l7_shield: !curL7 }); }
    function resetAll() { post('/api/reset', {}); }
    function copyWs(el, text) {
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text);
      const old = el.textContent;
      el.dataset.busy = '1';
      el.textContent = '✓ Đã copy: ' + text;
      setTimeout(() => { el.textContent = old; el.dataset.busy = ''; }, 1200);
    }
    async function openWS() {
      const r = await fetch('/api/wireshark', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
      const j = await r.json();
      if (!j.ok) alert(j.message || 'Không mở được Wireshark Live');
    }

    function draw(id, arr, color, maxVal) {
      const c = document.getElementById(id), ctx = c.getContext('2d');
      const w = c.width, h = c.height;
      ctx.clearRect(0, 0, w, h);
      ctx.strokeStyle = '#1e293b'; ctx.fillStyle = '#64748b'; ctx.font = '11px Consolas';
      for (let i = 0; i <= 3; i++) {
        const y = 12 + ((h - 24) * i) / 3;
        ctx.beginPath(); ctx.moveTo(36, y); ctx.lineTo(w - 8, y); ctx.stroke();
        ctx.fillText(Math.round(maxVal * (1 - i / 3)), 4, y + 4);
      }
      if (!arr || arr.length < 2) return;
      ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.beginPath();
      const step = (w - 44) / Math.max(arr.length - 1, 1);
      arr.forEach((v, idx) => {
        const x = 36 + idx * step;
        const y = 12 + (h - 24) * (1 - Math.min(v, maxVal) / maxVal);
        if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    async function tick() {
      try {
        const d = await (await fetch('/api/status?_=' + Date.now())).json();
        const m = d.metrics || {};
        curL4 = !!m.l4_enabled;
        curL7 = !!(m.l7_shield && (m.l7_shield.header_timeout || m.l7_shield.conn_limit));

        const syn = m.l4_syn_recv || 0;
        const l4Drop = m.l4_packets_dropped || 0;
        document.getElementById('num-l4').textContent = `SYN-RECV: ${syn} / 128`;
        document.getElementById('bar-l4').style.width = Math.min(100, (syn / 128) * 100) + '%';
        document.getElementById('bar-l4').style.background = syn >= 80 ? '#ef4444' : '#f59e0b';
        document.getElementById('sub-l4').textContent = `SYN Cookies: ${(m.l4_syncookies ? 'ON' : 'OFF')} | Đã chặn (iptables): ${l4Drop.toLocaleString()} gói`;
        document.getElementById('p-l4').className = 'panel ' + (syn >= 80 ? 'danger' : (curL4 ? 'shield' : ''));
        document.getElementById('st-l4').textContent = curL4 ? 'ĐANG BẢO VỆ' : 'CHƯA BẢO VỆ';
        document.getElementById('st-l4').style.color = curL4 ? '#34d399' : '#f87171';
        const b4 = document.getElementById('btn-l4');
        b4.className = 'def-btn ' + (curL4 ? 'def-on' : 'def-off');
        b4.textContent = '🛡️ PHÒNG THỦ L4 (SYN Cookies + Firewall): ' + (curL4 ? 'ĐANG BẬT' : 'ĐANG TẮT');

        const w = m.l7_active_workers || 0;
        const maxW = m.l7_max_workers || 30;
        document.getElementById('num-l7').textContent = `Workers: ${w} / ${maxW}`;
        document.getElementById('bar-l7').style.width = Math.min(100, (w / maxW) * 100) + '%';
        document.getElementById('bar-l7').style.background = w >= 25 ? '#ef4444' : '#a855f7';
        document.getElementById('sub-l7').textContent = `Socket đang mở: ${m.l7_open_sockets || 0} | Đã chặn ở Proxy: ${(m.total_blocked || 0).toLocaleString()} req`;
        document.getElementById('p-l7').className = 'panel ' + (w >= 25 ? 'danger' : (curL7 ? 'shield' : ''));
        document.getElementById('st-l7').textContent = curL7 ? 'ĐANG BẢO VỆ' : 'CHƯA BẢO VỆ';
        document.getElementById('st-l7').style.color = curL7 ? '#34d399' : '#f87171';
        const b7 = document.getElementById('btn-l7');
        b7.className = 'def-btn ' + (curL7 ? 'def-on' : 'def-off');
        b7.textContent = '🛡️ PHÒNG THỦ L7 (Header Timeout 2.5s + Max 8 Conn): ' + (curL7 ? 'ĐANG BẬT' : 'ĐANG TẮT');

        const ips = d.docker_ips || {};
        if (ips.attacker) {
          atkFilter = `ip.addr == ${ips.attacker} && tcp.port == 80`;
          const chip = document.getElementById('ws-atk-chip');
          if (!chip.dataset.busy) chip.textContent = `Chỉ Attacker: ${atkFilter}`;
        }
        document.getElementById('ws-ips').textContent = `Target: ${ips.target || '...'} | Attacker: ${ips.attacker || '...'} | Client: ${ips.client || '...'}`;

        const hist = d.history || [];
        draw('c-l4', hist.map(x => x.syn_recv), '#f59e0b', 140);
        draw('c-l7', hist.map(x => x.workers), '#a855f7', 35);

        const logs = m.forensics || [];
        document.getElementById('logs').innerHTML = logs.length
          ? logs.map(x => `<div class="logrow"><span style="color:#64748b;">[${x.time}]</span> <b style="color:#fbbf24;">${x.type}</b> (${x.ip}) — ${x.detail}</div>`).join('')
          : '<span style="color:#64748b;">Chưa có sự kiện chặn...</span>';

        renderTerm('srv-term', (d.logs || {}).server);
      } catch (e) {}
    }
    setInterval(tick, 500);
    tick();
  </script>
</body>
</html>
"""
SERVER_HTML = (
    SERVER_HTML
    .replace("__TERM_CSS__", TERMINAL_CSS)
    .replace("__TERM_JS__", TERMINAL_JS)
    .replace("__TERM_BOX__", make_terminal_html("root@doslab_u_target:~# (Lệnh Kernel & Log phòng thủ)", "srv-term", 145))
)

# ==============================================================================
# 3. CLIENT UI (Port 9003)
# ==============================================================================
CLIENT_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>CLIENT View — NovaCloud Portal (:9003)</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { margin: 0; background: #f1f5f9; color: #0f172a; padding: 18px; }
    .hdr { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #cbd5e1; padding-bottom: 10px; margin-bottom: 16px; }
    .hdr h1 { margin: 0; font-size: 21px; color: #1e3a8a; }
    .status-box { border-radius: 14px; padding: 20px 18px; text-align: center; margin-bottom: 14px; border: 3px solid; transition: 0.2s; }
    .status-ok { background: #dcfce7; border-color: #16a34a; color: #14532d; }
    .status-err { background: #fee2e2; border-color: #dc2626; color: #7f1d1d; }
    .status-title { font-size: 25px; font-weight: 900; margin-bottom: 6px; }
    .status-sub { font-size: 15px; font-weight: 600; }
    .card { background: #fff; border-radius: 12px; padding: 14px; box-shadow: 0 2px 8px rgba(15,23,42,0.08); margin-bottom: 12px; }
    .card h3 { margin: 0 0 10px; font-size: 13.5px; color: #475569; text-transform: uppercase; }
    .timeline { display: grid; grid-template-columns: repeat(20, 1fr); gap: 5px; height: 30px; }
    .bar { border-radius: 5px; background: #cbd5e1; }
    .bar.ok { background: #22c55e; }
    .bar.err { background: #ef4444; }
    .btn-test { width: 100%; background: #2563eb; color: #fff; border: none; padding: 11px; border-radius: 9px; font-size: 14.5px; font-weight: 700; cursor: pointer; }
    .btn-test:hover { background: #1d4ed8; }
    #manual-res { margin-top: 8px; font-family: Consolas, monospace; font-size: 12.5px; color: #334155; text-align: center; }
    __TERM_CSS__
  </style>
</head>
<body>
  <div class="hdr">
    <h1>CLIENT — Người dùng hợp pháp (doslab_u_client)</h1>
    <span style="font-size:13px;color:#475569;">Đang truy cập: <b>http://target/</b></span>
  </div>

  <div id="sbox" class="status-box status-ok">
    <div id="stitle" class="status-title">ĐANG KẾT NỐI...</div>
    <div id="ssub" class="status-sub">Chờ phản hồi từ Client Prober...</div>
  </div>

  <div class="card">
    <h3>Lịch sử 20 lần truy cập gần nhất (Xanh = Vào được | Đỏ = Sập / Timeout)</h3>
    <div id="timeline" class="timeline"></div>
  </div>

  <div class="card">
    <button class="btn-test" onclick="testNow()">🔄 Kiểm Tra Truy Cập Thủ Công Ngay</button>
    <div id="manual-res">Nhấn nút để gửi một HTTP request trực tiếp từ Client tới Server...</div>
  </div>

  __TERM_BOX__

  <script>
    __TERM_JS__
    async function testNow() {
      const el = document.getElementById('manual-res');
      el.textContent = 'Đang gửi GET http://target/ từ doslab_u_client...';
      try {
        const res = await (await fetch('/api/probe_now', { method: 'POST' })).json();
        el.textContent = res.ok
          ? `THÀNH CÔNG: HTTP ${res.status_code} (${res.latency_ms} ms)`
          : `THẤT BẠI: ${res.message} (${res.latency_ms} ms)`;
        await tick();
      } catch (e) { el.textContent = 'Lỗi kiểm tra'; }
    }

    async function tick() {
      try {
        const d = await (await fetch('/api/status?_=' + Date.now())).json();
        const p = d.probe || {};
        const box = document.getElementById('sbox');
        if (p.ts && p.ok) {
          box.className = 'status-box status-ok';
          document.getElementById('stitle').textContent = `TRUY CẬP BÌNH THƯỜNG — HTTP ${p.status_code}`;
          document.getElementById('ssub').textContent = `Độ trễ phản hồi: ${p.latency_ms} ms (Cập nhật: ${p.time_str})`;
        } else if (p.ts) {
          box.className = 'status-box status-err';
          document.getElementById('stitle').textContent = `KHÔNG THỂ TRUY CẬP — ${p.message}`;
          document.getElementById('ssub').textContent = `Hệ thống mục tiêu đang quá tải / nghẽn (${p.time_str})`;
        }

        const hist = d.probe_history || [];
        const padded = Array(Math.max(0, 20 - hist.length)).fill(null).concat(hist);
        document.getElementById('timeline').innerHTML = padded.map(item => {
          if (!item) return '<div class="bar"></div>';
          return `<div class="bar ${item.ok ? 'ok' : 'err'}" title="${item.time_str}: ${item.message} (${item.latency_ms}ms)"></div>`;
        }).join('');

        renderTerm('cli-term', (d.logs || {}).client);
      } catch (e) {}
    }
    setInterval(tick, 450);
    tick();
  </script>
</body>
</html>
"""
CLIENT_HTML = (
    CLIENT_HTML
    .replace("__TERM_CSS__", TERMINAL_CSS)
    .replace("__TERM_JS__", TERMINAL_JS)
    .replace("__TERM_BOX__", make_terminal_html("user@doslab_u_client:~$ (Lệnh HTTP Prober & Phản hồi)", "cli-term", 165))
)

INDEX_HTML = """<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><title>Demo Launcher (:9000)</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
  .box { background: #1e293b; padding: 28px; border-radius: 14px; text-align: center; max-width: 520px; }
  a { display: block; margin: 12px 0; padding: 14px; border-radius: 9px; text-decoration: none; font-weight: 800; color: #fff; font-size: 16px; }
</style></head>
<body><div class="box">
  <h2>CEHv13 Module 10 — 3 Giao Diện Demo Riêng Biệt</h2>
  <a href="http://127.0.0.1:9001" target="_blank" style="background:#dc2626;">1. Mở Giao Diện ATTACKER (:9001)</a>
  <a href="http://127.0.0.1:9002" target="_blank" style="background:#2563eb;">2. Mở Giao Diện SERVER & PHÒNG THỦ (:9002)</a>
  <a href="http://127.0.0.1:9003" target="_blank" style="background:#16a34a;">3. Mở Giao Diện CLIENT (:9003)</a>
</div></body></html>
"""


class RoleHandler(http.server.BaseHTTPRequestHandler):
    def send_html(self, html: str):
        raw = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, code: int, obj: dict):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        p = self.path.split("?")[0]
        port = self.server.server_port
        if p == "/api/status":
            m = read_json_safe(METRICS_FILE, {})
            pr = read_json_safe(PROBE_FILE, {})
            if pr.get("ts"):
                pr["time_str"] = fmt_host_time(pr.get("ts"), pr.get("time_str", ""))
            for ev in (m.get("forensics") or []):
                key = (ev.get("time", ""), ev.get("type", ""), ev.get("ip", ""), ev.get("detail", ""))
                ev["time"] = fmt_host_time(ev.get("ts"), forensics_host_times.get(key) or ev.get("time", ""))
            with state_lock:
                atk = dict(attack_state)
            self.send_json(200, {
                "metrics": m,
                "probe": pr,
                "probe_history": list(probe_history_20),
                "attack": atk,
                "history": list(history_60s),
                "logs": {
                    "attacker": snapshot_logs(attacker_logs),
                    "server": snapshot_logs(server_logs),
                    "client": snapshot_logs(client_logs),
                },
                "docker_ips": dict(container_ips),
            })
            return

        if p == "/attacker" or (p == "/" and port == 9001):
            self.send_html(ATTACKER_HTML)
        elif p == "/server" or (p == "/" and port == 9002):
            self.send_html(SERVER_HTML)
        elif p == "/client" or (p == "/" and port == 9003):
            self.send_html(CLIENT_HTML)
        else:
            self.send_html(INDEX_HTML)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        data = json.loads(body.decode("utf-8") or "{}")

        if self.path == "/api/attack":
            if "syn_flood" in data:
                set_syn_flood(bool(data["syn_flood"]))
            if "slowloris" in data:
                set_slowloris(bool(data["slowloris"]))
            self.send_json(200, {"ok": True})
        elif self.path == "/api/defense":
            if "l4_enabled" in data:
                set_l4_defense(bool(data["l4_enabled"]))
            if "l7_shield" in data:
                set_l7_defense(bool(data["l7_shield"]))
            self.send_json(200, {"ok": True})
        elif self.path == "/api/reset":
            global last_logged_l4_drop
            set_syn_flood(False)
            set_slowloris(False)
            set_l4_defense(False)
            write_json_atomic(POLICY_L7_FILE, {"header_timeout": False, "conn_limit": False, "rate_limit": False, "reset": True})
            history_60s.clear()
            probe_history_20.clear()
            seen_forensics.clear()
            forensics_host_times.clear()
            last_logged_l4_drop = 0
            push_log(attacker_logs, "ok", "[RESET] all attack processes stopped.")
            push_log(server_logs, "cmd", "$ iptables -F L4_SHIELD && sysctl -w net.ipv4.tcp_syncookies=0")
            push_log(server_logs, "ok", "[RESET] firewall rules cleared & telemetry reset.")
            push_log(client_logs, "info", "[RESET] probe timeline reset.")
            self.send_json(200, {"ok": True})
        elif self.path == "/api/wireshark":
            ok, msg = launch_wireshark_live()
            self.send_json(200 if ok else 500, {"ok": ok, "message": msg})
        elif self.path == "/api/probe_now":
            py_one = (
                "import json, time, urllib.request, urllib.error\n"
                "t0 = time.perf_counter()\n"
                "try:\n"
                "  with urllib.request.urlopen('http://target/api/search?q=manual', timeout=1.8) as r:\n"
                "    print(json.dumps({'ok': True, 'status_code': r.status, 'latency_ms': round((time.perf_counter()-t0)*1000,1), 'message': f'HTTP {r.status}'}))\n"
                "except urllib.error.HTTPError as e:\n"
                "  print(json.dumps({'ok': False, 'status_code': e.code, 'latency_ms': round((time.perf_counter()-t0)*1000,1), 'message': f'HTTP {e.code}'}))\n"
                "except Exception:\n"
                "  print(json.dumps({'ok': False, 'status_code': 0, 'latency_ms': round((time.perf_counter()-t0)*1000,1), 'message': 'TIMEOUT'}))\n"
            )
            push_log(client_logs, "cmd", "$ curl -m 1.8 http://target/api/search?q=manual  (manual check)")
            _, out = run_docker(["exec", "doslab_u_client", "python3", "-c", py_one])
            try:
                res = json.loads(out)
            except Exception:
                res = {"ok": False, "status_code": 0, "latency_ms": 0, "message": "ERROR"}
            if res.get("ok"):
                push_log(client_logs, "ok", f"  -> HTTP {res.get('status_code', 200)} OK ({res.get('latency_ms', 0)} ms)")
            else:
                push_log(client_logs, "err", f"  -> FAIL: {res.get('message', 'ERR')} ({res.get('latency_ms', 0)} ms)")
            self.send_json(200, res)
        else:
            self.send_json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def serve_port(port: int):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), RoleHandler)
    srv.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", default="9000,9001,9002,9003")
    args = parser.parse_args()

    write_json_atomic(POLICY_L4_FILE, {"enabled": False})
    write_json_atomic(POLICY_L7_FILE, {"header_timeout": False, "conn_limit": False, "rate_limit": False, "reset": False})

    push_log(attacker_logs, "info", "container doslab_u_attacker ready (network=unified_net, target=target:80)")
    push_log(attacker_logs, "info", "waiting for SYN Flood / Slowloris command...")
    push_log(server_logs, "info", "edge-proxy listening on 0.0.0.0:80 (backlog=128) -> backend 127.0.0.1:8081 (30 workers)")
    push_log(server_logs, "cmd", "$ sysctl net.ipv4.tcp_syncookies=0 tcp_max_syn_backlog=512")
    push_log(client_logs, "info", "container doslab_u_client prober active (interval=0.7s -> http://target/api/search?q=user)")

    threading.Thread(target=telemetry_sampler, daemon=True).start()
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    for p in ports[1:]:
        threading.Thread(target=serve_port, args=(p,), daemon=True).start()

    print("[UNIFIED PANEL] Ready:")
    print("  - Attacker : http://127.0.0.1:9001")
    print("  - Server   : http://127.0.0.1:9002")
    print("  - Client   : http://127.0.0.1:9003")
    try:
        serve_port(ports[0])
    except KeyboardInterrupt:
        print("\nStopping attacks and exiting...")
        set_syn_flood(False)
        set_slowloris(False)


if __name__ == "__main__":
    main()
