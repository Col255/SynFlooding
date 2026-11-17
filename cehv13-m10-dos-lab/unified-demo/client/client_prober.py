"""
Legitimate Client Prober (runs inside isolated Docker container `doslab_u_client`).
Sends normal requests to http://target/api/search?q=user every 0.7s and writes
real latency + HTTP status to /shared/probe.json.
"""

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

SHARED = Path("/shared")
PROBE_FILE = SHARED / "probe.json"
PROBE_TMP = SHARED / "probe.tmp"


def main():
    SHARED.mkdir(parents=True, exist_ok=True)
    url = "http://target/api/search?q=user"
    while True:
        t0 = time.perf_counter()
        ok = False
        code = 0
        msg = ""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LegitUser-Client/1.0"})
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                _ = resp.read()
                code = resp.status
                latency_ms = (time.perf_counter() - t0) * 1000.0
                ok = 200 <= code < 400
                msg = f"HTTP {code}"
        except urllib.error.HTTPError as e:
            code = e.code
            latency_ms = (time.perf_counter() - t0) * 1000.0
            msg = f"HTTP {code} (Quá tải)"
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            msg = "TIMEOUT" if "timed out" in str(e).lower() else "CONN REFUSED"

        payload = {
            "ts": round(time.time(), 2),
            "time_str": time.strftime("%H:%M:%S"),
            "ok": ok,
            "status_code": code,
            "latency_ms": round(latency_ms, 1),
            "message": msg,
        }
        try:
            PROBE_TMP.write_text(json.dumps(payload), encoding="utf-8")
            PROBE_TMP.replace(PROBE_FILE)
        except OSError:
            pass
        time.sleep(0.7)


if __name__ == "__main__":
    main()
