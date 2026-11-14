#!/usr/bin/env python3
"""
==============================================================================
FR1 - THĂM DÒ & XÁC ĐỊNH MỤC TIÊU (TCP PORT SCANNER - RECONNAISSANCE)
Chạy trên: attacker_node (192.168.100.20)
==============================================================================
Mô tả:
Thực hiện quét cổng TCP (Port Scanning) nhắm vào victim_server (192.168.100.10)
để xác định cổng dịch vụ HTTP (Port 80) đang mở trước khi thực hiện các bước tiếp theo.
==============================================================================
"""

import socket
import sys
import time

TARGET_IP = "192.168.100.10"
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]

def scan_target(target_ip, ports):
    print("=" * 65)
    print(f" [!] BẮT ĐẦU THĂM DÒ MỤC TIÊU (RECONNAISSANCE - PORT SCAN)")
    print(f" [*] Mục tiêu kiểm tra: {target_ip}")
    print(f" [*] Danh sách cổng: {ports}")
    print("=" * 65)
    printf_format = "{:<8} | {:<12} | {:<15} | {:<15}"
    print(printf_format.format("PORT", "TRẠNG THÁI", "DỊCH VỤ", "THỜI GIAN"))
    print("-" * 65)

    open_ports = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        start_time = time.perf_counter()

        service_name = "unknown"
        if port == 80: service_name = "HTTP (Nginx)"
        elif port == 443: service_name = "HTTPS"
        elif port == 22: service_name = "SSH"
        elif port == 21: service_name = "FTP"
        elif port in [8080, 8443]: service_name = "HTTP-Alt"

        try:
            result = s.connect_ex((target_ip, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if result == 0:
                print(printf_format.format(f"{port}/tcp", "OPEN", service_name, f"{elapsed_ms:.2f} ms"))
                open_ports.append(port)
            else:
                print(printf_format.format(f"{port}/tcp", "CLOSED", service_name, "-"))
        except Exception as e:
            print(printf_format.format(f"{port}/tcp", "FILTERED", service_name, "error"))
        finally:
            s.close()

    print("=" * 65)
    print(f"[+] KẾT QUẢ THĂM DÒ: Tìm thấy {len(open_ports)} cổng đang mở.")
    if 80 in open_ports:
        print(f"[+] XÁC NHẬN: Cổng 80/TCP (HTTP Web Service) đang mở trên {target_ip}!")
        print(f"[+] Mục tiêu đã sẵn sàng cho các bài kiểm nghiệm tiếp theo.")
    print("=" * 65)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_IP
    scan_target(target, PORTS_TO_SCAN)
