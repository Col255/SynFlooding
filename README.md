# ĐỒ ÁN HỌC THUẬT AN NINH MẠNG
## Mô Phỏng Tấn Công SYN Flooding Khai Thác Bắt Tay 3 Bước TCP và Xây Dựng Cơ Chế Phòng Thủ Theo Chiều Sâu (Defense in Depth)

---

## 1. Giới thiệu tổng quan
Dự án được thiết kế đồng bộ 100% theo bản Đặc tả Yêu cầu Hệ thống (**SRS FR1–FR5, NFR1–NFR3**) và Bảng phân công 3 thành viên trong Kịch bản học thuật:
- **Thành viên 1 (Hạ tầng, Giám sát & Báo cáo):** Quản lý `docker-compose.yml`, card mạng cô lập `192.168.100.0/24`, bắt gói tin `.pcap` bằng `tcpdump` và xuất minh chứng Wireshark.
- **Thành viên 2 (Nghiên cứu Kịch bản Tấn công):** Thực hiện quét cổng mục tiêu (Port Scanning), phát động tấn công SYN Flood ngụy tạo IP nguồn ngẫu nhiên (`IP Spoofing`) bằng `hping3` và Python `Scapy`.
- **Thành viên 3 (Nghiên cứu Kịch bản Phòng thủ):** Hiện thực hóa mô hình Defense in Depth 2 tầng gồm Tường lửa `iptables` giới hạn tần suất (Lớp Mạng) và Tinh chỉnh tham số nhân Linux `TCP SYN Cookies` (Lớp Máy chủ).

---

## 2. Sơ đồ mạng & Bảng cấu hình các Node

Mạng nội bộ cô lập: `isolated_net` (Subnet: `192.168.100.0/24`, Gateway: `192.168.100.1`, Driver: `bridge`).

```
                    ┌──────────────────────────────────────────────┐
                    │      MẠNG CÔ LẬP: isolated_net (Bridge)     │
                    │               192.168.100.0/24               │
                    └──────┬───────────────┬───────────────┬───────┘
                           │               │               │
                           │               │               │
            192.168.100.10 │192.168.100.20│192.168.100.30│
            ┌──────────────▼─────┐  ┌──────▼────────────┐  ┌▼──────────────────┐
            │   victim_server    │  │   attacker_node   │  │   normal_client   │
            │  (Ubuntu 22.04)    │  │  (Ubuntu 22.04)   │  │  (Ubuntu 22.04)   │
            ├────────────────────┤  ├───────────────────┤  ├───────────────────┤
            │ • Nginx (Port 80)  │  │ • hping3          │  │ • curl            │
            │ • iptables         │  │ • Scapy (Python3) │  │ • python3         │
            │ • tcpdump          │  │ • iputils-ping    │  │ • iputils-ping    │
            │ • net-tools        │  │ • Raw socket      │  │ • benchmark tool  │
            │ • NET_ADMIN        │  │ • NET_ADMIN       │  │                   │
            │ • privileged: true │  │ • privileged: true│  │                   │
            └────────────────────┘  └───────────────────┘  └───────────────────┘
```

| Tên Container | Địa chỉ IP | Vai trò học thuật | Phân công |
| :--- | :--- | :--- | :--- |
| **`victim_server`** | `192.168.100.10` | Nạn nhân (Nginx Web Server port 80) | Thành viên 1 & 3 |
| **`attacker_node`** | `192.168.100.20` | Kẻ tấn công phát sinh SYN Flood đa IP | Thành viên 2 |
| **`normal_client`** | `192.168.100.30` | Người dùng hợp lệ đo lường độ trễ & DoS | Thành viên 1 & 2 |

---

## 3. Cấu trúc thư mục Module hóa

```
DoAn_ANM_SyncFLood/
├── docker-compose.yml                      # [Thành viên 1] Cấu hình 3 container và mạng isolated_net
├── README.md                               # Hướng dẫn chi tiết quy trình thực nghiệm
├── .gitignore                              # Bỏ qua tệp tin pcap và log
│
├── infrastructure/                         # [Thành viên 1] Module Hạ tầng ảo hóa
│   └── docker/
│       ├── victim/
│       │   ├── Dockerfile                  # Ubuntu 22.04 + Nginx (port 80), iptables, tcpdump
│       │   └── entrypoint.sh               # Tự khởi động service Nginx ở chế độ daemon off
│       ├── attacker/
│       │   └── Dockerfile                  # Ubuntu 22.04 + hping3, python3-scapy, ping
│       └── client/
│           └── Dockerfile                  # Ubuntu 22.04 + curl, python3, ping
│
├── attacks/                                # [Thành viên 2] Module Tấn công & Thăm dò
│   ├── 01_port_scan.py                     # [FR1] Quét cổng xác định mục tiêu port 80
│   ├── 02_syn_flood_hping3.sh              # [FR2] Chạy hping3 --flood --rand-source
│   ├── 03_syn_flood_scapy.py               # [FR2] Script Scapy ngụy tạo IP ngẫu nhiên
│   └── README.md                           # Lý thuyết bắt tay 3 bước & IP Spoofing
│
├── defense/                                # [Thành viên 3] Module Phòng thủ theo chiều sâu
│   ├── 01_host_hardening.sh                # Lớp 2: sysctl syncookies=1, backlog=2048, synack_retries=1
│   ├── 02_network_firewall.sh              # Lớp 1: iptables chuỗi SYN_PROTECT (limit 20/s burst 30)
│   ├── reset_defense.sh                    # Khôi phục trạng thái chưa phòng thủ (backlog=128)
│   └── README.md                           # Kiến trúc và nguyên lý Defense in Depth
│
└── measurement/                            # [Cả nhóm] Module Đo lường & Đánh giá định lượng
    ├── capture_evidence.sh                 # [FR3] Bắt gói tin ra syn_attack.pcap và đếm SYN_RECV
    ├── benchmark_client.py                 # [FR5] Đo HTTP Response Time & Failure Rate vào results.csv
    ├── results.csv                         # Dữ liệu đối sánh giữa 3 kịch bản
    └── README.md                           # Phương pháp luận và công thức toán học
```

---

## 4. Hướng dẫn Khởi chạy Hệ thống

Mở terminal tại thư mục dự án trên máy host:
```powershell
cd C:\Users\Col\Desktop\DoAn_ANM_SyncFLood
docker compose up -d --build
```
Kiểm tra cả 3 container đang hoạt động:
```powershell
docker compose ps
```

---

## 5. Quy trình Kiểm thử Thực nghiệm Từng bước (Chuẩn theo Google Docs)

Quy trình thực nghiệm được chia làm **3 Kịch bản đối sánh** phục vụ làm báo cáo và nộp bài:

### Giai đoạn 1: Thăm dò Mục tiêu (FR1 - Reconnaissance)
Từ `attacker_node`, quét cổng xem cổng 80 của `victim_server` đã mở chưa:
```bash
docker exec -it attacker_node python3 /workspace/attacks/01_port_scan.py
```
*Kết quả:* Phát hiện `Port 80/tcp: OPEN | Dịch vụ: HTTP (Nginx)`.

---

### Kịch bản 1: Đo lường Trạng thái Bình thường (Baseline Benchmark)
Trước khi phát động tấn công, đo đạc đường cơ sở từ `normal_client`:
```bash
docker exec -it normal_client python3 /workspace/measurement/benchmark_client.py --scenario "Baseline_Binh_Thuong"
```
*Kết quả mong đợi:*
- Tỷ lệ lỗi (Failure Rate): `0.00%`
- Tỷ lệ sẵn sàng (Availability): `100.00%`
- Thời gian phản hồi trung bình: `< 5 ms`.

---

### Kịch bản 2: Mô phỏng Tấn công SYN Flooding (Chưa Phòng Thủ - Sập Dịch Vụ)

1. **Bước 2.1 (Trên `victim_server`):** Đưa máy chủ về trạng thái Chưa phòng thủ (Backlog `128`, tắt Cookies):
   ```bash
   docker exec -it victim_server bash /workspace/defense/reset_defense.sh
   ```
2. **Bước 2.2 (Trên `victim_server`):** Bật công cụ ghi nhận gói tin và đếm hàng đợi:
   ```bash
   docker exec -it victim_server bash /workspace/measurement/capture_evidence.sh 20
   ```
3. **Bước 2.3 (Mở Terminal khác - Trên `attacker_node`):** Bắt đầu phát tán SYN Flood với IP giả mạo ngẫu nhiên:
   ```bash
   docker exec -it attacker_node hping3 -S --flood -V -p 80 --rand-source 192.168.100.10
   ```
   *(Hoặc chạy script Scapy: `docker exec -it attacker_node python3 /workspace/attacks/03_syn_flood_scapy.py`)*

4. **Bước 2.4 (Mở Terminal khác - Trên `normal_client`):** Truy vấn dịch vụ đồng thời lúc tấn công đang diễn ra:
   ```bash
   docker exec -it normal_client python3 /workspace/measurement/benchmark_client.py --scenario "Chua_Phong_Thu_Bi_DoS"
   ```

*Hiện tượng quan sát được:*
- **Trên `victim_server`:** Hàng đợi `SYN_RECV` bị lấp đầy hoàn toàn chạm ngưỡng trần `128/128`. File [syn_attack.pcap](file:///C:/Users/Col/Desktop/DoAn_ANM_SyncFLood/measurement/syn_attack.pcap) được ghi nhận thành công.
- **Trên `normal_client`:** Các request HTTP GET bị treo và trả về `CONNECTION_TIMED_OUT`. Tỷ lệ lỗi kết nối (Failure Rate) tăng vọt lên **`80% - 100%`** (DoS thành công).

---

### Kịch bản 3: Kích hoạt Phòng Thủ Theo Chiều Sâu (Defense in Depth - Khôi Phục Dịch Vụ)

Giữ nguyên luồng tấn công từ `attacker_node`, tiến hành kích hoạt 2 lớp phòng thủ trên `victim_server`:

1. **Bước 3.1 (Trên `victim_server`):** Kích hoạt Lớp Máy chủ (Kernel SYN Cookies & Backlog 2048):
   ```bash
   docker exec -it victim_server bash /workspace/defense/01_host_hardening.sh
   ```
2. **Bước 3.2 (Trên `victim_server`):** Kích hoạt Lớp Mạng (Tường lửa iptables giới hạn 20 gói/s, burst 30):
   ```bash
   docker exec -it victim_server bash /workspace/defense/02_network_firewall.sh
   ```
3. **Bước 3.3 (Trên `normal_client`):** Chạy lại công cụ đo lường ngay trong lúc đợt tấn công vẫn đang xả gói:
   ```bash
   docker exec -it normal_client python3 /workspace/measurement/benchmark_client.py --scenario "Co_Phong_Thu_Toan_Dien"
   ```

*Hiện tượng quan sát được:*
- **Lớp Mạng:** Tường lửa `SYN_PROTECT` lọc bỏ phần lớn lưu lượng SYN bất thường vượt quá 20 gói/s.
- **Lớp Máy chủ:** Các gói SYN lọt qua được xử lý bằng thuật toán mã hóa cookie bí mật (SYN Cookies), không tốn RAM cấp phát TCB.
- **Trên `normal_client`:** Dịch vụ Web phản hồi lại `HTTP 200 OK` mượt mà, tỷ lệ lỗi giảm về **`0.00%`**, thời gian phản hồi quay lại mức mili-giây.

---

## 6. Xem Dữ liệu Đối sánh Báo cáo
Mở file [measurement/results.csv](file:///C:/Users/Col/Desktop/DoAn_ANM_SyncFLood/measurement/results.csv) trên máy host để xem bảng số liệu đối sánh hoàn chỉnh của 3 kịch bản phục vụ vẽ biểu đồ:
```csv
Timestamp,Scenario,Total_Requests,Successful_Requests,Failed_Requests,Failure_Rate_Percent,Availability_Percent,Avg_Response_Time_ms
```

---

## 7. Dọn dẹp Môi trường
```powershell
docker compose down
```
