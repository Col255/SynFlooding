# Module Phòng Thủ Theo Chiều Sâu (Defense in Depth)

Module này do **Thành viên 3** phụ trách, hiện thực hóa yêu cầu **FR4 (Defense in Depth)** theo đúng kiến trúc bảo vệ đa tầng trong tài liệu Báo cáo đồ án.

---

## 1. Mô hình kiến trúc Defense in Depth 2 Cấp độ

```
                      LƯU LƯỢNG GÓI TIN ĐẾN (TCP SYN)
                                     │
                                     ▼
    ┌────────────────────────────────────────────────────────────────┐
    │     CẤP ĐỘ 1: PHÒNG THỦ TẠI LỚP MẠNG (NETWORK LAYER - IPTABLES) │
    │     Tệp thực thi: 02_network_firewall.sh                       │
    │                                                                │
    │  • Chuỗi tùy biến: SYN_PROTECT                                 │
    │  • Thuật toán Token Bucket: --limit 20/s --limit-burst 30      │
    │  • Hành động: DROP thẳng tay toàn bộ gói SYN vượt ngưỡng       │
    └────────────────────────────────┬───────────────────────────────┘
                                     │ (Gói tin hợp lệ đi tiếp)
                                     ▼
    ┌────────────────────────────────────────────────────────────────┐
    │    CẤP ĐỘ 2: PHÒNG THỦ TẠI LỚP MÁY CHỦ (HOST LAYER - KERNEL)   │
    │    Tệp thực thi: 01_host_hardening.sh                          │
    │                                                                │
    │  • net.ipv4.tcp_syncookies = 1 (Không cấp phát RAM cho TCB)   │
    │  • net.ipv4.tcp_max_syn_backlog = 2048 (Mở rộng vùng đệm)      │
    │  • net.ipv4.tcp_synack_retries = 1 (Giải phóng kết nối rác)    │
    └────────────────────────────────┬───────────────────────────────┘
                                     │ (Hoàn tất bắt tay hợp lệ)
                                     ▼
    ┌────────────────────────────────────────────────────────────────┐
    │                       DỊCH VỤ ỨNG DỤNG                         │
    │                  Nginx Web Server (Port 80)                    │
    │           Phục vụ Normal Client (192.168.100.30) ổn định       │
    └────────────────────────────────────────────────────────────────┘
```

---

## 2. Danh mục công cụ trong Module

| Tệp tin | Cấp độ bảo vệ | Mô tả kỹ thuật |
| :--- | :--- | :--- |
| `01_host_hardening.sh` | **Lớp Máy chủ** | Kích hoạt TCP SYN Cookies (`=1`), mở rộng Backlog (`=2048`), giảm SYN-ACK Retries (`=1`). |
| `02_network_firewall.sh` | **Lớp Mạng** | Tạo chuỗi `SYN_PROTECT`, giới hạn `20/s` (burst `30`), DROP gói vượt ngưỡng. |
| `reset_defense.sh` | **Khôi phục** | Đưa máy chủ về trạng thái Chưa phòng thủ (Backlog `128`, Cookies `=0`, chặn RST từ gateway). |

---

## 3. Lệnh thực thi trên `victim_server`

```bash
# 1. Đưa máy chủ về trạng thái Chưa phòng thủ (phục vụ đối chứng kịch bản bị sập)
docker exec -it victim_server bash /workspace/defense/reset_defense.sh

# 2. Bật Lớp Máy chủ (Kernel Tuning)
docker exec -it victim_server bash /workspace/defense/01_host_hardening.sh

# 3. Bật Lớp Mạng (Tường lửa iptables)
docker exec -it victim_server bash /workspace/defense/02_network_firewall.sh
```
