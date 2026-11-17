# Kịch Bản Thuyết Trình & Demo Live (10–15 Phút)

**Tổng thời lượng mục tiêu:** ~13 phút (dư ~2 phút Q&A trong khung 10–15 phút).

---

## Chặng 1: Phân Tích Cơ Chế Tấn Công & Phòng Thủ (Slide 1–11 | 0:00 – 7:00)
- **Slide 1–2 (0:50):** Vào thẳng đề tài và Case Study **HTTP/2 Rapid Reset (CVE-2023-44487, 398M rps)** → đặt câu hỏi trung tâm về sự dịch chuyển từ đè băng thông sang đánh vào cơ chế L4 và L7.
- **Slide 3–4 (1:20):** Phân loại **Volumetric / Protocol / Application**, cấu trúc Botnet (*C&C Handler → Zombies*), và cơ chế khuếch đại/phản xạ (**Smurf, NTP `monlist`, Pulse Wave, DRDoS**).
- **Slide 5–6 (1:40):** Đi sâu **SYN Flood** (nghẽn `listen queue` & biến thể *Spoofed Session, Fragmentation, SACK Panic*) và **Slowloris / HTTP Slow GET-POST / Multi-Vector** (bắt tay TCP hợp lệ, băng thông nhỏ nhưng khóa Worker Pool).
- **Slide 7–9 (1:50):** Cơ chế phòng thủ theo 3 lớp: **L3 Anti-Spoofing** (*RFC 3704, Egress, IP Source Guard*), **L4 TCP Stack** (*SYN Cookies, Cisco TCP Intercept Active/Watch, Rate Limiting*), **L7 Edge Proxy** (*Header Buffering/Timeout, Conn/Rate Limit, Throttling/Puzzle*).
- **Slide 10–11 (1:20):** Kỹ thuật phát hiện (*Activity Profiling, CUSUM, Wavelet*), *Honeypot*, *Forensics*, 3 chiến lược ứng phó (*Absorb / Degrade / Shutdown*) và giải pháp **ISP/Cloud** (*RTBH `BGP null0`*, *BGP/DNS Swing Scrubbing*).

---

## Chặng 2: Slide 12 — Chuyển Sang Demo Live (7:00 – 11:30)
*(Chiếu Slide 12 ngắn gọn 10 giây rồi chuyển sang 3 cửa sổ **Attacker `:9001` – Server `:9002` – Client `:9003`** + **Wireshark Live**)*

### Bước 0 – Baseline (15 giây)
- **Chỉ:** Trên **Server (`:9002`)**, `SYN-RECV = 0/128` và `Workers = 0/30`. Trên **Client (`:9003`)**, bảng trạng thái Xanh **`HTTP 200`**.

### Bước 1 – Tấn công L4: SYN Flood (55 giây)
- **Thao tác:** Trên **ATTACKER (`:9001`)**, bấm **`▶ BẮT ĐẦU SYN FLOOD (L4)`**.
- **Nói & Chỉ:**
  *"**Đây là lúc bắt đầu tấn công gửi SYN liên tục** bằng `hping3`. Nhìn **Wireshark** (lọc `tcp.flags.syn == 1 && tcp.flags.ack == 0`): hàng loạt gói `[SYN]` tràn màn hình không có `[ACK]`. Nhìn sang **SERVER (`:9002`)**: `SYN-RECV` nhảy vọt lên kịch trần **`128/128`**, trong khi `Workers` L7 vẫn bằng `0/30`. Nhìn sang **CLIENT (`:9003`)**: chuyển **ĐỎ (`TIMEOUT`)**."*

### Bước 2 – Bật Phòng thủ L4 (`SYN Cookies + iptables Firewall`) (50 giây)
- **Thao tác:** Giữ nguyên SYN Flood đang chạy, sang **SERVER (`:9002`)** bấm bật **`🛡️ PHÒNG THỦ L4`**.
- **Nói & Chỉ:**
  *"Server kích hoạt **TCP SYN Cookies** và rule **`iptables`** giới hạn tốc độ SYN. Trên **SERVER**, `SYN-RECV` tụt từ `128` về gần `0`, bộ đếm gói Drop tăng vọt và terminal in trực tiếp lệnh `iptables`; sang **CLIENT (`:9003`)** hồi phục ngay **XANH (`HTTP 200 OK`)**."*
- **Chuyển tiếp:** Sang **ATTACKER (`:9001`)** bấm **`⏹ DỪNG TẤT CẢ TẤN CÔNG`** (chờ ~5–8s cho về `0`).

### Bước 3 – Lách qua Phòng thủ L4 bằng Slowloris L7 (55 giây)
- **Thao tác:** Vẫn giữ Phòng thủ L4 đang BẬT, trên **ATTACKER (`:9001`)** bấm **`▶ BẮT ĐẦU SLOWLORIS (L7)`**.
- **Nói & Chỉ:**
  *"L4 vẫn đang bật bảo vệ, nhưng attacker đổi sang **Slowloris** với băng thông cực nhỏ (chỉ vài KB/s). Trên **Wireshark** (lọc `http || tcp.flags.reset == 1`), bắt tay 3 bước hoàn tất bình thường rồi giữ kết nối HTTP lửng. Trên **SERVER**, `SYN-RECV` giữ mức `0`, nhưng **`Workers` chạm trần `30/30`** và **CLIENT** lại chuyển **ĐỎ (`HTTP 503`)**."*

### Bước 4 – Bật Phòng thủ L7 (`Edge Reverse Proxy Shield`) (50 giây)
- **Thao tác:** Giữ nguyên Slowloris đang chạy, sang **SERVER (`:9002`)** bấm bật **`🛡️ PHÒNG THỦ L7`**.
- **Nói & Chỉ:**
  *"Edge Proxy L7 lập tức áp dụng timeout header và giới hạn kết nối/IP, cắt sạch socket giữ kết nối chậm. Trên **SERVER**, `Workers` tụt ngay về **`0/30`** và **CLIENT** hồi phục **XANH (`HTTP 200 OK`)**."*
- **Kết thúc Demo:** Bấm dừng tấn công / Reset.

---

## Chặng 3: Slide 13 — Tổng Kết & Hỏi Đáp (11:30 – 13:00)
- Chiếu **Slide 13** chốt ma trận **Tầng tấn công ↔ Điểm nghẽn ↔ Cơ chế phòng thủ** → nhấn mạnh thông điệp **Defense-in-Depth** → Mở Q&A.
