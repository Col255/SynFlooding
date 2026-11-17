# Kịch Bản Thuyết Trình & Demo Live (10–15 Phút) — Bản 3 Cửa Sổ Riêng + Wireshark

**Tổng thời lượng mục tiêu:** ~13 phút (dư ~2 phút Q&A trong khung 10–15 phút).
**Bố cục màn hình khi Demo (rất dễ nhìn cho người xem):**
- **Cửa sổ 1 (Trái):** **ATTACKER (`:9001`)** — Bấm 2 đòn tấn công L4 & L7.
- **Cửa sổ 2 (Giữa):** **SERVER & PHÒNG THỦ (`:9002`)** — 2 biểu đồ L4 vs L7 + 2 công tắc phòng thủ + nút mở **Wireshark Live**.
- **Cửa sổ 3 (Phải trên):** **CLIENT (`:9003`)** — Trạng thái truy cập Xanh/Đỏ + dải 20 lần truy cập gần nhất.
- **Cửa sổ 4 (Phải dưới hoặc nửa màn hình phụ):** **Wireshark Live** (bấm nút **`Mở Wireshark Live`** trên Server `:9002` — **KHÔNG** mở Wireshark bắt card Wi-Fi bên ngoài).

> **Mẹo lọc Wireshark (có sẵn nút bấm Copy ngay trên giao diện Server `:9002`):**
> - Chỉ xem gói tấn công từ Attacker (ẩn Client probe): `ip.addr == <IP_Attacker> && tcp.port == 80`
> - Chỉ xem pha L4 SYN Flood (`[SYN]`): `tcp.flags.syn == 1 && tcp.flags.ack == 0`
> - Chỉ xem pha L7 Slowloris & lúc Proxy ngắt (`HTTP`/`[RST]`): `http || tcp.flags.reset == 1`

---

## Chặng 1: Vấn Đề & Cơ Chế (Slide 1–6 | 0:00 – 4:30)
- **Slide 1–2 (1:20):** Vào thẳng đề tài và Case Study **HTTP/2 Rapid Reset (CVE-2023-44487, 398M rps)** → đặt câu hỏi: *Làm sao bảo vệ cổng dịch vụ khi attacker đổi tầng từ L4 sang L7 với băng thông nhỏ?*
- **Slide 3–5 (2:25):** Tóm tắt 3 Vector (Volumetric / Protocol / Application) & cơ chế **SYN Flood (L4)** vs **Slowloris (L7)**.
- **Slide 6 (0:45):** Giới thiệu 3 thành phần lab (**Attacker – Server – Client** kèm **Wireshark**) → **Chuyển sang màn hình Demo!**

---

## Chặng 2: DEMO TRỰC TIẾP TRÊN 3 GIAO DIỆN + WIRESHARK (4:30 – 9:30)

### Bước 0 – Baseline (15 giây)
- **Chỉ:** Trên **Server (`:9002`)**, cả `SYN-RECV = 0/128` và `Workers = 0/30`. Trên **Client (`:9003`)**, bảng trạng thái Xanh **`TRUY CẬP BÌNH THƯỜNG — HTTP 200`**.

### Bước 1 – Bắt đầu Tấn công L4: SYN Flood (55 giây)
- **Thao tác:** Trên cửa sổ **ATTACKER (`:9001`)**, bấm **`▶ BẮT ĐẦU SYN FLOOD (L4)`**.
- **Nói & Chỉ:**
  *"**Đây là lúc bắt đầu tấn công gửi SYN liên tục** bằng `hping3`. Nhìn **Wireshark**: hàng loạt gói `[SYN]` tràn màn hình không có `[ACK]`. Nhìn sang **SERVER (`:9002`)**: cột Trái `SYN-RECV` nhảy vọt lên **`128/128`** kịch trần, trong khi cột Phải `Workers` vẫn là `0/30`. Nhìn sang **CLIENT (`:9003`)**: bảng chuyển **ĐỎ (`TIMEOUT`)** — người dùng thật không truy cập được!"*

### Bước 2 – Bật Phòng thủ L4 (`SYN Cookies + iptables Firewall`) (50 giây)
- **Thao tác:** **Giữ nguyên SYN Flood đang chạy**, sang cửa sổ **SERVER (`:9002`)**, bấm **`🛡️ PHÒNG THỦ L4: ĐANG TẮT`** để chuyển thành **ĐANG BẬT**.
- **Nói & Chỉ:**
  *"Ngay lập tức, Server kích hoạt **TCP SYN Cookies** và rule **Firewall `iptables`** giới hạn tốc độ SYN từ IP tấn công. Kết quả thấy rõ ngay trên **SERVER**: `SYN-RECV` tụt từ `128` xuống gần `0`, bộ đếm `Đã chặn (iptables)` tăng hàng nghìn gói, và nhìn sang **CLIENT (`:9003`)**: ô lịch sử lập tức chuyển **XANH (`HTTP 200 OK`)**!"*
- **Thao tác chuyển tiếp:** Sang **ATTACKER (`:9001`)** bấm **`⏹ DỪNG TẤT CẢ TẤN CÔNG`** (chờ ~5–8 giây cho `SYN-RECV` và rule tạm tự xả sạch về 0).

### Bước 3 – Lách qua Phòng thủ L4 bằng Slowloris L7 (55 giây)
- **Thao tác:** *(Vẫn giữ Phòng thủ L4 đang BẬT!)* Trên **ATTACKER (`:9001`)**, bấm **`▶ BẮT ĐẦU SLOWLORIS (L7)`**.
- **Nói & Chỉ:**
  *"L4 vẫn đang bật bảo vệ, nhưng attacker đổi sang **Slowloris**: nhìn **ATTACKER** thấy băng thông rất nhỏ (chỉ vài KB/s). Trên **Wireshark**, bắt tay TCP 3 bước hoàn tất bình thường rồi giữ nguyên kết nối HTTP dở dang. Trên **SERVER (`:9002`)**, cột Trái `SYN-RECV` bằng `0` (L4 không bắt được!), nhưng cột Phải **`Workers` chạm trần `30/30`**! Và nhìn **CLIENT (`:9003`)**: lại chuyển **ĐỎ (`HTTP 503 / TIMEOUT`)**!"*

### Bước 4 – Bật Phòng thủ L7 (`Header Timeout 2.5s + Max 8 Conn/IP`) (50 giây)
- **Thao tác:** **Giữ nguyên Slowloris đang chạy**, sang **SERVER (`:9002`)** bấm **`🛡️ PHÒNG THỦ L7: ĐANG TẮT`** để chuyển thành **ĐANG BẬT**.
- **Nói & Chỉ:**
  *"Proxy tầng L7 lập tức áp dụng `Header Timeout 2.5s` và `Max 8 Conn/IP`, cắt cổ toàn bộ socket giữ header chậm (`[RST]`/`408`/`503` hiện trên **Wireshark** và Nhật ký chặn). Trên **SERVER**, `Workers` tụt ngay về **`0/30`**. Trên **CLIENT**, người dùng thật hồi phục **XANH (`HTTP 200 OK`)**!"*
- **Kết thúc Demo:** Bấm **`⏹ DỪNG TẤT CẢ TẤN CÔNG`** trên Attacker (hoặc bấm `Reset` trên Server).

---

## Chặng 3: Phân Tích Giải Pháp Quy Mô Lớn & Kết Luận (Slide 10–13 | 9:30 – 13:00)
- **Slide 10–11:** Tổng kết Detection & cơ chế Reverse Proxy (`nginx.conf`: `client_header_timeout`, `limit_conn`, `limit_req`) + bảng so sánh Before vs After.
- **Slide 12:** Giải pháp quy mô ISP/Cloud cho Volumetric (*RFC 3704*, *RTBH Black Hole*, *Cloudflare/Akamai Scrubbing*, *Absorb/Degrade/Shutdown*).
- **Slide 13:** Chốt ma trận giải pháp theo từng tầng → Hỏi đáp Q&A.
