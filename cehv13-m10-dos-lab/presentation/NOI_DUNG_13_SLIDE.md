# Nội Dung Chi Tiết 13 Slide PowerPoint (Module 10: Denial-of-Service)

> **Nguyên tắc thiết kế:** Đúng **13 slide** (trong khung 10–15 slide), **bỏ qua khái niệm nhập môn** ("an ninh mạng là gì..."), đi thẳng vào **Vấn đề → Tấn công L4 & L7 → Demo 3 màn hình (Attacker – Server – Client) + Wireshark → Giải pháp Phòng thủ đa tầng → Đối chiếu Before/After**.

---

### Slide 1: Trang Bìa
- **Tiêu đề:** Tấn Công Từ Chối Dịch Vụ (DoS/DDoS) & Phòng Thủ Đa Tầng Thực Nghiệm
- **Phụ đề:** Chuyên đề Module 10 – CEHv13 | Nhóm thực hiện: [Điền tên thành viên]

### Slide 2: Bài Toán Thực Tế – Tại Sao DoS/DDoS Vẫn Là Hiểm Họa Top Đầu?
- **Vấn đề:** DoS/DDoS đánh sập **tính sẵn sàng (Availability)** của hệ thống, gây gián đoạn dịch vụ, thiệt hại tài chính và uy tín.
- **Case study thực tế (CEHv13 Module 10, trang 19–21):** **HTTP/2 "Rapid Reset" (CVE-2023-44487, CVSS 7.5)** nhắm vào Google Cloud (09/2023), đạt đỉnh **398 triệu requests/giây**.
- **Câu hỏi xuyên suốt bài báo cáo:** *Làm sao bảo vệ một cổng dịch vụ trước kẻ tấn công chỉ dùng băng thông nhỏ, khi chúng liên tục đổi tầng tấn công từ L4 sang L7?*

### Slide 3: Phân Loại 3 Vector Tấn Công & Mô Hình Botnet
*(Bảng so sánh 3 cột từ Slide 10 CEHv13)*
- **Volumetric (`bps`):** Làm ngập băng thông đường truyền (UDP/ICMP Flood, NTP `monlist` Amplification).
- **Protocol (`pps/cps`):** Làm cạn bảng trạng thái kết nối (**TCP SYN Flood**, Fragmentation, TCP SACK Panic).
- **Application Layer – L7 (`rps`):** Băng thông nhỏ nhưng làm cạn tài nguyên ứng dụng (**Slowloris**, HTTP GET/POST Flood).
- **Sơ đồ tóm tắt Botnet:** Attacker → C&C Handler → Zombies → Primary Target.
- **Phạm vi thực nghiệm:** Tấn công & phòng thủ trực tiếp **SYN Flood (L4)** và **Slowloris (L7)** trên cùng 1 mục tiêu để thấy rõ ranh giới bảo vệ của từng tầng.

### Slide 4: Nấc Thang 1 – Tấn Công Tầng Giao Vận (L4): TCP SYN Flood
- **Cơ chế:** Lợi dụng bắt tay 3 bước (`SYN → SYN/ACK → ACK`), attacker gửi liên tục gói `SYN` nhưng **không hoàn tất `ACK`**.
- **Điểm nghẽn:** Kernel phải giữ kết nối bán mở (`SYN_RECV`) trong hàng đợi *listen queue* (mặc định chờ tới ~75s trong giáo trình) → tràn hàng đợi (`511/511`), người dùng thật không bắt tay TCP được (**Timeout**).
- **Nhận diện trên Wireshark:** Ngập tràn gói `[SYN]` liên tiếp không kèm `[ACK]` hoàn tất phiên.

### Slide 5: Nấc Thang 2 – Tấn Công Tầng Ứng Dụng (L7): Slowloris
- **Vì sao cần đánh L7?** Nếu server đã chặn SYN Flood, attacker chuyển sang *bắt tay TCP hoàn chỉnh đàng hoàng*, sau đó gửi HTTP header dở dang (thiếu `\r\n\r\n`) và giữ sống định kỳ.
- **Điểm nghẽn:** Tốn băng thông cực nhỏ (**chỉ ~1–2 KB/s**) nhưng chiếm trọn **Worker Pool (`30/30`)** của ứng dụng web.
- **Nhận diện trên Wireshark:** 3-way handshake thành công bình thường, sau đó nhiều kết nối giữ `HTTP GET` không kết thúc.

### Slide 6: Kiến Trúc Lab Thống Nhất (`unified-demo`: 1 Mục Tiêu – 2 Tầng)
*(Sơ đồ pipeline 4 khối chạy cô lập trong mạng Docker `internal: true`)*
1. **Attacker (`doslab_u_attacker`):** Tích hợp `hping3` (L4 SYN Flood) và `slowloris_worker` (L7 Slowloris).
2. **Target (`doslab_u_target:80`):** 1 mục tiêu duy nhất gồm **TCP Kernel (L4)** + **Edge Proxy (`:80`)** + **Web Backend (`:8081`, 30 workers)**; gắn `tcpdump` truyền trực tiếp sang **Wireshark**.
3. **Legitimate Client (`doslab_u_client`):** Gửi request hợp pháp mỗi `0.7s` để đo trạng thái `200 OK` vs `Timeout/503`.
4. **3 Giao Diện Tách Vai (`START_UNIFIED_DEMO.bat`):**
   - **Attacker Console (`http://127.0.0.1:9001`):** Điều khiển `SYN Flood (L4)` / `Slowloris (L7)` và dòng log lệnh thực thi.
   - **Server & Defense (`http://127.0.0.1:9002`):** Theo dõi L4 `SYN-RECV` + gói `iptables` Drop, L7 `Worker Pool`, bật/tắt L4 Defense, L7 Shield và **Wireshark Live**.
   - **Client Monitor (`http://127.0.0.1:9003`):** Hiển thị trạng thái người dùng thật (`HTTP 200 OK` / `TIMEOUT` / `HTTP 503`), 20 thanh lịch sử và nút test truy cập trực tiếp.

### Slide 7: [DEMO PHẦN 1] Tấn Công L4 (SYN Flood) & Tác Động Lên Hệ Thống
- Chạy **SYN Flood** khi Phòng thủ L4 = OFF (`tcp_syncookies = 0`):
  - **Wireshark:** Tràn ngập gói `[SYN]`.
  - **Server – Tầng L4 (`SYN-RECV`):** Dựng đứng lên mức trần hàng đợi (`128`).
  - **Server – Tầng L7 (`Worker Pool`):** Vẫn bằng **`0/30`** (chưa vào được tới App).
  - **Client:** Mất kết nối (**TIMEOUT**).

### Slide 8: Giải Pháp L4 & Demo Hồi Phục (SYN Cookies + Kernel L4 Rate Limit)
- **Nguyên lý kết hợp 2 lớp tại Kernel L4:**
  1. **`net.ipv4.tcp_syncookies = 1`:** Khi hàng đợi gần đầy, Kernel không cấp phát bộ nhớ vào `listen queue` mà mã hóa trạng thái vào Initial Sequence Number (`ISN`) của gói `SYN/ACK`, cho phép người dùng hợp lệ vẫn hoàn tất bắt tay khi nhận `ACK` đúng.
  2. **`iptables L4_SHIELD` (SYN Rate Limit & Auto-Drop):** Phát hiện IP gửi ngập `SYN_RECV`, giới hạn tốc độ SYN và `DROP` phần gói flood dư thừa ngay tại Kernel.
- **Bổ sung tầng L4:** Giảm `tcp_synack_retries` & Cisco **TCP Intercept**.
- **Kết quả Demo:** Bật **Phòng thủ L4** ngay khi `hping3` vẫn chạy → `SYN-RECV` tụt từ `128` xuống còn ~`0–3`, bộ đếm gói Drop tăng vọt và **Client** hồi phục **`HTTP 200 OK`**.

### Slide 9: [DEMO PHẦN 2] Lách Qua Phòng Thủ L4 Bằng Slowloris (L7)
- Giữ nguyên **SYN Cookies = ON**, chuyển sang chạy **Slowloris**:
  - **Biểu đồ L4 (`SYN-RECV`):** Giữ mức **`0`** — chứng minh phòng thủ L4 không chặn được đòn L7!
  - **Wireshark:** Bắt tay 3 bước hoàn tất bình thường, nhưng các luồng HTTP bị giữ mở lửng.
  - **Biểu đồ L7 (`Worker Pool`):** Bão hòa **`30/30`**, băng thông chỉ vài KB/s → User thật lại bị **503 / TIMEOUT**.

### Slide 10: Cơ Chế Phát Hiện (Detection) & Pháp Chứng (Forensics)
- **Kỹ thuật phát hiện (CEHv13 Slide 25 & 31):**
  - *Activity Profiling* & *Change-Point Detection:* Tách biệt bất thường L4 (đột biến `SYN-RECV`) vs L7 (socket mở lâu, worker pool chạm trần dù băng thông thấp).
  - *Post-Attack Forensics:* Ghi nhật ký `forensics.jsonl` (IP vi phạm, loại chặn, thời điểm) để tinh chỉnh rule firewall.

### Slide 11: Giải Pháp L7 & Demo Phòng Thủ Đa Tầng (Defense-in-Depth)
- **Cơ chế Edge Reverse Proxy (`target_node.py` / `nginx.conf`):**
  1. **Header Buffering & Timeout (`client_header_timeout 2.5s–3s`):** Gom đủ HTTP header ở biên trước khi đẩy vào Backend → cắt cổ Slowloris (`408`/`RST`).
  2. **Connection Limit (`limit_conn = 8 / IP`):** Ngăn 1 IP giữ hàng chục socket treo (`503`).
  3. **Rate Limit (`limit_req`) + Auto-Quarantine:** Chặn burst (`429`) & tạm cách ly IP (`403`).
- **Kết quả Demo (Before vs After & Multi-Vector):** Bật L7 Shield → Worker Pool tụt về `0/30`, User thật hồi **`HTTP 200`**, và đứng vững ngay cả khi đánh **Multi-Vector (SYN Flood + Slowloris cùng lúc)**.

### Slide 12: Phòng Thủ Quy Mô Lớn (ISP & Cloud Level)
- Khi gặp tấn công **Volumetric** lớn hơn băng thông đường truyền vật lý, phải kết hợp giải pháp biên mạng & ISP/Cloud (CEHv13 trang 56, 59, 67–79):
  - **Chống IP Spoofing:** *Ingress / Egress Filtering* (RFC 3704).
  - **Cắt lưu lượng tại Router ISP:** *Black Hole Filtering (RTBH / BGP null0)*.
  - **Làm sạch lưu lượng (Scrubbing) & Cloud WAF:** Cloudflare, Akamai; cùng 3 chiến lược ứng phó (*Absorbing – Degrading Services – Shutting Down*).

### Slide 13: Tổng Kết – Ma Trận Tấn Công & Giải Pháp
- **L4 (`SYN Flood`):** Nghẽn `SYN-RECV` → `SYN Cookies` + `TCP Intercept` + `Rate Limit`.
- **L7 (`Slowloris / HTTP Flood`):** Nghẽn `Worker Pool` (băng thông nhỏ) → Edge Reverse Proxy (`Header Timeout` + `limit_conn` + `limit_req`).
- **L3/L4 (`Volumetric`):** Nghẽn đường truyền → ISP `RTBH` + `RFC 3704` + `Cloud Scrubbing`.
- **Thông điệp kết:** Bảo mật sẵn sàng đòi hỏi **Phòng thủ theo chiều sâu (Defense-in-Depth)** ở đúng từng tầng nghẽn.
