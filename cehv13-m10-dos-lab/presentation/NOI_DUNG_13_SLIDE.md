# Nội Dung Chi Tiết 13 Slide PowerPoint (Module 10: Denial-of-Service)

> **Nguyên tắc thiết kế:** Đúng **13 slide** (trong khung 10–15 slide), bỏ qua khái niệm nhập môn; **tập trung phân tích sâu cơ chế tấn công & cơ chế phòng thủ theo từng tầng** (dựa trên giáo trình EC-Council CEHv13 Module 10). Phần demo thực nghiệm tách thành **1 slide chuyển cảnh gọn nhẹ** để người trình bày tự chạy live.

---

### Slide 1: Trang Bìa
- **Tiêu đề:** Tấn Công Từ Chối Dịch Vụ (DoS/DDoS) — Phân Tích Cơ Chế & Phòng Thủ Đa Tầng
- **Phụ đề:** Chuyên đề Module 10 – CEHv13 | Nhóm thực hiện: [Điền tên thành viên]

---

### Slide 2: Bài Toán Thực Tế & Case Study Hiện Đại
- **Bản chất mối đe dọa:** Khác với tấn công đánh cắp dữ liệu, DoS/DDoS đánh trực tiếp vào **tính sẵn sàng (Availability)** — làm cạn băng thông, bảng trạng thái kết nối, hoặc tài nguyên ứng dụng khiến người dùng hợp lệ bị từ chối truy cập.
- **Case Study điển hình — HTTP/2 "Rapid Reset" (CVE-2023-44487, CVSS 7.5 | CEHv13 tr. 19–21):**
  - Nhắm vào hạ tầng Google Cloud (08–09/2023), đạt đỉnh **398 triệu requests/giây**.
  - **Cơ chế khai thác:** Lạm dụng tính năng *stream multiplexing* của HTTP/2 (mở tối đa ~100 luồng song song trên 1 kết nối TCP), gửi ồ ạt request rồi lập tức gửi **`RST`** hủy stream → tạo bão reset vượt khả năng xử lý mà không cần quá nhiều kết nối TCP mới.
- **Câu hỏi xuyên suốt:** *Khi kẻ tấn công chuyển dịch linh hoạt từ đè băng thông sang khai thác điểm nghẽn giao thức (L4) và tài nguyên ứng dụng (L7) với băng thông rất nhỏ, hệ thống cần cơ chế phòng thủ theo tầng như thế nào?*

---

### Slide 3: Phân Loại 3 Vector Tấn Công & Kiến Trúc Botnet
*(Bảng so sánh 3 cột từ Slide 10 CEHv13 + Sơ đồ Botnet tr. 8–16)*
1. **Volumetric Attacks (`bps`):** Làm cạn kiệt **băng thông đường truyền** thông qua lưu lượng khổng lồ (*Flood* và *Amplification*).
2. **Protocol Attacks (`pps` / `cps`):** Làm cạn kiệt **bảng trạng thái kết nối** của firewall, load balancer và hệ điều hành (*TCP SYN Flood, Spoofed Session, Fragmentation, TCP SACK Panic*).
3. **Application Layer Attacks – L7 (`rps`):** Dùng **băng thông nhỏ** nhưng gửi yêu cầu giống người thật để làm cạn **worker/thread/DB** của ứng dụng (*Slowloris, HTTP GET/POST Flood*).
- **Kiến trúc & Vòng đời Botnet (tr. 8–16, 19):**
  - Chuỗi điều khiển: **Attacker → C&C Handler → Compromised Systems / Zombies (cả PC & thiết bị di động Android APK) → Primary Target**.
  - **Kỹ thuật quét & lây lan:** Quét *Hit-list* / *Permutation* (tránh lây trùng bằng hoán vị 32-bit); phát tán mã độc theo 3 mô hình *Central Source* (HTTP/FTP/RPC), *Back-chaining* (TFTP) và *Autonomous*.

---

### Slide 4: Cơ Chế Tấn Công Tầng Mạng & Khuếch Đại (Volumetric & Reflection)
*(CEHv13 Module 10, tr. 27–33, 47–48)*
- **Flooding trực tiếp (UDP / ICMP Flood & Pulse Wave):**
  - **UDP Flood:** Bắn gói UDP giả mạo IP vào các cổng ngẫu nhiên → server phải kiểm tra dịch vụ không tồn tại và phản hồi hàng loạt *ICMP Destination Unreachable*, làm nghẽn cả hai chiều.
  - **Pulse Wave DDoS:** Tung các đợt xung khổng lồ (từ **300 Gbps** trở lên) lặp lại theo chu kỳ ~10 phút, gây khó khăn cho các cơ chế tự động điều tiết lưu lượng chậm.
- **Khuếch đại & Phản xạ (Amplification / DRDoS):**
  - **Smurf & NTP `monlist` Amplification:** Giả mạo IP nguồn là IP nạn nhân gửi tới mạng broadcast (Smurf) hoặc máy chủ NTP mở lệnh **`monlist`** → phản hồi lớn gấp hàng chục/trăm lần gói tin gốc dồn vào nạn nhân.
  - **DRDoS (Distributed Reflection DoS):** Attacker sai *Zombies* gửi gói **`TCP SYN`** giả mạo IP nạn nhân tới hàng loạt máy chủ trung gian hợp lệ (*Reflectors*) → toàn bộ *Reflectors* bắn ngược **`SYN/ACK`** liên tục (kèm retry) làm ngập nạn nhân và che giấu hoàn toàn nguồn gốc thật.

---

### Slide 5: Phân Tích Cơ Chế Tấn Công Tầng Giao Vận (L4 — Protocol)
*(CEHv13 Module 10, tr. 34–38, 45–46)*
- **TCP SYN Flood — Điểm nghẽn bắt tay 3 bước (`SYN → SYN/ACK → ACK`):**
  - Server nhận `SYN` phải cấp phát bộ nhớ giữ trạng thái bán mở **`SYN_RECV`** trong *listen queue* và đợi `ACK` (mặc định có thể giữ tới ~`75 giây` nếu không nhận phản hồi).
  - Attacker bơm liên tục gói `SYN` không hoàn tất `ACK` (hoặc chặn `RST` / giả IP) → đầy cứng *listen queue* → **người dùng hợp lệ bị từ chối kết nối dù CPU/RAM server vẫn rảnh**.
- **Các kỹ thuật né lọc & phá hủy trạng thái L4 khác:**
  - **Spoofed Session Flood:** Bỏ qua hoàn toàn bước `SYN`, chỉ gửi ngập gói **`ACK`** kèm **`RST`/`FIN`** để vượt qua các rule tường lửa chỉ lọc gói `SYN`.
  - **Fragmentation Attack:** Gửi các phân mảnh TCP/UDP (`1500+ byte`) với nội dung ngẫu nhiên để né kiểm tra ở router/IDS/IPS và làm quá tải bộ nhớ tái hợp gói tin.
  - **TCP SACK Panic:** Gửi chuỗi gói SACK ép **`MSS` nhỏ nhất (`48 bytes`)**, khiến danh sách liên kết *Socket Buffer (`SKB`, giới hạn 17 segments)* trên Linux bị tràn số nguyên (*integer overflow*) gây **Kernel Panic**.

---

### Slide 6: Phân Tích Cơ Chế Tấn Công Tầng Ứng Dụng (L7 & Multi-Vector)
*(CEHv13 Module 10, tr. 39–42)*
- **Vì sao phòng thủ L4 không chặn được L7?** Tấn công L7 thực hiện **bắt tay TCP 3 bước hoàn chỉnh đàng hoàng**, không giả mạo IP và chỉ dùng lưu lượng rất nhỏ, nên lưu lượng đi xuyên qua tường lửa L4 như người dùng hợp lệ.
- **Slowloris & HTTP Slow GET/POST:**
  - **Slowloris / HTTP GET chậm:** Mở nhiều kết nối cùng lúc, gửi HTTP header dở dang (thiếu kết thúc `\r\n\r\n`) và nhỏ giọt từng header giữ sống định kỳ → server phải giữ mở socket & luồng xử lý (**Worker Pool / Connection Pool**) chờ hoàn tất cho đến khi hết chỗ.
  - **HTTP POST chậm:** Gửi xong header hợp lệ kèm `Content-Length` lớn, nhưng truyền phần *message body* cực chậm để khóa cứng tiến trình ứng dụng.
- **HTTP Flood nâng cao & Multi-Vector:**
  - *Single-Session / Single-Request* (nhiều request trong 1 gói/phiên) và *Recursive / Random Recursive GET* (giả vờ duyệt trang web hợp pháp để né firewall).
  - **Multi-Vector Attack:** Phối hợp **tuần tự hoặc song song** Volumetric + Protocol + L7 để làm phân tán và kiệt sức đội ngũ vận hành khi vá sai tầng.

---

### Slide 7: Cơ Chế Phòng Thủ Tầng Mạng & Chống Giả Mạo (Anti-Spoofing)
*(CEHv13 Module 10, tr. 59–60, 67–68)*
- **Nguyên tắc cốt lõi:** Triệt tiêu gói tin giả mạo IP nguồn — gốc rễ của *SYN Flood IP giả*, *Smurf*, *NTP Amplification* và *DRDoS*.
- **4 Cơ chế lọc tại biên mạng & router:**
  1. **Ingress Filtering (RFC 3704 & Bogon ACL):** Router/ISP kiểm tra tiền tố địa chỉ nguồn trên chiều đi vào; chặn ngay gói có IP không khớp dải định tuyến hợp lệ hoặc thuộc danh sách **Bogon** (IP chưa cấp phát/dành riêng).
  2. **Egress Filtering:** Quét IP nguồn chiều đi ra khỏi mạng nội bộ, chỉ cho phép gói có prefix thuộc mạng tổ chức đi ra → ngăn chặn hệ thống bị lợi dụng làm bàn đạp phát tán DDoS và chặn kết nối ngược từ payload exploit.
  3. **IP Source Guard (Switch/Router):** Ràng buộc bảng **DHCP Snooping** (IP ↔ MAC ↔ Port), chặn bot phát gói tin giả mạo IP trong mạng LAN.
  4. **Source IP Reputation Filtering:** Đồng bộ danh sách đen IP botnet, darknet và malware theo thời gian thực (như Cisco Global Correlation).

---

### Slide 8: Cơ Chế Phòng Thủ Tầng Giao Vận (L4 — Bảo Vệ TCP Stack)
*(CEHv13 Module 10, tr. 36, 46, 59–60, 71–72)*
- **1. TCP SYN Cookies (`net.ipv4.tcp_syncookies = 1`):**
  - Khi hàng đợi `SYN_RECV` chạm ngưỡng đầy, Kernel **ngừng cấp phát bộ nhớ trạng thái** cho gói `SYN` mới.
  - Thông tin kết nối (IP, port, MSS, timestamp) được băm mật mã vào trường **Initial Sequence Number (`ISN`)** của gói `SYN/ACK` gửi trả. Server **chỉ tạo kết nối khi client gửi lại `ACK` hợp lệ** (có `ack_num = ISN + 1`).
- **2. Cisco TCP Intercept (`ip tcp intercept mode intercept | watch`):**
  - **Chế độ Active (`intercept`):** Router đứng làm trung gian, tự bắt tay 3 bước với client thay cho server; **chỉ khi client chứng minh được IP thật (trả `ACK`)**, router mới bắt tay với server rồi nối 2 nửa kết nối lại.
  - **Chế độ Passive (`watch`):** Cho lưu lượng đi qua và giám sát; nếu quá `30 giây` chưa xong bắt tay, router chủ động bắn **`RST`** giải phóng hàng đợi cho server.
- **3. Tinh chỉnh TCP Stack & Lọc gói bất thường:**
  - Giảm thời gian chờ `SYN_RECV` và số lần gửi lại `SYN/ACK` (`SynAttackProtect` / `tcp_synack_retries`).
  - Giới hạn tốc độ gói `SYN` theo IP nguồn (**Rate Limiting L4/L5** qua `iptables`/`nftables`) và chặn gói TCP có **`MSS` quá nhỏ (48 bytes)** để chống SACK Panic.

---

### Slide 9: Cơ Chế Phòng Thủ Tầng Ứng Dụng (L7 — Bảo Vệ Worker Pool)
*(CEHv13 Module 10, tr. 25, 63, 69)*
- **Nguyên tắc:** Không để các kết nối chậm hoặc yêu cầu rác chạm được vào **Backend Worker Pool & Database**. Đẩy kiểm soát ra **Edge Reverse Proxy / WAF**:
  1. **Header/Body Buffering & Timeout nghiêm ngặt:** Proxy biên gom trọn vẹn toàn bộ HTTP Header (kèm thời gian chờ ngắn) trước khi chuyển tiếp vào Backend. Nếu client giữ kết nối dở dang kiểu Slowloris/Slow POST quá ngưỡng → lập tức ngắt (`408 Request Timeout` / `RST`).
  2. **Giới hạn kết nối & Tần suất (Connection Limit & Rate Limiting):** Chặn mỗi IP chỉ giữ tối đa số socket đồng thời nhất định (`503`) và giới hạn số request/giây (`429`), kết hợp **tự động cách ly tạm (Quarantine)** khi tái phạm.
  3. **Throttling & Drop Requests (Computational Puzzle — tr. 63):**
     - **Throttling:** Bộ điều tiết *min-max fair router* bóp băng thông/lưu lượng đột biến về ngưỡng an toàn cho server (lưu ý rủi ro lọc nhầm nhẹ lưu lượng thật nếu cấu hình quá gắt).
     - **Challenge-Response / Puzzle:** Khi tải tăng cao, buộc client giải bài toán tiêu tốn CPU/bộ nhớ (hoặc JS/CAPTCHA challenge) trước khi cấp tài nguyên → khiến máy zombie chậm lại hoặc bỏ cuộc.
  4. **Load Balancing & Replicated Servers:** Phân tải qua cụm nhiều server dự phòng để triệt tiêu điểm nghẽn đơn.

---

### Slide 10: Phát Hiện Sớm, Đánh Lạc Hướng & Pháp Chứng Sau Tấn Công
*(CEHv13 Module 10, tr. 54–55, 61–62, 65–66)*
- **3 Kỹ thuật Phát hiện bất thường (Detection Techniques — Slide 25):**
  1. **Activity Profiling:** Gom cụm các *packet flow* dựa trên header (`Src/Dst IP, Port, Protocol`) để đo tốc độ gói trung bình và tính **Entropy** (độ ngẫu nhiên) — khi số cụm hoặc mức hoạt động tăng đột biến sẽ báo động DDoS.
  2. **Sequential Change-Point Detection (Thuật toán `CUSUM`):** Chuyển luồng mạng thành chuỗi thời gian; thuật toán tổng tích lũy **CUSUM** tách chính xác điểm gãy lệch khỏi giá trị trung bình cục bộ bình thường.
  3. **Wavelet-Based Signal Analysis:** Phân rã tín hiệu lưu lượng theo phổ tần số; lưu lượng bình thường nằm ở **tần số thấp**, còn tấn công tạo ra đột biến năng lượng **tần số cao** tách biệt khỏi nhiễu nền.
- **Đánh lạc hướng (Deflect Attacks):** Triển khai **Honeypot / Honeynet** (tương tác thấp/cao, dẫn hướng nghi ngờ qua IPsec) nhằm dụ C&C/Agent lộ công cụ, TTP và tự động khóa IP nguồn ngay tại switch/firewall.
- **Pháp chứng sau tấn công (Post-Attack Forensics):** *Traffic Pattern Analysis* (tối ưu lại bộ lọc), *Packet Traceback* (truy ngược dấu vết tới nguồn phát tán) và *Event Log Analysis* (đối chiếu log Firewall/IDS/Sniffer).

---

### Slide 11: Chiến Lược Ứng Phó & Phòng Thủ Quy Mô Lớn (ISP & Cloud)
*(CEHv13 Module 10, tr. 49, 56, 68–70, 77–79)*
- **3 Chiến lược ứng phó khi hệ thống bị quá tải (Slide 26):**
  - **Absorbing the Attack:** Dùng năng lực dự phòng đã chuẩn bị trước để hấp thụ đòn đánh *(tốn chi phí duy trì hạ tầng dư)*.
  - **Degrading Services:** Chủ động ngắt dịch vụ phụ để dồn tài nguyên giữ sống **dịch vụ cốt lõi**.
  - **Shutting Down Services:** Tạm tắt toàn bộ dịch vụ cho đến khi đợt tấn công dịu xuống *(giải pháp cuối cùng)*.
- **Phòng thủ ở tầng ISP & Cloud (khi Volumetric vượt băng thông đường truyền):**
  - **RTBH — Remotely Triggered Black Hole Filtering (`BGP null0`):** Phối hợp ISP phát tuyến BGP ném toàn bộ lưu lượng tới IP nạn nhân vào giao diện ảo **`null0`** tại router nhà mạng trước khi làm nghẽn đường truyền doanh nghiệp.
  - **Clean-Pipes & Cloud Scrubbing (Cloudflare 100 Tbps, Akamai, Imperva):** Dùng **BGP / DNS Swing** chuyển hướng toàn bộ lưu lượng qua trung tâm lọc đám mây (lọc sạch L3–L7) rồi mới trả lưu lượng sạch về hệ thống gốc.

---

### Slide 12: Thực Nghiệm Trực Quan (Live Demo)
- **Minh họa thực tế cơ chế tấn công & phòng thủ theo tầng:**
  - Quan sát luồng gói tin và tác động trực tiếp khi kẻ tấn công chuyển hướng từ **Tầng Giao vận (L4)** sang **Tầng Ứng dụng (L7)** — và hiệu quả cách ly của từng lớp phòng thủ tương ứng.

*(Người trình bày chuyển màn hình sang phần Demo Live)*

---

### Slide 13: Tổng Kết — Ma Trận Tấn Công & Phòng Thủ Đa Tầng
| Tầng / Vector | Cơ chế gây nghẽn chính | Cơ chế phòng thủ trọng tâm |
| :--- | :--- | :--- |
| **L3 / Volumetric (`bps`)** | Ngập băng thông đường truyền, phản xạ/khuếch đại (`UDP/ICMP, Smurf, NTP monlist, DRDoS`) | **RFC 3704 Ingress/Egress Filtering**, **RTBH (`BGP null0`)**, **ISP Clean-Pipes & Cloud Scrubbing** |
| **L4 / Protocol (`pps`)** | Tràn bảng trạng thái & `listen queue` (`SYN Flood, Spoofed ACK, Fragmentation, SACK Panic`) | **TCP SYN Cookies**, **Cisco TCP Intercept**, **L4 Rate Limiting**, **Lọc MSS bất thường** |
| **L7 / Application (`rps`)** | Giữ socket & khóa cứng Worker/DB với băng thông nhỏ (`Slowloris, HTTP GET/POST, Rapid Reset`) | **Edge Proxy Header Timeout**, **Per-IP Conn/Rate Limit**, **Throttling / Puzzle Challenge**, **Load Balancing** |
| **Giám sát & Điều phối** | Đổi vector liên tục (*Multi-Vector*), che giấu nguồn qua *Botnet* | **CUSUM / Activity Profiling / Wavelet**, **Honeypot**, **Post-Attack Forensics** |

- **Thông điệp cốt lõi:** Không có một tường lửa đơn lẻ nào chống được mọi loại DoS/DDoS — hệ thống chỉ đứng vững khi triển khai **Phòng thủ theo chiều sâu (Defense-in-Depth)**, khóa đúng điểm nghẽn ở từng tầng từ **ISP/Cloud → L3/L4 Kernel → Edge L7 Proxy**.
