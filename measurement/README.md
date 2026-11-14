# Module Đo Lường Định Lượng & Bằng Chứng (Measurement Module)

Module này cung cấp các công cụ định lượng khoa học đáp ứng yêu cầu **FR3 (Traffic Observation)** và **FR5 (Service Availability Benchmark)** theo kịch bản đồ án:

---

## 1. Các chỉ số kỹ thuật đo lường (Key Metrics)

1. **Trạng thái Socket `SYN_RECV` (FR3):**
   - Theo dõi số lượng kết nối đang kẹt trong hàng đợi SYN Backlog của `victim_server`.
   - Trích xuất file chứng cứ bắt gói tin `syn_attack.pcap` bằng `tcpdump`.
2. **Tỷ lệ lỗi kết nối (HTTP Failure Rate % - FR5):**
   $$\text{Failure Rate} = \left(\frac{N_{\text{failed}}}{N_{\text{total}}}\right) \times 100\%$$
3. **Thời gian phản hồi (HTTP Response Time - FR5):**
   - Đo đạc chính xác bằng mili-giây (ms) thời gian hoàn tất một yêu cầu HTTP GET từ `normal_client`.

---

## 2. Các công cụ sử dụng

| Tệp tin | Vị trí chạy | Chức năng |
| :--- | :--- | :--- |
| `capture_evidence.sh` | `victim_server` | Bắt luồng gói tin TCP port 80 trong 15s ra `syn_attack.pcap` và đếm số lượng kết nối `SYN_RECV`. |
| `benchmark_client.py` | `normal_client` | Gửi 50 request HTTP GET (delay 0.2s, timeout 2.0s), tính toán Failure Rate và Latency, lưu vào `results.csv`. |
| `results.csv` | File lưu trữ | Bảng số liệu tổng hợp đối sánh giữa các kịch bản phục vụ vẽ biểu đồ báo cáo. |
