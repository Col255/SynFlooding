#!/bin/bash
# ==============================================================================
# CẤP ĐỘ 2: PHÒNG THỦ TẠI LỚP MÁY CHỦ (HOST LAYER - TCP SYN COOKIES & KERNEL TUNING)
# Chạy trên: victim_server (192.168.100.10)
# ==============================================================================
# Trích từ mục 1.3 và Giai đoạn 4 trong Báo cáo:
# 1. Bật TCP SYN Cookies: Loại bỏ việc lưu TCB vào RAM khi chưa hoàn tất bắt tay.
# 2. Tăng dung lượng hàng đợi kết nối nửa mở lên 2048.
# 3. Giảm số lần gửi lại gói SYN-ACK xuống 1 lần để nhanh chóng giải phóng kết nối rác.
# ==============================================================================

set -e

echo "=============================================================================="
echo " [!] KÍCH HOẠT PHÒNG THỦ LỚP MÁY CHỦ (HOST LAYER HARDENING)"
echo "=============================================================================="

# 1. Kích hoạt TCP SYN Cookies (Khắc phục triệt để cạn kiệt hàng đợi RAM)
echo "[*] Kích hoạt TCP SYN Cookies (net.ipv4.tcp_syncookies = 1)..."
sysctl -w net.ipv4.tcp_syncookies=1

# 2. Mở rộng dung lượng hàng đợi bộ đệm kết nối nửa mở lên 2048
echo "[*] Mở rộng SYN Backlog Queue (net.ipv4.tcp_max_syn_backlog = 2048)..."
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.core.somaxconn=2048

# 3. Giảm số lần truyền lại gói SYN-ACK xuống còn 1 lần (mặc định là 5)
echo "[*] Rút ngắn chu kỳ giải phóng kết nối rác (net.ipv4.tcp_synack_retries = 1)..."
sysctl -w net.ipv4.tcp_synack_retries=1

# 4. Mở rộng cấu hình listen backlog của Nginx lên 2048
sed -i -E "s/listen (\[::\]:)?80 default_server( backlog=[0-9]+)?;/listen \180 default_server backlog=2048;/g" /etc/nginx/sites-available/default 2>/dev/null || true
nginx -s reload 2>/dev/null || true

echo ""
echo "=============================================================================="
echo " [+] ĐÃ BẬT PHÒNG THỦ LỚP MÁY CHỦ THÀNH CÔNG!"
echo " Thông số hiện hành:"
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.core.somaxconn net.ipv4.tcp_synack_retries
echo "=============================================================================="
