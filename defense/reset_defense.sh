#!/bin/bash
# ==============================================================================
# KHÔI PHỤC TRẠNG THÁI CHƯA PHÒNG THỦ (VULNERABLE BASELINE SETUP)
# Chạy trên: victim_server (192.168.100.10)
# ==============================================================================
# Trích từ Giai đoạn 3 trong Báo cáo:
# Tạm thời tắt SYN Cookies và thu hẹp hàng đợi SYN Backlog về 128 (và ép Nginx
# listen backlog = 64) để mô phỏng máy chủ phòng thủ kém trước khi tấn công.
#
# *LƯU Ý KỸ THUẬT QUAN TRỌNG TRONG DOCKER:*
# Khi sử dụng IP Spoofing ngoài dải mạng, Host Gateway (192.168.100.1) sẽ gửi gói
# TCP RST làm hủy trạng thái SYN_RECV. Script thêm luật chặn gói RST này để
# mô phỏng chính xác môi trường Internet thực tế (hàng đợi nghẽn kịch trần).
# ==============================================================================

echo "=============================================================================="
echo " [-] ĐƯA MÁY CHỦ VỀ TRẠNG THÁI CHƯA PHÒNG THỦ (VULNERABLE BASELINE)"
echo "=============================================================================="

# 1. Tắt SYN Cookies (bắt buộc server cấp phát TCB vào RAM)
sysctl -w net.ipv4.tcp_syncookies=0

# 2. Thu hẹp hàng đợi kết nối nửa mở của kernel
sysctl -w net.ipv4.tcp_max_syn_backlog=128
sysctl -w net.core.somaxconn=128

# 3. Đặt số lần gửi lại SYN-ACK về mặc định của Linux (5 lần)
sysctl -w net.ipv4.tcp_synack_retries=5

# 4. Gỡ bỏ chuỗi tường lửa bảo vệ SYN_PROTECT
iptables -P INPUT ACCEPT
iptables -F INPUT
iptables -F SYN_PROTECT 2>/dev/null || true
iptables -X SYN_PROTECT 2>/dev/null || true

# 5. Chặn gói RST từ Gateway để giữ nguyên trạng thái kết nối nửa mở trong Docker
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

# 6. Ép cấu hình listen của Nginx nhận đúng kích thước hàng đợi nhỏ (backlog=64)
sed -i -E "s/listen (\[::\]:)?80 default_server( backlog=[0-9]+)?;/listen \180 default_server backlog=64;/g" /etc/nginx/sites-available/default 2>/dev/null || true
nginx -s reload 2>/dev/null || true

echo ""
echo "[+] ĐÃ THIẾT LẬP THÀNH CÔNG TRẠNG THÁI DỄ BỊ TỔN THƯƠNG (CHƯA PHÒNG THỦ):"
echo " - net.ipv4.tcp_syncookies       = 0   (Đã tắt SYN Cookies)"
echo " - net.ipv4.tcp_max_syn_backlog   = 128 (Hàng đợi kernel giới hạn)"
echo " - Nginx listen backlog          = 64  (Send-Q giới hạn 64)"
echo " - net.ipv4.tcp_synack_retries   = 5   (Giữ kết nối rác lâu)"
echo " - Tường lửa SYN_PROTECT         = Đã gỡ bỏ"
echo "=============================================================================="
