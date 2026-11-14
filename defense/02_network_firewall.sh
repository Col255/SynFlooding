#!/bin/bash
# ==============================================================================
# CẤP ĐỘ 1: PHÒNG THỦ TẠI LỚP MẠNG (NETWORK LAYER - TƯỜNG LỬA IPTABLES)
# Chạy trên: victim_server (192.168.100.10)
# ==============================================================================
# Trích từ mục 1.3 và Giai đoạn 4 trong Báo cáo:
# Áp dụng thuật toán giới hạn tần suất (Rate Limiting) theo cơ chế Token Bucket:
# Cho phép tối đa 20 kết nối SYN/giây, hạn mức bùng nổ (burst) tối đa 30 gói.
# Toàn bộ gói tin SYN vượt quá ngưỡng trên sẽ bị DROP ngay tại card mạng.
# ==============================================================================

set -e

echo "=============================================================================="
echo " [!] KÍCH HOẠT PHÒNG THỦ LỚP MẠNG: CHUỖI SYN_PROTECT (IPTABLES)"
echo "=============================================================================="

# 1. Dọn dẹp các luật cũ trên chuỗi INPUT và chuỗi SYN_PROTECT
echo "[*] Dọn dẹp bảng luật cũ..."
iptables -F INPUT
iptables -F SYN_PROTECT 2>/dev/null || true
iptables -X SYN_PROTECT 2>/dev/null || true

# 2. Cho phép các kết nối đã thiết lập hợp lệ, loopback và ping ICMP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

# 3. Tạo chuỗi quy tắc kiểm soát gói SYN riêng biệt: SYN_PROTECT
echo "[*] Khởi tạo chuỗi mới: SYN_PROTECT..."
iptables -N SYN_PROTECT

# 4. Chuyển các gói tin bắt đầu kết nối mới (SYN=1, ACK=0) vào chuỗi kiểm soát
echo "[*] Chuyển các gói TCP SYN vào chuỗi SYN_PROTECT..."
iptables -A INPUT -p tcp --syn -j SYN_PROTECT

# 5. Cho phép tối đa 20 kết nối SYN/giây, burst tối đa 30 gói (Đúng chuẩn Google Docs)
echo "[*] Cấu hình hạn mức: 20 gói/giây, burst 30 gói..."
iptables -A SYN_PROTECT -m limit --limit 20/s --limit-burst 30 -j ACCEPT

# 6. Toàn bộ gói tin SYN vượt quá ngưỡng trên sẽ bị DROP thẳng tay
echo "[*] Thiết lập hủy (DROP) các gói SYN vượt ngưỡng bảo vệ..."
iptables -A SYN_PROTECT -j DROP

echo ""
echo "=============================================================================="
echo " [+] ĐÃ BẬT PHÒNG THỦ LỚP MẠNG THÀNH CÔNG!"
echo " Bảng luật iptables hiện hành:"
iptables -L INPUT -v -n --line-numbers
echo ""
iptables -L SYN_PROTECT -v -n --line-numbers
echo "=============================================================================="
