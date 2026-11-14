#!/bin/bash
# ==============================================================================
# FR3 - GIÁM SÁT TRẠNG THÁI HÀNG ĐỢI VÀ BẮT GÓI TIN BẰNG TCPDUMP
# Chạy trên: victim_server (192.168.100.10)
# ==============================================================================
# Trích từ Giai đoạn 3 trong Báo cáo:
# 1. Bắt gói tin: tcpdump -i eth0 -w /workspace/measurement/syn_attack.pcap tcp port 80
# 2. Thống kê hàng đợi: netstat -nat | grep SYN_RECV | wc -l
# ==============================================================================

DURATION=${1:-15}
OUTPUT_FILE="/workspace/measurement/syn_attack.pcap"

echo "=============================================================================="
echo " [!] BẮT ĐẦU BẮT GÓI TIN VÀ THEO DÕI HÀNG ĐỢI (FR3 - TRAFFIC OBSERVATION)"
echo " Thời lượng ghi nhận: $DURATION giây"
echo " File chứng cứ PCAP: $OUTPUT_FILE"
echo "=============================================================================="

# Khởi chạy tcpdump nền trong $DURATION giây
timeout $DURATION tcpdump -i eth0 -w "$OUTPUT_FILE" "tcp port 80" 2>/dev/null &
TCPDUMP_PID=$!

echo "[*] tcpdump đang chạy ngầm để ghi nhận các luồng bắt tay TCP..."
echo "[*] Đang theo dõi biến động số lượng kết nối nửa mở (SYN_RECV)..."
echo "------------------------------------------------------------------------------"

for i in $(seq 1 $DURATION); do
    CURRENT_SYN=$(netstat -nat | grep -c "SYN_RECV" || true)
    CURRENT_EST=$(netstat -nat | grep -c "ESTABLISHED" || true)
    printf " Giây %02d/%02d | Hàng đợi SYN_RECV: %-4s | Kết nối ESTABLISHED: %-4s\n" "$i" "$DURATION" "$CURRENT_SYN" "$CURRENT_EST"
    sleep 1
done

wait $TCPDUMP_PID 2>/dev/null || true

echo "------------------------------------------------------------------------------"
echo "=============================================================================="
echo " [!] KẾT QUẢ QUAN SÁT TRẠNG THÁI MÁY CHỦ"
echo "=============================================================================="
TOTAL_SYN_RECV=$(netstat -nat | grep -c "SYN_RECV" || true)
TOTAL_ESTABLISHED=$(netstat -nat | grep -c "ESTABLISHED" || true)
echo " - Tổng số kết nối kẹt ở SYN_RECV : $TOTAL_SYN_RECV"
echo " - Tổng số kết nối ESTABLISHED     : $TOTAL_ESTABLISHED"
echo ""
echo "[+] Danh sách chi tiết 15 kết nối nửa mở gần nhất:"
netstat -nat | grep "SYN_RECV" | head -n 15 || echo "Không có kết nối SYN_RECV"
echo ""
echo "[+] File pcap đã được lưu tại: $OUTPUT_FILE"
echo "[+] Bạn có thể mở file này bằng Wireshark để chụp ảnh biểu đồ luồng bắt tay!"
echo "=============================================================================="
