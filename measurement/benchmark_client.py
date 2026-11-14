#!/usr/bin/env python3
"""
==============================================================================
FR5 - KIỂM THỬ ĐÁP ỨNG DỊCH VỤ (SERVICE AVAILABILITY BENCHMARK)
Chạy trên: normal_client (192.168.100.30)
==============================================================================
Trích từ mục FR5 & Giai đoạn 3 trong Báo cáo:
Máy trạm hợp lệ gửi yêu cầu HTTP GET định kỳ tới máy chủ (http://192.168.100.10),
đo lường và ghi nhận 2 chỉ số chính phục vụ đối sánh khoa học:
1. Thời gian phản hồi (HTTP Response Time - đơn vị ms)
2. Tỷ lệ lỗi kết nối (HTTP Failure / Loss Rate - đơn vị %)
Lưu tự động kết quả vào results.csv để vẽ biểu đồ và lập bảng so sánh.
==============================================================================
"""

import sys
import os
import time
import argparse
import csv
import socket
from datetime import datetime
import urllib.request
import urllib.error

DEFAULT_URL = "http://192.168.100.10"
DEFAULT_REQUESTS = 50
DEFAULT_DELAY = 0.2
DEFAULT_TIMEOUT = 2.0
DEFAULT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.csv")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Đo lường hiệu năng dịch vụ Web HTTP.")
    parser.add_argument("--scenario", "-s", type=str, required=True,
                        help="Tên kịch bản đối sánh (Ví dụ: 'Baseline', 'Chua_Phong_Thu', 'Co_Phong_Thu')")
    parser.add_argument("--url", "-u", type=str, default=DEFAULT_URL, help="URL máy chủ Nginx")
    parser.add_argument("--requests", "-n", type=int, default=DEFAULT_REQUESTS, help="Tổng số request (mặc định: 50)")
    parser.add_argument("--delay", "-d", type=float, default=DEFAULT_DELAY, help="Khoảng cách giữa các request (s)")
    parser.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help="Timeout mỗi request (s)")
    parser.add_argument("--output", "-o", type=str, default=DEFAULT_CSV, help="File CSV lưu kết quả")
    return parser.parse_args()

def run_benchmark(scenario, url, total_requests, delay, timeout, csv_file):
    print("=" * 80)
    print(f" [!] BẮT ĐẦU ĐO LƯỜNG HIỆU NĂNG TRUY CẬP (FR5 - BENCHMARK)")
    print(f" [*] Kịch bản thử nghiệm  : {scenario}")
    print(f" [*] Mục tiêu             : {url}")
    print(f" [*] Tổng số request       : {total_requests} (delay {delay}s, timeout {timeout}s)")
    print("=" * 80)
    print(f"{'STT':<6} | {'Mã HTTP':<10} | {'Thời gian phản hồi':<20} | {'Trạng thái':<20}")
    print("-" * 80)

    success_count = 0
    failure_count = 0
    response_times_ms = []

    for i in range(1, total_requests + 1):
        start_time = time.perf_counter()
        status_code = None
        status_str = ""
        latency_ms = 0.0

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NormalClient-Benchmark/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                status_code = response.getcode()
                if status_code == 200:
                    status_str = "SUCCESS (200 OK)"
                    success_count += 1
                    response_times_ms.append(latency_ms)
                else:
                    status_str = f"HTTP_{status_code}"
                    failure_count += 1
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            status_code = "TIMEOUT"
            status_str = "CONNECTION_TIMED_OUT"
            failure_count += 1
        except Exception:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            status_code = "DROPPED"
            status_str = "CONNECTION_REFUSED"
            failure_count += 1

        print(f"{i:<6} | {str(status_code):<10} | {latency_ms:>8.2f} ms{'':<9} | {status_str:<20}")

        if i < total_requests:
            time.sleep(delay)

    # Tính toán các chỉ số định lượng theo Báo cáo
    failure_rate = (failure_count / total_requests) * 100.0
    availability = (success_count / total_requests) * 100.0
    avg_response_time = (sum(response_times_ms) / len(response_times_ms)) if response_times_ms else 0.0

    print("=" * 80)
    print(f" [!] BÁO CÁO THỐNG KÊ ĐỊNH LƯỢNG - KỊCH BẢN: [{scenario}]")
    print("=" * 80)
    print(f" - Tổng số request gửi đi             : {total_requests}")
    print(f" - Số request thành công (HTTP 200)    : {success_count}")
    print(f" - Số request thất bại (Timeout/Drop)  : {failure_count}")
    print(f" - Tỷ lệ lỗi kết nối (HTTP Failure Rate): {failure_rate:.2f}%")
    print(f" - Tỷ lệ sẵn sàng (Service Availability): {availability:.2f}%")
    print(f" - Thời gian phản hồi trung bình       : {avg_response_time:.2f} ms")
    print("=" * 80)

    # Ghi nhận kết quả vào tệp CSV
    save_to_csv(csv_file, scenario, total_requests, success_count, failure_count, failure_rate, availability, avg_response_time)

def save_to_csv(csv_file, scenario, total, success, failure, failure_rate, availability, avg_latency):
    file_exists = os.path.isfile(csv_file)
    os.makedirs(os.path.dirname(os.path.abspath(csv_file)), exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    headers = [
        "Timestamp", "Scenario", "Total_Requests", "Successful_Requests",
        "Failed_Requests", "Failure_Rate_Percent", "Availability_Percent", "Avg_Response_Time_ms"
    ]
    row = [
        timestamp, scenario, total, success, failure,
        f"{failure_rate:.2f}", f"{availability:.2f}", f"{avg_latency:.2f}"
    ]

    try:
        with open(csv_file, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(csv_file) == 0:
                writer.writerow(headers)
            writer.writerow(row)
        print(f"[+] Đã ghi nhận số liệu vào file đối sánh: {csv_file}")
    except Exception as e:
        print(f"[-] Lỗi ghi file CSV: {e}")

if __name__ == "__main__":
    args = parse_arguments()
    run_benchmark(args.scenario, args.url, args.requests, args.delay, args.timeout, args.output)
