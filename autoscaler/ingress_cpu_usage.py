import subprocess
import csv
import time
import signal
import sys

cpu_usage_data = []
absolute_time = 1

def signal_handler(sig, frame):
    print("\nCollection terminated, writing data to nginx_cpu_usage.csv...")

    with open("nginx_cpu_usage.csv", mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Time (s)", "CPU Usage (%)"])
        writer.writerows(cpu_usage_data)
    print("CPU usage collection completed.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_nginx_cpu_usage():
    try:
        # Use pidstat to collect the CPU usage of the NGINX workers
        result = subprocess.run(
            ["pidstat", "-h", "-p", "ALL", "1", "1"],  # Collect data within 1 second
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        lines = result.stdout.strip().split("\n")
        nginx_lines = [line for line in lines if "nginx" in line]
        
        # Parse %CPU in column 9 on each line and sum it.
        # NOTE: pidstat on Ubuntu 20.04 may have different layout
        total_cpu = 0.0
        for line in nginx_lines:
            columns = line.split()
            total_cpu += float(columns[8])  # 9th column is total %CPU
        
        return total_cpu
    except subprocess.CalledProcessError as e:
        print(f"Collection failed: {e.stderr}")
        return 0.0

print("Start collecting NGINX CPU usage (Ctrl+C to terminate)...")

while True:
    try:
        cpu_usage = get_nginx_cpu_usage()
        print(f"Time: {time.time()}, CPU Usage: {cpu_usage:.2f}%")
        cpu_usage_data.append([time.time(), cpu_usage])
        absolute_time += 1

    except Exception as e:
        print(f"Error during data collection: {e}")
        break