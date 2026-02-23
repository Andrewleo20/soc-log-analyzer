import argparse
import csv
from datetime import datetime


# -----------------------------
# SOC Log Analyzer CLI Version
# With CSV Reporting
# -----------------------------

def read_log_file(filename):
    try:
        with open(filename, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Error: Log file not found.")
        return []


def parse_timestamp(line):
    timestamp_str = line.split("[")[1].split("]")[0]
    return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")


def detect_bruteforce(lines, threshold, time_window_seconds):
    attempts = {}

    for line in lines:
        if "401" in line:
            ip = line.split()[0]
            timestamp = parse_timestamp(line)

            if ip not in attempts:
                attempts[ip] = []

            attempts[ip].append(timestamp)

    suspicious_ips = {}

    for ip, timestamps in attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            for j in range(i + 1, len(timestamps)):
                time_diff = (timestamps[j] - timestamps[i]).total_seconds()
                if time_diff <= time_window_seconds:
                    count += 1
                else:
                    break

            if count >= threshold:
                suspicious_ips[ip] = count
                break

    return suspicious_ips


def export_to_csv(suspicious_ips, filename="alerts_report.csv"):
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Failed Attempts Within Window"])

        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

    print(f"\nReport exported to {filename}")


def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer - Brute Force Detection")

    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--threshold", type=int, default=3,
                        help="Number of failed attempts to trigger alert (default=3)")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in seconds (default=60)")

    args = parser.parse_args()

    lines = read_log_file(args.logfile)

    if not lines:
        return

    suspicious_ips = detect_bruteforce(lines, args.threshold, args.window)

    print("\n=== Time-Based Brute Force Detection ===\n")
    print(f"Threshold: {args.threshold} attempts")
    print(f"Time Window: {args.window} seconds\n")

    print(f"Total Log Entries: {len(lines)}")
    print(f"Total Suspicious IPs: {len(suspicious_ips)}\n")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"🚨 ALERT: {ip}")
            print(f"Failed Attempts within window: {count}")
            print("-----------------------------")

        export_to_csv(suspicious_ips)
    else:
        print("No brute force patterns detected.")


if __name__ == "__main__":
    main()