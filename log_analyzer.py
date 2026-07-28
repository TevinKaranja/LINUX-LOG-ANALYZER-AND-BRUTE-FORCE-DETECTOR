#!/usr/bin/env python3
"""
log_analyzer.py - Basic Linux authentication log analyzer
Usage: sudo ./log_analyzer.py
"""
import re
import subprocess
from collections import Counter
from datetime import datetime

LOGFILE = "/var/log/auth.log"
THRESHOLD = 5


def read_log():
    try:
        with open(LOGFILE, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        # fall back to journalctl on systemd-only systems
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "--no-pager"],
            capture_output=True, text=True
        )
        return result.stdout.splitlines()


def analyze(lines):
    ip_pattern = re.compile(r"Failed password.*from ([0-9a-fA-F:.]+) port")
    ip_counter = Counter()
    for line in lines:
        match = ip_pattern.search(line)
        if match:
            ip_counter[match.group(1)] += 1
    return ip_counter


def write_report(ip_counter):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.txt"
    with open(filename, "w") as f:
        f.write("=== Linux Auth Log Report ===\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        total = sum(ip_counter.values())
        f.write(f"Total failed login attempts: {total}\n\n")
        f.write("Top offending IP addresses:\n")
        for ip, count in ip_counter.most_common():
            f.write(f"{count:>5}  {ip}\n")
        f.write("\nFlagged IPs (>= threshold):\n")
        for ip, count in ip_counter.items():
            if count >= THRESHOLD:
                f.write(f"{ip} - {count} attempts\n")
    print(f"Report saved to {filename}")


if __name__ == "__main__":
    lines = read_log()
    counts = analyze(lines)
    write_report(counts)
