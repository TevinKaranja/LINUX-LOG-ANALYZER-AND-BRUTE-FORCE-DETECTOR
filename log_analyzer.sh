#!/bin/bash
#
# log_analyzer.sh - Linux authentication log analyzer
# Scans /var/log/auth.log for failed SSH login attempts, counts failed
# attempts per source address (IPv4 or IPv6), and flags any address that
# crosses a threshold.
#
# Usage: sudo ./log_analyzer.sh

LOGFILE="/var/log/auth.log"
REPORT="report_$(date +%Y%m%d_%H%M%S).txt"
THRESHOLD=5   # failed attempts before flagging an address

if [ ! -f "$LOGFILE" ]; then
  echo "Log file not found at $LOGFILE."
  echo "If your system uses systemd-journald instead, try:"
  echo "  journalctl -u ssh --no-pager | grep 'Failed password'"
  exit 1
fi

echo "=== Linux Auth Log Report ===" > "$REPORT"
echo "Generated: $(date)" >> "$REPORT"
echo "" >> "$REPORT"

TOTAL_FAILED=$(grep "Failed password" "$LOGFILE" | wc -l)
echo "Total failed login attempts: $TOTAL_FAILED" >> "$REPORT"
echo "" >> "$REPORT"

echo "Top offending addresses:" >> "$REPORT"
grep "Failed password" "$LOGFILE" \
  | awk '{print $(NF-3)}' \
  | sort | uniq -c | sort -nr > /tmp/ip_counts.txt
cat /tmp/ip_counts.txt >> "$REPORT"
echo "" >> "$REPORT"

echo "Flagged addresses (>= $THRESHOLD failed attempts):" >> "$REPORT"
awk -v t="$THRESHOLD" '$1 >= t {print $2}' /tmp/ip_counts.txt >> "$REPORT"

echo "Report saved to $REPORT"
