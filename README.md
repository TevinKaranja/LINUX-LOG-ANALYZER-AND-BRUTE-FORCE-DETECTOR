# LINUX-LOG-ANALYZER-AND-BRUTE-FORCE-DETECTOR
# Linux Log Analyzer & Brute-Force Detector

A beginner cybersecurity project that parses Linux SSH authentication logs to detect brute-force login attempts — built and tested on Kali Linux.

## Why I Built This

I wanted to understand how brute-force detection actually works under the hood, rather than just running a prebuilt tool like `fail2ban` and trusting it as a black box. Building this from scratch — reading raw log lines, writing the parsing logic, and hitting real bugs along the way — taught me far more about Linux logging and authentication than just reading about it would have.

## What It Does

The script scans `/var/log/auth.log` for failed SSH login attempts, counts how many times each source address fails, flags any address that crosses a configurable threshold, and writes a timestamped report summarizing the results.

This mirrors, on a small scale, what real intrusion-detection and log-monitoring tools do in a Security Operations Center (SOC): parse logs → detect patterns → flag suspicious activity → report.

## How It Works

1. Reads every line in the authentication log
2. Uses a regular expression to find lines containing `Failed password` and extract the source address
3. Counts failed attempts per address
4. Flags any address whose count meets or exceeds a threshold (default: 5)
5. Writes all of this to a timestamped `report_YYYYMMDD_HHMMSS.txt` file

```python
ip_pattern = re.compile(r"Failed password.*from ([0-9a-fA-F:.]+) port")
```

## Environment

- **OS:** Kali Linux (VM)
- **Language:** Python 3
- **Log source:** `/var/log/auth.log` (rsyslog)
- **Test setup:** a dedicated low-privilege `testuser` account, used to generate realistic failed-login attempts via `ssh testuser@localhost` rather than testing against root

> **Note:** Screenshots referenced below live in a `screenshots/` folder at the repo root — e.g. `screenshots/report-output.png` and `screenshots/auth-log-evidence.png`. Add your own cropped terminal screenshots there with matching filenames (or update the paths below) before pushing.

## Sample Output

Real report generated from an actual test run against my own machine:

![Terminal output of generated report](screenshots/report-output.png)

```
=== Linux Auth Log Report ===
Generated: 2026-07-23 12:37:55.358725

Total failed login attempts: 9

Top offending IP addresses:
    9  ::1

Flagged IPs (>= threshold):
::1 - 9 attempts
```

Corresponding raw log evidence from `/var/log/auth.log`:

![Failed password entries in auth.log](screenshots/auth-log-evidence.png)

```
sshd-session[59525]: Failed password for testuser from ::1 port 56824 ssh2
sshd-session[59525]: Failed password for testuser from ::1 port 56824 ssh2
sshd-session[59525]: Failed password for testuser from ::1 port 56824 ssh2
sshd-session[59525]: Connection closed by authenticating user testuser ::1 port 56824 [preauth]
sshd-session[59525]: PAM 2 more authentication failures; ... user=testuser
```

## Installation & Usage

```bash
# Clone the repo
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer

# Make the script executable
chmod +x log_analyzer.py

# Run it (root privileges are needed to read /var/log/auth.log)
sudo ./log_analyzer.py

# View the generated report
cat "$(ls -t report_*.txt | head -1)"
```

To simulate an attack for testing, open a second terminal and repeatedly attempt an SSH login with a wrong password against a test account:

```bash
ssh testuser@localhost
# enter a wrong password a few times
```

## Technologies Used

- **Python 3** — log parsing, regex matching, report generation
- **Bash** — a simpler equivalent version using `grep`, `awk`, `sort`, and `uniq` is also included (`log_analyzer.sh`)
- **Linux authentication logging** — `rsyslog`, `/var/log/auth.log`, `sshd`
- **Kali Linux** — testing environment

## Lessons Learned / Challenges Faced

The most interesting bug I hit: my first version of the regex only matched IPv4 addresses (`\d+\.\d+\.\d+\.\d+`). When I ran the script, `grep` on the raw log clearly showed 10 matching "Failed password" lines, but my script reported 0 every time. After comparing the raw log output line-by-line against what the script was supposed to match, I found the cause — I was testing via `ssh testuser@localhost`, which connects over the IPv6 loopback address `::1`, not an IPv4 address. My regex simply had no way to match that format, so every line silently failed to parse.

The fix was updating the pattern to accept both IPv4 and IPv6-style addresses:

```python
# Before (IPv4 only - silently matched nothing for local/IPv6 traffic)
ip_pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

# After (matches IPv4 and IPv6)
ip_pattern = re.compile(r"Failed password.*from ([0-9a-fA-F:.]+) port")
```

This taught me a real lesson about not assuming log data will always match the "clean" format you expect, and about verifying a script's output against raw ground-truth data (`grep`/`wc -l`) rather than trusting the script blindly.

## Future Improvements

- [ ] Simulate a more realistic attack using `hydra` (included in Kali) against a local test SSH service
- [ ] Automate scans on a schedule using `cron`
- [ ] Auto-block flagged IP addresses, or integrate with `fail2ban`
- [ ] Generate an HTML report instead of plain text, for a dashboard-style view
- [ ] Add GeoIP lookups to show the origin country of offending addresses
- [ ] Add email/Slack alerting when an address crosses the threshold

## Disclaimer

This project was tested only against my own local machine and accounts. Any brute-force simulation (manual or via tools like `hydra`) was run exclusively against `localhost`/my own lab environment. Never run login attack tools against systems you do not own or do not have explicit written authorization to test.
