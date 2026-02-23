# SOC Log Analyzer

CLI-based Python Security Operations Center (SOC) log analysis tool that detects brute-force login attempts using time-window correlation and rule-based behavioral detection.

---

## Features

- Parses structured server log files
- Detects failed login attempts (HTTP 401)
- Implements time-based brute-force detection
- Configurable threshold and time window
- Command-line interface (CLI)
- Exports alerts to CSV report

---

python log_analyzer.py server.log
python log_analyzer.py server.log --threshold 4 --window 90

=== Time-Based Brute Force Detection ===
...
