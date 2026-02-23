# SOC Log Analyzer

A Python-based Security Operations Center (SOC) log analysis tool designed to detect brute-force login attempts using time-window correlation logic.

## Features

- Parses structured server log files
- Detects failed login attempts (HTTP 401)
- Implements time-based brute-force detection
- Configurable threshold and time window
- Command-line interface (CLI)
- Exports alerts to CSV report
- Modular and professional code structure

---

## Detection Logic

The tool identifies brute-force activity by:

- Grouping failed login attempts by IP address
- Correlating events within a configurable time window
- Triggering alerts if failed attempts exceed a threshold

Example rule:

> 3 or more failed login attempts within 60 seconds triggers an alert.

---

## Installation

No external dependencies required.

Clone the repository:


---

## Usage

Basic usage:
python log_analyzer.py server.log


Custom threshold:
python log_analyzer.py server.log --threshold 5


Custom time window:
python log_analyzer.py server.log --window 120


Full example:
python log_analyzer.py server.log --threshold 4 --window 90


---

## Output

The tool generates:

- Console alert output
- `alerts_report.csv` containing suspicious IPs

---

## Example Output
