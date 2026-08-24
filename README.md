# SQL Injection Indicator Scanner

Educational Week 3 cybersecurity internship project for testing authorized local applications such as DVWA.

## Features
- Controlled SQL injection probes
- Baseline response
- GET parameter testing
- SQL error indicator detection
- Response status/length comparison
- Basic thread concurrency
- Rate limiting with `--delay`
- Timeouts and exception handling
- Logging to `scan_results.log`
- Safety restriction to localhost targets

## Install
```bash
pip install -r requirements.txt
```

## Run
```bash
python scanner.py -u "http://127.0.0.1/dvwa/vulnerabilities/sqli/" -p id
```

Optional controls:
```bash
python scanner.py -u "http://127.0.0.1/dvwa/vulnerabilities/sqli/" -p id --threads 2 --delay 0.5 --timeout 5
```

In PyCharm, put those arguments in **Run > Edit Configurations > Parameters**.

## How it works
1. Sends a baseline request.
2. Sends a small controlled payload set.
3. Checks responses for common database error indicators.
4. Compares HTTP status and response length to the baseline.
5. Reports possible indicators and logs the scan.

A finding is only an indicator for manual verification, not automatic proof of SQL injection.

## Ethical use
The scanner intentionally accepts only `localhost`, `127.0.0.1`, and `::1`. Use only applications you own or are explicitly authorized to test, such as a local DVWA installation. Do not scan public or third-party websites without permission.

## Limitations
GET parameters only; small payload set; generic indicators; no authentication bypass; no database extraction; not a production vulnerability scanner.

## Learning outcomes
HTTP requests, SQL injection concepts, response analysis, concurrency, rate limiting, exception handling, logging, and ethical security testing.
