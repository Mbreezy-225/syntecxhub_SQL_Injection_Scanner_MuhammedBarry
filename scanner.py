"""
Educational SQL Injection Indicator Scanner
For authorized local laboratory environments only.

Run:
    python scanner.py

The program will interactively ask for the target settings.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from detector import analyze_response, compare_responses
from payloads import PAYLOADS

logging.basicConfig(
    filename="scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

MAX_THREADS = 5


def build_url(url, parameter, value):
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    found = False
    updated_query = []

    for key, current_value in query:
        if key == parameter:
            updated_query.append((key, value))
            found = True
        else:
            updated_query.append((key, current_value))

    if not found:
        updated_query.append((parameter, value))

    return urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urlencode(updated_query), parts.fragment
    ))


def validate_target(url):
    if not url:
        raise ValueError("Target URL cannot be empty.")

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()

    if parts.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")

    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError(
            "Only localhost, 127.0.0.1, and ::1 are allowed."
        )


def get_positive_int(prompt, default, minimum=1, maximum=None):
    while True:
        value = input(f"{prompt} [{default}]: ").strip()

        if not value:
            return default

        try:
            value = int(value)

            if value < minimum:
                print(f"[!] Enter a value of at least {minimum}.")
                continue

            if maximum is not None and value > maximum:
                print(f"[!] Enter a value no greater than {maximum}.")
                continue

            return value

        except ValueError:
            print("[!] Please enter a valid whole number.")


def get_positive_float(prompt, default, minimum=0, strict=False):
    while True:
        value = input(f"{prompt} [{default}]: ").strip()

        if not value:
            return default

        try:
            value = float(value)

            if strict and value <= minimum:
                print(f"[!] Enter a value greater than {minimum}.")
                continue

            if not strict and value < minimum:
                print(f"[!] Enter a value greater than or equal to {minimum}.")
                continue

            return value

        except ValueError:
            print("[!] Please enter a valid number.")


def get_user_input():
    print("=" * 65)
    print("SQL INJECTION INDICATOR SCANNER")
    print("AUTHORIZED LOCAL/DVWA TESTING ONLY")
    print("=" * 65)
    print()

    while True:
        url = input(
            "Enter local target URL "
            "(example: http://127.0.0.1/page.php): "
        ).strip()

        try:
            validate_target(url)
            break
        except ValueError as error:
            print(f"[!] {error}")

    while True:
        parameter = input(
            "Enter parameter to test (example: id): "
        ).strip()

        if parameter:
            break

        print("[!] Parameter cannot be empty.")

    threads = get_positive_int(
        "Number of threads", default=2, minimum=1, maximum=MAX_THREADS
    )
    delay = get_positive_float(
        "Delay between payload submissions in seconds",
        default=0.5,
        minimum=0,
    )
    timeout = get_positive_float(
        "Request timeout in seconds",
        default=5.0,
        minimum=0,
        strict=True,
    )

    return {
        "url": url,
        "parameter": parameter,
        "threads": threads,
        "delay": delay,
        "timeout": timeout,
    }


def make_request(session, url, timeout):
    start = time.perf_counter()

    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )
        return {
            "ok": True,
            "status": response.status_code,
            "length": len(response.text),
            "text": response.text,
            "elapsed": time.perf_counter() - start,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "ok": False,
            "status": None,
            "length": 0,
            "text": "",
            "elapsed": time.perf_counter() - start,
            "error": str(error),
        }


def test_payload(session, target, parameter, payload, baseline, timeout):
    test_url = build_url(target, parameter, payload)
    result = make_request(session, test_url, timeout)

    if not result["ok"]:
        return {
            "payload": payload,
            "vulnerable": False,
            "confidence": "ERROR",
            "evidence": result["error"],
        }

    indicators = analyze_response(result["text"])
    differences = compare_responses(baseline, result)

    vulnerable = bool(indicators) or differences["strong_change"]

    if indicators:
        confidence = "HIGH"
    elif differences["strong_change"]:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "payload": payload,
        "vulnerable": vulnerable,
        "confidence": confidence,
        "evidence": indicators,
        "differences": differences,
    }


def main():
    settings = get_user_input()

    print()
    print("=" * 65)
    print("SCAN CONFIGURATION")
    print(f"Target: {settings['url']}")
    print(f"Parameter: {settings['parameter']}")
    print(f"Payloads: {len(PAYLOADS)}")
    print(f"Threads: {settings['threads']}")
    print(f"Delay: {settings['delay']} seconds")
    print(f"Timeout: {settings['timeout']} seconds")
    print("=" * 65)

    session = requests.Session()
    session.headers["User-Agent"] = "Educational-SQLi-Scanner/1.0"

    print("\n[*] Establishing baseline response...")

    baseline_url = build_url(
        settings["url"],
        settings["parameter"],
        "1",
    )
    baseline = make_request(
        session,
        baseline_url,
        settings["timeout"],
    )

    if not baseline["ok"]:
        print(f"[!] Baseline request failed: {baseline['error']}")
        return

    print(
        f"[+] Baseline established: HTTP {baseline['status']}, "
        f"{baseline['length']} bytes, "
        f"{baseline['elapsed']:.2f}s"
    )

    logging.info(
        "Scan started target=%s parameter=%s",
        settings["url"],
        settings["parameter"],
    )

    results = []
    start = time.perf_counter()

    print("\n[*] Testing payloads...\n")

    with ThreadPoolExecutor(
        max_workers=settings["threads"]
    ) as executor:
        futures = []

        for payload in PAYLOADS:
            futures.append(
                executor.submit(
                    test_payload,
                    session,
                    settings["url"],
                    settings["parameter"],
                    payload,
                    baseline,
                    settings["timeout"],
                )
            )
            time.sleep(settings["delay"])

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            if result["confidence"] == "ERROR":
                print(f"[!] Request error: {result['evidence']}")
            elif result["vulnerable"]:
                print(
                    f"[+] Possible indicator | "
                    f"{result['confidence']} | "
                    f"{result['payload']}"
                )
            else:
                print(
                    f"[-] No strong indicator | "
                    f"{result['payload']}"
                )

    duration = time.perf_counter() - start
    high = sum(r["confidence"] == "HIGH" for r in results)
    medium = sum(r["confidence"] == "MEDIUM" for r in results)
    errors = sum(r["confidence"] == "ERROR" for r in results)

    print("\n" + "=" * 65)
    print("SUMMARY")
    print(f"Payloads tested: {len(results)}")
    print(f"High indicators: {high}")
    print(f"Medium indicators: {medium}")
    print(f"Request errors: {errors}")
    print(f"Scan time: {duration:.2f}s")
    print("Log file: scan_results.log")
    print("=" * 65)

    logging.info(
        "Scan completed payloads=%d high=%d medium=%d errors=%d duration=%.2fs",
        len(results),
        high,
        medium,
        errors,
        duration,
    )


if __name__ == "__main__":
    main()