"""
Concurrent client stress test for the secure file transfer server.

Start the server separately, for example:
    python app.py --mock --plain --host 127.0.0.1 --port 5000

Then run:
    python tests/stress_test.py --host 127.0.0.1 --port 5000 --clients 50
"""
import argparse
from datetime import datetime
import os
import sys
import tempfile
import threading
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from client import SecureFTClient


STAGES = ("REGISTER", "LOGIN", "UPLOAD", "LIST", "DOWNLOAD", "LOGOUT")


def run_worker(index, host, port, use_tls, cafile, results):
    username = "stressuser%d" % index
    password = "StressPass%d!" % index
    remote_name = "stress-%d.txt" % index
    result = {
        "username": username,
        "completed": [],
        "failed_stage": "SETUP",
        "error": None,
    }
    client = None

    try:
        with tempfile.TemporaryDirectory() as folder:
            local_path = os.path.join(folder, remote_name)
            download_dir = os.path.join(folder, "downloads")
            os.makedirs(download_dir)
            with open(local_path, "wb") as file:
                file.write(("stress payload %d\n" % index).encode("utf-8"))

            client = SecureFTClient(host=host, port=port, use_tls=use_tls, cafile=cafile)
            client.connect()

            result["failed_stage"] = "REGISTER"
            registered = client.register(username, password)
            if registered["status"] not in (200, 409):
                raise RuntimeError("register returned status %s" % registered["status"])
            result["completed"].append("REGISTER")

            result["failed_stage"] = "LOGIN"
            logged_in = client.login(username, password)
            if logged_in["status"] != 200:
                raise RuntimeError("login returned status %s" % logged_in["status"])
            result["completed"].append("LOGIN")

            result["failed_stage"] = "UPLOAD"
            uploaded = client.put(local_path, remote_name=remote_name, overwrite=True)
            if uploaded["status"] != 200:
                raise RuntimeError("upload returned status %s" % uploaded["status"])
            result["completed"].append("UPLOAD")

            result["failed_stage"] = "LIST"
            listed = client.list_files()
            if listed["status"] != 200:
                raise RuntimeError("list returned status %s" % listed["status"])
            names = {item["filename"] for item in listed["data"]["files"]}
            if remote_name not in names:
                raise RuntimeError("uploaded file missing from list")
            result["completed"].append("LIST")

            result["failed_stage"] = "DOWNLOAD"
            downloaded, downloaded_path = client.get(remote_name, download_dir)
            if downloaded["status"] != 200 or downloaded_path is None:
                raise RuntimeError("download returned status %s" % downloaded["status"])
            with open(downloaded_path, "rb") as downloaded_file:
                with open(local_path, "rb") as original_file:
                    if downloaded_file.read() != original_file.read():
                        raise RuntimeError("downloaded content mismatch")
            result["completed"].append("DOWNLOAD")

            result["failed_stage"] = "LOGOUT"
            logged_out = client.logout()
            if logged_out["status"] != 200:
                raise RuntimeError("logout returned status %s" % logged_out["status"])
            result["completed"].append("LOGOUT")

        result["failed_stage"] = None
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if client is not None:
            client.close()
        results[index] = result


def format_report(host, port, clients, use_tls, backend, duration, results):
    passed = sum(result["failed_stage"] is None for result in results)
    failed = clients - passed
    total_ops = clients * len(STAGES)
    completed_ops = sum(len(result["completed"]) for result in results)
    lines = [
        "Secure File Transfer - Concurrent Stress Test",
        "Timestamp: %s" % datetime.now().astimezone().isoformat(timespec="seconds"),
        "Target: %s:%d" % (host, port),
        "Backend: %s" % backend,
        "Transport: %s" % ("TLS" if use_tls else "PLAINTEXT (testing only)"),
        "Concurrent clients: %d" % clients,
        "Passed clients: %d" % passed,
        "Failed clients: %d" % failed,
        "Completed workflow operations: %d/%d" % (completed_ops, total_ops),
        "Elapsed time: %.2f seconds" % duration,
        "Client throughput: %.2f clients/second" % (passed / duration if duration else 0),
        "",
        "Operation results:",
    ]
    for stage in STAGES:
        count = sum(stage in result["completed"] for result in results)
        lines.append("  %-8s %d/%d" % (stage, count, clients))

    failures = [result for result in results if result["failed_stage"] is not None]
    if failures:
        lines.extend(["", "Failures:"])
        for result in failures:
            lines.append(
                "  %s at %s: %s"
                % (result["username"], result["failed_stage"], result["error"])
            )

    lines.extend(["", "Overall result: %s" % ("PASS" if failed == 0 else "FAIL")])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run concurrent secure file transfer clients")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--cafile", default="certs/server.crt")
    parser.add_argument(
        "--backend",
        choices=("mock", "real", "unspecified"),
        default="unspecified",
        help="label the server backend in the results report",
    )
    parser.add_argument("--report", help="optional path to save the text results report")
    args = parser.parse_args(argv)

    if args.clients < 1:
        parser.error("--clients must be at least 1")

    results = [None] * args.clients
    threads = [
        threading.Thread(
            target=run_worker,
            args=(index, args.host, args.port, not args.no_tls, args.cafile, results),
        )
        for index in range(args.clients)
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    duration = time.perf_counter() - started

    report = format_report(
        args.host, args.port, args.clients, not args.no_tls, args.backend, duration, results
    )
    print(report)
    if args.report:
        report_path = os.path.abspath(args.report)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write(report + "\n")
        print("Report saved to: %s" % report_path)

    return 0 if all(result["failed_stage"] is None for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())