"""
Concurrent client stress test for the secure file transfer server.

Start the server separately, for example:
    python app.py --mock --plain --host 127.0.0.1 --port 5000

Then run:
    python tests/stress_test.py --host 127.0.0.1 --port 5000 --clients 20
"""
import argparse
import os
import sys
import tempfile
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from client import SecureFTClient


def run_worker(index, host, port, use_tls, cafile, errors):
    username = "stressuser%d" % index
    password = "StressPass%d!" % index
    remote_name = "stress-%d.txt" % index

    with tempfile.TemporaryDirectory() as folder:
        local_path = os.path.join(folder, remote_name)
        download_dir = os.path.join(folder, "downloads")
        os.makedirs(download_dir)
        with open(local_path, "wb") as file:
            file.write(("stress payload %d\n" % index).encode("utf-8"))

        try:
            client = SecureFTClient(host=host, port=port, use_tls=use_tls, cafile=cafile)
            client.connect()
            try:
                registered = client.register(username, password)
                if registered["status"] not in (200, 409):
                    raise RuntimeError("register failed: %r" % registered)

                logged_in = client.login(username, password)
                if logged_in["status"] != 200:
                    raise RuntimeError("login failed: %r" % logged_in)

                uploaded = client.put(local_path, remote_name=remote_name, overwrite=True)
                if uploaded["status"] != 200:
                    raise RuntimeError("upload failed: %r" % uploaded)

                listed = client.list_files()
                if listed["status"] != 200:
                    raise RuntimeError("list failed: %r" % listed)
                names = {item["filename"] for item in listed["data"]["files"]}
                if remote_name not in names:
                    raise RuntimeError("uploaded file missing from list")

                downloaded, downloaded_path = client.get(remote_name, download_dir)
                if downloaded["status"] != 200 or downloaded_path is None:
                    raise RuntimeError("download failed: %r" % downloaded)
                with open(downloaded_path, "rb") as downloaded_file:
                    with open(local_path, "rb") as original_file:
                        if downloaded_file.read() != original_file.read():
                            raise RuntimeError("downloaded content mismatch")

                logged_out = client.logout()
                if logged_out["status"] != 200:
                    raise RuntimeError("logout failed: %r" % logged_out)
            finally:
                client.close()
        except Exception as exc:
            errors.append("worker %d: %s" % (index, exc))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run concurrent secure file transfer clients")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--cafile", default="certs/server.crt")
    args = parser.parse_args(argv)

    if args.clients < 1:
        parser.error("--clients must be at least 1")

    errors = []
    threads = [
        threading.Thread(
            target=run_worker,
            args=(index, args.host, args.port, not args.no_tls, args.cafile, errors),
        )
        for index in range(args.clients)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if errors:
        print("STRESS TEST FAILED")
        for error in sorted(errors):
            print(error)
        return 1

    print("STRESS TEST PASSED: %d concurrent clients" % args.clients)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())