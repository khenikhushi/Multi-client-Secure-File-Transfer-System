"""
client.py  [PERSON A]

Command-line client for the secure file transfer server.

  python client.py                       # interactive shell (TLS, trusts certs/server.crt)
  python client.py --host 10.0.0.5 --port 5000
  python client.py --no-tls              # plain TCP (isolated Wireshark lab ONLY)

Shell commands:
  register <user>        create an account (asks for the password)
  login <user>           log in (asks for the password)
  list                   show your files
  put <path> [--overwrite]   upload a local file
  get <name> [folder] [--overwrite]   download into folder (default: current folder)
  logout | quit | help

SecureFTClient is also used by tests/stress_test.py, so keep it importable.
This file never imports server-side (Person B) modules.
"""
import argparse
import getpass
import hashlib
import os
import shlex
import socket
import ssl
import sys

import config
from utils import framing

CHUNK = config.CHUNK_SIZE


class ClientError(Exception):
    """Network or protocol problem (not a normal 'file not found' style answer)."""


class IntegrityError(ClientError):
    """A downloaded file did not match the SHA-256 the server announced."""


def _sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


class SecureFTClient:
    def __init__(self, host=config.SERVER_HOST, port=config.SERVER_PORT, use_tls=True,
                 cafile=config.TLS_CERT, timeout=30):
        self.host, self.port, self.use_tls, self.cafile, self.timeout = host, port, use_tls, cafile, timeout
        self.sock = None
        self.token = None
        self._n = 0

    # --------------------------------------------------------- connection
    def connect(self):
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_tls:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
                # check_hostname and certificate verification stay ON (defaults).
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            raw.settimeout(self.timeout)
            self.sock = raw
        except (OSError, ssl.SSLError) as exc:
            raise ClientError("cannot connect: %s" % exc) from exc

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.token = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_exc):
        del _exc
        self.close()

    # ------------------------------------------------------------ plumbing
    def _send(self, cmd, **fields):
        if self.sock is None:
            raise ClientError("not connected")
        self._n += 1
        req_id = "r-%d" % self._n
        msg = {"v": config.PROTOCOL_VERSION, "id": req_id, "cmd": cmd}
        msg.update(fields)
        try:
            framing.send_message(self.sock, msg)
        except (OSError, framing.FramingError) as exc:
            self.close()
            raise ClientError("send failed: %s" % exc) from exc
        return req_id

    def _recv(self, req_id):
        try:
            resp = framing.recv_message(self.sock)
        except (framing.ConnectionClosed, framing.FramingError, OSError) as exc:
            self.close()
            raise ClientError("receive failed: %s" % exc) from exc
        if resp.get("id") not in (req_id, None):
            self.close()
            raise ClientError("response does not match the request")
        return resp

    def request(self, cmd, **fields):
        return self._recv(self._send(cmd, **fields))

    # ------------------------------------------------------------ commands
    def register(self, username, password):
        return self.request("REGISTER", username=username, password=password)

    def login(self, username, password):
        resp = self.request("LOGIN", username=username, password=password)
        if resp["status"] == 200:
            self.token = resp["data"]["token"]
        return resp

    def logout(self):
        resp = self.request("LOGOUT", token=self.token or "")
        if resp["status"] == 200:
            self.token = None
        return resp

    def list_files(self):
        return self.request("LIST", token=self.token or "")

    def put(self, path, remote_name=None, overwrite=False):
        """Upload a local file. Returns the server's final response dict."""
        size = os.path.getsize(path)
        if size == 0:
            raise ClientError("empty files cannot be uploaded")
        digest = _sha256_of_file(path)
        name = remote_name or os.path.basename(path)
        req_id = self._send("PUT", token=self.token or "", filename=name, size=size,
                            sha256=digest, overwrite=overwrite)
        ready = self._recv(req_id)
        if ready["status"] != 200:
            return ready  # refused before any bytes were sent
        sent = 0
        try:
            with open(path, "rb") as f:
                while True:
                    block = f.read(CHUNK)
                    if not block:
                        break
                    self.sock.sendall(block)
                    sent += len(block)
        except OSError as exc:
            self.close()
            raise ClientError("upload failed: %s" % exc) from exc
        if sent != size:
            self.close()  # the file changed while uploading; the stream is unusable
            raise ClientError("file changed during upload")
        return self._recv(req_id)

    def get(self, name, dest_dir=".", overwrite=False):
        """
        Download `name` into dest_dir. Returns (response, local_path or None).
        The data goes to <file>.part and is renamed only after the SHA-256 matches.
        """
        dest = os.path.join(dest_dir, os.path.basename(name))
        if os.path.exists(dest) and not overwrite:
            raise ClientError("%s already exists (use overwrite)" % dest)
        req_id = self._send("GET", token=self.token or "", filename=name)
        resp = self._recv(req_id)
        if resp["status"] != 200:
            return resp, None
        size, expected = resp["data"].get("size"), resp["data"].get("sha256")
        if not isinstance(size, int) or size < 0 or not isinstance(expected, str):
            self.close()
            raise ClientError("server sent an invalid download header")
        part = dest + ".part"
        h = hashlib.sha256()
        try:
            with open(part, "wb") as f:
                for chunk in framing.recv_file_bytes(self.sock, size):
                    h.update(chunk)
                    f.write(chunk)
        except (framing.ConnectionClosed, OSError) as exc:
            self._remove(part)
            self.close()
            raise ClientError("download failed: %s" % exc) from exc
        if h.hexdigest() != expected:
            self._remove(part)
            raise IntegrityError("SHA-256 mismatch: the downloaded data was corrupted or altered")
        os.replace(part, dest)
        return resp, dest

    @staticmethod
    def _remove(path):
        try:
            os.remove(path)
        except OSError:
            pass


# ======================================================================= CLI
HELP = __doc__.split("Shell commands:")[1].split("SecureFTClient")[0].rstrip()


def _show(resp):
    print("[%s %s] %s" % (resp["status"], resp["code"], resp["message"]))


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def run_command(client, line):
    """Execute one shell line. Returns False when the user wants to quit."""
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        print("cannot parse: %s" % exc)
        return True
    if not parts:
        return True
    cmd, args = parts[0].lower(), parts[1:]
    flags = [a for a in args if a.startswith("--")]
    args = [a for a in args if not a.startswith("--")]
    overwrite = "--overwrite" in flags
    try:
        if cmd in ("quit", "exit"):
            return False
        elif cmd == "help":
            print("Commands:" + HELP)
        elif cmd in ("register", "login") and len(args) == 1:
            password = getpass.getpass("Password: ")
            resp = client.register(args[0], password) if cmd == "register" else client.login(args[0], password)
            _show(resp)
        elif cmd == "logout":
            _show(client.logout())
        elif cmd == "list":
            resp = client.list_files()
            _show(resp)
            for f in resp["data"].get("files", []):
                print("  %-30s %10s  %s  %s" % (f["filename"], _human(f["size"]), f["modified"], f["sha256"][:12]))
        elif cmd == "put" and len(args) == 1:
            resp = client.put(args[0], overwrite=overwrite)
            _show(resp)
            if resp["status"] == 200:
                print("  sha256 %s" % resp["data"]["sha256"])
        elif cmd == "get" and len(args) in (1, 2):
            resp, path = client.get(args[0], args[1] if len(args) == 2 else ".", overwrite)
            _show(resp)
            if path:
                print("  saved to %s (SHA-256 verified)" % path)
        else:
            print("Unknown or incomplete command. Type 'help'.")
    except IntegrityError as exc:
        print("INTEGRITY ERROR: %s" % exc)
    except ClientError as exc:
        print("error: %s" % exc)
        if client.sock is None:
            return False
    except OSError as exc:
        print("local file error: %s" % exc)
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="Secure file transfer client")
    ap.add_argument("--host", default=config.SERVER_HOST)
    ap.add_argument("--port", type=int, default=config.SERVER_PORT)
    ap.add_argument("--no-tls", action="store_true", help="plain TCP (isolated lab only)")
    ap.add_argument("--cafile", default=config.TLS_CERT, help="server certificate to trust")
    args = ap.parse_args(argv)

    client = SecureFTClient(args.host, args.port, not args.no_tls, args.cafile)
    try:
        client.connect()
    except ClientError as exc:
        print("error: %s" % exc)
        return 1
    print("Connected to %s:%d (%s). Type 'help'." % (args.host, args.port, "plain TCP" if args.no_tls else "TLS"))
    try:
        while True:
            try:
                line = input("sft> ")
            except EOFError:
                break
            if not run_command(client, line):
                break
    except KeyboardInterrupt:
        print()
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
