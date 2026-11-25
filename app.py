"""
app.py  [JOINT FILE]

Wires the controllers into the server and starts the application.

    python app.py            # real controllers (needs MySQL, see README)
    python app.py --mock     # in-memory fake controllers (no database)
    python app.py --plain    # TLS OFF: isolated Wireshark lab with dummy data only
"""
import argparse
import os
import sys
from types import SimpleNamespace

import config
import server


def build_real_controllers():
    # Imported here so --mock works on a machine without MySQL drivers configured.
    from controllers import auth_controller, file_controller
    from services import file_service

    file_service.ensure_storage_dirs()
    removed = file_service.cleanup_stale_temp()
    if removed:
        print("Removed %d stale temp upload(s)." % removed)
    return SimpleNamespace(
        register=auth_controller.register,
        login=auth_controller.login,
        logout=auth_controller.logout,
        list_files=file_controller.list_files,
        begin_upload=file_controller.begin_upload,
        open_download=file_controller.open_download,
    )


def build_mock_controllers():
    from mocks import mock_controllers
    return mock_controllers.build()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Secure file transfer server")
    ap.add_argument("--mock", action="store_true", help="use fake in-memory controllers (no MySQL)")
    ap.add_argument("--plain", action="store_true", help="disable TLS (isolated lab only)")
    ap.add_argument("--host", help="override SERVER_HOST")
    ap.add_argument("--port", type=int, help="override SERVER_PORT")
    args = ap.parse_args(argv)

    cfg = SimpleNamespace(**{k: v for k, v in vars(config).items() if k.isupper()})
    if args.host:
        cfg.SERVER_HOST = args.host
    if args.port:
        cfg.SERVER_PORT = args.port
    if args.plain:
        cfg.USE_TLS = False

    if cfg.USE_TLS and not (os.path.isfile(cfg.TLS_CERT) and os.path.isfile(cfg.TLS_KEY)):
        print("TLS certificate not found. Create one with:  bash scripts/gen_certs.sh")
        return 1

    server.setup_logging(cfg.LOG_DIR)
    controllers = build_mock_controllers() if args.mock else build_real_controllers()
    print("Starting server on %s:%d (%s, %s controllers). Ctrl+C to stop." % (
        cfg.SERVER_HOST, cfg.SERVER_PORT, "TLS" if cfg.USE_TLS else "PLAIN TCP",
        "mock" if args.mock else "real"))
    server.run_server(controllers, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
