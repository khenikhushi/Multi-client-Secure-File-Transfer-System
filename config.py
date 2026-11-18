import os

from dotenv import load_dotenv


load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
USE_TLS = _env_bool("USE_TLS", True)
TLS_CERT = os.getenv("TLS_CERT", "certs/server.crt")
TLS_KEY = os.getenv("TLS_KEY", "certs/server.key")
MAX_CLIENTS = int(os.getenv("MAX_CLIENTS", "100"))
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "104857600"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
STORAGE_DIR = os.getenv("STORAGE_DIR", "storage")
LOG_DIR = os.getenv("LOG_DIR", "logs")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "secure_ft")
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))

MAX_CONTROL_MSG = 65536
CHUNK_SIZE = 65536
IDLE_TIMEOUT = 60
TRANSFER_TIMEOUT = 30
PROTOCOL_VERSION = 1