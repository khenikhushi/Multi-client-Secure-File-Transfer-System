# Multi-Client Secure File Transfer System — Interface Contract

This document describes the system architecture, protocol, and interfaces.
Keep it consistent with the implementation and test results.

---

## 1. Architecture

```
 CLIENT (client.py)                       SERVER PROCESS
 ┌──────────────┐   TCP + TLS    ┌───────────────────────────────────────────┐
 │ CLI          │◄──────────────►│ app.py                                    │
 │ framing.py   │  4-byte length │   ├── server.py (thread per connection)   │
 └──────────────┘  + JSON, then  │   ├── protocol.py and routes/             │
                   raw bytes     │   └── controllers → services → models     │
                                 │                      ├── MySQL database   │
                                 │                      └── storage and logs │
                                 └───────────────────────────────────────────┘
```

**Dependency injection:** `server.py` receives a controller object from `app.py`.
The app can provide database-backed controllers or in-memory mock controllers.

**Concurrency model:** the server uses one thread per connection, capped by
`MAX_CLIENTS` (default 100). MySQL connections are managed by a connection pool.

---

## 2. Project structure

```text
secure_file_transfer/
├── app.py                       wires controllers into the server
├── config.py                    loads .env and exposes settings
├── server.py                    accepts connections and handles requests
├── client.py                    interactive command-line client
├── protocol.py                  validates protocol requests and responses
│
├── database/
│   ├── __init__.py
│   ├── connection.py            MySQL connection pool and query helpers
│   ├── init_db.py               runs schema.sql and seed.sql
│   ├── schema.sql
│   └── seed.sql                 roles: user, admin
├── models/
│   ├── __init__.py
│   ├── user.py  role.py  file_record.py  session.py  audit_log.py
├── controllers/
│   ├── __init__.py
│   ├── auth_controller.py       register, login, logout
│   └── file_controller.py       list_files, begin_upload, open_download
├── middleware/
│   ├── __init__.py
│   ├── auth_middleware.py       require_session(token, ip)
│   └── validators.py            username / password / filename / size checks
├── services/
│   ├── __init__.py
│   ├── auth_service.py  session_service.py
│   ├── file_service.py  audit_service.py
│
├── routes/
│   ├── __init__.py
│   └── file_routes.py           command → controller mapping
│
├── mocks/
│   ├── __init__.py
│   └── mock_controllers.py      in-memory controllers for testing
│
├── utils/
│   ├── __init__.py
│   ├── framing.py               control-message and file-byte framing
│   ├── hashing.py               SHA-256 helpers
│   ├── passwords.py             password hashing and verification
│   └── paths.py                 safe storage path handling
│
├── certs/                       local TLS certificate and private key
├── scripts/
│   └── gen_certs.sh             creates a local self-signed certificate
├── storage/                     uploaded files and temporary uploads
├── logs/                        server and audit logs
│
├── tests/
│   ├── test_protocol.py         framing tests
│   ├── stress_test.py           concurrent client test
│   ├── test_auth.py             authentication tests
│   └── test_files.py            file and path tests
│
├── docs/
│   ├── protocol.md
│   ├── threat-model.md
│   └── test-plan.md
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

`logs/server.log` records server activity. `logs/audit.log` and the
`audit_logs` table record authentication and file-operation events.

---

## 3. Protocol

### 3.1 Transport and framing

- TCP, wrapped in TLS (TLS 1.2 minimum, certificate from `certs/`). A `USE_TLS=false` switch exists **only** for the isolated-lab Wireshark comparison.
- **Control message** = 4-byte unsigned big-endian length `N`, then `N` bytes of UTF-8 JSON (one object).
- `N` must satisfy `1 <= N <= MAX_CONTROL_MSG` (65 536). Otherwise the server sends a 400 response and closes the connection.
- **File data** is *not* JSON. After a control message announces `size` bytes, exactly `size` raw bytes follow on the same connection, sent in chunks of `CHUNK_SIZE` (65 536). Both sides know the byte count in advance, so no end marker is needed.
- Every read uses an "exact read" helper (loops on `recv` until N bytes or EOF).
- Timeouts: `IDLE_TIMEOUT` 60 s waiting for a control message; `TRANSFER_TIMEOUT` 30 s per chunk.
- The connection stays open for multiple requests (login once, then many commands).

### 3.2 Request

```json
{ "v": 1, "id": "r-0001", "cmd": "LIST", "token": "...", ...command fields }
```

| Field | Type | Notes |
|---|---|---|
| `v` | int | Protocol version, must be `1` |
| `id` | string | Client-chosen request id, echoed in the response (max 64 chars) |
| `cmd` | string | `REGISTER`, `LOGIN`, `LOGOUT`, `LIST`, `GET`, `PUT` |
| `token` | string | Required for everything except `REGISTER` and `LOGIN` |

### 3.3 Response

```json
{ "v": 1, "id": "r-0001", "status": 200, "code": "OK", "message": "Done", "data": {} }
```

`data` is always an object (empty `{}` if nothing to return).

### 3.4 Status codes

| status | code | Meaning |
|---|---|---|
| 200 | `OK` | Success |
| 400 | `BAD_REQUEST` | Malformed JSON, missing/wrong-type field, invalid username/filename/password format, bad frame length |
| 401 | `UNAUTHENTICATED` | Wrong credentials, missing/expired/invalid token |
| 403 | `FORBIDDEN` | Authenticated but not allowed |
| 404 | `NOT_FOUND` | File does not exist (for this user) |
| 409 | `CONFLICT` | Username taken, or file exists and `overwrite` is false |
| 413 | `TOO_LARGE` | File larger than `MAX_FILE_SIZE` (default 100 MB) |
| 422 | `CHECKSUM_MISMATCH` | SHA-256 of received bytes ≠ declared SHA-256 |
| 429 | `TOO_MANY_ATTEMPTS` | Account temporarily locked (5 failed logins → 5 min lock) |
| 500 | `SERVER_ERROR` | Unexpected error (details only in logs, never sent to client) |

Authentication note: login failures use the same message ("Invalid username or
password") whether the username exists or not.

### 3.5 Validation responsibilities

- The protocol layer checks that each message is a JSON object with the
  supported version, a request id, and a known command.
- The application layer validates credentials, sessions, filenames, file
  sizes, hashes, ownership, and file existence.

Current validation rules:
- username: starts with a letter, then 2–31 letters, digits, underscores, or hyphens
- password: 8–1024 characters
- filename: starts with a letter or digit, up to 128 characters; no traversal
  sequences, path separators, trailing period, or reserved Windows device names
- size: `0 < size <= MAX_FILE_SIZE` (100 MiB by default)
- sha256: 64 lowercase hexadecimal characters

### 3.6 Command definitions and examples

**REGISTER**
```json
→ {"v":1,"id":"r-1","cmd":"REGISTER","username":"alice","password":"CorrectHorse9!"}
← {"v":1,"id":"r-1","status":200,"code":"OK","message":"Registered","data":{}}
← {"v":1,"id":"r-1","status":409,"code":"CONFLICT","message":"Username already exists","data":{}}
```

**LOGIN**
```json
→ {"v":1,"id":"r-2","cmd":"LOGIN","username":"alice","password":"CorrectHorse9!"}
← {"v":1,"id":"r-2","status":200,"code":"OK","message":"Logged in",
   "data":{"token":"u3Kf...43chars","expires_in":1800,"username":"alice","role":"user"}}
← {"v":1,"id":"r-2","status":401,"code":"UNAUTHENTICATED","message":"Invalid username or password","data":{}}
```

**LIST**
```json
→ {"v":1,"id":"r-3","cmd":"LIST","token":"u3Kf..."}
← {"v":1,"id":"r-3","status":200,"code":"OK","message":"2 file(s)",
   "data":{"files":[
     {"filename":"report.pdf","size":120394,"sha256":"9f86d0...","modified":"2026-11-16T10:21:05Z"},
     {"filename":"notes.txt","size":220,"sha256":"a1b2c3...","modified":"2026-11-16T10:25:40Z"}]}}
```

**PUT (upload)** — sequence:
```
1. Client computes size and SHA-256 of the local file.
2. C→S  {"v":1,"id":"r-4","cmd":"PUT","token":"u3Kf...","filename":"report.pdf",
         "size":120394,"sha256":"9f86d0...","overwrite":false}
3. S→C  {"v":1,"id":"r-4","status":200,"code":"OK","message":"Ready","data":{}}
        (or an error response → transfer ends, no bytes are sent)
4. C→S  exactly 120394 raw bytes, in 64 KB chunks
5. S→C  {"v":1,"id":"r-4","status":200,"code":"OK","message":"Uploaded and verified",
         "data":{"filename":"report.pdf","size":120394,"sha256":"9f86d0..."}}
        (or 422 CHECKSUM_MISMATCH; the temp file is deleted, nothing is stored)
```
`overwrite` is optional (default `false`).

**GET (download)** — sequence:
```
1. C→S  {"v":1,"id":"r-5","cmd":"GET","token":"u3Kf...","filename":"report.pdf"}
2. S→C  {"v":1,"id":"r-5","status":200,"code":"OK","message":"Sending",
         "data":{"filename":"report.pdf","size":120394,"sha256":"9f86d0..."}}
        (or 404 / 401 → no bytes follow)
3. S→C  exactly 120394 raw bytes
4. Client recomputes SHA-256 while receiving and compares with data.sha256.
   Mismatch → client deletes the partial file and prints an error.
```
The client downloads to `<name>.part` and renames only after the hash matches.

**LOGOUT**
```json
→ {"v":1,"id":"r-6","cmd":"LOGOUT","token":"u3Kf..."}
← {"v":1,"id":"r-6","status":200,"code":"OK","message":"Logged out","data":{}}
```

**Protocol errors (generated by the server)**
```json
← {"v":1,"id":null,"status":400,"code":"BAD_REQUEST","message":"Unknown command","data":{}}
```
If framing is invalid (for example, an invalid length or malformed JSON), the
server returns an error and closes the connection. If the connection drops
during an upload, the server aborts the upload handle.

---

## 4. Authentication and session handling

- `LOGIN` verifies the password with Argon2id (`argon2-cffi`). On success the
  authentication service generates a token with `secrets.token_urlsafe(32)`.
- The token is returned once. The session service stores only
  `SHA-256(token)` in the `sessions` table, so a database leak does not expose
  live tokens.
- Session lifetime is `SESSION_TTL_SECONDS` (default 1800). `LOGOUT` marks the session revoked.
- Controller calls except `register`/`login` take `token` and validate the
  session through `auth_middleware.require_session`.
- Authorization: every file query is scoped by `user_id` taken from the session, never from the request. Users cannot name another user's files. (An admin role exists in the DB for later; it has no extra powers in this version.)
- Lockout: 5 consecutive failed logins → account locked 5 minutes (`failed_attempts`, `locked_until`).
- Token-to-IP binding and per-IP rate limiting are **postponed**; they are listed as limitations in `threat-model.md`.

---

## 5. File data flow

**Upload:**
1. The server routes the PUT request to `file_controller.begin_upload(...)`.
2. The controller checks the session and calls the file service, which
   validates the filename, size, and SHA-256; checks the overwrite rule; and
   returns an `UploadHandle` for a temporary file.
3. The server sends the 200 "Ready" response, reads exactly `size` bytes, and
   writes each chunk through the handle.
4. The server calls `handle.commit()`. The file service flushes and fsyncs,
   compares the computed SHA-256 with the declared one, atomically moves the
   file to `storage/<user_id>/<filename>`, updates the `files` row, and writes
   the audit event.
5. On failure, the server aborts the handle, which removes the temporary file.

**Download:**
1. The server routes the GET request to `file_controller.open_download(...)`.
2. The controller checks the session, and the file service resolves the path
   within the user's directory and returns a `DownloadHandle` with `.size` and
   `.sha256`.
3. The server sends the 200 response with `data`, streams the chunks from
   `handle.read_chunks()`, and closes the handle.

Streaming throughout: neither side loads a whole file into memory.

---

## 6. Integration contract (function signatures)

### 6.1 Return convention

Controllers return a response dict for expected failures:

```python
{"status": int, "code": str, "message": str, "data": dict}
```

The route layer adds the protocol version and request id before sending the
response. Unexpected controller errors are logged and returned as a generic
500 response.

### 6.2 Authentication controller

```python
def register(username: str, password: str, ip: str) -> dict: ...
def login(username: str, password: str, ip: str) -> dict:
    # on success data = {"token": str, "expires_in": int, "username": str, "role": str}
def logout(token: str, ip: str) -> dict: ...
```

### 6.3 File controller

```python
def list_files(token: str, ip: str) -> dict:
    # data = {"files": [{"filename","size","sha256","modified"}, ...]}

def begin_upload(token: str, ip: str, filename: str, size: int,
                 sha256: str, overwrite: bool = False) -> tuple[dict, "UploadHandle | None"]:
    # status 200 -> (response, handle); any error -> (response, None)

def open_download(token: str, ip: str, filename: str) -> tuple[dict, "DownloadHandle | None"]:
    # status 200 -> (response with data={"filename","size","sha256"}, handle); else (response, None)
```

### 6.4 File transfer handles

```python
class UploadHandle:
    def write(self, chunk: bytes) -> None: ...       # append to temp file
    def commit(self) -> dict: ...                    # verify SHA-256, finalize, audit; returns response dict
    def abort(self, reason: str = "") -> None: ...   # delete temp file, audit; safe to call twice

class DownloadHandle:
    size: int
    sha256: str
    def read_chunks(self, chunk_size: int = 65536): ...  # generator of bytes
    def close(self) -> None: ...                         # safe to call twice
```

### 6.5 Controller bundle in `app.py`

```python
from types import SimpleNamespace
controllers = SimpleNamespace(
    register=auth_controller.register, login=auth_controller.login, logout=auth_controller.logout,
    list_files=file_controller.list_files,
    begin_upload=file_controller.begin_upload, open_download=file_controller.open_download,
)
# python app.py          -> real controllers (needs MySQL)
# python app.py --mock   -> mocks.mock_controllers.build() (no DB)
```

### 6.6 Protocol and framing utilities

```python
# utils/framing.py
def recv_exact(sock, n: int) -> bytes                      # raises ConnectionClosed on EOF
def send_message(sock, obj: dict) -> None                  # 4-byte length + JSON
def recv_message(sock, max_size: int = MAX_CONTROL_MSG) -> dict   # raises FramingError
def send_file_bytes(sock, chunk_iter) -> int
def recv_file_bytes(sock, size: int, chunk_size=CHUNK_SIZE)       # generator of chunks

# protocol.py
def validate_request(msg: dict) -> tuple[bool, str]        # (ok, error message)
def make_response(req_id, status: int, code: str, message: str, data: dict | None = None) -> dict

# routes/file_routes.py
def dispatch(request: dict, ip: str, sock, controllers) -> None   # runs the command, sends all replies and file bytes

# server.py
def run_server(controllers, cfg) -> None
```

### 6.7 Shared utility functions

```python
# utils/passwords.py
def hash_password(password: str) -> str
def verify_password(stored_hash: str, password: str) -> bool
# utils/hashing.py
def sha256_file(path: str, chunk_size: int = 65536) -> str
def new_sha256() -> "hashlib._Hash"
# utils/paths.py
def safe_user_path(base_dir: str, user_id: int, filename: str) -> str   # raises ValueError if unsafe
```

---

## 7. Database schema (MySQL 8, InnoDB, utf8mb4)

`database/schema.sql` (tables only; `init_db.py` creates the database named by `DB_NAME` and selects it first, so the name is not hardcoded):

```sql
CREATE TABLE IF NOT EXISTS roles (
  id TINYINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(20) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(32) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,          -- Argon2id encoded string
  role_id TINYINT UNSIGNED NOT NULL DEFAULT 1,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sessions (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,          -- SHA-256 hex of the token
  ip VARCHAR(45) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  revoked TINYINT(1) NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_sessions_expires (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS files (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  filename VARCHAR(128) NOT NULL,
  size_bytes BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_file (user_id, filename),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id INT UNSIGNED NULL,                    -- NULL for failed logins of unknown users
  username VARCHAR(32) NULL,
  event_type VARCHAR(32) NOT NULL,              -- REGISTER, LOGIN, LOGIN_FAIL, LOGOUT, LIST, UPLOAD, DOWNLOAD, UPLOAD_ABORT, ACCESS_DENIED
  success TINYINT(1) NOT NULL,
  detail VARCHAR(255) NULL,
  ip VARCHAR(45) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_user (user_id),
  INDEX idx_audit_time (created_at)
) ENGINE=InnoDB;
```

`database/seed.sql`:
```sql
INSERT IGNORE INTO roles (id, name) VALUES (1,'user'),(2,'admin');
```

All queries use parameterized statements (`cursor.execute(sql, params)`), never string formatting.

---

## 8. Configuration (`config.py` + `.env.example`)

```ini
# .env.example  (copy to .env, never commit .env)
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
USE_TLS=true
TLS_CERT=certs/server.crt
TLS_KEY=certs/server.key
MAX_CLIENTS=100
MAX_FILE_SIZE=104857600
SESSION_TTL_SECONDS=1800
STORAGE_DIR=storage
LOG_DIR=logs
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=secure_ft_user
DB_PASSWORD=change_me
DB_NAME=secure_ft
DB_POOL_SIZE=20
```

`config.py` reads these with `python-dotenv` and exposes them, plus the constants `MAX_CONTROL_MSG=65536`, `CHUNK_SIZE=65536`, `IDLE_TIMEOUT=60`, `TRANSFER_TIMEOUT=30`, `PROTOCOL_VERSION=1`. No credentials are hardcoded anywhere.

---

## 9. Installation prerequisites

- Python 3.10 or newer, MySQL Server 8.x, OpenSSL (to generate the test certificate), Wireshark (Npcap on Windows; capture the loopback adapter), Git.

```bash
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt`:
```text
mysql-connector-python>=8.0
argon2-cffi>=23.1
python-dotenv>=1.0
pytest>=8.0
```

Create a MySQL account for the application:
```sql
CREATE USER 'secure_ft_user'@'localhost' IDENTIFIED BY '<choose-a-password>';
GRANT ALL PRIVILEGES ON secure_ft.* TO 'secure_ft_user'@'localhost';
```
Then `python -m database.init_db`.

Generate a local test certificate with `scripts/gen_certs.sh`:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/server.key -out certs/server.crt \
  -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```
The client verifies the server by loading `certs/server.crt` as its trusted CA file. Verification is never disabled.

---

## 10. Current scope

The project supports registration, login, logout, file listing, upload,
download, SHA-256 integrity verification, optional TLS, and concurrent clients.
The server can run with either MySQL-backed controllers or in-memory mock
controllers for testing.

Features outside the current scope include a graphical interface, resumable
transfers, mutual TLS, per-IP rate limiting, token-to-IP binding, and storage
quotas.
