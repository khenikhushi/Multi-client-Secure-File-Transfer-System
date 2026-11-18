# INTERFACE_CONTRACT.md — Multi-Client Secure File Transfer System

**Status: DRAFT v1 → becomes FROZEN once both members sign off (Day 1, Hour 0–1).**
After freezing, any change needs both members to agree and a version bump at the bottom of this file.

---

## 1. Architecture

```
 CLIENT (client.py)                       SERVER PROCESS
 ┌──────────────┐   TCP + TLS    ┌─────────────────────────────────────────────┐
 │ CLI          │◄──────────────►│  PERSON A                  PERSON B         │
 │ framing.py   │  4-byte length │  server.py                                  │
 └──────────────┘  + JSON, then  │    │ thread per connection                  │
                   raw bytes     │  utils/framing.py                           │
                                 │    │                                        │
                                 │  protocol.py  (validate shape, dispatch)    │
                                 │    │                                        │
                                 │  routes/file_routes.py                      │
                                 │    │  ═══ INTEGRATION BOUNDARY ═══          │
                                 │    ▼  (controllers injected by app.py)      │
                                 │  controllers/  → middleware/ → services/    │
                                 │                              → models/      │
                                 │                              → database/ ── MySQL
                                 │                              → storage/, logs/
                                 └─────────────────────────────────────────────┘
```

**Rule of the boundary:** Person A never imports anything from `database/`, `models/`, `services/`, `middleware/`. Person A only calls the six controller functions in §6. Person B never imports `socket`, `ssl`, `server`, `client`, `protocol`, `framing`.

**Dependency injection:** `server.py` does not import controllers. `app.py` builds a `Controllers` object (real or mock) and passes it to `server.run_server(controllers, config)`. That is how A tests with mocks and B tests without a socket.

**Concurrency model:** one thread per connection (`threading.Thread`), capped by `MAX_CLIENTS` (default 100, enforced with a `BoundedSemaphore`). MySQL access uses a connection pool (`pool_size=20`) inside Person B's `database/connection.py`. Simple, beginner-friendly, and enough for 50+ clients.

---

## 2. Final directory structure and ownership

`[A]` = Person A only, `[B]` = Person B only, `[J]` = joint (created once in Hour 0, then changed only by agreement).

```text
secure_file_transfer/
├── app.py                       [J] wires controllers into server; --mock flag
├── config.py                    [J] loads .env, exposes constants (frozen §9)
├── server.py                    [A]
├── client.py                    [A]
├── protocol.py                  [A]
│
├── database/                    [B]
│   ├── __init__.py
│   ├── connection.py            pool + get_connection()
│   ├── init_db.py               runs schema.sql + seed.sql
│   ├── schema.sql               (§7)
│   └── seed.sql                 roles: user, admin
├── models/                      [B]
│   ├── __init__.py
│   ├── user.py  role.py  file_record.py  session.py  audit_log.py
├── controllers/                 [B]
│   ├── __init__.py
│   ├── auth_controller.py       register, login, logout
│   └── file_controller.py       list_files, begin_upload, open_download
├── middleware/                  [B]
│   ├── __init__.py
│   ├── auth_middleware.py       require_session(token, ip)
│   └── validators.py            username / password / filename / size checks
├── services/                    [B]
│   ├── __init__.py
│   ├── auth_service.py  session_service.py
│   ├── file_service.py  audit_service.py
│
├── routes/
│   ├── __init__.py
│   └── file_routes.py           [A] command → controller mapping
│
├── mocks/
│   ├── __init__.py
│   └── mock_controllers.py      [A] fake controllers so A needs no DB
│
├── utils/
│   ├── __init__.py              [J] empty
│   ├── framing.py               [A]
│   ├── hashing.py               [B]
│   ├── passwords.py             [B]
│   └── paths.py                 [B]
│
├── certs/                       [A] gitignored; server.crt / server.key
├── scripts/
│   └── gen_certs.sh             [A] openssl self-signed cert
├── storage/                     [B] runtime, gitignored (storage/<user_id>/, storage/.tmp/)
├── logs/                        [B] audit.log / app.log;  [A] server.log
│
├── tests/
│   ├── test_protocol.py         [A]
│   ├── stress_test.py           [A] N concurrent clients
│   ├── test_auth.py             [B]
│   └── test_files.py            [B]
│
├── docs/
│   ├── protocol.md              [A]
│   ├── threat-model.md          [B]
│   └── test-plan.md             [J]
│
├── INTERFACE_CONTRACT.md        [J] this file
├── requirements.txt  .env.example  .gitignore  README.md   [J]
```

`logs/server.log` (connections, disconnects, protocol errors) is Python `logging` written by A. `logs/audit.log` plus the `audit_logs` table (logins, file operations) is written by B.

**Git workflow:** branches `person-a` and `person-b`; each only commits to their own paths; `[J]` files are edited on `main` by agreement. Merge to `main` at the end of Day 1 and again at the end of Day 2.

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

Security note for B: login failures always return the same message ("Invalid username or password") whether the user exists or not.

### 3.5 Who validates what

- **Person A (syntactic):** valid JSON, `v == 1`, `cmd` is known, required fields exist with the right Python types, `size` is a non-negative int. Failure → 400 straight from A.
- **Person B (semantic):** username/password/filename formats, size limit, path safety, existence, ownership, session validity. B returns the error response; A forwards it unchanged.

Validation rules B applies:
- username: `^[A-Za-z0-9_]{3,32}$`
- password: 8–128 characters
- filename: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, must not contain `..`, no slashes, no spaces
- size: `0 < size <= MAX_FILE_SIZE`
- sha256: 64 lowercase hex characters

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

**Protocol errors (generated by A)**
```json
← {"v":1,"id":null,"status":400,"code":"BAD_REQUEST","message":"Unknown command","data":{}}
```
If the framing itself is broken (length 0, length above the limit, invalid UTF-8/JSON), A sends one 400 response and closes the connection. If the connection drops mid-upload, A calls `handle.abort()`.

---

## 4. Authentication and session handling

- `LOGIN` verifies the password with Argon2id (`argon2-cffi`). On success B generates a token with `secrets.token_urlsafe(32)`.
- The token is returned once. B stores only `SHA-256(token)` in the `sessions` table, so a database leak does not leak live tokens.
- Session lifetime is `SESSION_TTL_SECONDS` (default 1800). `LOGOUT` marks the session revoked.
- Every controller call except `register`/`login` takes `token` and performs the session check itself (B's `auth_middleware.require_session`). A never inspects tokens.
- Authorization: every file query is scoped by `user_id` taken from the session, never from the request. Users cannot name another user's files. (An admin role exists in the DB for later; it has no extra powers in this version.)
- Lockout: 5 consecutive failed logins → account locked 5 minutes (`failed_attempts`, `locked_until`).
- Token-to-IP binding and per-IP rate limiting are **postponed**; they are listed as limitations in `threat-model.md`.

---

## 5. File data flow

**Upload:**
1. A parses PUT, calls `file_controller.begin_upload(...)`.
2. B checks session, validates filename/size/sha256, checks overwrite rule, creates `storage/.tmp/<random>.part`, and returns an `UploadHandle`.
3. A sends the 200 "Ready" response, then reads exactly `size` bytes and calls `handle.write(chunk)` for each chunk.
4. A calls `handle.commit()`. B flushes and fsyncs, compares computed SHA-256 with the declared one, then `os.replace()` moves the file to `storage/<user_id>/<filename>` (atomic), upserts the `files` row, writes the audit event, and returns the final response dict.
5. On any failure A calls `handle.abort(reason)` and B deletes the temp file.

**Download:**
1. A calls `file_controller.open_download(...)`.
2. B checks the session, resolves the path with `utils/paths.py` (confined to the user's directory), and returns a `DownloadHandle` with `.size` and `.sha256`.
3. A sends the 200 response with `data`, then streams `for chunk in handle.read_chunks(): send(chunk)`, then `handle.close()`.

Streaming throughout: neither side loads a whole file into memory.

---

## 6. Integration contract (function signatures)

### 6.1 Return convention

Controllers **never raise** for expected failures. They return a response dict:

```python
{"status": int, "code": str, "message": str, "data": dict}
```

A wraps it with `v` and `id` before sending. If a controller raises anyway, A logs the traceback, sends a generic 500, and keeps serving other clients.

### 6.2 `controllers/auth_controller.py` (B implements, A calls)

```python
def register(username: str, password: str, ip: str) -> dict: ...
def login(username: str, password: str, ip: str) -> dict:
    # on success data = {"token": str, "expires_in": int, "username": str, "role": str}
def logout(token: str, ip: str) -> dict: ...
```

### 6.3 `controllers/file_controller.py` (B implements, A calls)

```python
def list_files(token: str, ip: str) -> dict:
    # data = {"files": [{"filename","size","sha256","modified"}, ...]}

def begin_upload(token: str, ip: str, filename: str, size: int,
                 sha256: str, overwrite: bool = False) -> tuple[dict, "UploadHandle | None"]:
    # status 200 -> (response, handle); any error -> (response, None)

def open_download(token: str, ip: str, filename: str) -> tuple[dict, "DownloadHandle | None"]:
    # status 200 -> (response with data={"filename","size","sha256"}, handle); else (response, None)
```

### 6.4 Handle objects (B implements in `services/file_service.py`, A uses)

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

### 6.5 `Controllers` bundle (joint, in `app.py`)

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

### 6.6 A's own interfaces (for reference and tests)

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

### 6.7 `utils` that B exposes (used inside B's services only)

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

MySQL (one-time, by Person B):
```sql
CREATE USER 'secure_ft_user'@'localhost' IDENTIFIED BY '<choose-a-password>';
GRANT ALL PRIVILEGES ON secure_ft.* TO 'secure_ft_user'@'localhost';
```
Then `python -m database.init_db`.

Test certificate (Person A), in `scripts/gen_certs.sh`:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/server.key -out certs/server.crt \
  -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```
The client verifies the server by loading `certs/server.crt` as its trusted CA file. Verification is never disabled.

---

## 10. Two-day task allocation

### DAY 1 — build independently, integrate at the end

| Hour | Person A | Person B |
|---|---|---|
| 0–1 | **Both:** review and freeze this contract; create repo, `config.py`, `.env.example`, `requirements.txt`, empty package folders | same |
| 1–3 | `utils/framing.py` + `tests/test_protocol.py` (framing, partial reads, oversize, bad JSON) | `database/` (schema, pool, init), `models/`, `utils/passwords.py`, `utils/hashing.py`, `utils/paths.py` |
| 3–5 | `protocol.py`, `mocks/mock_controllers.py`, `routes/file_routes.py` | `services/auth_service.py`, `session_service.py`, `audit_service.py`, `middleware/`, `controllers/auth_controller.py`, `tests/test_auth.py` |
| 5–7 | `server.py` (threads, TLS, timeouts, shutdown), `scripts/gen_certs.sh`, `client.py` (login, list) | `services/file_service.py` (handles), `controllers/file_controller.py`, `tests/test_files.py` |
| 7–8 | **Integration:** write `app.py`; run server with `--mock`; run real controllers; fix interface mismatches | same |

**Day 1 exit criteria:** `REGISTER → LOGIN → LIST` works end to end over TLS against real MySQL; `pytest tests/test_protocol.py tests/test_auth.py` passes.

### DAY 2 — complete, verify, document

| Hour | Person A | Person B |
|---|---|---|
| 0–2 | `client.py` PUT/GET with hash verification and `.part` rename; large-file test | Verify upload atomicity, size limit, overwrite rule, traversal attempts (`../`, absolute paths, encoded variants) |
| 2–4 | `tests/stress_test.py`; run 10 → 25 → 50 → 100 clients; fix timeouts and thread issues | Check DB pool under load, audit log completeness, lockout behavior; tune pool size |
| 4–5 | **Both:** Wireshark capture with `USE_TLS=false` (dummy credentials, isolated lab), then with TLS; screenshots of both | same |
| 5–7 | `docs/protocol.md`, README run instructions | `docs/threat-model.md`, README setup/DB section |
| 7–8 | **Both:** `docs/test-plan.md` with actual results, final regression run, demo rehearsal | same |

### Progress checklist

**Person A**
- [ ] Contract frozen
- [ ] `utils/framing.py` + tests
- [ ] `protocol.py`
- [ ] `mocks/mock_controllers.py`
- [ ] `routes/file_routes.py`
- [ ] `server.py` (TCP → TLS → threads → shutdown)
- [ ] `scripts/gen_certs.sh`
- [ ] `client.py` (register, login, list)
- [ ] `client.py` (put, get + hash check)
- [ ] `tests/stress_test.py` (50+ clients)
- [ ] `docs/protocol.md`

**Person B**
- [ ] Contract frozen
- [ ] `database/` + `init_db`
- [ ] `models/`
- [ ] `utils/passwords.py`, `hashing.py`, `paths.py`
- [ ] `services/` (auth, session, audit)
- [ ] `middleware/`
- [ ] `controllers/auth_controller.py` + `tests/test_auth.py`
- [ ] `services/file_service.py` (handles)
- [ ] `controllers/file_controller.py` + `tests/test_files.py`
- [ ] `docs/threat-model.md`

**Joint**
- [ ] `app.py` integration
- [ ] End-to-end LIST/GET/PUT over TLS
- [ ] Concurrency test (50+)
- [ ] Wireshark plaintext vs TLS evidence
- [ ] README, `test-plan.md`, final demo

### Recommended to postpone (not needed for the deadline)

Frontend/GUI, admin features, file deletion/rename, resumable transfers, mutual TLS, per-IP rate limiting, token-IP binding, DB migrations beyond `schema.sql`, compression.

---

## 11. Change log

| Version | Date | Change | Agreed by |
|---|---|---|---|
| 1 (draft) | 2026-11-16 | Initial contract | pending A / pending B |
| 1.1 | 2026-11-16 | §7: `CREATE DATABASE`/`USE` moved from schema.sql into `init_db.py` (DB name from `.env`; also works on MariaDB). §3.5 filename rule tightened inside B's `utils/paths.py` only: also rejects `..` anywhere, trailing `.`, and Windows device names (CON, NUL, COM1...). No change visible to A. | pending A / pending B |
| 1.2 | 2026-11-16 | Clarifications, no signature changes. §3.4/§4: `LOGIN` with malformed username/password returns 401 (same as wrong credentials), not 400; `REGISTER` still returns 400 for bad format. A locked account returns 429 before the password is checked. New A-owned `tests/test_routes.py`; new B-owned `services/errors.py` (AppError, internal to B) and `tests/test_database.py`. Routes behaviour: a server-side storage failure during PUT/GET closes the connection after a best-effort 500. | pending A / pending B |
| 1.3 | 2026-11-16 | Stage 3, no signature changes. Behaviour now fixed: uploads stage in `storage/.tmp/<user_id>_<random>.part` and are finalized with an atomic `os.replace`; a global lock around name-check + rename + DB write guarantees that of N concurrent uploads of one filename (overwrite=false) exactly one succeeds and the rest get 409. A traversal-looking filename returns 400 and writes an `ACCESS_DENIED` audit event; a symlink escaping the user folder returns 403. `server.py`: `Server(...)` class plus `run_server(controllers, cfg)`; TLS handshake runs in the client's own thread; connections beyond `MAX_CLIENTS` are closed immediately; idle connections close after `IDLE_TIMEOUT`; `shutdown()` closes idle clients at once and lets in-flight requests finish. `routes` now restores the socket timeout the server had set. Client downloads to `<name>.part` and renames only after the SHA-256 matches. `utils/passwords.py` limits concurrent Argon2 hashes to 4 (memory protection). New: `scripts/gen_certs.sh`, `app.py`, `tests/test_server.py` (A), `tests/test_integration.py` (joint). | pending A / pending B |
