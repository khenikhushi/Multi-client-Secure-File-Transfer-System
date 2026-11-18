# Test Plan

## Unit Tests

- Password hashing and verification
- Filename, hash, and traversal protection
- Message framing and partial socket reads
- Raw file byte transfers
- Database operations when MySQL is available

## Integration Tests

Run the mock server and exercise register, login, list, upload, download,
and logout operations over a real TCP connection.

```text
python app.py --mock --plain --host 127.0.0.1 --port 5000
python tests/stress_test.py --host 127.0.0.1 --port 5000 --no-tls --clients 20
```

## Acceptance Criteria

- No framing or protocol test failures
- Uploaded and downloaded files have matching SHA-256 hashes
- Concurrent clients complete without server crashes
- Database tests pass with an initialized MySQL server