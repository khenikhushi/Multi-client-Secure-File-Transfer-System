# Threat Model

## Assets

- User credentials and Argon2id password hashes
- Session tokens and account state
- Stored files and file integrity hashes
- Audit and server logs

## Threats and Mitigations

- Password disclosure: passwords are never stored or logged; Argon2id hashes
  are stored instead.
- Session theft: database records store only SHA-256 token hashes.
- SQL injection: database operations use parameterized SQL.
- Path traversal: filenames and resolved user storage paths are validated.
- File corruption: SHA-256 hashes are checked during upload and download.
- Log injection: audit values are stripped and length-limited.
- Unauthorized file access: file queries and paths are scoped to the session
  user id.
- Transport interception: TLS is enabled by default; plain TCP is limited to
  isolated lab use.

## Current Limitations

Token-to-IP binding and per-IP rate limiting are not yet implemented.