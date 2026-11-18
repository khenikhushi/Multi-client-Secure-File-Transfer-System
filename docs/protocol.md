# Secure File Transfer Protocol

The protocol uses a persistent TCP connection. Each control message is a
UTF-8 JSON object prefixed by a four-byte unsigned big-endian length.

## Commands

- `REGISTER`: create a user account.
- `LOGIN`: authenticate and receive a session token.
- `LOGOUT`: revoke the current session.
- `LIST`: list files owned by the authenticated user.
- `PUT`: begin an upload, then send exactly `size` raw bytes.
- `GET`: begin a download and receive exactly `size` raw bytes.

## Control Messages

Requests contain `v`, `id`, `cmd`, and command-specific fields. Responses
echo the request id and include `status`, `code`, `message`, and `data`.

The server validates protocol structure before dispatch. Invalid frames,
unknown versions, unknown commands, and malformed requests receive a 400
response. Semantic validation, authentication, authorization, and file
ownership checks are handled by the controller and service layers.