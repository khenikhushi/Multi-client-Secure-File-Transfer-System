"""
utils/framing.py  [PERSON A]

Message framing for the secure file transfer protocol.

Control message  = 4-byte big-endian length + UTF-8 JSON object.
File data        = raw bytes, exactly `size` bytes, sent right after a
                   control message that announced the size.

TCP is a byte stream: one send() does NOT equal one recv(). That is why
every read goes through recv_exact(), which loops until all bytes arrive.
"""
import json
import struct

from config import CHUNK_SIZE, MAX_CONTROL_MSG


class FramingError(Exception):
    """The bytes received do not follow the protocol (bad length, bad JSON...)."""


class ConnectionClosed(Exception):
    """The other side closed the connection before we got all the bytes."""


def recv_exact(sock, n):
    """Read exactly n bytes from sock, or raise ConnectionClosed."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:  # empty bytes means the peer closed the connection
            raise ConnectionClosed(
                "connection closed after %d of %d bytes" % (len(buf), n)
            )
        buf.extend(chunk)
    return bytes(buf)


def send_message(sock, obj, max_size=MAX_CONTROL_MSG):
    """Send one JSON control message (dict) with a 4-byte length prefix."""
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > max_size:
        raise FramingError("message too large to send (%d bytes)" % len(data))
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_message(sock, max_size=MAX_CONTROL_MSG):
    """
    Receive one JSON control message and return it as a dict.
    Raises FramingError for a bad length, invalid UTF-8/JSON, or a
    JSON value that is not an object. Raises ConnectionClosed on EOF.
    """
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        raise FramingError("empty message")
    if length > max_size:
        raise FramingError("message too large (%d > %d)" % (length, max_size))
    payload = recv_exact(sock, length)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FramingError("message is not valid UTF-8 JSON")
    if not isinstance(obj, dict):
        raise FramingError("message must be a JSON object")
    return obj


def send_file_bytes(sock, chunk_iter):
    """Send raw file bytes from an iterable of bytes chunks. Returns total sent."""
    total = 0
    for chunk in chunk_iter:
        sock.sendall(chunk)
        total += len(chunk)
    return total


def recv_file_bytes(sock, size, chunk_size=CHUNK_SIZE):
    """
    Generator: yields chunks until exactly `size` bytes were received.
    Never reads past `size`, so the next control message stays intact.
    Raises ConnectionClosed if the peer disconnects early.
    """
    remaining = size
    while remaining > 0:
        chunk = sock.recv(min(chunk_size, remaining))
        if not chunk:
            raise ConnectionClosed(
                "connection closed with %d bytes still expected" % remaining
            )
        remaining -= len(chunk)
        yield chunk
