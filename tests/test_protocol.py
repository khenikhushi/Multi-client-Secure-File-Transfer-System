"""
tests/test_protocol.py  [PERSON A]
Stage 1: framing tests. Later stages add protocol.py validation tests.
Run:  pytest tests/test_protocol.py -v
"""
import socket
import struct

import pytest

from utils import framing
from utils.framing import ConnectionClosed, FramingError


class TrickleSocket:
    """Fake socket that hands out at most 1 byte per recv() (worst-case TCP)."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def recv(self, _n):
        del _n
        if self.pos >= len(self.data):
            return b""
        b = self.data[self.pos:self.pos + 1]
        self.pos += 1
        return b


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    yield a, b
    a.close()
    b.close()


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def test_message_roundtrip(pair):
    a, b = pair
    msg = {"v": 1, "id": "r-1", "cmd": "LIST", "token": "abc", "name": "héllo ✓"}
    framing.send_message(a, msg)
    assert framing.recv_message(b) == msg


def test_two_messages_back_to_back(pair):
    a, b = pair
    framing.send_message(a, {"n": 1})
    framing.send_message(a, {"n": 2})
    assert framing.recv_message(b) == {"n": 1}
    assert framing.recv_message(b) == {"n": 2}


def test_partial_reads_one_byte_at_a_time():
    data = frame(b'{"cmd":"LIST"}')
    assert framing.recv_message(TrickleSocket(data)) == {"cmd": "LIST"}


def test_recv_exact_eof(pair):
    a, b = pair
    a.sendall(b"abc")
    a.close()
    with pytest.raises(ConnectionClosed):
        framing.recv_exact(b, 10)


def test_eof_in_middle_of_header():
    with pytest.raises(ConnectionClosed):
        framing.recv_message(TrickleSocket(b"\x00\x00"))


def test_eof_in_middle_of_payload():
    with pytest.raises(ConnectionClosed):
        framing.recv_message(TrickleSocket(struct.pack("!I", 50) + b'{"a":1}'))


def test_zero_length_rejected():
    with pytest.raises(FramingError):
        framing.recv_message(TrickleSocket(struct.pack("!I", 0)))


def test_oversize_length_rejected_before_reading_body():
    # Only the header is supplied; the check must fail BEFORE trying to read 1 GB.
    with pytest.raises(FramingError):
        framing.recv_message(TrickleSocket(struct.pack("!I", 1_000_000_000)))


def test_custom_max_size():
    data = frame(b'{"a":"' + b"x" * 100 + b'"}')
    with pytest.raises(FramingError):
        framing.recv_message(TrickleSocket(data), max_size=50)


@pytest.mark.parametrize("payload", [b"not json", b"\xff\xfe\xfd", b"{broken", b"[1,2,3]", b'"text"', b"42"])
def test_bad_payloads_rejected(payload):
    with pytest.raises(FramingError):
        framing.recv_message(TrickleSocket(frame(payload)))


def test_send_oversize_message_refused(pair):
    a, _ = pair
    with pytest.raises(FramingError):
        framing.send_message(a, {"big": "x" * 200}, max_size=50)


def test_file_bytes_roundtrip(pair):
    a, b = pair
    data = bytes(range(256)) * 1000  # 256,000 bytes
    chunks = [data[i:i + 1000] for i in range(0, len(data), 1000)]
    import threading
    t = threading.Thread(target=framing.send_file_bytes, args=(a, iter(chunks)))
    t.start()
    received = b"".join(framing.recv_file_bytes(b, len(data), chunk_size=4096))
    t.join()
    assert received == data


def test_file_bytes_does_not_overread(pair):
    a, b = pair
    a.sendall(b"12345" + frame(b'{"next":true}'))
    assert b"".join(framing.recv_file_bytes(b, 5)) == b"12345"
    assert framing.recv_message(b) == {"next": True}


def test_file_bytes_truncated(pair):
    a, b = pair
    a.sendall(b"only-ten-b")
    a.close()
    with pytest.raises(ConnectionClosed):
        b"".join(framing.recv_file_bytes(b, 100))


def test_zero_size_file(pair):
    _, b = pair
    assert list(framing.recv_file_bytes(b, 0)) == []
