"""Minimal RFC6455 text-frame client. Stdlib only, on purpose: this runs on a
bare session host where nothing but python3 is guaranteed."""
import base64, json, os, socket, ssl, struct, urllib.parse


def connect(base_url, path="/api/websockets", timeout=20):
    u = urllib.parse.urlsplit(base_url)
    secure = u.scheme in ("https", "wss")
    host = u.hostname
    port = u.port or (443 if secure else 80)
    sock = socket.create_connection((host, port), timeout)
    if secure:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = [
        f"GET {u.path.rstrip('/')}{path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if u.username is not None:
        cred = base64.b64encode(
            f"{u.username}:{u.password or ''}".encode()).decode()
        req.append(f"Authorization: Basic {cred}")
    sock.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f"server closed during handshake: {buf!r}")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].decode()
    if "101" not in status:
        raise RuntimeError(f"upgrade refused: {status}\n{head.decode(errors='replace')}")
    return sock, rest


def _parse(buf):
    """One frame out of the buffer, or None if it is not all there yet.

    Returns (opcode, final, payload, remainder). Parsing from a buffer rather
    than reading exactly-so-many bytes is what makes a read timeout harmless:
    a partially arrived frame stays in the buffer and is finished on the next
    attempt. The obvious version, which recv's each field in turn, loses
    whatever it had already read when a timeout fires in the middle -- and
    since it lived inside a generator, the timeout ended the generator too and
    every later read returned nothing. It took three false failures in one run
    to notice, because a dead reader and a silent server look identical.
    """
    if len(buf) < 2:
        return None
    fin_op, mask_len = buf[0], buf[1]
    at = 2
    length = mask_len & 0x7F
    if length == 126:
        if len(buf) < at + 2:
            return None
        length = struct.unpack(">H", buf[at:at + 2])[0]
        at += 2
    elif length == 127:
        if len(buf) < at + 8:
            return None
        length = struct.unpack(">Q", buf[at:at + 8])[0]
        at += 8
    masked = bool(mask_len & 0x80)
    if masked:
        if len(buf) < at + 4:
            return None
        key = buf[at:at + 4]
        at += 4
    if len(buf) < at + length:
        return None
    payload = buf[at:at + length]
    if masked:  # a server must not mask, but decode rather than lie about it
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return fin_op & 0x0F, bool(fin_op & 0x80), payload, buf[at + length:]


def frames(sock, rest=b""):
    """Yield decoded text payloads, and None whenever a read timed out.

    The None is not noise: it hands control back to a caller that wants to stop
    waiting, without abandoning a frame that is halfway through arriving.

    Control frames are answered rather than yielded, and a fragmented message
    is reassembled before it is. Fragmentation is not hypothetical -- this same
    client drives Chrome's debugging protocol, where a screenshot arrives in
    pieces, and a reader that ignored the continuations would hand back a
    truncated one that still base64-decodes into something almost right.
    """
    buf = rest
    pending = None
    while True:
        parsed = _parse(buf)
        if parsed is None:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                yield None
                continue
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            continue
        opcode, final, payload, buf = parsed
        if opcode == 0x8:      # close
            return
        if opcode == 0x9:      # ping
            send(sock, payload, opcode=0xA)
            continue
        if opcode == 0xA:      # pong, to a ping we never sent
            continue
        if opcode == 0x0:      # continuation of the message before it
            if pending is None:
                continue
            pending += payload
        elif opcode in (0x1, 0x2):
            pending = payload
        else:
            continue
        if final:
            whole, pending = pending, None
            yield whole.decode("utf-8", "replace")


def send(sock, data, opcode=0x1):
    if isinstance(data, str):
        data = data.encode()
    mask = os.urandom(4)
    head = bytes([0x80 | opcode])
    n = len(data)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < (1 << 16):
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def server_settings(base_url, limit=40):
    """Return the server_settings payload the session pushes on connect."""
    sock, rest = connect(base_url)
    try:
        for i, text in enumerate(frames(sock, rest)):
            if text is None:
                continue
            if text.startswith("{"):
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                if msg.get("type") == "server_settings":
                    return msg.get("settings", {})
            if i >= limit:
                break
    finally:
        sock.close()
    raise RuntimeError("no server_settings frame arrived")


if __name__ == "__main__":
    import sys
    print(json.dumps(server_settings(sys.argv[1]), indent=2, sort_keys=True))
