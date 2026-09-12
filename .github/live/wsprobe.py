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


def _recv(sock, n, buf):
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed mid-frame")
        buf += chunk
    return buf[:n], buf[n:]


def frames(sock, rest=b""):
    """Yield decoded text payloads. Control frames are answered, not yielded."""
    buf = rest
    while True:
        hdr, buf = _recv(sock, 2, buf)
        fin_op, mask_len = hdr[0], hdr[1]
        opcode = fin_op & 0x0F
        length = mask_len & 0x7F
        if length == 126:
            ext, buf = _recv(sock, 2, buf)
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext, buf = _recv(sock, 8, buf)
            length = struct.unpack(">Q", ext)[0]
        if mask_len & 0x80:  # a server must not mask, but decode rather than lie
            mkey, buf = _recv(sock, 4, buf)
        payload, buf = _recv(sock, length, buf)
        if mask_len & 0x80:
            payload = bytes(b ^ mkey[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:      # close
            return
        if opcode == 0x9:      # ping
            send(sock, payload, opcode=0xA)
            continue
        if opcode in (0x1, 0x2):
            yield payload.decode("utf-8", "replace")


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
