"""Minimal RFC6455 text-frame client. Stdlib only, on purpose: this runs on a
bare session host where nothing but python3 is guaranteed."""
import base64, json, os, socket, ssl, struct, urllib.parse


def credentials(base_url, password_file=None):
    """The user and password to offer, or None.

    A password FILE, not a password argument and not an environment variable.
    What that buys, precisely, and no more:

      * argv is out. /proc/<pid>/cmdline is world-readable, so a credential
        passed as an argument is visible to every account on the box for as
        long as the process lives. Measured on a session host: 68 same-uid
        processes, all 68 command lines readable.
      * the environment is out for the same reason. ProtectProc=invisible does
        NOT hide a process from its own uid, so /proc/<pid>/environ is readable
        by anything running as that user. On a box where the untrusted party
        shares the uid -- which is exactly a desktop session -- an environment
        variable is a marginal improvement on argv, not a fix.

    What it does NOT buy, and no comment here should be read as claiming it:
    the file itself is only as private as its mode and the account that can
    read it, and anything running as this uid can still read our memory, our
    /proc/<pid>/fd and our open descriptors. This is hygiene against casual
    disclosure, not a security boundary against a hostile same-uid process.
    """
    u = urllib.parse.urlsplit(base_url)
    if u.username is not None:
        return u.username, (u.password or "")
    if not password_file:
        return None
    with open(password_file) as f:
        raw = f.read().strip()
    if not raw:
        raise RuntimeError(f"{password_file} is empty; no credential to offer")
    # "user:password", or a bare password for the conventional account.
    if ":" in raw:
        user, pw = raw.split(":", 1)
    else:
        user, pw = "hdw4s", raw
    return user, pw


def challenges(base_url, path="/api/websockets", timeout=20):
    """True if the endpoint refuses an unauthenticated upgrade.

    The positive control for the credential path. Without it, a probe that
    "connected fine" proves nothing about the password it was handed: an
    endpoint with authentication switched off accepts a wrong password, an
    empty one, and no header at all, and every one of them reads as success.
    """
    try:
        sock, _ = connect(base_url, path=path, timeout=timeout, _no_auth=True)
    except RuntimeError as e:
        return "401" in str(e) or "403" in str(e)
    sock.close()
    return False


def connect(base_url, path="/api/websockets", timeout=20,
            password_file=None, _no_auth=False):
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
    cred_pair = None if _no_auth else credentials(base_url, password_file)
    if cred_pair is not None:
        cred = base64.b64encode(
            f"{cred_pair[0]}:{cred_pair[1]}".encode()).decode()
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


def server_settings(base_url, limit=40, password_file=None):
    """Return the server_settings payload the session pushes on connect."""
    sock, rest = connect(base_url, password_file=password_file)
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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--password-file", help="file holding 'user:password'")
    ap.add_argument("--require-auth", action="store_true",
                    help="fail unless the endpoint refuses an unauthenticated "
                         "upgrade -- the positive control for the credential")
    a = ap.parse_args()
    if a.require_auth and not challenges(a.url):
        raise SystemExit("wsprobe: %s does not challenge an unauthenticated "
                         "upgrade; a success here would say nothing about the "
                         "credential" % a.url)
    print(json.dumps(server_settings(a.url, password_file=a.password_file),
                     indent=2, sort_keys=True))
