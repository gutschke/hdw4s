"""One headless Chrome, driven over CDP, with no dependencies.

The old walkthrough drove Chrome through the `websockets` package and asyncio.
Both are gone here: CDP is a websocket protocol like any other, `wsprobe`
already speaks it, and a test that is synchronous is a test whose failures are
readable. Nothing in this file is specific to a transport or to a client
version, so it survives the parts of the walkthrough that do not.

Two guards live here rather than in the walkthrough, because forgetting either
one has already cost a day:

  * `kill_strays`, because a run cut short never reaches its cleanup and the
    browser it leaves behind goes on holding the session invisibly;
  * `attached_stable`, because one reading of who is connected is not enough
    and a test that interferes with a real user is worse than no test.
"""
import base64
import glob
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
import zlib

import wsprobe

PROFILE_PREFIX = "hdw4s-live-"


class Browser:
    def __init__(self, port, tag, headers=None):
        self.port, self.tag = port, tag
        self.headers = headers or {}
        self.profile = tempfile.mkdtemp(prefix=PROFILE_PREFIX + tag + "-",
                                        dir="/dev/shm")
        self.proc = self.sock = None
        self._id = 0
        # Websocket frames the page received, tallied by the first byte of the
        # payload, which is the session protocol's type tag: 0x01 audio,
        # 0x03/0x04 video. This is the only audio oracle that is independent of
        # the decoder, the worklet, the volume and whether the desktop happens
        # to be making a noise -- every page-side audio signal is
        # indistinguishable from silence otherwise.
        self.wire = {}

    def start(self):
        self.proc = subprocess.Popen([
            "google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu",
            "--disable-extensions", "--disable-background-networking",
            "--remote-debugging-port=%d" % self.port,
            "--user-data-dir=" + self.profile,
            "--no-first-run", "--no-default-browser-check",
            # Without this the audio element never starts and the test measures
            # Chrome's autoplay policy rather than the session.
            "--autoplay-policy=no-user-gesture-required",
            "--use-fake-ui-for-media-stream",
            "--window-size=1280,800",
            "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _connect(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                targets = json.loads(urllib.request.urlopen(
                    "http://127.0.0.1:%d/json" % self.port, timeout=2).read())
                pages = [t for t in targets if t.get("type") == "page"]
                if pages:
                    url = pages[0]["webSocketDebuggerUrl"]
                    _, _, rest = url.partition("://")
                    hostport, _, path = rest.partition("/")
                    self.sock, self._rest = wsprobe.connect(
                        "http://" + hostport, path="/" + path)
                    self.sock.settimeout(30)
                    self._frames = wsprobe.frames(self.sock, self._rest)
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def call(self, method, params=None, timeout=30):
        """One CDP command, and the reply to it. Events in between are dropped."""
        self._id += 1
        want = self._id
        wsprobe.send(self.sock, json.dumps(
            {"id": want, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                text = next(self._frames)
            except (StopIteration, OSError):
                return None
            if text is None:          # nothing arrived yet; keep waiting
                continue
            try:
                msg = json.loads(text)
            except ValueError:
                continue
            if msg.get("id") == want:
                return msg.get("result")
            self._event(msg)
        return None

    def _event(self, msg):
        if msg.get("method") != "Network.webSocketFrameReceived":
            return
        payload = msg.get("params", {}).get("response", {}).get("payloadData")
        if not payload:
            return
        try:
            first = base64.b64decode(payload[:4] + "==")[:1]
        except Exception:
            return
        if first:
            self.wire[first[0]] = self.wire.get(first[0], 0) + 1

    def pump(self, seconds):
        """Read events for a while, so the tally reflects that interval.

        Nothing else drives the connection: without this the tally only
        advances as a side effect of whatever command happens to be in flight.
        """
        deadline = time.time() + seconds
        self.sock.settimeout(0.5)
        try:
            while time.time() < deadline:
                try:
                    text = next(self._frames)
                except (StopIteration, OSError):
                    return
                if text is None:
                    continue
                try:
                    self._event(json.loads(text))
                except ValueError:
                    pass
        finally:
            self.sock.settimeout(30)

    def open(self, page, timeout=90):
        if not self._connect(timeout):
            return False
        for m in ("Page.enable", "Runtime.enable", "Network.enable"):
            self.call(m)
        if self.headers:
            self.call("Network.setExtraHTTPHeaders", {"headers": self.headers})
        self.call("Page.navigate", {"url": page}, timeout=timeout)
        time.sleep(2.0)
        return True

    def eval(self, expression, timeout=30):
        r = self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True,
            "awaitPromise": True}, timeout=timeout)
        if not r:
            return None
        return r.get("result", {}).get("value")

    def wait_for(self, expression, accept, timeout=90, gap=0.5):
        """Poll until the expression satisfies `accept`, then return it.

        `accept` is a predicate, not a set: a status oracle that is a string in
        one client version and an object in the next should be the caller's
        problem, not a silent timeout here.
        """
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            last = self.eval(expression)
            if accept(last):
                return last
            time.sleep(gap)
        return last

    def screenshot(self):
        """Raw RGB pixels of what is on the screen, as (width, height, bytes).

        Decoded here rather than measured in the page on purpose. Anything
        evaluated in the page is the client's own account of itself, and the
        reason this walkthrough exists at all is that every state the client
        reported was correct while the user looked at a spinner. A screenshot
        is the one observation the client cannot get wrong.
        """
        r = self.call("Page.captureScreenshot", {"format": "png"}, timeout=60)
        if not r or "data" not in r:
            return None
        return _decode_png(r["data"])

    def stop(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


def _decode_png(b64):
    """Minimal PNG reader: 8-bit truecolour, the only thing CDP returns.

    Enough to count colours. It is not a general decoder and does not pretend
    to be one -- it returns None rather than guessing at anything else.
    """
    import base64
    raw = base64.b64decode(b64)
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos, idat, width = 8, b"", None
    while pos < len(raw):
        (length,) = struct.unpack(">I", raw[pos:pos + 4])
        kind = raw[pos + 4:pos + 8]
        body = raw[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack(">IIBB", body[:10])
            if depth != 8 or colour not in (2, 6):
                return None
            stride = width * (3 if colour == 2 else 4)
            pixel = 3 if colour == 2 else 4
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length
    if width is None:
        return None
    data = bytearray(zlib.decompress(idat))
    out = bytearray()
    prev = bytearray(stride)
    at = 0
    for _ in range(height):
        filt = data[at]
        line = bytearray(data[at + 1:at + 1 + stride])
        at += 1 + stride
        for i in range(stride):
            a = line[i - pixel] if i >= pixel else 0
            b = prev[i]
            c = prev[i - pixel] if i >= pixel else 0
            if filt == 1:
                line[i] = (line[i] + a) & 0xFF
            elif filt == 2:
                line[i] = (line[i] + b) & 0xFF
            elif filt == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 0xFF
            elif filt == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc
                                      else b if pb <= pc else c)) & 0xFF
        out += line
        prev = line
    return width, height, bytes(out), pixel


def colours(shot, step=7):
    """How many distinct colours are on screen, sampled.

    A desktop has thousands. A spinner on a dark page, a splash, or a canvas
    that never received a frame has a handful. Sampling every seventh pixel
    keeps a full-screen count under a second in pure Python and does not change
    the answer at the scale that matters.
    """
    if not shot:
        return 0
    _, _, data, pixel = shot
    seen = set()
    for i in range(0, len(data) - pixel, pixel * step):
        seen.add(data[i:i + 3])
    return len(seen)


def kill_strays():
    """Kill headless browsers a previous run leaked.

    A run cut short by a timeout never reaches its cleanup, and the browser it
    leaves behind keeps its connection to the session open, so it goes on
    holding the session for as long as the machine is up. Two of them once sat
    there for three quarters of an hour refusing every window this test opened,
    and the refusals were written up as a defect in the product. Only browsers
    carrying this test's own profile prefix are touched.
    """
    pids = subprocess.run(
        ["pgrep", "-f", "--", "user-data-dir=/dev/shm/" + PROFILE_PREFIX],
        capture_output=True, text=True).stdout.split()
    for sig in (15, 9):
        for pid in pids:
            try:
                os.kill(int(pid), sig)
            except OSError:
                pass
        if pids and sig == 15:
            time.sleep(2)
    for d in glob.glob("/dev/shm/" + PROFILE_PREFIX + "*"):
        shutil.rmtree(d, ignore_errors=True)
    return len(pids)


def attached(port):
    """Clients connected to the session right now, or None if unknowable.

    Counted on the machine the session runs on. Aimed at a public URL from
    somewhere else the connections are not visible here at all, and this says
    None rather than reporting a confident zero.
    """
    if not port:
        return None
    out = subprocess.run(["ss", "-Htn", "state", "established",
                          "sport = :%d" % port], capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return len([l for l in out.stdout.splitlines() if l.strip()])


def attached_stable(port, samples=4, gap=1.5):
    """The largest count over a few seconds.

    One reading is not enough. A real client that has just been refused, or is
    between connections, shows nothing for an instant and then comes back. Two
    runs of the old walkthrough started against a session a browser was about
    to reclaim and reported the resulting refusal as a failure of the feature.
    """
    seen = attached(port)
    if seen is None:
        return None
    for _ in range(samples - 1):
        time.sleep(gap)
        seen = max(seen, attached(port) or 0)
    return seen
