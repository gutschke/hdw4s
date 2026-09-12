"""The basic walk-through: two windows, one hand-over, does everything still work?

Every other suite here asserts that the signalling server moves between the
right states. None of them ever asserted that a session reaches the screen --
which is how a build shipped that handed the session over correctly and left
the viewer behind a spinner with no sound. This one drives two real browsers
against a real session and asks the only questions a user asks: is there a
picture, is there sound, and has the spinner gone away.

It runs against a live session, so it refuses to start if anyone is attached.

    HDW4S_WT_USER=... HDW4S_WT_PASSWORD=... walkthrough.py <port>
"""
import asyncio, base64, glob, json, os, shutil, subprocess, sys, tempfile, time, urllib.request

import websockets

PORT = int(sys.argv[1])
PAGE = "http://127.0.0.1:%d/" % PORT
# Taken from the environment, not the command line, so the session's credential
# does not appear in ps for every account on the machine.
USER = os.environ["HDW4S_WT_USER"]
PASSWORD = os.environ["HDW4S_WT_PASSWORD"]
AUTH = "Basic " + base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode()

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print("  %-4s %-52s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def attached():
    """Connections the socket proxy is relaying, i.e. real clients."""
    out = subprocess.run(["sudo", "-n", "ss", "-Htnp", "state", "established",
                          "dport = :%d" % PORT], capture_output=True, text=True).stdout
    return sum(1 for line in out.split("\n") if "systemd-socket-" in line)


class Browser:
    """One headless Chrome, driven over CDP."""

    def __init__(self, port, tag):
        self.port, self.tag = port, tag
        self.profile = tempfile.mkdtemp(prefix="hdw4s-wt-%s-" % tag, dir="/dev/shm")
        self.proc = self.ws = None
        self._id = 0

    def start(self):
        self.proc = subprocess.Popen([
            "google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu",
            "--disable-extensions", "--disable-background-networking",
            "--remote-debugging-port=%d" % self.port,
            "--user-data-dir=" + self.profile,
            "--no-first-run", "--no-default-browser-check",
            # Without this the audio element never starts and the test would
            # be measuring Chrome's autoplay policy rather than the session.
            "--autoplay-policy=no-user-gesture-required",
            "--use-fake-ui-for-media-stream",
            "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    async def _send(self, method, params=None):
        self._id += 1
        await self.ws.send(json.dumps({"id": self._id, "method": method,
                                       "params": params or {}}))
        return self._id

    async def attach(self, timeout=60):
        url = "http://127.0.0.1:%d/json" % self.port
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                targets = json.loads(urllib.request.urlopen(url, timeout=2).read())
                pages = [t for t in targets if t.get("type") == "page"]
                if pages:
                    self.ws = await websockets.connect(
                        pages[0]["webSocketDebuggerUrl"], max_size=20 * 1024 * 1024)
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)
        if self.ws is None:
            return False
        for m in ("Page.enable", "Runtime.enable", "Network.enable"):
            await self._send(m)
        # The session is behind the proxy's basic auth. Setting the header
        # beats putting credentials in the URL, which Chrome has stripped for
        # years and which would silently test the 401 page instead.
        await self._send("Network.setExtraHTTPHeaders",
                         {"headers": {"Authorization": AUTH}})
        await self._send("Page.navigate", {"url": PAGE})
        end = loop.time() + timeout
        while loop.time() < end:
            try:
                msg = json.loads(await asyncio.wait_for(self.ws.recv(), 2.0))
            except asyncio.TimeoutError:
                continue
            if msg.get("method") == "Page.loadEventFired":
                await asyncio.sleep(1.0)
                return bool(await self.eval("!!window.app"))
        return False

    async def eval(self, expr, timeout=15):
        i = await self._send("Runtime.evaluate", {
            "expression": expr, "returnByValue": True, "awaitPromise": True})
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout))
            except asyncio.TimeoutError:
                return None
            if msg.get("id") == i:
                return msg.get("result", {}).get("result", {}).get("value")
        return None

    async def wait_for(self, expr, wanted, timeout=45):
        """Poll until the expression is one of `wanted`, then return it."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        last = None
        while loop.time() < deadline:
            last = await self.eval(expr)
            if last in wanted:
                return last
            await asyncio.sleep(0.5)
        return last

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


# How much media has actually arrived. Asking the peer connection rather than
# the element, because a <video> in headless Chrome reports a duration and a
# readyState whether or not a single frame ever decoded -- which is exactly how
# "the stream is fine" was believed while the viewer saw a spinner.
BYTES = """(async () => {
  const out = {video: 0, audio: 0};
  for (const [name, w] of [['video', window.webrtc], ['audio', window.audio_webrtc]]) {
    try {
      const pc = w && w.peerConnection;
      if (!pc) continue;
      const stats = await pc.getStats();
      stats.forEach((r) => {
        if (r.type === 'inbound-rtp' && !r.isRemote) out[name] += (r.bytesReceived || 0);
      });
    } catch (e) { /* no connection yet */ }
  }
  return out;
})()"""

SPINNER = """(() => {
  const els = Array.from(document.querySelectorAll('.loading-text'));
  return els.filter((e) => e.offsetParent !== null && e.textContent.trim())
            .map((e) => e.textContent.trim()).join(' | ');
})()"""

TAKEOVER_BTN = """(() => {
  const b = Array.from(document.querySelectorAll('button'))
    .find((x) => x.textContent.trim().toLowerCase() === 'take over'
                 && x.offsetParent !== null);
  if (!b) return 'absent';
  b.click();
  return 'clicked';
})()"""


async def flowing(br, label, settle=4.0):
    """Did both tracks move over a wall-clock interval?

    A cumulative byte count that is merely non-zero can be a handful of packets
    from a connection that has since died, so this samples twice.
    """
    first = await br.eval(BYTES)
    await asyncio.sleep(settle)
    second = await br.eval(BYTES)
    if not isinstance(first, dict) or not isinstance(second, dict):
        return False, False, "no stats (%r -> %r)" % (first, second)
    dv = second.get("video", 0) - first.get("video", 0)
    da = second.get("audio", 0) - first.get("audio", 0)
    return dv > 0, da > 0, "%s video +%dB audio +%dB over %.0fs" % (label, dv, da, settle)


def kill_strays():
    """Kill headless browsers this test leaked in an earlier run.

    A run cut short by a timeout never reaches its cleanup, and the browser it
    left behind keeps its signalling sockets open -- so it goes on holding the
    session, invisibly, for as long as the machine is up. Two of them sat there
    for three quarters of an hour refusing every window this test opened, and
    the refusals were read as a defect in the feature. Only browsers carrying
    this test's own profile prefix are touched.
    """
    out = subprocess.run(["pgrep", "-f", "--", "user-data-dir=/dev/shm/hdw4s-wt-"],
                         capture_output=True, text=True).stdout.split()
    for pid in out:
        try:
            os.kill(int(pid), 15)
        except Exception:
            pass
    if out:
        time.sleep(2)
        for pid in out:
            try:
                os.kill(int(pid), 9)
            except Exception:
                pass
    for d in glob.glob("/dev/shm/hdw4s-wt-*"):
        shutil.rmtree(d, ignore_errors=True)
    return len(out)


def attached_stable(samples=4, gap=1.5):
    """The largest count seen over a few seconds.

    One reading is not enough: a real client that has just been refused, or is
    between its two legs, shows nothing for an instant and then comes back. Two
    runs of this test started against a session a browser was about to reclaim,
    and reported the resulting refusal as a failure of the feature.
    """
    seen = 0
    for i in range(samples):
        seen = max(seen, attached())
        if i + 1 < samples:
            time.sleep(gap)
    return seen


async def main():
    strays = kill_strays()
    if strays:
        print("  cleaned up %d browser(s) left behind by an earlier run" % strays)
    busy = attached_stable()
    if busy:
        print("  ABORT: %d client(s) attached over the last few seconds; "
              "refusing to interfere." % busy)
        return 2

    first = Browser(9222, "first")
    second = Browser(9223, "second")
    try:
        print("\n  --- one window, from cold ---")
        first.start()
        check("the first window loads the session", await first.attach(), PAGE)
        st = await first.wait_for("window.app && app.status",
                                  ("connected", "failed", "busy"), timeout=90)
        check("it connects", st == "connected", "status=%s" % st)
        check("and no spinner is left on screen", not await first.eval(SPINNER),
              await first.eval(SPINNER) or "clear")
        v, a, d = await flowing(first, "first:")
        check("video is arriving", v, d)
        check("audio is arriving", a, d)

        print("\n  --- a second window, and the hand-over ---")
        second.start()
        check("the second window loads", await second.attach(), PAGE)
        st = await second.wait_for("window.app && app.status",
                                   ("busy", "connected", "failed"), timeout=90)
        check("it is told the desktop is open elsewhere", st == "busy",
              "status=%s" % st)
        why = await second.eval("window.app && app.handoverReason")
        check("  and told why, in the code reserved for it", why == 4001, "code=%s" % why)
        check("  and offered a way in", "take over" in (await second.eval(SPINNER) or "")
              or await second.eval(
                  "!!Array.from(document.querySelectorAll('button'))"
                  ".find(x => x.textContent.trim().toLowerCase() === 'take over')"),
              "")

        clicked = await second.eval(TAKEOVER_BTN)
        check("the take over button is there and clickable", clicked == "clicked", clicked)

        st = await second.wait_for("window.app && app.status",
                                   ("connected", "failed", "busy"), timeout=90)
        check("the second window connects", st == "connected", "status=%s" % st)

        print("\n  --- and is it actually usable? ---")
        left = await second.eval(SPINNER)
        check("the spinner has gone", not left, left or "clear")
        v, a, d = await flowing(second, "second:", settle=6.0)
        check("video is arriving after the hand-over", v, d)
        check("audio is arriving after the hand-over", a, d)

        print("\n  --- and now hand it back ---")
        # The take-back was never exercised, and it is what a user does within
        # a minute of discovering the feature. It is also a different code
        # path: the window asking for it is the one that was evicted, so it
        # arrives on 4002 rather than 4001.
        st = await first.wait_for("window.app && app.status", ("busy", "failed"), timeout=45)
        check("the first window is offered it back", st == "busy", "status=%s" % st)
        clicked = await first.eval(TAKEOVER_BTN)
        check("  and its take over button works", clicked == "clicked", clicked)
        st = await first.wait_for("window.app && app.status",
                                  ("connected", "failed", "busy"), timeout=90)
        check("  and it connects again", st == "connected", "status=%s" % st)
        left = await first.eval(SPINNER)
        check("  with no spinner", not left, left or "clear")
        v, a, d = await flowing(first, "first:", settle=6.0)
        check("  with video", v, d)
        check("  with audio", a, d)
        # The 502 that ended a real session: handing it back killed the whole
        # desktop, so the next request reached a port with nothing behind it.
        alive = await second.eval(
            "fetch('/', {method: 'HEAD'}).then(r => r.status).catch(e => -1)")
        check("  and the session is still alive", alive not in (-1, 502, 503),
              "HEAD / -> %s" % alive)

        print("\n  --- and the window that lost it ---")
        st = await second.wait_for("window.app && app.status", ("busy", "failed"), timeout=30)
        check("the second window is told it was taken over", st == "busy",
              "status=%s" % st)
        why = await second.eval("window.app && app.handoverReason")
        check("  in the code that means taken over, not busy", why == 4002, "code=%s" % why)
        check("  and is offered it back", await second.eval(
            "!!Array.from(document.querySelectorAll('button'))"
            ".find(x => x.textContent.trim().toLowerCase() === 'take over')"), "")
    finally:
        first.stop()
        second.stop()
        await asyncio.sleep(2.0)

    passed = sum(1 for r in RESULTS if r)
    print("\n  === %d passed, %d failed ===" % (passed, len(RESULTS) - passed))
    left = attached()
    print("  clients attached afterwards: %d%s" % (left, "" if not left else "  <-- LEAK"))
    return 0 if passed == len(RESULTS) and not left else 1


sys.exit(asyncio.get_event_loop().run_until_complete(main()))
