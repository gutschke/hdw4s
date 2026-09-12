"""The hand-over race, with the desktop application modelled as it really is.

The application's own main loop is the thing that makes this bug permanent:

    while True:
        run_until_complete(signalling.connect())        # peer 0, video
        run_until_complete(audio_signalling.connect())  # peer 2, audio
        ensure_future(audio_signalling.start())         # audio, fire and forget
        run_until_complete(signalling.start())          # blocks on VIDEO only

Only the video leg is waited on. An audio socket that closes on its own ends
the task driving it and nothing starts another, so the audio leg stays dead
until the video leg happens to drop -- which, after a hand-over, it does not.

Modelled here: both legs registered together, each asking for its session once
and retrying every two seconds while the peer is absent (as upstream does), and
the whole pair rebuilt only when the video leg closes.

    pairing_race.py [gap-seconds]

The gap is how long the browser's second leg trails its first.
"""
import asyncio, base64, json, os, sys

import websockets

# The signalling endpoint of a running server. Default is the port a
# sandbox server is usually started on; override for anything else.
URI = os.environ.get("HDW4S_SIGNALLING_URI",
                     "ws://127.0.0.1:%s/webrtc/signalling/"
                     % os.environ.get("HDW4S_SIGNALLING_PORT", "8790"))
GAP = float(sys.argv[1]) if len(sys.argv) > 1 else 0.25
PARTNER = {"0": "1", "2": "3"}
NOPEER_RETRY = 2.0
RESULTS = []


def enc(d):
    return base64.b64encode(json.dumps(d).encode()).decode()


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print("  %-4s %-54s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def dev(client, takeover=False):
    m = {"res": "1x1", "scale": 1, "client": client}
    if takeover:
        m["takeover"] = True
    return m


class Leg:
    """One signalling connection of the application: peer 0 or peer 2."""

    def __init__(self, uid, app):
        self.uid, self.app = uid, app
        self.partner = PARTNER[uid]
        self.ws = None
        self.paired_with = []
        self.errors = []

    async def connect(self):
        self.ws = await websockets.connect(URI)
        await self.ws.send("HELLO %s" % self.uid)
        reply = await asyncio.wait_for(self.ws.recv(), 5)
        if reply != "HELLO":
            self.errors.append("register: %s" % reply)
            raise RuntimeError(reply)

    async def start(self):
        """Read until the socket closes. Returns when it does."""
        await self.ws.send("SESSION %s" % self.partner)
        while True:
            msg = await self.ws.recv()
            if msg.startswith("SESSION_OK"):
                blob = msg.split(maxsplit=1)[1] if " " in msg else ""
                meta = json.loads(base64.b64decode(blob)) if blob else {}
                self.paired_with.append(meta.get("client"))
            elif msg.startswith("ERROR") and "not found" in msg:
                # Upstream waits two seconds and asks again, forever.
                self.errors.append(msg)
                await asyncio.sleep(NOPEER_RETRY)
                await self.ws.send("SESSION %s" % self.partner)
            elif msg.startswith("ERROR"):
                self.errors.append(msg)


class App:
    """The desktop application: two legs, rebuilt only together."""

    def __init__(self):
        self.video = Leg("0", self)
        self.audio = Leg("2", self)
        self.cycles = 0
        self.stop = False

    async def run(self):
        while not self.stop:
            try:
                await self.video.connect()
                await self.audio.connect()
            except Exception:
                await asyncio.sleep(0.3)
                continue
            self.cycles += 1
            audio_task = asyncio.ensure_future(self.audio.start())
            try:
                # The loop turns over only when the VIDEO leg ends.
                await self.video.start()
            except Exception:
                pass
            # Upstream cancels the audio task and opens fresh connections; it
            # never closes the old sockets. The old audio socket therefore
            # lingers, registered, and the next HELLO on peer 2 arrives as a
            # re-registration. Closing them here would be tidier and would also
            # cascade into the browser's peer 3, which is the very state this
            # test exists to preserve.
            audio_task.cancel()
            await asyncio.sleep(0.05)

    async def close(self):
        self.stop = True
        for leg in (self.video, self.audio):
            try:
                await leg.ws.close()
            except Exception:
                pass


async def hello(uid, meta=None, timeout=5):
    ws = await websockets.connect(URI)
    await ws.send("HELLO %s" % uid if meta is None
                  else "HELLO %s %s" % (uid, enc(meta)))
    try:
        return ws, await asyncio.wait_for(ws.recv(), timeout)
    except websockets.ConnectionClosed as e:
        return ws, "closed:%s:%s" % (e.code, e.reason)
    except asyncio.TimeoutError:
        return ws, "no-reply"


async def main():
    print("  browser's second leg trails its first by %.2fs\n" % GAP)
    app = App()
    task = asyncio.ensure_future(app.run())
    socks = []
    try:
        await asyncio.sleep(1.0)

        y1, _ = await hello("1", dev("Y"))
        y3, _ = await hello("3", dev("Y"))
        socks += [y1, y3]
        await asyncio.sleep(NOPEER_RETRY + 1.5)
        check("the application pairs both legs with the first device",
              app.video.paired_with[-1:] == ["Y"] and app.audio.paired_with[-1:] == ["Y"],
              "video=%s audio=%s" % (app.video.paired_with, app.audio.paired_with))

        # Both legs opened concurrently, as a browser does: the second is not
        # waiting on the first's reply. Doing it sequentially made the second
        # leg start only after the server had answered the first, which no
        # browser does and which quietly defeats anything that tries to admit
        # the pair together.
        async def later(uid, delay):
            await asyncio.sleep(delay)
            return await hello(uid, dev("X", takeover=True))

        (x1, rx1), (x3, rx3) = await asyncio.gather(later("1", 0.0),
                                                    later("3", GAP))
        socks += [x1, x3]
        check("the second device is admitted on both legs",
              rx1 == "HELLO" and rx3 == "HELLO", "1=%s 3=%s" % (rx1, rx3))

        # Everything the application does to recover, it does within a few
        # seconds: close, reconnect, ask again, and retry a missing peer twice.
        await asyncio.sleep(NOPEER_RETRY * 2 + 6.0)

        check("the application's video leg is paired with the new device",
              app.video.paired_with[-1:] == ["X"],
              "history %s" % (app.video.paired_with,))
        check("the application's audio leg is paired with the new device",
              app.audio.paired_with[-1:] == ["X"],
              "history %s, errors %s" % (app.audio.paired_with,
                                         app.audio.errors or "none"))
        check("  so the desktop has sound after a hand-over",
              app.audio.paired_with[-1:] == ["X"],
              "an audio leg left on the outgoing client is never repaired")

        codes = []
        for w in (y1, y3):
            try:
                await asyncio.wait_for(w.recv(), 1.0)
                codes.append("open")
            except websockets.ConnectionClosed as e:
                codes.append(str(e.code))
            except asyncio.TimeoutError:
                codes.append("open")
        check("the first device is told it lost both legs",
              codes == ["4002", "4002"], str(codes))
    finally:
        await app.close()
        task.cancel()
        for w in socks:
            try:
                await w.close()
            except Exception:
                pass

    passed = sum(1 for r in RESULTS if r)
    print("\n  === %d passed, %d failed ===   (application rebuilt %d times)"
          % (passed, len(RESULTS) - passed, app.cycles))
    return 0 if passed == len(RESULTS) else 1


sys.exit(asyncio.get_event_loop().run_until_complete(main()))
