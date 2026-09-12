"""The hand-over race that broke audio, forced into the order that loses.

A hand-over closes the browser leg it takes, and upstream tears down that leg's
session -- which closes the application peer paired with it. The application
then reconnects BOTH of its legs. The other browser leg is usually handed over
in the same breath, freeing the application peer it was paired with, and the
reconnect lands on two free ids. That is the order a browser almost always
produces, and it is the order every test here happened to produce, so the suite
was green while a user watched a spinner.

When the reconnect arrives first, the second application peer is still
registered, its re-registration is refused, no audio session is ever started,
and the viewer sits behind "Waiting for stream." with no sound. This drives that
order deliberately: take over one browser leg, then re-register both
application peers before touching the other. Nothing here is timing-sensitive.
"""
import asyncio, base64, json, os, sys

import websockets

# The signalling endpoint of a running server. Default is the port a
# sandbox server is usually started on; override for anything else.
URI = os.environ.get("HDW4S_SIGNALLING_URI",
                     "ws://127.0.0.1:%s/webrtc/signalling/"
                     % os.environ.get("HDW4S_SIGNALLING_PORT", "8790"))
RESULTS = []


def enc(d):
    return base64.b64encode(json.dumps(d).encode()).decode()


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print("  %-4s %-52s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


async def hello(uid, meta=None, timeout=4):
    ws = await websockets.connect(URI)
    await ws.send("HELLO %s" % uid if meta is None
                  else "HELLO %s %s" % (uid, enc(meta)))
    try:
        return ws, await asyncio.wait_for(ws.recv(), timeout)
    except websockets.ConnectionClosed as e:
        return ws, "closed:%s:%s" % (e.code, e.reason)
    except asyncio.TimeoutError:
        return ws, "no-reply"


async def still(ws, t=1.0):
    try:
        return await asyncio.wait_for(ws.recv(), t)
    except websockets.ConnectionClosed as e:
        return "closed:%s:%s" % (e.code, e.reason)
    except asyncio.TimeoutError:
        return "still-open"


def dev(client, takeover=False):
    m = {"res": "1x1", "scale": 1, "client": client}
    if takeover:
        m["takeover"] = True
    return m


async def main():
    socks = []

    # The desktop's own application: a bare HELLO on each of its two ids.
    app0, r0 = await hello("0")
    app2, r2 = await hello("2")
    check("the application registers its own two peers", r0 == "HELLO" and r2 == "HELLO",
          "0=%s 2=%s" % (r0, r2))

    # A device holding both browser legs.
    a1, _ = await hello("1", dev("A"))
    a3, _ = await hello("3", dev("A"))
    socks += [a1, a3]

    # A second device takes the video leg, and only the video leg.
    b1, rb1 = await hello("1", dev("B", takeover=True))
    socks.append(b1)
    check("the second device takes the video leg", rb1 == "HELLO", rb1)

    # Upstream's session cleanup closes the application peer paired with the
    # leg that moved. Which one that is depends on the session, so accept
    # either being gone and require that at least one survived -- the surviving
    # one is the whole point of this test.
    s0, s2 = await still(app0, 1.5), await still(app2, 1.5)
    check("one application peer is still registered afterwards",
          "still-open" in (s0, s2), "0=%s 2=%s" % (s0, s2))

    # THE ORDER THAT LOSES: the application reconnects both of its legs now,
    # before the audio leg has been handed over. One of the two ids it is
    # re-registering has never been freed.
    new0, rn0 = await hello("0")
    new2, rn2 = await hello("2")
    socks += [app0, app2, new0, new2]
    check("the application can re-register peer 0", rn0 == "HELLO", rn0)
    check("the application can re-register peer 2", rn2 == "HELLO", rn2)
    check("  neither is turned away as a duplicate",
          rn0 == "HELLO" and rn2 == "HELLO",
          "this is the refusal that left the viewer with no audio")

    # And only then does the audio leg follow, as a real client eventually does.
    b3, rb3 = await hello("3", dev("B", takeover=True))
    socks.append(b3)
    check("the second device then takes the audio leg", rb3 == "HELLO", rb3)

    # The displaced device is told it was taken over on both legs, so it can
    # offer the way back rather than silently retrying.
    e1, e3 = await still(a1, 1.0), await still(a3, 1.0)
    check("the first device is told it lost both legs",
          e1.startswith("closed:4002") and e3.startswith("closed:4002"),
          "1=%s 3=%s" % (e1, e3))

    for w in socks:
        try:
            await w.close()
        except Exception:
            pass

    passed = sum(1 for r in RESULTS if r)
    print("\n  === %d passed, %d failed ===" % (passed, len(RESULTS) - passed))
    return 0 if passed == len(RESULTS) else 1


sys.exit(asyncio.get_event_loop().run_until_complete(main()))
