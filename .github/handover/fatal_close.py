"""Does a closed signalling socket stop the desktop?

This is the fault that destroyed a user's session: the application's read loop
runs its callbacks inside the loop body, and those callbacks send on the same
socket. The iterator survives any close code -- measured, 1000 and 4003 alike --
but a send does not, and the application wraps its whole main loop in a bare
`except Exception` followed by `sys.exit`. The process then stops with status 0,
so `Restart=on-failure` does not bring it back, and GNOME and every window the
user had open go with it.

The window is wide: the retry path for an unregistered peer does a BLOCKING
two-second sleep before its send, and that is the path a hand-over puts the
application on. The close is upstream's own -- cleanup_session closes the peer
paired with a leg that moved -- so every hand-over runs this risk whether or not
this feature is installed.

Run against the real installed application, not a model:

    fatal_close.py
"""
import asyncio, sys

import websockets

sys.path.insert(0, "/usr/lib/hdw4s")
import hdw4s_signalling                                    # noqa: E402
from selkies_gstreamer import webrtc_signalling as sig     # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8794
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print("  %-4s %-52s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


async def hostile(ws, path=None):
    """A session that answers, then closes while the client is still replying."""
    await ws.recv()
    await ws.send("ERROR peer '3' not found")
    await asyncio.sleep(0.1)
    await ws.close(code=1000, reason="cleanup_session")


async def run_leg():
    """One real WebRTCSignalling against that server. Returns what escaped."""
    s = sig.WebRTCSignalling("ws://127.0.0.1:%d/" % PORT, 0, 1)
    sent = []

    async def on_connect():
        await s.setup_call()

    async def on_error(e):
        # Upstream sleeps two seconds here and then sends. The sleep is what
        # makes the window wide; the send is what raises.
        await asyncio.sleep(0.4)
        sent.append("retry")
        await s.setup_call()

    s.on_connect = on_connect
    s.on_error = on_error
    s.on_session = lambda *a: None
    s.on_disconnect = lambda: None
    await s.connect()
    try:
        await s.start()
        return None, sent
    except Exception as exc:
        return exc, sent


async def main():
    async with websockets.serve(hostile, "127.0.0.1", PORT):
        exc, sent = await run_leg()
        check("the application's own read loop is reached",
              sent == ["retry"], "callbacks run: %s" % sent)
        check("a close during a callback does not escape start()",
              exc is None,
              "escaped %s -- this reaches the application's bare except and "
              "stops the whole desktop" % type(exc).__name__ if exc else "clean")
        check("  and the guard says it is installed",
              getattr(sig.WebRTCSignalling, hdw4s_signalling.HARDENED_FLAG, False),
              "flag absent" if not getattr(
                  sig.WebRTCSignalling, hdw4s_signalling.HARDENED_FLAG, False) else "")

    passed = sum(1 for r in RESULTS if r)
    print("\n  === %d passed, %d failed ===" % (passed, len(RESULTS) - passed))
    return 0 if passed == len(RESULTS) else 1


hdw4s_signalling.harden_signalling_client()
sys.exit(asyncio.get_event_loop().run_until_complete(main()))
