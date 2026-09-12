#!/usr/bin/env python3
"""The basic walk-through: does a browser actually get a desktop, with sound?

  .github/live/walkthrough.py <port|url> [--tone INSTANCE]

Every other suite here asks the server whether it is configured correctly, and
a server can answer all of those right while the user looks at a status bar
that never goes away. This one drives real browsers and asks the questions a
user asks: is there a picture, is there sound, and did the second window take
the session over cleanly when it was opened.

Three things learned the hard way are built into how it measures:

  * **A screenshot on its own cannot fail.** When a session is taken over, the
    client tears its decoders down but never clears the canvas, so the evicted
    page goes on showing a perfectly good desktop indefinitely. Every visual
    assertion here is paired with a counter that has to move.
  * **Nothing read out of `window` is automatically server truth.** The client
    writes most settings into globals with the browser's own stored value
    preferred, so a global can report the operator's policy while disagreeing
    with it. Only counters derived from observed traffic are used.
  * **Audio has no counter in the page at all.** The transport's frames are
    tallied over the debugging protocol instead, by the type tag in the first
    byte, which is independent of the decoder, the volume, and whether the
    desktop is making any noise. `--tone` additionally plays one, which is the
    only way to prove the sound reaches a speaker rather than a buffer.

It refuses to start if anyone is attached.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser  # noqa: E402

AUDIO, VIDEO = 0x01, (0x03, 0x04)
HIDDEN = ("(document.getElementById('status-display')||{classList:{contains:()=>false}})"
          ".classList.contains('hidden')")
STATUS = "(document.getElementById('status-display')||{}).textContent || ''"
CHUNKS = "window.videoChunksReceived || 0"
FPS = "window.fps || 0"
LEVEL = "window.currentAudioLevel || 0"
CLOSED = "(window.selkiesTransport||{}).readyState === 3"

results = []


def check(name, good, detail=""):
    results.append(bool(good))
    print("  %-4s %-56s %s" % ("ok" if good else "FAIL", name, detail), flush=True)


def video_frames(br):
    return sum(br.wire.get(t, 0) for t in VIDEO)


def moved(br, seconds=3.0):
    """Did video actually arrive over an interval, by two independent counts?

    The page's own counter and the transport's frames are counted separately
    because they fail differently: the global stops being updated if the client
    tears down, the wire tally stops if the server stops sending.
    """
    before_chunks, before_wire = br.eval(CHUNKS) or 0, video_frames(br)
    br.pump(seconds)
    return (br.eval(CHUNKS) or 0) - before_chunks, video_frames(br) - before_wire


def tone(instance):
    """Make the desktop audible. Silence is indistinguishable from no audio.

    It has to be played inside the session -- as that user, against that
    session's sound server -- or it goes to whatever the caller's own audio
    happens to be and the test measures nothing. That needs the privilege to
    become the session user, which is why this is opt-in rather than always on.
    """
    return subprocess.run(
        ["sudo", "-n", "-u", instance, "env",
         "XDG_RUNTIME_DIR=/run/hdw4s/" + instance,
         "speaker-test", "-t", "sine", "-f", "440", "-l", "1"],
        capture_output=True, timeout=40)


def picture(br, label):
    shot = br.screenshot()
    return browser.colours(shot), shot


def main():
    argv = sys.argv[1:]
    want_tone = None
    if "--tone" in argv:
        i = argv.index("--tone")
        want_tone = argv[i + 1]
        del argv[i:i + 2]
    target = argv[0] if argv else "7303"
    if target.startswith("http"):
        page, port = target.rstrip("/"), 0
    else:
        port = int(target)
        page = "http://127.0.0.1:%d" % port
    # The session socket runs inside a worker unless this is asked for, and a
    # worker's frames belong to a different debugging target, where the page's
    # own instrumentation cannot see them. This is upstream's documented escape
    # hatch, not a trick.
    page += "/?socket_worker=false"

    strays = browser.kill_strays()
    if strays:
        print("  cleaned up %d browser(s) left behind by an earlier run" % strays)
    busy = browser.attached_stable(port)
    if busy:
        print("  ABORT: %d client(s) attached over the last few seconds; "
              "refusing to interfere." % busy)
        return 2
    if busy is None:
        print("  note: aiming at a URL, so who else is attached is not visible "
              "from here and was not checked")

    first = browser.Browser(9222, "first")
    second = browser.Browser(9223, "second")
    try:
        print("\n  --- one window, from cold ---")
        first.start()
        check("the first window loads the session", first.open(page), page)

        # Calibrate the visual oracle against this machine, this run: a page
        # that cannot stream, in the same browser at the same size. Without
        # this the threshold below is a number someone once measured elsewhere.
        first.call("Page.navigate", {"url": "http://127.0.0.1:1/"})
        time.sleep(2)
        blank, _ = picture(first, "blank")
        first.call("Page.navigate", {"url": page})
        time.sleep(2)

        status = first.wait_for(HIDDEN, lambda v: v is True, timeout=90)
        check("the status bar goes away, so a frame was painted", status is True,
              "" if status is True else "still showing %r" % first.eval(STATUS))

        chunks, wire = moved(first)
        check("video is arriving", chunks > 0 and wire > 0,
              "+%d chunks in the page, +%d frames on the wire" % (chunks, wire))
        fps = first.eval(FPS)
        check("the client reports a frame rate", (fps or 0) > 0, "fps=%s" % fps)

        lit, _ = picture(first, "first")
        check("there is a picture on the screen", lit > max(2000, blank * 3),
              "%d distinct colours, against %d on a page that cannot stream"
              % (lit, blank))

        print("\n  --- sound ---")
        audio_before = first.wire.get(AUDIO, 0)
        level = 0
        if want_tone:
            tone(want_tone)
        for _ in range(6):
            level = max(level, first.eval(LEVEL) or 0)
            first.pump(1.0)
        audio = first.wire.get(AUDIO, 0) - audio_before
        check("audio is arriving", audio > 0, "+%d audio frames on the wire" % audio)
        if want_tone:
            check("and it reaches the output", level > 0,
                  "peak level %s while a tone played" % level)
        else:
            print("  skip whether the sound is audible (pass --tone INSTANCE; "
                  "the desktop is silent and silence looks like no audio)")

        print("\n  --- a second window takes the session over ---")
        second.start()
        check("the second window loads the session", second.open(page), page)
        st2 = second.wait_for(HIDDEN, lambda v: v is True, timeout=90)
        check("it gets a picture of its own", st2 is True,
              "" if st2 is True else "still showing %r" % second.eval(STATUS))
        c2, w2 = moved(second)
        check("video is arriving in the second window", c2 > 0 and w2 > 0,
              "+%d chunks, +%d frames" % (c2, w2))

        # The one that a screenshot would have got wrong. Only the wire count
        # is asserted on: the page's own counter is whatever the client last
        # managed to write, and reading it from a page that has just been torn
        # down returns nothing at all, which arithmetic turns into a large
        # negative number rather than an error.
        c1, w1 = moved(first, 4.0)
        check("the first window stopped receiving", w1 == 0,
              "+%d frames on the wire after being taken over "
              "(the page's own count moved by %d)" % (w1, c1))
        check("its transport closed", first.wait_for(
            CLOSED, lambda v: v is True, timeout=20) is True)
        said = first.eval(STATUS) or ""
        check("and the window says why", "terminated" in said.lower()
              and "client" in said.lower(), repr(said))
        check("and shows the bar again", first.eval(HIDDEN) is False)
        still, _ = picture(first, "evicted")
        print("  note: the evicted window still shows %d colours -- the client "
              "leaves the last frame up, which is why every visual check here "
              "is paired with a counter" % still)

        print("\n  --- and back again ---")
        first.call("Page.navigate", {"url": page})
        time.sleep(2)
        back = first.wait_for(HIDDEN, lambda v: v is True, timeout=90)
        check("reloading the first window takes it back", back is True,
              "" if back is True else "still showing %r" % first.eval(STATUS))
        c1b, w1b = moved(first)
        check("video is arriving in it again", c1b > 0 and w1b > 0,
              "+%d chunks, +%d frames" % (c1b, w1b))
        c2b, w2b = moved(second, 4.0)
        check("and the second window stopped", c2b == 0 and w2b == 0,
              "+%d chunks, +%d frames" % (c2b, w2b))
    finally:
        first.stop()
        second.stop()
        browser.kill_strays()

    failed = results.count(False)
    print("\n%d/%d checks passed" % (len(results) - failed, len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
