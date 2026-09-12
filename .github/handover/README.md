# Session hand-over: the tests that need a running desktop

The suite in `../tests.sh` and `../test-handover.py` runs anywhere: it checks
the patcher, the guards, and every decision `hello_peer` makes, against fakes.
These three need a real signalling server, and two of them need a real session
with a real media pipeline, so they are not run by CI. Run them by hand on the
machine after a change to hand-over.

They exist because three separate defects reached a user despite the offline
suite being green, and each one was invisible to it for the same reason: the
component that caused the fault was not in the test.

## `walkthrough.py` -- does the feature work at all

    HDW4S_WT_USER=<instance> HDW4S_WT_PASSWORD=<credential> \
      walkthrough.py <session port>

Drives two headless Chrome instances against a live session over CDP: connect,
open a second window, take the session over, hand it back, and check at every
step that there is a picture, that there is sound, that the spinner has gone,
and that the window which lost it is told so and offered a way back.

It measures bytes on the peer connection over an interval rather than asking
the media elements, because a `<video>` in headless Chrome reports a duration
and a readyState whether or not a single frame ever decoded.

It refuses to start if anyone is connected, and kills browsers left behind by
an earlier run -- a run cut short by a timeout keeps its signalling sockets
open and goes on holding the session invisibly, which produced three false
failures that read exactly like product defects.

## `pairing_race.py` -- the desktop's half of a hand-over

    pairing_race.py [gap-seconds]

Models the application faithfully: both signalling legs, each asking for its
session once and retrying every two seconds while the peer is absent, sockets
left open on reconnect rather than closed, and the pair rebuilt only when the
video leg ends -- which is what upstream's main loop actually does.

That last detail is the whole point. Upstream waits on the video leg and fires
the audio one off, so an audio socket closed on its own is never replaced. A
hand-over closes exactly that one, and the desktop keeps a picture and loses
sound for the rest of its life.

The gap is how long the browser's second leg trails its first. Real browsers
open them within milliseconds; the argument exists to drive the interleaving
deliberately rather than wait for it.

Both `pairing_race.py` and `audio_race.py` talk to `ws://127.0.0.1:8790/` by
default. Point them elsewhere with `HDW4S_SIGNALLING_PORT`, or
`HDW4S_SIGNALLING_URI` for a path that is not the usual one.

## `fatal_close.py` -- does a closed socket stop the desktop

Runs the real installed `WebRTCSignalling` against a server that answers and
then closes while the client is still replying. The application's callbacks run
inside its read loop and send on the same socket: the iterator survives any
close code, a send does not, and what escapes reaches a bare `except Exception`
followed by `sys.exit`. The process stops with status 0, so `Restart=on-failure`
does not bring it back, and GNOME and every open window go with it.

This is the fault that destroyed a live session. It needs no hand-over to
trigger -- upstream closes the paired peer itself -- so it is worth running
after any change to the signalling client, not only to this feature.

## `audio_race.py` -- re-registration during a hand-over

Forces the order in which the application re-registers a peer it still holds,
with no timing dependence. Faster than `pairing_race.py` and narrower.

## Before trusting a run

A regression test that does not fail on the broken build is not a test. Each of
these was checked against the build that had the defect and against the build
that fixed it, and the difference recorded. Do the same for anything added
here.
