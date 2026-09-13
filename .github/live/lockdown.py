#!/usr/bin/env python3
"""Prove the session's feature lockdown is still in force, against a live one.

  .github/live/lockdown.py [http://host:port] [--unit hdw4s@INSTANCE]
                           [--home DIR] [--framerate N]

The package hands a browser a desktop that is already logged in as a real
account. Everything the streaming server offers beyond pixels, sound and input
-- file transfer, a shell, extra viewers, a second screen, the microphone --
would hand that account out too, so the session starts with all of it turned
off. Those sixteen switches are passed on a command line to a server that
accepts an unrecognised flag with nothing but a log line, which means a typo or
an upstream rename lifts a control and the session still starts, streams, and
looks completely normal. Nothing about a working desktop says the lockdown is
gone. This asks the server itself.

Two independent oracles, because one of them can be right for the wrong reason:

  * the settings the server publishes to every client on connect. Each entry
    carries "overridden", which is true only when the value came from an
    explicit choice rather than the built-in default -- so a dropped or
    renamed flag fails here even where upstream's default happens to agree
    with us, which it does for four of the sixteen;
  * what the server actually does when asked. The settings payload is the
    server's account of itself; a refused request is the behaviour. One of
    those behavioural checks reads the session journal and so needs --unit and
    the privilege to read it; it is skipped, loudly, without them.

Run it against a session with no browser attached. Connecting opens a data
websocket, which the server treats as the session's current one.
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import wsprobe  # noqa: E402

# name -> (expected value, expected locked). None for locked means the setting
# has no lock flag (a string or a list rather than a bool). Every entry is also
# required to be "overridden": the point is to catch a control that stopped
# being applied, not merely one whose value looks safe today.
EXPECTED = {
    # Serve one transport. Dual mode also stands up the WebRTC stack, which is
    # a second signalling surface with its own peer handling and its own bugs.
    "enable_dual_mode": (False, True),
    # No STUN/TURN lookups to third parties from the user's session.
    "webrtc_ice_lite": (True, True),
    # The browser must not read or write the account's files.
    "file_transfers": ([], None),
    # The binary path carries arbitrary MIME types into the X selection. This
    # is the one the server reads back out of a client SETTINGS frame, so the
    # lock is the whole control and the value on its own means nothing.
    "enable_binary_clipboard": (False, True),
    "microphone_enabled": (False, True),
    "webcam_enabled": (False, True),
    # No uinput device is wired up for a session; refuse rather than half-work.
    "gamepad_enabled": (False, True),
    # Every form of second viewer. A session is one account's desktop, and
    # admitting a second viewer means admitting them to that account.
    "enable_sharing": (False, True),
    "enable_shared": (False, True),
    "enable_collab": (False, True),
    "enable_player2": (False, True),
    "enable_player3": (False, True),
    "enable_player4": (False, True),
    # A command channel is a shell as the user, straight from the page.
    "command_enabled": (False, True),
    # Unauthenticated metrics on the same port as the stream.
    "enable_metrics_http": (False, True),
    # One X screen is configured; a second one streams a display that is not
    # there and lets a client resize what is.
    "second_screen": (False, True),
    # Not security, but the tab belongs to this package, not to upstream.
    "ui_title": ("Desktop", None),
}

results = []


def ok(name):
    results.append(True)
    print(f"  ok   {name}")


def bad(name, detail):
    results.append(False)
    print(f"  FAIL {name}\n       {detail}")


def check_settings(base):
    settings = wsprobe.server_settings(base)
    for name, (value, locked) in EXPECTED.items():
        entry = settings.get(name)
        if entry is None:
            bad(name, "the server publishes no such setting -- renamed upstream?")
            continue
        if entry.get("value") != value:
            bad(name, f"expected {value!r}, server reports {entry.get('value')!r}")
            continue
        if not entry.get("overridden"):
            bad(name, "value is right but is upstream's default, not ours: the "
                      "flag did not reach the server")
            continue
        if locked is not None and entry.get("locked") is not locked:
            bad(name, f"expected locked={locked}, server reports "
                      f"locked={entry.get('locked')}")
            continue
        ok(name)
    return settings


def check_ceilings(settings, framerate):
    """Two controls that are a ceiling rather than a switch.

    A range setting publishes the bounds a client may move inside, so these
    are the only assertions that show a ceiling reached the server at all --
    the value alone looks the same whether the client may raise it or not.

    The framerate the operator configures is a *maximum*: this machine hosts
    several sessions off one CPU, and a client that could set its own rate
    would take the whole budget. The ceiling has to be passed in rather than
    read out of the range being checked -- deriving it from the payload made
    the check agree with whatever the server said, and it passed against a
    session whose ceiling had become 240. The encoder list is published as the menu the
    sidebar offers, so withdrawing every entry but one is what stops a client
    switching to something this build cannot do in software.
    """
    fr = settings.get("framerate")
    if not fr:
        bad("framerate", "the server publishes no framerate range")
    elif not fr.get("overridden"):
        bad("framerate", "the range is upstream's default, not ours")
    elif fr.get("value") != [8, framerate]:
        bad("framerate", f"expected [8, {framerate}], server reports "
                         f"{json.dumps(fr, sort_keys=True)}")
    else:
        ok(f"framerate is a ceiling: 8-{framerate}, not a client's choice")

    enc = settings.get("encoder")
    if not enc:
        bad("encoder", "the server publishes no encoder setting")
    elif enc.get("allowed") != [enc.get("value")]:
        bad("encoder", f"the client may still choose from "
                       f"{enc.get('allowed')!r}")
    else:
        ok(f"encoder menu withdrawn to {enc.get('value')!r}")


def check_refusals(base):
    """The lockdown as behaviour rather than as self-description."""
    for path, expect in (("/api/files/", 403),):
        req = urllib.request.Request(base.rstrip("/") + path)
        try:
            code = urllib.request.urlopen(req, timeout=10).getcode()
        except urllib.error.HTTPError as exc:
            code = exc.code
        except OSError as exc:
            bad(f"GET {path}", f"unreachable: {exc}")
            continue
        if code == expect:
            ok(f"GET {path} -> {expect}")
        else:
            bad(f"GET {path}", f"expected {expect}, got {code}")


def check_home(home, unit):
    """The upload directory must not be inside the account's home.

    It is created when the module is imported, before any flag is read, so
    `--file-transfers=none` refuses the transfers and makes the folder anyway.
    The path is one the server never publishes, so it is read off the running
    server's own command line.

    This used to look for `~/Desktop` and call its absence a pass. That works
    only on a home that has never had a desktop session: `Desktop` is an
    ordinary xdg-user-dirs entry, so on any real account the check failed while
    nothing was wrong, and on a fresh one it passed without establishing where
    the upload directory actually points. Asking the server is both.
    """
    if not home:
        print("  skip the upload directory (pass --home DIR: the session's "
              "own home, which is not this script's)")
        return
    argv = _server_argv(unit)
    if argv is None:
        bad("upload directory", "cannot find the running streaming server to "
                                "ask; pass --unit, or check the session is up")
        return
    path = next((a.split("=", 1)[1] for a in argv
                 if a.startswith("--file-manager-path=")), None)
    if path is None:
        bad("upload directory", "the server was given no --file-manager-path, "
                                "so it defaults to ~/Desktop in the account's "
                                "home")
    elif os.path.realpath(path).startswith(os.path.realpath(home) + os.sep):
        bad("upload directory", f"{path} is inside {home}")
    else:
        ok(f"the upload directory is outside the home ({path})")


def _server_argv(unit):
    """The streaming server's argv, found under the session's own cgroup."""
    import glob
    for cmdline in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(cmdline, "rb") as fh:
                argv = fh.read().split(b"\0")
        except OSError:
            continue
        if not argv or b"/selkies" not in argv[0]:
            continue
        if unit:
            try:
                with open(cmdline.replace("cmdline", "cgroup")) as fh:
                    if unit not in fh.read():
                        continue
            except OSError:
                continue
        return [a.decode("utf-8", "replace") for a in argv if a]
    return None


def check_defeat(base, unit):
    """Try to turn a control back on the way a connected page could.

    A boolean the server reads back out of a client SETTINGS frame is only a
    default until it is locked, and binary clipboard is the one upstream wires
    into that path. This is not a settings assertion because it cannot be: the
    payload the server publishes is built from the global settings object,
    while the frame updates the input handler, so a defeated clipboard goes on
    being reported as off. The only place the difference is visible is the
    session's own log.
    """
    if not unit:
        print("  skip runtime defeat of enable_binary_clipboard "
              "(pass --unit hdw4s@INSTANCE; needs the session journal)")
        return
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    time.sleep(1)  # journal timestamps have one-second resolution
    try:
        sock, rest = wsprobe.connect(base)
    except OSError as exc:
        bad("runtime defeat", f"could not connect: {exc}")
        return
    try:
        for i, text in enumerate(wsprobe.frames(sock, rest)):
            if text.startswith("{") and '"server_settings"' in text:
                break
            if i > 40:
                break
        # Off first, then on. The server logs the change, not the state, and
        # returns early when a frame asks for what is already set -- so a run
        # that only asks for "on" against an already-defeated session sees
        # silence and reads it as a refusal. Establish the starting point.
        for want in (False, True):
            wsprobe.send(sock, "SETTINGS," + json.dumps({
                "displayId": "primary",
                "initialClientWidth": 1920, "initialClientHeight": 1080,
                "enable_binary_clipboard": want,
            }))
            time.sleep(3)
    finally:
        sock.close()
    log = subprocess.run(
        ["journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "cat"],
        capture_output=True, text=True)
    if log.returncode != 0:
        bad("runtime defeat", "cannot read the session journal: "
                              f"{log.stderr.strip() or log.returncode}")
    elif "Binary clipboard setting changing to: True" in log.stdout:
        bad("runtime defeat", "a client turned binary clipboard back on -- the "
                              "flag needs |locked, not a bare false")
    else:
        ok("enable_binary_clipboard survives a client asking for it")


def main():
    argv = sys.argv[1:]
    unit = None
    home = None
    framerate = 30
    for flag in ("--unit", "--home", "--framerate"):
        if flag in argv:
            i = argv.index(flag)
            value = argv[i + 1]
            del argv[i:i + 2]
            if flag == "--unit":
                unit = value
            elif flag == "--home":
                home = value
            else:
                framerate = int(value)
    base = argv[0] if argv else "http://127.0.0.1:7303"
    print(f"lockdown: {base}")
    try:
        settings = check_settings(base)
    except Exception as exc:                       # noqa: BLE001 -- report, don't trace
        bad("server_settings", f"{type(exc).__name__}: {exc}")
        settings = {}
    if settings:
        check_ceilings(settings, framerate)
    check_refusals(base)
    check_defeat(base, unit)
    check_home(home, unit)

    # Not an assertion: a setting the server never heard of is already caught
    # above by "overridden". This only names the likely cause when it happens.
    if settings and not all(results):
        print("\nif a flag stopped being recognised the session log says so:")
        print("  journalctl -u hdw4s@INSTANCE -g 'Ignoring unrecognized argument'")

    failed = results.count(False)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
