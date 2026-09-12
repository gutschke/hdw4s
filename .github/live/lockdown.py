#!/usr/bin/env python3
"""Prove the session's feature lockdown is still in force, against a live one.

  .github/live/lockdown.py [http://host:port]

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
    server's account of itself; a refused request is the behaviour.

Run it against a session with no browser attached. Connecting opens a data
websocket, which the server treats as the session's current one.
"""
import json
import sys
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
    "enable_dual_mode": (False, False),
    # No STUN/TURN lookups to third parties from the user's session.
    "webrtc_ice_lite": (True, False),
    # The browser must not read or write the account's files.
    "file_transfers": ([], None),
    # The binary path carries arbitrary MIME types into the X selection.
    "enable_binary_clipboard": (False, False),
    # Locked, not merely off: an unlocked default-off is a client toggle, so
    # any page could turn its own microphone or camera capture back on.
    "microphone_enabled": (False, True),
    "webcam_enabled": (False, True),
    # No uinput device is wired up for a session; refuse rather than half-work.
    "gamepad_enabled": (False, False),
    # Every form of second viewer. A session is one account's desktop, and
    # admitting a second viewer means admitting them to that account.
    "enable_sharing": (False, False),
    "enable_shared": (False, False),
    "enable_collab": (False, False),
    "enable_player2": (False, False),
    "enable_player3": (False, False),
    "enable_player4": (False, False),
    # A command channel is a shell as the user, straight from the page.
    "command_enabled": (False, False),
    # Unauthenticated metrics on the same port as the stream.
    "enable_metrics_http": (False, False),
    # One X screen is configured; a second one streams a display that is not
    # there and lets a client resize what is.
    "second_screen": (False, False),
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


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7303"
    print(f"lockdown: {base}")
    try:
        settings = check_settings(base)
    except Exception as exc:                       # noqa: BLE001 -- report, don't trace
        bad("server_settings", f"{type(exc).__name__}: {exc}")
        settings = {}
    check_refusals(base)

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
