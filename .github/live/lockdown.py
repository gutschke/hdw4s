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
import base64
import glob
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
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
    # Files move both ways, scoped to the account's Downloads folder by
    # file_manager_path rather than the whole home.
    "file_transfers": (["upload", "download"], None),
    # Images in the clipboard, which is the common case after a screenshot.
    # Measured working in both directions; formatted text is not carried by
    # either end, so a rich copy still arrives as plain text. This is the one
    # setting the server reads back out of a client SETTINGS frame, so the lock
    # is what makes it hold -- in this direction as much as the other.
    "enable_binary_clipboard": (True, True),
    "microphone_enabled": (False, True),
    "webcam_enabled": (False, True),
    # No uinput device is wired up for a session; refuse rather than half-work.
    "gamepad_enabled": (False, True),
    # Every form of second viewer. Admitting one still requires a credential:
    # the view-only password is separate and cannot match while it is unset,
    # which is asserted below rather than taken on trust.
    "enable_sharing": (True, True),
    "enable_shared": (True, True),
    "enable_collab": (True, True),
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


def _request(url):
    """A GET that carries the credential if the URL names one.

    urllib does not turn "user:pass@host" into an Authorization header by
    itself, and the difference matters here: an unauthenticated request to a
    session that wants a credential answers 401, which is neither the 403 this
    asserts nor a failure of the thing being asserted. Without this the suite
    could only ever be run against a session with authentication turned off --
    which is not the configuration anyone actually runs.
    """
    u = urllib.parse.urlsplit(url)
    if u.username is None:
        return urllib.request.Request(url)
    netloc = u.hostname + (f":{u.port}" if u.port else "")
    req = urllib.request.Request(urllib.parse.urlunsplit(
        (u.scheme, netloc, u.path, u.query, u.fragment)))
    cred = base64.b64encode(
        f"{u.username}:{u.password or ''}".encode()).decode()
    req.add_header("Authorization", f"Basic {cred}")
    return req


def check_refusals(base):
    """The lockdown as behaviour rather than as self-description."""
    for path, expect in (("/api/files/", 200),):
        req = _request(base.rstrip("/") + path)
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


def check_no_anonymous(base):
    """A second viewer still needs a credential.

    Sharing is on, so the question is no longer whether extra viewers are
    refused but whether one can arrive without a password. The view-only login
    is a separate secret that nothing sets here, and the server only accepts it
    when it is non-empty -- so an unauthenticated request must still be
    refused. Asserted rather than read out of the settings, because the
    settings describe intent and this describes what the socket does.
    """
    import urllib.parse
    u = urllib.parse.urlsplit(base)
    anon = urllib.parse.urlunsplit(
        (u.scheme, u.netloc.split("@")[-1], u.path, u.query, u.fragment))
    for path in ("/", "/api/files/"):
        try:
            code = urllib.request.urlopen(
                anon.rstrip("/") + path, timeout=10).getcode()
        except urllib.error.HTTPError as exc:
            code = exc.code
        except OSError as exc:
            bad(f"anonymous GET {path}", f"unreachable: {exc}")
            continue
        if code == 401:
            ok(f"anonymous GET {path} is refused")
        else:
            bad(f"anonymous GET {path}",
                f"expected 401, got {code} -- a viewer reached this without "
                f"a credential")


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


def _server_proc(unit):
    """The streaming server's /proc directory, found under the session's cgroup."""
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
        return cmdline.rsplit("/", 1)[0]
    return None


def check_interposer(unit):
    """The V4L2 interposer belongs in the applications, never in the server.

    HDW4S_WEBCAM=yes preloads a shared object that answers a program's camera
    calls out of the session's own socket. The streaming server is what is on
    the other end of that socket: preloading it there would have the producer
    of the frames intercepting its own camera calls. The two are launched with
    deliberately different environments, and nothing but this notices if that
    stops being true.
    """
    if not unit:
        print("  skip the interposer's placement (pass --unit hdw4s@INSTANCE)")
        return
    proc = _server_proc(unit)
    if proc is None:
        bad("interposer", "cannot find the running streaming server to ask")
        return
    try:
        with open(proc + "/environ", "rb") as fh:
            env = fh.read().decode("utf-8", "replace").split("\0")
    except OSError as exc:
        bad("interposer", f"cannot read the server's environment: {exc}")
        return
    preload = next((e.split("=", 1)[1] for e in env
                    if e.startswith("LD_PRELOAD=")), "")
    if "interposer" in preload:
        bad("interposer", f"the streaming server has it preloaded: {preload}")
    elif preload:
        bad("interposer", f"the streaming server has an unexpected LD_PRELOAD: {preload}")
    else:
        ok("the streaming server has no LD_PRELOAD")


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
    configured = EXPECTED["enable_binary_clipboard"][0]
    attack = not configured
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
        # The configured value first, then its opposite. The server logs the
        # change, not the state, and returns early when a frame asks for what
        # is already set -- so a run that only sends the attack against an
        # already-defeated session sees silence and reads it as a refusal.
        # Establish the starting point, then try to move it.
        #
        # Which value is the attack follows the policy rather than being
        # written down here. Hard-coding "on" meant that turning the setting on
        # left this asking the server to do what it already does, which no
        # session will ever log -- a check that cannot fail.
        for want in (configured, attack):
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
    elif "Binary clipboard setting changing to: %s" % attack in log.stdout:
        bad("runtime defeat", "a client moved binary clipboard to %s -- the "
                              "flag needs |locked, not a bare value" % attack)
    else:
        ok("enable_binary_clipboard survives a client asking for it")


def check_defeat_wire_verb(base, unit, probe_file):
    """The lock is enforced on one path. This is the other one.

    check_defeat above proves a SETTINGS frame cannot move
    enable_binary_clipboard, because "|locked" is enforced inside the settings
    object's sanitize_value. Only the SETTINGS path calls it. The one-token
    "_ebc,<bool>" message writes the input handler's own copy of the setting
    directly and never goes near it, so the lock does not hold there -- and the
    stock client sends "_ebc", so it is a live path rather than a curiosity.

    That on its own moves a flag, not data. What stops the data is a second and
    unrelated gate on the way out, which reads a *different* copy of the
    setting -- the one built from the command line, which "_ebc" cannot reach.
    That gate is what this asserts, because it is the one whose removal would
    matter: it exists only in the websocket transport, and the WebRTC transport
    has no equivalent check at all. Today that is academic because dual mode is
    locked off. It stops being academic the moment it is not.

    The precondition is established here rather than assumed: the clipboard is
    loaded, over the same socket, with a uri-list naming a real file. Without
    that the server has nothing to refuse to send, and silence would be read as
    a pass.
    """
    if not unit or not probe_file:
        print("  skip the _ebc path (needs --unit and --probe-file NAME.png, "
              "a real file inside the session)")
        return
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    time.sleep(1)  # journal timestamps have one-second resolution
    try:
        sock, rest = wsprobe.connect(base)
    except OSError as exc:
        bad("_ebc path", f"could not connect: {exc}")
        return
    try:
        for i, text in enumerate(wsprobe.frames(sock, rest)):
            if text and text.startswith("{") and '"server_settings"' in text:
                break
            if i > 40:
                break
        # Off, then on: the server logs the change and not the state, and
        # returns early when asked for what is already set.
        for want in ("false", "true"):
            wsprobe.send(sock, f"_ebc,{want}")
            time.sleep(1)
        uri = "file://" + probe_file
        wsprobe.send(sock, "cb,text/uri-list," +
                     base64.b64encode(uri.encode()).decode())
        time.sleep(2)
        wsprobe.send(sock, "cr")
        time.sleep(3)
    finally:
        sock.close()
    log = subprocess.run(
        ["journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "cat"],
        capture_output=True, text=True)
    if log.returncode != 0:
        bad("_ebc path", "cannot read the session journal: "
                         f"{log.stderr.strip() or log.returncode}")
        return
    moved = "Binary clipboard setting changing to: True" in log.stdout
    refused = "Attempted to send binary clipboard data" in log.stdout
    planted = "Set binary clipboard content" in log.stdout
    # Assert the configured state, not a remembered one. The day binary
    # clipboard is deliberately turned on, EXPECTED changes and this assertion
    # has to turn around with it -- reading the policy from there rather than
    # hard-coding it is what stops that day ending in a check being switched
    # off instead of corrected.
    want_off = EXPECTED["enable_binary_clipboard"][0] is False
    if refused and not want_off:
        bad("_ebc path", "binary clipboard is configured on, but the outbound "
                         "gate refused the send anyway")
    elif refused:
        ok("a file read reached the outbound gate and was refused")
    elif planted and not want_off:
        ok("binary clipboard is configured on and nothing refused the send")
    elif not planted:
        # The uri-list never reached the X11 clipboard, so the server had
        # nothing to resolve and nothing to refuse. Reporting that as a pass
        # would be reading silence as a result; reporting it as a failure would
        # blame the gate for a precondition this script did not manage to set.
        #
        # The usual cause is that xclip is absent: 2.0 offers the clipboard
        # in-process over XFixes and shells out to xclip only for targets the
        # native path will not offer, which is exactly this one. Install xclip
        # in the session to run this check.
        #
        # Its absence is not a defence and must not be read as one. Nothing
        # asserts it, any package may pull it in, and an administrator may
        # install it this afternoon. The reason hdw4s does not depend on it is
        # that the locked-down configuration does not need it -- not that
        # leaving it out protects anything. What protects the session is the
        # outbound gate this check asserts, which holds either way.
        print("  skip the _ebc path (the clipboard write did not land; "
              "install xclip in the session to exercise it)")
    elif moved:
        bad("_ebc path", "the wire verb moved the setting and nothing refused "
                         "the send -- the outbound gate did not fire")
    else:
        # Neither line: the verb did not move the setting either, so upstream
        # has closed the path. Say so rather than quietly passing.
        ok("the _ebc wire verb no longer moves the setting")
    if moved:
        print("  note: \"_ebc\" moved enable_binary_clipboard despite |locked; "
              "the lock is enforced only on the SETTINGS path")


def adopt_configured(unit):
    """Take the operator's choice from the running server, for settings that
    are a policy rather than a fixed refusal.

    Most of EXPECTED is hdw4s's intended lockdown and does not vary. The
    microphone does: HDW4S_MICROPHONE decides it per machine, so asserting a
    remembered value would fail on exactly the machines where the feature was
    deliberately turned on -- and a check that fails when the operator does
    what the setting is for is a check that gets switched off.

    What does not vary, and is still asserted, is the lock. Whichever way the
    value went, a connected page must not be able to move it.
    """
    argv = _server_argv(unit) if unit else None
    if argv is None:
        return
    for flag, name in (("--microphone-enabled=", "microphone_enabled"),
                       ("--webcam-enabled=", "webcam_enabled")):
        raw = next((a.split("=", 1)[1] for a in argv if a.startswith(flag)), None)
        if raw is None:
            continue
        value = raw.split("|", 1)[0] == "true"
        if value != EXPECTED[name][0]:
            EXPECTED[name] = (value, EXPECTED[name][1])
            print(f"  note: {name} is configured on for this session; "
                  f"asserting that, and that it is still locked")


def main():
    argv = sys.argv[1:]
    unit = None
    home = None
    framerate = 30
    probe = None
    for flag in ("--unit", "--home", "--framerate", "--probe-file"):
        if flag in argv:
            i = argv.index(flag)
            value = argv[i + 1]
            del argv[i:i + 2]
            if flag == "--unit":
                unit = value
            elif flag == "--home":
                home = value
            elif flag == "--probe-file":
                probe = value
            else:
                framerate = int(value)
    base = argv[0] if argv else "http://127.0.0.1:7303"
    print(f"lockdown: {base}")
    adopt_configured(unit)
    try:
        settings = check_settings(base)
    except Exception as exc:                       # noqa: BLE001 -- report, don't trace
        bad("server_settings", f"{type(exc).__name__}: {exc}")
        settings = {}
    if settings:
        check_ceilings(settings, framerate)
    check_refusals(base)
    check_no_anonymous(base)
    check_defeat(base, unit)
    check_interposer(unit)
    check_defeat_wire_verb(base, unit, probe)
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
