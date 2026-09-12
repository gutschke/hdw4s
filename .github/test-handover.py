#!/usr/bin/env python3
"""Tests for session hand-over that run anywhere, with nothing installed.

Written because the checks that existed could not fail on this feature at all:
deleting the server module entirely still passed, because a missing file was
skipped and then reported as parsing. Everything here is a property the feature
would lose if a piece of it were removed or renamed.

The signalling module imports nothing outside the standard library at import
time -- the application is imported inside install() -- so all of this works on
a machine with no GStreamer and no Selkies.
"""
import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []


# What the client patch stamps into each file it touches. The server looks for
# this shape rather than for prose, so a fixture has to carry it.
STAMP = "HDW4S-PATCH v1 orig:%s body:%s" % ("a" * 64, "b" * 64)


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("  %-4s %-52s %s" % ("PASS" if ok else "FAIL", name, detail))


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    was = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


# --------------------------------------------------------------- packaging

def _sources():
    """The file list install.sh actually copies."""
    text = open(os.path.join(REPO, "install.sh")).read()
    start = text.index("SOURCES=(")
    end = text.index(")", start)
    return text[start:end]


def test_shipped():
    """Every piece has to be present, executable as intended, and packaged.

    Dropping the server module from the package left a build that installed
    cleanly with the feature silently absent.
    """
    for rel, executable in (("hdw4s_signalling.py", False),
                            ("hdw4s-patch-client", True)):
        path = os.path.join(REPO, rel)
        check("%s is present" % rel, os.path.isfile(path))
        if os.path.isfile(path):
            is_x = os.access(path, os.X_OK)
            check("  and is %s" % ("executable" if executable else "not executable"),
                  is_x == executable)
        text = open(os.path.join(REPO, "debian/install")).read()
        check("  and is listed in debian/install",
              any(line.split()[0] == rel for line in text.splitlines() if line.split()))
        # Specifically inside SOURCES, not merely somewhere in the file: the
        # names also appear in the chmod lines further down, so looking anywhere
        # would pass for a file the installer no longer copies.
        check("  and is listed in install.sh SOURCES", rel in _sources())

    update = open(os.path.join(REPO, "hdw4s-update")).read()
    check("the updater still applies the client half",
          "# --- SESSION HAND-OVER, CLIENT HALF" in update
          and "# --- END SESSION HAND-OVER" in update)
    check("  and does so after the reconnect loop fix",
          update.index("# --- RECONNECT LOOP FIX")
          < update.index("# --- SESSION HAND-OVER, CLIENT HALF"))
    # The two substitutions that keep an unattended, root-run updater from
    # aborting on any answer but the two good ones. The comment above them is
    # currently the only thing defending them from being tidied away, and a
    # comment is not a check.
    block = update[update.index("# --- SESSION HAND-OVER, CLIENT HALF"):
                   update.index("# --- END SESSION HAND-OVER")]
    # The substitutions that keep an unattended, root-run updater from aborting
    # on any answer but the two good ones. Asserted on the "|| :" alone: an
    # earlier version of this pinned the whole line including a "| head -1" that
    # was itself a bug, so the check was holding the defect in place.
    check("the updater cannot abort reading the client state",
          block.count("|| :") >= 2,
          "without the trailing || : this kills the whole updater under set -e")

    # It has no shebang, so without this dpkg would ship it executable and
    # lintian would object.
    check("the module is installed unexecutable",
          'chmod 0644 "${dst}"/hdw4s_signalling.py' in open(os.path.join(REPO, "install.sh")).read())

    session = open(os.path.join(REPO, "hdw4s-run-session")).read()
    check("a session can still start without the wrapper",
          "selkies-gstreamer" in session and "hdw4s_signalling" in session)
    check("  and decides by importing it, not by finding the file",
          "import hdw4s_signalling" in session)
    check("  with the working directory kept off the module path",
          "PYTHONSAFEPATH=1" in session)
    check("  and cannot block session start for ever",
          "timeout 15 env PYTHONSAFEPATH=1" in session,
          "the file test it replaced could not block; this can")
    check("  and actually selects the wrapper when it works",
          "-m hdw4s_signalling)" in session,
          "every other assertion here matches text inside the probe, so "
          "deleting this line leaves them all green and the wrapper unused")
    check("  and says so when it falls back",
          "session hand-over is not available" in session,
          "otherwise a session runs without it for its whole life, silently")


# ------------------------------------------------------------ server module

def test_server_module():
    h = load(os.path.join(REPO, "hdw4s_signalling.py"), "hdw4s_signalling_t")

    for name in ("HandoverMixin", "make_server_class", "install_into",
                 "upstream_state", "client_supports_handover", "main"):
        check("the module offers %s" % name, hasattr(h, name))
    for code, want in (("CLOSE_SESSION_IN_USE", 4001),
                       ("CLOSE_TAKEN_OVER", 4002),
                       ("CLOSE_SUPERSEDED", 4003)):
        check("%s is %d" % (code, want), getattr(h, code, None) == want,
              "a client keys its behaviour off these")
    for method in ("hello_peer", "connection_handler", "remove_peer"):
        check("the mixin overrides %s" % method, method in vars(h.HandoverMixin),
              "renaming one would override nothing, silently")

    # A stand-in for the class the application builds, so the rebinding can be
    # exercised without Selkies present.
    class FakeServer:
        async def hello_peer(self, ws): pass
        async def connection_handler(self, ws, uid, meta=None): pass
        async def remove_peer(self, uid): pass
        async def run(self): pass
        async def cleanup_session(self, uid): pass

    module = types.ModuleType("fake_app")
    module.WebRTCSimpleServer = FakeServer
    # Teach the gate about this stand-in, so it is recognised rather than drifted.
    import inspect
    for name in list(h.KNOWN_UPSTREAM):
        src = inspect.getsource(getattr(FakeServer, name))
        h.KNOWN_UPSTREAM[name] = {hashlib.sha256(src.encode()).hexdigest()}

    with tempfile.TemporaryDirectory() as root:
        for f in ("app.js", "signalling.js", "index.html"):
            open(os.path.join(root, f), "w").write("// %s\n" % STAMP)
        h.WEBROOT = root
        state = h.install_into(module)
        check("install_into recognises a known server", state == "recognised", state)
        check("  and replaces the class the application constructs",
              module.WebRTCSimpleServer is not FakeServer,
              "this is the only seam; renaming the target does nothing at all")
        check("  with a subclass of it",
              isinstance(module.WebRTCSimpleServer, type)
              and issubclass(module.WebRTCSimpleServer, FakeServer))
        check("  that announces itself to a future upstream",
              getattr(module.WebRTCSimpleServer, "SUPPORTS_SESSION_HANDOVER", False) is True)

        # drift
        h.KNOWN_UPSTREAM["hello_peer"] = {"0" * 64}
        module.WebRTCSimpleServer = FakeServer
        state = h.install_into(module)
        check("a changed server is detected", state == "drifted", state)
        check("  and is left alone", module.WebRTCSimpleServer is FakeServer,
              "an override dropped onto changed code is worse than none")

        # upstream adopting it
        h.KNOWN_UPSTREAM["hello_peer"] = {
            hashlib.sha256(inspect.getsource(FakeServer.hello_peer).encode()).hexdigest()}
        FakeServer.SUPPORTS_SESSION_HANDOVER = True
        module.WebRTCSimpleServer = FakeServer
        state = h.install_into(module)
        check("upstream adopting it is noticed", state == "upstream-has-it", state)
        check("  and ours stands down", module.WebRTCSimpleServer is FakeServer)
        del FakeServer.SUPPORTS_SESSION_HANDOVER

    # the two halves must agree
    with tempfile.TemporaryDirectory() as root:
        check("a stock client is seen as unable to ask",
              h.client_supports_handover(root) is False)
        for f in ("app.js", "signalling.js"):
            open(os.path.join(root, f), "w").write("// %s\n" % STAMP)
        check("  and so is one missing the markup that holds the button",
              h.client_supports_handover(root) is False,
              "the button exists only in index.html")
        # Prose alone must not satisfy it: an upstream comment mentioning this
        # feature would otherwise convince the server a stock client can ask.
        open(os.path.join(root, "index.html"), "w").write("HDW4S takeover\n")
        check("  and prose alone does not convince it",
              h.client_supports_handover(root) is False,
              "a phrase is something upstream could write; a digest is not")
        open(os.path.join(root, "index.html"), "w").write("<!-- %s -->\n" % STAMP)
        check("  a fully patched one can", h.client_supports_handover(root) is True)


# ------------------------------------------------- server behaviour, offline

class FakeSocket:
    """Enough of a websocket to drive hello_peer without a network."""

    def __init__(self, message):
        self.remote_address = ("127.0.0.1", 4242)
        self._message = message
        self.sent = []
        self.closed = None

    async def recv(self):
        if self._message is None:
            raise ConnectionError("client went away")
        return self._message

    async def send(self, data):
        self.sent.append(data)

    async def close(self, code=None, reason=None):
        self.closed = (code, reason)


def test_server_behaviour():
    """Drive the decisions rather than reading them.

    Everything else here checks that names exist. Breaking the metadata parse,
    or never closing a refused connection, or letting a client claim the peer
    ids the desktop itself uses, changes no name at all -- and each of those has
    been a real defect in this feature.
    """
    import asyncio
    import base64 as b64
    import json as js

    h = load(os.path.join(REPO, "hdw4s_signalling.py"), "hdw4s_signalling_b")

    class Base:
        def __init__(self):
            self.peers = {}
            self.sessions = {}
            self.rooms = {}
        async def cleanup_session(self, uid): pass
        async def remove_peer(self, uid): self.peers.pop(uid, None)
        async def connection_handler(self, ws, uid, meta=None): pass

    def server():
        cls = h.make_server_class(Base)
        srv = cls()
        srv._owner_task = {}
        srv._refusal_count = {}
        srv._refusal_logged_at = {}
        srv._refusal_streak = {}
        srv._refusal_seen = {}
        srv._last_takeover = {}
        srv._evictions = set()
        srv._client_ok = True
        srv._client_checked = float("inf")
        return srv

    def hello(uid, meta=None):
        if meta is None:
            return "HELLO %s" % uid
        return "HELLO %s %s" % (uid, b64.b64encode(js.dumps(meta).encode()).decode())

    async def run():
        h.REFUSAL_DELAY_STEP = 0.0
        out = {}

        srv = server()
        ws = FakeSocket(hello("1", {"client": "a"}))
        out["first"] = await srv.hello_peer(ws)
        out["first_sent"] = list(ws.sent)

        other = FakeSocket(hello("1", {"client": "b"}))
        out["dup"] = await srv.hello_peer(other)
        out["dup_closed"] = other.closed

        taker = FakeSocket(hello("1", {"client": "b", "takeover": True}))
        out["takeover"] = await srv.hello_peer(taker)

        srv2 = server()
        bad = FakeSocket("HELLO")
        out["malformed"] = await srv2.hello_peer(bad)
        out["malformed_closed"] = bad.closed

        srv3 = server()
        nul = FakeSocket(hello("1", None))
        await srv3.hello_peer(nul)
        thief = FakeSocket(hello("1", {"client": "z", "takeover": True}))
        out["bare_reclaimable"] = await srv3.hello_peer(thief)

        srv4 = server()
        app = FakeSocket(hello("0"))
        await srv4.hello_peer(app)
        evil = FakeSocket(hello("0", {"client": "evil", "takeover": True}))
        out["app_peer"] = await srv4.hello_peer(evil)
        out["app_peer_closed"] = evil.closed

        srv6 = server()
        nul = FakeSocket("HELLO 1 " + b64.b64encode(b"null").decode())
        out["json_null"] = await srv6.hello_peer(nul)
        out["json_null_closed"] = nul.closed

        srv5 = server()
        gone = FakeSocket(None)
        out["no_hello"] = await srv5.hello_peer(gone)
        return out

    r = asyncio.new_event_loop().run_until_complete(run())

    check("a first client is registered", r["first"][0] == "1",
          "got %r" % (r["first"],))
    check("  and is told so", r["first_sent"] == ["HELLO"], str(r["first_sent"]))
    check("a duplicate is refused", r["dup"] == (None, None), str(r["dup"]))
    check("  with the code a client keys on",
          r["dup_closed"] == (h.CLOSE_SESSION_IN_USE, "session in use"),
          str(r["dup_closed"]))
    check("  and the socket is actually closed", r["dup_closed"] is not None)
    check("asking to take over is granted", r["takeover"][0] == "1",
          str(r["takeover"]))
    check("a malformed HELLO is refused, not raised", r["malformed"] == (None, None),
          str(r["malformed"]))
    check("  with a protocol error", r["malformed_closed"] == (1002, "invalid protocol"),
          str(r["malformed_closed"]))
    check("a slot claimed with no metadata can still be taken back",
          r["bare_reclaimable"][0] == "1", str(r["bare_reclaimable"]))
    check("the desktop's own peers cannot be taken over",
          r["app_peer"] == (None, None), str(r["app_peer"]))
    check("  and the attempt is refused, not granted",
          r["app_peer_closed"] == (h.CLOSE_SESSION_IN_USE, "session in use"),
          str(r["app_peer_closed"]))
    check("a client that never says HELLO is handled", r["no_hello"] == (None, None),
          str(r["no_hello"]))
    check("metadata that is not an object is refused",
          r["json_null"] == (None, None), str(r["json_null"]))
    check("  because null would look like the desktop's own peer",
          r["json_null_closed"] == (1002, "invalid protocol"),
          str(r["json_null_closed"]))


# ---------------------------------------------------------------- patcher

def test_patcher():
    p = load(os.path.join(REPO, "hdw4s-patch-client"), "hdw4s_patch_client_t")

    for name, tokens in p.EVIDENCE.items():
        known = dict(p.FILES)
        check("%s is a file the patcher knows" % name,
              name in known or name in p.TOKEN_FILES)
    for name, _ in p.FILES:
        check("%s has evidence defined" % name, name in p.EVIDENCE,
              "without it a stamp alone counts as patched")

    # Backups and patched files are written by rename, not in place. A plain
    # write leaves a truncated file where an interrupt lands, which for a backup
    # is the difference between a rollback that works and one that installs a
    # broken client.
    patcher_src = open(os.path.join(REPO, "hdw4s-patch-client")).read()
    for where in ("_write_atomic(_backup_path(root, name), originals[name])",
                  "_write_atomic(os.path.join(root, name), text)"):
        check("writes go through the atomic path: %s" % where.split("(")[0],
              where in patcher_src)
    # What the client patch is supposed to consist of, recorded here rather than
    # derived from the patch itself. Every other check in this file is
    # self-consistent, so deleting a whole replacement left them all green: the
    # file simply had one fewer edit and one fewer piece of evidence, and agreed
    # with itself. Changing this list is meant to be a deliberate act.
    expected_edits = {
    "signalling.js": (
        "client identity and hand-over callbacks",
        "carry identity and intent in HELLO",
        "close the previous socket before opening another",
        "recognise the private close codes",
        "do not retry out of the hand-over screen",
    ),
    "app.js": (
        "hand-over state in the model",
        "the take-over action",
        "one identity for both channels",
        "do not cascade while held elsewhere",
        "do not cascade while held elsewhere (audio)",
        "the hand-over screen",
        "keep the hand-over screen when the media notices the eviction",
        "keep the hand-over screen when the media notices (audio)",
    ),
    "index.html": (
        "the hand-over screen",
    ),
    }
    for name, edits in p.FILES:
        got = tuple(label for label, _o, _n in edits)
        want = expected_edits.get(name, ())
        check("%s has exactly the edits it should" % name, got == want,
              "expected %d, found %d -- update this list if the change is intended"
              % (len(want), len(got)))

    check("every edit contributes its own evidence",
          all(len(p._sentinels(n)) == len(dict(p.FILES)[n])
              for n, _ in p.FILES),
          "otherwise deleting a whole replacement leaves the file reading patched")

    # Replacements must not change how many brackets are open.
    bad = []
    for name, edits in p.FILES:
        for label, old, new in edits:
            for a, b in (("{", "}"), ("(", ")"), ("[", "]")):
                if (old.count(a) - old.count(b)) != (new.count(a) - new.count(b)):
                    bad.append("%s/%s" % (name, label))
    check("no replacement changes bracket balance", not bad, ", ".join(bad))

    # A real client, if this machine has one.
    webroot = os.environ.get("HDW4S_GST_WEB", "/opt/gst-web")
    if not os.path.isdir(webroot) or shutil.which("node") is None:
        check("full apply/revert against a real client", True,
              "skipped: no client at %s" % webroot)
        return
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "gst-web")
        shutil.copytree(webroot, work)
        # Everything the patcher writes has to stay in here. Left at its
        # defaults this test wrote to /var/lib and /etc -- which fails as an
        # ordinary user, and as root deleted an operator's rollback switch,
        # because applying clears it. A check must not be able to do that.
        p.BACKUP_DIR = os.path.join(tmp, "backups")
        p.DISABLE_MARKER = os.path.join(tmp, "handover.off")
        before = {f: open(os.path.join(work, f), "rb").read()
                  for f, _ in p.FILES}
        if p.analyse(work)[0] != "applicable":
            check("full apply/revert against a real client", True,
                  "skipped: client is %s" % p.analyse(work)[0])
            return
        check("the patch applies to a real client", p.main([work]) == 0)
        check("  and the tree reports itself patched", p.analyse(work)[0] == "patched")
        for f in ("app.js", "signalling.js"):
            r = subprocess.run(["node", "--check", os.path.join(work, f)],
                               capture_output=True, text=True)
            check("  %s still parses" % f, r.returncode == 0,
                  r.stderr.strip().split("\n")[0] if r.returncode else "")
        check("  reverting puts every file back byte for byte",
              p.main(["--revert", work]) == 0
              and all(open(os.path.join(work, f), "rb").read() == before[f]
                      for f, _ in p.FILES))
        check("  and leaves nothing behind",
              not [f for f in os.listdir(work) if f.endswith(p.BACKUP_SUFFIX)])


def main():
    test_shipped()
    test_server_module()
    test_server_behaviour()
    test_patcher()
    bad = [n for n, ok in RESULTS if not ok]
    print("\n  %d passed, %d failed" % (len(RESULTS) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
