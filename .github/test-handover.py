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
    for what in ('"${patcher}" --check "${WEBROOT}" 2>/dev/null | head -1)" || :',
                 "HANDOVER\n)\" || :"):
        check("the updater cannot abort on %s" % ("--check" if "patcher" in what else "the state query"),
              what in block,
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
            open(os.path.join(root, f), "w").write("HDW4S takeover\n")
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
            open(os.path.join(root, f), "w").write("HDW4S takeover\n")
        check("  and so is one missing the markup that holds the button",
              h.client_supports_handover(root) is False,
              "the button exists only in index.html")
        open(os.path.join(root, "index.html"), "w").write("HDW4S takeover\n")
        check("  a fully patched one can", h.client_supports_handover(root) is True)


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
    test_patcher()
    bad = [n for n, ok in RESULTS if not ok]
    print("\n  %d passed, %d failed" % (len(RESULTS) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
