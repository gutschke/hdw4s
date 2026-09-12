#!/usr/bin/env python3
"""Check the JavaScript that hdw4s-patch-client puts into the streaming client.

The updater's own injected JavaScript is parsed by extract-injected-js.py, but
the client patcher carries several kilobytes more of it in string constants, and
that code reaches a browser without anything having looked at it. A syntax error
there shows up as a blank tab and nothing in any log.

Two modes, because the strong check needs something this repository does not
carry:

  * given a real client (HDW4S_GST_WEB, or /opt/gst-web), apply the patch to a
    throwaway copy and hand the result to "node --check". This validates what
    is actually served.
  * otherwise, check that every replacement keeps brackets balanced relative to
    the text it replaces. That catches the realistic mistake -- an unbalanced
    brace in a hand-written fragment -- without needing a client to patch.

Exit status is 0 when everything checked passed, 1 otherwise. The mode used is
printed, so a weaker run is never mistaken for a strong one.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Beside this script when it is run from a checkout of .github/, or one level
# up in the repository root.
for _candidate in (os.path.join(REPO, "hdw4s-patch-client"),
                   os.path.join(HERE, "hdw4s-patch-client")):
    if os.path.isfile(_candidate):
        spec_path = _candidate
        break
else:
    print("cannot find hdw4s-patch-client next to %s" % HERE)
    sys.exit(1)


def load_patcher():
    # Importing by path otherwise leaves a __pycache__ beside the file it
    # imported, in a source tree that has no business gaining one.
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        return _load_patcher()
    finally:
        sys.dont_write_bytecode = previous


def _load_patcher():
    spec = importlib.util.spec_from_loader(
        "hdw4s_patch_client",
        importlib.machinery.SourceFileLoader("hdw4s_patch_client", spec_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def balanced(patcher):
    """Every replacement must not change how many brackets are open."""
    problems = []
    for name, edits in patcher.FILES:
        for label, old, new in edits:
            for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
                delta_old = old.count(opener) - old.count(closer)
                delta_new = new.count(opener) - new.count(closer)
                if delta_old != delta_new:
                    problems.append(
                        "%s / %s: '%s' balance changes by %+d"
                        % (name, label, opener, delta_new - delta_old))
    return problems


def parsed(patcher, webroot):
    """Patch a copy of a real client and parse the result."""
    problems = []
    tmp = tempfile.mkdtemp(prefix="hdw4s-jscheck-")
    try:
        work = os.path.join(tmp, "gst-web")
        shutil.copytree(webroot, work)
        rc = patcher.main([work])
        if rc != 0:
            return ["patcher exited %d" % rc]
        state, _ = patcher.analyse(work)
        if state != "patched":
            return ["patcher left the tree %r" % state]
        for name in ("app.js", "signalling.js"):
            path = os.path.join(work, name)
            out = subprocess.run(["node", "--check", path],
                                 capture_output=True, text=True)
            if out.returncode != 0:
                problems.append("%s: %s" % (name, out.stderr.strip().split("\n")[0]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return problems


def main():
    patcher = load_patcher()
    problems = balanced(patcher)
    mode = "bracket balance"

    webroot = os.environ.get("HDW4S_GST_WEB", "/opt/gst-web")
    have_node = shutil.which("node") is not None
    if os.path.isdir(webroot) and have_node:
        state, _ = patcher.analyse(webroot)
        if state == "applicable":
            mode = "full parse against %s" % webroot
            problems += parsed(patcher, webroot)
        elif state == "mismatch":
            # The one answer worth failing on: the client this patch is written
            # against has changed, so it would silently install nothing.
            problems.append("%s no longer matches what the patch expects" % webroot)
        else:
            mode += " (%s is %s, not a stock client)" % (webroot, state)
    elif not have_node:
        mode += " (node is not installed)"
    else:
        mode += " (no client at %s)" % webroot

    print("mode: %s" % mode)
    for p in problems:
        print("  %s" % p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
