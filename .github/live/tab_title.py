#!/usr/bin/python3
"""WHAT DOES THE TAB STRIP SAY? A real browser, on session pages built by a tree.

    .github/live/tab_title.py [<tree>]

Builds a named and a pool session page with <tree>'s hdw4s-gate-index, serves
them from loopback, opens each arm in headless Chrome, and records EVERY value
document.title took (an observer installed before the page's first script, so
a one-frame flash is caught rather than sampled past). Prints one line per
check and exits 1 on any failure. <tree> defaults to the one this file is in;
pointing it at an older checkout is how the red half is seen.

STAND-INS, named. The streaming client is a two-statement module that does
exactly what upstream's selkies-ws-core.js does to the tab when it loads --
writes "Selkies", then fetches manifest.json and writes its "name" -- and
nothing else. So nothing here connects, streams or evicts; a lost connection
is stood in for by putting the card back up, which is what the gate's lost()
does. Real: the gate generator, the title keeper and names script it inlines,
Chrome's parser, its title handling and its fetch.

What it cannot show: the tab strip's PIXELS, or an installed app's name. Those
are screenshots on a real session (see the round's merge walk).
"""
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import browser as B  # noqa: E402

TREE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", ".."))
SID = "ab" * 16
UPSTREAM = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Selkies</title>
    <link rel="apple-touch-icon" href="icon-512.png">
    <link rel="manifest" href="manifest.json" crossorigin="use-credentials">
    <link rel="icon" type="image/png" href="icon.png" />
    <script type="module" crossorigin src="./assets/client.js"></script>
  </head>
  <body><div id="root"></div></body>
</html>
"""
# upstream selkies-ws-core.js, the two statements that touch the tab, verbatim
CLIENT = """document.title = 'Selkies';
fetch('manifest.json')
  .then(response => response.json())
  .then(manifest => {
    if (manifest.name) {
      document.title = manifest.name;
    }
  })
  .catch(() => {
  });
"""
RECORD = """(function(){
  window.__titles = [];
  var last = null;
  function note(){ var t = document.title; if (t !== last) { last = t; window.__titles.push(t); } }
  new MutationObserver(note).observe(document, {subtree:true, childList:true, characterData:true});
  document.addEventListener('DOMContentLoaded', note);
})();"""


def build(root, rel, env):
    d = os.path.join(root, rel)
    os.makedirs(os.path.join(d, "assets"), exist_ok=True)
    with open(os.path.join(d, "upstream.html"), "w") as f:
        f.write(UPSTREAM)
    with open(os.path.join(d, "assets", "client.js"), "w") as f:
        f.write(CLIENT)
    e = dict(os.environ, HDW4S_LIBDIR=TREE, **env)
    subprocess.run([os.path.join(TREE, "hdw4s-gate-index"),
                    os.path.join(d, "upstream.html"), os.path.join(d, "index.html")],
                   env=e, check=True, stdout=subprocess.DEVNULL)
    return d


def manifest(d, name):
    p = os.path.join(d, "manifest.json")
    if name is None:
        if os.path.exists(p):
            os.unlink(p)
    else:
        with open(p, "w") as f:
            json.dump({"name": name, "short_name": name}, f)


def main():
    root = tempfile.mkdtemp(prefix="hdw4s-tab-title-")
    named = build(root, "n", {"HDW4S_SESSION_NAME": "Desktop"})
    pool = build(root, "s/%s" % SID, {"HDW4S_SESSION_NAME": "Desktop",
                                      "HDW4S_DIRECTORY": "yes"})

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=root, **k)

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]

    failed = 0

    def check(name, cond, detail=""):
        nonlocal failed
        print(("ok   " if cond else "FAIL ") + name + ("" if cond else "  -- " + detail))
        failed += 0 if cond else 1

    B.kill_strays()
    b = B.Browser(9333, "tabtitle")
    b.start()
    try:
        if not b._connect(60):
            print("FAIL the browser started")
            return 1
        for m in ("Page.enable", "Runtime.enable"):
            b.call(m)
        b.call("Page.addScriptToEvaluateOnNewDocument", {"source": RECORD})

        def visit(url):
            b.call("Page.navigate", {"url": url})
            b.wait_for("document.readyState", lambda v: v == "complete", timeout=20)
            b.pump(1.5)
            return b.eval("window.__titles") or [], b.eval("document.title")

        def never(label, seen):
            bad = [t for t in seen if "selkies" in (t or "").lower()]
            check(label + ": the tab never read the upstream word", not bad,
                  "titles seen: %r" % seen)

        # 1. A named desktop whose proxy names it, on its card.
        manifest(named, "Desktop: studio")
        seen, now = visit(base + "/n/index.html")
        never("named, on the card", seen)
        check("named, on the card: the administrator's name, marked idle",
              now == "Desktop: studio (idle)", repr(now))
        # 2. Connected (gate=off loads the client at once).
        seen, now = visit(base + "/n/index.html?gate=off")
        never("named, connected", seen)
        check("named, connected: the administrator's name, unmarked",
              now == "Desktop: studio", repr(now))
        # 3. Connected, and the manifest cannot be fetched -- the client's own
        #    word is all it wrote.
        manifest(named, None)
        seen, now = visit(base + "/n/index.html?gate=off")
        never("named, connected, no manifest", seen)
        check("named, connected, no manifest: the built name",
              now == "Desktop", repr(now))
        # 4. The card comes back (the gate's lost() puts it up): idle again.
        b.eval("document.getElementById('hdw4s-gate').hidden = false")
        b.pump(0.5)
        now = b.eval("document.title")
        check("named, card back up after a loss: marked idle",
              now == "Desktop (idle)", repr(now))

        # 5. A pool desktop: this browser's own number, on its card.
        manifest(pool, "Desktop")
        seen, now = visit(base + "/s/%s/index.html" % SID)
        never("pool, on the card", seen)
        check("pool, on the card: this browser's number, marked idle",
              now == "Desktop 1 (idle)", repr(now))
        # 6. Connected with no manifest: the client's write must not stand.
        manifest(pool, None)
        seen, now = visit(base + "/s/%s/index.html?gate=off" % SID)
        never("pool, connected, no manifest", seen)
        check("pool, connected, no manifest: this browser's number",
              now == "Desktop 1", repr(now))
    finally:
        b.stop()
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)
    print("%d failed" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
