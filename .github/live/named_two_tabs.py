#!/usr/bin/env python3
"""Two tabs on a NAMED session: does the second silently steal the first?

Reported by the owner 2026-09-22 against a named session: the tab loaded last
took the desktop and freeze-framed the other, with no gate and no warning.

THIS IS NOT A REGRESSION TEST. The gate has never existed for named sessions --
it lives in a page injected into a web root, and only ephemeral sessions are
given one. There was no code path to test, which is why nothing caught this.
The check exists so that when a gate IS built, its arrival is observed rather
than assumed, and so the gap is visible until then.

WHERE IT RUNS. The workstation or the sandbox, NEVER inside a desktop container:
the containers are on the isolated guest network and cannot reach the LAN proxy,
and that isolation fails as a timeout indistinguishable from a broken vhost.

WHICH SESSION. The TEST account on the test container only. Never the owner's
own named session, and never the one real user's: connecting to either evicts a
person mid-use with nothing shown to them.

PRE-REGISTERED, before the run -- opening tab 2 BACKGROUNDS tab 1 and Chrome
throttles a backgrounded renderer, so a frozen counter is what eviction AND
throttling both look like. No page-side number can separate them. The verdict
comes from outside the perturbed channel:
    1. tab 1's session socket still ESTABLISHED on the container
    2. tab 1's delta after Page.bringToFront -- throttling resumes, eviction does not
    3. tab 2 streaming at the same moment
"""
import json, subprocess, sys, time, urllib.parse, urllib.request

sys.path.insert(0, "/".join(__file__.split("/")[:-1]))
import browser, wsprobe

# Nothing about a particular estate is written down here. This file ships in a
# public repository, so a hostname, an address or an account name would leak a
# private deployment's topology into it -- and a default would also be the wrong
# one for every reader but us.
#
# It fails closed rather than guessing: without these set it refuses to run,
# instead of silently pointing at something plausible. Choose them with care --
# THE SESSION NAMED HERE WILL BE TAKEN OVER MID-RUN. Point this at a test
# account on a test machine, never at a session a person is using: connecting
# evicts the occupant and shows them nothing.
#
#   HDW4S_LIVE_URL       the session's URL through the reverse proxy
#   HDW4S_LIVE_INSTANCE  the hdw4s instance name behind it
#   HDW4S_LIVE_SSH       ssh destination of the machine running that session
import os

HOST = os.environ.get("HDW4S_LIVE_URL", "")
INSTANCE = os.environ.get("HDW4S_LIVE_INSTANCE", "")
SESSION_HOST = os.environ.get("HDW4S_LIVE_SSH", "")
DISPLAY = os.environ.get("HDW4S_LIVE_DISPLAY", ":81")
PORT = int(os.environ.get("HDW4S_LIVE_CDP_PORT", "9391"))


def on_host(cmd):
    return subprocess.run(["ssh", "-o", "ConnectTimeout=8", SESSION_HOST, cmd],
                          capture_output=True, text=True).stdout


def internal_port():
    """The port the session itself listens on, derived rather than hardcoded.

    NOT the external port the socket unit binds: when this was written against
    a hardcoded 7300 it was watching a different account's session entirely,
    and would have reported on somebody else's desktop while claiming to
    measure this one.
    """
    idx = on_host("awk '$1 !~ /^#/ && $2 == \"%s\" { print $1; exit }' "
                  "/etc/hdw4s/instances" % INSTANCE).strip()
    if not idx.isdigit():
        raise SystemExit("PRECONDITION: no index for instance %r" % INSTANCE)
    base = 7300
    block = 64
    return base + block + int(idx)


def attached(port):
    """Clients on the named session's stream port, read from the MACHINE.

    Out of band on purpose: the page cannot tell eviction from Chrome
    throttling a backgrounded tab, and opening the second tab creates exactly
    that confound.
    """
    out = on_host("ss -Htn state established 'sport = :%d'" % port)
    return len([l for l in out.splitlines() if l.strip()])


class Tab:
    """A second tab inside an already-running Chrome: same cookie jar, same
    profile -- which is what the owner did."""

    def __init__(self, port, url):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/json/new?about:blank" % port, method="PUT")
        t = json.loads(urllib.request.urlopen(req, timeout=10).read())
        _, _, rest = t["webSocketDebuggerUrl"].partition("://")
        hostport, _, path = rest.partition("/")
        self.sock, self._rest = wsprobe.connect("http://" + hostport,
                                                path="/" + path)
        self.sock.settimeout(30)
        self._frames = wsprobe.frames(self.sock, self._rest)
        self._id = 0
        self.call("Page.navigate", {"url": url})

    def call(self, method, params=None, timeout=30):
        self._id += 1
        want = self._id
        wsprobe.send(self.sock, json.dumps(
            {"id": want, "method": method, "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            for fr in self._frames:
                try:
                    msg = json.loads(fr)
                except Exception:
                    continue
                if msg.get("id") == want:
                    return msg.get("result")
                break
        return None

    def eval(self, expr, timeout=30):
        r = self.call("Runtime.evaluate",
                      {"expression": expr, "returnByValue": True}, timeout)
        try:
            return r["result"].get("value")
        except Exception:
            return None


def main():
    missing = [n for n, v in (("HDW4S_LIVE_URL", HOST),
                              ("HDW4S_LIVE_INSTANCE", INSTANCE),
                              ("HDW4S_LIVE_SSH", SESSION_HOST)) if not v]
    if missing:
        print("PRECONDITION: set %s -- see the header. This test TAKES OVER the "
              "session it is pointed at, so it will not guess one."
              % ", ".join(missing))
        return 2
    xvfb = subprocess.Popen(["Xvfb", DISPLAY, "-screen", "0", "1280x800x24"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    try:
        browser.kill_strays()
        b = browser.Browser(PORT, "named-t1", display=DISPLAY)
        b.start()
        b.open(HOST + "/?socket_worker=false", timeout=120)
        b.pump(8)
        t0 = time.time()
        while time.time() - t0 < 90:
            if (b.eval("window.videoChunksReceived || 0") or 0) > 0:
                break
            time.sleep(2)
        if not (b.eval("window.videoChunksReceived || 0") or 0):
            print("  PRECONDITION FAILED: tab 1 never streamed")
            return 2
        iport = internal_port()
        print("  instance %s, internal port %d" % (INSTANCE, iport))
        print("  tab 1 streaming, clients attached: %d" % attached(iport))

        t2 = Tab(PORT, HOST + "/?socket_worker=false")
        time.sleep(12)
        gate = t2.eval("(()=>{var e=document.getElementById('hdw4s-gate');"
                       "return e ? !e.hidden : 'no gate element'})()")
        print("  tab 2 gate: %r" % gate)
        t0 = time.time()
        while time.time() - t0 < 60:
            if (t2.eval("window.videoChunksReceived || 0") or 0) > 0:
                break
            time.sleep(2)
        print("  tab 2 chunks: %s" % t2.eval("window.videoChunksReceived || 0"))

        sock = attached(iport)
        b.call("Page.bringToFront")
        time.sleep(2)
        f1 = b.eval("window.videoChunksReceived || 0") or 0
        time.sleep(10)
        f2 = b.eval("window.videoChunksReceived || 0") or 0
        print("  [1] clients attached now            : %d" % sock)
        print("  [2] tab 1 delta after bringToFront  : %d" % (f2 - f1))
        print("  [3] tab 2 streaming concurrently    : %s"
              % t2.eval("window.videoChunksReceived || 0"))

        stolen = (f2 - f1) <= 0
        if gate is True:
            print("\n  PASS: tab 2 was gated; the owner is asked before taking over.")
            rc = 0
        elif stolen:
            print("\n  FAIL (known gap): tab 2 took the desktop silently and "
                  "tab 1 is frozen. No gate exists for named sessions.")
            rc = 1
        else:
            print("\n  UNDECIDED: no gate, but tab 1 is still streaming.")
            rc = 3
        b.stop()
        return rc
    finally:
        xvfb.terminate()


if __name__ == "__main__":
    sys.exit(main())
