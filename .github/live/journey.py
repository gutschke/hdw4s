#!/usr/bin/env python3
"""The journey a junior QA technician does first, driven end to end.

  journey.py --instance _hdw4s_0 --front 7303 --session 7367 \
             --cred /etc/hdw4s/_hdw4s_0.auth.cred

Open the URL, get a desktop, SEE A PICTURE, open a second tab, see what
happened to the first, click the recovery control, confirm recovery -- and
then take the link the product's own share panel offers and check that a
viewer does not steal the desktop.

Three properties this file exists to have, each of them paid for:

  * PRECONDITION FAILED is a separate, loud outcome from CHECK FAILED. The
    harness this replaces reported plausible results when the stream never
    started; a run whose apparatus was wrong must never look like a verdict
    about the product.
  * A check whose precondition did not hold is SKIPPED, never passed. If
    there was never a picture, "did it come back" is not a question.
  * Every oracle is chosen by the DIRECTION of its failure. The picture is a
    screenshot decoded outside the page -- the page's own account of itself
    has been correct while a person looked at a spinner. Movement is the
    page's own decoded-chunk counter, whose failure mode is a false negative,
    which is the safe direction for a claim that something is still working.
    Every window carries a liveness probe, so a dead debugger scores
    UNDECIDED and never "the product stopped".

Each client is its own browser process, profile and debugging port. A run that
shared one display was struck once already.
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser

CHUNKS = "window.videoChunksReceived || 0"
STATUS = "(document.getElementById('status-display')||{}).textContent || ''"
GATE_UP = ("(()=>{var e=document.getElementById('hdw4s-gate');"
           "return e ? !e.hidden : null})()")
GO_LABEL = ("(document.getElementById('hdw4s-go')||{}).textContent || ''")
SHARE_LINK = ("(document.querySelector('#hdw4s-panel .lnk')||{}).value || ''")

PASS, FAIL, SKIP, UNDEC = "PASS", "FAIL", "SKIP", "UNDECIDED"
rows = []


def record(name, outcome, detail=""):
    rows.append((name, outcome, detail))
    print("  %-9s %-46s %s" % (outcome, name, detail), flush=True)
    return outcome == PASS


class Precondition(Exception):
    pass


def need(cond, what, detail=""):
    if not cond:
        raise Precondition("%s%s" % (what, (" -- " + detail) if detail else ""))
    print("  ok        precondition: %s %s" % (what, detail), flush=True)


class Client:
    def __init__(self, port, tag, headers):
        self.br = browser.Browser(port, tag, headers=headers)
        self.tag = tag

    def open(self, url, timeout=120):
        self.br.start()
        if not self.br._connect(60):
            return "the debugger never attached"
        for m in ("Page.enable", "Runtime.enable"):
            self.br.call(m)
        if self.br.headers:
            self.br.call("Network.enable")
            self.br.call("Network.setExtraHTTPHeaders",
                         {"headers": self.br.headers})
        self.br.call("Page.navigate", {"url": url}, timeout=timeout)
        time.sleep(2.0)
        return None

    def eval(self, e, timeout=30):
        return self.br.eval(e, timeout)

    def alive(self):
        return self.br.eval("1+1") == 2

    def moving(self, seconds=5.0):
        """Is video arriving now? (page-side counter, liveness-checked)"""
        a = self.br.eval(CHUNKS)
        time.sleep(seconds)
        b = self.br.eval(CHUNKS)
        if not self.alive():
            return None, (a, b)
        return (b or 0) - (a or 0) > 0, (a, b)

    def colours(self):
        r = self.br.call("Page.captureScreenshot",
                         {"format": "png", "captureBeyondViewport": False},
                         timeout=60)
        if not r or "data" not in r:
            return -1
        # step=1, not the walkthrough's step=7. Both discriminate, but the
        # threshold has to be calibrated for the step in use, and mixing them
        # is how this file's first run reported "no picture" over a desktop
        # that a screenshot showed was perfectly fine: a constant floor of
        # 2500 borrowed from a step=1 calibration, applied to step=7 counts
        # that top out around 1450. The absolute floor is gone with it --
        # every threshold here is derived from this run's own blank page.
        return browser.colours(browser._decode_png(r["data"]), step=1)

    def wait_picture(self, thresh, timeout=60):
        end = time.time() + timeout
        best = 0
        while time.time() < end:
            c = self.colours()
            best = max(best, c)
            if c > thresh:
                return True, c
            time.sleep(0.5)
        return False, best

    def stop(self):
        self.br.stop()


def credential(path, instance):
    """The Authorization header, built the way the product builds it.

    The credential on disk is a systemd ENCRYPTED credential -- reading the
    file gives the blob, which is what an earlier version of this offered the
    server, and the server answered 401 to its own password. It is decrypted
    the same way the session decrypts it, and the plaintext travels in a pipe:
    never in argv, where /proc/<pid>/cmdline publishes it to every account on
    the box, and never into this log.

    The user is the instance name, not a fixed account: hdw4s-run-session sets
    SELKIES_BASIC_AUTH_USER from the instance. Guessing "hdw4s" here fails
    against a server that is configured correctly, which is the worst kind of
    harness bug.
    """
    if not path:
        return {}
    import base64, subprocess
    r = subprocess.run(["systemd-creds", "decrypt", "--name=hdw4s-auth",
                        path, "-"], capture_output=True)
    if r.returncode != 0:
        raise Precondition("could not decrypt %s (systemd-creds exit %d)"
                           % (path, r.returncode))
    pw = r.stdout.decode().strip()
    if not pw:
        raise Precondition("the credential in %s is empty" % path)
    user = instance
    return {"Authorization": "Basic " + base64.b64encode(
        ("%s:%s" % (user, pw)).encode()).decode()}


def http_code(port, headers):
    import urllib.request, urllib.error
    req = urllib.request.Request("http://127.0.0.1:%d/" % port,
                                 headers=headers or {})
    try:
        return urllib.request.urlopen(req, timeout=20).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    ap.add_argument("--front", type=int, required=True)
    ap.add_argument("--session", type=int, required=True)
    ap.add_argument("--cred", default="")
    ap.add_argument("--share", default="view", choices=("view", "control"))
    ap.add_argument("--steal-with-plain-tab", action="store_true",
                    help="run the share check against an ORDINARY second tab, "
                         "which really does steal -- the red run that proves "
                         "the check can fail")
    a = ap.parse_args()

    base = "http://127.0.0.1:%d/?socket_worker=false" % a.front
    url_a = base + "&share=" + a.share
    A = B = C = None
    try:
        hdrs = credential(a.cred, a.instance)
        print("\n-- preconditions (the apparatus and the box, not the product)")
        need(browser.kill_strays() >= 0, "stray browsers cleared")
        code_bare = http_code(a.front, {})
        code_auth = http_code(a.front, hdrs)
        need(code_auth == 200, "the front door answers with our credential",
             "(%s with it, %s without)" % (code_auth, code_bare))
        if hdrs:
            need(code_bare in (401, 403),
                 "and refuses without one, so the credential is doing work",
                 "(%s)" % code_bare)
        busy = browser.attached_stable(a.session, samples=3, gap=1.0)
        need(busy == 0, "nobody else is attached to this desktop",
             "(%s)" % busy)

        A = Client(9310, "A", hdrs)
        need(A.open(url_a) is None, "the first tab's debugger attached")
        A.br.call("Page.navigate", {"url": "http://127.0.0.1:1/"}, timeout=30)
        time.sleep(2)
        blank = A.colours()
        thresh = max(blank * 2, blank + 500)
        need(blank > 0, "the picture oracle is calibrated on this run",
             "(blank page %d colours, threshold %d)" % (blank, thresh))
        A.br.call("Page.navigate", {"url": url_a}, timeout=120)
        time.sleep(2)

        print("\n-- the journey")
        gate = A.eval(GATE_UP)
        record("1. the first tab is offered a way in", PASS if gate else FAIL,
               "gate card up=%s, button %r" % (gate, A.eval(GO_LABEL)))
        if not gate:
            record("2. and pressing it shows a desktop", SKIP, "no card to press")
            return
        A.eval("document.getElementById('hdw4s-go').click()")
        got, c = A.wait_picture(thresh)
        why = ""
        if not got:
            # Name WHICH failure this is. "Frames are arriving and nothing is
            # painted" and "nothing is arriving" are different faults with
            # different owners, and a harness that cannot tell them apart
            # sends people to the wrong one.
            mv, pair = A.moving(4.0)
            why = ("; video IS arriving (chunks %s, fps %s) and the screen is "
                   "still nearly blank -- compare another slot before calling "
                   "it a black desktop" % (pair, A.eval("window.fps||0"))
                   if mv else
                   "; no video is arriving at all (chunks %s) -- the stream "
                   "never established" % (pair,))
        record("2. and pressing it shows a desktop", PASS if got else FAIL,
               "%d colours against a %d-colour blank page (threshold %d)%s"
               % (c, blank, thresh, why))
        if not got:
            for n in ("3. a second tab gets the desktop",
                      "4. the first tab is told it lost it",
                      "5. and its recovery control brings it back",
                      "6. a share link does not steal the desktop"):
                record(n, SKIP, "there was never a picture to lose")
            return

        B = Client(9311, "B", hdrs)
        need(B.open(base) is None, "the second tab's debugger attached")
        B.eval("document.getElementById('hdw4s-go').click()")
        gotb, cb = B.wait_picture(thresh)
        record("3. a second tab gets the desktop", PASS if gotb else FAIL,
               "%d colours" % cb)

        mov, pair = A.moving()
        gate_a, label = A.eval(GATE_UP), A.eval(GO_LABEL)
        if mov is None:
            record("4. the first tab is told it lost it", UNDEC,
                   "the first tab's debugger died")
        else:
            told = (not mov) and gate_a is True
            record("4. the first tab is told it lost it",
                   PASS if told else FAIL,
                   "still receiving=%s, card back=%s, button %r, status %r"
                   % (mov, gate_a, label, A.eval(STATUS)))
        if not gotb or mov is None or mov:
            record("5. and its recovery control brings it back", SKIP,
                   "the first tab never lost the desktop")
        elif gate_a is not True:
            record("5. and its recovery control brings it back", FAIL,
                   "there is no recovery control on screen to press")
        else:
            A.eval("document.getElementById('hdw4s-go').click()")
            time.sleep(2.0)
            back, pic = A.moving(6.0)
            # What the PERSON sees decides this, not whether bytes moved. The
            # first version of this check asserted only that the chunk counter
            # advanced, and passed while the card was still covering the
            # screen -- which is precisely the complaint: the tab looks stuck
            # in "bring it back" whatever is happening behind it. The card is
            # position:fixed, inset:0, at the top of the stacking order, so a
            # card that is up IS what is on screen.
            seen, cols = A.wait_picture(thresh, timeout=20)
            gate_after = A.eval(GATE_UP)
            good = bool(back) and seen and gate_after is not True
            record("5. and its recovery control brings it back",
                   PASS if good else (UNDEC if back is None else FAIL),
                   "chunks %s, %d colours (threshold %d), card still up=%s, "
                   "err %r, selkiesCoreInitialize present=%s, lost=%r, "
                   "status %r"
                   % (pic, cols, thresh, gate_after,
                      A.eval("(document.getElementById('hdw4s-err')||{})"
                             ".textContent || ''"),
                      A.eval("typeof window.selkiesCoreInitialize"),
                      A.eval("window.__hdw4sLost || null"), A.eval(STATUS)))

        # 6. the product's OWN share link, read off its own panel.
        # Who holds the desktop by now depends on what happened in 4 and 5, so
        # it is measured rather than assumed: the first version picked the
        # second tab and skipped the whole check because that tab had since
        # been evicted by the recovery click.
        primary, who = None, "nobody"
        for cand, nm in ((A, "the first tab"), (B, "the second tab")):
            mv, _ = cand.moving(3.0)
            if mv:
                primary, who = cand, nm
                break
        print("      (the desktop is currently going to %s)" % who)
        if primary is None:
            primary = A
        link = A.eval(SHARE_LINK)
        if a.steal_with_plain_tab:
            link, kind = base, "AN ORDINARY SECOND TAB (the red run)"
        else:
            kind = "the link the share panel offers"
        if not link:
            record("6. a share link does not steal the desktop", SKIP,
                   "the share panel offered no link (share=%s)" % a.share)
        else:
            before, _ = primary.moving(4.0)
            if before is not True:
                record("6. a share link does not steal the desktop", SKIP,
                       "the desktop was not streaming to anyone first")
            else:
                C = Client(9312, "C", hdrs)
                need(C.open(link) is None, "the viewer's debugger attached")
                if C.eval(GATE_UP) is True:
                    C.eval("document.getElementById('hdw4s-go').click()")
                time.sleep(6.0)
                after, pair2 = primary.moving(5.0)
                if after is None:
                    record("6. a share link does not steal the desktop", UNDEC,
                           "the primary's debugger died")
                else:
                    record("6. a share link does not steal the desktop",
                           PASS if after else FAIL,
                           "%s -> the desktop's owner %s (chunks %s)"
                           % (kind, "kept streaming" if after
                              else "WAS EVICTED", pair2))
    except Precondition as e:
        print("\n  PRECONDITION FAILED: %s" % e)
        print("  This run says NOTHING about the product. It says the "
              "apparatus or the box was not ready.")
        return 3
    finally:
        for c in (A, B, C):
            if c:
                c.stop()
        browser.kill_strays()
        if rows:
            bad = [r for r in rows if r[1] == FAIL]
            und = [r for r in rows if r[1] == UNDEC]
            skp = [r for r in rows if r[1] == SKIP]
            print("\n  %d passed, %d FAILED, %d undecided, %d skipped"
                  % (len(rows) - len(bad) - len(und) - len(skp), len(bad),
                     len(und), len(skp)))
            for n, o, d in bad:
                print("    FAILED: %s -- %s" % (n, d))
    return 1 if [r for r in rows if r[1] == FAIL] else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
