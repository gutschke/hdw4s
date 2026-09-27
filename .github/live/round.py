#!/usr/bin/env python3
"""The standing walkthrough, driven through the proxy hostname by a real browser.

WHY THIS EXISTS, and why it is not another suite. Five branches can be green at
their own layers -- a duration parser, a page generator, a cookie lifetime, a
residue sweep, a socket rig -- without one of them being evidence that a person
gets a desktop. This file is the arm that looks at the product: a real Chrome on
a real framebuffer, arriving at the hostname a visitor types, and a picture as
the oracle. `curl` proves arrival and never a picture, so no arm here scores a
status code.

WHY THE HOSTNAME AND NOT A PORT. Reaching a session by its internal port skips
the reverse proxy, which is the thing under test on three of the release
criteria. Guest-isolated containers cannot reach the proxy at all, so this file
is meant to be run FROM THE WORKSTATION against --url. The loopback-side arms
already live in journey.py; this one deliberately does not duplicate them,
because an arm that confuses the two tests a different path than it claims.

WHY NOTHING ABOUT THE ESTATE IS IN HERE. Hostnames, instances, slot counts and
the way to ask a server a question all arrive as arguments. This file ships.

WHAT IT WILL NOT TELL YOU. A matrix score counts the paths somebody thought of.
This file prints a SHAPE -- the same rows, with the same detector named on each
-- and the assertion between rounds is that the shape repeats, not that a number
repeats. Two rows that go green by a different route are a different product.

SAFETY, AND WHAT IT DOES NOT COVER. This rig will not start until a person has
asserted which hostnames it may open and which container serves each, and until
the named container reports that NOBODY is attached to any session on it.
Both are refusals, not warnings. Read the two-layer note further down before
changing either.

  The occupancy check can be waived once you have asked the occupant. THE
  ALLOWLIST CANNOT BE WAIVED AT ALL -- an override lets a person overrule a
  measurement, never their own earlier assertion. If you need a host that is
  not listed, add it to the list; that is deliberate and reviewable, and an
  override a one-line addition would replace should be that addition.

  NEITHER LAYER CLOSES THE MAIN HOLE, and it is stated here so that nobody
  reads the pair as airtight. Every hostname on this estate resolves to the
  SAME proxy, which routes by Host header, so the address distinguishes a test
  pool from a real person's live desktop not at all. The hostname-to-container
  mapping is therefore a HUMAN ASSERTION -- it lives in the proxy's config on a
  host nobody currently has access to. Give this rig a real person's hostname
  while telling it an idle development container and it will probe the idle
  box, see nobody, report clear, and connect to that person. `--guardtest`
  demonstrates exactly that, on purpose. When the mapping can be DERIVED from
  the proxy instead of declared, the derivation replaces the allowlist and must
  be re-read EVERY RUN: a cached mapping is the same defect with a longer fuse.

  ./round.py --url https://desk.example/ --slots 2 --display-base 90 \
             --allow-host desk.example=<container> \
             --occupancy-probe '<command printing attached count for {container}>'
  ./round.py --selftest     # detectors AND the guard, against known answers
  ./round.py --guardtest    # just the guard, seen refusing
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser  # noqa: E402
import isolation  # noqa: E402  -- for XServer only
import wsprobe  # noqa: E402

# Every caller in this directory appends it, and the reason is not cosmetic:
# without it the session's socket lives in a worker, whose frames belong to a
# different CDP target, and the wire-side tally sees nothing at all. An arm
# that forgets it measures silence and calls it a dead stream.
WORKER_OFF = "socket_worker=false"


def visit_url(url):
    if not url.startswith("http") or WORKER_OFF in url:
        return url
    return url + ("&" if "?" in url else "?") + WORKER_OFF

PASS, FAIL, SKIP, UNDEC, GATED = "PASS", "FAIL", "SKIP", "UNDECIDED", "GATED"

# A sixth, and it is not a synonym for any of the five.
#
# UNDECIDED means the question was PUT and the answer was unclear. UNASKABLE
# means it was never put, because this apparatus cannot reach the state the row
# exists to look at -- no such device, no such page, nothing to photograph. The
# distinction is the difference between "we looked and could not tell" and "we
# did not look", and collapsing them is how a row stops being run while still
# printing a line every round. SKIP stays what it was: the ROUND did not reach
# the state, though the apparatus could have.
UNASKABLE = "UNASKABLE"

# The page-side video counter. Its LEVEL is not liveness -- a frozen tab keeps
# whatever count it reached -- so every use of it here is a DELTA over a window.
#
# IT RETURNS None WHEN THERE IS NO COUNTER, AND THAT IS THE WHOLE POINT. This
# used to be `window.videoChunksReceived || 0`, which maps an ABSENT counter and
# a counter sitting at zero onto the same value. The counter is published by
# the upstream Selkies client and by nothing in this repository, so the day
# upstream renames it every window reads 0 -> 0, `moving()` says no video, and
# arm 1 reports FAIL -- a product defect that does not exist, reported by an
# instrument that cannot see. Measured 2026-09-23 in real Chrome on the real
# gate page before the client module had loaded: `... || 0` returned 0, this
# expression returned None. Absent is not zero; the arms now say UNDECIDED.
CHUNKS = ("(typeof window.videoChunksReceived === 'number'"
          " ? window.videoChunksReceived : null)")

# The gate and its button, as RAW FACTS. Nothing here decides anything: what
# the facts MEAN lives in shown() below, in Python, where the self-test points
# at it. Two implementations plus a test is three things to keep in step.
#
# WHY GEOMETRY AND NOT `.hidden`, and it is measured rather than argued. This
# used to be `e ? !e.hidden : null`. hdw4s-gate-index carries a stylesheet
# whose comment says an author `display:flex` beats the user-agent
# `[hidden]{display:none}`, so without its `!important` rule the card stays on
# the screen while every DOM probe reads back hidden. That state was produced
# on purpose 2026-09-23 -- real Chrome, the real gate page, one extra rule
# appended after the product's own <style>: the card measured 1279x656 and the
# screenshot counted 1445 colours, and `!e.hidden` said the gate was DOWN. A
# detector for "is the product still asking" that reads an attribute instead of
# the picture cannot see the one failure its own stylesheet exists to prevent.
#
# The `hidden` flag is still collected, because hidden-but-painted is worth
# printing on the detail line: it is a product defect, not a rig defect.
def _facts(el_id):
    return ("(()=>{var e=document.getElementById(%s);"
            "if(!e) return {present:false};"
            "var r=e.getBoundingClientRect();var s=getComputedStyle(e);"
            "return {present:true,hidden:!!e.hidden,display:s.display,"
            "visibility:s.visibility,w:r.width,h:r.height};})()"
            % json.dumps(el_id))


GATE_FACTS = _facts("hdw4s-gate")
GO_FACTS = _facts("hdw4s-go")

# Clicking Connect, and SAYING WHAT HAPPENED. The old form was
# `document.getElementById('hdw4s-go') && document.getElementById(...).click()`,
# whose value is undefined when the button was found and clicked and undefined
# when `.click()` did nothing -- measured, it returned None in every state,
# including one where the button was there. It carried no information at all,
# so click_gate() reported "clicked" on the strength of a different detector.
# This returns one of three primitives and the caller records which.
CLICK_GO = ("(()=>{var e=document.getElementById('hdw4s-go');"
            "if(!e) return 'absent';"
            "if(!e.getClientRects().length) return 'not-rendered';"
            "e.click(); return 'clicked';})()")

# The product's own wording for the capacity refusal, and the ONLY thing that
# separates it from the 502 the same builder produces when a desktop dies.
# selftest() checks this against hdw4s-demux itself, so a rewording goes red
# there instead of quietly turning a crash into a pass.
CAPACITY_TITLE = "Every desktop is in use"

# The address bar, and NOTHING BUT the address bar. The session id is derived
# from this in Python by sid_of(), which is the one the self-test exercises.
#
# WHY THE EXTRACTION IS NOT DONE IN THE PAGE, and it is the reason four rows of
# the first real run were lost. This used to ask the page for the id directly:
#
#   (((location.pathname.match(/^\/s\/([^\/]+)\//))||[])[2])||''
#
# which reads capture group TWO of a regex that has ONE, so it evaluated to ''
# on every address a browser could possibly be at. Measured 2026-09-23 in a
# real Chrome parked on /s/abc123def/: the expression returned '', the same
# expression indexed [1] returned 'abc123def'.
#
# The self-test was green throughout, and could not have been anything else: it
# exercised sid_of(), a PYTHON TWIN of that expression, and nothing ever
# asserted the two agreed. A detector checked in one language and run in
# another is two detectors, and only one of them was ever pointed at a known
# answer. So the repair is not a second self-test for the JS -- it is deleting
# the twin. The page is asked only for a primitive it cannot get wrong, and
# every rule about what an address means lives in sid_of(), once.
PATHNAME = "location.pathname"


# --------------------------------------------------------------------------
# Result vocabulary
# --------------------------------------------------------------------------

rows = []


def record(name, outcome, detector, detail="", artefact=None, question=""):
    """One row. `detector` is not decoration.

    An arm whose detector is "no error" is not an arm, so every row has to name
    what was actually observed. It is printed on every run because the thing
    compared between rounds is the shape -- these names, these detectors -- and
    a detector that quietly changed is how a matrix goes green by a new route.

    `artefact` and `question` are the row's instruction to a reader, and they
    are a pair on purpose. A row that saves a file and says "see the evidence
    directory" has built a filing cabinet; a row that names the file AND the
    specific question somebody is meant to answer from it has left an
    instruction. The first real run left two undecided rows sitting as "awaiting
    a human verdict" across two exchanges, and opening the image took one step
    and produced three facts -- one of which was about a different row
    altogether.
    """
    rows.append((name, outcome, detector, detail, artefact, question))
    print("  %-9s %-44s [%s] %s" % (outcome, name, detector, detail),
          flush=True)
    if artefact:
        print("            READ %s -- %s" % (artefact, question), flush=True)
    return outcome == PASS


def print_reading_list(counts):
    """What a person must OPEN before this round means anything.

    Pixel counting is the default and stays the default: it is cheap, it runs
    unattended, and a row answering cleanly should not have its picture read.
    This is the other half of that -- when a row is NOT answering cleanly, the
    image gets read now rather than filed, because a wild goose chase is what
    the deferral buys.

    Two triggers, and the second is the one nobody would have written down:

      1. An undecided row that saved an artefact. Undecided plus a file is an
         instruction to open the file, not a note for later.

      2. A PASS THAT DOES NOT FIT ITS NEIGHBOURS. In the first real run one row
         passed while reporting the same empty identifier that made four of its
         neighbours skip -- its detector is a picture and a chunk delta, and
         neither consults that datum, so it was perfectly entitled to pass and
         the tally hid the anomaly completely. A pass surrounded by rows that
         could not run is a claim about a round that mostly did not happen, and
         it deserves its evidence read for the same reason an undecided row
         does.
    """
    unrun = counts[SKIP] + counts[GATED] + counts[UNASKABLE] + counts[UNDEC]
    lonely = unrun > counts[PASS] and counts[PASS] > 0
    todo = [r for r in rows if r[4] and r[1] != PASS]
    if not todo and not lonely:
        return
    print("\n  READ THIS EVIDENCE BEFORE BELIEVING THE ROUND:")
    for name, outcome, _, _, artefact, question in todo:
        print("    %s (%s)\n      %s\n      question: %s"
              % (artefact, outcome, name, question))
    if lonely:
        print("    %d row(s) passed while %d could not run. A pass whose "
              "neighbours\n      never reached their own state is a claim "
              "about a round that mostly did\n      not happen -- re-read the "
              "passing rows' detail lines and ask what a\n      failure of the "
              "unrun rows would have done to them."
              % (counts[PASS], unrun))


class Precondition(Exception):
    """The apparatus or the box was not ready.

    Raised, never recorded. A run that ends this way says NOTHING about the
    product, and saying so is the whole point of the separate exit status: a
    harness that reports "0 failures" after failing to start a browser has
    reported that it found nothing, which is not the same as there being
    nothing.
    """


def need(cond, what, detail=""):
    if not cond:
        raise Precondition("%s%s" % (what, (" -- " + detail) if detail else ""))
    print("  ok        precondition: %s %s" % (what, detail), flush=True)


# --------------------------------------------------------------------------
# Detectors
#
# Each of these is exercised by --selftest against a known positive AND a known
# negative before any of them is believed. A detector only ever seen agreeing
# with the product is indistinguishable from one that cannot disagree with it.
# --------------------------------------------------------------------------

def sid_of(html_or_path):
    m = re.match(r"^/s/([^/]+)/", html_or_path or "")
    return m.group(1) if m else ""


def owner_update(kind, sid, previous):
    """The session a visitor OWNS -- the SECOND notion of identifier.

    The rig had one where it needs two, and this is the one it was missing.
    sid() reads location.pathname, so it answers WHICH ADDRESS THIS BROWSER IS
    DISPLAYING. Most of the time that is also the session the visitor holds,
    which is exactly why the conflation survived: the two coincide until
    somebody is deliberately sent to an address that is not theirs.

    Measured 2026-09-23, and it is where this function comes from. Row 6 pastes
    A's link into B, the product refuses, and B is left SITTING at A's address
    displaying the refusal. Row 7 then asked "whose session does B hold?"
    through sid() and was told "A's" -- a correct answer to the question sid()
    answers, and the wrong question. It reported the two visitors SWAPPED while
    the three neighbouring rows about the same two browsers all passed, and the
    product was not implicated in any of it.

    So ownership is adopted ONLY from an arrival at the front door that was
    SERVED. A capacity refusal, a dead desktop, an unknown page, or a landing
    with no session in the path are things that happened to the address bar,
    not transfers of a session, and each leaves ownership where it was.

    Not "navigate B away after the refusal": that repairs one call site and
    leaves the next one to rediscover this. Ownership is now a value only
    front_door() can move, so a raw goto() cannot corrupt it by construction.
    """
    return sid if sid and kind in ("desktop", "gate") else previous


def fresh_visitor_verdict(kind):
    """What a BRAND-NEW visitor meeting a full pool must be told.

    'refused' is the capacity page. 'broken' is a 502 from a dead desktop and
    is NOT the same answer -- the round-4 note has said so since the detector
    tier was built, while the arm carrying that expectation was putting it to
    the wrong browser entirely. Anything else means the pool was not full,
    which makes every later row here evidence about nothing.
    """
    if kind == "refused":
        return PASS, "the capacity page"
    if kind == "broken":
        return FAIL, ("a DEAD desktop (502), not a capacity refusal -- the "
                      "failure that scores as a pass if 'no desktop' is the "
                      "whole test")
    if kind in ("desktop", "gate"):
        return FAIL, ("served, so the pool was not full and nothing later is "
                      "evidence about an exhausted pool")
    return FAIL, "neither served nor refused"


def second_tab_verdict(kind, sid2, sid1):
    """What the OWNER's second tab must get when the pool has no free slot.

    This row used to assert the capacity refusal, and that was a category
    error rather than a threshold set too high. Two tabs in one browser share
    one cookie jar, so tab 2 is the SAME VISITOR arriving again -- the arrival
    rule resumes it, and resuming consumes no slot. A second tab should never
    reach the capacity path at all, full pool or not. The row was exercising
    one mechanism and asserting another's expectation, so it had the shape of
    a product failure while the product was doing what the owner ruled.

    The expectation that belongs here is the one a full pool actually puts at
    risk: THE OWNER IS NOT LOCKED OUT OF HIS OWN DESKTOP because strangers
    filled the pool. A refusal to tab 2 is that lock-out. That is why this
    keeps running against a full pool rather than folding into row 8, whose
    pool has room: same assertion, different and harsher circumstance.
    """
    if kind == "refused":
        return FAIL, ("the owner's own second tab was told the pool is full; "
                      "resuming consumes no slot, so this is a lock-out")
    if kind not in ("desktop", "gate"):
        return FAIL, "the owner's second tab landed on %r" % kind
    if not sid1:
        return UNDEC, "tab 1 held no session to be resumed"
    if sid2 != sid1:
        return FAIL, "tab 2 minted %s rather than resuming %s" % (sid2[:12],
                                                                 sid1[:12])
    return PASS, "resumed tab 1's session"


def shown(facts):
    """Is this element ON THE SCREEN? -- three answers, and the third matters.

    None   there is no such element. Not "it is down": a front-door card and a
           refusal page have no gate at all, and an arm that reads that as
           "the gate is down" has answered a question nobody put.
    False  it exists and nothing of it is painted.
    True   it exists and occupies a box.

    Read the PICTURE, not the attribute. `hidden` is a property the page sets;
    whether the card is covering the desktop is a fact about what was drawn,
    and the two come apart -- measured, see GATE_FACTS. `visibility:hidden`
    still occupies a box, so it is checked separately; `opacity:0` is not, and
    is named under "what this cannot see" on click_gate().

    `facts` is whatever GATE_FACTS/GO_FACTS returned, INCLUDING None: a probe
    that could not be evaluated at all (a dead debugger, a page that refused
    the eval) comes back None from browser.eval, and returning None here keeps
    "I could not ask" distinct from "there is nothing there". Both are un-
    answered, and neither is a failure of the product.
    """
    if not isinstance(facts, dict) or not facts.get("present"):
        return None
    if facts.get("display") == "none" or facts.get("visibility") == "hidden":
        return False
    return (facts.get("w") or 0) > 0 and (facts.get("h") or 0) > 0


def contradicts(facts):
    """Painted while claiming to be hidden -- the product defect shown() sees.

    Printed on the detail line rather than scored: the round's verdict is about
    what the visitor got, and this is about how the page got there. It is the
    exact state hdw4s-gate-index's stylesheet comment exists to prevent, so a
    round that ever prints it has caught that stylesheet regressing.
    """
    return bool(isinstance(facts, dict) and facts.get("hidden")
                and shown(facts))


def classify(title, body_html):
    """Which of the three pages is this? -- and this is a PROXY, not a reading.

    The product emits three kinds of page from the front door and they are
    distinguishable only by accident:

      desktop  the gated client, which carries #hdw4s-gate / #hdw4s-go
      gate     demux gate_page(): a card WITH a button (POST /sessions/new)
      refused  demux page(): the same card WITHOUT the link (the 503)

    gate_page() and page() differ by one <form action="/sessions/new"> and
    nothing else (it was an <a href="/"> until the ended page's button stopped
    resuming another desktop; both are still read, so an older build classifies
    too). Neither carries an id, a class or a data- attribute saying which it
    is, so this function is reading a styling decision and calling it a
    protocol. It is good enough to run the round and it is not good enough to
    keep: the repair
    is one attribute on <body> in hdw4s-demux (see the report accompanying this
    file), after which this function reads that attribute and the structural
    guess below becomes the fallback rather than the oracle.

    Until then: this classification is UNMEASURED against a restyled page, and
    the experiment that settles it is changing the card's markup and watching
    --selftest go red.
    """
    if body_html is None:
        return "unreachable"
    if "hdw4s-gate" in body_html or "hdw4s-go" in body_html:
        return "desktop"
    card = 'style="max-width:32rem' in body_html or "max-width:32rem" in body_html
    if not card:
        return "unknown"
    if 'action="/sessions/new"' in body_html or 'href="/"' in body_html:
        return "gate"
    # A LINKLESS CARD IS NOT ONE THING, and this cost the exhaustion arm its
    # meaning before it ever ran. page() builds BOTH the 503 "every desktop is
    # in use" (capacity: the correct answer to a second tab on a full box) and
    # the 502 "that desktop closed the connection" (the backend died). They are
    # byte-identical in structure. An arm asserting "tab 2 was refused" would
    # therefore score a CRASHED DESKTOP as a correct capacity refusal -- a
    # failure SATISFYING the check that was supposed to catch it.
    #
    # There is no marker to read, so this matches the product's own title
    # strings, which is prose matching and is the weakest thing in this file.
    # It is survivable only because selftest() asserts these constants still
    # equal what the product builds: a reworded page goes RED there rather than
    # silently misclassifying here. The real repair is still one attribute.
    return "refused" if CAPACITY_TITLE in (title or "") else "broken"


def colour_floor(client):
    """The picture threshold, derived from THIS run's own blank page.

    Not a constant. A constant floor borrowed from a different screenshot step
    once reported "no picture" over a desktop that was perfectly fine, and a
    constant is in any case a claim about a box nobody re-checked. The floor is
    whatever about:blank scores here, today, plus a margin.
    """
    client.goto("about:blank")
    time.sleep(1.0)
    blank = max(client.colours() for _ in range(3))
    if blank < 0:
        raise Precondition("could not screenshot about:blank")
    # journey.py's formula, at journey.py's step. The two must be quoted
    # together: a floor calibrated for one sampling step applied to counts from
    # another once reported "no picture" over a desktop that was perfectly
    # fine. colours() here is step=1, so this is the step=1 formula.
    return max(blank * 2, blank + 500), blank


# --------------------------------------------------------------------------
# Browser handles
# --------------------------------------------------------------------------

class Visitor:
    """One browser profile -- its own cookie jar, which is what "another
    person" means to this product, since ownership is keyed on the browser."""

    def __init__(self, port, tag, display_num, real_media_ui=False):
        # ONE X SERVER PER BROWSER, never a shared one. Two headful Chromes on
        # one display occlude each other, and the one underneath screenshots as
        # a blank rectangle -- a convincing false "the product did not paint"
        # that has cost this project two runs. isolation.XServer already knows
        # how to raise and wait for one, so this borrows it rather than
        # spawning Xvfb a third way.
        self.x = isolation.XServer(display_num)
        self.display = ":%d" % display_num
        self.br = browser.Browser(port, tag, display=self.display,
                                  fake_media_ui=not real_media_ui)
        self.tag = tag
        self.tabs = []
        # THE SECOND NOTION OF IDENTIFIER. sid() answers "which address is this
        # browser displaying"; this answers "which session does this visitor
        # hold". Only front_door() moves it -- see owner_update().
        self.held = ""

    def start(self):
        if not self.x.up(timeout=20):
            raise Precondition("no framebuffer on %s for %s"
                               % (self.display, self.tag))
        self.br.start()
        if not self.br._connect(60):
            raise Precondition("the debugger never attached for %s" % self.tag)
        for m in ("Page.enable", "Runtime.enable"):
            self.br.call(m)

    def goto(self, url, settle=2.0):
        """Navigate. DELIBERATELY does not touch ownership: an arm that sends a
        browser to an address chosen by the arm -- a pasted link, someone
        else's session -- is moving the address bar, not handing over a
        session. Front-door arrivals go through front_door()."""
        self.br.call("Page.navigate", {"url": visit_url(url)}, timeout=120)
        time.sleep(settle)

    def front_door(self, url, settle=4.0):
        """Arrive the way a person does: type the address, answer the card.

        Returns (kind, clicked). This is the ONLY thing that can change what
        this visitor owns, so a row asking about ownership reads `held` and
        gets an answer that no later navigation can have overwritten.
        """
        self.goto(url, settle=settle)
        clicked = self.click_gate()
        kind = classify(self.title(), self.html())
        self.held = owner_update(kind, self.sid(), self.held)
        return kind, clicked

    def owned(self):
        """The session this visitor holds, as last established at the front
        door. NOT what its address bar currently reads -- see owner_update()
        for the round where those two came apart and cost a row."""
        return self.held

    def photograph(self, path):
        """The whole framebuffer, address bar included.

        An ownership row's detector reads location.pathname; this reads the
        same fact off the screen with a different mechanism, which is what was
        missing when a one-character bug in the id expression survived a green
        self-test. Returns an error string, or None on success.
        """
        return root_screenshot(self.display, path)

    def eval(self, e, timeout=30):
        return self.br.eval(e, timeout)

    def alive(self):
        return self.br.eval("1+1") == 2

    def sid(self):
        return sid_of(self.eval(PATHNAME) or "")

    def html(self):
        return self.eval("document.documentElement.outerHTML") or ""

    def title(self):
        return self.eval("document.title") or ""

    def front(self):
        # Opening a second tab BACKGROUNDS the first and freezes its counter,
        # which is indistinguishable from eviction. Anything that measures a
        # delta on a tab that may have been backgrounded raises it first.
        try:
            self.br.call("Page.bringToFront")
        except Exception:
            pass
        time.sleep(0.5)

    def moving(self, seconds=5.0, raise_first=True):
        """Is video arriving NOW? Returns (bool|None, (before, after)).

        None means UNANSWERED, and it now has two causes rather than one. The
        debugger dying mid-measure was always one. The other is the counter not
        being there: it is published by the upstream client and by nothing we
        ship, so a rename upstream leaves this rig reading None forever. Scored
        as "no video" that is a FAIL against a desktop that is streaming
        perfectly -- the expensive direction -- so it is scored as no answer,
        and the pair it returns carries the None through to the detail line
        where a reader can see WHICH kind of silence it was.
        """
        if raise_first:
            self.front()
        a = self.eval(CHUNKS)
        time.sleep(seconds)
        b = self.eval(CHUNKS)
        if not self.alive():
            return None, (a, b)
        if a is None or b is None:
            return None, (a, b)
        return b - a > 0, (a, b)

    def colours(self):
        r = self.br.call("Page.captureScreenshot",
                         {"format": "png", "captureBeyondViewport": False},
                         timeout=60)
        if not r or "data" not in r:
            return -1
        return browser.colours(browser._decode_png(r["data"]), step=1)

    def wait_picture(self, floor, timeout=75):
        end = time.time() + timeout
        best = 0
        while time.time() < end:
            c = self.colours()
            best = max(best, c)
            if c > floor:
                return True, best
            time.sleep(0.5)
        return False, best

    def grant_media(self, origin):
        """Answer the camera/microphone prompt, the way a person clicking
        Allow does, without turning the prompt off.

        NOT --use-fake-ui-for-media-stream: that browser never asks, and the
        arm this exists for is about what the browser's chrome SHOWS. This
        answers the question that was actually put.

        Two mechanics, both of which bit while this was written:

          * Browser.grantPermissions is a BROWSER-domain command, so it goes
            to the browser target's websocket. The rest of this file talks to
            a PAGE target, which does not carry it.
          * It REPLACES the granted set for the origin. Granting videoCapture
            and then audioCapture leaves video revoked -- measured, as a
            NotAllowedError on video while audio succeeded. Hence one call.
        """
        try:
            ver = json.loads(urllib.request.urlopen(
                "http://127.0.0.1:%d/json/version" % self.br.port,
                timeout=5).read())
            _, _, rest = ver["webSocketDebuggerUrl"].partition("://")
            hostport, _, path = rest.partition("/")
            sock, tail = wsprobe.connect("http://" + hostport, path="/" + path)
            sock.settimeout(20)
            frames = wsprobe.frames(sock, tail)
            wsprobe.send(sock, json.dumps({
                "id": 1, "method": "Browser.grantPermissions",
                "params": {"origin": origin,
                           "permissions": ["videoCapture", "audioCapture"]}}))
            end = time.time() + 20
            while time.time() < end:
                try:
                    text = next(frames)
                except (StopIteration, OSError):
                    return False
                if text is None:
                    continue
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                if msg.get("id") == 1:
                    return "result" in msg
        except Exception:
            return False
        return False

    def gate(self):
        """(shown, facts) for the card. `shown` is True/False/None -- see shown()."""
        f = self.eval(GATE_FACTS)
        return shown(f), f

    def click_gate(self):
        """Press Connect if the card is up, and REPORT WHAT THE PAGE DID.

        Returns the page's own word: 'clicked', 'not-rendered', 'absent', or
        None when the card was not up so nothing was pressed. It used to return
        a bare True on the strength of the gate detector while the click
        expression itself returned undefined in every state -- so "we clicked
        Connect" was an inference, never an observation.

        WHAT THIS CANNOT SEE, and both are reachable: a button rendered but
        covered by something with a higher z-index, and one at opacity:0. Both
        have a client rect, so this reports 'clicked' and the person's click
        would have landed elsewhere. `.click()` also dispatches to a covered
        element where a real pointer would not, so this is a weaker test than a
        person for exactly that case. The picture is the oracle that settles
        it: the arm goes on to wait for a desktop, and a click that did nothing
        leaves the card up and is recorded as GATED.
        """
        up, _ = self.gate()
        if up is not True:
            return None
        what = self.eval(CLICK_GO)
        time.sleep(3.0)
        return what

    def new_tab(self, url):
        """A second tab in THIS browser: same profile, same cookie jar."""
        t = Tab(self.br.port, url)
        self.tabs.append(t)
        return t

    def stop(self):
        self.br.stop()
        try:
            self.x.stop()
        except Exception:
            pass


class Tab:
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
        self.call("Page.navigate", {"url": visit_url(url)})
        time.sleep(3.0)

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

    def sid(self):
        return sid_of(self.eval(PATHNAME) or "")

    def html(self):
        return self.eval("document.documentElement.outerHTML") or ""

    def title(self):
        return self.eval("document.title") or ""


# --------------------------------------------------------------------------
# Talking to the server without pretending to be a browser
# --------------------------------------------------------------------------

class Occupied(Exception):
    """Somebody may be at a desk, or we cannot show that nobody is.

    Deliberately NOT a Precondition: a precondition failure means the apparatus
    was not ready and the fix is to make it ready. This one means the apparatus
    WAS ready and using it would have been the harm.
    """


# --------------------------------------------------------------------------
# The occupancy guard -- TWO LAYERS, AND NEITHER ONE IS SUFFICIENT
#
# The danger. Connecting to a session somebody is using either evicts them or
# silently joins with full keyboard, pointer and clipboard while they are shown
# nothing; the URL fragment decides which, so a harness must never assume it
# would be noticed. There is a real person on this estate.
#
# Why this is not a network problem. EVERY hostname here resolves to the SAME
# address: one reverse proxy routing by Host header. The ephemeral pool and a
# real person's live session are indistinguishable at the network layer, so
# checking an address proves nothing at all. Nothing below resolves a name, on
# purpose -- and if someone is tempted to add it later: `getent hosts` appends
# the search domain and a wildcard answers, returning confident addresses for
# names that do not exist. That trap has fired twice on this project. `dig
# +short` is the tool, and it still would not help here.
#
# LAYER 1, the allowlist. A person asserts, once, which hostnames this rig may
# ever open and which container each one is served by. Thereafter it is
# mechanical: a hostname not on the list is a refusal. This converts "the
# operator must remember, every run" into "one assertion, enforced forever".
#
# LAYER 2, the container probe. Ask the named container whether ANY session on
# it is attached -- not just the slot about to be used. Which slot the proxy
# routes to is not knowable from here, so the only safe predicate is that the
# whole box is idle.
#
# WHAT NEITHER LAYER CLOSES, and this is stated here rather than left implied:
# the hostname-to-container mapping is a HUMAN ASSERTION. The mapping lives in
# the proxy's configuration on a host nobody currently has access to, so it
# cannot be derived. Point this rig at the real user's hostname while telling
# it the development container and it will probe an idle box, see nobody, report
# clear, and connect to a person. LAYER 2 CANNOT DETECT A WRONG LAYER 1. The
# pair is not airtight and must not be described as though it were.
#
# The repair, when the access exists: derive the mapping from the proxy's own
# configuration instead of declaring it, and RE-READ IT EVERY RUN. A mapping
# read once and cached is the same defect with a longer fuse, because a
# configuration can change after it was read.
# --------------------------------------------------------------------------

def parse_hostmap(entries):
    """HOST=CONTAINER pairs into a dict, refusing anything malformed.

    One assertion carries both layers: being on the list is the permission,
    and the container named beside it is what gets probed. Keeping them in one
    place means a host can never be permitted without also saying where to look
    to see whether it is busy.
    """
    out = {}
    for e in entries or []:
        host, sep, container = e.partition("=")
        host, container = host.strip().lower(), container.strip()
        if not sep or not host or not container:
            raise Occupied(
                "REFUSING TO START: --allow-host %r is not HOST=CONTAINER. "
                "Every permitted hostname must name the container that serves "
                "it, because that container is what gets asked whether anybody "
                "is using it." % e)
        out[host] = container
    return out


def probe_attached(probe, container):
    """How many clients are attached anywhere on `container`? Three answers.

    Returns (count, reason). `count` is an int only when the probe answered a
    number; None means "could not tell", which is NOT zero. A zero that came
    from a failed probe is not a zero, and treating it as one is the whole
    failure this guard exists to prevent.
    """
    if not probe:
        return None, "no --occupancy-probe was given"
    cmd = probe.replace("{container}", container)
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd],
                           capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None, "the probe did not finish within 60s"
    except Exception as e:
        return None, "the probe could not be run: %s" % e
    out = r.stdout.decode(errors="replace").strip()
    err = r.stderr.decode(errors="replace").strip()
    if r.returncode != 0:
        return None, ("the probe exited %d (stderr: %r)"
                      % (r.returncode, err[:200]))
    if not out:
        # Empty stdout with a zero exit is the shape most easily misread as
        # "zero attached". `ss ... | wc -l` against an unreachable host does
        # exactly this, and so does a typo in a remote command.
        return None, "the probe printed nothing (exit 0, empty stdout)"
    token = out.split()[-1]
    try:
        return int(token), "the probe answered %r" % out[:200]
    except ValueError:
        return None, "the probe printed %r, which is not a number" % out[:200]


def guard_unoccupied(url, allow_entries, probe, asked=False):
    """Both layers. Raises Occupied, or returns (container, count, reason).

    `asked` overrides LAYER 2 ONLY, and never layer 1. The rule behind that
    asymmetry, because it is not obvious from either layer on its own:

      AN OVERRIDE LETS A PERSON OVERRULE A MEASUREMENT. IT MUST NOT LET THEM
      OVERRULE THEIR OWN ASSERTION.

    Layer 2 asks "is somebody using this machine right now". A person really
    does have better information than the probe -- they can go and ask the
    occupant -- so overriding it CONTRIBUTES new information, and that is the
    case the estate's "ask, permission is almost always granted" rule is about.

    Layer 1 asks "am I pointed at the right machine". The allowlist IS a
    person's own earlier, more careful answer to that question. A flag that
    bypasses it lets the same person overrule themselves in a hurry, with less
    context than they had when they wrote the list. That is not permission, it
    is forgetting.

    The consequences are not symmetrical either. Layer 2 failing means we
    disturbed somebody who was there: bad, and visible immediately. Layer 1
    failing means we connected to the estate's one real user believing we were
    on a development box -- the cardinal rule broken silently, by a run that
    reported success. Those two do not deserve the same key.
    """
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").lower()
    allowed = parse_hostmap(allow_entries)

    if not allowed:
        raise Occupied(
            "REFUSING TO START: no --allow-host was given, so there is no "
            "assertion about which hostnames this rig may open.\n"
            "  Every hostname on this estate resolves to the same proxy, so "
            "nothing about the address distinguishes the test pool from a real "
            "person's desktop. Pass --allow-host HOST=CONTAINER.")
    if host not in allowed:
        raise Occupied(
            "REFUSING TO START: %r is not on the allowlist.\n"
            "  Permitted: %s\n"
            "  This is a refusal, not a warning: a hostname nobody vouched for "
            "may be somebody's live desktop, and it would look identical from "
            "here." % (host, ", ".join(sorted(allowed)) or "(none)"))

    container = allowed[host]
    if asked:
        # Layer 1 has already passed by this point -- the override never
        # reaches it.
        return container, None, ("layer 2 waived by "
                                 "--i-have-asked-and-may-proceed")
    n, why = probe_attached(probe, container)
    if n is None:
        raise Occupied(
            "REFUSING TO START: cannot establish that %s is idle -- %s.\n"
            "  Not a warning and not a skip. An unanswered question about "
            "whether somebody is at a desk is answered NO.\n"
            "  --occupancy-probe must print the number of clients attached to "
            "ANY session on the container ({container} is substituted) and "
            "exit non-zero when it cannot tell." % (container, why))
    if n > 0:
        raise Occupied(
            "REFUSING TO START: %d client(s) attached on %s -- %s.\n"
            "  Somebody may be at that desk. Ask before running this."
            % (n, container, why))
    return container, n, why


def server_count(probe, instance):
    """How many clients the SERVER thinks are attached, via an opaque command.

    The caller supplies the command; this file knows nothing about how to reach
    the machine, and deliberately cannot. {instance} is substituted. The
    command must print one integer on stdout.

    This exists because the page-side counter cannot tell a backgrounded tab
    from an evicted one, and the arm that matters most this round -- a second
    tab against an exhausted pool -- turns entirely on that distinction. With
    no probe, that arm reports UNDECIDED rather than passing.
    """
    if not probe:
        return None
    cmd = probe.replace("{instance}", instance or "")
    r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=60)
    if r.returncode != 0:
        return None
    try:
        return int(r.stdout.decode().strip().split()[-1])
    except Exception:
        return None


def root_screenshot(display, path):
    """The WHOLE framebuffer, including the browser's own chrome.

    A CDP screenshot is the page and only the page: the omnibox, and the
    capture indicator that lives in it, are not in it at all. An arm about what
    the browser's chrome shows cannot use one. Needs ImageMagick's `import`.
    """
    if not display:
        return "no --display, so there is no framebuffer to photograph"
    env = dict(os.environ, DISPLAY=display)
    try:
        r = subprocess.run(["import", "-window", "root", path],
                           env=env, capture_output=True, timeout=60)
    except FileNotFoundError:
        return "ImageMagick `import` is not installed on this machine"
    if r.returncode != 0:
        return "import exited %d" % r.returncode
    return None


def discriminator(url):
    """Is this hostname actually served by the product, or by a catch-all?

    A catch-all vhost answers 200 to any hostname, so "the URL returned 200" is
    not evidence that the name under test is configured at all. This asks for a
    name that certainly is not configured, on the same address, and requires a
    DIFFERENT answer. Same answer for both means the run would be testing the
    catch-all, and the round stops rather than reporting on it.

    IT MUST NOT ASK FOR "/". Every cookieless GET of the front door MINTS, and
    consumes a slot: two probes here would empty a pool of two before the first
    browser arrived, and the round would then be measuring a machine this
    function exhausted. So it asks for a session id that cannot exist, which
    the demux answers 403 or 410 from WITHOUT minting, and which a catch-all
    has no reason to answer the same way.
    """
    from urllib.parse import urlsplit, urljoin
    parts = urlsplit(url)
    url = urljoin(url, "/s/hdw4s-no-such-session-%d/" % int(time.time()))
    bogus = "hdw4s-no-such-name-%d.invalid" % int(time.time())

    def fetch(host_header):
        req = urllib.request.Request(url)
        if host_header:
            req.add_header("Host", host_header)
        try:
            r = urllib.request.urlopen(req, timeout=20)
            return r.status, len(r.read(4096))
        except urllib.error.HTTPError as e:
            return e.code, len(e.read(4096) or b"")
        except Exception as e:
            return None, str(e)

    real = fetch(None)
    fake = fetch(bogus)
    return real, fake, (real != fake), parts.hostname


# --------------------------------------------------------------------------
# The arms
# --------------------------------------------------------------------------

def arm_first_visit(a, url, floor):
    """A person opens the address and gets a desktop.

    Detector: colour count on a screenshot rises above this run's own blank
    floor, AND the video counter advances over a window. Either alone is weak
    -- a still error page can be colourful, and a counter that has advanced at
    some point in the past is not a counter advancing now.

    Gate vs failure: if #hdw4s-gate is PAINTED, this is the product ASKING,
    which is a correct outcome for some arrivals and not a failure. The arm
    clicks Connect once, because that is what a person does, and only reports
    GATED if the card is still up afterwards.

    The gate detector decides GATED against FAIL here, so a detector that
    cannot see the card manufactures a product defect that does not exist --
    which is the expensive direction, because a false FAIL is a chase. It is
    measured against a real Chrome on the real gate page by browsertest().
    """
    kind, clicked = a.front_door(url)
    if kind == "refused":
        # NOT a soft row. A capacity refusal to the FIRST visitor of a run
        # means every slot was owned before the run started, so every row
        # after this one is about an exhausted pool while claiming to be about
        # something else -- which is exactly what happened once, and was caught
        # only because a person read the transcript. A row that says "this
        # round cannot see a desktop" and then lets thirteen more rows print is
        # a remedy living in somebody's memory.
        #
        # It REFUSES rather than resetting. A reset kills every session on the
        # machine, and a test rig that destroys state to make its own
        # preconditions true is a rig that will one day do it to the wrong box
        # -- the same reasoning that keeps reset-state.sh behind
        # private/dev-targets. So it names the remedy and stops.
        raise Precondition(
            "the FIRST visitor of this run was refused for capacity (%r).\n"
            "    Every slot was already owned before the run began, so nothing "
            "this rig\n"
            "    could go on to measure would be about the thing its rows "
            "name.\n"
            "    The remedy, which this tool will not perform for you because "
            "it destroys\n"
            "    every session on the target:  private/reset-state.sh "
            "<ssh-target>" % a.title())
    got, best = a.wait_picture(floor)
    if not got:
        up, facts = a.gate()
        if up is True:
            return record("1. first visit gets a desktop", GATED,
                          "picture<floor AND #hdw4s-gate painted",
                          "the card is still asking (%dx%d); no desktop was "
                          "promised%s"
                          % (facts.get("w") or 0, facts.get("h") or 0,
                             "; and it claims hidden -- the [hidden] rule in "
                             "hdw4s-gate-index has stopped winning"
                             if contradicts(facts) else ""))
        if up is None and facts is None:
            # The probe itself could not be evaluated. That is not a product
            # verdict, and calling it FAIL would be this rig blaming the
            # product for its own blindness.
            return record("1. first visit gets a desktop", UNDEC,
                          "picture<floor and the gate probe did not answer",
                          "colours %d <= floor %d, page kind %s"
                          % (best, floor, kind))
        return record("1. first visit gets a desktop", FAIL,
                      "picture<floor, no gate painted",
                      "colours %d <= floor %d, page kind %s, click %r"
                      % (best, floor, kind, clicked))
    mov, pair = a.moving(5.0)
    if mov is None:
        return record("1. first visit gets a desktop", UNDEC,
                      "chunk counter gone or debugger died mid-measure",
                      "chunks %s -- a None here is the counter this rig reads "
                      "not existing on this build, NOT an absence of video"
                      % (pair,))
    return record("1. first visit gets a desktop", PASS if mov else FAIL,
                  "colours>floor AND chunk delta>0",
                  "colours %d>%d, chunks %s->%s%s"
                  % (best, floor, pair[0], pair[1],
                     ", after Connect (%s)" % clicked if clicked else ""))


def arm_reload_resumes(a, url):
    """A reload is not a new tab, and must never mint.

    Detector: the session id in the ADDRESS BAR before and after. Equal means
    resumed; different means a reload minted, which is the release blocker this
    product has already had once. Empty afterwards means the reload landed on
    the front door, which is a third outcome and is reported as such.
    """
    before = a.sid()
    if not before:
        return record("2. a reload resumes, never mints", SKIP,
                      "no sid to resume", "arm 1 did not reach /s/<sid>/")
    a.front_door(url)
    after = a.sid()
    if not after:
        return record("2. a reload resumes, never mints", GATED,
                      "sid absent after reload",
                      "the reload landed on the front door (%s) rather than a "
                      "session" % classify(a.title(), a.html()))
    return record("2. a reload resumes, never mints",
                  PASS if after == before else FAIL,
                  "sid before == sid after",
                  "%s -> %s" % (before[:12], after[:12]))


def arm_second_tab(a, url, probe, instance, exhausted):
    """Two tabs in ONE browser -- the shape the owner broke by hand in a minute
    while a matrix reported sixteen of sixteen.

    Run twice by the caller: once with the pool having room, once EXHAUSTED.

    WHAT THE EXHAUSTED HALF USED TO ASSERT, AND WHY IT WAS WRONG: it demanded
    that tab 2 be told the pool is full. Tab 2 shares tab 1's cookie jar, so it
    is the same visitor arriving again and the arrival rule RESUMES it --
    which is what the deployment did, and the row called it a failure. A
    capacity refusal needs a FRESH VISITOR with a fresh cookie jar; that is now
    row 4a, taken from the browsers exhaust() opens. See second_tab_verdict().

    Detector, tab 2: which page it landed on, AND whether it came back to tab
    1's session rather than minting or being refused.
    Detector, tab 1: chunk delta AFTER Page.bringToFront, because opening tab 2
    backgrounds tab 1 and freezes its counter, which looks exactly like
    eviction. Where a --server-probe is supplied, the server's own count of
    attached clients is the corroborating reading, and it is the one that
    settles it: the client-side delta cannot separate "frozen" from "gone" on
    its own, so with no probe and a zero delta this arm is UNDECIDED and says
    so rather than reporting a failure it cannot see.
    """
    label = ("4b. two tabs, pool EXHAUSTED" if exhausted
             else "3. two tabs, pool has room")
    sid1 = a.owned()
    before_n = server_count(probe, instance)
    t = a.new_tab(url)
    kind = classify(t.title(), t.html())
    sid2 = t.sid()

    if exhausted:
        outcome, why = second_tab_verdict(kind, sid2, sid1)
        record(label + " (tab 2 resumes, is NOT refused)", outcome,
               "tab 2 resumes tab 1's session; a refusal is a LOCK-OUT",
               "tab 2 got %s, title %r, sid %r vs tab 1's %r -- %s"
               % (kind, t.title(), sid2[:12], sid1[:12], why))
    else:
        ok2 = kind in ("desktop", "gate")
        record(label + " (tab 2 is served)", PASS if ok2 else FAIL,
               "page kind in {desktop,gate}",
               "tab 2 got %s, sid %r" % (kind, sid2[:12]))

    mov, pair = a.moving(6.0)
    after_n = server_count(probe, instance)
    label = label.replace("4b.", "4c.")
    if mov is None:
        return record(label + " (tab 1 survives)", UNDEC,
                      "tab 1's counter gone, or its debugger died",
                      "chunks %s -- a None is no counter to read, not no video"
                      % (pair,))
    if mov:
        return record(label + " (tab 1 survives)", PASS,
                      "chunk delta>0 after bringToFront",
                      "chunks %s->%s, sid %s, server %s->%s"
                      % (pair[0], pair[1], sid1[:12], before_n, after_n))
    if after_n is None:
        return record(label + " (tab 1 survives)", UNDEC,
                      "zero delta, no --server-probe",
                      "a backgrounded tab and an evicted one both read zero "
                      "here; supply --server-probe to separate them")
    return record(label + " (tab 1 survives)",
                  PASS if after_n >= (before_n or 0) and after_n > 0 else FAIL,
                  "server-side attached count",
                  "page delta zero; server %s->%s" % (before_n, after_n))


def arm_reverse_order(a, b, url, evidence):
    """The same two visitors, arriving in the other order.

    Not a relabelling of the row above: it re-navigates B first and A second,
    where the first run had A first. Order is exactly the kind of thing a
    cookie-keyed ownership rule gets wrong in one direction only -- whoever
    arrives second resuming the first one's session is a swap that a
    same-order test can never see, because in that test the second arrival is
    always the same browser.

    Detector: each browser comes back to the sid it already held. A swap, or
    either of them minting a third, is the failure.

    THE BEFORE-VALUES ARE OWNERSHIP, NOT THE ADDRESS BAR, and the difference
    is not academic here. This arm runs immediately after row 6 pastes A's
    link into B, which leaves B parked at A's address displaying a refusal --
    so reading B's before-value with sid() read A's id out of B's window and
    reported a swap that never happened. See owner_update().
    """
    was_a, was_b = a.owned(), b.owned()
    if not was_a or not was_b:
        return record("7. reverse order does not swap owners", SKIP,
                      "one visitor owned no session to return to",
                      "A=%r B=%r" % (was_a[:12], was_b[:12]))
    b.front_door(url)
    a.front_door(url)
    now_a, now_b = a.sid(), b.sid()
    swapped = now_a == was_b or now_b == was_a
    kept = now_a == was_a and now_b == was_b
    shots, errs = ownership_photos((("A", a), ("B", b)), evidence, "reversed")
    return record("7. reverse order does not swap owners",
                  PASS if kept and not swapped else FAIL,
                  "each browser returns to the sid it held",
                  "A %s->%s, B %s->%s%s%s"
                  % (was_a[:12], now_a[:12], was_b[:12], now_b[:12],
                     ", SWAPPED" if swapped else "",
                     "; NOT photographed: " + "; ".join(errs) if errs else ""),
                  artefact=" and ".join(shots) or None,
                  question=ADDRESS_BAR_QUESTION if shots else "")


ADDRESS_BAR_QUESTION = (
    "in each photograph, does the address bar show the id this row reported "
    "for that browser? The row read it from location.pathname; the photograph "
    "reads the same fact by a different mechanism, which is what was missing "
    "when a one-character bug in that expression survived a green self-test.")


def ownership_photos(pair, evidence_dir, stem):
    """Photograph each visitor's whole screen, address bar included.

    WHY THESE ROWS AND NOT ALL OF THEM. The standing rule is to look at the
    screen, and the ownership rows are the ones that never did: every detector
    in them is a DOM query -- a pathname, a counter, some document text --
    so nine of them passed today without a single pixel being examined. Three
    earlier and worse runs left a photograph each and the good one left none,
    because the only camera in the rig sat behind an early return for "no live
    media track". The better the run went, the less there was to look at.

    The two rows photographed are the two that assert WHO OWNS WHAT, which is
    also where both of today's detector faults landed -- one returned an empty
    identifier while the address bar held the truth, the other read the right
    address bar for the wrong browser. A picture aimed at the address bar is
    therefore worth more here than one aimed at browser chrome, and it is what
    the cheap text extractors read best.

    Not every row, deliberately: a directory of files nobody opens is
    indistinguishable from no evidence, and print_reading_list() only puts an
    artefact in front of a person when its row did NOT pass cleanly. These
    files are for the round that goes wrong.

    WHAT A PHOTOGRAPH HERE STILL DOES NOT SETTLE, and it is the harder half:
    it shows that A DESKTOP appeared, not that THE RIGHT desktop did. Two
    slots running the same image look identical on screen. The address bar is
    the part of the picture that carries identity, which is why it is what the
    question asks about, and telling one desktop's CONTENT from another's
    needs something the sessions do not currently have -- named as an open
    question rather than answered here.

    Returns (paths, errors); a failed photograph is reported, never dropped.
    """
    paths, errs = [], []
    for tag, v in pair:
        p = os.path.join(evidence_dir, "%s-%s.png" % (stem, tag))
        err = v.photograph(p)
        if err:
            errs.append("%s: %s" % (tag, err))
        else:
            paths.append(p)
    return paths, errs


def arm_two_visitors(a, b, url, evidence):
    """Two browsers are two people, and neither is the other.

    Detector: the two session ids differ, AND B's whole document does not
    contain A's id anywhere. The second half is the leak check: two distinct
    ids prove the demux issued two, not that one page never mentions the other.
    """
    n = "5. two browsers are two visitors"
    # Ownership, not the address bar: this row is about who holds what.
    sa, sb = a.owned(), b.owned()
    if not sa or not sb:
        return record(n, GATED, "one visitor has no sid",
                      "A=%r B=%r -- one of them was gated rather than served"
                      % (sa[:12], sb[:12]))
    if sa == sb:
        return record(n, FAIL, "sid(A) != sid(B)",
                      "both browsers were given %s" % sa[:12])
    leaked = sa in b.html() or sb in a.html()
    shots, errs = ownership_photos((("A", a), ("B", b)), evidence, "owners")
    return record(n, FAIL if leaked else PASS,
                  "sids differ AND neither document names the other's",
                  "A=%s B=%s%s%s"
                  % (sa[:12], sb[:12], ", LEAKED" if leaked else "",
                     "; NOT photographed: " + "; ".join(errs) if errs else ""),
                  artefact=" and ".join(shots) or None,
                  question=ADDRESS_BAR_QUESTION if shots else "")


def arm_share_without_key(a, b, url):
    """Pasting someone's session address is expected to fail. Run it anyway.

    Detector: B does NOT reach a streaming picture at A's address, and A keeps
    streaming. Two separate assertions, because a product that refuses B by
    killing A's session has refused correctly and broken the thing that
    mattered.
    """
    sa = a.owned()
    if not sa:
        return record("6. a pasted session link is refused", SKIP,
                      "A owns no session to paste", "")
    from urllib.parse import urljoin
    b.goto(urljoin(url, "/s/%s/" % sa), settle=5.0)
    kind = classify(b.title(), b.html())
    # b.sid() ON PURPOSE: this half asks what B's window is showing, which is
    # the address-bar question. B's OWNERSHIP is deliberately not touched by
    # this navigation -- goto() cannot move it -- which is what lets row 7
    # still know whose session B holds after B has been parked here.
    b_sid = b.sid()
    stole = kind == "desktop" and b_sid == sa
    record("6. a pasted session link is refused",
           FAIL if stole else PASS,
           "B's page kind, and whether B holds A's sid",
           "B got %s (sid %r); expected refusal or gate" % (kind, b_sid[:12]))
    mov, pair = a.moving(5.0)
    if mov is None:
        return record("6b. A survives B's attempt", UNDEC,
                      "A's counter gone, or A's debugger died",
                      "chunks %s -- a None is no counter to read, not no video"
                      % (pair,))
    return record("6b. A survives B's attempt", PASS if mov else FAIL,
                  "A's chunk delta>0 after bringToFront",
                  "chunks %s->%s" % pair)


def arm_second_interaction(a, url):
    """Clicking the card twice, and going back, must not mint a second session.

    Detector: the sid is unchanged across a second Connect and a history back.
    A second interaction is where a gate that is really a mint shows itself.
    """
    before = a.sid()
    if not before:
        return record("8. a second interaction does not mint", SKIP,
                      "no sid", "")
    a.click_gate()
    a.eval("history.back()")
    time.sleep(3.0)
    a.click_gate()
    after = a.sid()
    if not after:
        return record("8. a second interaction does not mint", GATED,
                      "sid absent after going back",
                      "landed on %s" % classify(a.title(), a.html()))
    return record("8. a second interaction does not mint",
                  PASS if after == before else FAIL,
                  "sid unchanged across click+back+click",
                  "%s -> %s" % (before[:12], after[:12]))


def arm_capture_indicators(a, evidence_dir, display, expect_media, url_origin):
    """Microphone and webcam: what the browser's own chrome shows.

    THIS ARM IS DELIBERATELY SPLIT, because one half of it cannot be automated
    and pretending otherwise is how a human row silently stops being run.

    Automated, and it is the safety direction: how many live audio and video
    input tracks the PAGE holds. With the feature off, a live input track is a
    finding on its own -- the server is supposed to refuse. With it on, at
    least one live track is the precondition for any indicator to be correct.

    NOT automated: the indicator in the omnibox. It is not in the DOM and it is
    not in a CDP screenshot, which photographs the page and not the browser. It
    is on the framebuffer, so this arm captures the WHOLE root window and hands
    the file to a person. An automated claim about it would be a claim about a
    region of pixels somebody calibrated once, and Chrome moves it.

    One more trap, and it is the reason this arm insists on its own browser:
    the shipped Browser passes --use-fake-ui-for-media-stream, which accepts
    the permission prompt without showing it. An arm about the chrome must not
    run in a browser configured never to ask.

    WHAT THE FIRST REAL RUN GOT WRONG, because the photograph it took says so.
    Both rows below came back UNDECIDED against a tab whose title was the
    capacity refusal, with the permission prompt still on screen, unanswered.
    Three separate faults, and none of them is "the answer was unclear":

      * The tab had never held a desktop. There was nothing to capture and
        nothing an indicator could be about, so a granted permission would
        still have measured nothing. Hence the precondition below, which
        REFUSES rather than reporting a soft outcome -- and which makes the
        ordering constraint in main() enforced rather than remembered.
      * Nobody answered the prompt, which is why getUserMedia never settled.
        A pending prompt is not a lit indicator: the indicator lights when
        capture is ACTIVE, so photographing the question photographs a state
        upstream of the one the row exists to see. This arm now ANSWERS the
        prompt, at the browser target, and only then looks.
      * The prompt said "microphones (0)", and that was read as "this browser
        has no microphone, so the row can never run". It is not: Chrome
        withholds device labels and counts until a capture permission exists.
        Measured 2026-09-23 with --use-fake-device-for-media-stream and no
        real hardware -- before the grant, enumerateDevices() returned one
        unlabelled audioinput; after it, three labelled ones, and
        getUserMedia({audio:true}) returned a LIVE audio track. The mic half
        is askable, and the count in a pending prompt is not evidence about
        the apparatus.

    Browser.grantPermissions REPLACES the granted set for an origin rather
    than adding to it. Granting video and then audio leaves video REVOKED, and
    the video half then fails NotAllowedError -- measured here while writing
    this, in exactly that shape. So there is one call, with both.
    """
    kind = classify(a.title(), a.html())
    if kind != "desktop":
        for n in ("9a. the page may capture video", "9b. the page may capture audio",
                  "10. the indicator in the browser's chrome"):
            record(n, UNASKABLE, "this tab never reached a desktop",
                   "the tab is on %r (%s); there is nothing capturing and "
                   "nothing to photograph, so the question was never put"
                   % (a.title(), kind))
        return

    granted = a.grant_media(url_origin)
    if not granted:
        record("9a. the page may capture video", UNASKABLE,
               "Browser.grantPermissions did not answer",
               "the prompt would still be pending, and a pending prompt "
               "measures nothing")
        record("9b. the page may capture audio", UNASKABLE,
               "Browser.grantPermissions did not answer", "")
        record("10. the indicator in the browser's chrome", UNASKABLE,
               "no permission, so nothing can be capturing", "")
        return

    # Devices are enumerated AFTER the grant, because before it the list is
    # censored and a censored list is not a statement about the hardware.
    devs = a.eval(
        "(async()=>{try{const d=await navigator.mediaDevices.enumerateDevices();"
        "return d.map(x=>x.kind).join(',')}catch(e){return 'error:'+e.name}})()",
        timeout=30) or ""

    live_any = False
    for label, want, cons in (
            ("9a. the page may capture video", "videoinput", "{video:true}"),
            ("9b. the page may capture audio", "audioinput", "{audio:true}")):
        if want not in devs:
            record(label, UNASKABLE, "no %s device in this browser" % want,
                   "enumerateDevices() after the grant reported %r, so this "
                   "half can never light whatever the product does -- the row "
                   "was not asked, and that is not an undecided answer" % devs)
            continue
        # TWO PHASES, and the reason is that one phase could not tell two
        # things apart. browser.eval passes awaitPromise, so an unsettled
        # getUserMedia simply never gets a CDP reply and the call times out
        # returning None -- the same None a dead debugger returns. Both rounds
        # so far reported "never settled" and NEITHER of them knows which of
        # those happened, which is an unanswered row that cannot say what to
        # fix. moving() already refuses to conflate a missing counter with an
        # absent video; this is the same rule applied to the same kind of None.
        #
        # So: fire the call, park its outcome on the page, and then POLL with a
        # plain synchronous read. A poll that keeps answering "pending" is a
        # measurement of a hung getUserMedia -- the page is alive and the call
        # has not come back. A poll that stops answering at all is the rig
        # going blind, and it is a different sentence with a different repair.
        started = a.eval(
            "(()=>{window.__hdw4s_cap='pending';"
            "navigator.mediaDevices.getUserMedia(%s).then(s=>{"
            "window.__hdw4s_cap='tracks:'+(s.getTracks()"
            ".filter(t=>t.readyState==='live').map(t=>t.kind).sort()"
            ".join(',')||'none')})"
            ".catch(e=>{window.__hdw4s_cap='refused:'+e.name});"
            "return 'started'})()" % cons, timeout=20)
        if started != "started":
            record(label, UNDEC, "the capture call could not even be started",
                   "the page returned %r rather than 'started', so nothing was "
                   "asked of getUserMedia and this says nothing about the "
                   "product" % (started,))
            continue
        deadline, tracks, polls, blind = time.time() + 45, None, 0, False
        while time.time() < deadline:
            time.sleep(1.5)
            polls += 1
            v = a.eval("window.__hdw4s_cap", timeout=15)
            if v is None:
                blind = True
                break
            blind = False
            if v != "pending":
                tracks = v[len("tracks:"):] if v.startswith("tracks:") else v
                break
        if blind:
            record(label, UNDEC, "the page stopped answering mid-measure",
                   "getUserMedia was started and the poll went silent after "
                   "%d read(s); that is this rig losing the page, NOT the "
                   "product refusing" % polls)
            continue
        if tracks is None:
            record(label, UNDEC, "getUserMedia still PENDING after 45s",
                   "measured, not inferred: the page answered %d poll(s) and "
                   "said 'pending' every time, so the page is alive and the "
                   "call has not come back. The permission was granted, so "
                   "this is not a prompt waiting for a click -- it is a "
                   "getUserMedia that does not settle, and it is apparatus to "
                   "fix rather than a product verdict" % polls)
            continue
        live = not str(tracks).startswith("refused") and tracks != "none"
        live_any = live_any or live
        if expect_media:
            record(label, PASS if live else FAIL,
                   "live MediaStreamTrack kinds",
                   "tracks=%r (deployed with capture enabled)" % (tracks,))
        else:
            record(label, PASS if not live else FAIL,
                   "live MediaStreamTrack kinds",
                   "tracks=%r (deployed with capture disabled; a live track "
                   "here is the server failing to refuse)" % (tracks,))

    # The photograph is of an indicator, and an indicator is about capture that
    # is HAPPENING. With nothing live there is no indicator state to read, and
    # a picture of its absence proves nothing in either direction -- so the row
    # says it could not be asked instead of handing a person a meaningless file.
    if not live_any:
        record("10. the indicator in the browser's chrome", UNASKABLE,
               "no live track, so no capture for an indicator to be about",
               "nothing was photographed")
        return
    shot = os.path.join(evidence_dir, "chrome-indicators.png")
    err = root_screenshot(display, shot)
    if err:
        return record("10. the indicator in the browser's chrome", UNASKABLE,
                      "the framebuffer could not be photographed",
                      "NOT captured: %s" % err)
    record("10. the indicator in the browser's chrome", UNDEC,
           "root-window photograph, read by a person",
           "captured while a track was live", artefact=shot,
           question="is the capture indicator LIT in the omnibox, and is the "
                    "tab behind the dialog a desktop rather than a card? Read "
                    "the address bar and the tab title too -- they answer "
                    "other rows.")


# --------------------------------------------------------------------------
# Pool exhaustion, measured rather than assumed
# --------------------------------------------------------------------------

def exhaust(url, display_base, base_port, declared, limit=8):
    """Fill the pool with throwaway browsers, and REPORT what it actually held.

    The slot count is HDW4S_EPHEMERAL_SLOTS, set when the slots were minted at
    boot -- not something a test run can turn down. So this does not assume the
    deployment matches --slots: it opens fresh profiles, each its own cookie
    jar and so its own visitor, until the front door refuses, and then compares
    what it counted against what was declared. A mismatch is a finding about
    the deployment, and it is reported instead of being smoothed over, because
    every later arm that says "exhausted" is resting on this number.

    It also stops on ANY page that is not a served desktop, and says which,
    rather than only on the capacity page. A 502 from a dead desktop used to be
    kept as a filler and the loop carried on, so a broken front door would have
    been counted as a slot -- and the one row that cares about the difference
    between a refusal and a crash would never have been shown it.

    Returns (held_open, stopped_on, browsers_to_close), where stopped_on is the
    page kind that ended the loop, or None if the front door was still serving
    when the limit ran out. The LAST visitor it opens is the fresh visitor row
    4a is about: its cookie jar is its own, which is the whole difference
    between it and a second tab.
    """
    held, kept = 0, []
    for i in range(limit):
        v = Visitor(base_port + 40 + i, "fill%d" % i, display_base + i)
        try:
            v.start()
            kind, _ = v.front_door(url)
        except Precondition:
            v.stop()
            break
        if kind not in ("desktop", "gate"):
            v.stop()
            return held, kind, kept
        kept.append(v)
        held += 1
    return held, None, kept


# --------------------------------------------------------------------------
# Self-test: every detector, against a positive and a negative
# --------------------------------------------------------------------------

DESKTOP_HTML = '<html><body><div id="hdw4s-gate" hidden></div><canvas></canvas>'


def product_pages():
    """The gate and refusal cards AS THE PRODUCT BUILDS THEM.

    Not fixtures typed out here. A detector checked against a copy of the page
    that somebody transcribed is a detector checked against the transcription:
    it stays green forever while the real page drifts away from it, which is
    the whole failure this file's classify() is exposed to. So the self-test
    calls hdw4s-demux's own gate_page() and page(), and if it cannot reach
    them it says so rather than quietly falling back to a guess.

    Returns (gate_html, refused_html) or raises.
    """
    import importlib.machinery
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "..", "hdw4s-demux")
    spec = importlib.util.spec_from_loader(
        "hdw4s_demux", importlib.machinery.SourceFileLoader("hdw4s_demux",
                                                            os.path.normpath(path)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return (m.gate_page("Start a desktop", "detail", "Start").decode(),
            m.page(CAPACITY_TITLE, "detail").decode(),
            m.page("That desktop closed the connection", "detail").decode())


# A document with exactly what hdw4s-gate-index requires of upstream's: one
# module <script> and a </body> to append the overlay before. Everything else
# upstream ships is irrelevant to the three probes, and standing in for it with
# a whole client would make this need a product to test the instrument.
STUB_UPSTREAM = ('<!doctype html><html><head><title>stub</title></head><body>'
                 '<div id="status-display"></div>'
                 '<script type="module" src="./core.js"></script>'
                 '</body></html>')

# The upstream client, reduced to the ONE thing this rig reads from it. The
# real client publishes window.videoChunksReceived and advances it; so does
# this. That the real one still uses that NAME is the part this cannot settle
# -- see browsertest()'s closing note.
STUB_CORE = ("window.videoChunksReceived = 0;"
             "setInterval(function(){ window.videoChunksReceived++; }, 100);")


def browsertest(display_num=95, port=9495, http_port=8795):
    """The three page-side expressions, in the language they actually run in.

    THIS IS THE TIER THAT WAS MISSING, and its absence is why a one-character
    bug in the session-id expression survived a green self-test: that test
    exercised a Python twin, and nothing ever asserted the two agreed. Here
    there is no twin. Real Chrome, on a framebuffer, is handed the REAL gate
    page -- built by running hdw4s-gate-index, not transcribed -- and each
    expression is read at a state whose answer is already known, both ways.

    The page is driven into its states by the product's own controls: the
    default takeover arm shows the card, "?gate=off" boots without it, and the
    Connect button is pressed the way the round presses it. Nothing about the
    gate's behaviour is simulated; the desktop behind it is.

    No product, no remote machine, no network beyond loopback.
    """
    import functools
    import http.server
    import socketserver
    import tempfile
    import threading

    bad = 0

    def expect(what, got, want):
        nonlocal bad
        ok = got == want
        bad += 0 if ok else 1
        print("  %-4s %-52s got %r want %r"
              % ("ok" if ok else "RED", what, got, want))

    here = os.path.dirname(os.path.abspath(__file__))
    gen = os.path.normpath(os.path.join(here, "..", "..", "hdw4s-gate-index"))
    if not os.path.exists(gen):
        print("  RED  hdw4s-gate-index is not beside this checkout, so the "
              "page these\n       probes read would have to be transcribed. "
              "Refusing.")
        return 1
    tmp = tempfile.mkdtemp(prefix="hdw4s-browsertest-")
    up = os.path.join(tmp, "upstream.html")
    with open(up, "w") as f:
        f.write(STUB_UPSTREAM)
    with open(os.path.join(tmp, "core.js"), "w") as f:
        f.write(STUB_CORE)
    r = subprocess.run([sys.executable, gen, up, os.path.join(tmp, "index.html")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  RED  hdw4s-gate-index refused to build the page: %s"
              % (r.stderr or r.stdout).strip()[:200])
        return 1
    print("  ..   page built by hdw4s-gate-index itself, not transcribed")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        # Silent, because the request log interleaves with the self-test's own
        # lines and this tier's output is read by a person deciding whether to
        # believe a round.
        def log_message(self, *a):
            pass

    class Server(socketserver.TCPServer):
        # A CLASS attribute, not one set on the instance afterwards: the socket
        # is bound in __init__, so an assignment after construction arrives too
        # late and the second run of the day dies on a TIME_WAIT from the
        # first. Found by running this tier twice in three minutes.
        allow_reuse_address = True

    handler = functools.partial(Quiet, directory=tmp)
    # Two runs in quick succession can still collide: SO_REUSEADDR does not
    # help while a browser from a run that was cut short is holding the port
    # open. A few seconds of patience beats making the caller guess a port,
    # and a hard refusal after that beats a silent skip.
    srv = None
    for _ in range(10):
        try:
            srv = Server(("127.0.0.1", http_port), handler)
            break
        except OSError:
            time.sleep(1.0)
    if srv is None:
        print("  RED  127.0.0.1:%d would not bind, so the probes were not "
              "read. Something\n       from an earlier run is still holding "
              "it." % http_port)
        return 1
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/index.html" % http_port

    x = isolation.XServer(display_num)
    b = None
    try:
        if not x.up(timeout=20):
            print("  RED  no framebuffer on :%d -- the probes cannot be read "
                  "in the language\n       they run in, so nothing below is "
                  "known. This is not a pass." % display_num)
            return 1
        b = browser.Browser(port, "probes", display=":%d" % display_num)
        b.start()
        if not b._connect(60):
            print("  RED  the debugger never attached; the probes were not read")
            return 1
        for m in ("Page.enable", "Runtime.enable"):
            b.call(m)

        def go(url, settle=2.5):
            b.call("Page.navigate", {"url": url}, timeout=60)
            time.sleep(settle)

        # KNOWN POSITIVE: a fresh arrival on the takeover arm shows the card.
        go(base)
        gf = b.eval(GATE_FACTS)
        expect("GATE_FACTS finds the card the product drew",
               isinstance(gf, dict) and gf.get("present"), True)
        expect("the card is ON SCREEN when the product is asking", shown(gf), True)
        expect("and it does not claim to be hidden", contradicts(gf), False)
        expect("GO_FACTS finds Connect, rendered",
               shown(b.eval(GO_FACTS)), True)
        # The counter does not exist yet: the module is deferred behind the
        # gate, so this is a real page in a real state with no counter on it.
        expect("CHUNKS says ABSENT before the client loads",
               b.eval(CHUNKS), None)

        # The click, and the page's own word for what happened.
        expect("CLICK_GO reports pressing the button", b.eval(CLICK_GO),
               "clicked")
        time.sleep(2.5)

        # KNOWN NEGATIVE: the card is down and the client has loaded.
        gf = b.eval(GATE_FACTS)
        expect("the card is OFF SCREEN once it has been dismissed",
               shown(gf), False)
        expect("Connect is no longer rendered", shown(b.eval(GO_FACTS)), False)
        expect("CLICK_GO refuses a button nobody can press", b.eval(CLICK_GO),
               "not-rendered")
        n1 = b.eval(CHUNKS)
        expect("CHUNKS reads a NUMBER once a client publishes one",
               isinstance(n1, int), True)
        time.sleep(1.0)
        expect("and the DELTA is what moves, not the level",
               (b.eval(CHUNKS) or 0) > (n1 or 0), True)

        # KNOWN NEGATIVE, the other kind: nothing of ours on the page at all.
        go("about:blank", settle=1.0)
        expect("GATE_FACTS on a page with no card", shown(b.eval(GATE_FACTS)),
               None)
        expect("absent is not the same answer as down",
               shown(b.eval(GATE_FACTS)) is False, False)
        expect("CLICK_GO says so rather than throwing", b.eval(CLICK_GO),
               "absent")
        expect("CHUNKS on a page with no client", b.eval(CHUNKS), None)

        # The product's own "never ask" arm: a real page that boots straight
        # through, which must read as down and NOT as absent.
        go(base + "?gate=off")
        expect("the 'off' arm leaves the card down, not missing",
               shown(b.eval(GATE_FACTS)), False)

        # THE REGRESSION THE PRODUCT'S OWN STYLESHEET EXISTS TO PREVENT, made
        # to happen rather than argued about: `hidden` set, an author display
        # rule winning, the card still covering the desktop. Measured
        # 2026-09-23 -- 1279x656 on screen, 1445 colours in the screenshot --
        # while `!e.hidden`, the expression this replaced, said the gate was
        # DOWN. That reading turns "the product is asking" into FAIL.
        go(base)
        b.eval("(()=>{var s=document.createElement('style');"
               "s.textContent='#hdw4s-gate[hidden]{display:flex !important}';"
               "document.body.appendChild(s);"
               "document.getElementById('hdw4s-gate').hidden=true;return 1})()")
        time.sleep(0.5)
        gf = b.eval(GATE_FACTS)
        expect("a card painted over the desktop reads as UP", shown(gf), True)
        expect("and the contradiction is reported", contradicts(gf), True)
        expect("the attribute alone would have said DOWN",
               bool(gf.get("hidden")), True)
    finally:
        if b is not None:
            b.stop()
        try:
            x.stop()
        except Exception:
            pass
        srv.shutdown()
        srv.server_close()

    # WHAT THIS STILL DOES NOT SETTLE, stated because a green tier that is
    # quiet about its stand-ins is how the last one stayed green: the counter's
    # NAME. window.videoChunksReceived is published by the upstream client and
    # by nothing in this repository -- hdw4s-gate-index reads it too, for its
    # stall backstop -- and the client here is a stub that publishes it because
    # this file told it to. The experiment that settles it is a round against a
    # real desktop: if CHUNKS reads None there, the name has moved, and the
    # arms now say UNDECIDED instead of FAIL while somebody looks.
    print("\n  %s -- %d page-side probe(s) disagreed with a known answer"
          % ("BROWSER PROBES RED" if bad else "BROWSER PROBES PROVEN", bad))
    return 1 if bad else 0


def guardtest():
    """Point the occupancy guard at known-bad inputs and watch it refuse.

    A guard that has never been observed refusing is not known to refuse, and
    on this project six checks in one day had a red arm that was WRITTEN and
    never RUN. So this ships beside the guard rather than living in whatever
    transcript it was first demonstrated in.

    It ends by DEMONSTRATING the hole rather than describing it: the real
    user's hostname paired with the wrong container sails straight through.
    That row is supposed to print "ALLOWED". If it ever prints a refusal,
    somebody has closed the hole and this text is out of date.
    """
    IDLE, BUSY = "echo 0", "echo 2"
    cases = [
        ("L1 no allowlist at all", "https://pool.x/", None, IDLE, None),
        ("L1 host NOT on allowlist", "https://other.x/", ["pool.x=cA"], IDLE, None),
        ("L1 malformed entry", "https://pool.x/", ["pool.x"], IDLE, None),
        ("L1 entry names no container", "https://pool.x/", ["pool.x="], IDLE, None),
        ("L2 container is BUSY", "https://pool.x/", ["pool.x=cA"], BUSY, None),
        ("L2 no probe given", "https://pool.x/", ["pool.x=cA"], "", None),
        ("L2 probe exits non-zero", "https://pool.x/", ["pool.x=cA"],
         "echo 0; exit 1", None),
        ("L2 probe silent, exit 0", "https://pool.x/", ["pool.x=cA"], "true", None),
        ("L2 probe non-numeric", "https://pool.x/", ["pool.x=cA"],
         "echo unreachable", None),
        ("a permitted, idle target", "https://pool.x/", ["pool.x=cA"], IDLE, "allow"),
        ("hostnames are case-folded", "https://POOL.X/", ["pool.x=cA"], IDLE, "allow"),
    ]
    bad = 0
    for label, url, allow, probe, want in cases:
        try:
            c, n, _ = guard_unoccupied(url, allow, probe)
            got, detail = "allow", "container=%s attached=%s" % (c, n)
        except Occupied as e:
            got, detail = None, str(e).splitlines()[0]
        ok = got == want
        bad += 0 if ok else 1
        print("  %-4s %-30s -> %-6s %s"
              % ("ok" if ok else "RED", label, got or "REFUSE", detail[:72]))
    # THE OVERRIDE, and the thing that must stay true about it: it waives the
    # occupancy measurement and NEVER the allowlist. If the first of these ever
    # prints "allow", somebody has widened the override into a way of skipping
    # a person's own assertion, and the asymmetry documented on
    # guard_unoccupied() has been lost.
    ov = [
        ("override does NOT waive the allowlist", "https://other.x/",
         ["pool.x=cA"], BUSY, None),
        ("override does NOT waive a missing list", "https://pool.x/",
         None, BUSY, None),
        ("override DOES waive a busy container", "https://pool.x/",
         ["pool.x=cA"], BUSY, "allow"),
        ("override DOES waive an unusable probe", "https://pool.x/",
         ["pool.x=cA"], "exit 1", "allow"),
    ]
    for label, url, allow, probe, want in ov:
        try:
            c, n, _ = guard_unoccupied(url, allow, probe, asked=True)
            got, detail = "allow", "container=%s attached=%s" % (c, n)
        except Occupied as e:
            got, detail = None, str(e).splitlines()[0]
        ok = got == want
        bad += 0 if ok else 1
        print("  %-4s %-30s -> %-6s %s"
              % ("ok" if ok else "RED", label, got or "REFUSE", detail[:72]))

    print("\n  The hole, demonstrated rather than claimed:")
    try:
        c, n, _ = guard_unoccupied("https://a-real-persons-desktop.example/",
                                   ["a-real-persons-desktop.example=an-idle-dev-box"],
                                   IDLE)
        print("    a real desktop's hostname + the WRONG container -> ALLOWED "
              "(container=%s, attached=%s)" % (c, n))
        print("    The guard passed. Layer 2 cannot detect a wrong layer 1.")
    except Occupied:
        print("    RED: this used to be allowed. If the mapping is now DERIVED "
              "rather than declared, delete this row and the note above it.")
        bad += 1
    print("\n  %s -- %d case(s) behaved wrongly"
          % ("GUARD RED" if bad else "GUARD PROVEN", bad))
    return 1 if bad else 0


def selftest():
    """Run the detectors where the answer is already known, both ways.

    A detector that has only ever been seen agreeing with the product is
    indistinguishable from one that cannot disagree with it, so each case below
    has a matching case that must come out the other way. If this ever prints
    all-green after someone restyles the card, it is this file that is wrong.
    """
    bad = 0
    try:
        GATE_HTML, REFUSED_HTML, BROKEN_HTML = product_pages()
        print("  ..   cards taken from hdw4s-demux itself, not transcribed")
    except Exception as e:
        print("  RED  could not build the cards from hdw4s-demux: %s: %s"
              % (type(e).__name__, e))
        print("       Refusing to self-test against a transcription. Run this "
              "from a checkout that has hdw4s-demux beside it.")
        return 1

    def expect(what, got, want):
        nonlocal bad
        ok = got == want
        bad += 0 if ok else 1
        print("  %-4s %-52s got %r want %r"
              % ("ok" if ok else "RED", what, got, want))

    expect("classify: the gated client", classify("", DESKTOP_HTML), "desktop")
    expect("classify: a card WITH an action link",
           classify("", GATE_HTML), "gate")
    expect("classify: the capacity refusal (503)",
           classify(CAPACITY_TITLE, REFUSED_HTML), "refused")
    # The negative that this file got wrong first time round. The 502 a dead
    # desktop produces is the SAME card with no link, so an arm that accepts
    # any linkless card as "correctly refused" scores a crash as a pass.
    expect("classify: a DEAD desktop (502) is not a refusal",
           classify("That desktop closed the connection", BROKEN_HTML),
           "broken")
    expect("capacity and a crash are not the same verdict",
           classify(CAPACITY_TITLE, REFUSED_HTML)
           != classify("That desktop closed the connection", BROKEN_HTML),
           True)
    # And the constant that separates them must still be the product's wording.
    expect("the product still says %r" % CAPACITY_TITLE,
           CAPACITY_TITLE in REFUSED_HTML, True)
    expect("classify: something else entirely",
           classify("", "<html><body>hello"), "unknown")
    expect("classify: nothing came back", classify("", None), "unreachable")
    # The negative that matters: gate and refusal must not collapse together.
    expect("gate and refusal are not the same verdict",
           classify("", GATE_HTML) != classify("", REFUSED_HTML), True)

    # These are location.pathname values, because location.pathname is the
    # only thing the page is now asked for. Every one of them is a string a
    # browser on this product really reports, and the extraction they feed is
    # the SAME function the run uses -- not a twin of it. See PATHNAME.
    expect("sid: a session path", sid_of("/s/abc123/"), "abc123")
    expect("sid: a session path with a page under it",
           sid_of("/s/abc123/index.html"), "abc123")
    expect("sid: the front door", sid_of("/"), "")
    expect("sid: a lookalike path", sid_of("/session/abc/"), "")
    # The trailing slash is what the demux redirects TO, so an id without one
    # is a state the browser passes through and never rests in. Reporting it
    # as "no session" would be a lie about a real address, but reporting an id
    # from it would accept a shape the product never serves -- and the arms
    # compare ids to each other, so consistency is what matters. It is pinned
    # here so that a change to it is deliberate rather than noticed in a run.
    expect("sid: an id with no trailing slash", sid_of("/s/abc123"), "")
    expect("sid: nothing at all", sid_of(""), "")
    # The negative that the old JS extraction would have failed: a real id must
    # not come back empty. This is the assertion that was missing, and its
    # absence cost four rows of the first real run.
    expect("sid: a real id is not empty", sid_of("/s/abc123/") != "", True)

    # shown(), which is the whole of what GATE_FACTS/GO_FACTS mean. The facts
    # below are not invented: every one is a dict a real Chrome returned from
    # GATE_FACTS on the real gate page, recorded 2026-09-23 by the measurement
    # in browsertest(), which re-derives them rather than trusting this list.
    up = {"present": True, "hidden": False, "display": "flex",
          "visibility": "visible", "w": 1279, "h": 656}
    down = {"present": True, "hidden": True, "display": "none",
            "visibility": "visible", "w": 0, "h": 0}
    painted_but_hidden = {"present": True, "hidden": True, "display": "flex",
                          "visibility": "visible", "w": 1279, "h": 656}
    expect("shown: the card is up", shown(up), True)
    expect("shown: the card is down", shown(down), False)
    expect("shown: there is no card at all", shown({"present": False}), None)
    expect("shown: the probe did not answer", shown(None), None)
    expect("shown: absent and down are NOT the same answer",
           shown({"present": False}) is shown(down), False)
    expect("shown: visibility:hidden is not on screen",
           shown(dict(up, visibility="hidden")), False)
    expect("shown: a zero-height box is not on screen",
           shown(dict(up, h=0)), False)
    # The measured regression: `hidden` set, author display rule winning, card
    # covering the desktop. An attribute-reading detector called this DOWN and
    # the arm would have reported FAIL on a product that was merely asking.
    expect("shown: painted while claiming hidden is UP",
           shown(painted_but_hidden), True)
    expect("contradicts: and it is called out", contradicts(painted_but_hidden),
           True)
    expect("contradicts: a card that is honestly down is not",
           contradicts(down), False)

    # ----------------------------------------------------------------
    # THE TWO NOTIONS OF IDENTIFIER. Each of these is a line from the
    # 2026-09-23 round, and the middle one is the failure itself: B owned
    # a77ed5b6a8c3 and was parked at A's address after a refused paste, so
    # the address bar read 12c6ab05201f and row 7 called it a swap.
    # ----------------------------------------------------------------
    expect("owned: a served front-door arrival adopts the session",
           owner_update("desktop", "AAA", ""), "AAA")
    expect("owned: the card at the front door adopts nothing yet",
           owner_update("gate", "", "AAA"), "AAA")
    expect("owned: a refused paste of another's link moves NOTHING",
           owner_update("broken", "12c6ab05201f", "a77ed5b6a8c3"),
           "a77ed5b6a8c3")
    expect("owned: and the address bar would have said otherwise",
           owner_update("broken", "12c6ab05201f", "a77ed5b6a8c3")
           != "12c6ab05201f", True)
    expect("owned: a capacity refusal moves nothing",
           owner_update("refused", "", "BBB"), "BBB")
    expect("owned: an unknown page moves nothing",
           owner_update("unknown", "AAA", "BBB"), "BBB")

    # Row 4a: what a FRESH visitor must be told, and the two answers that
    # look like a refusal and are not one.
    expect("fresh visitor: the capacity page is the pass",
           fresh_visitor_verdict("refused")[0], PASS)
    expect("fresh visitor: a DEAD desktop (502) is NOT a refusal",
           fresh_visitor_verdict("broken")[0], FAIL)
    expect("fresh visitor: being served means the pool was not full",
           fresh_visitor_verdict("desktop")[0], FAIL)

    # Row 4b: the row that used to assert the OPPOSITE of the arrival rule.
    # The last line is today's deployment, which the old row failed.
    expect("second tab: resuming tab 1's session is the pass",
           second_tab_verdict("desktop", "AAA", "AAA")[0], PASS)
    expect("second tab: a capacity refusal to the owner is a LOCK-OUT",
           second_tab_verdict("refused", "", "AAA")[0], FAIL)
    expect("second tab: minting a second session fails",
           second_tab_verdict("desktop", "ZZZ", "AAA")[0], FAIL)
    expect("second tab: the deployment the old row FAILED now passes",
           second_tab_verdict("desktop", "12c6ab05201f", "12c6ab05201f")[0],
           PASS)
    expect("second tab: and the old expectation and the new disagree",
           second_tab_verdict("refused", "", "AAA")[0]
           != second_tab_verdict("desktop", "AAA", "AAA")[0], True)

    print("\n  %s -- %d detector(s) disagreed with a known answer"
          % ("SELFTEST RED" if bad else "SELFTEST GREEN", bad))
    return 1 if bad else 0


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="The standing walkthrough, through the proxy hostname.")
    ap.add_argument("--url", help="the address a visitor types, e.g. "
                                  "https://desk.example/ -- NOT an internal port")
    ap.add_argument("--instance", default="",
                    help="passed to --server-probe as {instance}")
    ap.add_argument("--slots", type=int, default=0,
                    help="what HDW4S_EPHEMERAL_SLOTS was deployed as; this run "
                         "MEASURES the pool and tells you if it disagrees")
    ap.add_argument("--display-base", type=int, default=90,
                    help="first X display number; EACH browser gets its own "
                         "Xvfb, because two headful Chromes on one display "
                         "occlude each other and the one underneath "
                         "screenshots blank -- a convincing false negative")
    ap.add_argument("--base-port", type=int, default=9400,
                    help="first CDP debugging port; each browser takes one")
    ap.add_argument("--allow-host", action="append", metavar="HOST=CONTAINER",
                    help="REQUIRED, repeatable. A hostname this rig may open, "
                         "and the container that serves it. A hostname not "
                         "listed is refused. Every name on this estate "
                         "resolves to the same proxy, so the address "
                         "distinguishes nothing and this assertion is the only "
                         "thing that does.")
    ap.add_argument("--occupancy-probe", default="",
                    help="REQUIRED. A shell command printing the number of "
                         "clients attached to ANY session on the container "
                         "({container} is substituted), exiting non-zero when "
                         "it cannot tell. The run REFUSES TO START unless this "
                         "answers a number, and refuses unless it is zero.")
    ap.add_argument("--i-have-asked-and-may-proceed", action="store_true",
                    help="Waive the OCCUPANCY check only -- you asked the "
                         "occupant and they said yes. It does NOT waive the "
                         "hostname allowlist, and cannot: that list is your "
                         "own more careful earlier answer to a different "
                         "question. IF YOU NEED A HOST THAT IS NOT LISTED, ADD "
                         "IT TO THE LIST -- that is deliberate and reviewable, "
                         "and an override that a one-line addition would "
                         "replace should be that addition instead.")
    ap.add_argument("--server-probe", default="",
                    help="shell command printing the number of clients the "
                         "server sees attached; {instance} is substituted")
    ap.add_argument("--media", action="store_true",
                    help="the deployment has HDW4S_MICROPHONE/WEBCAM=yes")
    ap.add_argument("--evidence", default="",
                    help="directory for screenshots a person has to look at")
    ap.add_argument("--guardtest", action="store_true",
                    help="point the occupancy guard at known-bad inputs and "
                         "watch it refuse; touches no machine")
    ap.add_argument("--selftest", action="store_true",
                    help="exercise every detector against known answers and "
                         "exit; touches no machine and needs no product. "
                         "Includes the PAGE-SIDE probes, read in a real "
                         "browser on a framebuffer -- a detector written in "
                         "JavaScript and checked in Python is two detectors")
    ap.add_argument("--no-page-probes", action="store_true",
                    help="skip the browser tier of --selftest. Deliberate and "
                         "loud: the three page-side expressions are then "
                         "UNPROVEN for that run, which is the state a "
                         "one-character bug survived in once")
    args = ap.parse_args()

    if args.guardtest:
        return guardtest()
    if args.selftest:
        bad = selftest()
        if args.no_page_probes:
            print("\n  SKIPPED: the page-side probes were not read in a "
                  "browser. GATE_FACTS,\n           GO_FACTS, CLICK_GO and "
                  "CHUNKS are unproven for this run.")
        else:
            bad = browsertest() or bad
        return bad or guardtest()
    if not args.url:
        ap.error("--url is required (or --selftest)")

    evidence = args.evidence or os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "hdw4s-round-%d" % os.getpid())

    A = B = M = None
    fillers = []
    print("\nThe standing walkthrough, through %s" % args.url)
    print("Evidence for the human rows (once the guard permits): %s\n"
          % evidence)
    try:
        # FIRST, before the detectors and before anything is opened: is
        # anybody there? Nothing below this line is worth doing if the answer
        # is yes or unknown.
        from urllib.parse import urlsplit as _urlsplit
        container, n, why = guard_unoccupied(
            args.url, args.allow_host, args.occupancy_probe,
            asked=args.i_have_asked_and_may_proceed)
        if n is None:
            print("  ok        precondition: %s is on the allowlist, served by "
                  "%s -- %s"
                  % (_urlsplit(args.url).hostname, container, why))
        else:
            print("  ok        precondition: %s is on the allowlist, served by "
                  "%s, and nobody is attached there (%s)"
                  % (_urlsplit(args.url).hostname, container, why))
        print("  ..        NOTE: that mapping is a human assertion. This "
              "guard cannot tell you it is correct.")

        os.makedirs(evidence, exist_ok=True)
        need(guardtest() == 0, "the occupancy guard was seen refusing",
             "(known-bad inputs, this run)")
        need(selftest() == 0, "every detector agrees with a known answer",
             "(and disagrees where it should)")
        # The page-side probes, read where they run, before a single row is
        # scored. It costs one browser start and it is the only thing standing
        # between a mistyped expression and a round of invented defects. Its
        # display and ports are derived from this run's own bases so that it
        # cannot collide with the visitors below.
        need(browsertest(display_num=args.display_base + 30,
                         port=args.base_port + 90,
                         http_port=args.base_port + 300) == 0,
             "the page-side probes were read in a real browser",
             "(the gate, the button and the counter, both ways)")

        real, fake, differs, host = discriminator(args.url)
        need(real[0] is not None, "the address answers at all", "%s" % (real,))
        need(differs, "this hostname is not just a catch-all",
             "%s answered %s, a bogus Host answered %s" % (host, real, fake))

        A = Visitor(args.base_port, "A", args.display_base)
        A.start()
        floor, blank = colour_floor(A)
        need(floor > 0, "a colour floor was derived from this run's blank page",
             "blank=%d floor=%d" % (blank, floor))

        arm_first_visit(A, args.url, floor)
        arm_reload_resumes(A, args.url)

        # Two tabs while the pool still has room.
        arm_second_tab(A, args.url, args.server_probe, args.instance,
                       exhausted=False)

        B = Visitor(args.base_port + 1, "B", args.display_base + 1)
        B.start()
        B.front_door(args.url)
        arm_two_visitors(A, B, args.url, evidence)
        arm_share_without_key(A, B, args.url)
        arm_reverse_order(A, B, args.url, evidence)
        arm_second_interaction(A, args.url)

        # THE CAPTURE BROWSER NEEDS A FREE SLOT, so it runs here and not where
        # its row numbers suggest.
        #
        # The numbering and the ordering constraint used to disagree, and the
        # disagreement was silent. Rows 9 and 10 are numbered after row 4, row
        # 4 needs an EXHAUSTED pool, and exhaustion is deliberately last
        # because it leaves the machine with no free slot -- so the capture
        # browser arrived third in line for a pool that had none, got the
        # capacity refusal, and photographed a permission prompt in front of a
        # card. The row numbers are names, not a schedule.
        #
        # Stated as a need rather than a position: every row above needs a slot
        # and runs before exhaustion; row 4 needs the pool full and runs after
        # it. A comment alone would not hold this -- the arm itself now refuses
        # unless its tab is on a desktop, so getting the order wrong again
        # produces an UNASKABLE row naming the reason instead of two soft
        # verdicts about a state nobody reached.
        M = Visitor(args.base_port + 2, "M", args.display_base + 2,
                    real_media_ui=True)
        M.start()
        M.front_door(args.url)
        sp = _urlsplit(args.url)
        arm_capture_indicators(M, evidence, M.display, args.media,
                               "%s://%s" % (sp.scheme, sp.netloc))

        # Now fill the pool and do the two-tab row again. This is the row the
        # owner found by hand, and it is last because it leaves the machine
        # with no free slot.
        held, stopped_on, fillers = exhaust(args.url, args.display_base + 3,
                                            args.base_port, args.slots)
        # DERIVED, not the digit that used to be here. This arithmetic said
        # "+ 2" because A and B were the only browsers holding a session when
        # it was written; moving the capture browser ahead of the exhaustion
        # made it three, and a literal would have gone on reporting the pool as
        # misconfigured with nothing wrong with the pool. A constant in a
        # comparison is a claim, and this one is now read off the browsers that
        # exist rather than asserted.
        ours = len([v for v in (A, B, M) if v is not None])

        # ROW 0 IS RECORDED ON EVERY PATH, including the one where it agrees.
        # It used to print only when it disagreed, so the run where the pool
        # matched left NO ROW AT ALL -- and the standing comparison between
        # rounds is "the same rows with the same detectors", which an absent
        # row passes by not being there. A missing row is a shape change; it is
        # the loudest thing this rig can get wrong quietly, because the reader
        # is looking for failures and a row that is gone is neither.
        n0 = "0. the deployed pool is the one declared"
        if not args.slots:
            record(n0, SKIP, "no --slots to compare against",
                   "nothing declared the pool size, so this run measured it "
                   "(%d + %d) and had nothing to check it against"
                   % (held, ours))
        elif stopped_on is None:
            record(n0, UNDEC, "the front door never stopped serving",
                   "--slots said %d; this run served %d fillers on top of %d "
                   "held sessions and the front door was still serving when "
                   "the filler limit ran out, so %d is a floor, not a count"
                   % (args.slots, held, ours, held + ours))
        else:
            record(n0, PASS if held + ours == args.slots else FAIL,
                   "browsers served before the front door stopped serving",
                   "--slots said %d; %d fillers were served on top of %d "
                   "sessions already held, then the door answered %r"
                   % (args.slots, held, ours, stopped_on))

        # ROW 4a IS THE CAPACITY REFUSAL, and it is put to a FRESH VISITOR --
        # a browser with its own cookie jar, which is what "a new person" means
        # to this product. It is read off the visitor exhaust() already opened
        # rather than opening a second one: deriving it from the measurement
        # that was taken beats taking a new one that could disagree with it.
        if stopped_on is None:
            for nm, det in (
                    ("4a. a fresh visitor meets the capacity refusal",
                     "page kind == refused (capacity), NOT 'broken'"),
                    ("4b. two tabs, pool EXHAUSTED (tab 2 resumes, is NOT "
                     "refused)",
                     "tab 2 resumes tab 1's session; a refusal is a LOCK-OUT"),
                    ("4c. two tabs, pool EXHAUSTED (tab 1 survives)",
                     "chunk delta>0 after bringToFront")):
                record(nm, UNDEC, det,
                       "opened %d extra visitors and the front door kept "
                       "serving; the exhausted case was never reached, so "
                       "nothing here is evidence about it" % held)
        else:
            outcome, why = fresh_visitor_verdict(stopped_on)
            record("4a. a fresh visitor meets the capacity refusal", outcome,
                   "page kind == refused (capacity), NOT 'broken'",
                   "visitor %d, with a cookie jar of its own, got %r -- %s"
                   % (held + 1, stopped_on, why))
            arm_second_tab(A, args.url, args.server_probe, args.instance,
                           exhausted=True)

    except Occupied as e:
        print("\n  %s" % e)
        print("  Nothing was opened. No session was touched.")
        return 4
    except Precondition as e:
        print("\n  PRECONDITION FAILED: %s" % e)
        print("  This run says NOTHING about the product. It says the "
              "apparatus or the box was not ready.")
        return 3
    finally:
        for v in [A, B, M] + fillers:
            if v:
                try:
                    v.stop()
                except Exception:
                    pass
        browser.kill_strays()
        if rows:
            n = {o: len([r for r in rows if r[1] == o])
                 for o in (PASS, FAIL, UNDEC, SKIP, GATED, UNASKABLE)}
            print("\n  SHAPE -- compare these rows and detectors to last "
                  "round's, not the counts:")
            for name, outcome, det, _, _, _ in rows:
                print("    %-9s %-44s [%s]" % (outcome, name, det))
            print("\n  %d passed, %d FAILED, %d undecided, %d gated, "
                  "%d skipped, %d unaskable"
                  % (n[PASS], n[FAIL], n[UNDEC], n[GATED], n[SKIP],
                     n[UNASKABLE]))
            if n[UNDEC] or n[GATED]:
                print("  An undecided or gated row is not a pass. The round "
                      "has not seen what that row exists to see.")
            if n[UNASKABLE]:
                print("  An UNASKABLE row was never asked. Fix the apparatus; "
                      "it will not answer by being run again.")
            print_reading_list(n)
    return 1 if [r for r in rows if r[1] == FAIL] else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
