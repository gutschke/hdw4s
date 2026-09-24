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

# The page-side video counter. Its LEVEL is not liveness -- a frozen tab keeps
# whatever count it reached -- so every use of it here is a DELTA over a window.
CHUNKS = "window.videoChunksReceived || 0"

# The gate, by the element the product actually draws, not by its wording.
GATE_UP = ("(()=>{var e=document.getElementById('hdw4s-gate');"
           "return e ? !e.hidden : null})()")
GO = "document.getElementById('hdw4s-go')"

# The product's own wording for the capacity refusal, and the ONLY thing that
# separates it from the 502 the same builder produces when a desktop dies.
# selftest() checks this against hdw4s-demux itself, so a rewording goes red
# there instead of quietly turning a crash into a pass.
CAPACITY_TITLE = "Every desktop is in use"

# The session id, taken from the address bar rather than from anything the page
# says about itself: /s/<sid>/ is what the demux issued, and a page that lies
# about its own identity is exactly the failure an arm here is looking for.
SID = r"(((location.pathname.match(/^\/s\/([^\/]+)\//))||[])[2])||''"


# --------------------------------------------------------------------------
# Result vocabulary
# --------------------------------------------------------------------------

rows = []


def record(name, outcome, detector, detail=""):
    """One row. `detector` is not decoration.

    An arm whose detector is "no error" is not an arm, so every row has to name
    what was actually observed. It is printed on every run because the thing
    compared between rounds is the shape -- these names, these detectors -- and
    a detector that quietly changed is how a matrix goes green by a new route.
    """
    rows.append((name, outcome, detector, detail))
    print("  %-9s %-44s [%s] %s" % (outcome, name, detector, detail),
          flush=True)
    return outcome == PASS


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


def classify(title, body_html):
    """Which of the three pages is this? -- and this is a PROXY, not a reading.

    The product emits three kinds of page from the front door and they are
    distinguishable only by accident:

      desktop  the gated client, which carries #hdw4s-gate / #hdw4s-go
      gate     demux gate_page(): a card WITH an action link back to /
      refused  demux page(): the same card WITHOUT the link (the 503)

    gate_page() and page() differ by one <a href="/"> and nothing else. Neither
    carries an id, a class or a data- attribute saying which it is, so this
    function is reading a styling decision and calling it a protocol. It is
    good enough to run the round and it is not good enough to keep: the repair
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
    if 'href="/"' in body_html:
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
        self.br.call("Page.navigate", {"url": visit_url(url)}, timeout=120)
        time.sleep(settle)

    def eval(self, e, timeout=30):
        return self.br.eval(e, timeout)

    def alive(self):
        return self.br.eval("1+1") == 2

    def sid(self):
        return self.eval(SID) or ""

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
        """Is video arriving NOW? Returns (bool|None, (before, after))."""
        if raise_first:
            self.front()
        a = self.eval(CHUNKS)
        time.sleep(seconds)
        b = self.eval(CHUNKS)
        if not self.alive():
            return None, (a, b)
        return (b or 0) - (a or 0) > 0, (a, b)

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

    def click_gate(self):
        if self.eval(GATE_UP) is True:
            self.eval("%s && %s.click()" % (GO, GO))
            time.sleep(3.0)
            return True
        return False

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
        return self.eval(SID) or ""

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

    Gate vs failure: if #hdw4s-gate is up, this is the product ASKING, which is
    a correct outcome for some arrivals and not a failure. The arm clicks
    Connect once, because that is what a person does, and only reports GATED if
    the card is still up afterwards.
    """
    a.goto(url, settle=4.0)
    kind = classify(a.title(), a.html())
    if kind == "refused":
        return record("1. first visit gets a desktop", GATED,
                      "front-door refusal page",
                      "the server refused: %r -- not a failure, but this round "
                      "cannot see a desktop" % a.title())
    clicked = a.click_gate()
    got, best = a.wait_picture(floor)
    if not got:
        if a.eval(GATE_UP) is True:
            return record("1. first visit gets a desktop", GATED,
                          "picture<floor AND #hdw4s-gate still up",
                          "the card is still asking; no desktop was promised")
        return record("1. first visit gets a desktop", FAIL,
                      "picture<floor, no gate",
                      "colours %d <= floor %d, page kind %s" % (best, floor, kind))
    mov, pair = a.moving(5.0)
    if mov is None:
        return record("1. first visit gets a desktop", UNDEC,
                      "debugger died mid-measure", "chunks %s" % (pair,))
    return record("1. first visit gets a desktop", PASS if mov else FAIL,
                  "colours>floor AND chunk delta>0",
                  "colours %d>%d, chunks %s->%s%s"
                  % (best, floor, pair[0], pair[1],
                     ", after clicking Connect" if clicked else ""))


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
    a.goto(url, settle=4.0)
    a.click_gate()
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
    The interesting half is the second, and its assertion is not about tab 2 at
    all. It is that TAB 1 IS STILL THERE.

    Detector, tab 2: which page it landed on (desktop / gate / refusal).
    Detector, tab 1: chunk delta AFTER Page.bringToFront, because opening tab 2
    backgrounds tab 1 and freezes its counter, which looks exactly like
    eviction. Where a --server-probe is supplied, the server's own count of
    attached clients is the corroborating reading, and it is the one that
    settles it: the client-side delta cannot separate "frozen" from "gone" on
    its own, so with no probe and a zero delta this arm is UNDECIDED and says
    so rather than reporting a failure it cannot see.
    """
    label = "4. two tabs, pool EXHAUSTED" if exhausted else "3. two tabs, pool has room"
    sid1 = a.sid()
    before_n = server_count(probe, instance)
    t = a.new_tab(url)
    kind = classify(t.title(), t.html())
    sid2 = t.sid()

    if exhausted:
        ok2 = kind == "refused"
        record(label + " (tab 2 is told so)", PASS if ok2 else FAIL,
               "page kind == refused (capacity), NOT 'broken'",
               ("tab 2 got %s, title %r, sid %r" % (kind, t.title(), sid2[:12]))
               + (" -- a DEAD desktop, not a capacity refusal; this is the "
                  "failure that would otherwise have scored as a pass"
                  if kind == "broken" else ""))
    else:
        ok2 = kind in ("desktop", "gate")
        record(label + " (tab 2 is served)", PASS if ok2 else FAIL,
               "page kind in {desktop,gate}",
               "tab 2 got %s, sid %r" % (kind, sid2[:12]))

    mov, pair = a.moving(6.0)
    after_n = server_count(probe, instance)
    if mov is None:
        return record(label + " (tab 1 survives)", UNDEC,
                      "tab 1's debugger died", "chunks %s" % (pair,))
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


def arm_reverse_order(a, b, url):
    """The same two visitors, arriving in the other order.

    Not a relabelling of the row above: it re-navigates B first and A second,
    where the first run had A first. Order is exactly the kind of thing a
    cookie-keyed ownership rule gets wrong in one direction only -- whoever
    arrives second resuming the first one's session is a swap that a
    same-order test can never see, because in that test the second arrival is
    always the same browser.

    Detector: each browser comes back to the sid it already held. A swap, or
    either of them minting a third, is the failure.
    """
    was_a, was_b = a.sid(), b.sid()
    if not was_a or not was_b:
        return record("7. reverse order does not swap owners", SKIP,
                      "one visitor had no sid to return to",
                      "A=%r B=%r" % (was_a[:12], was_b[:12]))
    b.goto(url, settle=4.0)
    b.click_gate()
    a.goto(url, settle=4.0)
    a.click_gate()
    now_a, now_b = a.sid(), b.sid()
    swapped = now_a == was_b or now_b == was_a
    kept = now_a == was_a and now_b == was_b
    return record("7. reverse order does not swap owners",
                  PASS if kept and not swapped else FAIL,
                  "each browser returns to the sid it held",
                  "A %s->%s, B %s->%s%s"
                  % (was_a[:12], now_a[:12], was_b[:12], now_b[:12],
                     ", SWAPPED" if swapped else ""))


def arm_two_visitors(a, b, url, floor):
    """Two browsers are two people, and neither is the other.

    Detector: the two session ids differ, AND B's whole document does not
    contain A's id anywhere. The second half is the leak check: two distinct
    ids prove the demux issued two, not that one page never mentions the other.
    """
    n = "5. two browsers are two visitors"
    sa, sb = a.sid(), b.sid()
    if not sa or not sb:
        return record(n, GATED, "one visitor has no sid",
                      "A=%r B=%r -- one of them was gated rather than served"
                      % (sa[:12], sb[:12]))
    if sa == sb:
        return record(n, FAIL, "sid(A) != sid(B)",
                      "both browsers were given %s" % sa[:12])
    leaked = sa in b.html() or sb in a.html()
    return record(n, FAIL if leaked else PASS,
                  "sids differ AND neither document names the other's",
                  "A=%s B=%s%s" % (sa[:12], sb[:12],
                                   ", LEAKED" if leaked else ""))


def arm_share_without_key(a, b, url):
    """Pasting someone's session address is expected to fail. Run it anyway.

    Detector: B does NOT reach a streaming picture at A's address, and A keeps
    streaming. Two separate assertions, because a product that refuses B by
    killing A's session has refused correctly and broken the thing that
    mattered.
    """
    sa = a.sid()
    if not sa:
        return record("6. a pasted session link is refused", SKIP,
                      "A has no sid to paste", "")
    from urllib.parse import urljoin
    b.goto(urljoin(url, "/s/%s/" % sa), settle=5.0)
    kind = classify(b.title(), b.html())
    b_sid = b.sid()
    stole = kind == "desktop" and b_sid == sa
    record("6. a pasted session link is refused",
           FAIL if stole else PASS,
           "B's page kind, and whether B holds A's sid",
           "B got %s (sid %r); expected refusal or gate" % (kind, b_sid[:12]))
    mov, pair = a.moving(5.0)
    if mov is None:
        return record("6b. A survives B's attempt", UNDEC,
                      "A's debugger died", "chunks %s" % (pair,))
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


def arm_capture_indicators(a, evidence_dir, display, expect_media):
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
    """
    # browser.eval passes awaitPromise, so an async expression settles before
    # the value comes back. It returns None on a timeout, which must NOT be
    # read as "no tracks": that would score a dead debugger as the product
    # correctly refusing, which is a green light for the wrong reason.
    tracks = a.eval(
        "(async()=>{try{"
        "const s=await navigator.mediaDevices.getUserMedia({audio:true,video:true});"
        "return s.getTracks().filter(t=>t.readyState==='live')"
        ".map(t=>t.kind).sort().join(',')||'none';"
        "}catch(e){return 'refused:'+e.name}})()", timeout=45)
    if tracks is None:
        record("9. capture at the page layer", UNDEC,
               "getUserMedia never settled",
               "no answer came back; this says nothing either way")
        tracks, live = None, None
    else:
        live = not str(tracks).startswith("refused") and tracks != "none"

    if live is None:
        pass
    elif expect_media:
        record("9. capture is live at the page layer",
               PASS if live else FAIL,
               "live MediaStreamTrack kinds",
               "tracks=%r (deployed with capture enabled)" % (tracks,))
    else:
        record("9. capture is refused when disabled",
               PASS if not live else FAIL,
               "live MediaStreamTrack kinds",
               "tracks=%r (deployed with capture disabled; a live track here "
               "is the server failing to refuse)" % (tracks,))

    shot = os.path.join(evidence_dir, "chrome-indicators.png")
    err = root_screenshot(display, shot)
    record("10. the indicator in the browser's chrome", UNDEC,
           "root-window photograph, read by a person",
           ("captured %s -- a person must look at it" % shot) if not err
           else ("NOT captured: %s" % err))


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

    Returns (held_open, reached_refusal, browsers_to_close).
    """
    held, kept = 0, []
    for i in range(limit):
        v = Visitor(base_port + 40 + i, "fill%d" % i, display_base + i)
        try:
            v.start()
            v.goto(url, settle=4.0)
            v.click_gate()
            kind = classify(v.title(), v.html())
        except Precondition:
            v.stop()
            break
        if kind == "refused":
            v.stop()
            return held, True, kept
        kept.append(v)
        held += 1
    return held, False, kept


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

    expect("sid: a session path", sid_of("/s/abc123/"), "abc123")
    expect("sid: the front door", sid_of("/"), "")
    expect("sid: a lookalike path", sid_of("/session/abc/"), "")

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
                         "exit; touches no machine and needs no product")
    args = ap.parse_args()

    if args.guardtest:
        return guardtest()
    if args.selftest:
        return selftest() or guardtest()
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
        B.goto(args.url, settle=4.0)
        B.click_gate()
        arm_two_visitors(A, B, args.url, floor)
        arm_share_without_key(A, B, args.url)
        arm_reverse_order(A, B, args.url)
        arm_second_interaction(A, args.url)

        # Now fill the pool and do the two-tab row again. This is the row the
        # owner found by hand, and it is last because it leaves the machine
        # with no free slot.
        held, refused, fillers = exhaust(args.url, args.display_base + 3,
                                         args.base_port, args.slots)
        if args.slots and held + 2 != args.slots and refused:
            record("0. the deployed pool is the one declared", FAIL,
                   "browsers served before the front door refused",
                   "--slots said %d; this run got %d more visitors served "
                   "before refusal, with 2 already holding sessions"
                   % (args.slots, held))
        if not refused:
            record("4. two tabs, pool EXHAUSTED", UNDEC,
                   "the pool never refused",
                   "opened %d extra visitors and the front door kept serving; "
                   "the exhausted case was never reached, so nothing here is "
                   "evidence about it" % held)
        else:
            arm_second_tab(A, args.url, args.server_probe, args.instance,
                           exhausted=True)

        # The capture arm gets its own browser, without the fake permission UI.
        M = Visitor(args.base_port + 2, "M", args.display_base + 2,
                    real_media_ui=True)
        M.start()
        M.goto(args.url, settle=4.0)
        M.click_gate()
        arm_capture_indicators(M, evidence, M.display, args.media)

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
                 for o in (PASS, FAIL, UNDEC, SKIP, GATED)}
            print("\n  SHAPE -- compare these rows and detectors to last "
                  "round's, not the counts:")
            for name, outcome, det, _ in rows:
                print("    %-9s %-44s [%s]" % (outcome, name, det))
            print("\n  %d passed, %d FAILED, %d undecided, %d gated, %d skipped"
                  % (n[PASS], n[FAIL], n[UNDEC], n[GATED], n[SKIP]))
            if n[UNDEC] or n[GATED]:
                print("  An undecided or gated row is not a pass. The round "
                      "has not seen what that row exists to see.")
    return 1 if [r for r in rows if r[1] == FAIL] else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
