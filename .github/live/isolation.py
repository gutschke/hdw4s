#!/usr/bin/env python3
"""Two ephemeral sessions at once, and the wall between them.

  isolation.py --a _hdw4s_0 --b _hdw4s_1

The reviewer journey in journey.py drives ONE session and asks whether the
product works. This asks the question that only exists once there is more than
one: with two desktops live at the same moment, does each visitor get their
own -- their own picture, their own identity, their own home -- and does
nothing of theirs reach the other?

It is an extension of journey.py rather than a second harness: the browser,
the credential, the precondition/skip/undecided vocabulary and the picture
oracle all come from there, so a fix to any of them fixes both files.

FOUR ORACLES, each chosen by the direction of its failure.

  * A PICTURE, decoded outside the page. journey.py's, unchanged, and the
    reason this file starts an Xvfb per browser and has no headless mode: a
    headless browser has no framebuffer, so it cannot observe a picture, and a
    harness that cannot see one must never be in a position to report one.

  * WHICH SESSION A TAB IS SHOWING. A tab pointed at slot A's front door is
    ASSUMED to be showing slot A; that assumption is the whole thing under
    test, so it is not allowed to be an assumption. A fullscreen window of a
    known colour is opened INSIDE each session, and the colour is then read
    off the browser's own screenshot. Nothing on the page reports it and
    nothing on the host is trusted for it: the colour travels the entire
    product path -- X server, encoder, relay, front door, decoder, canvas --
    and arrives as pixels.

  * WHO THE SESSION THINKS IT IS. `id`, run inside the session's own mount
    namespace under the session's own uid, not on the host. The expected
    answer is the same NAME with different NUMBERS, and the failure mode that
    mimics it is nss not answering at all: `id` then prints a bare number
    where the name should be, which also differs between sessions. So the
    check is not "the numbers differ" -- it is "the name resolved, to `user`,
    in both, AND the numbers differ".

  * WHETHER A FILE CROSSED. One reader, `markers()`, used for every reading:
    the one that must find the marker and the ones that must not. A check that
    reads with one instrument and denies with another is not a comparison.

THE POSITIVE CONTROL THIS FILE EXISTS FOR. "B does not have A's file" is
satisfied by a write that never happened, and that is the easy way to ship a
green isolation claim that rests on nothing. So the marker is SHOWN PRESENT in
A, by markers(A), before anything is asked of B -- and if it is not present,
every downstream isolation check is SKIPPED, never passed. Both directions are
run for the same reason: "A's file is absent from B" is also satisfied by an
empty B.

PROVING THE CHECKS CAN FAIL. --red runs the same journey with one thing
deliberately broken, and the named check must then go red. See RED.
"""
import argparse, os, re, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser
import journey
from journey import (Client, Precondition, record, need, credential,
                     PASS, FAIL, SKIP, UNDEC)

# Two colours chosen to survive a lossy encoder and still not be confusable
# with each other or with the ephemeral desktop's aubergine (#772953): they sit
# at opposite corners of the cube, and the aubergine is nearer to neither.
PAINT = {"a": (0xFF, 0x00, 0x00), "b": (0x00, 0x00, 0xFF)}
AUBERGINE = (0x77, 0x29, 0x53)

# Fills the screen with one colour from inside the session. Cairo is not
# installed there, so the colour is a CSS background on the window rather than
# a draw handler -- measured: with a draw handler this dies with "Couldn't find
# foreign struct converter for 'cairo.Context'" and paints nothing, while the
# process stays alive and a caller watching only the exit status sees success.
PAINTER = r"""
import sys, gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk
css = Gtk.CssProvider()
css.load_from_data(("window { background-color: %s; }" % sys.argv[1]).encode())
Gtk.StyleContext.add_provider_for_screen(
    Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
w = Gtk.Window(); w.set_decorated(False); w.fullscreen()
w.connect("destroy", Gtk.main_quit); w.show_all()
Gtk.main()
"""

RED = ("none", "same-slot", "skip-write", "host-reader", "swap-paint",
       "no-cycle", "bare-uid")


def sh(argv, timeout=60):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


class XServer:
    """One Xvfb, for one browser, and never shared.

    journey.py already says each client gets its own browser process, profile
    and debugging port, because a run that shared one display was struck once.
    A framebuffer is the same resource and was not on that list, and it cost
    this file two runs: two headful browsers, both started at --window-position
    0,0 with no window manager to place them, and the second window sits
    exactly on top of the first. Chrome does not render an occluded window, so
    Page.captureScreenshot on the covered tab returns the page shell with no
    video frame in it -- 238 colours against a 1464-colour blank page, twice,
    while the desktop behind it was streaming at 45 fps and a screenshot taken
    through a browser of its own showed it perfectly.

    The failure is worth naming because of its direction: it accuses the
    PRODUCT of not painting, in a run whose whole purpose is to watch two
    sessions paint at once, and the evidence it offers looks exactly like the
    real fault.
    """

    def __init__(self, number, geometry="1280x800x24"):
        self.name = ":%d" % number
        self.proc = subprocess.Popen(
            ["Xvfb", self.name, "-screen", "0", geometry],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)

    def up(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if subprocess.run(["xdpyinfo"], env=dict(os.environ,
                                                     DISPLAY=self.name),
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


class Slot:
    """One ephemeral slot, and the way into the session it is running.

    Everything here that claims to be "inside" goes through nsenter into the
    session unit's own mount and pid namespaces, under the slot's uid. That is
    the only reading that answers the question asked: the host's view of the
    same uid resolves against the host's passwd and shows the slot's OUTSIDE
    name, which is exactly the answer the product is trying not to give.
    """

    def __init__(self, name, front, session, cred):
        self.name, self.front, self.session, self.cred = (name, front,
                                                          session, cred)
        self.painter = None

    # -- what systemd knows -------------------------------------------------
    def prop(self, p):
        return sh(["systemctl", "show", "hdw4s-ephemeral@%s.service" % self.name,
                   "-p", p, "--value"])[1]

    def active(self):
        return sh(["systemctl", "is-active",
                   "hdw4s-ephemeral@%s.service" % self.name])[1]

    def uid(self):
        rc, out, _ = sh(["getent", "passwd", self.name])
        return int(out.split(":")[2]) if rc == 0 and out else None

    def display(self):
        m = re.search(r"display (:\d+)", self.prop("StatusText") or "")
        return m.group(1) if m else None

    def bus(self):
        """The session bus address, read from the session's own environment.

        Taken from a process in the session rather than guessed from a path:
        dbus-run-session names the socket randomly, and a guessed path fails
        by silently starting a SECOND bus, which is indistinguishable from
        success until something looks for a service on it.
        """
        pid = self.prop("MainPID")
        rc, out, _ = sh(["pgrep", "-P", pid, "-f", "hdw4s-run-session"])
        for cand in ([out.split()[0]] if rc == 0 and out else []) + [pid]:
            try:
                with open("/proc/%s/environ" % cand, "rb") as f:
                    for line in f.read().split(b"\0"):
                        if line.startswith(b"DBUS_SESSION_BUS_ADDRESS="):
                            return line.decode()
            except OSError:
                pass
        return None

    # -- running something inside -------------------------------------------
    def inside(self, argv, timeout=60, background=False):
        pid, uid = self.prop("MainPID"), self.uid()
        if not pid or pid == "0" or uid is None:
            return 127, "", "%s is not running" % self.name
        env = ["env", "HOME=/home/user", "USER=user", "LOGNAME=user",
               "DISPLAY=%s" % (self.display() or ":0"),
               "XDG_RUNTIME_DIR=/run/hdw4s/%s" % self.name,
               "XAUTHORITY=/run/hdw4s/%s/Xauthority" % self.name,
               "DCONF_PROFILE=hdw4s-ephemeral"]
        b = self.bus()
        if b:
            env.append(b)
        cmd = ["nsenter", "-t", pid, "-m", "-p",
               "--setuid", str(uid), "--setgid", str(uid)] + env + argv
        if background:
            return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    start_new_session=True)
        return sh(cmd, timeout=timeout)

    def paint(self, colour):
        """Open a fullscreen window of `colour` inside this session.

        The script is delivered on the session's own /tmp rather than read
        from a path on the host: the host's /root is hidden by ProtectHome=,
        so a path that exists for the caller does not exist for the callee,
        and python3 then fails with a file-not-found that reads like a bug in
        the harness rather than a namespace doing its job.
        """
        self.unpaint()
        script = "/tmp/hdw4s-paint.py"
        # Carried as base64 in the command line rather than on stdin: the
        # script has to land on a filesystem the SESSION can see, and nsenter's
        # stdin does not survive the setuid hand-off reliably enough to build a
        # test on.
        import base64
        blob = base64.b64encode(PAINTER.encode()).decode()
        self.painter = self.inside(
            ["sh", "-c", "echo %s | base64 -d > %s; exec python3 %s '%s'"
             % (blob, script, script, colour)], background=True)
        return self.painter

    def unpaint(self):
        # A pattern that cannot match the command carrying it: pkill -f reads
        # the whole command line, including this process's own, and killing
        # your own ssh session is how three runs of this ended before the
        # bracket went in.
        self.inside(["pkill", "-f", "hdw4s-[p]aint[.]py"], timeout=20)
        if self.painter is not None:
            try:
                self.painter.kill()
            except Exception:
                pass
            self.painter = None

    # -- the one reader -----------------------------------------------------
    def markers(self, host=False):
        """Every marker file this session's home holds, as a set of names.

        ONE reader, used for the reading that must find something and for the
        readings that must not. `host=True` is the red arm: it reads the same
        path on the host, where the session's tmpfs home is not mounted, and
        must therefore find nothing -- which is what proves the normal arm is
        looking inside rather than at an empty directory that happens to
        agree.
        """
        if host:
            rc, out, _ = sh(["ls", "-1", "/home/user"])
        else:
            rc, out, _ = self.inside(["ls", "-1", "/home/user/Desktop"])
        if rc != 0:
            return set()
        return set(n for n in out.split() if n.startswith("HDW4S-MARK-"))

    def write_marker(self, tag):
        name = "HDW4S-MARK-%s" % tag
        rc, _, err = self.inside(
            ["sh", "-c", "mkdir -p /home/user/Desktop && "
                         "printf 'left by the live harness\\n' "
                         "> /home/user/Desktop/%s" % name])
        return name, rc, err

    def id_line(self, host=False, unresolvable=False):
        if unresolvable:
            # The failure that mimics success, produced on purpose. It has to
            # be produced by BECOMING a uid nothing resolves, not by asking
            # `id` about one: `id 60990` reports "no such user" on stderr and
            # prints nothing, which the parser rejects for the wrong reason.
            # Run AS that uid it prints the real signature --
            # "uid=60990 gid=60990 groups=60990" -- a bare number where the
            # name should be, which still DIFFERS between two sessions and is
            # what makes this mistakable for the expected result.
            n = (self.uid() or 0) + 90
            return sh(["setpriv", "--reuid=%d" % n, "--regid=%d" % n,
                       "--clear-groups", "id"])[1]
        if host:
            return sh(["id", str(self.uid())])[1]
        return self.inside(["id"])[1]

    def logout(self):
        """Destroy the session the way a person does, from inside.

        NOT `systemctl stop`. On the stop path Requires= and BindsTo= are
        indistinguishable, and a fix was once declared verified on exactly
        that path without ever meeting the case it was written for. A normal
        GNOME logout exits non-zero and leaves the unit failed -- measured, and
        not a fault of this check.
        """
        return self.inside(["gnome-session-quit", "--logout", "--no-prompt"],
                           timeout=60)

    def invocation(self):
        """systemd's id for THIS start of the unit.

        The oracle for "the session was replaced", and it replaces watching for
        the unit to go inactive, which does not work and read as UNDECIDED on
        the first run of this file. A visitor's client reconnects the moment
        the relay drops, socket activation fires, and the next session is up
        again inside the polling interval -- so a watcher looking for an
        absence sees an unbroken "active" and cannot tell a session that
        cycled from one that ignored the logout. The invocation id changes on
        every start and cannot be outrun, however fast the turnaround.
        """
        return self.prop("InvocationID")

    def wait_cycled(self, was, timeout=180):
        """Wait until this slot is running a DIFFERENT session from `was`."""
        end = time.time() + timeout
        saw_down = False
        while time.time() < end:
            if self.active() != "active":
                saw_down = True
            now = self.invocation()
            if now and now != was:
                return True, saw_down, now
            time.sleep(0.5)
        return False, saw_down, self.invocation()

    def wait_active(self, timeout=150):
        end = time.time() + timeout
        while time.time() < end:
            if self.active() == "active":
                return True
            time.sleep(2)
        return False


def dominant(shot, box=(0.15, 0.25, 0.85, 0.75)):
    """The most common colour in the middle of the screen, as (r, g, b).

    The middle, not the whole frame: the browser's own chrome, the letterbox
    around a stream whose aspect ratio does not match the tab, and GNOME's top
    bar are all constant between the two sessions, so counting them dilutes
    exactly the signal being looked for.
    """
    if not shot:
        return None
    w, h, data, pixel = shot
    x0, y0, x1, y1 = (int(box[0] * w), int(box[1] * h),
                      int(box[2] * w), int(box[3] * h))
    seen = {}
    for y in range(y0, y1, 3):
        row = y * w * pixel
        for x in range(x0, x1, 3):
            i = row + x * pixel
            k = data[i:i + 3]
            seen[k] = seen.get(k, 0) + 1
    if not seen:
        return None
    best = max(seen, key=seen.get)
    return (best[0], best[1], best[2])


def nearest(rgb, palette):
    """Which of the named colours this one is closest to.

    A distance, not an equality test: the colour has been through a lossy
    encoder and comes back a few units off. What matters is that it is nearer
    to its own session's colour than to the other's, which a threshold on the
    absolute value would not say.
    """
    if rgb is None:
        return None, None
    d = {k: sum((a - b) ** 2 for a, b in zip(rgb, v))
         for k, v in palette.items()}
    k = min(d, key=d.get)
    return k, int(d[k] ** 0.5)


def id_verdict(line):
    """(name, uid) from an `id` line, or (None, uid) when nothing resolved.

    The failure that mimics success: with the namespaced passwd missing, `id`
    prints `uid=60901 gid=60901` -- a bare number where the name should be,
    which still DIFFERS between two sessions and reads, to anyone comparing
    only the numbers, exactly like the result being hoped for.
    """
    m = re.match(r"uid=(\d+)\(([^)]+)\)", line or "")
    if m:
        return m.group(2), int(m.group(1))
    m = re.match(r"uid=(\d+)", line or "")
    return (None, int(m.group(1))) if m else (None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default="_hdw4s_0")
    ap.add_argument("--b", default="_hdw4s_1")
    ap.add_argument("--front-a", type=int, default=7303)
    ap.add_argument("--front-b", type=int, default=7304)
    ap.add_argument("--session-a", type=int, default=7367)
    ap.add_argument("--session-b", type=int, default=7368)
    ap.add_argument("--cred-a", default="/etc/hdw4s/_hdw4s_0.auth.cred")
    ap.add_argument("--cred-b", default="")
    ap.add_argument("--display-base", type=int, default=90,
                    help="the harness starts one Xvfb per browser, at this "
                         "display number and the next. There is no headless "
                         "mode: a headless browser has no framebuffer, so it "
                         "cannot see a picture, and this file must never be "
                         "in a position to report one it did not see.")
    ap.add_argument("--red", default="none", choices=RED,
                    help="break one thing on purpose and name the check that "
                         "must go red")
    a = ap.parse_args()

    A = Slot(a.a, a.front_a, a.session_a, a.cred_a)
    B = Slot(a.b, a.front_b, a.session_b, a.cred_b)
    if a.red == "same-slot":
        # Both tabs at ONE slot, and both readers at ONE session. Isolation is
        # then false by construction, so every isolation check must fail. If
        # any of them still passes, it was not reading what it claims to.
        B = Slot(a.a, a.front_a, a.session_a, a.cred_a)

    ta = tb = None
    xa = xb = None
    del journey.rows[:]
    try:
        print("\n-- preconditions (the apparatus and the box, not the product)")
        need(os.geteuid() == 0, "running as root",
             "(nsenter into a session's namespace needs it)")
        xa = XServer(a.display_base)
        xb = XServer(a.display_base + 1)
        need(xa.up() and xb.up(),
             "a framebuffer of its own for each browser",
             "(%s and %s)" % (xa.name, xb.name))
        need(browser.kill_strays() >= 0, "stray browsers cleared")
        # And strays INSIDE the sessions, which is a class this harness
        # introduced itself: a fullscreen colour window left behind by an
        # earlier run makes the screen almost one colour, so the picture
        # oracle -- which counts colours -- reads 238 against a 1464-colour
        # blank page and reports "no desktop" over a desktop that is working.
        # That is precisely a measurement of the observer, and it cost this
        # file its first run.
        for s in (A, B):
            s.unpaint()
        need(True, "any window a previous run left inside a session is closed")

        ha = credential(A.cred, A.name)
        hb = credential(B.cred, B.name)
        need(journey.http_code(A.front, ha) == 200,
             "slot %s's front door answers" % A.name)
        need(journey.http_code(B.front, hb) == 200,
             "slot %s's front door answers" % B.name)
        for s in (A, B):
            busy = browser.attached_stable(s.session, samples=3, gap=1.0)
            need(busy == 0, "nobody else is attached to %s" % s.name,
                 "(%s)" % busy)

        base_a = "http://127.0.0.1:%d/?socket_worker=false" % A.front
        base_b = "http://127.0.0.1:%d/?socket_worker=false" % B.front
        ta = Client(9330, "A", ha)
        ta.br.display = xa.name
        tb = Client(9331, "B", hb)
        tb.br.display = xb.name
        need(ta.open("http://127.0.0.1:1/") is None, "tab A's debugger attached")
        need(tb.open("http://127.0.0.1:1/") is None, "tab B's debugger attached")
        blank = max(ta.colours(), tb.colours())
        thresh = max(blank * 2, blank + 500)
        need(blank > 0, "the picture oracle is calibrated on this run",
             "(blank page %d colours, threshold %d)" % (blank, thresh))

        print("\n-- two sessions at once")
        ta.br.call("Page.navigate", {"url": base_a}, timeout=120)
        tb.br.call("Page.navigate", {"url": base_b}, timeout=120)
        time.sleep(3)
        # Kept, because it is the control for every LATER reading of the
        # gate: a cold tab must be offered the card, and if it is not, this
        # apparatus is not reaching the gate at all and "the gate stayed
        # silent" would mean nothing anywhere below.
        cold = {}
        for nm, t in (("A", ta), ("B", tb)):
            cold[nm] = t.eval(journey.GATE_UP)
            if cold[nm] is True:
                t.eval("document.getElementById('hdw4s-go').click()")
        oka, ca = ta.wait_picture(thresh, timeout=90)
        okb, cb = tb.wait_picture(thresh, timeout=90)
        both = oka and okb
        # A count BELOW the blank page is its own diagnosis and says so: the
        # screen is not failing to paint, something is covering it with one
        # colour. "Fewer colours than nothing" is the tell.
        odd = [s.name for s, c in ((A, ca), (B, cb)) if c < blank]
        record("1. two tabs, two slots, both show a desktop",
               PASS if both else FAIL,
               "%s %d colours, %s %d colours (threshold %d, blank %d)%s"
               % (A.name, ca, B.name, cb, thresh, blank,
                  "; %s shows FEWER colours than a blank page -- something is "
                  "covering the screen, which is not the same fault as a "
                  "stream that never started" % ", ".join(odd) if odd else ""))
        if both:
            # At the same MOMENT, not one after the other: a slot that only
            # works when it is the only one running would pass a sequential
            # reading of exactly these two numbers.
            ma, pa = ta.moving(4.0)
            mb, pb = tb.moving(4.0)
            record("2. and both are streaming at the same moment",
                   PASS if (ma and mb) else (UNDEC if None in (ma, mb) else FAIL),
                   "%s chunks %s, %s chunks %s" % (A.name, pa, B.name, pb))
        else:
            record("2. and both are streaming at the same moment", SKIP,
                   "there was never a picture in both tabs")

        # ---- 3. which session is each tab actually showing? ---------------
        if not both:
            record("3. each tab shows ITS OWN session's screen", SKIP,
                   "there was never a picture in both tabs")
        else:
            before_a = dominant(browser._decode_png(
                ta.br.call("Page.captureScreenshot", {"format": "png"},
                           timeout=60)["data"]))
            col_a, col_b = "#ff0000", "#0000ff"
            if a.red == "swap-paint":
                col_a, col_b = col_b, col_a
            A.paint(col_a)
            B.paint(col_b)
            time.sleep(8)
            da = dominant(browser._decode_png(
                ta.br.call("Page.captureScreenshot", {"format": "png"},
                           timeout=60)["data"]))
            db = dominant(browser._decode_png(
                tb.br.call("Page.captureScreenshot", {"format": "png"},
                           timeout=60)["data"]))
            palette = {"A": PAINT["a"], "B": PAINT["b"], "desktop": AUBERGINE}
            na, dista = nearest(da, palette)
            nb, distb = nearest(db, palette)
            good = na == "A" and nb == "B"
            record("3. each tab shows ITS OWN session's screen",
                   PASS if good else FAIL,
                   "tab A %s -> %s (d=%s), tab B %s -> %s (d=%s); was %s "
                   "before painting"
                   % (da, na, dista, db, nb, distb, before_a))
            A.unpaint(); B.unpaint()
            time.sleep(3)

        # ---- 4. who does each session think it is? ------------------------
        la = A.id_line(host=(a.red == "host-reader"),
                       unresolvable=(a.red == "bare-uid"))
        lb = B.id_line(host=(a.red == "host-reader"),
                       unresolvable=(a.red == "bare-uid"))
        na_, ua = id_verdict(la)
        nb_, ub = id_verdict(lb)
        if na_ is None or nb_ is None:
            verdict, why = FAIL, "the name did not resolve at all"
        elif na_ != nb_:
            verdict, why = FAIL, "the two sessions report DIFFERENT names"
        elif na_ != "user":
            verdict, why = FAIL, "the name is the slot's outside name"
        elif ua == ub:
            verdict, why = FAIL, "the two sessions share one uid"
        else:
            verdict, why = PASS, "same name, different numbers"
        record("4. id: one name, different numbers", verdict,
               "%s: %r | %s: %r -- %s" % (A.name, la, B.name, lb, why))

        # ---- 5. the marker, and the control that makes it mean anything ---
        tag = "%d" % int(time.time())
        mark_a = mark_b = None
        if a.red == "skip-write":
            # The failure this control exists for: nothing is written, and
            # every "absent from B" reading below is still true.
            mark_a, mark_b = "HDW4S-MARK-A" + tag, "HDW4S-MARK-B" + tag
            print("      (red arm: nothing was written)")
        else:
            mark_a = A.write_marker("A" + tag)[0]
            mark_b = B.write_marker("B" + tag)[0]
        host_read = (a.red == "host-reader")
        seen_a = A.markers(host=host_read)
        seen_b = B.markers(host=host_read)
        present = mark_a in seen_a and mark_b in seen_b
        record("5. each marker is PRESENT in the session that wrote it",
               PASS if present else FAIL,
               "%s holds %s (want %s); %s holds %s (want %s)"
               % (A.name, sorted(seen_a), mark_a,
                  B.name, sorted(seen_b), mark_b))

        if not present:
            for n in ("6. A's marker never appears in B",
                      "7. B's marker never appears in A",
                      "8. cycling A destroys its marker",
                      "9. and B is untouched by A's cycle"):
                record(n, SKIP, "no marker was ever shown present -- "
                                "'absent from the other' would mean nothing")
        else:
            record("6. A's marker never appears in B",
                   PASS if mark_a not in seen_b else FAIL,
                   "%s in %s: %s" % (mark_a, B.name, mark_a in seen_b))
            record("7. B's marker never appears in A",
                   PASS if mark_b not in seen_a else FAIL,
                   "%s in %s: %s" % (mark_b, A.name, mark_b in seen_a))

            # ---- 8/9. cycle A, by a real logout from inside ---------------
            was = A.invocation()
            if a.red == "no-cycle":
                print("      (red arm: A was never cycled)")
                cycled, saw_down, now = True, False, was
            else:
                rcq, _, err = A.logout()
                print("      (gnome-session-quit exited %s%s -- that is the "
                      "CLIENT's status, not the session's)"
                      % (rcq, (" -- " + err) if err else ""))
                # The occupant's own client reconnects when the relay drops,
                # and socket activation starts the next session in this slot:
                # the product's path, which `systemctl start` is not. It is
                # given its own window first, and only nudged if it does not
                # happen -- a nudge that always fires would hide a reconnect
                # that never worked.
                cycled, saw_down, now = A.wait_cycled(was, timeout=75)
                if not cycled:
                    print("      (no session came back on its own; opening "
                          "the front door again)")
                    ta.br.call("Page.navigate", {"url": base_a}, timeout=120)
                    cycled, saw_down, now = A.wait_cycled(was, timeout=120)
            jrn = sh(["journalctl", "-u",
                      "hdw4s-ephemeral@%s.service" % A.name,
                      "--since", "-5min", "--no-pager"])[1]
            latched = "Start request repeated too quickly" in jrn
            mb_mid, pb_mid = tb.moving(4.0)
            if not cycled:
                record("8. cycling A destroys its marker", FAIL,
                       "a logout left the SAME session running (invocation %s "
                       "unchanged, went inactive at any point=%s, "
                       "start-limit latched=%s)" % (was[:8], saw_down, latched))
                record("9. and B is untouched by A's cycle", SKIP,
                       "A never cycled")
            else:
                up = A.wait_active()
                after = A.markers(host=host_read) if up else set()
                clean = up and (mark_a not in after) and not latched
                record("8. cycling A destroys its marker",
                       PASS if clean else FAIL,
                       "new session %s (was %s), holds %s (want %s gone), "
                       "start-limit latched=%s"
                       % (now[:8], was[:8], sorted(after), mark_a, latched))
                record("9. and B is untouched by A's cycle",
                       PASS if mb_mid else (UNDEC if mb_mid is None else FAIL),
                       "B still streaming across A's teardown (chunks %s), "
                       "B still holds %s"
                       % (pb_mid, sorted(B.markers(host=host_read))))

        # ---- the gate, per tab -------------------------------------------
        # The card is shown once per TAB, ever: hdw4s-gate-index keeps the
        # flag in sessionStorage, which is per-tab, survives a reload and dies
        # with the tab. Every arm here is therefore a claim about one tab's
        # own state, and none of them can be made with curl or with a fresh
        # browser per arm -- a harness that started a new profile for each
        # would see a first visit every time and conclude the opposite of the
        # truth.
        record("11. a cold tab is offered the way in (the control)",
               PASS if cold.get("A") is True and cold.get("B") is True else FAIL,
               "tab A card up=%s, tab B card up=%s" % (cold.get("A"),
                                                       cold.get("B")))
        print("\n-- observed, not judged: what the gate DOES in a tab that "
              "has already been through it")
        tb.br.call("Page.reload", {}, timeout=60)
        time.sleep(6)
        back, cols = tb.wait_picture(thresh, timeout=45)
        print("      reload, same tab:  card up=%s, desktop back=%s (%d "
              "colours)" % (tb.eval(journey.GATE_UP), back, cols))
        print("      after a logout and a reconnect IN THE SAME TAB: "
              "card up=%s" % ta.eval(journey.GATE_UP))
        print("      (a genuinely new tab in the SAME profile, and a tab "
              "restored by Chrome after a clean exit, are NOT tested here: "
              "this client attaches to one page target per browser, so it "
              "cannot drive a second tab of the same profile. Reported as "
              "not done rather than approximated by writing sessionStorage, "
              "which would only assert that the setup code works.)")

        # ---- 10. and none of it reached the machine's real homes ----------
        rc, out, _ = sh(["sh", "-c",
                         "find /home -maxdepth 3 -name 'HDW4S-MARK-*' "
                         "-printf '%p\\n' 2>/dev/null"])
        record("10. no marker reached a real home on this machine",
               PASS if not out.strip() else FAIL,
               out.strip() or "nothing under /home")

    except Precondition as e:
        print("\n  PRECONDITION FAILED: %s" % e)
        print("  This run says NOTHING about the product. It says the "
              "apparatus or the box was not ready.")
        return 3
    finally:
        for s in (A, B):
            try:
                s.unpaint()
            except Exception:
                pass
        for t in (ta, tb):
            if t:
                t.stop()
        browser.kill_strays()
        for x in (xa, xb):
            if x:
                x.stop()
        rows = journey.rows
        if rows:
            bad = [r for r in rows if r[1] == FAIL]
            und = [r for r in rows if r[1] == UNDEC]
            skp = [r for r in rows if r[1] == SKIP]
            print("\n  %d passed, %d FAILED, %d undecided, %d skipped  [red=%s]"
                  % (len(rows) - len(bad) - len(und) - len(skp), len(bad),
                     len(und), len(skp), a.red))
            for n, o, d in bad:
                print("    FAILED: %s -- %s" % (n, d))
    return 1 if [r for r in journey.rows if r[1] == FAIL] else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
