#!/usr/bin/env python3
"""The clipboard, driven the way a person drives it.

  .github/live/clipboard_xtest.py <url> [--instance NAME] [--host HOST]

The headless suite next door can put bytes on the browser's clipboard, but it
cannot paste: a paste is honoured only after genuine user activation, and a key
event injected over the debugging protocol is not that. So this runs a real
browser on an Xvfb display and presses the keys through XTEST, which the X
server delivers as ordinary input.

That also makes the local half honest. Instead of writing into the page's
clipboard from JavaScript, the image is put on the *X server's* clipboard and
the browser reads it from there -- which is what happens when someone takes a
screenshot on their own machine and pastes it into the session.

Run with a Python that has python-xlib. The clipboard agent is spawned with the
system interpreter, because it needs GTK from the distribution's packages.
"""
import base64
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser  # noqa: E402
from clipboard import Session, ok, bad, png, pixels, PASS, FAIL  # noqa: E402

from Xlib import X, XK, display as xdisplay  # noqa: E402
from Xlib.ext import xtest  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "clipagent.py")


class LocalX:
    """An X server of our own, standing in for the user's desktop."""

    def __init__(self, num=99):
        self.name = ":%d" % num
        self.proc = subprocess.Popen(
            ["Xvfb", self.name, "-screen", "0", "1400x900x24"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.agent = None
        for _ in range(40):
            time.sleep(0.25)
            try:
                self.d = xdisplay.Display(self.name)
                return
            except Exception:
                continue
        raise RuntimeError("Xvfb never came up on " + self.name)

    def put(self, target, data):
        """Own this display's CLIPBOARD, the way a local application would."""
        if self.agent:
            self.agent.terminate()
        path = "/tmp/xtest-clip.bin"
        with open(path, "wb") as fh:
            fh.write(data)
        env = dict(os.environ, DISPLAY=self.name)
        self.agent = subprocess.Popen(
            ["/usr/bin/python3", AGENT, "put", target, path], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.0)

    def targets(self):
        env = dict(os.environ, DISPLAY=self.name)
        r = subprocess.run(["/usr/bin/python3", AGENT, "targets"], env=env,
                           capture_output=True, text=True)
        return r.stdout.split()

    def get(self, target):
        env = dict(os.environ, DISPLAY=self.name)
        r = subprocess.run(["/usr/bin/python3", AGENT, "get", target], env=env,
                           capture_output=True)
        return r.stdout if r.returncode == 0 else b""

    def focus_browser(self):
        """Point keyboard input at the browser window.

        There is no window manager on this display, so nothing assigns focus
        and XTEST keys would go to the root window and be discarded.
        """
        root = self.d.screen().root
        best, area = None, 0
        for w in root.query_tree().children:
            try:
                g = w.get_geometry()
            except Exception:
                continue
            if g.width * g.height > area:
                best, area = w, g.width * g.height
        if best is not None:
            self.d.set_input_focus(best, X.RevertToParent, X.CurrentTime)
            self.d.sync()
        return best

    def refocus(self):
        """Take focus away and give it back, so the page sees a real
        focus event.

        The client reads the local clipboard when its window regains focus,
        not continuously -- so placing content while the browser already holds
        focus produces no transition and nothing is ever read. Setting focus
        to the root first is what makes the second call an event rather than a
        no-op.
        """
        root = self.d.screen().root
        self.d.set_input_focus(root, X.RevertToParent, X.CurrentTime)
        self.d.sync()
        time.sleep(1.0)
        win = self.focus_browser()
        time.sleep(1.5)
        return win

    def click(self, x, y):
        xtest.fake_input(self.d, X.MotionNotify, x=x, y=y)
        self.d.sync()
        xtest.fake_input(self.d, X.ButtonPress, 1)
        xtest.fake_input(self.d, X.ButtonRelease, 1)
        self.d.sync()
        time.sleep(0.3)

    def key(self, name, ctrl=False):
        code = self.d.keysym_to_keycode(XK.string_to_keysym(name))
        ctrl_code = self.d.keysym_to_keycode(XK.string_to_keysym("Control_L"))
        if ctrl:
            xtest.fake_input(self.d, X.KeyPress, ctrl_code)
        xtest.fake_input(self.d, X.KeyPress, code)
        xtest.fake_input(self.d, X.KeyRelease, code)
        if ctrl:
            xtest.fake_input(self.d, X.KeyRelease, ctrl_code)
        self.d.sync()
        time.sleep(0.5)

    def stop(self):
        if self.agent:
            self.agent.terminate()
        self.proc.terminate()


def main():
    url = sys.argv[1]
    host, user = "HOST", "INSTANCE"
    for i, a in enumerate(sys.argv):
        if a == "--host":
            host = sys.argv[i + 1]
        if a == "--instance":
            user = sys.argv[i + 1]

    sess = Session(host, user)
    sess.install(AGENT)
    local = LocalX()
    browser.kill_strays()
    b = browser.Browser(9302, "xtest", display=local.name)
    b.start()
    try:
        b.open(url)
        b.call("Browser.grantPermissions", {
            "origin": "/".join(url.split("/")[:3]),
            "permissions": ["clipboardReadWrite", "clipboardSanitizedWrite"]})
        b.wait_for("(document.getElementById('status-display')||{classList:"
                   "{contains:()=>false}}).classList.contains('hidden')",
                   lambda v: v is True, timeout=120)
        # Focus first. The client stops the video stream while its window is
        # unfocused, so a frame count taken before this reads zero against a
        # perfectly healthy session.
        win = local.focus_browser()
        local.click(700, 500)
        # The status bar going away is not proof that anything is being sent.
        # A server throwing on every request cleared it just the same, and this
        # suite reported a healthy session against a desktop nobody could use.
        # Count frames on the wire, which stops moving the moment the server
        # does -- the same oracle the walkthrough uses, for the same reason.
        # Counted in the page, not off the wire: this suite opens the session
        # the way a user does, and the socket then lives in a Worker whose
        # frames never reach this debugging session. The walkthrough sidesteps
        # that with ?socket_worker=false; here the page's own counter is the
        # signal that survives either arrangement.
        CHUNKS = "window.videoChunksReceived || 0"
        before = b.eval(CHUNKS) or 0
        b.pump(5)
        frames = (b.eval(CHUNKS) or 0) - before
        if frames > 0:
            ok("the session is streaming in a real browser",
               "%s, +%d video chunks decoded" % (url, frames))
        else:
            bad("the session is streaming in a real browser",
                "no video arrived; every clipboard reading below would "
                "be taken against a session that is not working")
            raise SystemExit("refusing to measure the clipboard of a dead session")
        ok("the browser window has keyboard focus", "") if win else \
            bad("the browser window has keyboard focus", "no window found")

        print("\n  --- a screenshot on the local desktop, pasted into the session ---")
        sess.put("STRING", b"sentinel-before-the-paste")
        want = png((220, 30, 90))
        local.put("image/png", want)
        got = pixels(local.get("image/png"))
        if got and got[2] == (220, 30, 90):
            ok("the local desktop holds the image", "%dx%d, rgb%s" % got)
        else:
            bad("the local desktop holds the image", str(got))

        local.refocus()                # a genuine focus event, which is what
                                       # makes the client read the clipboard
        local.click(700, 500)          # user activation, on the desktop canvas
        local.key("v", ctrl=True)      # a real Ctrl+V through XTEST
        time.sleep(6)

        after = sess.targets()
        img = [t for t in after if t.startswith("image/")]
        arrived = pixels(sess.get(img[0])) if img else None
        if arrived and arrived[2] == (220, 30, 90):
            ok("the image reaches the session's clipboard",
               "%s, %dx%d, rgb%s" % (img[0], arrived[0], arrived[1], arrived[2]))
        else:
            bad("the image reaches the session's clipboard",
                "targets are %s" % (" ".join(after) or "(none)"))

        print("\n  --- a copy inside the session, landing on the local desktop ---")
        back = png((20, 120, 210))
        sess.put("image/png", back)
        time.sleep(4)
        local.refocus()
        time.sleep(3)
        here = pixels(local.get("image/png"))
        if here and here[2] == (20, 120, 210):
            ok("the session's image reaches the local desktop",
               "%dx%d, rgb%s" % here)
        else:
            bad("the session's image reaches the local desktop",
                "local clipboard holds %s" % (("%dx%d rgb%s" % here) if here
                                              else " ".join(local.targets()) or "(none)"))

        print("\n  --- formatted text ---")
        if sess.can_offer("text/html"):
            sess.put("text/html", b"<u>underlined-from-the-session</u>")
            time.sleep(4)
            local.focus_browser()
            time.sleep(3)
            body = local.get("text/html").decode("utf-8", "replace")
            if "underlined-from-the-session" in body:
                ok("formatting reaches the local desktop", body[:50])
            else:
                bad("formatting reaches the local desktop",
                    "local targets: %s" % (" ".join(local.targets()) or "(none)"))
        else:
            print("  skip the session side of formatted text (needs xclip there)")
    finally:
        b.stop()
        local.stop()
        browser.kill_strays()
    print("\n%d/%d checks passed" % (len(PASS), len(PASS) + len(FAIL)))


if __name__ == "__main__":
    main()
