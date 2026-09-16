#!/usr/bin/env python3
"""Does the clipboard carry more than plain text?

  .github/live/clipboard.py <url> [--instance NAME] [--host HOST]

Text already works. The two questions here are the ones a user actually hits:
an image copied in the local browser, and formatted text. Both are measured in
both directions, because a clipboard that only works outbound is a clipboard
that looks fine until someone tries to paste into the desktop.

The browser's clipboard is not readable without permission and not writable
without focus, so both are arranged explicitly rather than hoped for -- a
failure to grant would otherwise read as a failure of the feature.

The session side is read with xclip over ssh rather than from the page, so the
two ends of every assertion are independent: the page says what it sent, the X
selection says what arrived.
"""
import base64
import os
import subprocess
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser  # noqa: E402

PASS, FAIL = [], []


def ok(what, detail=""):
    PASS.append(what); print("  ok   %-52s %s" % (what, detail))


def bad(what, detail=""):
    FAIL.append(what); print("  FAIL %-52s %s" % (what, detail))


def png(rgb, w=64, h=64):
    """A solid PNG, built here so the bytes are known exactly."""
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    def chunk(tag, data):
        c = tag + data
        return (len(data).to_bytes(4, "big") + c
                + (zlib.crc32(c) & 0xffffffff).to_bytes(4, "big"))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", w.to_bytes(4, "big") + h.to_bytes(4, "big")
                    + bytes([8, 2, 0, 0, 0]))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


class Session:
    """The desktop's own clipboard, reached over ssh as the session's user."""

    def __init__(self, host, user):
        self.host, self.user = host, user
        self._tool = None

    AGENT = "/tmp/clipagent.py"

    def tool(self):
        """xclip if the box has it, otherwise the GTK agent.

        Both are exercised deliberately. The server has an xclip fallback path,
        so a machine where something later installs xclip is a different
        machine from the one tested here, and the difference would surface as a
        clipboard that quietly stops working.
        """
        if self._tool is None:
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "root@" + self.host,
                 "command -v xclip >/dev/null && echo yes || echo no"],
                capture_output=True, text=True)
            self._tool = "xclip" if r.stdout.strip() == "yes" else "gtk"
        return self._tool

    def _as_user(self, shell):
        return subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             "root@" + self.host,
             "sudo -u %s env DISPLAY=:0 XAUTHORITY=/run/hdw4s/%s/Xauthority %s"
             % (self.user, self.user, shell)],
            capture_output=True)

    def install(self, local):
        subprocess.run(["scp", "-o", "BatchMode=yes", local,
                        "root@%s:%s" % (self.host, self.AGENT)],
                       capture_output=True)
        subprocess.run(["ssh", "-o", "BatchMode=yes", "root@" + self.host,
                        "chmod 0644 " + self.AGENT], capture_output=True)

    def targets(self):
        if self.tool() == "xclip":
            r = self._as_user("xclip -selection clipboard -t TARGETS -o")
            return r.stdout.decode("utf-8", "replace").split() if r.returncode == 0 else []
        r = self._as_user("python3 %s targets" % self.AGENT)
        return r.stdout.decode("utf-8", "replace").split() if r.returncode == 0 else []

    def get(self, target):
        if self.tool() == "xclip":
            r = self._as_user("xclip -selection clipboard -t %s -o" % target)
            return r.stdout if r.returncode == 0 else b""
        r = self._as_user("python3 %s get %s" % (self.AGENT, target))
        return r.stdout if r.returncode == 0 else b""

    def put(self, target, data):
        """Own the selection, and keep owning it.

        The agent is left running on purpose: an X selection is served by its
        owner, so a writer that exits leaves an empty clipboard behind and
        every later reading measures nothing at all.
        """
        subprocess.run(["ssh", "-o", "BatchMode=yes", "root@" + self.host,
                        "pkill -u %s -f clipagent.py; true" % self.user],
                       capture_output=True)
        b64 = base64.b64encode(data).decode()
        f = "/tmp/clip-%s.bin" % self.user
        self._as_user("sh -c 'printf %%s %s | base64 -d > %s'" % (b64, f))
        if self.tool() == "xclip":
            self._as_user("sh -c 'setsid xclip -selection clipboard -t %s -i %s "
                          ">/dev/null 2>&1 </dev/null &'" % (target, f))
        else:
            self._as_user("sh -c 'setsid python3 %s put %s %s >/dev/null 2>&1 "
                          "</dev/null &'" % (self.AGENT, target, f))
        time.sleep(2.5)

    def can_offer(self, target):
        """Whether the writing tool can put this target on the clipboard."""
        return self.tool() == "xclip" or target.startswith("image/") or \
            target in ("STRING", "UTF8_STRING", "text/plain")


def pixels(raw):
    """Decode a PNG far enough to say what colour and size it is.

    Byte equality is the wrong test here: Chrome re-encodes images on their way
    into the clipboard, so the bytes that arrive are never the bytes that were
    sent even when the picture is identical. What travelled is the picture.
    """
    shot = browser._decode_png(base64.b64encode(raw).decode())
    if not shot:
        return None
    w, h, data, pixel = shot
    seen = {}
    for i in range(0, len(data) - pixel, pixel):
        c = bytes(data[i:i + 3])
        seen[c] = seen.get(c, 0) + 1
    top = max(seen, key=seen.get)
    return w, h, tuple(top)


def main():
    url = sys.argv[1]
    # No defaults. A suite that ships one names somebody's machine and somebody's
    # account in a public repository, and it did.
    host = user = ""
    for i, a in enumerate(sys.argv):
        if a == "--host":
            host = sys.argv[i + 1]
        if a == "--instance":
            user = sys.argv[i + 1]

    if not host or not user:
        sys.exit(f"{sys.argv[0]}: --host and --instance are required; this suite drives a\n"
                 "  live session and will not guess whose.")

    sess = Session(host, user)
    sess.install(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "clipagent.py"))
    browser.kill_strays()
    b = browser.Browser(9301, "clip")
    b.start()
    try:
        origin = "/".join(url.split("/")[:3])
        b.open(url)
        # Without this the page cannot read the clipboard at all and every
        # assertion below would fail for a reason that is not the feature.
        # Sent after the page exists, because the connection is to a page
        # target and there is no browser-level socket to send it on before.
        granted = b.call("Browser.grantPermissions", {
            "origin": origin,
            "permissions": ["clipboardReadWrite", "clipboardSanitizedWrite"]})
        if granted is None:
            bad("clipboard permission granted to the page",
                "Browser.grantPermissions was refused; readings below are "
                "about the permission, not the feature")
        else:
            ok("clipboard permission granted to the page", origin)
        b.wait_for("(document.getElementById('status-display')||{classList:"
                   "{contains:()=>false}}).classList.contains('hidden')",
                   lambda v: v is True, timeout=90)
        ok("the session is streaming", url)
        b.call("Page.bringToFront")

        print("\n  --- an image copied in the browser, pasted in the desktop ---")
        sess.put("STRING", b"sentinel-text-only")
        time.sleep(1.5)
        before = sess.targets()

        blob = base64.b64encode(png((220, 30, 90))).decode()
        wrote = b.eval("""(async () => {
          const bin = atob("%s");
          const u8 = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
          const blob = new Blob([u8], {type: 'image/png'});
          try {
            await navigator.clipboard.write([new ClipboardItem({'image/png': blob})]);
            return 'ok';
          } catch (e) { return 'ERR ' + e.message; }
        })()""" % blob, timeout=30)
        if str(wrote).startswith("ERR") or wrote is None:
            bad("the browser clipboard accepts an image", str(wrote))
        else:
            ok("the browser clipboard accepts an image", "%d bytes" % len(png((220, 30, 90))))

        # Nudge the client the way a user would: focus, then a paste keystroke.
        b.eval("window.dispatchEvent(new Event('focus'))")
        for mods, key in ((2, "v"),):
            b.call("Input.dispatchKeyEvent", {
                "type": "keyDown", "modifiers": mods, "key": key,
                "code": "KeyV", "windowsVirtualKeyCode": 86})
            b.call("Input.dispatchKeyEvent", {
                "type": "keyUp", "modifiers": mods, "key": key,
                "code": "KeyV", "windowsVirtualKeyCode": 86})
        time.sleep(4)

        after = sess.targets()
        img = [t for t in after if t.startswith("image/")]
        if img:
            data = sess.get(img[0])
            got = pixels(data)
            if got and got[2] == (220, 30, 90):
                ok("the image reaches the desktop clipboard",
                   "%s, %dx%d, rgb%s" % (img[0], got[0], got[1], got[2]))
            elif got:
                bad("the image reaches the desktop clipboard",
                    "arrived %dx%d rgb%s, expected rgb(220, 30, 90)" % got)
            else:
                bad("the image reaches the desktop clipboard",
                    "%s offered but %d bytes did not decode" % (img[0], len(data)))
        else:
            bad("the image reaches the desktop clipboard",
                "targets are %s" % (" ".join(after) or "(none)"))
        print("     targets before: %s" % (" ".join(before) or "(none)"))
        print("     targets after:  %s" % (" ".join(after) or "(none)"))

        print("\n  --- an image copied in the desktop, pasted in the browser ---")
        want = png((20, 120, 210))
        # A different colour from the outbound image on purpose: the browser
        # clipboard still holds that one, so "an image is present" would pass
        # without anything having crossed. Only these bytes prove it.
        sess.put("image/png", want)
        # Decoded, not merely present: the outbound image from the previous
        # stage is still on this clipboard, so "an image/png is offered" would
        # pass without this one ever having been written.
        staged = pixels(sess.get("image/png"))
        if staged and staged[2] == (20, 120, 210):
            ok("the desktop clipboard holds the image to be read",
               "%dx%d, rgb%s" % staged)
        else:
            bad("the desktop clipboard holds the image to be read",
                "clipboard shows %s -- the agent did not win ownership"
                % (("%dx%d rgb%s" % staged) if staged else "nothing decodable"))
        time.sleep(3)
        b.eval("window.dispatchEvent(new Event('focus'))")
        time.sleep(4)
        got = b.eval("""(async () => {
          try {
            const items = await navigator.clipboard.read();
            for (const i of items) {
              if (i.types.includes('image/png')) {
                const buf = new Uint8Array(await (await i.getType('image/png')).arrayBuffer());
                let s = ''; for (const x of buf) s += String.fromCharCode(x);
                return 'B64:' + btoa(s);
              }
            }
            return 'types: ' + items.map(i => i.types.join(',')).join(' | ');
          } catch (e) { return 'ERR ' + e.message; }
        })()""", timeout=30)
        if str(got).startswith("B64:"):
            got_px = pixels(base64.b64decode(str(got)[4:]))
            if got_px and got_px[2] == (20, 120, 210):
                ok("the desktop's image reaches the browser",
                   "%dx%d, rgb%s" % got_px)
            elif got_px:
                bad("the desktop's image reaches the browser",
                    "arrived %dx%d rgb%s, expected rgb(20, 120, 210) -- this is "
                    "the outbound image, not the one from the desktop" % got_px)
            else:
                bad("the desktop's image reaches the browser", "did not decode")
        else:
            bad("the desktop's image reaches the browser", str(got))

        print("\n  --- formatted text, browser to desktop ---")
        sess.put("STRING", b"plain-sentinel")
        wrote = b.eval("""(async () => {
          const html = new Blob(['<b>bold</b> and <i>italic</i>'], {type: 'text/html'});
          const txt  = new Blob(['bold and italic'], {type: 'text/plain'});
          try {
            await navigator.clipboard.write([new ClipboardItem(
              {'text/html': html, 'text/plain': txt})]);
            return 'ok';
          } catch (e) { return 'ERR ' + e.message; }
        })()""", timeout=30)
        if str(wrote) != "ok":
            bad("the browser clipboard accepts formatted text", str(wrote))
        else:
            ok("the browser clipboard accepts formatted text",
               "text/html + text/plain")
            b.eval("window.dispatchEvent(new Event('focus'))")
            time.sleep(4)
            t = sess.targets()
            body = sess.get("text/html").decode("utf-8", "replace") if "text/html" in t else ""
            if "text/html" in t and "<b>" in body:
                ok("formatting reaches the desktop", body[:40])
            elif "text/html" in t:
                bad("formatting reaches the desktop",
                    "text/html offered but holds %r" % body[:40])
            else:
                plain = sess.get("UTF8_STRING").decode("utf-8", "replace") or \
                    sess.get("STRING").decode("utf-8", "replace")
                bad("formatting reaches the desktop",
                    "only %s -- the desktop received %r, so the markup was "
                    "dropped" % (" ".join(t) or "(none)", plain[:40]))

        print("\n  --- formatted text ---")
        # Deliberately different markup from the outbound stage: the browser
        # clipboard still holds that, so "text/html is present" would pass
        # without anything having come back from the desktop.
        html = b"<u>underlined-from-the-desktop</u>"
        if not sess.can_offer("text/html"):
            print("  skip the desktop side of formatted text: this run drives the "
                  "clipboard through GTK,\n       which cannot offer arbitrary "
                  "targets. Re-run on a box with xclip for this stage.")
            return_html = True
        else:
            return_html = False
        if not return_html:
            sess.put("text/html", html)
            time.sleep(2)
            t = sess.targets()
            ok("the desktop can hold text/html", " ".join(t) or "(none)") \
                if "text/html" in t else \
                bad("the desktop can hold text/html", " ".join(t) or "(none)")
            b.eval("window.dispatchEvent(new Event('focus'))")
            time.sleep(3)
            got = b.eval("""(async () => {
              try {
                const items = await navigator.clipboard.read();
                return items.map(i => i.types.join(',')).join(' | ');
              } catch (e) { return 'ERR ' + e.message; }
            })()""", timeout=30)
            body = b.eval("""(async () => {
              try {
                const items = await navigator.clipboard.read();
                for (const i of items) {
                  if (i.types.includes('text/html'))
                    return await (await i.getType('text/html')).text();
                }
                return 'no text/html: ' + items.map(i => i.types.join(',')).join(' | ');
              } catch (e) { return 'ERR ' + e.message; }
            })()""", timeout=30)
            if body and "underlined-from-the-desktop" in str(body):
                ok("formatting survives into the browser", str(body)[:60])
            elif body and "text/html" in str(got or ""):
                bad("formatting survives into the browser",
                    "browser holds %r -- that is the outbound markup, not the "
                    "desktop's" % str(body)[:50])
            else:
                bad("formatting survives into the browser",
                    "browser sees %s" % str(body)[:60])
    finally:
        b.stop()
        browser.kill_strays()

    print("\n%d/%d checks passed" % (len(PASS), len(PASS) + len(FAIL)))


if __name__ == "__main__":
    main()
