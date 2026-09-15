#!/usr/bin/env python3
"""Read and write the session's X clipboard, from inside the session.

  clipagent.py targets
  clipagent.py get <target>        raw bytes to stdout
  clipagent.py put <target> <file> takes ownership and keeps it

xclip is deliberately not installed on these machines, and installing it to run
a test would change what is being tested: the server's clipboard monitor has an
xclip fallback path, so a box with xclip is not the box users have. GTK is
already present for the desktop itself, and talks to the same selections.

`put` must keep running. An X selection is served by its owner process, so a
tool that exits leaves the clipboard empty no matter what it just wrote.
"""
import sys

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GdkPixbuf, GLib  # noqa: E402


def clipboard():
    return Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)


def main():
    cmd = sys.argv[1]
    cb = clipboard()

    if cmd == "targets":
        ok, atoms = cb.wait_for_targets()
        print(" ".join(a.name() for a in atoms) if ok and atoms else "")
        return

    if cmd == "get":
        data = cb.wait_for_contents(Gdk.Atom.intern(sys.argv[2], False))
        if data is None:
            sys.exit(1)
        raw = data.get_data()
        sys.stdout.buffer.write(raw if raw is not None else b"")
        return

    if cmd == "put":
        target, path = sys.argv[2], sys.argv[3]
        payload = open(path, "rb").read()

        # Gtk.Clipboard.set_with_data is not introspectable, so arbitrary
        # targets cannot be offered from Python here. The two that matter are
        # both covered by typed setters; anything else is the xclip run's job.
        if target.startswith("image/"):
            loader = GdkPixbuf.PixbufLoader()
            loader.write(payload)
            loader.close()
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_image(
                loader.get_pixbuf())
        elif target in ("STRING", "UTF8_STRING", "text/plain"):
            cb.set_text(payload.decode("utf-8", "replace"), -1)
        else:
            sys.exit("cannot offer %s from GTK; use the xclip run" % target)

        cb.store()
        GLib.idle_add(lambda: (print("owned", flush=True), False)[1])
        Gtk.main()
        return

    sys.exit("usage: clipagent.py targets|get <t>|put <t> <file>")


if __name__ == "__main__":
    main()
