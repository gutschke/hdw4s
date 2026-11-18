#!/usr/bin/env python3
"""Every command a shipped script runs comes from a package hdw4s depends on.

    .github/command-deps.py [debian/control] [debian/install]

The "dependencies exist" check asks the opposite question -- is every declared
package in the archive -- and so it could not see that mount(8) had been run
since the first release without "mount" ever being declared, or that a new
script began running pasta. "mount" is Priority: required but not Essential, so
a system without it is legal, and the first anybody would hear of it is a
desktop that will not start.

The table names the non-Essential packages whose commands we run. A command
that is not in the table is not checked, so adding a script that runs
something new means adding its row here -- the point of the table is that the
row is written once, beside the reason, not rediscovered from a bug report.
Essential packages (bash, coreutils, util-linux's nsenter, libc-bin's getent)
need no declaration and have no row.

Prints one line per missing package and exits 1; prints nothing and exits 0
when every command it found is covered.
"""
import glob
import os
import re
import sys

# command -> package that ships it on Ubuntu 24.04 (dpkg -S, read on noble).
TABLE = {
    "mount": "mount", "umount": "mount",
    "ip": "iproute2", "ss": "iproute2",
    "nft": "nftables",
    "pasta": "passt",
    "curl": "curl",
    "xdotool": "xdotool",
    "xauth": "xauth",
    "xrandr": "x11-xserver-utils",
    "dconf": "dconf-cli",
    "gsettings": "libglib2.0-bin", "gdbus": "libglib2.0-bin",
    "pgrep": "procps", "pkill": "procps",
    "systemctl": "systemd", "systemd-run": "systemd",
}

control = sys.argv[1] if len(sys.argv) > 1 else "debian/control"
install = sys.argv[2] if len(sys.argv) > 2 else "debian/install"
root = os.path.dirname(os.path.abspath(install)) + "/.."


def depends(path):
    """The hdw4s package's Depends, every alternative of every entry."""
    text = open(path).read()
    stanza = re.search(r"^Package: hdw4s\n(.*?)(?:\n\n|\Z)", text, re.S | re.M).group(1)
    m = re.search(r"^Depends:(.*?)(?=^\S)", stanza + "\nX:", re.S | re.M)
    names = set()
    for entry in m.group(1).split(","):
        for alt in entry.split("|"):
            alt = alt.strip().split(" ")[0].split("(")[0]
            if alt and not alt.startswith("$"):
                names.add(alt)
    return names


def shipped(path):
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for f in glob.glob(os.path.join(root, line.split()[0])):
            if os.path.isfile(f):
                yield f


# A command WORD in shell: at the start of a command, after a separator or a
# substitution, or after the keywords that begin one. In python: argv[0] of a
# list literal. Comments are dropped first, so "mount point" in prose is not
# a call.
SH_START = r"(?:^|[;&|({]|\$\(|\b(?:then|do|else|exec|!|if|while|until|timeout\s+\S+|nsenter\s+[^;|&]*?))\s*"


def commands(f):
    try:
        text = open(f, errors="replace").read()
    except OSError:
        return set()
    first = text.split("\n", 1)[0]
    found = set()
    path = r"(?:/usr)?/s?bin/%s"
    if "python" in first:
        # argv[0] of a list or tuple literal, or the command's full path in any
        # string -- hdw4s-netns runs pasta through PASTA = ".../usr/bin/pasta",
        # which the first version of this check could not see.
        for cmd in TABLE:
            c = re.escape(cmd)
            if re.search(r'[\[(,]\s*"%s"' % c, text) or re.search(r'"%s"' % (path % c), text):
                found.add(cmd)
    elif first.startswith("#!") and ("sh" in first):
        code = "\n".join(re.sub(r"(^|\s)#.*$", "", l) for l in text.split("\n"))
        for cmd in TABLE:
            c = re.escape(cmd)
            if (re.search(SH_START + c + r"(?=\s|$|;)", code, re.M) or
                    re.search(r"(?<![\w.-])%s(?=\s|$|;|\")" % (path % c), code, re.M)):
                found.add(cmd)
    return found


have = depends(control)
missing = {}
for f in shipped(install):
    for cmd in commands(f):
        pkg = TABLE[cmd]
        if pkg not in have:
            missing.setdefault(pkg, set()).add("%s (%s)" % (os.path.basename(f), cmd))
for pkg in sorted(missing):
    print("%s: run by %s" % (pkg, ", ".join(sorted(missing[pkg]))))
sys.exit(1 if missing else 0)
