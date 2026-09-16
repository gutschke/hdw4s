#!/usr/bin/env python3
"""What a session can and cannot do, as a matrix over capability bounding sets.

  .github/live/privileges.py [--user ACCOUNT] [--set 'CAP_A CAP_B' ...]

Run as root, on the machine whose sessions you are asking about.

The two session types ship different answers to the same question -- what may a
program in this desktop do that its own uid would not allow -- and the answer is
one systemd directive each. A directive is easy to change and its consequences
are not obvious: `CapabilityBoundingSet=` does not say which commands stop
working, and the commands that stop working do not say why.

So this runs the commands. For each bounding set it executes every operation in
a transient unit as the session's own account, and prints the exit status
side by side. A column that differs is a capability doing something; a column
that matches everywhere is a capability buying nothing, which is the case worth
finding, because an unused capability is only a liability.

WHY THE REASON IS RECORDED AND NOT JUST THE STATUS. The first version of this
matrix was written by hand and three of its nine rows were wrong in the same
direction: `traceroute` "failed" because the gateway does not answer its probes,
`crontab -l` "failed" because the account has no crontab, and `fusermount3`
"passed" because `-V` prints a version without mounting anything. Each looked
like a capability result and none was. A matrix of bare pass and fail is worse
than no matrix, because it reads as evidence. Every row here carries the exit
status and the first line the command said, and rows whose failure is expected
for a reason unrelated to capabilities are marked as such in the table rather
than left for the reader to misread.

Setuid and setgid are not the same question and the table keeps them apart. A
setgid binary receives its group from `execve` and never calls a capability, so
`CAP_SETGID` does nothing for it; the same is true of `euid 0` and `CAP_SETUID`.
Those two capabilities matter only where a program changes identity *after*
exec, which on a desktop means sudo and its relatives -- meaningful for an
account that may legitimately use them, and dead weight for one that may not.
"""
import argparse
import shutil
import subprocess
import sys

# Each row: the label, the command, and what it is expected to exercise.
#
# "needs" names the capability the operation would require, or None where the
# operation is here as a control -- something that must keep working, so that a
# run where everything fails is visibly a broken harness rather than a result.
OPERATIONS = [
    ("ping (file cap NET_RAW)", ["ping", "-c1", "-W2", "127.0.0.1"], "CAP_NET_RAW",
     "a file capability, granted only if it is inside the bounding set"),
    ("traceroute [setuid root]", ["traceroute", "-m", "1", "-w", "1", "127.0.0.1"], "CAP_NET_RAW",
     "reaches the network; an unanswered probe is not a capability failure"),
    ("crontab -l [setgid crontab]", ["crontab", "-l"], None,
     "setgid binaries take their group from execve, not from CAP_SETGID"),
    ("postqueue -p [setgid]", ["postqueue", "-p"], None, "as above"),
    ("ssh-keygen", ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", "/tmp/privprobe", "-q"], None,
     "a control: must work everywhere"),
    ("id", ["id"], None, "a control: must work everywhere"),
    ("sudo -n true", ["sudo", "-n", "true"], "CAP_SETUID",
     "needs both the capability AND sudo rights; says nothing for an account with neither"),
    ("newgrp [setuid root]", ["newgrp", "nogroup"], "CAP_SETGID",
     "no desktop calls this; here to show the capability's only other consumer"),
    ("mount --bind", ["mount", "--bind", "/tmp", "/tmp"], "CAP_SYS_ADMIN",
     "expected to fail: CAP_SYS_ADMIN is deliberately outside every set here"),
    ("unshare --user --mount", ["unshare", "--user", "--mount", "true"], None,
     "the path Chrome's namespace sandbox takes; must work or the browser is unsandboxed"),
    ("unshare --mount (no userns)", ["unshare", "--mount", "true"], "CAP_SYS_ADMIN",
     "the path the setuid sandbox helper takes; expected to fail"),
]


def run_under(bounding_set, user, argv, timeout=15):
    """Run one command in a transient unit with the given bounding set.

    Returns (status, first_line). stdin is closed: several of these prompt for
    a password when they cannot do their job, and a matrix that hangs on row
    seven is not a matrix.
    """
    unit = ["systemd-run", "--wait", "--collect", "--pipe", "--quiet",
            "-p", f"User={user}",
            "-p", f"CapabilityBoundingSet={bounding_set}",
            "-p", "PrivateTmp=yes"]
    try:
        p = subprocess.run(unit + ["--"] + argv, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", "no answer within %ds" % timeout)
    out = (p.stderr or p.stdout or "").strip().splitlines()
    return ("ok" if p.returncode == 0 else f"rc={p.returncode}",
            out[0][:60] if out else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--user", default="ephemeral0",
                    help="the account to run as; use a slot, never a real person")
    ap.add_argument("--set", action="append", dest="sets",
                    help="a bounding set to test; repeat for a matrix")
    args = ap.parse_args()

    sets = args.sets or [
        "CAP_NET_RAW CAP_SETUID CAP_SETGID",   # what both units ship today
        "CAP_NET_RAW",                          # the proposal for ephemeral slots
        "",                                     # the floor, to show what NET_RAW buys
    ]

    if shutil.which("systemd-run") is None:
        sys.exit("privileges.py: needs systemd-run, and root, on the session's own machine")

    missing = [o[0] for o in OPERATIONS if shutil.which(o[1][0]) is None]
    print(f"account: {args.user}")
    if missing:
        print(f"not installed here, rows will say so: {', '.join(missing)}")
    print()

    width = max(len(o[0]) for o in OPERATIONS)
    print(" " * (width + 2) + "  ".join(f"{s or '(empty)':<34}" for s in sets))
    differing = []
    for label, argv, needs, note in OPERATIONS:
        if shutil.which(argv[0]) is None:
            print(f"{label:<{width}}  " + "  ".join(f"{'not installed':<34}" for _ in sets))
            continue
        cells, results = [], []
        for s in sets:
            status, why = run_under(s, args.user, argv)
            # The REASON is part of the result, not decoration. sudo fails under
            # every set here, but it fails with "a password is required" where
            # CAP_SETUID is present and "unable to change to root" where it is
            # not -- the capability is plainly doing something, and a comparison
            # on exit status alone calls that row identical and moves on.
            results.append((status, why))
            cells.append(f"{status} {why}"[:33])
        print(f"{label:<{width}}  " + "  ".join(f"{c:<34}" for c in cells))
        if len(set(results)) > 1:
            differing.append((label, needs, results))

    print()
    print("Rows that DIFFER between sets -- these are the capabilities earning their place:")
    if differing:
        for label, needs, results in differing:
            same_status = len({r[0] for r in results}) == 1
            how = "same status, DIFFERENT REASON" if same_status else "different status"
            print(f"  {label}  ({needs or 'no capability named'}) -- {how}:")
            for status, why in results:
                print(f"      {status:<6} {why}")
    else:
        print("  none. Every operation behaved identically under every set above,")
        print("  so the capabilities that differ between them are buying nothing here.")
    print()
    print("A row that fails everywhere is not evidence about capabilities; read the")
    print("reason beside it. See this file's docstring for the three that caught us.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
