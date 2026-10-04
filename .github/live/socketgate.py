#!/usr/bin/env python3
"""Who may connect to a slot's socket -- asked by BUILDING the caller, not by looking for one.

  socketgate.py --router-group GROUP --proxy-group GROUP \\
                --ephemeral INSTANCE [--named INSTANCE] \\
                [--as-user ACCOUNT] [--neutral-group GROUP] \\
                [--only listening] [--red NAME] [--keep-slot]

Run as root, on the machine whose sessions you are asking about. Nothing about
any particular machine is written down here: every host, instance, account and
group is an argument, because this file ships publicly.

THE TRAP THIS FILE WAS WRITTEN FOR, and it is the reason the design looks the
way it does. An ephemeral slot is reached at a filesystem socket that the
router -- and nothing else on the box, the reverse proxy included -- is
supposed to be able to open. The obvious rig asks the machine: "enumerate the
processes that could connect, and show that only the router can." On our
development container that rig is GREEN TODAY, GREEN AFTER A FIX, AND GREEN
AFTER THE FIX IS REVERTED, because the reverse proxy runs on a different host
and its group has zero member processes here. It would be a check that cannot
fail, and one of those has never rejected anything.

So this file does not look for the excluded party. It MANUFACTURES it: a
transient unit carrying the group under test, running an unprivileged probe.
The credential under test is created rather than found, so the arm has
something to refuse whether or not anyone on this machine holds it.

WHAT THE KERNEL GATES ON, because it decides what may be asserted.
connect() to an AF_UNIX path is refused in two independent places -- search
permission on every directory component while the path is resolved, and WRITE
permission on the socket inode. Read permission on the socket is irrelevant;
write is the whole question. Only the directory can mask the socket, never the
other way round. Both refusals arrive as the same errno, so "it failed with
EACCES" does NOT establish that the gate under test is the one doing the work.
The discriminator is a stat() of the SAME path from the SAME credential in the
SAME probe: stat also fails -> the directory refused and the socket's own mode
was never consulted; stat succeeds -> the inode refused.

A PROBE THAT CANNOT SAY WHO IT WAS IS NOT EVIDENCE. A probe running as root
passes both gates forever, so before it touches the socket it asks the KERNEL
who it is -- os.getuid, os.getgid, os.getgroups, all three printed in its report
-- and refuses to continue if it is root, if it is wearing an identity under
test, if the group under test is absent, or if the group that must be excluded
is held. "I asked for uid N" is a different claim from "the kernel gave me uid
N", and the gap between them has already cost a live run here: a probing
identity collided with the account it was testing against, ran as root, and
returned a confident success that would have been published as the finding.

The identities it must not wear are DERIVED from the objects under examination
-- whoever owns the socket, whoever owns its directory, and whatever account
systemd says the slot's service runs as -- never from a list of names that
happen to be right today. See identities_under_test(), and --red as-root.

THE COMPOSITE IS MEASURED; THE TWO GATES ARE COMPUTED; THEY MUST AGREE.
A live connect() can only ever report whichever gate fired first, so it cannot
pin both -- and a check that pins one of two gates lets a later relaxation of
the other through in silence. So each gate is also evaluated from its own
st_mode and ownership, read as root, against the same (uid, gid, groups); the
run requires both computed verdicts AND requires the computed composite to
match what was measured. A disagreement is a finding in itself, not a rounding
error: it is what an ACL, a mount option or a namespace looks like from here.
Where an ACL is present the computation is refused outright and scored
UNDECIDED, because POSIX mode arithmetic quietly gives the wrong answer there.

THE ARMS, IN THIS ORDER, AND THE ORDER IS LOAD BEARING.

  0. IS ANYTHING LISTENING. Two oracles pointing opposite ways: `ss -lx`, for a
     listener the kernel has actually bound at this exact path -- a socket FILE
     is not a listener, and an orphan left on disk has been enumerated as a
     live slot on this project before -- and, for the ephemeral arm only, a
     connect() as root, which cannot be refused by permissions and so separates
     "nothing there" from "not for you". If this arm does not hold, every arm
     below it is SKIPPED. A refusal is indistinguishable from an empty socket.
  1. THE PERMITTED IDENTITY CONNECTS. The router's group, synthesised. If this
     fails, arms 2 and 3 are UNDECIDED and never PASS: an arm that cannot tell
     a locked door from an empty room has not measured a lock.
  2. THE EXCLUDED IDENTITY IS REFUSED, with the errno named. ENOENT, or a
     connection refused, is INCONCLUSIVE -- not a pass. Nothing there is not
     the same as not for you.
  3. BOTH GATES, INDEPENDENTLY, as described above.
  4. THE OTHER LEG STILL WORKS. The reverse proxy's group opens a NAMED
     session's socket. Without this arm, "chmod 000 everything" scores a clean
     sweep, and the thing the proxy is for stops working on the next deploy.

A COLD START IS A PASS, NOT A TIMEOUT. Connecting to a slot's socket activates
it and brings a desktop up, which takes tens of seconds. The connect() itself
returns as soon as systemd accepts, so the permitted arm is fast -- but the
slot is OCCUPIED afterwards, and a run that then asserts the pool is empty
fails for a reason that has nothing to do with this file. The occupancy before
and after is printed, and --keep-slot governs whether the arm releases what it
started. The release is refused outright for a slot that already had
established connections when the run began: see release_slot().

MAKING EACH ARM GO RED ON PURPOSE. A guard nobody has watched refuse is not
known to refuse, and on this project six guards written to fail were each shown
to be incapable of it. --red NAME sabotages one input and names the arm that
must then go red. Every one of these is a change to the RIG's arguments, not to
the machine, so they can be run back to back:

  --red as-root           the probe runs without dropping privilege.
                          RED: arm 1 and arm 2 both report "probe is root",
                          scored UNDECIDED. Nothing scores PASS. This is the
                          one that keeps every other arm honest.
  --red permitted-wrong   arm 1 runs with the EXCLUDED group instead.
                          RED: arm 1 FAILs, and arms 2-3 go UNDECIDED rather
                          than PASS -- which is the property being proved, not
                          arm 1's failure.
  --red excluded-allowed  arm 2 runs with the ROUTER's group.
                          RED: arm 2 FAILs on a successful connect. This is
                          today's shipping configuration written out as a
                          sabotage, so if arm 2 is green on a stock box, read
                          --print-cast before believing it.
  --red absent-socket     every arm is pointed at an instance name that does
                          not exist.
                          RED: arm 0 fails its precondition and arms 1-4 are
                          SKIPPED. A run reporting PASS here means the ENOENT
                          path is being scored as a refusal.
  --red compute-only      the measured composite is discarded and only the
                          computed gates are consulted.
                          RED: the agreement check in arm 3 reports UNDECIDED
                          for want of a measurement. It exists to show that the
                          agreement check is wired to the measurement at all.

Three more need the MACHINE changed, so they are documented rather than
implemented -- this file must not edit a deployment:

  * an orphaned socket file. As root:
      python3 -c 'import socket;s=socket.socket(socket.AF_UNIX);s.bind("DIR/NAME.sock")'
    (the process exits, the file stays). Point --ephemeral at NAME.
    RED: arm 0 reports a socket file with no listener, and everything below is
    SKIPPED. A green run here is the orphan-as-a-live-slot defect returning.
  * a group that does not exist. Set HDW4S_PROXY_GROUP to a name with no group
    record and re-run "hdw4s transport INSTANCE unix".
    RED: arm 0 reports the socket unit's own failure text and its result code.
    This is the whole reason arm 0 exists -- the unit does not bind, the slot is
    simply absent, and a rig asking only "can an outsider connect?" scores that
    ABSENCE AS A PASS. Ask what the broken state scores.
  * a colliding probe identity -- no flag needed, it is an argument. Pass
    --as-user with the slot's own account, or with whoever owns the socket.
    RED: the run REFUSES before arm 0, naming the uid and what it owns. A run
    that proceeds is the live defect above returning, and its symptom is a
    clean sweep rather than an error.
  * the directory relaxed. chmod 0755 on the slot directory where the fix made
    it tighter.
    RED: arm 3's directory half FAILs while the composite still passes, which
    is exactly the silent unpinning arm 3 exists to catch.

WHAT THIS FILE DOES NOT ESTABLISH, and no line of its output should be read as
claiming it. The identity it builds is a SYNTHETIC holder of a group, not the
router and not the reverse proxy. It shares their group membership and nothing
else -- not their unit's namespace, not its filters, not its own socket
activation. So a PASS here says the group is sufficient or insufficient; it
does not say the real component works, and --print-cast prints that sentence
beside the run so it cannot be quoted without it.
"""
import argparse
import errno
import grp
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys

# The four outcomes, and a precondition that is none of them. Spelled out here
# rather than imported from journey.py on purpose: that module imports the
# browser driver at module scope, and this rig has to run on a bare session
# host where nothing but python3 is guaranteed. Same words, same meanings --
# a check whose precondition did not hold is SKIPPED or UNDECIDED, NEVER passed.
PASS, FAIL, SKIP, UNDEC = "PASS", "FAIL", "SKIP", "UNDECIDED"

SENTINEL = "HDW4S-SOCKETGATE "

RED = ("none", "as-root", "permitted-wrong", "excluded-allowed",
       "absent-socket", "compute-only")

# Runs inside the transient unit, as the synthesised identity. Passed with
# python3 -c rather than left in a file: a transient unit can carry PrivateTmp=,
# ProtectSystem= or a namespace that hides a path, and a probe that fails to
# LOAD is indistinguishable at the exit status from a probe that ran and was
# refused -- which is the very answer this rig wants to hear, so it must not be
# obtainable by accident. Nothing secret is in it, so argv is an acceptable
# home; see wsprobe.credentials() for the case where it is not.
#
# argv: path, require_gid (-1 for none), forbid_gids (comma separated, may be
# empty), forbid_uids (comma separated, may be empty), timeout seconds.
PROBE = r"""
import errno, json, os, socket, sys
path, req, forbid, badu, tmo = (sys.argv[1], int(sys.argv[2]), sys.argv[3],
                                sys.argv[4], float(sys.argv[5]))
forbid = set(int(x) for x in forbid.split(",") if x)
badu = set(int(x) for x in badu.split(",") if x)
r = {"uid": os.getuid(), "gid": os.getgid(), "groups": sorted(os.getgroups())}
held = set(r["groups"]) | {r["gid"]}
r["held"] = sorted(held)
# THE PROBE SAYS WHO IT ACTUALLY IS BEFORE IT SAYS ANYTHING ABOUT THE SOCKET,
# and it asks the KERNEL, not its own arguments. "I asked for uid N" is not the
# same claim as "the kernel gave me uid N", and the difference has already cost
# a live run on this project: a probe whose identity collided with the account
# it was testing against ran as root and returned a confident success, which
# would have been published as the finding. It was caught by a positive control
# standing beside it, not by anything the probe itself said.
#
# So: uid 0 is refused, the identity UNDER TEST is refused, the group under test
# must be held, and the group that must not be held is checked for. The
# credential is in the report either way, so a reader can see who spoke.
if r["uid"] == 0:
    r["refused"] = "probe is running as root; both gates pass for root regardless"
elif r["uid"] in badu:
    r["refused"] = ("probe resolved to uid %d, which is an identity UNDER TEST "
                    "-- it would be testing the socket against its own owner"
                    % r["uid"])
elif req >= 0 and req not in held:
    r["refused"] = "required group %d is not held (have %s)" % (req, r["held"])
elif forbid & held:
    r["refused"] = "forbidden group(s) %s are held" % sorted(forbid & held)
if "refused" not in r:
    # stat() first and from this same credential: it is the discriminator
    # between the two gates, and it is worthless taken from anywhere else.
    try:
        os.stat(path)
        r["stat"] = "ok"
    except OSError as e:
        r["stat"] = errno.errorcode.get(e.errno, str(e.errno))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(tmo)
    try:
        s.connect(path)
        r["connect"] = "ok"
    except OSError as e:
        r["connect"] = errno.errorcode.get(e.errno, str(e.errno))
    except Exception as e:
        r["connect"] = "error:" + type(e).__name__
    finally:
        s.close()
sys.stdout.write("%s%s\n" % (SENTINEL, json.dumps(r)))
""".replace("SENTINEL", repr(SENTINEL))

rows = []


def record(name, outcome, detail=""):
    rows.append((name, outcome, detail))
    print("  %-9s %-44s %s" % (outcome, name, detail), flush=True)
    return outcome == PASS


def sh(argv, timeout=30):
    """Exit status and output. The verdict is never taken from matching text.

    A command that searches a machine for its own argument matches itself --
    pgrep and pkill -f both do, and so does anything piped into grep with the
    thing it is looking for on its own command line. Every caller below reads
    the exit status or parses a field it addressed by position.
    """
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


# --------------------------------------------------------------------------
# What the machine says


def gid_of(name):
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def identity(user, neutral_group, extra_gid):
    """The (uid, gid, groups) the transient unit below will actually carry.

    Group= is named explicitly rather than left to the account's own primary
    group, because a probe whose primary group happens to BE the group under
    test cannot test anything, and because systemd's group list differs
    depending on whether Group= was given. Derived, never assumed: the probe
    re-reads its own credential and refuses if it is not this one.
    """
    ent = pwd.getpwnam(user)
    gid = grp.getgrnam(neutral_group).gr_gid
    groups = sorted({gid} | ({extra_gid} if extra_gid is not None else set()))
    return ent.pw_uid, gid, groups


def identities_under_test(sockpath, rundir, ephem):
    """Every uid this rig must NOT be wearing, DERIVED from what it examines.

    Not from a list of names that happen to be right today. A name is a wrong
    answer waiting for a second deployment to exist, and on this project a
    probing identity that collided with the account under test ran as root and
    returned a confident success -- which would have been published as the
    finding, and was caught only because a positive control stood beside it.

    So the set is read off the objects themselves: whoever owns the socket,
    whoever owns the directory holding it, and whatever account systemd says
    the slot's own service runs as. Returns {uid: why}.
    """
    out = {0: "root, which passes both gates unconditionally"}
    for path, what in ((sockpath, "owns the socket"),
                       (rundir, "owns the directory holding it")):
        try:
            out.setdefault(os.stat(path).st_uid, what + " (%s)" % path)
        except OSError:
            pass
    for unit in ("hdw4s-ephemeral@%s.service" % ephem,
                 "hdw4s@%s.service" % ephem,
                 "hdw4s-proxy@%s.service" % ephem):
        name = unit_property(unit, "User")
        if not name:
            continue
        try:
            out.setdefault(pwd.getpwnam(name).pw_uid,
                           "the account %s runs as (%s)" % (unit, name))
        except KeyError:
            pass
    return out


def unit_property(unit, prop):
    rc, out, _ = sh(["systemctl", "show", "-p", prop, "--value", unit])
    return out if rc == 0 else ""


def bound_listeners():
    """Paths at which the kernel holds a LISTENING unix socket, as a set.

    `ls` answers a question about the filesystem; "is anything bound" is a
    question for the kernel, and the two have disagreed here -- an orphaned
    socket file was enumerated as a live slot while connect() was refused.
    This reads `ss -lx` and takes the last whitespace field of each row, which
    is the path, rather than searching the output for a name.
    """
    rc, out, err = sh(["ss", "-H", "-l", "-x"])
    if rc != 0:
        return None, err or "ss -H -l -x exited %d" % rc
    paths = set()
    for line in out.splitlines():
        fields = line.split()
        if not fields:
            continue
        # Trailing "* NNNN" peer column on some builds; the path is the last
        # field that looks like one.
        for f in reversed(fields):
            if f.startswith("/") or f.startswith("@"):
                paths.add(f)
                break
    return paths, ""


def gate_verdict(path, uid, gid, groups, want_bit):
    """Would this credential pass ONE gate? Computed from ownership and mode.

    want_bit is stat.S_IXUSR for a directory's search permission or S_IWUSR for
    the socket inode's write permission; the group and other bits are derived
    from it by shifting, so the three classes cannot drift apart by a typo.

    Returns (True|False|None, why). None means REFUSED TO COMPUTE, which is not
    a pass: an ACL overrides the group bits entirely, and mode arithmetic over
    one gives a confident wrong answer.
    """
    try:
        st = os.stat(path)
    except OSError as e:
        return None, "stat: %s" % errno.errorcode.get(e.errno, e.errno)
    try:
        if "system.posix_acl_access" in os.listxattr(path):
            return None, "an ACL is present; mode arithmetic does not decide this"
    except OSError:
        pass  # no xattr support, or not permitted: fall through to the mode.
    if uid == st.st_uid:
        bit, whose = want_bit, "owner"
    elif st.st_gid in set(groups) | {gid}:
        bit, whose = want_bit >> 3, "group"
    else:
        bit, whose = want_bit >> 6, "other"
    ok = bool(st.st_mode & bit)
    return ok, "%s %s:%s %04o -> %s bits %s" % (
        path, owner_name(st.st_uid), group_name(st.st_gid),
        stat.S_IMODE(st.st_mode), whose, "grant" if ok else "deny")


def owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def directory_gate(path, uid, gid, groups):
    """Every component from / down must grant search, so every one is asked.

    Only the directory can mask the socket, never the reverse, so a single
    denying component anywhere on the path is the whole answer and the socket's
    own mode is never consulted.
    """
    parts, cur, seen = path.strip("/").split("/")[:-1], "", []
    for part in parts:
        cur = cur + "/" + part
        ok, why = gate_verdict(cur, uid, gid, groups, stat.S_IXUSR)
        seen.append((cur, ok, why))
        if ok is not True:
            return ok, why, seen
    return True, "every component grants search", seen


# --------------------------------------------------------------------------
# Manufacturing the absent party


def probe_as(path, uid_user, neutral_group, require_gid, forbid_gids,
             forbid_uids=(), timeout=25, as_root=False):
    """Run the probe under a synthesised credential and return its report.

    The positive control and the refusal arm go through THIS function with the
    same unit shape, differing only in the group. That is deliberate and it is
    what makes the comparison mean anything: whatever a transient unit's
    sandbox does to a connect(), it does to both arms, so a difference between
    them is attributable to the group and not to systemd. The sandbox knobs are
    turned OFF here as well, so that a namespace cannot produce the refusal
    this rig is trying to attribute to a permission bit.
    """
    unit = ["systemd-run", "--wait", "--collect", "--pipe", "--quiet"]
    if not as_root:
        unit += ["-p", "User=%s" % uid_user, "-p", "Group=%s" % neutral_group]
        if require_gid is not None:
            unit += ["-p", "SupplementaryGroups=%s" % group_name(require_gid)]
    unit += ["-p", "PrivateTmp=no", "-p", "ProtectSystem=no",
             "-p", "ProtectHome=no", "-p", "PrivateMounts=no"]
    argv = unit + ["--", sys.executable or "/usr/bin/python3", "-c", PROBE,
                   path, str(-1 if require_gid is None else require_gid),
                   ",".join(str(g) for g in sorted(forbid_gids)),
                   ",".join(str(u) for u in sorted(forbid_uids)), str(timeout)]
    rc, out, err = sh(argv, timeout=timeout + 30)
    for line in reversed(out.splitlines()):
        if line.startswith(SENTINEL):
            return json.loads(line[len(SENTINEL):]), rc, err
    return None, rc, (err or out or "the probe printed no report")


# --------------------------------------------------------------------------
# Arms


def arm_listening(sockpath, unit, listeners, lerr):
    """Arm 0. Before any refusal is believed, something must be listening.

    A configuration naming a group that does not exist makes the socket unit
    fail to bind, and the slot is then simply ABSENT. A guard asking only "can
    an outsider connect?" scores that absence as a pass, which is why this arm
    runs first and why its failure SKIPS everything below rather than failing
    it: the rig has learnt nothing about permissions either way.
    """
    exists = os.path.exists(sockpath)
    st_desc = ""
    if exists:
        st = os.stat(sockpath)
        st_desc = "%s:%s %04o %s" % (
            owner_name(st.st_uid), group_name(st.st_gid),
            stat.S_IMODE(st.st_mode),
            "socket" if stat.S_ISSOCK(st.st_mode) else "NOT A SOCKET")

    if listeners is None:
        record("0. something is listening", UNDEC,
               "ss could not be read: %s" % lerr)
        return False

    bound = sockpath in listeners
    if bound and exists:
        record("0. something is listening", PASS, "%s  %s" % (sockpath, st_desc))
        return True

    # Everything below here is a reason to stop, and each says which.
    load = unit_property(unit, "LoadState")
    active = unit_property(unit, "ActiveState")
    result = unit_property(unit, "Result")
    why = "unit %s: Load=%s Active=%s Result=%s" % (unit, load or "?",
                                                    active or "?", result or "?")
    if exists and not bound:
        record("0. something is listening", FAIL,
               "socket FILE present (%s) with NO listener bound -- an orphan; %s"
               % (st_desc, why))
    else:
        record("0. something is listening", FAIL,
               "no socket at %s; %s" % (sockpath, why))
    rc, out, _ = sh(["journalctl", "-u", unit, "-n", "12", "--no-pager",
                     "-o", "cat"])
    if rc == 0 and out:
        print("    what the unit last said:")
        for line in out.splitlines()[-12:]:
            print("      " + line)
    else:
        print("    the unit's journal could not be read; run journalctl -u %s"
              % unit)
    return False


def arm_permitted(sockpath, args, router_gid, proxy_gid, red):
    """Arm 1. The permitted identity connects, and it goes FIRST.

    A refusal measured against a socket nobody can reach is not a refusal, so
    until this arm holds, arms 2 and 3 have no oracle.
    """
    use_gid = proxy_gid if red == "permitted-wrong" else router_gid
    rep, rc, err = probe_as(sockpath, args.as_user, args.neutral_group,
                            use_gid, {proxy_gid} - {use_gid},
                            forbid_uids=args.forbid_uids,
                            as_root=(red == "as-root"))
    if rep is None:
        return record("1. the permitted identity connects", UNDEC,
                      "no report from the probe (rc=%d): %s" % (rc, err)), None
    if "refused" in rep:
        return record("1. the permitted identity connects", UNDEC,
                      "the probe refused itself: %s" % rep["refused"]), rep
    if rep.get("connect") == "ok":
        return record("1. the permitted identity connects", PASS,
                      "group %s, uid %d" % (group_name(use_gid), rep["uid"])), rep
    return record("1. the permitted identity connects", FAIL,
                  "group %s: connect=%s stat=%s" % (group_name(use_gid),
                                                    rep.get("connect"),
                                                    rep.get("stat"))), rep


def arm_excluded(sockpath, args, router_gid, proxy_gid, red, permitted_ok):
    """Arm 2. The excluded identity is refused, with the errno named.

    ENOENT and ECONNREFUSED are INCONCLUSIVE and never a pass: an orphan and a
    missing file both keep an outsider out, and neither is the isolation this
    rig is asked about.
    """
    if not permitted_ok:
        record("2. the excluded identity is refused", UNDEC,
               "arm 1 did not hold; a refusal here would prove nothing")
        return None
    use_gid = router_gid if red == "excluded-allowed" else proxy_gid
    rep, rc, err = probe_as(sockpath, args.as_user, args.neutral_group,
                            use_gid, {router_gid} - {use_gid},
                            forbid_uids=args.forbid_uids,
                            as_root=(red == "as-root"))
    if rep is None:
        record("2. the excluded identity is refused", UNDEC,
               "no report from the probe (rc=%d): %s" % (rc, err))
        return None
    if "refused" in rep:
        record("2. the excluded identity is refused", UNDEC,
               "the probe refused itself: %s" % rep["refused"])
        return rep
    got, sta = rep.get("connect"), rep.get("stat")
    if got == "ok":
        record("2. the excluded identity is refused", FAIL,
               "group %s CONNECTED; the socket is not isolated from it"
               % group_name(use_gid))
    elif got in ("EACCES", "EPERM"):
        which = ("the DIRECTORY refused: stat also failed (%s), so the socket's"
                 " own mode was never consulted" % sta) if sta != "ok" else \
                "the INODE refused: stat succeeded, so the path resolved"
        record("2. the excluded identity is refused", PASS,
               "group %s: %s -- %s" % (group_name(use_gid), got, which))
    elif got == "ENOENT":
        record("2. the excluded identity is refused", UNDEC,
               "ENOENT: nothing at the path for this credential. Absence is "
               "not isolation -- see arm 0")
    elif got == "ECONNREFUSED":
        record("2. the excluded identity is refused", UNDEC,
               "ECONNREFUSED: the file is reachable and nothing is listening. "
               "An orphan, not a refusal")
    else:
        record("2. the excluded identity is refused", UNDEC,
               "connect=%s stat=%s -- neither a grant nor a permission refusal"
               % (got, sta))
    return rep


def arm_both_gates(sockpath, args, proxy_gid, measured, red):
    """Arm 3. Each gate pinned on its own, and pinned against the measurement.

    A composite connect() reports whichever gate fired first, so on its own it
    cannot keep the other from being relaxed later without anybody noticing.
    Both are therefore computed from ownership and mode, AND the computed
    composite is required to agree with what arm 2 measured.
    """
    uid, gid, groups = identity(args.as_user, args.neutral_group, proxy_gid)

    d_ok, d_why, seen = directory_gate(sockpath, uid, gid, groups)
    if d_ok is None:
        record("3a. the directory refuses the outsider", UNDEC, d_why)
    else:
        record("3a. the directory refuses the outsider",
               PASS if d_ok is False else FAIL,
               ("denies at " if d_ok is False else "GRANTS search: ") + d_why)

    i_ok, i_why = gate_verdict(sockpath, uid, gid, groups, stat.S_IWUSR)
    if i_ok is None:
        record("3b. the socket inode refuses the outsider", UNDEC, i_why)
    else:
        record("3b. the socket inode refuses the outsider",
               PASS if i_ok is False else FAIL,
               ("write denied: " if i_ok is False else "WRITE GRANTED: ") + i_why)
    # Every component that was consulted, printed whether or not one denied:
    # "the directory refused" is a claim about a specific directory, and the
    # reader has to be able to see WHICH.
    for _component, _ok, why in seen:
        print("      path: %s" % why)

    if red == "compute-only" or measured is None or "refused" in (measured or {}):
        record("3c. computed and measured agree", UNDEC,
               "no usable measurement to compare the computation against")
        return
    if d_ok is None or i_ok is None:
        record("3c. computed and measured agree", UNDEC,
               "a gate could not be computed; nothing to compare")
        return
    computed_grant = bool(d_ok) and bool(i_ok)
    measured_grant = measured.get("connect") == "ok"
    if computed_grant == measured_grant:
        record("3c. computed and measured agree", PASS,
               "both say %s" % ("grant" if computed_grant else "deny"))
    else:
        record("3c. computed and measured agree", FAIL,
               "mode arithmetic says %s, the kernel said %s -- something "
               "outside the mode bits is deciding this (ACL, mount option, "
               "namespace, LSM)" % ("grant" if computed_grant else "deny",
                                    "grant" if measured_grant else "deny"))


def arm_other_leg(sockpath, args, proxy_gid, router_gid, listeners):
    """Arm 4. Locking everything down must not be a way to score a clean sweep.

    The reverse proxy reaches a NAMED session over exactly this kind of socket,
    and that leg is supposed to keep working. Without this arm, chmod 000 on
    the whole directory passes arms 2 and 3 and breaks the product.
    """
    if sockpath is None:
        record("4. the proxy still reaches a named session", SKIP,
               "no --named instance given; the leg was not exercised")
        return
    if listeners is not None and sockpath not in listeners:
        record("4. the proxy still reaches a named session", UNDEC,
               "nothing is listening at %s -- see arm 0's reasoning" % sockpath)
        return
    rep, rc, err = probe_as(sockpath, args.as_user, args.neutral_group,
                            proxy_gid, {router_gid} - {proxy_gid},
                            forbid_uids=args.forbid_uids)
    if rep is None:
        record("4. the proxy still reaches a named session", UNDEC,
               "no report from the probe (rc=%d): %s" % (rc, err))
    elif "refused" in rep:
        record("4. the proxy still reaches a named session", UNDEC,
               "the probe refused itself: %s" % rep["refused"])
    elif rep.get("connect") == "ok":
        record("4. the proxy still reaches a named session", PASS,
               "group %s reaches %s" % (group_name(proxy_gid), sockpath))
    else:
        record("4. the proxy still reaches a named session", FAIL,
               "group %s: connect=%s stat=%s -- the leg the proxy needs is shut"
               % (group_name(proxy_gid), rep.get("connect"), rep.get("stat")))


# --------------------------------------------------------------------------
# The slot this run occupies


def established(sockpath):
    """How many connections are up on this socket right now.

    Counted before arm 1 and again after, because arm 1 ACTIVATES the slot and
    a later run that expects an empty pool would otherwise blame the product.
    """
    rc, out, _ = sh(["ss", "-H", "-x", "state", "established"])
    if rc != 0:
        return None
    return sum(1 for line in out.splitlines()
               if sockpath in line.split())


def release_slot(unit, before):
    """Stop what this run started -- and refuse to, if it was not ours.

    A slot that already had an established connection when the run began may be
    somebody's desktop. Stopping that is not this file's to do, and "it was
    probably idle" is not a measurement.
    """
    if before:
        print("  NOT releasing %s: it had %d established connection(s) before "
              "this run began, so the desktop may not be ours to stop."
              % (unit, before))
        return
    rc, _, err = sh(["systemctl", "stop", unit])
    print("  released %s (rc=%d)%s" % (unit, rc, (": " + err) if err else ""))


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--router-group", required=True,
                    help="the group the component that routes visitors runs in;"
                         " it MUST reach an ephemeral slot")
    ap.add_argument("--proxy-group", required=True,
                    help="the group the reverse proxy runs in; it must NOT"
                         " reach an ephemeral slot, but must reach a named one")
    ap.add_argument("--ephemeral", required=True,
                    help="an ephemeral slot instance name")
    ap.add_argument("--named", default=None,
                    help="a named session instance, for arm 4")
    ap.add_argument("--rundir", default=None,
                    help="the directory holding the slot sockets; read from"
                         " the socket unit when not given")
    ap.add_argument("--as-user", default="nobody",
                    help="an unprivileged account to synthesise the probe as;"
                         " it is verified to exist and not to be uid 0")
    ap.add_argument("--neutral-group", default="nogroup",
                    help="the probe's primary group, which must be neither of"
                         " the two under test")
    ap.add_argument("--only", choices=("listening", "all"), default="all",
                    help="listening: run arm 0 alone, and nothing that could"
                         " activate a slot")
    ap.add_argument("--red", choices=RED, default="none",
                    help="sabotage one input and watch the named arm go red;"
                         " see this file's docstring")
    ap.add_argument("--keep-slot", action="store_true",
                    help="leave the slot arm 1 activated running")
    ap.add_argument("--print-cast", action="store_true",
                    help="print what was exercised and what was stood in for")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("socketgate.py: needs root, on the session host itself -- it "
                 "reads the modes of both gates and creates transient units.")
    for tool in ("systemd-run", "systemctl", "ss"):
        if shutil.which(tool) is None:
            sys.exit("socketgate.py: %s is not on this machine." % tool)

    router_gid, proxy_gid = gid_of(args.router_group), gid_of(args.proxy_group)
    for name, gid in (("--router-group", router_gid), ("--proxy-group", proxy_gid)):
        if gid is None:
            sys.exit("socketgate.py: no group record for %s. A socket unit "
                     "naming a group that does not exist FAILS TO BIND and the "
                     "slot is then absent, which a refusal check scores as a "
                     "pass -- so this is fatal here rather than a skip."
                     % name.split()[-1])
    try:
        uid = pwd.getpwnam(args.as_user).pw_uid
    except KeyError:
        sys.exit("socketgate.py: no account %r to synthesise as." % args.as_user)
    if uid == 0:
        sys.exit("socketgate.py: --as-user %r is uid 0. A root probe passes "
                 "both gates forever and every arm would be green." % args.as_user)
    neutral = gid_of(args.neutral_group)
    if neutral is None:
        sys.exit("socketgate.py: no group %r." % args.neutral_group)
    if neutral in (router_gid, proxy_gid):
        sys.exit("socketgate.py: --neutral-group is one of the two under test; "
                 "the probe would hold it before any arm ran.")

    print("socketgate.py -- who may open a slot's socket, by building the caller")
    print("  router group : %s (gid %d)" % (args.router_group, router_gid))
    print("  proxy  group : %s (gid %d)" % (args.proxy_group, proxy_gid))
    print("  probe as     : %s (uid %d), primary group %s"
          % (args.as_user, uid, args.neutral_group))
    if args.red != "none":
        print("  RED ARM      : %s -- an arm is EXPECTED to fail below" % args.red)

    # The two groups being the same group is not a configuration this rig can
    # measure around: there is no identity that holds one and not the other, so
    # the isolation does not exist and no arm below could report its absence.
    if router_gid == proxy_gid:
        print()
        record("the two groups are distinct", FAIL,
               "%s and %s are BOTH gid %d -- one group, so nothing separates "
               "the router from the reverse proxy and no arm below can be run"
               % (args.router_group, args.proxy_group, router_gid))
        print("\nsocketgate.py: 1 failure.")
        return 1

    ephem = args.ephemeral if args.red != "absent-socket" else \
        args.ephemeral + "-no-such-instance"
    esock_unit = "hdw4s-proxy@%s.socket" % ephem
    rundir = args.rundir
    if rundir is None:
        # Derived from the unit, never from a constant: a constant is a wrong
        # answer waiting for a second deployment to exist.
        listen = unit_property(esock_unit, "Listen")
        m = re.search(r"(/\S+)/[^/]+\.sock", listen or "")
        rundir = m.group(1) if m else "/run/hdw4s/proxy"
        print("  socket dir   : %s (%s)"
              % (rundir, "from %s" % esock_unit if m else "FALLBACK -- the unit "
                 "named no filesystem address; pass --rundir"))
    esock = os.path.join(rundir, ephem + ".sock")
    nsock = os.path.join(rundir, args.named + ".sock") if args.named else None

    # WHO THIS RIG MUST NOT BE, derived from the objects it is about to examine
    # rather than from a list of names. A probing identity that collides with
    # the account under test has already produced a confident success on this
    # project -- it silently ran as root and returned 200, and only a positive
    # control standing beside it caught that. The refusal is here, before any
    # arm, AND again inside the probe, because only the probe can see what the
    # kernel actually gave it: this half can be fooled by nsswitch, that half
    # cannot.
    under_test = identities_under_test(esock, rundir, ephem)
    args.forbid_uids = sorted(under_test)
    if uid in under_test:
        sys.exit("socketgate.py: --as-user %r is uid %d, which %s. A probe "
                 "wearing an identity under test measures nothing -- and the "
                 "way that fails is a confident PASS, not an error."
                 % (args.as_user, uid, under_test[uid]))
    print("  not to be   : " + ", ".join(
        "%s (%d)" % (owner_name(u), u) for u in args.forbid_uids))
    print()

    listeners, lerr = bound_listeners()
    up = arm_listening(esock, esock_unit, listeners, lerr)

    if args.only == "listening":
        print("\n--only listening: arms 1-4 not run, and no slot was activated.")
    elif not up:
        for n in ("1. the permitted identity connects",
                  "2. the excluded identity is refused",
                  "3a. the directory refuses the outsider",
                  "3b. the socket inode refuses the outsider",
                  "3c. computed and measured agree",
                  "4. the proxy still reaches a named session"):
            record(n, SKIP, "arm 0 did not hold")
    else:
        before = established(esock)
        ok, _ = arm_permitted(esock, args, router_gid, proxy_gid, args.red)
        measured = arm_excluded(esock, args, router_gid, proxy_gid, args.red, ok)
        arm_both_gates(esock, args, proxy_gid, measured, args.red)
        arm_other_leg(nsock, args, proxy_gid, router_gid, listeners)
        after = established(esock)
        print("\n  established connections on %s: %s before, %s after."
              % (esock, before, after))
        print("  A cold start is a PASS of arm 1, not a timeout -- the slot is "
              "now OCCUPIED, and a later run expecting an empty pool will fail "
              "for that reason and not for a defect.")
        if ok and not args.keep_slot:
            release_slot("hdw4s-ephemeral@%s.service" % ephem, before)

    if args.print_cast:
        print("\nWhat was exercised, and what was stood in for:")
        print("  REAL   : the socket, its directory, their ownership and modes,")
        print("           and the kernel's own answer to connect().")
        print("  STOOD  : the router and the reverse proxy. Neither ran. A")
        print("    IN     transient unit holding the same GROUP stood in for")
        print("           each. This rig says the group is sufficient or not;")
        print("           it does not say either component works.")
        print("  ASSUMED: that group membership is the whole of the decision.")
        print("           Settle it by running the real component against a")
        print("           socket this rig has just shown it is refused at.")

    bad = [r for r in rows if r[1] == FAIL]
    und = [r for r in rows if r[1] == UNDEC]
    print("\nsocketgate.py: %d failure(s), %d undecided, %d skipped."
          % (len(bad), len(und), len([r for r in rows if r[1] == SKIP])))
    if args.red != "none":
        print("A --red run is CORRECT when the arm named in the docstring is "
              "the one that failed. Zero failures here means the sabotage was "
              "not noticed, which is the finding.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
