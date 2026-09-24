#!/usr/bin/env python3
"""Nothing on the router's observation path may ACT on the pool.

  .github/observer-purity.py check [<file>]      report, and exit non-zero
  .github/observer-purity.py selftest [<file>]   plant each violation, watch it go red

WHAT THIS IS FOR. hdw4s-demux answers two questions on every arrival -- "which
slot may I hand out" (pick_slot) and "is the desktop this record describes still
the one behind that slot" (session_replaced). The slots those questions are
about are SOCKET-ACTIVATED. Opening one is not a way of asking whether it is
alive; it is the way to MAKE it alive. A startup banner that connect()ed to each
slot to report reachability started a full GNOME desktop on every free slot and
then reported correctly, because it had made its own report true. Measured three
times, and slot_unreachable()'s docstring carries the account.

The repair was written down as prose -- "os.path.isdir, and nothing else", with
a paragraph asking the next person not to reach for something that opens. A rig
built against that warning still created its stand-in directory on accept, and
brought all three slots into existence occupied. A warning that has already been
ignored once is not a guard.

WHY THIS IS NOT A SOCKET CHECK. The obvious form of this check bans connect()
and socket(). It would have gone GREEN on the rig that motivated it, because
that rig failed by CREATING A DIRECTORY, not by connecting. A check that cannot
fail for the defect it was built for is worse than no check, so the ban is on
opening and creating in general, and the permission to do either is a table with
a reason beside each entry.

WHY IT PARSES RATHER THAN GREPS. A grep for "connect" is satisfied by a comment
saying the word, and defeated by a line break. This project has met a check
satisfiable by a comment naming the right thing twice. ast sees calls; it does
not see comments or strings at all.

HOW THE SET OF OBSERVERS IS DECIDED, and this is the part that must not become a
list somebody maintains. Only the two ROOTS are named here, because which
questions the router asks on arrival is a decision rather than a fact. Everything
they reach is DERIVED: the observers are the transitive closure of module-level
functions called from those roots. A helper added under pick_slot tomorrow is
covered the day it is added, by nobody remembering anything. The selftest proves
that by planting a violation in a function that does not exist yet.

WHAT IT CANNOT SEE, stated because an unwritten blind spot gets read as
exhaustive:

  * A method call on an object it did not watch being made -- up.connect() is
    invisible on its own. It is caught one step earlier instead: the socket had
    to come from socket.socket(), which is a call in a scanned namespace. The
    same is true of a file handle, which needs open().
  * Anything reached through getattr or eval. An import is NOT a gap: `from os
    import makedirs`, with or without an alias, and `import os.path as p` are
    both resolved back to what they really are, because a bare name is in no
    acting namespace and would otherwise sail through.
  * Anything a function calls in ANOTHER module. The closure stops at this file.
  * forward_request() is deliberately outside the closure. It exists to connect;
    that is not the observation path and banning it there would be nonsense.
    That the roots do not reach it is asserted, so that a future edit which wires
    them together is reported rather than silently widening this exemption to the
    whole proxy.
"""

import ast
import os
import subprocess
import sys
import tempfile

# The two questions the router asks on arrival. INTENT, not a fact: no analysis
# can decide which entry points are "the observation path", so these are named,
# and everything reachable from them is derived. Both are asserted to exist, so
# a rename lands here as a failure rather than as an empty scan that prints "ok".
ROOTS = ("pick_slot", "session_replaced")

# The one function that is allowed to act on a slot, and is therefore expected
# NOT to be reachable from the roots. Named so that its absence from the closure
# is an assertion rather than an accident.
ACTOR = "forward_request"

# Namespaces that can act on the world. A call whose dotted name begins with one
# of these -- or the bare builtins below -- must appear in PERMITTED or in
# EXEMPT, or it is a finding.
#
# An ALLOW-list over exactly the acting namespaces, rather than a deny-list of
# dangerous calls, because a deny-list fails OPEN: the next dangerous call is the
# one nobody thought to list, and os.mkdir, shutil.rmtree, pathlib.Path().touch
# and socket.create_connection are four spellings of the same defect. Ordinary
# code -- sorted(), time.time(), a set's .add() -- is not in an acting namespace
# and is not scanned, which is what keeps this table small enough to read.
ACTING_PREFIXES = ("os.", "io.", "shutil.", "socket.", "subprocess.",
                   "pathlib.", "tempfile.", "fcntl.", "signal.")
ACTING_BUILTINS = ("open", "exec", "eval", "compile", "__import__", "getattr")

# Primitives that answer a question about the filesystem without touching it.
# Each one is here because it CANNOT create, open or connect -- not because it
# happens to be in use today.
PERMITTED = {
    "os.path.join": "builds a string; touches nothing",
    "os.path.isdir": "a stat. The occupancy authority, and the whole reason this"
                     " file exists: it opens nothing and activates nothing",
    "os.path.exists": "a stat",
    "os.path.dirname": "builds a string",
    "os.path.basename": "builds a string",
    "os.listdir": "reads a directory's names; creates nothing in it",
    "os.stat": "a stat",
    "os.access": "asks the kernel about permission; does not open",
    "os.environ.get": "reads this process's own environment",
}

# Where an acting call is allowed anyway, by function and by call, each with the
# reason it cannot start a desktop. Checked in BOTH directions: an entry naming a
# call that no longer occurs is a failure, because a stale exemption reads as a
# considered decision about live code and nothing else will ever surface it.
EXEMPT = {
    ("listening_paths", "open"):
        "reads /proc/net/unix, a table the kernel writes. It names no slot and"
        " opening it starts nothing. This is the instrument that REPLACED the"
        " connect() probe, so banning it here would ban the repair.",
    ("slot_incarnation", "open"):
        "reads the published token out of the WEB ROOT, which is an ordinary"
        " directory served by the session -- not the socket. Opening a file"
        " there cannot activate a slot. Read-only, and the value may only ever"
        " cause a refusal.",
    ("slot_table", "open"):
        "reads /etc/hdw4s/instances, the root-owned configuration file that says"
        " which slots exist and what type each one is. It is an ordinary file in"
        " /etc: it is not a socket, it is not under /run, nothing is activated"
        " by reading it, and a visitor cannot write it. It is on the arrival"
        " path DELIBERATELY -- this is the repair that stopped the mint path"
        " deciding the pool from a directory listing, where a named desktop's"
        " leftover socket was enumerated as ephemeral capacity. Banning it here"
        " would ban that repair, exactly as it would have banned"
        " listening_paths() above.",
}


def dotted(call):
    """The dotted name of a call's callee, or '' if it is not a plain name."""
    f = call.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if not isinstance(f, ast.Name):
        return ""
    parts.append(f.id)
    return ".".join(reversed(parts))


def aliases_of(tree):
    """{local name: the dotted name it really is}, from every import in the file.

    Without this the whole scan is defeated by one line: `from os import
    makedirs` binds a BARE name, which is in no acting namespace and would sail
    through. `import os.path as p` is the same evasion wearing a different hat.
    Neither is exotic -- they are the two ordinary ways of shortening a call --
    so the check has to resolve what a name refers to rather than read the
    spelling at the call site.

    Imports anywhere are collected, including inside a function, because an
    import in the body of the very function being scanned is the form somebody
    reaches for when a module-level one looks out of place.
    """
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                out[a.asname or a.name] = "%s.%s" % (n.module, a.name)
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    out[a.asname] = a.name
    return out


def canonical(name, aliases):
    """NAME with its first segment resolved through the import table."""
    parts = name.split(".")
    if parts[0] in aliases:
        parts[0:1] = aliases[parts[0]].split(".")
    return ".".join(parts)


def is_acting(name):
    if name in ACTING_BUILTINS:
        return True
    return any(name.startswith(p) for p in ACTING_PREFIXES)


def functions_of(tree):
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def closure(funcs, roots):
    """Every module-level function reachable from ROOTS, roots included.

    Walks calls by name. A call to something that is not a module-level function
    in this file -- a method, a builtin, another module -- simply is not an edge,
    which is the honest bound: this is a map of THIS file.
    """
    seen = set()
    todo = [r for r in roots if r in funcs]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for call in ast.walk(funcs[name]):
            if not isinstance(call, ast.Call):
                continue
            callee = dotted(call)
            if callee in funcs and callee not in seen:
                todo.append(callee)
    return seen


def check(path):
    """Findings, as a list of strings. Empty means the file is clean."""
    out = []
    try:
        with open(path, "r") as f:
            tree = ast.parse(f.read(), filename=path)
    except (OSError, SyntaxError) as e:
        # A detector that could not run says so. Silence here would read exactly
        # like a clean sweep, which is the one thing it must not.
        return ["could not read or parse %s (%s), so NOTHING was checked --"
                " this is not a clean result" % (path, e)]

    funcs = functions_of(tree)
    for r in ROOTS:
        if r not in funcs:
            out.append("%s is named as an entry point of the observation path"
                       " and no such function exists in %s; the scan below"
                       " covers less than it claims" % (r, path))
    if ACTOR not in funcs:
        out.append("%s is named as the one function allowed to act on a slot and"
                   " no such function exists; its exemption now covers nothing"
                   % ACTOR)

    observers = closure(funcs, ROOTS)
    if not observers:
        return out + ["no observation path was found at all, so this check"
                      " examined nothing"]

    if ACTOR in observers:
        out.append("%s is reachable from %s, so the function that exists to"
                   " CONNECT is now on the path that must only observe"
                   % (ACTOR, " or ".join(ROOTS)))

    used = set()
    aliases = aliases_of(tree)
    for name in sorted(observers):
        for call in ast.walk(funcs[name]):
            if not isinstance(call, ast.Call):
                continue
            callee = canonical(dotted(call), aliases)
            if not callee or not is_acting(callee):
                continue
            if callee in PERMITTED:
                continue
            if (name, callee) in EXEMPT:
                used.add((name, callee))
                continue
            out.append(
                "%s() calls %s at line %d, and %s is on the path the router"
                " walks on every arrival. Nothing there may open, connect to or"
                " create anything: these slots are socket-activated, so asking"
                " is how you start a desktop. If this call genuinely cannot act"
                " on a slot, add it to PERMITTED or EXEMPT in %s with the reason"
                % (name, callee, call.lineno, name, os.path.basename(__file__)))

    # The other direction, and it is the one that rots quietly. An exemption
    # naming a call that has been removed or renamed still reads as a considered
    # decision about live code; nothing else will ever surface it, because the
    # thing it describes is not there to contradict it.
    for key in sorted(EXEMPT):
        if key not in used:
            fn, callee = key
            if fn not in observers:
                out.append("EXEMPT allows %s() to call %s, and %s() is no longer"
                           " on the observation path at all; the exemption is"
                           " describing something that has moved or gone"
                           % (fn, callee, fn))
            else:
                out.append("EXEMPT allows %s() to call %s, and it no longer does;"
                           " the exemption is describing code that has been"
                           " removed or renamed" % (fn, callee))
    return out


def cmd_check(path):
    found = check(path)
    for line in found:
        print("FAIL: %s" % line)
    if not found:
        tree = ast.parse(open(path).read(), filename=path)
        obs = sorted(closure(functions_of(tree), ROOTS))
        # The set is PRINTED, because "ok" over an empty or shrunken closure is
        # the way this check would fail green. A reader who sees two names where
        # there were ten knows something is wrong; a reader who sees "ok" does
        # not.
        print("observation path clean (%d function(s): %s)"
              % (len(obs), ", ".join(obs)))
    return 1 if found else 0


# ------------------------------------------------------------------ selftest --
# Every arm below is planted in a COPY of the file under test, never by editing
# this checker. A red arm that mutates the checker along with the code proves
# nothing, and this project has already had one: a blunt substitution changed a
# checker's own literal and came up green against a genuinely broken build.

def plant(src, old, new):
    """Return SRC with OLD replaced once, or None if OLD is not there.

    Returning None rather than the unchanged text is the difference between an
    arm that fires and an arm that reports success for a substitution that never
    happened -- which is how a planted violation silently becomes a green run.
    """
    if old not in src:
        return None
    return src.replace(old, new, 1)


def cmd_selftest(path):
    with open(path, "r") as f:
        original = f.read()
    fail = 0
    tmp = tempfile.mkdtemp(prefix="observer-purity-")
    copy = os.path.join(tmp, "subject")
    self_path = os.path.abspath(__file__)

    def run(label, want, text, match=None):
        nonlocal fail
        if text is None:
            print("%-52s FAIL: the violation could not be planted -- the text"
                  " this arm edits has changed, so it proved nothing" % label)
            fail = 1
            return
        with open(copy, "w") as f:
            f.write(text)
        p = subprocess.run([sys.executable, self_path, "check", copy],
                           capture_output=True, text=True)
        out = p.stdout + p.stderr
        if want == "red":
            # A non-zero status alone is not the check going red: a script that
            # dies on an unrelated error also exits non-zero and reads as a
            # successful proof. It has to have SAID what it found -- and, where
            # MATCH is given, said it about the right thing, because a contrived
            # edit can violate two rules at once.
            if p.returncode != 0 and "FAIL:" in out and \
               (match is None or match in out):
                print("%-52s ok (went red, and said why)" % label)
                return
            if p.returncode != 0 and match is not None and match not in out:
                print("%-52s FAIL: went red, but not for %r" % (label, match))
            elif p.returncode != 0:
                print("%-52s FAIL: exited %d without reporting a failure: it"
                      " crashed, it did not fire" % (label, p.returncode))
            else:
                print("%-52s FAIL: the violation was planted and the check"
                      " passed anyway" % label)
        else:
            if p.returncode == 0:
                print("%-52s ok (passed clean)" % label)
                return
            print("%-52s FAIL: wanted green, got exit %d" % (label, p.returncode))
        fail = 1
        for line in out.splitlines():
            print("      %s" % line)

    try:
        # The green control first. Without it every arm below could be red for a
        # reason that has nothing to do with what it plants.
        run("tree as it stands", "green", original)

        # 1. The original defect, exactly: a connect on the occupancy path.
        run("a socket opened in slot_occupied", "red",
            plant(original,
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n",
                  "    socket.socket()\n"
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n"),
            match="slot_occupied() calls socket.socket")

        # 2. THE ARM THIS CHECK EXISTS FOR. The rig that ignored the warning
        #    failed by CREATING A DIRECTORY, not by connecting, so a check that
        #    banned only sockets would have gone green on the very defect it was
        #    written for.
        run("a directory created in slot_occupied", "red",
            plant(original,
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n",
                  "    os.makedirs(os.path.join(rundir or '/', instance),"
                  " exist_ok=True)\n"
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n"),
            match="slot_occupied() calls os.makedirs")

        # 3. A plain open() where nothing is exempt. The occupancy directory is
        #    0700 and owned by the session, so an open there is both useless and
        #    the shape of the next mistake.
        run("a file opened in occupancy_readable", "red",
            plant(original,
                  "    return os.path.isdir(SESSION_RUNDIR if rundir is None"
                  " else rundir)",
                  "    open('/dev/null').close()\n"
                  "    return os.path.isdir(SESSION_RUNDIR if rundir is None"
                  " else rundir)"),
            match="occupancy_readable() calls open")

        # 3b. THE ONE-LINE EVASION. A bare name is in no acting namespace, so
        #     `from os import makedirs as mk` defeats a scan that reads the
        #     spelling at the call site -- and it is not an exotic trick, it is
        #     one of the two ordinary ways of shortening a call. The import
        #     table is resolved for exactly this, and the arm is planted with an
        #     ALIAS as well so that a resolver which only handled the plain form
        #     would still be caught.
        run("an acting call imported under another name", "red",
            plant(original,
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n",
                  "    from os import makedirs as mk\n"
                  "    mk(instance)\n"
                  "    root = SESSION_RUNDIR if rundir is None else rundir\n"),
            match="slot_occupied() calls os.makedirs")

        # 4. THE DERIVATION, not the list. A helper that does not exist today is
        #    added, called from a root, and acts. Nothing names it anywhere; it
        #    is caught because the observers are computed from the roots. If this
        #    arm ever goes green, the closure has silently become a fixed list.
        run("a NEW helper called from pick_slot", "red",
            plant(original,
                  "def pick_slot(own):\n",
                  "def warm_the_slot(instance):\n"
                  "    return shutil.rmtree(instance)\n"
                  "\n"
                  "\n"
                  "def pick_slot(own):\n"
                  "    warm_the_slot('x')\n"),
            match="warm_the_slot() calls shutil.rmtree")

        # 5. A stale exemption. The permission outlives the call it was written
        #    for, and then covers whatever is written next under that name.
        run("an exemption whose call has gone", "red",
            plant(original,
                  'with open(os.path.join(base, instance, "hdw4s-incarnation"), "r") as f:',
                  'with _not_open(os.path.join(base, instance, "hdw4s-incarnation")) as f:'),
            match="EXEMPT allows slot_incarnation()")

        # 6. A root that has been renamed. The scan would otherwise cover less
        #    than it claims while still printing a clean line.
        run("a renamed entry point", "red",
            plant(original, "def pick_slot(own):", "def choose_slot(own):"),
            match="pick_slot is named as an entry point")

        # 7. The proxy wired into the observation path. forward_request exists to
        #    connect; the assertion is that the arrival path does not reach it.
        run("the actor reachable from a root", "red",
            plant(original,
                  "    taken = slots_in_use(own, pool)\n",
                  "    taken = slots_in_use(own, pool)\n"
                  "    if False:\n"
                  "        forward_request(None, None, None, None, None, None,"
                  " None, None)\n"),
            match="forward_request is reachable")

        # 8. And the quiet half: the arms above prove it fires. This proves it
        #    stops firing, so that a check only ever seen to go red -- which is
        #    a check that is switched off within a week -- is not what we have.
        run("tree as it stands, again", "green", original)
    finally:
        try:
            os.unlink(copy)
        except OSError:
            pass
        os.rmdir(tmp)
    return fail


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(os.path.dirname(here), "hdw4s-demux")
    cmd = argv[1] if len(argv) > 1 else ""
    path = argv[2] if len(argv) > 2 else default
    if cmd == "check":
        return cmd_check(path)
    if cmd == "selftest":
        return cmd_selftest(path)
    sys.stderr.write("usage: %s check [<file>] | selftest [<file>]\n" % argv[0])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
