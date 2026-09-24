#!/usr/bin/python3
"""Do the tool and the router agree about what a setting MEANS?

    .github/setting-grammar.py [repository root]

WHY THIS EXISTS AS A CLASS CHECK RATHER THAN A TEST FOR ONE SETTING.

HDW4S_IDLE_DAYS was read by two components that parsed it differently. The tool
took systemd's unit letters -- "30d", "12h", "90m" -- validated them at "set"
time and wrote them into the conf file. The router read the same line with
int(), caught the ValueError, and used seven days. So a value the tool had
accepted, and that the sample configuration and the manual both told the
administrator to type, was silently discarded by the component whose behaviour
depended on it. Nothing failed anywhere: the conf file said one thing, the
router did another, and both looked healthy.

Writing a test for that one setting would have caught that one setting. The
shape of the defect is not specific to it: any value an administrator writes
down is read by at least one component that validates it and at least one that
acts on it, and nothing made those two agree. So this derives the settings in
that position and checks all of them, and a setting that joins the class later
is checked without anybody remembering to add it.

THE CORPUS IS THE DOCUMENTATION, deliberately. The values probed here are the
ones our own sample configuration and manual tell an administrator to type,
scraped out of those files rather than listed here. "Anything documented must
be possible to do" then has something that can actually fail: a form we print
in an example and a component cannot honour is exactly what this reports. A
hand-written corpus would have been written by whoever wrote the parser, and
would have contained the forms that parser takes.

THE TWO POSITIVE CONTROLS matter as much as the comparison. An empty class and
an empty corpus both produce a clean, confident pass, and they are the most
likely way for this to stop working -- a refactor renames conf_value(), the
scrape finds nothing, and this reports that every setting agrees. So the class
and the corpus are each asserted to contain a member we know is there, and the
run fails if either comes back empty.
"""

import os
import re
import subprocess
import sys
import tempfile

# A member of each derived set that we know is there. Not a list of what the
# sets should contain -- the point of deriving them is that nobody maintains
# such a list -- but a single known positive, so that a derivation which has
# quietly stopped finding anything is reported instead of passing.
KNOWN_KEY = "HDW4S_IDLE_DAYS"
KNOWN_VALUE = "30d"

# Which members of the class have ever been seen to FAIL this check, and on
# what. A green line is worth what the red behind it was worth, and a reader
# six months from now cannot recover that from a column of passes: a check that
# has only ever been pointed at correct code is not known to reject anything.
# So the distinction is printed rather than remembered, and a setting that
# joins the class arrives marked as never having been seen to fail -- which is
# the truth about it, and an invitation to break it on purpose once.
EVER_RED = {
    "HDW4S_IDLE_DAYS":
        "the tree that shipped it: the tool read 30d as 2592000 seconds and "
        "the router as 604800, and the router took 7x, 0x and '30d 30d' "
        "silently as 604800 too",
}

# Where a documented value can be written down. The manual is generated from
# the Markdown, so both are read: they are checked against each other
# elsewhere, and reading only one here would make this depend on that check
# having run.
DOC_FILES = ("hdw4s.conf", "hdw4s.8.md", "hdw4s.8", "hdw4s")

findings = []
notes = []


def finding(text):
    findings.append(text)


# --------------------------------------------------------------------------
# The class: settings BOTH components read
# --------------------------------------------------------------------------

def class_members(root):
    """Every setting the router reads out of a conf file.

    Derived from the router's own source rather than listed, because a list
    here would be correct until the next time somebody adds a conf read to it
    -- which is the moment this check is most needed and least likely to be
    remembered.
    """
    src = open(os.path.join(root, "hdw4s-demux"), "r", errors="replace").read()
    return sorted(set(re.findall(r'conf_value\([^()]*,\s*"([A-Z0-9_]+)"\s*\)',
                                 src)))


def settable_rules(root):
    """{key: rule} from the tool's own SETTABLE table.

    The rule is what the tool calls the setting's grammar -- "duration",
    "number", "size". It is read out of the table rather than restated so that
    the two cannot drift; a key whose rule this cannot find is reported rather
    than skipped.
    """
    src = open(os.path.join(root, "hdw4s"), "r", errors="replace").read()
    body = re.search(r"declare -A SETTABLE=\((.*?)\n\)", src, re.S)
    if not body:
        return {}
    out = {}
    for key, rule in re.findall(r"\[([A-Z0-9_]+)\]='([^']*)'", body.group(1)):
        out[key] = rule
    return out


# --------------------------------------------------------------------------
# The corpus: values we tell people to type
# --------------------------------------------------------------------------

def documented_values(root, key):
    """Every value written after KEY= anywhere we document it.

    Assignments only. Prose naming the key is not a value somebody can type,
    and including it would fill the corpus with sentences.
    """
    seen = []
    for name in DOC_FILES:
        path = os.path.join(root, name)
        try:
            text = open(path, "r", errors="replace").read()
        except OSError:
            continue
        for v in re.findall(re.escape(key) + r"=([^\s'\"\\]+)", text):
            v = v.rstrip(".,;:)")
            if v and v not in seen and not v.startswith("$"):
                seen.append(v)
    return seen


def hostile_variants(values):
    """Values the tool must refuse, derived from ones it must accept.

    A corpus of good values alone cannot see the defect that produced this
    check. The router did not merely mis-read a good value: it swallowed a
    BAD one and answered with a plausible number, so a typo and a decision
    were indistinguishable. Appending a letter that is not a unit to each
    documented value gives every setting in the class a value that must be
    refused, without this file knowing anything about any setting's grammar.
    """
    out = []
    for v in values:
        for bad in (v + "x", v + " " + v):
            if bad not in out:
                out.append(bad)
    return out


# --------------------------------------------------------------------------
# Asking the tool
# --------------------------------------------------------------------------

class Tool:
    """The CLI's own validator, loaded the way its test suite loads it.

    The dispatcher is cut off so that sourcing the script does not run a
    command, which is the same trick .github/tests.sh uses; doing it any other
    way would be a second way of loading the same file.
    """

    def __init__(self, root):
        self.root = root
        # The scripts resolve their siblings under this. Set here so that the
        # tool being asked is the one in THIS tree: without it an installed
        # copy answers, and the check compares the package against the working
        # tree while appearing to compare the working tree against itself.
        os.environ["HDW4S_LIBDIR"] = root
        self.tmp = tempfile.mkdtemp(prefix="grammar-tool-")
        src = open(os.path.join(root, "hdw4s"), "r", errors="replace").read()
        cut = src.find('\ncase "${1:-}" in')
        self.lib = os.path.join(self.tmp, "lib.sh")
        with open(self.lib, "w") as f:
            f.write(src if cut < 0 else src[:cut] + "\n")

    def accepts(self, key, value):
        """(accepted, why). The grammar only: check_value, not the policy
        guards that sit beside it. "0 is refused for an ephemeral slot" is a
        decision about what a readable value means, and the router is entitled
        to read it and then be told it is not allowed."""
        r = subprocess.run(
            ["bash", "-c",
             ". '%s'\ntrap - ERR\ncheck_value '%s' \"$1\"" % (self.lib, key),
             "x", value],
            capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    def seconds(self, value):
        r = subprocess.run(
            ["bash", "-c",
             ". '%s'\ntrap - ERR\nidle_seconds \"$1\" || exit 1\n"
             "printf '%%s' \"${IDLE_SECONDS}\"" % self.lib, "x", value],
            capture_output=True, text=True)
        if r.returncode != 0:
            return None
        return int(r.stdout.strip())


# --------------------------------------------------------------------------
# Asking the router
# --------------------------------------------------------------------------

def load_router(root):
    import importlib.machinery
    import importlib.util
    path = os.path.join(root, "hdw4s-demux")
    loader = importlib.machinery.SourceFileLoader("demux_mod", path)
    spec = importlib.util.spec_from_loader("demux_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def router_reads_duration(router, key, value, tmp):
    """What the router makes of a conf file that says KEY=VALUE, in seconds.

    THROUGH THE CONF FILE, not by calling the parser. An earlier version of
    this asked the router's parsing function directly, and that version would
    have passed a router whose parser was perfect and whose conf-reading path
    still swallowed the failure and substituted a week -- which is where the
    fallback actually lived. Measured: reinstating that one fallback left this
    check green while the router's own suite went red. The grammar is not the
    part that was broken; the path from the file to the number is.

    Raises when the router cannot read it. "Cannot read" includes answering
    None, which is how the router says so: an unreadable value must be
    distinguishable from a chosen one at every step, and a check that accepted
    None as an answer would be agreeing with a silence.
    """
    router.ETC_DIR = tmp
    router.SITE_CONF = os.path.join(tmp, "hdw4s.conf")
    router.SLOTS_FILE = os.path.join(tmp, "instances")
    with open(router.SLOTS_FILE, "w") as f:
        f.write("0 probe ephemeral\n")
    with open(os.path.join(tmp, "probe.conf"), "w") as f:
        f.write("%s=%s\n" % (key, value))
    with open(router.SITE_CONF, "w") as f:
        f.write("")
    said = []
    rows = dict((i, s) for i, s in router.idle_windows(complain=said.append))
    if "probe" not in rows:
        raise ValueError("the router did not read the slot at all")
    if rows["probe"] is None:
        raise ValueError("refused: %s" % ("; ".join(said) or "no reason given"))
    return rows["probe"]


# What each of the tool's grammars is asked for, on both sides, so that
# "agree" means the same NUMBER and not merely the same verdict. A rule with
# no entry here is reported rather than skipped: a setting joining the class
# with a grammar nobody taught this about is precisely the next instance of
# the defect, and passing it over would be the silence this check exists to
# remove.
#
# The router's side of each pair is a reader this file drives end to end,
# and it is deliberately unit-explicit: the defect was possible at all because
# the router worked in whole days, so a window of twelve hours had no
# representation in it before it was ever parsed.
QUANTITY = {
    "duration": ("seconds", "idle_windows", router_reads_duration),
}


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    keys = class_members(root)
    rules = settable_rules(root)
    router = load_router(root)
    tool = Tool(root)

    print("== settings both the tool and the router read ==")
    print("search space: conf_value() calls in hdw4s-demux, against the")
    print("              SETTABLE table in hdw4s; values scraped from %s"
          % ", ".join(DOC_FILES))

    # POSITIVE CONTROL on the class. An empty derivation reports that every
    # setting agrees, which is the same output as success.
    if KNOWN_KEY not in keys:
        finding("the class derivation found %d setting(s) and not %s, which is "
                "known to be in it -- the derivation is broken, not the class "
                "empty" % (len(keys), KNOWN_KEY))
        keys = []
    else:
        notes.append("class: %d setting(s): %s" % (len(keys), ", ".join(keys)))

    for key in keys:
        rule = rules.get(key)
        if rule is None:
            finding("%s is read by the router but is not in the tool's "
                    "SETTABLE table, so nothing validates what is written "
                    "into it" % key)
            continue
        good = documented_values(root, key)
        # POSITIVE CONTROL on the corpus, per key.
        if key == KNOWN_KEY and KNOWN_VALUE not in good:
            finding("the corpus for %s does not contain %s, which our own "
                    "documentation tells an administrator to type -- the "
                    "scrape is broken" % (key, KNOWN_VALUE))
            continue
        if not good:
            finding("%s has no documented value anywhere, so nothing here can "
                    "be compared -- either it is undocumented or the scrape "
                    "is broken" % key)
            continue
        notes.append("%s (%s): %d documented value(s): %s"
                     % (key, rule, len(good), ", ".join(good)))

        if rule not in QUANTITY:
            finding("%s has grammar '%s', which this check does not know how "
                    "to ask either side about; teach it before shipping a "
                    "setting both components read" % (key, rule))
            continue
        unit, exported, ask = QUANTITY[rule]
        if not callable(getattr(router, exported, None)):
            finding("the router exports no %s(), so nothing here can ask it "
                    "what it makes of a conf file, and it cannot be compared "
                    "with the tool at all. %s is documented as taking values "
                    "like %s, and a component that cannot express them cannot "
                    "honour them." % (exported, key, ", ".join(good)))
            continue
        probe = tempfile.mkdtemp(prefix="grammar-router-")

        def reader(v, _key=key, _probe=probe):
            return ask(router, _key, v, _probe)

        for value in good:
            want = tool.seconds(value) if rule == "duration" else None
            ok, why = tool.accepts(key, value)
            if not ok:
                finding("%s=%s is documented and the tool refuses it: %s"
                        % (key, value, why.splitlines()[0] if why else ""))
                continue
            try:
                got = reader(value)
            except Exception as e:
                finding("%s=%s is documented, the tool accepts it as %s %s, "
                        "and the router refuses it: %r" % (key, value, want,
                                                           unit, e))
                continue
            if got != want:
                finding("%s=%s: the tool reads %s %s and the router reads %s "
                        "%s" % (key, value, want, unit, got, unit))

        for value in hostile_variants(good):
            ok, _ = tool.accepts(key, value)
            if ok:
                # Not a finding about the router. The mutation is supposed to
                # be refusable, and one the tool takes says the mutation rule
                # is wrong here, not that anything disagrees.
                notes.append("%s=%s was meant to be refusable and the tool "
                             "takes it; not compared" % (key, value))
                continue
            try:
                got = reader(value)
            except Exception:
                continue
            finding("%s=%s is refused by the tool and the router reads it as "
                    "%s %s, so a typo and a decision are indistinguishable"
                    % (key, value, got, unit))

    for n in notes:
        print("  note: %s" % n)
    for f in findings:
        print("  DISAGREE: %s" % f)

    # Printed whether the run passed or failed, because it is what a reader
    # weighs the result by.
    print("  -- what this check has been seen to reject --")
    for key in keys:
        if key in EVER_RED:
            print("  %s: seen to fail, on %s" % (key, EVER_RED[key]))
        else:
            print("  %s: NEVER SEEN TO FAIL. A pass here says the two callers "
                  "agree today; it does not say this check would notice if "
                  "they stopped. Break it on purpose once and record it above."
                  % key)
    if findings:
        return 1
    print("  ok: every setting in the class is read the same way by both.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
