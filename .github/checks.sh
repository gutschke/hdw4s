#!/bin/bash -e
export LC_ALL='C'
set -o nounset -o pipefail
# No bytecode in the tree: its python checks import the scripts, and a cache
# left behind is a generated file one "git add ." away from public history (a
# committed .pyc once carried the build path there). tests.sh does the same.
export PYTHONDONTWRITEBYTECODE=1

# Every check CI runs, in the order CI runs them. Run this before pushing and
# there should be no surprises afterwards; that is the entire point of it being
# a script rather than a list of steps in a workflow file.
#
#   .github/checks.sh
#
# Needs: shellcheck, groff-base, systemd, and for --package also debhelper,
# dpkg-dev and fakeroot.

cd "$(dirname "$0")/.."

SCRIPTS=(hdw4s hdw4s-session hdw4s-run-session hdw4s-firewall hdw4s-update hdw4s-wait
         hdw4s-ledger
         hdw4s-stream-dir
         hdw4s-ephemeral-slots hdw4s-incarnation hdw4s-webroot
         install.sh uninstall.sh wrappers/firefox wrappers/thunderbird
         debian/postinst debian/prerm debian/postrm
         debian/hdw4s-shared-sweep.postinst debian/hdw4s-shared-sweep.prerm
         debian/hdw4s-shared-sweep.postrm
         .github/checks.sh .github/tests.sh .github/clean-install-test.sh
         .github/purge-safety-test.sh .github/uid-invariant.sh
         bash-completion/hdw4s)
# Every unit in the tree, found rather than listed. The list this replaces named
# thirteen of the fifteen: hdw4s-incarnation@.service and hdw4s-refuse@.service
# were never handed to systemd-analyze verify, so a syntax error in either would
# have shipped and surfaced only when a session tried to start. Both are started
# by another unit -- one by Wants=, one by OnFailure= -- which is exactly the
# shape a hand-written list forgets, because nothing ever names them out loud.
#
# Globbed against the tree, so adding a unit file is the whole of adding it here.
UNITS=()
for u in hdw4s*.service hdw4s*.socket hdw4s*.timer hdw4s*.slice hdw4s*.path; do
  [ -e "${u}" ] && UNITS+=("${u}")
done
# A glob that matches nothing expands to itself, and an empty UNITS would make
# every unit check below a silent no-op that still prints "ok". This file is run
# from the repository root and from the unpacked copy private/build.sh makes, so
# the wrong working directory is the way that happens.
[ "${#UNITS[@]}" -gt 0 ] || {
  echo 'checks.sh: no unit files found; wrong working directory?' >&2
  exit 1
}

# Units that debian/rules deliberately does not name, with the reason. Anything
# not listed here has to appear in an override_dh_installsystemd line, because a
# unit debhelper is never told about gets no maintainer-script handling at all:
# no enable, no disable on removal, and no record in deb-systemd-helper's state.
#
# Each entry is checked to still name a unit that exists, so a renamed unit takes
# its exemption with it instead of leaving one behind that silently covers
# nothing.
RULES_EXEMPT=(
  # dh_installsystemd handles service, socket, target, path, timer, mount, swap
  # and busname. It does not handle .slice, and passing it one is an error.
  hdw4s.slice
)

fail=0
mark=0
note() { printf '%-28s %s\n' "$1" "$2"; }
# Counts, rather than latching at 1, and that is the whole of a bug fix.
# With "fail=1" the flag could not rise again once it was set, so `begin` in
# any later section took a mark of 1, `bad` set it to 1 again, the comparison
# in `okif` held, and EVERY SECTION AFTER THE FIRST FAILURE PRINTED "ok" NO
# MATTER WHAT IT FOUND -- beside its own FAIL lines. Reproduced in four lines
# away from this file, and seen here for real: a run whose unit verification
# had already failed went on to print "uid invariant  ok" directly under two
# uid-invariant failures.
#
# The exit status was always right. Only the report lied, which is the half a
# person reads -- and it is a regression against the intent stated in the
# comment directly above, which was written to stop a summary claiming success
# the loop did not have.
bad()  { note "$1" "FAIL: $2"; fail=$((fail + 1)); }
# A summary line after a loop must not claim success the loop did not have.
# These used to print "ok" unconditionally, so a run that had already reported
# a failure went on to say the same check passed two lines later. The exit
# status was right and the report was not, which is the worse half to get
# wrong: the report is the part a person reads.
begin() { mark="${fail}"; }
okif()  { if [ "${fail}" = "${mark}" ]; then note "$1" 'ok'; fi; }
# A check that cannot run has to say so. Silently skipping one means CI prints
# "All checks passed" for a check it never performed.
#
# Saying so on its own line is not enough, because the line a person reads is
# the last one. private/build.sh runs this against an unpacked copy where four
# checks skip at once, and a run with four skips ended in exactly the same
# "All checks passed." as a run with none. That is a DIFFERENT defect from a
# truncated run -- here every section ran and the report is complete, it is the
# SUMMARY that overstates what was covered -- but it corrupts the same line, so
# it is repaired in the same place: the skips are counted and named at the
# bottom. A skip is deliberately NOT a failure; ronn missing on a workstation
# is the normal case, and failing on it is how this check would get turned off.
skips=0
SKIPPED=()
skip()  { note "$1" "skipped: $2"; skips=$((skips + 1)); SKIPPED+=("$1: $2"); }

# ---------------------------------------------------------------------------
# Did this run reach the end?
#
# Nothing asserted this, and it has already gone wrong once for real: the
# python file list below carried git's exit 128 out through "set -e" and the
# run ABORTED there, having printed an unbroken column of ok, never reaching
# the behaviour tests, the packaging checks or the build, and never printing
# "Some checks failed". The repair at the time was local to that one command.
# The CLASS was not repaired: any command in any later section can still do
# it, and a truncated run is indistinguishable from a clean one to a reader,
# because the failure counter of a run that died before finding anything is
# zero.
#
# Two guards, because they catch different things and neither implies the
# other:
#
#   * `finished` plus an EXIT trap answers "did control reach the summary?".
#     It covers every cause at once -- "set -e", an unbound variable, an
#     unexpected `exit` deep in a section, a signal -- without anybody having
#     to anticipate which command will do it. This is the primary guard.
#
#   * SECTIONS is a roster, and it catches the quieter case the trap cannot
#     see: a section that never ran although the script finished, because it
#     was wrapped in a condition that turned out false. The trap is happy with
#     that run; the count is not.
#
# The roster names only the sections that are UNCONDITIONAL. The build and
# lintian sections run only under --package and only when lintian is present,
# so listing them would make an ordinary run report a hole that is not one --
# and a check that cries wolf ends unread. A truncation inside those blocks is
# still caught, by the trap.
SECTIONS=(vocabulary 'the pool has one name' shell 'systemd units'
          'unit manifests' 'uid invariant' documentation
          'behaviour tests' packaging)
sections_seen=0
section_now='(before the first section)'
finished=''
section() { section_now="$1"; sections_seen=$((sections_seen + 1)); echo "== $1 =="; }

# SC2317 calls this unreachable, which is what a trap handler looks like to a
# static reader: nothing in the file calls it by name. The `trap` below is the
# call. Disabled here rather than globally, so the same note elsewhere still
# means what it says -- and it is not cosmetic: the shell section rejects ANY
# output from the linter, so an un-silenced note would fail every run.
#
# Two traps, both met while writing this. The directive has to be the LAST
# comment line before the function, so the prose goes above it. And no comment
# line here may BEGIN with the linter's name, because it then gets parsed as a
# directive and fails the file with SC1073 -- the self-match trap this file
# already warns about for process searches, in a new place.
# shellcheck disable=SC2317
on_exit() {
  local status=$?
  # An `if`, not `&&`: under "set -e" a failing `&&` list exits the trap, and
  # a guard that returns early on its own failure path reports nothing. Seen
  # while writing this one.
  if [ -z "${finished}" ]; then
    echo >&2
    echo "checks.sh: RUN TRUNCATED -- died in section '${section_now}', ${sections_seen} of ${#SECTIONS[@]} sections reached, exit status ${status}." >&2
    echo 'checks.sh: everything after that section did NOT run. This is NOT a pass.' >&2
    # A run that died is a failure even where the dying command exited 0,
    # which is what a bare `exit` in the middle of a section does.
    [ "${status}" -ne 0 ] || status=1
  fi
  exit "${status}"
}
trap on_exit EXIT
# Bash does not run the EXIT trap when the default SIGINT or SIGTERM handler
# kills it, so a Ctrl-C would still leave a column of ok and no verdict. These
# turn the signal into an ordinary exit, which the trap then sees.
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# The repository has to BE this tree, not merely contain it. The packaging
# helper copies the tree into a build directory INSIDE this repository, so
# "git rev-parse --git-dir" succeeds there and every git question below is
# then answered about the PARENT repository instead of the copy under test.
# Do not simplify this back to --git-dir: the copy's location inside the repo
# is the whole reason, and it is invisible from this file.
#
# Measured: a copy run from inside the repo printed "no privileged file, and
# no estate detail, in the index  ok" -- an affirmative clean bill of health
# about a different tree's index. A skip is honest; an ok about the wrong
# tree is worse than having no check at all.
#
# Defined here rather than beside its first reader because the file list below
# needs it too, and that list is built before the first section runs.
same_repo() {
  local top
  top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  [ -n "${top}" ] && [ "${top}" = "$(pwd -P)" ]
}

# The directories a filesystem walk of this tree must not descend into, for a
# tree that is not a repository of its own. Shared by the scans below and by
# the python list much further down, which discovered every entry the hard way:
# .git, private, tmp and node_modules are not ours to scan; debian/.debhelper
# and debian/<package> are staging trees holding COPIES of installed files, and
# reporting on a stale duplicate is the same defect as not reporting at all.
walk_prune_args() {
  local pkg
  printf '%s\0' -name .git -o -name private -o -name tmp -o -name node_modules \
                -o -path ./debian/.debhelper
  while read -r pkg; do
    [ -n "${pkg}" ] || continue
    printf '%s\0' -o -path "./debian/${pkg}"
  done < <(awk '/^Package:/ {print $2}' debian/control 2>/dev/null)
}

# ---------------------------------------------------------------------------
# The files the content scans below cover, DERIVED rather than excluded.
#
# This used to be "grep -r ." minus four hand-written --exclude-dir names, and
# the list went stale the way a hand-written list always does. Measured: at a
# clean HEAD, with nothing wrong with the tree at all, the local-detail scan
# failed the whole suite on a file inside .claude/worktrees/ -- a dozen stale
# agent checkouts of THIS repository, each of them carrying a full copy of
# .github/live. The named file could not ship; it is not in the package, it is
# not in the index, it is not even in this branch.
#
# The damage is not the false positive. It is that containment is one of the
# few things here that must not break, and the next person to meet it red for
# a silly reason learns that the containment check fails for silly reasons.
# After that it protects nothing. And it is invisible to CI, which checks out
# a clean tree and never has a worktree inside it -- so "green in CI" was not
# evidence against it.
#
# Adding .claude to the exclusion list would have fixed this instance and left
# the class: the next ignored directory to appear does it again. So the list
# comes from git, which already knows what is part of this project, and the
# answer is maintained by the same .gitignore everything else already
# maintains. Note .claude is ignored via .git/info/exclude rather than
# .gitignore, which is exactly why CI never saw it; --exclude-standard honours
# both.
#
# --others as well as --cached, deliberately. Restricting this to the index
# would narrow the check: a leak in a file that has been written but not yet
# staged is precisely the one worth catching before it is committed. --others
# keeps those, and --exclude-standard drops only what git is already ignoring.
SCAN_FILES=()
scan_src=''
if same_repo; then
  scan_src='git (tracked, plus untracked files git does not ignore)'
  while IFS= read -r -d '' f; do
    [ -f "${f}" ] && SCAN_FILES+=("${f}")
  done < <(git ls-files -z --cached --others --exclude-standard 2>/dev/null)
elif [ -r debian/control ]; then
  # The build copy has no repository of its own. Walking it is not optional:
  # this is the only tree that ships anything, so a scan that skipped here
  # would leave the release path uncovered.
  scan_src='a filesystem walk'
  mapfile -d '' scan_prune < <(walk_prune_args)
  while IFS= read -r -d '' f; do
    SCAN_FILES+=("${f#./}")
  done < <(find . \( "${scan_prune[@]}" \) -prune -o -type f -print0)
fi
# One place that decides whether the scans can run at all, so that neither of
# them can quietly scan an empty list and print ok. This is the shape the
# python check already had to grow for the same reason.
scan_ok() {
  if [ -z "${scan_src}" ] || [ "${#SCAN_FILES[@]}" -eq 0 ]; then
    skip "$1" 'the file list could not be derived (neither a git repository of its own nor a Debian source tree)'
    return 1
  fi
}
# grep over the derived list. xargs rather than one grep, because the list is
# longer than a single argv entry is allowed to be on a big tree.
scan_grep() { xargs -0 -r grep -Il "$@" < <(printf '%s\0' "${SCAN_FILES[@]}") || true; }

# THE LOCAL-DETAIL PATTERN, IN ONE PLACE. It was written out twice -- once for
# the file scan and once for the index -- and the two had already drifted: the
# index copy was widened after a committed .pyc carried a home directory into
# public history, and the file copy was not, so the narrower one had been
# reporting clean about a class it does not look for. A third copy was about to
# be added for commit messages, which is what made the drift worth fixing rather
# than working around.
#
# Every alternative is written with a bracketed character so this file does not
# match its own source -- the same trap as a process search containing its own
# pattern -- which is why the scans below can include this file rather than
# having to exclude it.
#
# The maintainer's own name is deliberately absent: it belongs in debian/control
# and in the licence, and banning it would make every scan here cry wolf until
# somebody turned them off.
LOCAL_DETAIL_RE='ariadn[e]|atticu[s]|ct1[0-9][0-9]|10\.10\.[0-9]|172\.24\.[0-9]'
LOCAL_DETAIL_RE="${LOCAL_DETAIL_RE}"'|/home/(markus|root)/|gutschke\.com'
LOCAL_DETAIL_RE="${LOCAL_DETAIL_RE}"'|schlag[e]|van-aake[n]|proxmo[x]'

# The browser-mode word for a private window must not appear in anything that
# ships. It names privacy from other people using the same machine, which is not
# what this session type offers -- it keeps one session's state out of the next
# one, and promises nothing against the administrator. Shipping the browser's
# word would import the browser's promise. "ephemeral" is the term.
#
# A local deployment may still call a hostname whatever it likes; that is
# configuration, and configuration is not in this tree.
#
# The pattern below is bracketed and no comment here spells the word, so this
# file does not match itself -- the same reason a process search must not
# contain its own pattern.
section 'vocabulary'
begin
if scan_ok 'vocabulary'; then
  banned="$(scan_grep -i 'inc[o]gnito' 2>/dev/null)"
  if [ -n "${banned}" ]; then
    printf '%s\n' "${banned}"
    bad 'vocabulary' 'the browser-mode word appears in files above; use "ephemeral"'
  fi
  okif "no browser-mode word in ${#SCAN_FILES[@]} file(s) (from ${scan_src})"
fi

# The name of the component that fronts the pool must not appear in anything a
# user or an administrator READS AS PROSE. The owner ruled it directly: "they
# don't want to know that a demultiplexer is involved. our cli should reflect
# that." The model the tool presents is named sessions plus a growable pool of
# unnamed ephemeral ones, and the machinery that picks a slot out of the pool is
# an implementation detail of "the pool".
#
# THE SCOPE IS THE WHOLE OF THIS CHECK, and getting it wrong in either
# direction makes it worthless:
#
#   * Too narrow and it misses the places the word actually reaches a person --
#     help output, the manual, the configuration this tool PRINTS for somebody
#     to paste into nginx, and refusals.
#
#   * Too wide and it bans the unit name. An administrator sees hdw4s-demux in
#     "systemctl status" and in the journal whatever the manual calls it, and a
#     manual that cannot name the unit it is describing is worse than one that
#     does. A check that forbids a fact gets turned off, and then it is not
#     protecting the prose either.
#
# So the rule is: the word is allowed only INSIDE AN IDENTIFIER somebody has to
# type or will see -- the unit, the credential file, the environment, and an
# internal shell function whose call is substituted away before any reader sees
# it. As an English word it is banned. Those identifiers are removed from the
# text first, and whatever survives is prose.
#
# Comments in the source are not user-facing and are left alone: they are where
# the mechanism is supposed to be described accurately. That is why the shell
# script is filtered rather than grepped, and the filter has to be heredoc-aware
# -- the nginx block "hdw4s proxy" prints is made of lines beginning with "#"
# inside a heredoc, so a naive comment-stripper would exempt exactly the
# generated configuration this check exists to cover.
#
# Every pattern below is bracketed so this file does not match itself, the same
# trap as a process search containing its own pattern.
section 'the pool has one name'
begin

# Lines of a shell script that can reach a user: everything inside a heredoc,
# and everything outside one that is not a whole-line comment.
user_text_of_shell() {
  awk '
    # Inside a heredoc every line is text somebody is handed.
    #
    # One line in, one line out, always -- a dropped line would shift every
    # line number after it, and a report that names the wrong line is how a
    # person concludes the check is broken and stops reading it.
    delim != "" {
      t = $0; sub(/^[ \t]+/, "", t)
      if (t == delim) { delim = ""; print ""; next }
      print; next
    }
    {
      line = $0
      # Opening a heredoc. "<<<" is a here-string and is not one; the pattern
      # cannot match it, because a quote or a letter has to follow the "<<".
      if (match(line, /<<-?[ ]*("|'"'"')?[A-Za-z_][A-Za-z0-9_]*/)) {
        d = substr(line, RSTART, RLENGTH)
        sub(/^<<-?[ ]*/, "", d)
        gsub(/("|'"'"')/, "", d)
        delim = d
      }
      sub(/^[ \t]*#.*$/, "", line)
      print line
    }
  ' "$1"
}

# The identifiers the word is allowed to be part of, removed before the search.
# Each is a thing that exists: a unit systemd prints, a file the service loads,
# an environment variable, and a shell function whose call is substituted away.
strip_pool_identifiers() {
  # The backslash is optional because roff escapes a hyphen: the generated
  # manual spells the unit "hdw4s\-demux", and without this the check would go
  # red on a page whose only mention is the unit name it is supposed to allow.
  # Found by running it, not by reading it.
  # The same is true of the DOT, and it was missed when the hyphen was fixed:
  # roff writes the credential file as "demux\.auth\.cred", so the pattern below
  # went red on the first manual page that ever mentioned it -- two years of
  # green meaning only that nobody had documented the file. Same lesson as the
  # line above, found the same way.
  # And the router's runtime directory, which is "<runtime root>/demux" since
  # every runtime path moved under /run/hdw4s: a path, like the unit name.
  sed -e 's/hdw4s\\\?-[d]emux//g' \
      -e 's#\(/run/hdw4s\|[$]{RUNDIR}\)/[d]emux##g' \
      -e 's/[d]emux\\\?\.auth\\\?\.cred//g' \
      -e 's/HDW4S_[D]EMUX[A-Z_]*//g' \
      -e 's/[d]emux_port//g'
}

pool_word='[d]emux\|[d]emultiplex'
pool_hits=''
for f in hdw4s hdw4s.conf hdw4s.8.md hdw4s.8 README.md install.sh uninstall.sh; do
  [ -e "${f}" ] || continue
  case "${f}" in
    hdw4s|install.sh|uninstall.sh) text="$(user_text_of_shell "${f}")";;
    # A sample configuration, a manual and a README are read from end to end;
    # there is nothing in them that is not user-facing.
    *)                             text="$(cat "${f}")";;
  esac
  hit="$(printf '%s\n' "${text}" | strip_pool_identifiers |
         grep -n -i "${pool_word}" || true)"
  [ -z "${hit}" ] || pool_hits="${pool_hits}${f}: ${hit}
"
done
if [ -n "${pool_hits}" ]; then
  printf '%s' "${pool_hits}"
  bad 'pool vocabulary' \
      'the internal component is named in user-facing text above; say "the pool"'
fi
okif 'user-facing text says "pool", not the component name'

# Local detail: the addresses, container ids and account names of the machines
# this happens to be developed on. None of it is useful to anybody who installs
# the package, and two of them -- a real person's account name and an internal
# address -- sat in a public repository for weeks as the default arguments of a
# test, where nobody was looking because they were not secrets and did not feel
# like a leak.
#
# Each pattern is written with a bracketed character so this check does not match
# its own source, the same trap as a process search containing its own pattern.
# The maintainer's own name is deliberately absent: it belongs in debian/control
# and the licence, and banning it would make this check cry wolf until somebody
# turned it off.
begin
if scan_ok 'local detail'; then
  local_detail="$(scan_grep -E "${LOCAL_DETAIL_RE}" 2>/dev/null)"
  # This file names the estate in the comments explaining why it must not be
  # named, so it is exempted from its own scan. The path has NO leading "./"
  # any more: the list comes from git and from a walk that strips it, where it
  # used to come from "grep -r .". A self-exclusion that no longer matches
  # makes the check fail on itself on every run -- which is the cry-wolf
  # failure this change exists to remove, reintroduced one line lower down.
  local_detail="$(printf '%s\n' "${local_detail}" | grep -v '^\.github/checks\.sh$' || true)"
  if [ -n "${local_detail}" ]; then
    printf '%s\n' "${local_detail}"
    bad 'local detail' 'a machine or account from this estate appears in the files above'
  fi
  okif "no local machine or account names in ${#SCAN_FILES[@]} file(s) (from ${scan_src})"
fi

# The privileged instruction file is the one thing allowed to carry the detail
# the scan above forbids. That exemption is only safe while the file is provably
# outside the repository, so this checks the INDEX rather than the working tree:
# .gitignore is a convention that `git add -f` overrides, and an ignored file is
# invisible to `git status`, so nothing else here would notice it drifting in.
#
# Note the scan above uses `grep -r`, which does NOT descend into the symlink at
# CLAUDE.local.md. Changing it to -R would make every run fail on a correctly
# contained file, and a check that fails on the correct state gets turned off.
#
# Fails closed. private/build.sh runs this against a COPY of the tree, which has
# no .git -- and there "git grep" exits 128 and "git ls-files" fails, both
# swallowed, both reading as clean. Measured: a file containing a hostname and
# two account names sat in that copy while this block printed ok, one line under
# a genuine failure from the scan above. A check that cannot run has to say so,
# which is what skip() is for.
# same_repo() answers "is this tree a repository of its own?", and is defined at
# the top of this file beside the scan file list, which needs the same answer
# before the first section runs. Its reasoning -- including why it must not be
# simplified back to --git-dir -- is written out there.

begin
if ! same_repo; then
  skip 'containment' 'this tree is not a git repository of its own (a build copy) -- the index was NOT checked'
else
  for f in CLAUDE.md CLAUDE.local.md; do
    if git ls-files --error-unmatch "${f}" >/dev/null 2>&1; then
      bad 'containment' "${f} is TRACKED; it carries estate detail and must never be published"
    fi
  done
  # --cached, because the comment above used to claim this checked the index and it
  # did not: "git grep" without it reads the WORKING TREE, so a staged leak whose
  # working copy had been cleaned passed. And no -I: that skips binaries, which
  # exempts a screenshot with a hostname in its title bar from every scan here.
  # The pattern list is the check. An earlier version of this scanned only for
  # account names, container ids and the two internal /16s -- and would NOT have
  # caught the leak it was written in response to: a committed .pyc carrying
  # "/home/<user>/src/..." in its co_filename, which CPython embeds at compile
  # time and no text review can see. A guard whose list omits the class of thing
  # that motivated it is decoration. Username-bearing paths, the estate's own
  # domain and its machine names are in scope too.
  tracked_leak="$(git grep --cached -lE "${LOCAL_DETAIL_RE}" \
      -- ':(exclude).github/checks.sh' 2>/dev/null || true)"
  if [ -n "${tracked_leak}" ]; then
    printf '%s\n' "${tracked_leak}"
    bad 'containment' 'estate detail appears in the STAGED content of the files above'
  fi
  okif 'no privileged file, and no estate detail, in the index'
fi

# ESTATE DETAIL IN A COMMIT MESSAGE, which nothing here has ever looked at.
#
# THE GAP, and it is as old as this file: every scan above reads the INDEX or the
# working tree. A push publishes HISTORY as well, and a commit message is in
# neither of those places, so the containment rule has been enforced on files and
# unenforced on messages from the beginning. A check that does not exist and a
# check that has never rejected anything read identically from here.
#
# FOUND BY AUDITING A TREE FOR A PUBLIC RELEASE and not by anything automatic:
# three messages on the release branch named a development container. The owner's
# ruling on those three is worth recording because it is the reason this check
# exists in the shape it does -- *"isn't a problem from a security point of view,
# but it will trip future scripts that scan for leaks"*. So this is a check about
# keeping later tooling honest, and the repair for a hit is cheap: substitute the
# name and move on.
#
# THE SAME PATTERN AS THE FILE SCANS, read from LOCAL_DETAIL_RE rather than
# written out again. A fourth copy of the list is how the first two came to
# disagree with each other.
#
# WHAT IT COVERS: commits that are NOT yet on the published branch, because those
# are the ones a push would add and the only ones anybody can still change. It is
# deliberately not the whole history: a hit in something already published cannot
# be repaired by failing this build, and a check that is red on every run for
# something nobody can fix is one somebody turns off.
#
# IT SKIPS RATHER THAN PASSES when it cannot resolve the published branch -- a
# shallow clone has no history to compare against, and reporting ok there would
# be the loudest possible version of the failure this check exists for.
begin
if ! same_repo; then
  skip 'commit messages' 'this tree is not a git repository of its own (a build copy) -- no history to read'
else
  msg_base=''
  for ref in origin/master master; do
    if git rev-parse --verify --quiet "${ref}" >/dev/null 2>&1; then
      msg_base="${ref}"; break
    fi
  done
  if [ -z "${msg_base}" ]; then
    skip 'commit messages' 'neither origin/master nor master is present (a shallow clone?) -- history was NOT read'
  else
    # THE CONTROL, and it is not decoration. An empty range, an unreadable log
    # and a pattern that matches nothing all produce the same silence, and two of
    # those three are broken instruments. So the range is counted first and the
    # count is reported, which is also what tells a reader whether the silence
    # below is about anything at all.
    msg_n="$(git rev-list --count "${msg_base}..HEAD" 2>/dev/null || echo 0)"
    msg_hits=''
    while read -r c; do
      [ -n "${c}" ] || continue
      hit="$(git log -1 --format='%s%n%b' "${c}" |
             grep -niE "${LOCAL_DETAIL_RE}" || true)"
      [ -z "${hit}" ] || msg_hits="${msg_hits}$(git log -1 --format='%h %s' "${c}")
$(printf '%s\n' "${hit}" | sed 's/^/      /')
"
    done < <(git rev-list "${msg_base}..HEAD" 2>/dev/null)
    if [ -n "${msg_hits}" ]; then
      printf '%s' "${msg_hits}"
      bad 'commit messages' \
          "estate detail is in the message(s) above, and a push publishes them"
    else
      note 'commit messages' \
        "no estate detail in ${msg_n} commit(s) not yet on ${msg_base}"
    fi
  fi
fi

# THE TOOLS THAT HELPED ARE NOT NAMED IN ANYTHING PUBLISHED -- not in code, not
# in comments, not in the manual, not in the changelog. The rule was written down
# and nothing checked it, which was found while auditing a tree for a public
# release: the tree was clean, so there was nothing to notice and no way to learn
# that the rule was resting on somebody remembering it. A check that does not
# exist and a check that has never rejected anything read identically from here.
#
# Bracketed characters throughout, so this file does not match itself and can
# therefore be scanned rather than excluded -- the same trap as a process search
# containing its own pattern.
#
# Whole words, so that ordinary English and ordinary names survive: a check that
# cries wolf is turned off within a week. The trailer form is included because it
# is what a tool adds by itself, which is the way this leaks without anybody
# typing it.
#
# THE INDEX, not the working tree, for the reason the containment check above
# gives: the staged content is what a push publishes, and a leak whose working
# copy has been cleaned is exactly the case that matters.
#
# WHAT THIS CANNOT SEE, and it is the larger half: a commit MESSAGE. A push
# publishes history, and history is not in the index. That needs a hook on the
# machine where commits are made; it is not pretended to here.
begin
if ! same_repo; then
  skip 'tool attribution' 'this tree is not a git repository of its own (a build copy) -- the index was NOT checked'
else
  # THE CONTROL COMES FIRST. This search is expected to find nothing, and a bad
  # pattern, a bad pathspec and a grep that cannot read the index all look
  # exactly like that. So the same command shape is pointed at a word that must
  # be in the index before its silence is believed.
  if [ -z "$(git grep --cached -licE 'ephemera[l]' -- hdw4s.conf 2>/dev/null)" ]; then
    bad 'tool attribution' \
        'the control failed: this search cannot find a word that IS in hdw4s.conf, so its empty result means nothing'
  else
    # THE THREE NAMES THAT ARE ALLOWED, removed before the search rather than by
    # exempting the files that hold them, and this is the whole difference
    # between a check that stays on and one somebody turns off.
    #
    # They are PATHS OF THE PRIVILEGED INSTRUCTION FILE AND ITS DIRECTORY, and
    # they are load-bearing in two places: .gitignore is what keeps that file
    # out, and the containment check above has to name the file it refuses to
    # let be tracked. A rule cannot be enforced without naming its subject, so
    # banning the name would mean deleting the mechanism -- which is a strictly
    # worse outcome than the name being visible.
    #
    # Exempting the two FILES instead would exempt every future line in them,
    # including a real attribution added to a comment. Exempting the STRINGS
    # leaves every other use of the vendor's name, anywhere in the tree,
    # including in those same two files, still caught. The pool-vocabulary
    # check above uses the same shape for the same reason.
    #
    # ⚠ THEY ARE ALREADY PUBLISHED and have been for as long as the containment
    # mechanism has existed. This is therefore a decision about what goes in
    # from now on, not a retraction; removing them would not unpublish them.
    # The directory is stripped WITH OR WITHOUT its trailing slash: two of the
    # three real occurrences are prose about the directory rather than a path
    # ("... is ignored via .git/info/exclude"), and a pattern that required the
    # slash left them in. Found by running this, not by reading it.
    strip_allowed_tool_paths() {
      sed -e 's|\.[c]laude|.<harness>|g' \
          -e 's|[C]LAUDE\.local\.md|<privileged>|g' \
          -e 's|[C]LAUDE\.md|<privileged>|g'
    }
    # Two passes, because the shape of the answer differs: which FILES, so the
    # message can name them, and then the surviving LINES, so a file whose only
    # hits were allowed names does not get blamed.
    attribution=''
    for f in $(git grep --cached -linE \
        '\b([c]laude|[a]nthropic|[c]hatgpt|[o]penai|[c]opilot|[c]o-authored-by)\b' \
        2>/dev/null || true); do
      # Each surviving line carries its own file name. Without the sed the name
      # printed once and the rest of a multi-line hit read as belonging to the
      # file above it -- a list that looks complete is harder to doubt.
      hit="$(git show ":${f}" 2>/dev/null | strip_allowed_tool_paths |
             grep -nEi '\b([c]laude|[a]nthropic|[c]hatgpt|[o]penai|[c]opilot|[c]o-authored-by)\b' |
             sed "s|^|  ${f}:|" || true)"
      [ -z "${hit}" ] || attribution="${attribution}${hit}
"
    done
    if [ -n "${attribution}" ]; then
      printf '%s' "${attribution}"
      bad 'tool attribution' \
          'the files above name an assistant, its vendor, or carry a tool trailer'
    else
      note 'tool attribution' \
        'none in the index (control: the same search finds a known word in it)'
    fi
  fi
fi

# Whether the tree this run describes is the tree that is in git.
#
# Nothing asserted this before. It matters most during mutation testing, the
# one activity that deliberately puts a defect into a file to find out whether
# a check notices: a mutation left behind is indistinguishable from a real
# defect to the next reader, and identical to one to the package build. The
# packaging helper copies whatever is in the tree, so a mutation injected to
# prove a check CAN fail is one build away from being packaged and installed
# as a shipped defect. A half-finished edit left behind by an interrupted
# session does the same thing without anybody having intended it.
#
# Reported on every run, and fatal only for --package. A dirty tree during
# development is the normal case and must not be blocked: a gate that makes
# ordinary work impossible is bypassed within a day, and a bypassed gate is
# worse than no gate. What must never happen silently is producing an
# ARTEFACT from a tree that matches no commit, so the refusal is attached to
# the build, and --dirty overrides it deliberately and records that it did.
#
# Tracked files only. Untracked scratch is normal in this tree and failing on
# it would make this cry wolf until somebody turned it off; a mutation is by
# definition an edit to a file that is already tracked.
dirty=''
if ! same_repo; then
  skip 'working tree' 'this tree is not a git repository of its own -- cannot tell whether it matches git'
else
  dirty="$(git status --porcelain --untracked-files=no 2>/dev/null || true)"
  if [ -n "${dirty}" ]; then
    printf '%s\n' "${dirty}"
    note 'working tree' "DIRTY: $(printf '%s\n' "${dirty}" | wc -l) tracked file(s) differ from $(git rev-parse --short HEAD 2>/dev/null)"
  else
    note 'working tree' "clean at $(git rev-parse --short HEAD 2>/dev/null)"
  fi
fi

section 'shell'
begin
for f in "${SCRIPTS[@]}"; do
  bash -n "$f" 2>/dev/null || bad "${f}" 'bash -n rejected it'
done
okif 'bash -n'
if out="$(shellcheck -f gcc "${SCRIPTS[@]}" 2>&1)" && [ -z "${out}" ]; then
  note 'shellcheck' 'ok'
else
  printf '%s\n' "${out}"
  bad 'shellcheck' 'findings above'
fi

# Every command a script dispatches must resolve to a function that exists.
# A "case" branch calling a name nobody defined parses cleanly, survives the
# linter, and fails only when somebody runs that one subcommand. When that
# subcommand is one a timer runs rather than a person, nothing surfaces it.
#
# (Note for the next person: a comment line may not begin with the linter's own
# name, because it then gets read as a directive and rejected as malformed.)
begin
for f in hdw4s hdw4s-firewall; do
  while read -r fn; do
    [ -n "${fn}" ] || continue
    grep -qE "^${fn}\(\) \{" "${f}" ||
      bad "${f}" "dispatches ${fn}, which is not defined"
  done < <(grep -oE '\bcmd_[a-z_]+' "${f}" | sort -u)
done
okif 'dispatch targets exist'

echo
section 'systemd units'
begin
for u in "${UNITS[@]}"; do
  # Unit files reference paths that only exist once installed, and reference
  # each other by name, so those two complaints are expected here and are not
  # what this check is looking for. Anything else -- an unknown directive, an
  # unparseable value -- is a real error that would only surface at runtime.
  out="$(systemd-analyze verify "./${u}" 2>&1 |
         grep -viE 'not executable|does not exist|man .* failed|command .* failed|Unit .* not found|ssh\.socket' || :)"
  [ -z "${out}" ] || { printf '%s\n' "${out}"; bad "${u}" 'verify reported the above'; }
done
okif 'systemd-analyze verify'

echo
section 'unit manifests'
# Four independent places used to name a subset of the units, by hand, and they
# drifted. hdw4s-incarnation@.service and hdw4s-refuse@.service were in
# debian/install and install.sh and in neither debian/rules nor uninstall.sh --
# found once, still there a week later, because nothing compares the lists.
#
# Two of the four are gone now: install.sh derives its symlink loop from the
# file list it already has, and uninstall.sh finds the links it planted instead
# of reciting them. What is left is debian/rules, which cannot be derived
# because it IS the policy -- which unit is enabled, which is started, which is
# left for "hdw4s enable" -- and install.sh's SOURCES, which is the file list.
#
# So this is the oracle for the two that remain. It is deliberately about
# COMPLETENESS and not about correctness: it cannot tell whether a unit was
# given the right flags, only that somebody had to decide. That is the failure
# that has actually happened here twice -- the slot minter swept into the
# --no-enable list was a wrong decision and this would not have caught it; a
# unit nobody ever mentioned is the one this catches.
begin
# install.sh's own list, evaluated rather than parsed: it is a bash array with
# brace expansion in it, and a regexp over the source would have to reimplement
# the shell to read it. Evaluated in a subshell that defines nothing else, so a
# stray command in that block would fail here rather than run.
sources="$(sed -n '/^SOURCES=(/,/)$/p' install.sh)"
if [ -z "${sources}" ]; then
  bad 'install.sh SOURCES' 'could not find the SOURCES array'
else
  # shellcheck disable=SC2016  # the array is expanded by the subshell, not here
  installed_names="$(bash -c "${sources}"$'\nprintf "%s\\n" "${SOURCES[@]}"')" || {
    bad 'install.sh SOURCES' 'the array does not evaluate'
    installed_names=''
  }
  for u in "${UNITS[@]}"; do
    grep -qxF "${u}" <<<"${installed_names}" ||
      bad "${u}" 'is not in install.sh SOURCES, so install.sh would not copy it'
  done
fi

# debian/rules. Every unit gets a line, or an exemption with a reason above.
rules_named="$(grep -oE 'hdw4s[^[:space:]]*\.(service|socket|timer|slice|path)' debian/rules |
               sort -u)"
for u in "${UNITS[@]}"; do
  case " ${RULES_EXEMPT[*]} " in *" ${u} "*) continue;; esac
  grep -qxF "${u}" <<<"${rules_named}" ||
    bad "${u}" 'is not named in debian/rules, so debhelper never sees it'
done
# And an exemption that no longer names anything is an exemption nobody will
# notice has stopped applying.
for u in "${RULES_EXEMPT[@]}"; do
  [ -e "${u}" ] || bad "${u}" 'is exempted in RULES_EXEMPT but no such unit exists'
done

# debian/install (the hdw4s package) and debian/hdw4s-shared-sweep.install,
# which are what actually put the files on disk. hdw4s's unit lines are globs,
# so this expands them the way dh_install will, MINUS what debian/rules
# excludes from hdw4s: every name in the shared tool's list, as a substring,
# which is what dh_install -X does. Each unit must land in EXACTLY ONE package:
# none is a unit nobody ships, two is a dpkg file conflict at install time.
# package.sh asserts the same thing again on the built .debs.
shipped="$(awk '$2 == "usr/lib/systemd/system" {print $1}' debian/install)"
sweep_list="$(sed -e 's/#.*//' debian/hdw4s-shared-sweep.install 2>/dev/null | awk 'NF {print $1}')"
# shellcheck disable=SC2016  # a make expression, matched literally
rules_exclusion='dh_install -phdw4s $(addprefix -X,$(SWEEP_FILES))'
if [ -z "${shipped}" ]; then
  bad 'debian/install' 'ships no units into usr/lib/systemd/system'
elif [ -z "${sweep_list}" ]; then
  bad 'debian/hdw4s-shared-sweep.install' 'is missing or empty'
elif ! grep -qF "${rules_exclusion}" debian/rules; then
  # The exclusion this mirrors. Without it hdw4s would ship every shared unit
  # too, and this section would be checking a rule that is not there.
  bad 'debian/rules' 'no longer excludes the shared tool list from hdw4s'
else
  for u in "${UNITS[@]}"; do
    n=0
    grep -qxF "${u}" <<<"${sweep_list}" && n=$((n + 1))
    excluded=''
    while read -r x; do
      case "${u}" in *"${x}"*) excluded='yes'; break;; esac
    done <<<"${sweep_list}"
    if [ -z "${excluded}" ]; then
      for pat in ${shipped}; do
        # shellcheck disable=SC2254  # pat is a glob on purpose
        case "${u}" in ${pat}) n=$((n + 1)); break;; esac
      done
    fi
    [ "${n}" = 1 ] || bad "${u}" "is shipped by ${n} packages, not exactly one (debian/*install)"
  done
fi
okif 'every unit is in every manifest'

# Which units are turned ON is the other half, and it is a different list again:
# debian/rules decides it for the package, install.sh for a source install, and
# uninstall.sh is supposed to be install.sh's inverse. All three are policy and
# none can be derived from the tree -- but they have to agree with each other,
# and twice now they have not. The slot minter was enabled by install.sh and
# shipped --no-enable by debian/rules, so the feature died at the first reboot
# of a packaged machine and nobody could see it, because both installers also
# run the minter directly. Then it was enabled by install.sh and disabled by
# nothing, so every uninstall left a dangling sysinit.target.wants symlink.
#
# Set comparison, not a spelling check: it says the three disagree and about
# which unit, and it has nothing to say about whether the shared answer is right.
begin
rules_on="$(grep -E '^[[:space:]]*dh_installsystemd' debian/rules |
            grep -v -- '--no-enable' |
            grep -oE 'hdw4s[^[:space:]]*\.(service|socket|timer)' | sort -u)"
install_on="$(grep -oE 'systemctl enable --now [^[:space:]]+' install.sh |
              awk '{print $NF}' | sort -u)"
uninstall_off="$(grep -oE 'systemctl disable --now [a-z0-9@._-]+' uninstall.sh |
                 awk '{print $NF}' | sort -u)"
if [ -z "${rules_on}" ] || [ -z "${install_on}" ] || [ -z "${uninstall_off}" ]; then
  # An empty side compares equal to nothing and would pass silently, which is
  # the failure this whole section exists to stop happening elsewhere.
  bad 'enable policy' 'one of the three lists came back empty; the parse is wrong'
else
  d="$(comm -3 <(printf '%s\n' "${rules_on}") <(printf '%s\n' "${install_on}"))"
  [ -z "${d}" ] || {
    printf '%s\n' "${d}" | sed 's/^/  /'
    bad 'enable policy' 'debian/rules and install.sh enable different units (above)'
  }
  d="$(comm -3 <(printf '%s\n' "${install_on}") <(printf '%s\n' "${uninstall_off}"))"
  [ -z "${d}" ] || {
    printf '%s\n' "${d}" | sed 's/^/  /'
    bad 'enable policy' 'install.sh enables units uninstall.sh does not disable (above)'
  }
fi
okif 'the three enable lists agree'

echo
section 'uid invariant'
# A logical session identity dies with its session; the PHYSICAL uid goes back
# to a pool and is handed to a stranger. .github/uid-invariant.sh is the two
# properties that make that harmless, as a check rather than as a paragraph, and
# "selftest" is it breaking each of its own assertions on purpose and watching
# them go red.
#
# THIRTEEN of that selftest's twenty arms run here. The other seven need root and
# a parked slot, so this wiring exercises the static and fixture halves only; the
# live halves are a hand tool for a disposable box, and the file says so. Quote
# the number with the claim, or the next summary turns it into twenty.
#
# Neither arm needs a GIT REPOSITORY, and that is deliberate rather than
# incidental. This file runs in two environments -- the repo, and the unpacked
# copy private/build.sh makes, which has no .git -- and a check that quietly
# depends on one reports green in the other while never having looked. Verified
# in that copy in both directions: a planted violation went red there and named
# itself, and the same tree went green once it was removed.
#
# The exit status is not trusted on its own. A red has to NAME what it rejected;
# a bare non-zero status cannot be told apart from the script failing to start,
# and that confusion is not hypothetical -- uid-invariant.sh's own selftest
# scored a crash as a successful rejection until it was made to require the word
# FAIL, which is why this loop requires it too.
begin
for check in static selftest; do
  if out="$("$(dirname "$0")/uid-invariant.sh" "${check}" . 2>&1)"; then
    :
  elif grep -q 'FAIL:' <<<"${out}"; then
    printf '%s\n' "${out}" | grep 'FAIL:' | sed 's/^/  /'
    bad "uid-invariant ${check}" 'reported the above'
  else
    printf '%s\n' "${out}" | sed 's/^/  /'
    bad "uid-invariant ${check}" \
        'exited non-zero without rejecting anything: it did not run'
  fi
done
okif 'uid invariant'

# Nothing on the router's arrival path may open, connect to or create anything.
# The slots are socket-activated, so asking whether one is alive is the way to
# make it alive: a startup banner that connect()ed to each slot started a full
# GNOME desktop on every free one and then reported correctly, having made its
# own report true. The repair was written down as a paragraph asking the next
# person not to reach for something that opens, and a rig built against that
# paragraph created its stand-in directory anyway.
#
# The same "it has to SAY what it found" rule as the loop above, for the same
# reason: a bare non-zero status cannot be told apart from the checker failing
# to start, and a crash that scores as a successful rejection is a check that
# reports green for the rest of its life.
begin
for check in check selftest; do
  if out="$(python3 "$(dirname "$0")/observer-purity.py" "${check}" 2>&1)"; then
    :
  elif grep -q 'FAIL:' <<<"${out}"; then
    printf '%s\n' "${out}" | grep 'FAIL:' | sed 's/^/  /'
    bad "observer purity ${check}" 'reported the above'
  else
    printf '%s\n' "${out}" | sed 's/^/  /'
    bad "observer purity ${check}" \
        'exited non-zero without rejecting anything: it did not run'
  fi
done
okif 'observation path acts on nothing'

echo
section 'documentation'
# A converter that silently writes nothing is the failure mode worth guarding:
# ronn exits 0 after producing an empty file when it dislikes an argument.
# Every manual page this tree ships, each from its own markdown source.
MANPAGES=(hdw4s.8 hdw4s-shared-sweep.8)
for page in "${MANPAGES[@]}"; do
  if [ ! -s "${page}" ]; then
    bad "${page}" 'missing or empty'
  else
    note "${page} non-empty" "$(wc -l < "${page}") lines"
  fi
  if out="$(groff -man -Tutf8 -ww "${page}" 2>&1 >/dev/null)" && [ -z "${out}" ]; then
    note "${page} groff warnings" 'none'
  else
    printf '%s\n' "${out}"
    bad "${page} groff" 'warnings above'
  fi
done
for section in NAME SYNOPSIS DESCRIPTION COMMANDS CONFIGURATION \
               'SHARED HOME DIRECTORIES' 'REVERSE PROXY AND SECURITY' FILES \
               DIAGNOSTICS UPDATES LIMITATIONS; do
  grep -q "^\.SH \"\{0,1\}${section}" hdw4s.8 ||
    bad 'hdw4s.8' "section '${section}' is missing"
done
note 'required sections' 'present'

# The roff page is generated from the markdown one and committed alongside it,
# so the two can drift: an edit to the source that nobody regenerates ships a
# manual describing the previous release. Naming sections cannot catch that --
# the whole LIMITATIONS section could vanish and every named section would
# still be present. Regenerating and comparing can.
if command -v ronn >/dev/null; then
  regen="$(mktemp)"
  # The .TH line carries the build date and the leading .\" lines name the
  # generator's version, so both differ between machines and neither says
  # anything about content. Everything else must match exactly.
  strip() { grep -v '^\.\\"' "$1" | grep -v '^\.TH '; }
  for page in "${MANPAGES[@]}"; do
    if ronn --roff --pipe --manual='hdw4s' --organization='hdw4s' \
            --date='2000-01-01' "${page}.md" > "${regen}" 2>/dev/null &&
       [ -s "${regen}" ]; then
      if diff -q <(strip "${regen}") <(strip "${page}") >/dev/null; then
        note "${page} matches its source" 'yes'
      else
        bad "${page}" "differs from ${page}.md -- regenerate it"
        diff <(strip "${page}") <(strip "${regen}") | head -10
      fi
    else
      bad "${page}" 'could not be regenerated for comparison'
    fi
  done
  rm -f "${regen}"
else
  skip 'manual pages match their source' 'ronn is not installed (apt package: ronn)'
fi

# Whatever Python ships in this package, parsed. The list is derived rather
# than written out: a named list went stale the moment the server module was
# deleted, and a missing file used to be skipped here and then reported as
# parsing, so deleting one outright was a passing run.
#
# Deriving it is not enough on its own. This asked git for "*.py", and the two
# Python files this package actually INSTALLS -- hdw4s-refuse and
# hdw4s-gate-index, in /usr/lib/hdw4s -- are commands and carry no extension.
# So the eight files it reported were all test harnesses under .github/live,
# and a deliberate syntax error in hdw4s-gate-index left the whole suite at
# "8 file(s) parse" and "All checks passed". A hand-written list goes stale
# when a file is added; a derived one goes stale when its derivation encodes
# an assumption nobody rechecks, which is quieter and lasted longer.
#
# So the assumption is written down rather than left to be rediscovered: a
# Python file here either ends in .py or says python on its first line.
# Anything reaching the interpreter some third way -- a file with neither,
# run as "python3 thatfile" or imported by path -- is not in this list, and
# adding one means changing this derivation.
#
# There are two derivations because there are two trees, and the second one
# is where the package is actually built. A build copy is not a repository of
# its own, so the git list is empty there and this used to skip -- leaving
# the release path, the only path that ships anything, parsing no payload at
# all. The fallback walks the filesystem instead, and it has an assumption of
# its own that is NOT the git one and has to be stated separately:
#
#   it assumes nothing that must parse lives in .git, private, tmp or
#   node_modules -- the same four the scans at the top of this file already
#   exclude -- nor in debian's generated trees, which are .debhelper and one
#   directory per Package: in debian/control.
#
# Neither half is decoration, and both were found by running it.
# debian/<package> is a staging tree holding a COPY of each installed file:
# private/build/hdw4s/debian/hdw4s/usr/lib/hdw4s/hdw4s-gate-index is exactly
# the file this check exists for, left over from an earlier build, and
# parsing that instead of the source would report on a stale duplicate --
# the same defect this check already had once, looking at something adjacent
# to the payload and calling it the payload. And the first version of this
# walk, pruning only .git at the top, descended into tmp/selkies, which is
# an upstream checkout, and failed the run on fourteen files inside its
# .git/rr-cache. Another project's tree is not ours to parse.
#
# A tree whose generated directories are named some other way needs this
# list changed -- which is the point of writing the assumption down rather
# than leaving the next person to rediscover it, as this one was.
pyfail=''
# The same guard, for both of the same reasons. Outside a repository this
# assignment carried git's exit 128 out through "set -e": the run ABORTED
# here, having printed an unbroken column of ok, never reaching the behaviour
# tests, the packaging checks or the build, and never printing "Some checks
# failed". And in a copy that sits inside this repository, git answers about
# the parent, where the copy is ignored -- so the list came back empty and
# this reported "no python in this package" with eight Python files present.
pysrc=''
pyfiles=''
python_from_stdin() {
  while IFS= read -r -d '' f; do
    [ -f "${f}" ] || continue
    case "${f}" in *.py) printf '%s\n' "${f}"; continue;; esac
    case "$(head -n1 -- "${f}" 2>/dev/null)" in
      '#!'*python*) printf '%s\n' "${f}";;
    esac
  done
}
if same_repo; then
  pysrc='the git index'
  pyfiles="$(git ls-files -z 2>/dev/null | python_from_stdin)"
elif [ -r debian/control ]; then
  pysrc='a filesystem walk'
  # The prune list is walk_prune_args() at the top of this file, shared with the
  # content scans, which need the identical answer for the identical reason. It
  # is one list because two copies of it is two lists the moment one is edited.
  mapfile -d '' pyprune < <(walk_prune_args)
  pyfiles="$(find . \( "${pyprune[@]}" \) -prune -o -type f -print0 |
             python_from_stdin | sed 's|^\./||')"
else
  # The guard stays. It is not unreachable: a tree that is neither a
  # repository nor a Debian source tree gives this nothing to walk, and
  # saying so is better than walking an unknown directory. Outside a
  # repository the git call used to carry exit 128 out through "set -e" and
  # abort the run mid-column, having printed an unbroken sequence of ok.
  skip 'python syntax' 'neither a git repository of its own nor a Debian source tree -- the file list could not be derived'
fi
if [ -z "${pyfiles}" ]; then
  [ -z "${pysrc}" ] || note 'python syntax' "no python in this package (from ${pysrc})"
else
  for f in ${pyfiles}; do
    if ! python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "${f}" 2>/dev/null; then
      pyfail="${pyfail} ${f}"
    fi
  done
  if [ -z "${pyfail}" ]; then
    note 'python syntax' \
      "$(printf '%s\n' "${pyfiles}" | wc -l) file(s) parse (from ${pysrc})"
  else
    bad 'python syntax' "does not parse:${pyfail}"
  fi
fi

echo
# ---------------------------------------------------------------------------
# The idle window's grammar exists exactly once, and both callers reach it.
#
# It did not. The tool carried a unit table and the router read the same
# setting with int(), caught the failure and used seven days without a word --
# so "30d", which hdw4s.conf and hdw4s.8 both tell an administrator to type,
# was accepted, written down and then discarded by the component whose
# behaviour depended on it.
#
# WHAT MAKES THIS A CHECK RATHER THAN A COMMENT: the previous repair also put
# the grammar "in one place", and only half of it landed. One side learned the
# unit letters and the other kept its fallback, and nothing anywhere could
# notice, because "there is one implementation" is a property of the whole tree
# and no file can assert it about itself. So it is asserted here, over the
# tree, where a merge that keeps one half fails.
#
# .github/setting-grammar.py is the other half of the pair and they are not
# redundant: that one compares the two callers' ANSWERS, this one asserts there
# is only one thing to answer with. Two implementations that happen to agree
# today would pass that check and fail this one.
begin
# WHICH FILES ARE "THE TREE". Reuses SCAN_FILES rather than enumerating again,
# and the second enumeration is exactly the defect this section exists to name:
# one grammar, in one place. A private walk here reached .claude/worktrees (stale
# seat checkouts, which live INSIDE the repository) and debian/hdw4s (a build
# staging copy), and reported 107 failures about files nothing ships. A replacement
# private git call then broke the OTHER path -- the build copy has no repository,
# where SCAN_FILES deliberately falls back to a pruned walk, and the check died
# rather than running. Both mistakes were one mistake: a second enumeration.
scan_grammar_files() {
  local f
  for f in "${SCAN_FILES[@]}"; do
    case "${f}" in .github/*|private/*|tmp/*|*__pycache__/*) continue;; esac
    printf '%s\0' "${f}"
  done
}
# The two constants systemd uses for the units that have no fixed length -- a
# month of 30.44 days and a year of 365.25 -- keyed on because nothing else in
# this tree has any reason to name them. A second unit table is the defect
# returning, and it will carry these whether or not it is spelled the same way.
for n in 2629800 31557600; do
  holders="$(scan_grammar_files | xargs -0 -r grep -lF "${n}" 2>/dev/null | sort)"
  case "${holders}" in
    'hdw4s-duration') ;;
    '') bad 'duration grammar' "${n} is in no shipped file: hdw4s-duration has lost its unit table" ;;
    *)  bad 'duration grammar' \
            "${n} is named by $(printf '%s' "${holders}" | tr '\n' ' ' | sed 's/ $//'); the unit table belongs to hdw4s-duration alone" ;;
  esac
done
# And every shipped script that reads the setting must reach that file. A
# component naming the key and not the parser is a component with a reading of
# its own, which is the shape the router had. Derived from the tree rather than
# listed: a list would be right until the next component reads it.
readers="$(scan_grammar_files | xargs -0 -r grep -lF 'HDW4S_IDLE_DAYS' 2>/dev/null | sort)"
# POSITIVE CONTROL. An empty list passes this loop in silence, and a broken
# grep looks exactly like a tree where nothing reads the setting.
case "${readers}" in
  *hdw4s-demux*) ;;
  *) bad 'duration grammar' 'nothing in the tree reads HDW4S_IDLE_DAYS, which cannot be true: the search is broken, not the tree clean' ;;
esac
for f in ${readers}; do
  # Documentation names the key without reading it, and the parser names it in
  # the account of why it exists.
  case "${f}" in hdw4s.conf|hdw4s.8|hdw4s.8.md|hdw4s-duration|README.md|SECURITY.md) continue;; esac
  # Comment lines stripped first. The first version of this looked at the whole
  # file, so pointing the caller at a different parser and LEAVING THE COMMENT
  # that explains why it uses this one passed -- which is close to the exact
  # shape of the defect: the account of what the code does, still true-sounding,
  # while the code does something else.
  #
  # WHAT THIS STILL CANNOT SEE, said out loud rather than left to be assumed: a
  # Python caller that names the file only in a docstring satisfies it, because
  # a docstring is not a comment to grep. The behavioural half of the pair is
  # what closes that -- .github/setting-grammar.py asks the router for an answer
  # and compares it against the tool's -- and neither half is sufficient alone.
  grep -qF 'hdw4s-duration' <<<"$(grep -v '^[[:space:]]*#' "${f}")" ||
    bad 'duration grammar' "${f} reads HDW4S_IDLE_DAYS without reaching hdw4s-duration, so it has a grammar of its own"
done
okif 'the idle window has one grammar'

echo
section 'behaviour tests'
if "$(dirname "$0")/tests.sh" > /tmp/hdw4s-tests.$$ 2>&1; then
  printf '%-28s %s\n' 'tests.sh' "$(tail -n1 /tmp/hdw4s-tests.$$)"
else
  bad 'tests.sh' 'behaviour tests failed'
  # EVERYTHING BUT THE PASSES, not only the FAIL lines. A passing run prints
  # nothing besides "ok" lines and headers, so whatever else is there is what a
  # failing test printed about itself -- the router suite dumps its whole
  # output on failure, and CI, where nobody can rerun it by hand, showed only
  # "FAIL the router suite passes" and threw the reason away.
  grep -vE '^  ok |^== |^$' /tmp/hdw4s-tests.$$ | sed 's/^/  /' || :
fi
rm -f /tmp/hdw4s-tests.$$
echo

section 'packaging'
# The tag, the changelog and the built artifact have to agree, or a release
# ships a version nobody asked for.
version="$(dpkg-parsechangelog -S Version)"
note 'changelog version' "${version}"
if [ -n "${EXPECT_VERSION:-}" ] && [ "${version}" != "${EXPECT_VERSION}" ]; then
  bad 'version' "changelog says ${version}, tag says ${EXPECT_VERSION}"
fi
dpkg-parsechangelog >/dev/null || bad 'changelog' 'will not parse'

# The version is stated in the script rather than generated into it, so that
# the files in git are the files that ship down both distribution paths. That
# only works if something checks the two agree.
declared="$(sed -n "s/^HDW4S_VERSION='\(.*\)'\$/\1/p" hdw4s)"
if [ "${declared}" = "${version}" ]; then
  note 'hdw4s --version' "${declared}"
else
  bad 'hdw4s --version' "says ${declared}, changelog says ${version}"
fi
declared="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' hdw4s-shared-sweep)"
if [ "${declared}" = "${version}" ]; then
  note 'hdw4s-shared-sweep --version' "${declared}"
else
  bad 'hdw4s-shared-sweep --version' "says ${declared}, changelog says ${version}"
fi

# The camera and the microphone are asked for with "--webcam-on-start=demand",
# a value only a streaming server carrying capture-on-demand understands. An
# older one reads it through parse_bool -- "everything else is false" -- starts
# normally, and simply never brings the device up. For the microphone that
# leaves no capture device in the session at all. Nothing fails; the feature is
# just absent, which is the kind of regression a release ships without noticing.
#
# The session script no longer probes for this, deliberately: the flag it used
# to probe for never existed outside the branch that proposed it, and upstream
# spelled the merged feature differently. The requirement lives here instead,
# against the version the updater installs, so that shipping a package whose
# pinned Selkies cannot do what the session asks of it is something somebody has
# to walk past on purpose.
#
# Upstream cut 2.0.0rc1 on 2026-09-20 carrying the merged feature, so this is an
# assertion again rather than the placeholder it stood as for two days. The arm
# below names the releases that are known NOT to carry it; it cannot know that
# about a release that does not exist yet, which is why raising KNOWN_GOOD stays
# a decision somebody makes with the release in front of them.
known_good="$(sed -n "s/^KNOWN_GOOD='\([^']*\)'.*/\1/p" hdw4s-update | head -1)"
case "${known_good}" in
  1.*|2.0.0rc0)
    bad 'capture floor' "KNOWN_GOOD=${known_good} predates capture-on-demand: hdw4s-run-session passes --webcam-on-start=demand and --microphone-on-start=demand unconditionally, and a release without the feature reads 'demand' as false, so the camera and the microphone stay dark with nothing reported" ;;
  '')
    bad 'capture floor' 'could not read KNOWN_GOOD from hdw4s-update' ;;
  *)
    note 'capture floor' "KNOWN_GOOD=${known_good}" ;;
esac

# The overlay guard, exercised rather than read.
#
# SELKIES_PATCH copies one upstream tree's files onto whatever release is
# installed, and raising KNOWN_GOOD above moves that release. Nothing used to
# connect the two. hdw4s-update now refuses the combination, and a refusal
# nobody has watched happen is not known to happen -- so both arms run here:
# the ones that must be refused, and the ones that must be allowed. Without the
# second kind a guard that refuses everything would pass this.
#
# Three operands, so the answer comes from what is passed and not from whatever
# /etc/hdw4s/hdw4s.conf on the build machine happens to say.
begin
probe() {
  local want="$1" desc="$2"; shift 2
  local out rc=0
  out="$(./hdw4s-update --check-patch "$@" 2>&1)" || rc="$?"
  case "${want}" in
    refuse)
      if [ "${rc}" -eq 0 ]; then
        bad 'overlay guard' "allowed ${desc}"
      elif ! grep -q 'Nothing has been changed' <<<"${out}"; then
        bad 'overlay guard' "refused ${desc} without saying nothing was changed"
      fi ;;
    allow)
      [ "${rc}" -eq 0 ] ||
        bad 'overlay guard' "refused ${desc}: $(printf '%s' "${out}" | head -1)" ;;
  esac
}
probe refuse 'an overlay built for another release' \
      2.0.0rc1 /etc/hdw4s/selkies-patch 2.0.0rc0
probe refuse 'an overlay that does not say what it was built for' \
      2.0.0rc1 /etc/hdw4s/selkies-patch ''
probe allow  'an overlay built for the release being installed' \
      2.0.0rc1 /etc/hdw4s/selkies-patch 2.0.0rc1
probe allow  'a machine with no overlay at all' \
      2.0.0rc1 '' ''
# The message has to name the release the overlay was built for. A refusal that
# does not is a machine somebody has to reverse-engineer at the wrong hour.
#
# Into a variable, not down a pipe: the producer exits non-zero here by design,
# and under "pipefail" that is the status of the whole pipeline however well
# grep did -- so the test would report a missing version string that is right
# there in the output.
guard_says="$(./hdw4s-update --check-patch \
                2.0.0rc1 /etc/hdw4s/selkies-patch 2.0.0rc0 2>&1 || :)"
case "${guard_says}" in
  *2.0.0rc0*) ;;
  *) bad 'overlay guard' 'the refusal does not name the release the overlay was built for' ;;
esac
unset -f probe
okif 'overlay guard refuses and allows'

# Defaults are necessarily repeated between the scripts, the sample config and
# the man page. They drift silently, and only a user notices.
begin
for setting in HDW4S_BASE_PORT:7300 HDW4S_BLOCK_SIZE:64; do
  key="${setting%%:*}"; want="${setting#*:}"
  # Every script that carries its own copy, in either form it is written in.
  # hdw4s-wait and hdw4s-session carried one until the stream moved to a unix
  # socket (hdw4s-stream-dir); neither derives a port any more, so a copy
  # reappearing in either is itself worth a look.
  for f in hdw4s hdw4s-firewall; do
    got="$(sed -n "s/^${key}=\([0-9]*\)\$/\1/p;s/^ *: \"\${${key}:=\([0-9]*\)}\"\$/\1/p" \
           "${f}" | head -n1)"
    [ -n "${got}" ] ||
      bad "${f}" "does not set a default for ${key}"
    [ -z "${got}" ] || [ "${got}" = "${want}" ] ||
      bad "${f}" "${key} is ${got}, expected ${want}"
  done
  grep -q "^#${key}=${want}\$" hdw4s.conf ||
    bad 'hdw4s.conf' "documents a different ${key}"
done
okif 'defaults agree'

# "hdw4s show" carries its own table of the defaults a session falls back to,
# so that it can report an effective value for a setting nobody has written
# down. A table like that is drift waiting to happen, and the drift is
# invisible: show would confidently report a default the session does not use.
begin
while IFS=: read -r key def; do
  [ -n "${key}" ] || continue
  found=''
  # Every file, not the first one that matches. HDW4S_ADDR, HDW4S_FRAMERATE and
  # HDW4S_ENCODER are defaulted in both session scripts, and stopping at the
  # first meant the two could disagree with each other -- the harder kind of
  # drift to see by eye -- while this reported everything as fine.
  for f in hdw4s-run-session hdw4s-session hdw4s; do
    got="$(sed -n "s/^ *: \"\${${key}:=\(.*\)}\"\$/\1/p" "${f}" | head -n1)"
    [ -n "${got}" ] || continue
    found='yes'
    [ "${got}" = "${def}" ] ||
      bad 'hdw4s show' "${key} defaults to ${def} here and ${got} in ${f}"
  done
  # Not every setting is defaulted with the ":=" form. HDW4S_IDLE_DAYS is read
  # by the reaper and passes the default to setting_of instead. Accept that
  # spelling too rather than name the settings that use it, which is a list
  # that goes stale the moment one is added.
  if [ -z "${found}" ] &&
     grep -q "setting_of \"\${inst}\" ${key} ${def}\([^0-9a-zA-Z_]\|\$\)" hdw4s
  then
    found='yes'
  fi
  [ -n "${found}" ] ||
    bad 'hdw4s show' "${key} is in its table but nothing defaults it to ${def}"
done < <(sed -n '/^SESSION_SETTINGS=(/,/^)/p' hdw4s |
         sed -n "s/^  '\(.*\)'\$/\1/p")
okif 'show defaults match the session scripts'

# A package that builds but cannot be installed is not a working package. CI
# never installs this one -- pulling a whole desktop onto a runner is not worth
# it -- so at least check that every dependency names a package the archive
# actually has. This catches depending on something only one distribution
# ships, which is otherwise discovered by a person trying to install it.
if command -v apt-cache >/dev/null; then
  missing=''
  # A package built from this source is not in the archive and need not be:
  # hdw4s depends on hdw4s-shared-sweep at its own version. Matched as spelled.
  # shellcheck disable=SC2016  # a substvar, matched literally
  ours_suffix='(=${binary:Version})'
  while read -r dep; do
    [ -n "${dep}" ] || continue
    # Split alternatives: apt-cache treats "mawk|gawk" as a regular expression
    # and happily returns a candidate for it, so every "a | b" dependency used
    # to pass without either name being looked up at all.
    ok_dep=''
    for alt in $(printf '%s' "${dep}" | tr '|' ' '); do
      cand="$(apt-cache policy "${alt}" 2>/dev/null | sed -n 's/  Candidate: //p')"
      [ -n "${cand}" ] && [ "${cand}" != '(none)' ] && { ok_dep='yes'; break; }
    done
    [ -n "${ok_dep}" ] || missing="${missing} ${dep}"
  done < <(awk '/^Depends:/ { d = 1; sub(/^Depends:/, "") }
                /^[A-Z][A-Za-z-]*:/ && !/^Depends:/ { d = 0 }
                d { print }' debian/control |
           tr -d ' ' | tr ',' '\n' | grep -v '^[$]' | grep . |
           grep -vxFf <(awk '/^Package:/ {print $2}' debian/control |
                        sed "s/\$/${ours_suffix}/"))
  if [ -z "${missing}" ]; then
    note 'dependencies exist' 'ok'
  else
    bad 'dependencies' "not in the archive:${missing}"
  fi
else
  skip 'dependencies exist' 'apt-cache is not available'
fi

if [ "${1:-}" = '--package' ]; then
  echo
  echo '== build =='
  # One copy of how the package is built and read back, shared with the deploy
  # tool, which builds without running this whole file first.
  args=()
  case " $* " in *' --dirty '*) args=(--dirty) ;; esac
  "$(dirname "$0")/package.sh" ${args[@]+"${args[@]}"} || bad 'package' 'the build or its read-back failed (above)'
fi

echo
# The roster, checked. This is not the truncation guard -- control reached
# here, so the run did finish -- it is the quieter neighbour: a section that
# never announced itself although the script ran to the end.
if [ "${sections_seen}" -ne "${#SECTIONS[@]}" ]; then
  bad 'sections' "${sections_seen} of ${#SECTIONS[@]} sections ran; the roster at the top of this file names $(printf '%s, ' "${SECTIONS[@]}" | sed 's/, $//')"
fi

# Set before the summary, not after: `finished` means "control reached the
# verdict", and anything that dies between here and the last line has already
# produced the verdict a person will read.
finished=1

if [ "${fail}" -eq 0 ]; then
  # The census, not a bare claim. A run with four skips used to end in exactly
  # the same words as a run with none, and the four are the checks that did not
  # happen -- which is the thing a reader needs and cannot get anywhere else.
  if [ "${skips}" -eq 0 ]; then
    echo "All checks passed (${sections_seen} sections, nothing skipped)."
  else
    echo "All checks passed (${sections_seen} sections), but ${skips} check(s) did NOT run:"
    printf '  %s\n' "${SKIPPED[@]}"
  fi
else
  if [ "${skips}" -gt 0 ]; then
    printf '  %s\n' "${SKIPPED[@]}" >&2
  fi
  echo "Some checks failed (${fail} failure(s), ${skips} skipped, ${sections_seen} of ${#SECTIONS[@]} sections)." >&2
fi
exit "${fail}"
