#!/bin/bash -e
# The properties that make a recycled physical uid safe, and the one that makes
# an occupant's own slot directory mean anything, as checks rather than as
# paragraphs.
#
#   .github/uid-invariant.sh static [<tree>]   the directives, on the tree
#   .github/uid-invariant.sh distinct          no two live sessions share a uid
#   .github/uid-invariant.sh clean <slot>...   nothing still refers to a parked slot
#   .github/uid-invariant.sh rundir [<slot>]   an occupant cannot forge occupancy
#
# HDW4S_CLEAN_ROOTS overrides the directories "clean" sweeps. It defaults to the
# full list; narrowing it narrows the claim, so the roots used are printed.
#   .github/uid-invariant.sh selftest [<tree>] break each one on purpose, watch it go red
#
# WHERE EACH ONE RUNS, because the answer is not "everywhere" and a check
# believed to run where it does not is worse than no check.
#
#   static, selftest   CI, and any tree, including the unpacked copy
#                      private/build.sh builds from. Neither needs hdw4s, root,
#                      or a git repository -- that last one deliberately, because
#                      checks.sh runs in two environments and the release path is
#                      the one with no .git in it. Verified in that copy in BOTH
#                      directions: a planted violation went red and named itself,
#                      and the same tree went green once it was removed.
#
#                      THIRTEEN of the selftest's twenty-eight arms run there.
#                      Four more need root but no parked slot -- the "rundir"
#                      fixtures -- and the remaining eleven need root AND a
#                      parked slot, so CI exercises the static and fixture halves
#                      only. Keep those numbers attached to any claim about what
#                      CI covers here; they are the qualifier that disappears
#                      first in a summary, and then somebody believes
#                      twenty-eight arms run in CI.
#
#                      Count the arms EXECUTED, not the lines that call one: three
#                      of the static arms sit in a loop over three directives, so a
#                      grep for "expect" reports eleven where thirteen run. The
#                      number above was right and the obvious way of checking it is
#                      wrong, which is worth one sentence here rather than another
#                      person deciding the header had drifted.
#
#   distinct, clean,   a HAND TOOL for a disposable machine, and deliberately not
#   rundir             wired into any tier. They need root, and "clean" and
#                      "rundir" need a slot that is PARKED -- which a machine busy
#                      enough to be worth testing does not have, and a machine
#                      carrying real users is not somewhere to go looking. Wired,
#                      they would skip wherever they were actually run, which
#                      reads as coverage and delivers none. So: run them by hand,
#                      on a throwaway box, after any change to
#                      hdw4s-ephemeral@.service, to hdw4s-ephemeral-slots, or to
#                      how the pool hands a uid on -- and "rundir" also after a
#                      systemd upgrade, because the behaviour it measures is
#                      systemd's and not ours. Revisit the wiring only somewhere
#                      a slot is reliably parked.
#
# A logical identity dies with its session. The PHYSICAL uid goes back to a free
# pool and is handed to a stranger, and two things have to be true for that to be
# harmless:
#
#   1. no two live sessions hold the same physical uid, and
#   2. a recycled uid inherits nothing from the session before it.
#
# A third property belongs beside them because it is about the same uid and the
# same directory, and because nothing else in the tree asserts it:
#
#   3. an occupant cannot create or remove a slot directory in /run/hdw4s --
#      neither anybody else's nor its own.
#
# That is what makes the router's occupancy reading a fact about the pool rather
# than a claim by a stranger. See "rundir" below for what it costs if it is not
# true; unlike the first two it has no visible directive at all, which is why it
# survived this long unchecked.
#
# The first two were established once, by measurement, when the pool was static
# and a slot was reused a handful of times between reboots. Under a pool that
# grows and recycles they are continuous obligations, and until this script existed they
# were held up by directives being PRESENT -- which is an argument, not a check.
# Nothing would have noticed one being dropped.
#
# The specific edit this exists to catch, because it is the one an ordinary
# tidy-up makes: hdw4s-proxy@.socket sets RuntimeDirectoryPreserve=yes, for a
# documented reason of its own, and hdw4s-ephemeral@.service depends on the
# OPPOSITE value -- which it gets from the default, by saying nothing. The two
# files sit beside each other. Making them "consistent" deletes the only thing
# that removes /run/hdw4s/<slot>, which is the one path measured to carry a file
# from one start of a slot into the next. Nothing else in the tree fails.
#
# There is deliberately NO kernel-keyring assertion here, and its absence is a
# decision rather than an oversight. RemoveIPC= does not cover keyrings, so the
# channel is real; but keyctl_search, keyctl_describe and keyctl_read all return
# ENOSYS under the containers this product runs in -- for root as well -- so any
# keyring line this script could print would be a broken query wearing the word
# "ok". Do not close the gap by adding a check that always passes. Close it by
# measuring on a host where keyctl works, with KeyringMode=private and
# KeyringMode=shared as the two arms, and add the assertion once one of them has
# been seen to go red.
#
# "static" runs anywhere and needs no hdw4s. "distinct" and "clean" need the
# machine the sessions are on, and they read the KERNEL rather than the
# configuration wherever they can: a uid comes from /proc/<pid>/status, not from
# `systemctl show -p User`, because the question is what is running.
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
set -o nounset -o pipefail

fail=0
# Set by the selftest, and named at file scope because the EXIT trap that removes
# it runs after the function that made it has returned. A `local` here left the
# trap reading an unset variable under `nounset`, which made the selftest exit 1
# after every one of its assertions had passed -- a red result produced by the
# harness, on a script whose entire job is to be believed when it goes red.
scratch=''
note() { printf '%-34s %s\n' "$1" "$2"; }
bad()  { note "$1" "FAIL: $2"; fail=1; }
skip() { note "$1" "SKIP: $2"; }

# ---------------------------------------------------------------- static ----
# Every directive the reuse argument rests on, and every directive that must NOT
# appear. The second list is the half a reviewer forgets: a protective property
# held by a default is invisible in the file, so only an explicit test for the
# override can defend it.
#
# Matched anchored and whole-line, so a commented-out directive is not read as
# the directive, and "StateDirectory" inside a sentence is not read as a setting.
unit_has() { grep -qE "^$1\$" "$2"; }
unit_mentions() { grep -qE "^$1" "$2"; }

check_static() {
  local tree="${1:-.}"
  local unit="${tree}/hdw4s-ephemeral@.service"
  local slots="${tree}/hdw4s-ephemeral-slots"
  local d

  if [ ! -r "${unit}" ]; then bad 'static' "no unit at '${unit}'"; return; fi
  if [ ! -r "${slots}" ]; then bad 'static' "no script at '${slots}'"; return; fi

  # Present, exactly. A changed value is as bad as a deleted line: ProtectHome=yes
  # would leave the other accounts' names readable, and PrivateTmp=no is not a
  # smaller version of PrivateTmp=yes.
  for d in 'RemoveIPC=yes' 'PrivateTmp=yes' 'ProtectHome=tmpfs' \
           'ProtectSystem=strict' 'RuntimeDirectory=hdw4s/%i' \
           'TemporaryFileSystem=/var/tmp'; do
    if unit_has "${d}" "${unit}"; then note "unit ${d}" 'ok'
    else bad "unit ${d}" 'missing or changed'; fi
  done

  # Absent, and each absence is load-bearing.
  #
  # RuntimeDirectoryPreserve: the default is "no", and the default is what removes
  # /run/hdw4s/<slot> when the session stops. An explicit "no" is fine and clearer;
  # anything else hands the next occupant the previous one's runtime directory.
  if unit_mentions 'RuntimeDirectoryPreserve=' "${unit}"; then
    if unit_has 'RuntimeDirectoryPreserve=no' "${unit}"; then
      note 'unit RuntimeDirectoryPreserve' 'ok (explicit no)'
    else
      bad 'unit RuntimeDirectoryPreserve' \
          'set to something other than "no": /run/hdw4s/<slot> would survive the session'
    fi
  else
    note 'unit RuntimeDirectoryPreserve' 'ok (absent, defaults to no)'
  fi

  # A directory systemd creates outside the namespace, owned by the slot uid and
  # kept across restarts, is the whole failure this design avoids by not asking
  # for one.
  for d in StateDirectory CacheDirectory LogsDirectory ConfigurationDirectory; do
    if unit_mentions "${d}=" "${unit}"; then
      bad "unit ${d}" 'persistent per-uid directory: a recycled uid would inherit it'
    else note "unit ${d}" 'ok (absent)'; fi
  done

  # The three private filesystems are generated per slot, because a template
  # cannot turn %i into a number. The unit is therefore NOT where they are, and a
  # check that only read the unit would pass a tree that had lost all three.
  # The label and the pattern are separate because the pattern has to match the
  # shell variable as the script spells it, and "/run/hdw4s-profile/\${name}"
  # printed with its regex escapes is not something a reader should have to
  # decode out of a report line.
  check_dropin() {
    if grep -qE "^TemporaryFileSystem=$2" "${slots}"; then note "dropin $1" 'ok'
    else bad "dropin $1" 'the generated drop-in no longer mounts this'; fi
  }
  check_dropin /home/user            '/home/user:'
  check_dropin /run/hdw4s-profile    '/run/hdw4s-profile/\$\{name\}:'
  check_dropin /dev/shm              '/dev/shm:'
  # uid= on the two that hold the session's own files: without it the tmpfs is
  # root-owned and the session cannot write it, which fails loudly -- but a tmpfs
  # mounted with the WRONG uid would not, and would be readable by that uid.
  if grep -qE '^TemporaryFileSystem=/home/user:.*uid=\$\{id\}' "${slots}" &&
     grep -qE '^TemporaryFileSystem=/run/hdw4s-profile/.*uid=\$\{id\}' "${slots}"; then
    note 'dropin uid=' 'ok'
  else bad 'dropin uid=' 'the private filesystems are not pinned to the slot uid'; fi

  if grep -qE '^(RuntimeDirectoryPreserve|StateDirectory)=' "${slots}"; then
    bad 'dropin overrides' 'the generated drop-in sets a directive the unit relies on being absent'
  else note 'dropin overrides' 'ok'; fi
}

# -------------------------------------------------------------- distinct ----
# Assertion 1, read from the kernel. For every hdw4s session unit that is
# running, collect the real uid of every process in its cgroup and refuse two
# units that share one.
#
# Not `systemctl show -p User`: that reports what the unit asked for. A uid is
# what a process actually has, and the gap between those two is the bug this
# assertion exists to catch.
#
# HDW4S_UID_FIXTURE lets the selftest feed this a known-bad map. It is read only
# when set, and the selftest is the only thing that sets it -- a fixture that
# could be mistaken for a measurement is worse than no check.
# EVERY process in the session's cgroup, not just its MainPID. A session that
# puts one process under a different uid is the obvious way past an assertion
# that only looks at the process systemd happens to be tracking, and it costs one
# loop to close: cgroup.procs is the kernel's own list of who is in there.
#
# The cgroup path comes from systemd and the membership comes from the kernel, so
# the only thing taken on trust is which cgroup belongs to which unit.
#
# The limit, so nobody reads more into a pass than is there: a process holding
# the uid that has left the session's cgroup ENTIRELY is not seen. That is a
# real gap and it is deliberately not closed here, because it is a different
# assertion -- containment, "nothing of this session escapes its cgroup" --
# and answering it from inside a uniqueness check would mean scanning every
# process on the machine and deciding which strays are ours. Whoever writes
# the containment check owns it; this one is about two sessions, not one
# escapee.
live_uid_map() {
  if [ -n "${HDW4S_UID_FIXTURE:-}" ]; then cat "${HDW4S_UID_FIXTURE}"; return; fi
  local unit cg pid
  systemctl list-units --no-legend --no-pager --state=active \
      'hdw4s@*.service' 'hdw4s-ephemeral@*.service' 2>/dev/null |
    awk '{print $1}' |
  while read -r unit; do
    [ -n "${unit}" ] || continue
    cg="$(systemctl show -p ControlGroup --value "${unit}" 2>/dev/null || true)"
    if [ -z "${cg}" ] || [ ! -r "/sys/fs/cgroup${cg}/cgroup.procs" ]; then continue; fi
    while read -r pid; do
      if [ -z "${pid}" ] || [ "${pid}" = '0' ]; then continue; fi
      # Field 2 of "Uid:" is the real uid; field 3 is the effective one. Both are
      # printed so a setuid surprise is visible rather than averaged away.
      awk -v u="${unit}" '/^Uid:/ { print u, $2, $3 }' "/proc/${pid}/status" 2>/dev/null
    done < "/sys/fs/cgroup${cg}/cgroup.procs"
  # One line per (unit, uid) pair: a desktop has hundreds of processes and they
  # are all the same identity, which is the answer, not the noise.
  done | sort -u
}

check_distinct() {
  local map seen dup
  map="$(live_uid_map)" || true
  if [ -z "${map}" ]; then
    skip 'distinct' 'no hdw4s session unit is running, so this proves nothing'
    return
  fi
  note 'distinct (unit/uid pairs)' "$(echo "${map}" | wc -l)"

  # Root inside a session cgroup is its own failure, and it is separated from the
  # duplicate test below rather than folded into it. No session unit has a
  # "+"-prefixed Exec line -- checked, not assumed -- so root has no legitimate
  # reason to be in there; and if it were in two of them it would report as a
  # shared uid, which is a true statement that would send the reader after
  # entirely the wrong thing.
  if [ -n "$(echo "${map}" | awk '$2 == 0 || $3 == 0 {print}')" ]; then
    bad 'distinct (root in a session)' \
        "$(echo "${map}" | awk '$2 == 0 || $3 == 0 {printf "%s ", $1}')"
  else note 'distinct (no root in a session)' 'ok'; fi

  # Duplicate REAL uid across two different units, root excluded by the line above.
  dup="$(echo "${map}" | awk '$2 != 0 {print $2}' | sort | uniq -d)"
  if [ -n "${dup}" ]; then
    for seen in ${dup}; do
      bad 'distinct' "uid ${seen} is held by: $(echo "${map}" | awk -v u="${seen}" '$2==u {printf "%s ", $1}')"
    done
  else note 'distinct' 'ok (every live session holds its own uid)'; fi
  # Real and effective uid disagreeing inside a session is not this assertion,
  # but it is the same question asked one level down and costs one line.
  if echo "${map}" | awk '$2 != $3 { exit 1 }'; then
    note 'distinct (real == effective)' 'ok'
  else bad 'distinct' 'a session process has a real uid that differs from its effective uid'; fi
}

# ----------------------------------------------------------------- clean ----
# Assertion 2. Asked of a slot whose unit is NOT running: at that moment the uid
# is back in the pool and a stranger may be given it, so this is the exact
# instant the promise has to hold.
check_clean() {
  local slot="$1" id row n
  row="$(getent passwd "${slot}" 2>/dev/null || true)"
  if [ -z "${row}" ]; then skip "clean ${slot}" 'no such identity'; return; fi
  row="${row#*:}"; row="${row#*:}"; id="${row%%:*}"

  if [ "$(systemctl is-active "hdw4s-ephemeral@${slot}.service" 2>/dev/null || true)" = 'active' ]; then
    skip "clean ${slot}" 'the session is running; ask when it has stopped'
    return
  fi

  # A process. Nothing else on this list matters if one of these is alive.
  #
  # The braces are not decoration: ps exits 1 when the uid owns no process, which
  # under pipefail is the status of the whole pipeline, which under `-e` ends the
  # script. That is not a hypothetical -- it happened here, and the way it
  # presented is the reason this comment is long: every "clean" arm of the
  # selftest died before printing anything, the two arms that WANTED a non-zero
  # status read that as the check going red, and the selftest reported a proven
  # check while proving nothing. A harness that cannot tell "found a violation"
  # from "crashed" is worth less than no harness, so `expect` below now also
  # requires the word FAIL in the output before it will believe a red.
  n="$( { ps -o pid= -u "${id}" 2>/dev/null || true; } | wc -l )"
  if [ "${n}" -eq 0 ]; then note "clean ${slot} processes" 'ok'
  else bad "clean ${slot} processes" "${n} process(es) still run as uid ${id}"; fi

  # System V shared memory, semaphores and message queues. These are the ones
  # RemoveIPC= is there for, and the arm of this measured with RemoveIPC=no left
  # all three behind -- so an empty answer here is a real negative, not a query
  # that cannot find anything.
  for n in m s q; do
    if [ -n "$(ipcs -${n} 2>/dev/null | awk -v u="${slot}" '$3==u')" ]; then
      bad "clean ${slot} sysvipc -${n}" "an object owned by ${slot} outlived the session"
    else note "clean ${slot} sysvipc -${n}" 'ok'; fi
  done

  # POSIX message queues are files, and owned ones are visible by uid.
  if [ -d /dev/mqueue ] &&
     [ -n "$(find /dev/mqueue -mindepth 1 -uid "${id}" -print -quit 2>/dev/null)" ]; then
    bad "clean ${slot} posixmq" "a queue owned by uid ${id} outlived the session"
  else note "clean ${slot} posixmq" 'ok'; fi

  # The runtime directory, which is the one path measured to carry a file from
  # one start of a slot to the next. Checked as a path AND as a directive, because
  # a drop-in can turn the directive on without changing any file in the tree --
  # which is what the static half above cannot see.
  if [ -e "/run/hdw4s/${slot}" ]; then
    bad "clean ${slot} runtimedir" "/run/hdw4s/${slot} survived the session"
  else note "clean ${slot} runtimedir" 'ok'; fi
  n="$(systemctl show -p RuntimeDirectoryPreserve --value \
         "hdw4s-ephemeral@${slot}.service" 2>/dev/null || true)"
  if [ "${n}" = 'no' ] || [ -z "${n}" ]; then note "clean ${slot} preserve" "ok (${n:-no})"
  else bad "clean ${slot} preserve" "RuntimeDirectoryPreserve=${n} as loaded, drop-ins included"; fi

  # Anything under these roots that still REFERS to the identity.
  #
  # THE PREDICATE WAS THE BUG, NOT THE LIST. Until 2026-09-23 this arm swept the
  # same roots asking "what does this uid OWN", and its comment called itself the
  # part that does not depend on having thought of the right channel. It was
  # neither. Ownership is one of several ways a filesystem hands an identity
  # something, and the artefact that prompted the rewrite uses a different one: a
  # file owned by ROOT that grants the uid access through a POSIX ACL. Measured:
  # with such a file planted in a swept root, the old arm printed "ok" and the
  # script exited 0. No number of extra directories would ever have returned it,
  # because the list was not what could not see it.
  #
  # So the question asked now is whether anything still refers to the identity:
  #
  #   (1) owned by its uid, or group-owned by its PRIVATE gid;
  #   (2) named in a POSIX ACL, default ACLs included, whoever owns the file;
  #   (3) carrying its name or its uid as a whole token in a path, AND not being
  #       world-readable.
  #
  # (3) is not an access grant. It is how every channel found so far announces
  # itself -- user-<uid>.journal, /run/user/<uid>, a linger stamp, a crontab --
  # it costs nothing on a walk already being done, and it still works where
  # getfacl is missing, which (2) does not.
  #
  # The world-readable half of (3) is not tidiness, it is what makes the arm
  # usable, and it was added after watching the version without it. MEASURED on
  # an ordinary machine with a low stand-in uid: matching the uid as a bare token
  # returned /etc/grub.d/41_custom, every object under /var/lib/flatpak/repo/
  # objects/41/, cryptography-41.0.7.dist-info and srfi-41.scm -- pages of them,
  # none of them anything. That is the report nobody reads twice, and an unread
  # check protects nothing. Every one of those is world-readable; none of the
  # channels this arm is for is. Filtering on that turns a useless report into an
  # empty one without giving up a single known channel.
  #
  # WHAT THIS DELIBERATELY DOES NOT COUNT. A check that fires on the ordinary
  # state of a running machine gets switched off, and then it guards nothing;
  # that failure is as real as the one above and this project has met both. So:
  #
  #   * World-accessible objects are not counted. Every occupant gets those
  #     equally, so they carry nothing from one to the next -- and they are most
  #     of the filesystem.
  #   * SHARED supplementary groups are not counted. A grant handed to every
  #     occupant alike is not inheritance. Only the slot's PRIVATE gid counts.
  #     The groups skipped are PRINTED rather than assumed away, because the
  #     quiet half of a check is where its blind spot hides, and this is the one
  #     place this rewrite knowingly leaves one: a file group-owned by a shared
  #     group and mode g+rw does carry data from occupant to occupant, and is
  #     not reported here. Whoever closes it needs a different instrument -- a
  #     per-group sweep, run once per machine rather than once per slot.
  #   * ACL entries naming any OTHER identity are not counted. This is what keeps
  #     the arm quiet: ACLs and root-owned files referencing accounts are
  #     ordinary, but on a pool uid that no surviving account shares, the honest
  #     answer is zero, so any hit at all is worth a look.
  #
  # The ACL mask is NOT applied. An entry masked to nothing grants nothing today,
  # but on a parked slot nothing should name the uid at all, and a mask is one
  # chmod away from being back. The perms are printed so the reader can judge.
  #
  # -xdev stops the walk descending into SUB-mounts. It does NOT keep it off a
  # filesystem that is itself one of the roots: where the shared home is mounted
  # AT /home, "find /home -xdev" walks all of it. That is a cost, not a
  # correctness problem, and HDW4S_CLEAN_ROOTS exists so a run can be aimed
  # somewhere bounded. It defaults to the full list; a narrowed run is a narrowed
  # claim, and the roots actually swept are printed for that reason.
  local gid namepat roots found='' broke=''
  gid="$(getent passwd "${slot}" | cut -d: -f4)"
  roots="${HDW4S_CLEAN_ROOTS:-/run /tmp /var/tmp /dev/shm /var/lib /var/log /etc /home /srv /usr}"
  # Whole-token, so slot "s1" does not match "s10" and uid 900 does not match 9004.
  namepat="(^|[^[:alnum:]])(${slot}|${id})([^[:alnum:]]|\$)"
  note "clean ${slot} roots" "${roots}"
  note "clean ${slot} groups not swept" \
       "$(id -Gn "${slot}" 2>/dev/null | tr ' ' '\n' | grep -vx "$(id -gn "${slot}" 2>/dev/null)" |
          tr '\n' ' ' || true)"

  for n in ${roots}; do
    [ -d "${n}" ] || continue
    # find's own exit status travels IN BAND. It is not a pipefail problem to be
    # silenced: a find that could not read a directory swept less than it was
    # asked to, and an empty answer from an incomplete sweep is not a negative.
    # Silencing it with "|| true" is what the first version of this fix did, and
    # it turns "I could not look" into "I looked and there was nothing".
    # The trailing "|| true" is about SIGPIPE, not about find's status: awk stops
    # at twenty hits and the walk upstream of it dies 141, which under pipefail
    # and -e would end the script mid-arm. find's own status is already in band
    # above and is not what is being discarded here.
    found="${found}$(
      { { find "${n}" -xdev -printf '%U %G %m %p\n' 2>/dev/null; printf 'FINDRC %s\n' "$?"; } |
      awk -v id="${id}" -v gid="${gid}" -v pat="${namepat}" -v root="${n}" '
        /^FINDRC / { rc = $2; next }
        { p = $0; sub(/^[0-9]+ [0-9]+ [0-7]+ /, "", p)
          # Low octal digit of the mode: >= 4 means the world can read it, and a
          # world-readable object is not this identity being singled out.
          oth = int(substr($3, length($3), 1))
          if      ($1 == id)          { print "uid   " p; n++ }
          else if ($2 == gid)         { print "gid   " p; n++ }
          else if (p ~ pat && oth < 4) { print "name  " p; n++ }
          if (n >= 20) { print "...   more under " root ", truncated at 20"; trunc = 1; exit } }
        END { if (!trunc && rc != 0)
                print "!walk find could not read all of " root " (exit " rc \
                      "): an empty answer here is not a negative" }
      '; } || true)"$'\n'
  done

  # The ACL pass. getfacl -s prints only files that HAVE a non-base ACL, so on an
  # ordinary machine this produces almost nothing to filter; -n keeps the ids
  # numeric, because a uid whose passwd entry has already been removed is exactly
  # the case that matters and it has no name to print.
  if command -v getfacl >/dev/null 2>&1; then
    for n in ${roots}; do
      [ -d "${n}" ] || continue
      found="${found}$( {
        getfacl -R -s -n -p --absolute-names "${n}" 2>/dev/null |
        awk -v id="${id}" -v gid="${gid}" '
          /^# file: / { f = substr($0, 9); next }
          /^(default:)?user:[0-9]+:/  { split($0, a, ":"); if (a[length(a)-1] == id)  print "acl   " $0 "  " f; next }
          /^(default:)?group:[0-9]+:/ { split($0, a, ":"); if (a[length(a)-1] == gid) print "acl   " $0 "  " f }
        ' | head -20; } || true)"$'\n'
    done
  else
    broke='getfacl is not installed, so nothing asked whether an ACL names this identity'
  fi

  found="$(echo "${found}" | grep -v '^$' || true)"
  if [ -n "${broke}" ]; then
    # Not a skip. A missing instrument reporting green is the failure this whole
    # rewrite exists to stop, so the run goes red and says which half did not run.
    bad "clean ${slot} acl pass" "${broke}"
  fi
  if [ -z "${found}" ]; then note "clean ${slot} residue" 'ok (nothing refers to this identity)'
  else bad "clean ${slot} residue" "$(echo "${found}" | tr '\n' '|')"; fi
}

# ---------------------------------------------------------------- rundir ----
# Assertion 3, and it is the one the whole ephemeral design rests on without
# saying so anywhere.
#
# /run/hdw4s/<slot> is not a RECORD of whether a desktop is running behind that
# slot -- it IS that fact. systemd makes it with the session and removes it with
# the session, so the router reads it with os.path.isdir and never opens
# anything. Every derivation on the arrival path is built on that reading being
# something the occupant cannot arrange: a stranger with a full desktop and a
# shell sits inside one of these.
#
# The property that makes it unforgeable is not in any file. It is a permission
# on the PARENT: `RuntimeDirectory=hdw4s/%i` gives the last component to the
# session's user, and the intermediate /run/hdw4s is made by systemd as root.
# If an occupant could write that directory, two lines would do this:
#
#   rmdir /run/hdw4s/<some other slot>   makes an occupied slot read FREE, so
#                                        the router double-books a live desktop
#   mkdir /run/hdw4s/<every free slot>   makes the whole pool read FULL, so
#                                        every visitor is refused
#
# WHOSE ACT THE DIRECTORY IS, because two things one sentence apart get
# conflated and one of them cost a retracted measurement. The directory is made
# by SYSTEMD, while it builds the execution environment, BEFORE ExecStart runs
# -- so it is not something the session does and not something the session can
# undo, which is the whole reason it can be believed about the session. A
# measurement elsewhere timed that directory appearing and called it a session
# start; it was timing a mkdir. This check asks the other question, about
# permissions on a directory whose creation was never the session's, and that
# is why it is sound and the timing was not.
#
# Two readers disagreed from memory about whether systemd chowns every component
# of a nested RuntimeDirectory or only the last one. That disagreement is the
# reason this exists: a property nobody has checked, that everything depends on,
# is not an assumption, it is a measurement waiting to be taken. It was then
# taken, and it came back the safe way round -- which is exactly when a check has
# to be written, because the value of this arm is not today's answer. It is that
# a systemd upgrade which changes the behaviour goes RED here instead of silently
# inverting the router.
#
# WHY NOT JUST READ THE MODE. `stat` on the parent tells you what systemd did on
# this box today; it does not tell you what the kernel will refuse. A mode that
# looks right has been the wrong answer wearing the right shape twice on this
# project, and the question is whether the operation is REFUSED. So the mode is
# printed as evidence and the verdict comes from trying it.
#
# THE TWO POSITIVE CONTROLS ARE NOT OPTIONAL. Three refusals prove nothing on
# their own: a broken setpriv, a read-only /run, a missing parent and a uid that
# cannot do anything anywhere all produce the same three refusals and the same
# green line. So root must be seen to succeed at the same operations (the medium
# works), and the slot uid must be seen to succeed inside its OWN directory (the
# identity is really acting). A failure of either is reported as a failure of the
# CONTROL, in those words, and never as a pass.
#
# HDW4S_RUNDIR_PARENT points this at a fabricated parent, which is what the
# selftest uses to plant a world-writable one without touching /run. When it is
# set, the answer is about that directory and the report says so.
check_rundir() {
  local slot="${1:-_hdw4s_0}" id row parent dir fixture='' probe own msg
  row="$(getent passwd "${slot}" 2>/dev/null || true)"
  if [ -z "${row}" ]; then skip "rundir ${slot}" 'no such identity'; return; fi
  row="${row#*:}"; row="${row#*:}"; id="${row%%:*}"

  if [ "$(id -u)" != '0' ]; then
    skip "rundir ${slot}" 'needs root, to act as the slot uid and as root'
    return
  fi
  if ! command -v setpriv >/dev/null 2>&1; then
    skip "rundir ${slot}" 'no setpriv, so the slot uid could not be assumed'
    return
  fi

  if [ -n "${HDW4S_RUNDIR_PARENT:-}" ]; then
    parent="${HDW4S_RUNDIR_PARENT}"; fixture=' (fixture)'
  else
    # DERIVED, never pinned. A constant "/run/hdw4s" here would keep answering
    # confidently about a path the unit had stopped using -- which is the shape
    # of a check that validates a copy nobody runs.
    #
    # From the service manager first, because that is what is actually in force;
    # the tree's copy is the fallback for a box where the unit is not installed.
    dir="$(systemctl show -p RuntimeDirectory --value \
             "hdw4s-ephemeral@${slot}.service" 2>/dev/null || true)"
    [ -n "${dir}" ] ||
      dir="$(sed -n 's|^RuntimeDirectory=\(.*\)$|\1|p' \
               hdw4s-ephemeral@.service 2>/dev/null | head -n1 || true)"
    if [ -z "${dir}" ]; then
      bad "rundir ${slot}" 'nothing declares a RuntimeDirectory for this slot,'\
' so there is no parent to ask about'
      return
    fi
    case "${dir}" in
      */*) parent="/run/${dir%/*}" ;;
      *)   # A FLAT directive means the slot's own directory sits directly in
           # /run, and the question this check asks changes completely. Refuse
           # rather than answer about the wrong path.
           msg="RuntimeDirectory is '${dir}', which is not nested: the parent"
           msg="${msg} would be /run itself, and this check no longer asks what"
           msg="${msg} it was written to ask"
           bad "rundir ${slot}" "${msg}"
           return ;;
    esac
    if [ "$(systemctl is-active "hdw4s-ephemeral@${slot}.service" 2>/dev/null || true)" = 'active' ]; then
      skip "rundir ${slot}" 'the session is running; ask when it has stopped'
      return
    fi
  fi

  own="${parent}/${slot}"
  probe="${parent}/.uid-invariant-rundir-$$"
  if [ ! -d "${parent}" ]; then
    skip "rundir ${slot}" "no parent at '${parent}' to ask about"
    return
  fi
  if [ -e "${own}" ]; then
    # Somebody is in there, or something was left behind. Either way this arm
    # would be removing a directory it did not make.
    skip "rundir ${slot}" "'${own}' already exists; this will not touch it"
    return
  fi

  # Evidence, printed and not judged. The verdict below comes from what the
  # kernel refuses, not from what this line says.
  note "rundir ${slot} parent${fixture}" \
       "${parent} $(stat -c '%U:%G %a' "${parent}" 2>/dev/null || echo '?')"

  # CONTROL 1: the medium works. Root can make and remove a sibling here.
  if ! { mkdir "${probe}" 2>/dev/null && rmdir "${probe}" 2>/dev/null; }; then
    rm -rf "${probe}" 2>/dev/null || true
    msg="root itself cannot create a directory in '${parent}', so a refusal"
    msg="${msg} below would prove nothing"
    skip "rundir ${slot}" "${msg}"
    return
  fi
  note "rundir ${slot} control (root)" 'ok (root can create and remove here)'

  install -d -m 0700 -o "${id}" -g "${id}" "${own}"

  # CONTROL 2: the identity is really acting. The slot uid must be able to work
  # INSIDE its own directory -- otherwise setpriv is broken, or the uid cannot
  # do anything anywhere, and all three refusals below are the instrument
  # failing rather than the kernel protecting anything.
  if setpriv --reuid "${id}" --regid "${id}" --clear-groups \
       /bin/sh -c "touch '${own}/probe' && rm -f '${own}/probe'" 2>/dev/null; then
    note "rundir ${slot} control (uid ${id})" 'ok (writes inside its own directory)'
  else
    msg="could not write inside its OWN directory, so the refusals below are"
    msg="${msg} the CONTROL failing and not a property of the parent"
    bad "rundir ${slot} control (uid ${id})" "${msg}"
    rmdir "${own}" 2>/dev/null || true
    return
  fi

  # REFUSAL 1: making a sibling. This is the denial of the whole pool -- every
  # free slot made to read occupied.
  if setpriv --reuid "${id}" --regid "${id}" --clear-groups \
       /bin/mkdir "${probe}" 2>/dev/null; then
    msg="uid ${id} CREATED '${probe}': an occupant can make every free slot"
    msg="${msg} read as occupied and refuse the pool to everyone"
    bad "rundir ${slot} mkdir sibling" "${msg}"
    rmdir "${probe}" 2>/dev/null || true
  else
    note "rundir ${slot} mkdir sibling" 'ok (refused)'
  fi

  # REFUSAL 2: removing somebody else's. Done against a directory ROOT made a
  # moment ago, never against a real slot's -- if the kernel allowed it, the
  # arm would have destroyed a live session's runtime directory to find out.
  mkdir "${probe}"
  if setpriv --reuid "${id}" --regid "${id}" --clear-groups \
       /bin/rmdir "${probe}" 2>/dev/null; then
    msg="uid ${id} REMOVED '${probe}': an occupant can make an occupied slot"
    msg="${msg} read free, and the router then hands a live desktop to a second"
    msg="${msg} visitor"
    bad "rundir ${slot} rmdir sibling" "${msg}"
  else
    note "rundir ${slot} rmdir sibling" 'ok (refused)'
    rmdir "${probe}"
  fi

  # REFUSAL 3: removing its own. The directory is the occupant's, and it is
  # still not theirs to unmake: removing it needs write on the parent, and that
  # is the same permission as the two above asked from the other side.
  if setpriv --reuid "${id}" --regid "${id}" --clear-groups \
       /bin/rmdir "${own}" 2>/dev/null; then
    msg="uid ${id} REMOVED its own '${own}': the occupant can make their live"
    msg="${msg} desktop read as gone and have the slot re-let underneath them"
    bad "rundir ${slot} rmdir own" "${msg}"
  else
    note "rundir ${slot} rmdir own" 'ok (refused)'
    rmdir "${own}" 2>/dev/null || true
  fi
}

# -------------------------------------------------------------- selftest ----
# Every assertion above, broken on purpose and watched. A check nobody has seen
# go red is not known to go red, and this one guards properties whose whole
# failure mode is being silently absent -- so the proof belongs in the script,
# run every time, not in a message from whoever wrote it.
#
# The tree is copied first. Nothing here edits a tree anyone else is using.
expect() {  # expect <red|green> <label> <command...>
  local want="$1" label="$2"; shift 2
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "${want}" = 'red' ]; then
    # A non-zero status alone is not the check going red: a script that dies on
    # an unrelated error also exits non-zero, and reads as a successful proof.
    # The check has to have SAID what it found.
    # EXPECT_MATCH is for an arm that must fire for a PARTICULAR reason. A
    # contrived unit can violate two assertions at once, and "something went
    # red" would then not distinguish the one being proved from the one that
    # came along with it.
    if [ "${rc}" -ne 0 ] && grep -q 'FAIL:' <<<"${out}" &&
       { [ -z "${EXPECT_MATCH:-}" ] || grep -q "${EXPECT_MATCH}" <<<"${out}"; }; then
      note "selftest ${label}" 'ok (went red, and said why)'
      return
    fi
    if [ "${rc}" -ne 0 ] && [ -n "${EXPECT_MATCH:-}" ] &&
       ! grep -q "${EXPECT_MATCH}" <<<"${out}"; then
      bad "selftest ${label}" "went red, but not for '${EXPECT_MATCH}'"
      printf '      %s\n' "${out}"
      return
    fi
    if [ "${rc}" -ne 0 ]; then
      bad "selftest ${label}" "exited ${rc} without reporting a failure: the check crashed, it did not fire"
    else
      bad "selftest ${label}" 'the violation was planted and the check passed anyway'
    fi
  elif [ "${want}" = 'green' ] && [ "${rc}" -eq 0 ]; then
    note "selftest ${label}" 'ok (passed clean)'
    return
  else
    bad "selftest ${label}" "wanted ${want}, got exit ${rc}"
  fi
  printf '      %s\n' "${out}"
}

check_selftest() {
  local tree="${1:-.}" tmp self
  self="$(readlink -f "$0")"
  # A narrowed root list inherited from the environment would narrow the proof
  # while the selftest went on reporting the same twenty-three arms.
  unset HDW4S_CLEAN_ROOTS
  scratch="$(mktemp -d)"; tmp="${scratch}"
  trap 'rm -rf "${scratch}"' EXIT INT TERM QUIT HUP

  cp "${tree}/hdw4s-ephemeral@.service" "${tree}/hdw4s-ephemeral-slots" "${tmp}/"
  expect green 'static, tree as it stands' "${self}" static "${tmp}"

  # The edit this script exists for: one line, copied from the socket beside it.
  printf 'RuntimeDirectoryPreserve=yes\n' >> "${tmp}/hdw4s-ephemeral@.service"
  expect red 'static, RuntimeDirectoryPreserve=yes' "${self}" static "${tmp}"
  sed -i '/^RuntimeDirectoryPreserve=yes$/d' "${tmp}/hdw4s-ephemeral@.service"
  expect green 'static, line removed again' "${self}" static "${tmp}"

  local d
  for d in 'RemoveIPC=yes' 'PrivateTmp=yes' 'ProtectHome=tmpfs'; do
    sed -i "/^${d}\$/d" "${tmp}/hdw4s-ephemeral@.service"
    expect red "static, ${d} deleted" "${self}" static "${tmp}"
    printf '%s\n' "${d}" >> "${tmp}/hdw4s-ephemeral@.service"
  done
  printf 'StateDirectory=hdw4s/%%i\n' >> "${tmp}/hdw4s-ephemeral@.service"
  expect red 'static, StateDirectory added' "${self}" static "${tmp}"
  sed -i '/^StateDirectory=/d' "${tmp}/hdw4s-ephemeral@.service"

  sed -i 's|^TemporaryFileSystem=/dev/shm:|#&|' "${tmp}/hdw4s-ephemeral-slots"
  expect red 'static, drop-in loses /dev/shm' "${self}" static "${tmp}"
  sed -i 's|^#TemporaryFileSystem=/dev/shm:|TemporaryFileSystem=/dev/shm:|' "${tmp}/hdw4s-ephemeral-slots"
  expect green 'static, drop-in restored' "${self}" static "${tmp}"

  # The comparison in "distinct", against a map it cannot have produced itself.
  printf 'hdw4s-ephemeral@_hdw4s_0.service 60900 60900\nhdw4s-ephemeral@_hdw4s_1.service 60901 60901\n' \
    > "${tmp}/ok.map"
  printf 'hdw4s-ephemeral@_hdw4s_0.service 60900 60900\nhdw4s-ephemeral@_hdw4s_1.service 60900 60900\n' \
    > "${tmp}/dup.map"
  printf 'hdw4s-ephemeral@_hdw4s_0.service 60900 60901\n' > "${tmp}/euid.map"
  printf 'hdw4s-ephemeral@_hdw4s_0.service 0 0\n' > "${tmp}/root.map"
  HDW4S_UID_FIXTURE="${tmp}/ok.map"   expect green 'distinct, two different uids' "${self}" distinct
  HDW4S_UID_FIXTURE="${tmp}/dup.map"  expect red   'distinct, one uid twice'      "${self}" distinct
  HDW4S_UID_FIXTURE="${tmp}/euid.map" expect red   'distinct, euid != uid'        "${self}" distinct
  HDW4S_UID_FIXTURE="${tmp}/root.map" expect red   'distinct, root in a session'  "${self}" distinct
  # The fixtures prove the comparison. They cannot prove the thing that BUILDS
  # the map, and the map is the half that was just rewritten -- so the evasion
  # the cgroup walk exists to catch is planted for real, on real units:
  #
  #   one unit holds the uid as its MainPID, the other holds it only in a CHILD
  #   while its own MainPID is root.
  #
  # A MainPID-only check sees two different uids and passes. Both units are
  # short-lived sleeps and are removed again here; the gate below is the same one
  # the "clean" arms use, so this never runs on a machine with a live slot.
  unset HDW4S_UID_FIXTURE

  # "clean" is proved against the real machine or not at all: it reads ipcs, the
  # process table and the filesystem, and a fixture for those would be a check of
  # the fixture. Where there is no parked slot to ask about, say so.
  if [ "$(id -u)" = '0' ] && getent passwd _hdw4s_0 >/dev/null 2>&1 &&
     [ "$(systemctl is-active hdw4s-ephemeral@_hdw4s_0.service 2>/dev/null || true)" != 'active' ]; then
    local id; id="$(getent passwd _hdw4s_0 | cut -d: -f3)"

    expect green 'distinct, before the evasion is planted' "${self}" distinct
    cat > /run/systemd/system/hdw4s-ephemeral@zzselftest.service <<EOF
[Unit]
Description=uid-invariant selftest: holds the uid openly
[Service]
Type=simple
User=_hdw4s_0
ExecStart=/bin/sleep 30
EOF
    cat > /run/systemd/system/hdw4s@zzselftest.service <<EOF
[Unit]
Description=uid-invariant selftest: hides the uid in a child
[Service]
Type=simple
ExecStart=/bin/bash -c 'setpriv --reuid ${id} --regid ${id} --clear-groups /bin/sleep 30 & wait'
EOF
    systemctl daemon-reload
    systemctl start hdw4s-ephemeral@zzselftest.service hdw4s@zzselftest.service
    # "& wait" is the whole point: the MainPID systemd tracks stays the root
    # bash, and only the CHILD holds the uid. An earlier version of this arm
    # used setpriv as ExecStart, which execs and so becomes the MainPID -- it
    # went red, and would have gone red without the cgroup walk too, which
    # would have made it a proof of nothing. EXPECT_MATCH pins it to the
    # duplicate finding rather than to the root-in-a-session finding the same
    # contrived unit also triggers.
    EXPECT_MATCH="uid ${id} is held by" \
      expect red 'distinct, uid shared via a child process' "${self}" distinct
    unset EXPECT_MATCH
    systemctl stop hdw4s-ephemeral@zzselftest.service hdw4s@zzselftest.service || true
    rm -f /run/systemd/system/hdw4s-ephemeral@zzselftest.service \
          /run/systemd/system/hdw4s@zzselftest.service
    systemctl daemon-reload
    expect green 'distinct, evasion removed again' "${self}" distinct

    expect green 'clean, parked slot as it stands' "${self}" clean _hdw4s_0
    install -d -m 0700 -o "${id}" -g "${id}" /run/hdw4s/_hdw4s_0
    expect red 'clean, runtime directory planted' "${self}" clean _hdw4s_0
    rm -rf /run/hdw4s/_hdw4s_0
    : > /tmp/.uid-invariant-selftest && chown "${id}:${id}" /tmp/.uid-invariant-selftest
    EXPECT_MATCH="uid   /tmp/.uid-invariant-selftest" \
      expect red 'clean, one owned file planted' "${self}" clean _hdw4s_0
    unset EXPECT_MATCH
    rm -f /tmp/.uid-invariant-selftest
    expect green 'clean, both removed again' "${self}" clean _hdw4s_0

    # The three arms below are the rewrite of 2026-09-23, and they are planted
    # with setfacl, chmod and touch -- never by editing this script. An earlier
    # round elsewhere in this tree wrote a red arm with a blunt substitution that
    # changed the checker's own literal along with the code, and came up green
    # against a genuinely broken build. A red arm that mutates the checker proves
    # nothing, so nothing here touches it.
    #
    # First: the channel an OWNERSHIP predicate can never return -- root-owned,
    # granting the slot uid by ACL. This is the shape a per-uid journal file has.
    local aclf=/tmp/.uid-invariant-selftest-acl
    : > "${aclf}"; chmod 0640 "${aclf}"   # root-owned on purpose: NOT chowned
    if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:${id}:r--" "${aclf}" 2>/dev/null; then
      EXPECT_MATCH="acl   user:${id}:" \
        expect red 'clean, root-owned file granting the uid by ACL' "${self}" clean _hdw4s_0
      unset EXPECT_MATCH
    else
      # Not a silent pass. setfacl refuses a uid outside the container's uid map
      # -- measured, on a uid above the map's top -- and a filesystem can refuse
      # POSIX ACLs outright, so this says which it was rather than reporting a
      # proof it did not obtain.
      skip 'selftest clean acl' \
           "setfacl would not set an ACL for uid ${id} here, so this arm proved nothing"
    fi
    rm -f "${aclf}"

    # Second: the channel that announces itself by name while owning nothing and
    # granting nothing.
    local namef="/tmp/.uid-invariant-selftest-user-${id}.journal"
    : > "${namef}"; chmod 0640 "${namef}"
    EXPECT_MATCH="name  ${namef}" \
      expect red 'clean, a path naming the uid' "${self}" clean _hdw4s_0
    unset EXPECT_MATCH

    # Third, and it is the one that keeps the arm usable: the SAME file, world
    # readable, must NOT be a finding. A check only ever seen to fire is a check
    # whose quiet half nobody has tested, and the quiet half is why this one will
    # still be switched on in a year.
    chmod 0644 "${namef}"
    expect green 'clean, a world-readable path naming the uid is not a finding' \
      "${self}" clean _hdw4s_0
    rm -f "${namef}"

    # And then the real one, which is the measurement rather than the proof of
    # the comparison. It skips where there is no /run/hdw4s to ask about, and a
    # skip is not a pass -- it says so on its own line.
    expect green 'rundir, the real parent as it stands' "${self}" rundir _hdw4s_0
  else
    skip 'selftest clean' 'needs root and a parked _hdw4s_0 on this machine'
  fi

  # "rundir", against a FABRICATED parent. These arms need root -- setpriv, and
  # a directory owned by somebody else -- but NOT a parked slot, because they
  # never touch /run: the property is a permission on a directory, so it can be
  # planted with chmod on a directory of our own. That also keeps a
  # world-writable /run/hdw4s from existing for even a moment on a machine that
  # may have a live session on it. Gated separately from the block above for
  # exactly that reason: folded in with "clean", four arms that need nothing of
  # the sort would skip on every box with a session running, which is most of
  # them.
  if [ "$(id -u)" = '0' ] && getent passwd _hdw4s_0 >/dev/null 2>&1; then
    local fake="${tmp}/parent"
    # The SCRATCH DIRECTORY has to be traversable, and finding that out is the
    # best thing these arms have done so far. mktemp -d makes 0700 root-owned,
    # so the slot uid could not reach the fixture at all -- and every arm
    # reported the same thing: "could not write inside its OWN directory, so the
    # refusals below are the CONTROL failing and not a property of the parent".
    # Which is the check working. Without that control the three refusals would
    # have been produced by a uid that could not reach the directory, printed as
    # a clean green line, and the property would have been "proved" by an
    # instrument that never touched it. 0711 and not 0755: traverse is all the
    # uid needs, and it has no business listing our fixtures.
    #
    # The same thing happens where TMPDIR points somewhere the uid cannot
    # traverse -- /root, for instance -- and there is deliberately no attempt to
    # work around it. The control reports that it could not act, which is the
    # honest answer; an arm that quietly relocated itself would be answering
    # about a directory nobody asked about.
    chmod 0711 "${tmp}"
    install -d -m 0755 -o root -g root "${fake}"
    HDW4S_RUNDIR_PARENT="${fake}" \
      expect green 'rundir, a root-owned 0755 parent refuses the slot uid' \
      "${self}" rundir _hdw4s_0

    # THE ARM THIS ASSERTION EXISTS FOR. If systemd ever hands the intermediate
    # component to the session user -- which is what two readers disagreed about
    # from memory -- this is the shape it would have.
    chmod 0777 "${fake}"
    EXPECT_MATCH='mkdir sibling' \
      HDW4S_RUNDIR_PARENT="${fake}" \
      expect red 'rundir, a world-writable parent' "${self}" rundir _hdw4s_0
    unset EXPECT_MATCH

    # And the CONTROL has to be seen failing too, or a green line could be three
    # refusals produced by a uid that can do nothing anywhere. A parent the slot
    # cannot even traverse leaves root able to work here and the slot unable to
    # write inside its own directory, which must be reported as the control
    # failing and NOT as the property holding.
    chmod 0700 "${fake}"
    EXPECT_MATCH='control' \
      HDW4S_RUNDIR_PARENT="${fake}" \
      expect red 'rundir, the identity control cannot write its own directory' \
      "${self}" rundir _hdw4s_0
    unset EXPECT_MATCH

    chmod 0755 "${fake}"
    HDW4S_RUNDIR_PARENT="${fake}" \
      expect green 'rundir, the fabricated parent restored' \
      "${self}" rundir _hdw4s_0
    chmod 0700 "${tmp}"
  else
    skip 'selftest rundir' 'needs root and an _hdw4s_0 identity on this machine'
  fi
}

case "${1:-}" in
  static)   check_static "${2:-.}" ;;
  distinct) check_distinct ;;
  clean)    shift; [ "$#" -gt 0 ] || set -- _hdw4s_0
            for s in "$@"; do check_clean "${s}"; done ;;
  rundir)   check_rundir "${2:-_hdw4s_0}" ;;
  selftest) check_selftest "${2:-.}" ;;
  *) echo "usage: $0 static [<tree>] | distinct | clean <slot>... | rundir [<slot>] | selftest [<tree>]" >&2
     exit 2 ;;
esac

exit "${fail}"
