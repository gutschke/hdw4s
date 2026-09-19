#!/bin/bash -e
# The two properties that make a recycled physical uid safe, as a check rather
# than as a paragraph.
#
#   .github/uid-invariant.sh static [<tree>]   the directives, on the tree
#   .github/uid-invariant.sh distinct          no two live sessions share a uid
#   .github/uid-invariant.sh clean <slot>...   a parked slot owns nothing
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
#                      THIRTEEN of the selftest's twenty arms run there. The other
#                      seven need root and a parked slot, so CI exercises the
#                      static and fixture halves only. Keep that number attached to
#                      any claim about what CI covers here; it is the qualifier that
#                      disappears first in a summary, and then somebody believes
#                      twenty arms run in CI.
#
#   distinct, clean    a HAND TOOL for a disposable machine, and deliberately not
#                      wired into any tier. They need root, and "clean" needs a
#                      slot that is PARKED -- which a machine busy enough to be
#                      worth testing does not have, and a machine carrying real
#                      users is not somewhere to go looking. Wired, they would
#                      skip wherever they were actually run, which reads as
#                      coverage and delivers none. So: run them by hand, on a
#                      throwaway box, after any change to
#                      hdw4s-ephemeral@.service, to hdw4s-ephemeral-slots, or to
#                      how the pool hands a uid on. Revisit the wiring only
#                      somewhere a slot is reliably parked.
#
# A logical identity dies with its session. The PHYSICAL uid goes back to a free
# pool and is handed to a stranger, and two things have to be true for that to be
# harmless:
#
#   1. no two live sessions hold the same physical uid, and
#   2. a recycled uid inherits nothing from the session before it.
#
# Both were established once, by measurement, when the pool was static and a slot
# was reused a handful of times between reboots. Under a pool that grows and
# recycles they are continuous obligations, and until this script existed they
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

  # Anything at all, anywhere writable, still owned by the uid. This is the part
  # that does not depend on having thought of the right channel: the previous
  # rounds each found a new one, so the last check asks the filesystem instead of
  # asking a list. -xdev on each root keeps it off the NFS home and off /proc.
  local found=''
  for n in /run /tmp /var/tmp /dev/shm /var/lib /var/log /etc /home /srv /usr; do
    [ -d "${n}" ] || continue
    found="${found}$(find "${n}" -xdev -uid "${id}" -print 2>/dev/null | head -20)"$'\n'
  done
  found="$(echo "${found}" | grep -v '^$' || true)"
  if [ -z "${found}" ]; then note "clean ${slot} owned files" 'ok'
  else bad "clean ${slot} owned files" "$(echo "${found}" | tr '\n' ' ')"; fi
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
    if [ "${rc}" -ne 0 ] && echo "${out}" | grep -q 'FAIL:' &&
       { [ -z "${EXPECT_MATCH:-}" ] || echo "${out}" | grep -q "${EXPECT_MATCH}"; }; then
      note "selftest ${label}" 'ok (went red, and said why)'
      return
    fi
    if [ "${rc}" -ne 0 ] && [ -n "${EXPECT_MATCH:-}" ] &&
       ! echo "${out}" | grep -q "${EXPECT_MATCH}"; then
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
  printf 'hdw4s-ephemeral@ephemeral0.service 60900 60900\nhdw4s-ephemeral@ephemeral1.service 60901 60901\n' \
    > "${tmp}/ok.map"
  printf 'hdw4s-ephemeral@ephemeral0.service 60900 60900\nhdw4s-ephemeral@ephemeral1.service 60900 60900\n' \
    > "${tmp}/dup.map"
  printf 'hdw4s-ephemeral@ephemeral0.service 60900 60901\n' > "${tmp}/euid.map"
  printf 'hdw4s-ephemeral@ephemeral0.service 0 0\n' > "${tmp}/root.map"
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
  if [ "$(id -u)" = '0' ] && getent passwd ephemeral0 >/dev/null 2>&1 &&
     [ "$(systemctl is-active hdw4s-ephemeral@ephemeral0.service 2>/dev/null || true)" != 'active' ]; then
    local id; id="$(getent passwd ephemeral0 | cut -d: -f3)"

    expect green 'distinct, before the evasion is planted' "${self}" distinct
    cat > /run/systemd/system/hdw4s-ephemeral@zzselftest.service <<EOF
[Unit]
Description=uid-invariant selftest: holds the uid openly
[Service]
Type=simple
User=ephemeral0
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

    expect green 'clean, parked slot as it stands' "${self}" clean ephemeral0
    install -d -m 0700 -o "${id}" -g "${id}" /run/hdw4s/ephemeral0
    expect red 'clean, runtime directory planted' "${self}" clean ephemeral0
    rm -rf /run/hdw4s/ephemeral0
    : > /tmp/.uid-invariant-selftest && chown "${id}:${id}" /tmp/.uid-invariant-selftest
    expect red 'clean, one owned file planted' "${self}" clean ephemeral0
    rm -f /tmp/.uid-invariant-selftest
    expect green 'clean, both removed again' "${self}" clean ephemeral0
  else
    skip 'selftest clean' 'needs root and a parked ephemeral0 on this machine'
  fi
}

case "${1:-}" in
  static)   check_static "${2:-.}" ;;
  distinct) check_distinct ;;
  clean)    shift; [ "$#" -gt 0 ] || set -- ephemeral0
            for s in "$@"; do check_clean "${s}"; done ;;
  selftest) check_selftest "${2:-.}" ;;
  *) echo "usage: $0 static [<tree>] | distinct | clean <slot>... | selftest [<tree>]" >&2
     exit 2 ;;
esac

exit "${fail}"
