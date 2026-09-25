#!/bin/bash -e
# Four findings are inherent to what this file is, and are named rather than
# silenced wholesale:
#   SC2034  variables assigned here are read by the code sourced from hdw4s,
#           which the linter cannot see across the source boundary.
#   SC2154  "user" and "session" are outputs of split_name and
#           split_legacy_name, set as globals.
#   SC2030/SC2031  each group runs in its own subshell on purpose, so that one
#           failure cannot derail the rest; the linter reads the isolation as
#           an accident.
#   SC2015  "cond && ok ... || bad ..." is the assertion idiom here. The
#           warning is about C running when A is true, which needs B to fail;
#           ok() is an echo and a printf and does not.
#   SC1091  setup.sh is written by sandbox() at run time, so there is nothing
#           on disk for the linter to follow.
#   SC2317  the stubs standing in for systemctl and ss are called only from the
#           code sourced out of hdw4s, which the linter cannot see, so it reads
#           every branch of them as dead.
# shellcheck disable=SC2034,SC2154,SC2030,SC2031,SC2015,SC1091,SC2317
export LC_ALL='C'
set -o nounset -o pipefail

# Behaviour tests. Every one of these exists because the behaviour it checks
# was once wrong -- each is written from the failure, not from the code, so
# that it still means something after the code is rewritten.
#
#   .github/tests.sh
#
# Needs bash, coreutils, python3 and a loopback interface. Anything that would
# need systemd, nft or a live session is deliberately not here; those belong on
# a real machine.
#
# python3 was added when the last two groups were: the router is written in it,
# and a suite that cannot run the router cannot notice the router disagreeing
# with the tool -- which is exactly what shipped. It is a hard dependency of the
# package, so requiring it here narrows nothing.

cd "$(dirname "$0")/.."
ROOT="${PWD}"

# The scripts resolve their siblings under ${HDW4S_LIBDIR:-/usr/lib/hdw4s}.
# Exported here so that everything sourced or run below reaches THIS tree.
# Without it an installed copy would answer instead, and a suite that passes
# against the package while the working tree is broken is worse than no suite:
# hdw4s-duration is where the idle window's grammar lives, so the whole of the
# duration group would have been testing whatever is in /usr/lib/hdw4s.
export HDW4S_LIBDIR="${ROOT}"

# Results go to a file, not to shell variables: every group runs in a subshell
# so that one failure cannot derail the rest, and a subshell cannot hand a
# counter back to its parent. Counting in variables looked like it worked and
# reported "All 0 tests passed" no matter what happened.
RESULTS="$(mktemp)"
trap 'rm -f "${RESULTS}"' EXIT
ok()   { echo "ok" >> "${RESULTS}"; printf '  ok   %s\n' "$1"; }
bad()  { echo "fail" >> "${RESULTS}"; printf '  FAIL %s\n' "$1"; [ $# -lt 2 ] || printf '       %s\n' "$2"; }
is()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected [$3], got [$2]"; }
has()  { case "$2" in *"$3"*) ok "$1";; *) bad "$1" "missing: $3";; esac; }
hasnt(){ case "$2" in *"$3"*) bad "$1" "should not contain: $3";; *) ok "$1";; esac; }

# A sandbox with the CLI's functions loaded and every path it writes to
# redirected somewhere disposable. The dispatcher is cut off so that sourcing
# does not run a command.
sandbox() {
  SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s" > "${SB}/lib.sh"
  mkdir -p "${SB}/etc" "${SB}/dropin" "${SB}/profiles"
  # Written here, sourced at a group's top level, never from a function:
  # "declare -A" inside a function is local to it, so sourcing hdw4s from a
  # helper made SETTABLE and GLOBAL_ONLY disappear the moment the helper
  # returned -- and every test that depends on them then passed or failed for
  # reasons unrelated to what it names.
  cat > "${SB}/setup.sh" <<'SETUP'
  # shellcheck source=/dev/null
  . "${SB}/lib.sh"
  # The sourced script installs its own EXIT/ERR trap. An ERR trap fires even
  # under "set +e", so any bare non-zero command -- a grep that matches
  # nothing, a test used as a statement -- killed the rest of the group on the
  # spot: remaining assertions never ran, no failure was recorded, and the run
  # exited 0. It also replaced the sandbox cleanup, leaking a temp directory
  # per group.
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  CONF="${SB}/etc/hdw4s.conf"; SLOTS="${SB}/etc/instances"
  DROPIN="${SB}/dropin"; HDW4S_PROFILE_DIR="${SB}/profiles"
  ETCDIR="${SB}/etc"
  : > "${CONF}"
SETUP
}

echo '== instance names =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Not "split_name … && is …": if the call fails the assertion never runs and
  # nothing is recorded, so making split_name reject every name looked like a
  # pass.
  user=''; session=''
  split_name 'alice'   2>/dev/null || :; is 'plain name accepted'     "${user}:${session}" 'alice:1'
  # An account has one desktop. The second-session form is refused everywhere
  # except "release", which has to be able to retire one that already exists.
  split_name 'alice:2' 2>/dev/null && bad 'colon rejected' || ok 'colon rejected'
  user=''; session=''
  split_legacy_name 'alice:2' 2>/dev/null || :
  is 'colon accepted for release' "${user}:${session}" 'alice:2'
  # The escape hatch is not a hole: it gives up the session number, and nothing
  # else. Everything that keeps a name out of a file path still applies to it.
  split_legacy_name '../../root/x' 2>/dev/null && bad 'legacy path traversal rejected' || ok 'legacy path traversal rejected'
  split_legacy_name 'alice:0'      2>/dev/null && bad 'legacy session 0 rejected'      || ok 'legacy session 0 rejected'
  split_legacy_name ''             2>/dev/null && bad 'legacy empty name rejected'     || ok 'legacy empty name rejected'
  # A name reaches file paths, so it is checked even where the account need not exist.
  split_name '../../root/x' 2>/dev/null && bad 'path traversal rejected' || ok 'path traversal rejected'
  split_name 'alice:0'      2>/dev/null && bad 'session 0 rejected'       || ok 'session 0 rejected'
  split_name ''             2>/dev/null && bad 'empty name rejected'      || ok 'empty name rejected'
)

echo '== port arithmetic =='
( set +e; sandbox; . "${SB}/setup.sh"
  # The relay binds the first block; the streaming server listens on the second.
  # Deriving one where the other was meant made the reaper stop busy sessions.
  is 'external port'  "$(port_of 0)"          '7300'
  is 'internal port'  "$(internal_port_of 0)" '7364'
  is 'blocks do not overlap' "$(( $(internal_port_of 0) - $(port_of 63) ))" '1'
)

echo '== a session counts as protected only when both halves are there =='
( set +e; sandbox; . "${SB}/setup.sh"
  # "hdw4s enable" decides whether to generate a credential by asking this, and
  # "hdw4s list" counts unprotected sessions with it. Made to return true
  # unconditionally, every session reports AUTH=yes and the warning about
  # sessions that authenticate nobody never appears again.
  printf 'HDW4S_AUTH=basic\n' > "${SB}/etc/alice.conf"
  : > "${SB}/etc/alice.auth.cred"
  has_auth alice && is 'setting and credential together' 'yes' 'yes' \
                 || is 'setting and credential together' 'no' 'yes'

  rm -f "${SB}/etc/alice.auth.cred"
  has_auth alice && is 'setting without credential' 'yes' 'no' \
                 || is 'setting without credential' 'no' 'no'

  : > "${SB}/etc/bob.auth.cred"
  : > "${SB}/etc/bob.conf"
  has_auth bob && is 'credential without setting' 'yes' 'no' \
               || is 'credential without setting' 'no' 'no'
)

echo '== settings lookup =='
( set +e; sandbox; . "${SB}/setup.sh"
  printf 'HDW4S_TRANSPORT=unix\n' > "${CONF}"
  is 'global is read'            "$(setting_of alice HDW4S_TRANSPORT tcp)" 'unix'
  printf 'HDW4S_TRANSPORT=tcp\n' > "${SB}/etc/alice.conf"
  # The whole point of per-instance configuration, and the one direction the
  # group never asserted: with both files present the instance's must win.
  # Reversing the two file names inside setting_of left every test here
  # passing while every per-session override silently stopped working.
  is 'instance file wins over global' \
     "$(setting_of alice HDW4S_TRANSPORT zzz)" 'tcp'
  # cmd_seed once had its own copy of this and read only the instance file,
  # so a site-wide setting looked unset.
  mkdir -p "${SB}/etc"; CONF="${SB}/etc/hdw4s.conf"
  is 'fallback when unset'       "$(setting_of bob HDW4S_MISSING zzz)"     'zzz'
  # A trailing comment is not part of the value.
  printf 'HDW4S_TRANSPORT=unix   # keep it off the network\n' > "${CONF}"
  is 'trailing comment stripped' "$(setting_of bob HDW4S_TRANSPORT tcp)"   'unix'
)

echo '== slot allocation =='
( set +e; sandbox; . "${SB}/setup.sh"
  a="$(alloc_slot alice)"; b="$(alloc_slot bob)"
  is 'first slot'  "${a}" '0'
  is 'second slot' "${b}" '1'
  is 'same name is idempotent' "$(alloc_slot alice)" '0'
  is 'one row per instance' "$(awk '$2=="alice"' "${SLOTS}" | wc -l | tr -d ' ')" '1'
)

echo '== slot allocation is atomic =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Scanning for a free slot and claiming it must be one operation: two runs
  # at once used to read the same table and append the same index.
  for i in 1 2 3 4 5 6 7 8; do ( alloc_slot "u${i}" >> "${SB}/out" ) & done
  wait
  is 'eight distinct slots' "$(sort -u "${SB}/out" | wc -l)" '8'
  : > "${SB}/same"
  for i in 1 2 3 4 5 6; do ( alloc_slot shared >> "${SB}/same" ) & done
  wait
  is 'repeated name gets one slot' "$(sort -u "${SB}/same" | wc -l)" '1'
  is 'and one table row'           "$(awk '$2=="shared"' "${SLOTS}" | wc -l | tr -d ' ')" '1'
)

echo '== configuration is validated before it is trusted =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  # Sourcing a file with a syntax error applies every assignment before the
  # error and none after. Refusing is the only way to tell that apart from a
  # file that merely ends in a false conditional.
  printf 'HDW4S_PROXIES=10.0.0.1\nif [ x\n' > "${SB}/broken.conf"
  bash -n "${SB}/broken.conf" 2>/dev/null && bad 'broken config rejected' || ok 'broken config rejected'
  printf 'HDW4S_PROXIES=10.0.0.1\n[ -n "" ] && HDW4S_X=1\n' > "${SB}/falsy.conf"
  bash -n "${SB}/falsy.conf" 2>/dev/null && ok 'valid config accepted' || bad 'valid config accepted'
  # Run the real thing. Grepping for the literal "bash -n" passed with the
  # check pointed at /dev/null -- the string present, the validation gone,
  # which is the mechanism-not-outcome mistake this suite exists to end.
  mkdir -p "${SB}/etc"
  printf 'HDW4S_PROXIES=10.0.0.1\nif [ x\n' > "${SB}/etc/hdw4s.conf"
  out="$(HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" --version 2>&1)" && rc=0 || rc=$?
  is  'a broken config stops the CLI'      "${rc}" '1'
  has 'and the refusal names the file'     "${out}" "${SB}/etc/hdw4s.conf"
  out="$(HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s-firewall" --print 2>&1)" && rc=0 || rc=$?
  is  'a broken config stops the firewall' "${rc}" '1'
  printf 'HDW4S_PROXIES=10.0.0.1\n' > "${SB}/etc/hdw4s.conf"
  HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" --version >/dev/null 2>&1 \
    && ok 'a good config does not' || bad 'a good config does not'

  # Wrong arguments are the user's mistake. They used to exit through the ERR
  # trap, so the usage text was followed by "Script hdw4s failed unexpectedly"
  # and a mistyped command read as a crash in the tool.
  out="$(HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" auth one two 2>&1)" && rc=0 || rc=$?
  is    'too many arguments is a usage error' "${rc}" '2'
  has   'and prints the usage'                "${out}" 'Usage: hdw4s'
  hasnt 'and does not read as a crash'        "${out}" 'failed unexpectedly'

  # HDW4S_FRAMERATE is a rate or a range. hdw4s-run-session turns a bare number
  # into "N,8-N" so the setting caps the rate instead of merely starting there,
  # and passes an explicit range through untouched -- so the range form has to
  # be settable. Typed as a plain number it was not, and editing the file by
  # hand was the only way to use what the runner supports.
  for v in 30 30,8-30; do
    HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" set "HDW4S_FRAMERATE=${v}" >/dev/null 2>&1 \
      && ok "framerate ${v} accepted" || bad "framerate ${v} accepted"
  done
  for v in abc '30,' 30-8; do
    HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" set "HDW4S_FRAMERATE=${v}" >/dev/null 2>&1 \
      && bad "framerate ${v} refused" || ok "framerate ${v} refused"
  done
)

echo '== a setting owned by a command names a command that exists =='
( set +e; sandbox; . "${SB}/setup.sh"
  # "hdw4s set X HDW4S_AUTH=none" told the user to run "hdw4s auth X none",
  # which takes one argument too many and failed in front of them. Turning
  # authentication off is a different command, not a different argument.
  is 'turning auth off points at noauth' \
     "$(owning_command HDW4S_AUTH inst none)" 'hdw4s noauth inst'
  is 'turning it on points at auth'      \
     "$(owning_command HDW4S_AUTH inst basic)" 'hdw4s auth inst'
  # Transport really does take the value as an argument; it must keep it.
  is 'transport keeps its value'         \
     "$(owning_command HDW4S_TRANSPORT inst unix)" 'hdw4s transport inst unix'
  # And every suggestion has to be one the dispatcher actually accepts. Checking
  # only that the verb exists is not enough and was tried: "hdw4s auth X none"
  # names a real command and still fails, because auth takes one argument. So
  # run each suggestion and require that it is not rejected as a usage error --
  # it will fail for other reasons here, having no such instance, and that is
  # fine. Exit 2 is the one answer that means "you cannot type this".
  # One assertion, not one per suggestion: a group that emits a different
  # number of results depending on the outcome throws the suite's own count
  # off, and "129 of 128 tests ran" is a worse report than the failure it is
  # hiding.
  _unpasteable=''
  for _c in "$(owning_command HDW4S_AUTH i none)" \
            "$(owning_command HDW4S_AUTH i basic)" \
            "$(owning_command HDW4S_TRANSPORT i unix)"; do
    # Splitting is the point here: the suggestion is a command line, and the
    # test is whether the dispatcher accepts it as one.
    # shellcheck disable=SC2086
    set -- ${_c}; shift          # drop the leading "hdw4s"
    HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" "$@" >/dev/null 2>&1
    [ $? -ne 2 ] || _unpasteable="${_unpasteable}${_c}; "
  done
  is 'every suggestion can actually be typed' "${_unpasteable}" ''
)

echo '== unset takes a name, not a pattern =='
( set +e; sandbox; . "${SB}/setup.sh"
  printf 'HDW4S_A=1\nHDW4S_B=2\nHDW4S_C=3\n' > "${CONF}"
  # "hdw4s unset '.*'" once commented out every line and reported success.
  ( cmd_unset '.*' ) >/dev/null 2>&1 && bad 'pattern rejected' || ok 'pattern rejected'
  is 'file untouched by a rejected key' "$(grep -c '^HDW4S_' "${CONF}")" '3'
  ( cmd_unset 'HDW4S_B' ) >/dev/null 2>&1 || :
  is 'a real key is commented out' "$(grep -c '^HDW4S_' "${CONF}")" '2'
)

echo '== a machine-wide setting is refused per session =='
( set +e; sandbox; . "${SB}/setup.sh"
  me="$(id -un)"
  # A session sources both files, so most settings work per instance for free.
  # These are read by the CLI, the firewall or the updater, none of which has an
  # instance in hand -- writing one into an instance file parses, passes every
  # check, and does nothing.
  ( cmd_set "${me}" 'HDW4S_PROXIES=10.0.0.1' ) >/dev/null 2>&1 \
    && bad 'machine-wide setting refused on an instance' \
    || ok  'machine-wide setting refused on an instance'
  is 'and nothing was written' "$([ -e "${ETCDIR}/${me}.conf" ] && echo yes || echo no)" 'no'
  ( cmd_set 'HDW4S_PROXIES=10.0.0.1' ) >/dev/null 2>&1 \
    && ok  'the same setting is accepted globally' \
    || bad 'the same setting is accepted globally'
  ( cmd_set "${me}" 'HDW4S_ISOLATION=profile' ) >/dev/null 2>&1 \
    && ok  'a per-session setting is still accepted' \
    || bad 'a per-session setting is still accepted'

  # Settings whose effect lives in a drop-in only a dedicated command writes.
  # Accepting these recorded a value that "list", "show" and "proxy" then
  # reported while the session went on using the old one.
  for k in HDW4S_TRANSPORT=unix HDW4S_AUTH=basic; do
    ( cmd_set "${me}" "${k}" ) >/dev/null 2>&1 \
      && bad "${k%%=*} is not settable this way" \
      || ok  "${k%%=*} is not settable this way"
  done
  out="$( ( cmd_set "${me}" 'HDW4S_TRANSPORT=unix' ) 2>&1 )"
  has 'and says which command does write it' "${out}" 'hdw4s transport'

  # HDW4S_AUTH has NO machine-wide form -- the one key that is refused both
  # ways. This test used to assert the opposite, because hdw4s.conf and the
  # manual documented setting it site-wide so every session created afterwards
  # got a credential. Two administrators asked as users of the tool called that
  # a trap and the owner had it removed: a security-relevant switch set once and
  # inherited silently is how a session ends up without a credential that nobody
  # decided to drop.
  #
  # It never worked in the direction people reach for either. A global "none"
  # was silently overridden, because "enable" writes a per-session value that
  # shadows it; only "basic" appeared to take, and only because new sessions get
  # a credential anyway. One direction ignored, the other redundant.
  ( cmd_set 'HDW4S_AUTH=basic' ) >/dev/null 2>&1 \
    && bad 'HDW4S_AUTH is refused machine-wide too' \
    || ok  'HDW4S_AUTH is refused machine-wide too'
  out="$( ( cmd_set 'HDW4S_AUTH=basic' ) 2>&1 )"
  has 'and names the per-session command instead' "${out}" 'hdw4s auth <session>'
  # The control: another key with a legitimate machine-wide form still takes
  # one, so the refusal above is about this key and not about every global set.
  ( cmd_set 'HDW4S_IDLE_DAYS=9' ) >/dev/null 2>&1 \
    && ok  'a key that IS machine-wide still is' \
    || bad 'a key that IS machine-wide still is'

  # "set" was guarded and "unset" was not, so authentication could be turned
  # off in one word while the credential file stayed and "show" went on
  # reporting it.
  printf 'HDW4S_AUTH=basic\n' > "${SB}/etc/${me}.conf"
  ( cmd_unset "${me}" 'HDW4S_AUTH' ) >/dev/null 2>&1 \
    && bad 'unset is guarded the same way as set' \
    || ok  'unset is guarded the same way as set'
  has 'and the setting survived the refusal' \
      "$(cat "${SB}/etc/${me}.conf")" 'HDW4S_AUTH=basic'
)

echo '== the clean-install test will not delete outside its own directory =='
( set +e
  # ROOT is "${BASE}/${SUITE}" and that script runs "rm -rf" on it as root, so
  # a suite name that walks upwards deletes something else entirely. Argument
  # parsing happens before the root check, so this is safe to run here.
  for bad_suite in '../../tmp/x' '/etc' 'noble/../..' '-rf' ''; do
    if "${ROOT}/.github/clean-install-test.sh" --suite "${bad_suite}" >/dev/null 2>&1; then
      bad "rejects --suite '${bad_suite}'"
    else
      ok  "rejects --suite '${bad_suite}'"
    fi
  done
  "${ROOT}/.github/clean-install-test.sh" --suite noble --help >/dev/null 2>&1 \
    && ok 'and still accepts a real suite name' \
    || bad 'and still accepts a real suite name'
)

echo '== list accounts for every slot, including the ones it cannot resolve =='
( set +e; sandbox; . "${SB}/setup.sh"
  me="$(id -un)"
  # A slot whose account has been deleted was skipped in silence: gone from the
  # table and from the AUTH=NO count, while still holding its port and while
  # the firewall still opened it. "list" is what an administrator reads to find
  # out what is reachable.
  printf '0 %s\n1 nosuchuser-hdw4s\n' "${me}" > "${SLOTS}"
  out="$(cmd_list 2>/dev/null)"
  has 'the resolvable slot is listed'   "${out}" "${me}"
  has 'the orphaned slot is listed too' "${out}" 'nosuchuser-hdw4s'
  has 'and is marked as such'           "${out}" 'orphaned'
  has 'with its port still named'       "${out}" '7301'
  has 'and says what to do about it'    "${out}" 'hdw4s release'
)

echo '== show can say which file a value came from =='
( set +e; sandbox; . "${SB}/setup.sh"
  # "show" is documented as reporting where each setting came from, and could
  # not: it printed the instance file and nothing else, so every inherited
  # value -- the ones somebody runs the command to find -- was missing.
  printf 'HDW4S_FRAMERATE=60\n' > "${CONF}"
  r="$(setting_with_source alice HDW4S_FRAMERATE 30)"
  is 'a global value is found'   "${r%%$'\t'*}" '60'
  is 'and attributed to the global file' "${r#*$'\t'}" "${CONF}"

  printf 'HDW4S_FRAMERATE=24\n' > "${SB}/etc/alice.conf"
  r="$(setting_with_source alice HDW4S_FRAMERATE 30)"
  is 'the instance value wins'   "${r%%$'\t'*}" '24'
  is 'and is attributed to it'   "${r#*$'\t'}" "${SB}/etc/alice.conf"

  r="$(setting_with_source bob HDW4S_NOTHING zzz)"
  is 'a default is reported as such' "${r%%$'\t'*}" 'zzz'
  is 'with no file named'            "${r#*$'\t'}" ''
)

echo '== the profile directory is read the same way everywhere =='
( set +e; sandbox; . "${SB}/setup.sh"
  # hdw4s-session honours the instance file. "seed", "show" and "release" read
  # the globally sourced variable instead, so setting this per session made
  # "seed" populate a directory the session would never open -- and report that
  # it had seeded the profile.
  HDW4S_PROFILE_DIR='/var/lib/hdw4s'
  printf 'HDW4S_PROFILE_DIR=/srv/profiles\n' > "${SB}/etc/alice.conf"
  is 'the instance value is used'  "$(profile_dir_of alice)" '/srv/profiles'
  is 'and the global for another'  "$(profile_dir_of bob)"   '/var/lib/hdw4s'
  printf 'HDW4S_PROFILE_DIR=/srv/all\n' > "${CONF}"
  is 'a global setting is honoured' "$(profile_dir_of bob)"  '/srv/all'
  is 'and the instance still wins'  "$(profile_dir_of alice)" '/srv/profiles'
)

echo '== a setting is pointed at the action that applies it =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Every one of these used to print "restart the session", which for all
  # three of them does nothing at all.
  out="$(set_hint '' 'HDW4S_MEDIA_PORTS=direct' 2>&1)"
  has   'media ports point at the firewall' "${out}" 'firewall --apply'
  hasnt 'and not at a restart'              "${out}" 'estart'
  out="$(set_hint '' 'SELKIES_VERSION=1.6.2' 2>&1)"
  has   'a pinned version points at the updater' "${out}" 'hdw4s-update'
  out="$(set_hint 'alice' 'HDW4S_RESIZE=true' 2>&1)"
  has   'an ordinary setting still points at a restart' \
        "${out}" 'systemctl restart hdw4s@alice'
)

echo '== the updater checks what it downloaded =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  eval "$(sed -n '/^verify_sha256() {/,/^}/p;/^asset_digest() {/,/^}/p' \
          "${ROOT}/hdw4s-update")"

  printf 'payload' > "${SB}/f"
  good="$(sha256sum "${SB}/f" | cut -d' ' -f1)"
  bad="$(printf '%064d' 0)"

  verify_sha256 "${SB}/f" "${good}" thing >/dev/null 2>&1
  is 'a matching checksum passes' "$?" '0'
  verify_sha256 "${SB}/f" "${bad}" thing >/dev/null 2>&1
  is 'a mismatched checksum fails' "$?" '1'
  out="$(verify_sha256 "${SB}/f" "${bad}" thing 2>&1)"
  has 'and says what it expected' "${out}" "${bad}"
  has 'and what it got'           "${out}" "${good}"
  has 'and that nothing changed'  "${out}" 'Nothing has been changed'

  # Both shapes of the same response: the API is served compact to one client
  # and pretty-printed to another, and a parser that only handled one reported
  # "no digest published" for an asset that had one.
  d='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  cat > "${SB}/compact.json" <<EOF
{"tag_name":"v9","assets":[{"name":"none.tgz","uploader":{"login":"x"},"digest":null},{"name":"has.whl","uploader":{"login":"x"},"digest":"sha256:${d}"}]}
EOF
  cat > "${SB}/pretty.json" <<EOF
{
  "tag_name": "v9",
  "assets": [
    { "name": "none.tgz", "uploader": { "login": "x" }, "digest": null },
    { "name": "has.whl",  "uploader": { "login": "x" }, "digest": "sha256:${d}" }
  ]
}
EOF
  release="${SB}/compact.json"
  is 'a published digest is found in compact JSON' "$(asset_digest 'has.whl')" "${d}"
  # The asset embeds an uploader object, so splitting the array on braces puts
  # the name and the digest in different pieces. This is that regression.
  release="${SB}/pretty.json"
  is 'and in pretty-printed JSON'                 "$(asset_digest 'has.whl')" "${d}"
  # Without an upper bound on the span, an asset with a null digest borrows the
  # digest of whichever asset comes next -- a wrong answer, not a missing one.
  is 'an asset with no digest reports none'       "$(asset_digest 'none.tgz')" ''
  is 'an unknown asset reports none'              "$(asset_digest 'nope.whl')" ''
  release="${SB}/does-not-exist"
  is 'a missing release file reports none'        "$(asset_digest 'has.whl')" ''

  # The pins themselves. A release that bumps KNOWN_GOOD without recording the
  # hash of the package it now points at would install an unchecked download.
  deb_sum="$(sed -n "s/^KNOWN_GOOD_SHA256_DEB='\([0-9a-f]*\)'.*/\1/p" \
             "${ROOT}/hdw4s-update")"
  deb_asset="$(sed -n "s/^KNOWN_GOOD_ASSET='\([^']*\)'.*/\1/p" \
               "${ROOT}/hdw4s-update")"
  is 'the package hash is recorded, 64 hex digits' "${#deb_sum}" '64'
  # The hash is only reachable when the asset it belongs to is named: the
  # updater compares the downloaded filename against this before using it.
  is 'the asset it belongs to is named' \
     "$([ -n "${deb_asset}" ] && echo yes || echo no)" 'yes'
  is 'and it is a .deb'                 "${deb_asset##*.}" 'deb'
)

echo '== the four spellings of one release =='
# The tag, the package version and what "selkies --version" prints are three
# different strings for the same release. Compare the wrong pair and the
# updater either reinstalls every night, because they never match, or -- with a
# comparison loose enough to stop that -- never installs anything again.
( set +e
  eval "$(sed -n '/^version_from_package() {/,/^}/p;/^version_from_tag() /p' \
          "${ROOT}/hdw4s-update")"

  is 'a package version loses its revision and tildes' \
     "$(version_from_package '2.0.0~rc0-1~ubuntu24.04')" '2.0.0rc0'
  # Nothing to strip: a bare upstream version has to survive unchanged, or the
  # pre-2.0 installed version would never compare equal to anything.
  is 'a plain version is left alone' "$(version_from_package '1.6.2')" '1.6.2'
  is 'a tag loses its "v"'           "$(version_from_tag 'v2.0.0rc0')" '2.0.0rc0'
  # Upstream tagged without the prefix before 2.0, so it is optional.
  is 'an unprefixed tag is left alone' "$(version_from_tag '1.6.2')" '1.6.2'
)

# A dependency that is installed must be reported as installed however many
# packages the machine has. The version this replaces asked with
#
#   printf '%s\n' "${have}" | grep -qxF -- "${name}"
#
# and grep -q exits the instant it matches, which SIGPIPEs the producer, which
# is status 141, which under pipefail is the status of the pipeline -- so the
# answer inverted, and only once the list was long enough that grep finished
# first. A test container never saw it; a desktop with 4681 packages reported
# every one of Selkies' twenty dependencies missing and refused to install.
#
# So the list here is deliberately long and the match deliberately first. That
# is the shape that fails; a short list, or a match at the end, passes either
# way and would not be a test.
echo '== a long installed-package list does not invert the answer =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  eval "$(sed -n '/^unmet_depends() {/,/^}/p' "${ROOT}/hdw4s-update")"

  # Stubs, because the real ones read this machine's dpkg database and the
  # point is to fix the input, not to describe whatever is installed here.
  # They are called only from the function eval'd above, which shellcheck
  # cannot see, so it reads every one of them as dead code.
  # shellcheck disable=SC2317
  installed_names() { printf 'aardvark\n'; seq 1 20000 | sed 's/^/pkg/'; }
  # shellcheck disable=SC2317
  dpkg-deb() { printf 'aardvark, pkg19999, libnothing-at-all\n'; }

  out="$(unmet_depends "${SB}/unused.deb" | tr '\n' ' ')"
  is 'a match at the head of a long list counts as installed' \
     "$(printf '%s' "${out}" | grep -c 'aardvark')" '0'
  is 'a match at the tail counts too' \
     "$(printf '%s' "${out}" | grep -c 'pkg19999')" '0'
  has 'and something genuinely absent is still reported' "${out}" 'libnothing-at-all'

  # Alternatives and version constraints, which share the same loop.
  # shellcheck disable=SC2317
  dpkg-deb() { printf 'libglib2.0-0 | aardvark, pkg1 (>= 1.2), libgone:any\n'; }
  out="$(unmet_depends "${SB}/unused.deb" | tr '\n' ' ')"
  is 'an alternative satisfied by the second name is not missing' \
     "$(printf '%s' "${out}" | grep -c 'libglib')" '0'
  is 'a version constraint does not hide the name' \
     "$(printf '%s' "${out}" | grep -c 'pkg1 ')" '0'
  has 'an architecture qualifier is stripped before the lookup' "${out}" 'libgone'
)

echo '== firewall ruleset shape =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s-firewall" > "${SB}/fw.sh"
  # shellcheck source=/dev/null
  . "${SB}/fw.sh" 2>/dev/null || :
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  HDW4S_PROXIES='10.0.0.1'; HDW4S_BASE_PORT=7300; HDW4S_BLOCK_SIZE=64

  HDW4S_MEDIA_PORTS='proxied'; out="$(generate 2>/dev/null)"
  has  'input chain present'        "${out}" 'chain input'
  has  'media chain present'        "${out}" 'chain media'
  # Dropped once in a rewrite; ICMP errors for a session's own flow then hit
  # the drop and produced intermittent path-MTU black holes.
  has  'media keeps a protocol guard' "${out}" 'meta l4proto != { tcp, udp } accept'
  has  'established traffic accepted' "${out}" 'ct state established,related accept'
  has  'loopback accepted'            "${out}" 'iifname "lo" accept'
  # 'drop' alone matches the explanatory comments in the generated ruleset, so
  # turning every verdict into accept left this green.
  has  'input chain drops'            "${out}" 'counter drop'
  is   'both chains carry a verdict'  "$(printf '%s' "${out}" | grep -c 'counter drop')" '2'
  # Presence is not enough: nftables takes the first rule that matches, so an
  # accept placed above the drop makes the chain accept everything while every
  # assertion above still passes. Assert the position, not the existence -- the
  # last verdict in each chain has to be the drop.
  # Every legitimate accept in these chains carries a condition -- a protocol
  # test, a port test, "ct state", "iifname", a set lookup. An accept with no
  # condition matches everything, and because nftables takes the first rule
  # that matches, one placed anywhere above the drop opens the chain
  # completely. So the invariant is not where the drop sits but that nothing
  # unconditional precedes it: the drop is the only rule in a chain that
  # applies to every packet reaching it.
  uncond="$(printf '%s\n' "${out}" |
            sed 's/^[[:space:]]*//' |
            grep -cE '^(counter )?accept$')"
  is 'no chain accepts unconditionally' "${uncond}" '0'
  # And the drop is still there, once per chain, at the end of it.
  #
  # Keyed by the chain's name, and matched on the end of the rule rather than
  # the whole of it. Both mattered: this compared the second line of the list
  # against the exact string "counter drop", so it silently depended on which
  # chain generate() happened to emit second, and on which media chain this
  # machine gets -- the cgroup form ends "socket cgroupv2 level 1
  # "hdw4s.slice" counter drop", which is the same verdict wearing a
  # condition. It passed on a machine where hdw4s had never run and failed on
  # one where it had, which is not a property a test reading generated text
  # should have at all.
  ends="$(printf '%s\n' "${out}" |
          awk '/chain [a-z]+ \{/ { inchain = 1; last = ""; name = $2 }
               inchain && !/^[[:space:]]*#/ && /accept$|drop$/ { last = $0 }
               inchain && /^[[:space:]]*\}/ {
                 inchain = 0; sub(/^[[:space:]]+/, "", last)
                 print name "\t" last }')"
  ends_in_drop() {
    local line
    line="$(printf '%s\n' "${ends}" | awk -F'\t' -v n="$1" '$1 == n { print $2 }')"
    case "${line}" in
      '')             echo "no ${1} chain";;
      *'counter drop') echo 'counter drop';;
      *)              echo "${line}";;
    esac
  }
  is 'input chain ends in the drop' "$(ends_in_drop input)" 'counter drop'
  is 'media chain ends in the drop' "$(ends_in_drop media)" 'counter drop'
  # generate() emits whichever media chain this machine can support, so the
  # assertion above only ever sees one of the two. Hand the matcher the other
  # one directly, so that the test means the same thing on every machine
  # instead of quietly checking half as much on most of them.
  ends="$(printf 'media\tsocket cgroupv2 level 1 "hdw4s.slice" counter drop\n')"
  is 'the cgroup form counts as ending in the drop' \
     "$(ends_in_drop media)" 'counter drop'
  ends="$(printf 'media\tip saddr @proxies4 accept\n')"
  is 'a chain ending in an accept does not' \
     "$(ends_in_drop media)" 'ip saddr @proxies4 accept'

  # generate() emits one of two media chains depending on whether this machine
  # can match a cgroup, so a test of its output only ever exercises one of them.
  # Every variant has to carry the guard, so count them in the source.
  chains="$(grep -c 'chain media {' "${ROOT}/hdw4s-firewall")"
  # Anchored past the indentation so that commenting a guard out removes it
  # from the count. Counting the bare string meant "# meta l4proto ..." still
  # counted, and the guard could be disabled in every chain with this green.
  guards="$(grep -cE '^[[:space:]]+meta l4proto != \{ tcp, udp \} accept' \
            "${ROOT}/hdw4s-firewall")"
  is 'every media chain has a protocol guard' "${guards}" "${chains}"
  # Same reasoning for the unconditional-accept check above: generate() only
  # ever emits one of the two media chains on any given machine, so the
  # variant this machine does not build is never inspected. Both live in the
  # source, and neither may contain a verdict that matches every packet.
  srcuncond="$(grep -cE '^[[:space:]]+(counter )?accept$' "${ROOT}/hdw4s-firewall")"
  is 'no chain in the source accepts unconditionally' "${srcuncond}" '0'

  HDW4S_MEDIA_PORTS='direct'; out="$(generate 2>/dev/null)"
  hasnt 'direct omits the media chain' "${out}" 'chain media'
  has   'direct keeps the input chain' "${out}" 'chain input'
)

echo '== the check reads the slot table against the loaded table =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc" "${SB}/bin"
  export HDW4S_ETCDIR="${SB}/etc"
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s-firewall" > "${SB}/fw.sh"
  # shellcheck source=/dev/null
  . "${SB}/fw.sh" 2>/dev/null || :
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  HDW4S_BASE_PORT=7300; HDW4S_BLOCK_SIZE=4; HDW4S_PROXIES=''

  # A stub nft, so the range the check reads comes from a "loaded table" that
  # this test controls independently of the configuration. That separation is
  # the whole point: the previous version of this group computed the expected
  # range from HDW4S_BLOCK_SIZE, which is the same expression the code used,
  # so it compared the configuration against itself and would have passed with
  # the table-reading removed entirely. The JSON below is the shape nft 1.0.9
  # really emits for "tcp dport != 7300-7303 accept".
  cat > "${SB}/bin/nft" <<'NFT'
#!/bin/sh
case "$*" in
  *"-j list chain inet hdw4s input"*)
    [ -n "${STUB_RANGE}" ] || exit 1
    lo="${STUB_RANGE% *}"; hi="${STUB_RANGE#* }"
    printf '%s' '{"nftables":[{"rule":{"family":"inet","table":"hdw4s","chain":"input","expr":[{"match":{"op":"!=","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"range":['"${lo}"','"${hi}"']}}},{"accept":null}]}}]}'
    ;;
  *"list table inet hdw4s"*) [ -n "${STUB_RANGE}" ] || exit 1;;
  *"list chain inet hdw4s media"*) exit 1;;
  *) exit 1;;
esac
NFT
  chmod +x "${SB}/bin/nft"
  PATH="${SB}/bin:${PATH}"

  export STUB_RANGE='7300 7303'
  printf '# comment\n0 alice\n1 bob\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'counts the sessions it found' "${out}" 'sessions    2, all within the loaded range 7300-7303'

  printf '# comment\n0 alice\n9 carol\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'names a session outside the loaded range' "${out}" 'carol was allocated port 7309'
  has 'and says how many'                        "${out}" '1 of 2 not covered'

  printf '# only comments\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'reports none when none exist' "${out}" 'sessions    none allocated'

  # The invariant the old group could not express: widen the block in the
  # configuration, leave the loaded table on the old range, and the check must
  # notice. Under the previous implementation both sides moved together and
  # this said everything was covered.
  HDW4S_BLOCK_SIZE=16
  printf '# comment\n0 alice\n9 carol\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'a slot inside the config but outside the table is caught' \
      "${out}" 'carol was allocated port 7309'
  HDW4S_BLOCK_SIZE=4

  # And when there is no table at all it must say so, not answer from config.
  STUB_RANGE=''
  printf '# comment\n0 alice\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'says so when no table is loaded' "${out}" 'cannot tell'
  hasnt 'does not answer from the configuration' "${out}" 'all within'
)

echo '== proxy addresses compare by value, not by spelling =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s-firewall" > "${SB}/fw.sh"
  # shellcheck source=/dev/null
  . "${SB}/fw.sh" 2>/dev/null || :
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  # A check that cries wolf is a check nobody reads.
  # An absolute assertion first: comparing the function against itself passes
  # even when it returns nothing at all.
  is 'canonical form'             "$(canon_addrs '192.168.0.1/24')" '192.168.0.0/24'
  is 'case is not a difference'   "$(canon_addrs '2001:DB8::/32')" "$(canon_addrs '2001:db8::/32')"
  is 'host bits are not either'   "$(canon_addrs '192.168.0.1/24')" "$(canon_addrs '192.168.0.0/24')"
  is 'order is not either'        "$(canon_addrs '10.0.0.0/8 172.16.0.0/12')" \
                                  "$(canon_addrs '172.16.0.0/12 10.0.0.0/8')"
  is 'a real difference survives' "$(test "$(canon_addrs '10.0.0.0/8')" != "$(canon_addrs '10.0.0.0/16')" \
                                    && echo differs)" 'differs'
)

echo '== an install rewrites every file that names the payload path =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  dst="${SB}/opt/lib/hdw4s"; mkdir -p "${dst}/wrappers"
  for f in "${ROOT}"/hdw4s "${ROOT}"/hdw4s-* "${ROOT}"/*.service "${ROOT}"/*.socket "${ROOT}"/*.timer "${ROOT}"/*.slice; do
    [ -f "${f}" ] && cp "${f}" "${dst}/" 2>/dev/null || :
  done
  before="$(grep -rl -- '/usr/lib/hdw4s' "${dst}" 2>/dev/null | wc -l)"
  [ "${before}" -gt 4 ] && ok "more than four files name the path (${before})" \
    || bad 'fixture did not reproduce the condition' "found ${before}"
  # The real block out of install.sh, executed here. A copy of it would only
  # ever prove that this file's own sed works; install.sh needs root, so
  # running the whole script is not possible, but running the part under test
  # is. If the markers ever go missing the test fails rather than passing
  # vacuously.
  block="$(sed -n '/^# BEGIN path-rewrite/,/^# END path-rewrite/p' "${ROOT}/install.sh")"
  case "${block}" in
    *'grep -rl'*) ok 'the rewrite block was found and is not a list';;
    *) bad 'the rewrite block was found and is not a list' 'markers missing';;
  esac
  eval "${block}"
  after="$(grep -rl -- '/usr/lib/hdw4s' "${dst}" 2>/dev/null | wc -l)"
  is 'none left after the rewrite' "${after}" '0'
)

echo '== a slot records what kind of session it is =='
( set +e; sandbox; . "${SB}/setup.sh"
  printf '%s\n' '# comment' '0 alice' '1 eph0 ephemeral' > "${SLOTS}"
  # A row written before the type existed has two fields, and every session was
  # a desktop when it was written -- so that is what it must still mean.
  is 'a two-field row means desktop'   "$(type_of alice)"  'desktop'
  is 'a three-field row is read'       "$(type_of eph0)"   'ephemeral'
  is 'an unknown instance defaults'    "$(type_of nobody)" 'desktop'
  is 'the desktop unit'   "$(unit_of alice)" 'hdw4s@alice.service'
  is 'the ephemeral unit' "$(unit_of eph0)"  'hdw4s-ephemeral@eph0.service'
  is 'drop-ins follow the unit' "$(dropin_of eph0)" \
     "${DROPIN}/hdw4s-ephemeral@eph0.service.d"

  # -- the fourth type ------------------------------------------------------
  #
  # WHY THESE ARE HERE AND NOT BESIDE THE FEATURE. "template" is not a feature
  # of its own; it is a value that seventeen existing readers of this table each
  # decide something from, and every one of them used to fall through to the
  # named-desktop arm. The damage was never in one place, so neither is the
  # check: what is asserted below is that each reader asks one of the two
  # NAMED questions, and that the two questions give different answers.
  printf '%s\n' '# comment' '0 alice' '1 eph0 ephemeral' '2 tmpl template' \
    > "${SLOTS}"
  is 'the template row is read'   "$(type_of tmpl)" 'template'
  # The whole point: it runs the ephemeral unit, so it gets the tmpfs home at
  # /home/user, the namespaced passwd and the Chrome policy bind -- the same
  # machinery a visitor gets, which is what makes the template it produces
  # correct in every slot. On the named unit it would author against a real
  # home and bake /home/<admin> into every path it emits.
  is 'and runs the ephemeral unit' "$(unit_of tmpl)" 'hdw4s-ephemeral@tmpl.service'
  is 'so its drop-ins follow it too' "$(dropin_of tmpl)" \
     "${DROPIN}/hdw4s-ephemeral@tmpl.service.d"

  # The two questions, and they must disagree about exactly this row.
  ephemeral_shaped template && ok 'template is ephemeral-shaped' \
    || bad 'template is ephemeral-shaped' 'it is not'
  in_ephemeral_pool template && bad 'template is NOT pool capacity' \
    'it was offered as capacity' || ok 'template is NOT pool capacity'
  ephemeral_shaped ephemeral && ok 'ephemeral is ephemeral-shaped' \
    || bad 'ephemeral is ephemeral-shaped' 'it is not'
  in_ephemeral_pool ephemeral && ok 'ephemeral IS pool capacity' \
    || bad 'ephemeral IS pool capacity' 'it was not'
  ephemeral_shaped desktop && bad 'desktop is neither' 'shaped said yes' \
    || ok 'desktop is not ephemeral-shaped'

  # RED ARM for the pair. A predicate that answered yes to everything would
  # satisfy every permit above, so it is made to refuse something it must.
  ephemeral_shaped nonsense && bad 'an unknown type is not ephemeral-shaped' \
    'it was accepted' || ok 'an unknown type is not ephemeral-shaped'

  # -- the table that cannot be read ----------------------------------------
  #
  # ABSENT IS NOT EQUAL. type_of() used to answer "desktop" here, which is a
  # fabricated answer to a question that had none -- and since every reader
  # asks "is it ephemeral", one unreadable file turned all of them off at once.
  # The failure is not that a template row is misread; it is that a POOLED row
  # is, and lands on a TCP port.
  # The predicate half runs everywhere, because it needs no unreadable file:
  # it is handed the sentinel directly.
  ( ephemeral_shaped unreadable >/dev/null 2>&1 ) \
    && bad 'the sentinel refuses rather than guessing' 'it answered' \
    || ok 'the sentinel refuses rather than guessing'
  # The message has to send somebody to the FILE. "unknown type" sends them to
  # look at a session that is fine.
  case "$( ( ephemeral_shaped unreadable ) 2>&1 )" in
    *"${SLOTS}"*) ok 'and the refusal names the table';;
    *) bad 'and the refusal names the table' 'it does not';;
  esac
  # RED ARM: without this, both arms above are satisfied by a predicate that
  # refuses everything, which would refuse every slot on a healthy machine.
  ephemeral_shaped ephemeral && ok 'and a real type still permits' \
    || bad 'and a real type still permits' 'it refused'

  # The reader half needs a file it genuinely cannot read, which permissions
  # cannot produce for root. NOT skipped when root -- a skip that records
  # nothing is the shape this harness was rewritten to stop -- so the structure
  # is asserted instead, and it is asserted for everyone.
  # shellcheck disable=SC2016  # matching the literal source text, not expanding it
  case "$(sed -n '/^type_of()/,/^}/p' "${ROOT}/hdw4s")" in
    *'-e "${SLOTS}"'*'-r "${SLOTS}"'*unreadable*)
      ok 'type_of tells "no table" apart from "cannot read it"';;
    *) bad 'type_of tells "no table" apart from "cannot read it"' \
          'the -e/-r pair or the sentinel is gone';;
  esac
  chmod 000 "${SLOTS}"
  if [ -r "${SLOTS}" ]; then
    # Running as root: the arm below cannot be built here. Say so as a
    # measurement of the ENVIRONMENT rather than as a result about the code.
    printf '  --   %s\n' 'reading as root; the unreadable-table arm needs a non-root run'
  else
    is 'an unreadable table is not "desktop"' "$(type_of eph0)" 'unreadable'

    # THE ARM THE BRANCH SHIPPED WITHOUT, AND WHAT IT ACTUALLY GUARDS.
    #
    # Every arm above exercises the predicate DIRECTLY, where its die stops the
    # shell. Nothing went through unit_of -- and all nineteen of its callers
    # write $(unit_of ...), where a die kills only the SUBSHELL. Measured on
    # this tree before the dispatcher guard existed: unit_of answered the EMPTY
    # STRING with its refusal printed in full, and dropin_of answered
    # "${DROPIN}/.d". So "systemctl stop ''" and a drop-in written into a
    # directory named ".d", from a guard that had loudly refused.
    #
    # The repair is NOT to make the predicate die harder -- a predicate that
    # dies inside a substitution is the trap itself. It is that nothing ever
    # REACHES those functions with an unreadable table, refused once at the
    # dispatcher. So this asserts the refusal a real invocation meets, not the
    # behaviour of a function called out of context: sourcing the functions and
    # calling unit_of by hand still fails open, deliberately and harmlessly,
    # because no command can get there.
    # HDW4S_ETCDIR passed EXPLICITLY. Without it the binary reads the real
    # /etc/hdw4s, never sees this sandbox, and dies "no such instance" -- which
    # is also exit 1, so the status assertion below passed for entirely the
    # wrong reason on the first cut. An arm that goes red for a different cause
    # proves nothing, which is why the two message assertions are here rather
    # than a bare status check.
    out="$( ( HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" show eph0 ) 2>&1 )"; rc=$?
    is 'an unreadable table refuses before any command runs' "${rc}" '1'
    # Matching the SENTENCE rather than the path: the harness and the binary
    # derive ETCDIR separately, so asserting the exact filename here tests
    # whether two variables agree rather than whether the refusal is useful.
    has 'and the refusal says it cannot READ the file' "${out}" 'cannot be read'
    has 'and it names the table rather than the slot' "${out}" 'instances'
    hasnt 'and no command got far enough to build a unit name' "${out}" '.d'
  fi
  chmod 644 "${SLOTS}"

  # A table that does not exist at all is a different fact from one that
  # cannot be read, and it must not be swept into the refusal: a machine with
  # no slots has an untyped instance, and "desktop" there is information.
  rm -f "${SLOTS}"
  is 'no table at all still defaults to desktop' "$(type_of alice)" 'desktop'

  rm -f "${SLOTS}"
  alloc_slot newone ephemeral >/dev/null
  is 'alloc_slot records the type' "$(awk '$2=="newone"{print $3}' "${SLOTS}")" 'ephemeral'
  alloc_slot plain >/dev/null
  is 'and defaults it when not given' "$(awk '$2=="plain"{print $3}' "${SLOTS}")" 'desktop'
  alloc_slot tmpl template >/dev/null
  is 'and records the template type' "$(awk '$2=="tmpl"{print $3}' "${SLOTS}")" 'template'
  # RED ARM for the write side. A type nobody recognises is refused HERE, at the
  # only place that writes the column -- not guarded at the seventeen that read
  # it, every one of whose default arm is the named-desktop arm. "ephemerel"
  # would otherwise be given a real home, a password that means something and a
  # TCP port, with nothing reporting it.
  ( alloc_slot typo ephemerel >/dev/null 2>&1 ) \
    && bad 'an unknown type is refused where it is written' 'it was accepted' \
    || ok 'an unknown type is refused where it is written'
  is 'and no row was left behind' \
     "$(awk '$2=="typo"{print $3}' "${SLOTS}")" ''

  # The trap this field creates: "read -r idx inst" does not drop the third
  # field, it appends it to the name -- so the slot is indexed under a session
  # that does not exist. Guard the shape rather than the symptom.
  is 'no table reader swallows the type into the name' \
     "$(cat "${ROOT}/hdw4s" "${ROOT}/hdw4s-firewall" | grep -c 'read -r idx inst;' || :)" '0'

  # An ephemeral slot takes settings from its unit, which the conf files cannot
  # see. Stubbed, because the real answer needs a loaded unit.
  printf '%s\n' '1 eph0 ephemeral' '0 alice' > "${SLOTS}"
  printf 'HDW4S_ISOLATION=none\n' > "${CONF}"
  # Stubbed: the real answer needs a loaded unit. Reached through the function
  # under test, not called directly.
  # shellcheck disable=SC2317
  systemctl() { echo 'HDW4S_ISOLATION=profile HDW4S_PROFILE_DIR=/run/hdw4s'; }
  r="$(setting_with_source eph0 HDW4S_ISOLATION none)"
  is 'the unit wins for an ephemeral slot' "${r%%$'\t'*}" 'profile'
  is 'and is attributed to the unit' "${r#*$'\t'}" 'hdw4s-ephemeral@eph0.service'
  r="$(setting_with_source alice HDW4S_ISOLATION none)"
  is 'a desktop session still reads its files' "${r%%$'\t'*}" 'none'
)

echo '== an ephemeral slot cannot be put on the network =='
( set +e; sandbox; . "${SB}/setup.sh"
  # The defect this closes was measured, not imagined: on 2026-09-22 ports 7304
  # and 7305 on the test container answered HTTP 200 to an anonymous caller and
  # started a real GNOME session. The cause was not a missing credential, it was
  # a transport -- "hdw4s enable" put every slot on TCP, because HDW4S_TRANSPORT
  # defaults to it -- and a credential would have been the wrong repair. There is
  # no caller outside the machine for an ephemeral slot to have.
  me="$(id -un)"
  printf '%s\n' "0 ${me} ephemeral" > "${SLOTS}"

  # Run in a subshell: die() exits, and taking the group's subshell with it
  # would skip every assertion below while recording nothing.
  out="$( ( cmd_transport "${me}" tcp ) 2>&1 )"; rc=$?
  is 'tcp is refused for an ephemeral slot' "${rc}" '1'
  has 'and says which slot and why' "${out}" "${me} is an ephemeral slot"
  # The refusal must be a refusal, not a diagnostic printed on the way through.
  [ ! -e "${DROPIN}/hdw4s-proxy@${me}.socket.d/50-listen.conf" ] &&
    ok 'and writes no listener drop-in' ||
    bad 'and writes no listener drop-in' 'the port drop-in was written anyway'

  # The authoring slot is kept off a port by the SAME refusal, and it is the
  # site the type mattered at most: an ephemeral row and a template row are
  # both reachable only through the front door on this machine, so a port
  # serves no caller either has and every caller neither must have. A template
  # row used to fall through to the named-desktop arm and be accepted here.
  printf '%s\n' "0 ${me} template" > "${SLOTS}"
  rm -f "${DROPIN}/hdw4s-proxy@${me}.socket.d/50-listen.conf"
  out="$( ( cmd_transport "${me}" tcp ) 2>&1 )"; rc=$?
  is 'tcp is refused for the authoring slot too' "${rc}" '1'
  # And it says WHICH slot it refused. One refusal now covers two types, so the
  # noun is derived from the row: calling this one "an ephemeral slot" would
  # send the reader to look at the pool.
  has 'and calls it what it is' "${out}" 'the template-authoring slot'
  [ ! -e "${DROPIN}/hdw4s-proxy@${me}.socket.d/50-listen.conf" ] &&
    ok 'and writes no listener drop-in for it either' ||
    bad 'and writes no listener drop-in for it either' 'the port drop-in was written'

  # The control, and it is the half that makes the refusal mean something: the
  # same call on a desktop slot must still succeed, or the test above passes
  # for any broken cmd_transport at all.
  printf '%s\n' "0 ${me}" > "${SLOTS}"
  out="$( ( cmd_transport "${me}" tcp ) 2>&1 )"; rc=$?
  is 'a desktop slot still may' "${rc}" '0'
  [ -e "${DROPIN}/hdw4s-proxy@${me}.socket.d/50-listen.conf" ] &&
    ok 'and gets its listener drop-in' ||
    bad 'and gets its listener drop-in' 'nothing was written'

  # And "hdw4s proxy" must describe the POOL for a slot, never that slot.
  #
  # The assertion this replaced required the block to contain
  # "proxy_pass http://unix:" -- pointing nginx straight at one slot's socket,
  # which is the bypass. It was correct when a session's own socket was the only
  # kind there was, and it went on passing after the pool shipped, pinning the
  # defect in place exactly as the auth group's assertion pinned the dead end.
  #
  # The stale conf is still put in front of it: an ephemeral slot's file may be
  # absent, or may say "tcp" because an older version wrote it.
  printf '%s\n' "0 ${me} ephemeral" > "${SLOTS}"
  printf 'HDW4S_TRANSPORT=tcp\n' > "${ETCDIR}/${me}.conf"
  out="$( ( cmd_proxy "${me}" ) 2>&1 )"
  hasnt 'the block does NOT point nginx at a slot socket' \
        "${out}" "proxy_pass http://unix:"
  hasnt 'and no longer names a port'       "${out}" "HOST_RUNNING_HDW4S"
  # One line, not a phrase that spans one. The first version of this assertion
  # searched for "a pool is not configured slot by slot", which the block wraps
  # across a newline -- so it could never match, and the failure read as the
  # branch not firing rather than as the search being wrong.
  has 'and says it is one slot of a pool' \
      "${out}" 'is one slot of the ephemeral pool'
  has 'and speaks of the pool, not our internals' "${out}" 'the pool chooses'
)

echo '== a slot table written by an older version still works =='
( set +e; sandbox; . "${SB}/setup.sh"
  # The deployed machines have a two-field table written by 2.2.0, and the
  # install puts readers in front of it that were written for three. If a
  # two-field row mishandles, "list", "reap" and the firewall break for real
  # users -- on upgrade, which is the worst moment. This is that table.
  printf '%s\n' \
    '# Session slots. One line per session: <index> <instance>.' \
    '0 alice' '1 bob' '2 carol' > "${SLOTS}"

  is 'every old row reads as a desktop' \
     "$(for i in alice bob carol; do type_of "${i}"; done | sort -u | tr '\n' ' ')" \
     'desktop '
  is 'and resolves to the desktop unit' "$(unit_of bob)" 'hdw4s@bob.service'
  is 'slot_of still finds a two-field row' "$(slot_of carol)" '2'
  is 'and alloc_slot is idempotent against one' "$(alloc_slot bob)" '1'
  is 'which did not rewrite the row' \
     "$(awk '$2=="bob"{print NF}' "${SLOTS}" | head -1)" '2'

  # The readers walk the table with "read -r idx inst _". Prove that shape is
  # required, by showing what the old two-variable form does to a three-field
  # row: it does not drop the type, it appends it to the name, so the slot is
  # indexed under a session that does not exist.
  printf '%s\n' '3 eph0 ephemeral' >> "${SLOTS}"
  old_form="$(while read -r idx inst; do [ "${idx}" = '3' ] && echo "${inst}"; done < "${SLOTS}")"
  new_form="$(while read -r idx inst _; do [ "${idx}" = '3' ] && echo "${inst}"; done < "${SLOTS}")"
  is 'the old reader shape corrupts the name' "${old_form}" 'eph0 ephemeral'
  is 'and the shape the readers use does not' "${new_form}" 'eph0'
  is 'a mixed table still answers for the old rows' "$(unit_of alice)" 'hdw4s@alice.service'
  is 'and for the new one'                          "$(unit_of eph0)" 'hdw4s-ephemeral@eph0.service'
)

echo '== the relay names no session unit, and enable supplies one =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT

  # The template must not name a session unit. It used to, and a drop-in cannot
  # take that back: an empty "Requires=" does not reset the list, so an instance
  # served by a different unit would have carried both.
  is 'the proxy template names no session unit' \
     "$(grep -c '^\(Requires\|After\)=hdw4s@' "${ROOT}/hdw4s-proxy@.service")" '0'
  is 'and still requires its own socket' \
     "$(grep -c '^Requires=hdw4s-proxy@%i.socket' "${ROOT}/hdw4s-proxy@.service")" '1'
  case "$(sed -n '/^unit_of()/,/^}/p' "${ROOT}/hdw4s")" in
    *hdw4s-ephemeral@*) ok 'one helper names both session units';;
    *) bad 'one helper names both session units' 'unit_of does not';;
  esac
  # shellcheck disable=SC2016  # likewise: this matches the literal line in the script
  case "$(sed -n '/hdw4s-proxy@${inst}.service.d\/30-session.conf/p' "${ROOT}/hdw4s")" in
    *30-session.conf*) ok 'enable writes the session drop-in';;
    *) bad 'enable writes the session drop-in' 'not written';;
  esac

  # The two installers carry the same backfill. Duplicated on purpose --
  # packaging is not a dependency of install.sh -- so the only thing keeping
  # them honest is this comparison.
  # Leading whitespace is normalised away: the block sits inside an "if" in one
  # file and at top level in the other, and the thing that must not drift is what
  # it does, not how far it is indented.
  pick() { sed -n '/# BEGIN session-dropin-backfill/,/# END session-dropin-backfill/p' "$1" \
             | sed 's/^[[:space:]]*//'; }
  is 'the backfill block exists in postinst' "$(pick "${ROOT}/debian/postinst" | wc -l | tr -d ' ')" \
     "$(pick "${ROOT}/install.sh" | wc -l | tr -d ' ')"
  if [ -n "$(pick "${ROOT}/debian/postinst")" ] &&
     [ "$(pick "${ROOT}/debian/postinst")" = "$(pick "${ROOT}/install.sh")" ]; then
    ok 'both installers carry the identical block'
  else
    bad 'both installers carry the identical block' 'they differ or are missing'
  fi

  # Run the shipped block against a fixture, rather than a copy of it.
  mkdir -p "${SB}/etc/hdw4s" "${SB}/units/hdw4s-proxy@alice.service.d" \
           "${SB}/units/hdw4s-proxy@bob.service.d" \
           "${SB}/units/hdw4s-proxy@dave.service.d" \
           "${SB}/units/hdw4s-proxy@eve.service.d" \
           "${SB}/units/hdw4s-proxy@tmpl.service.d"
  printf '%s\n' '# comment' '0 alice' '1 bob' '2 carol' '3 dave ephemeral' '4 eve' \
                 '5 tmpl template' \
    > "${SB}/etc/hdw4s/instances"
  printf 'keep me\n' > "${SB}/units/hdw4s-proxy@bob.service.d/30-session.conf"
  # A drop-in from before the BindsTo fix. An upgrade has to correct it, because
  # nothing else rewrites the file -- "hdw4s enable" is not re-run on a machine
  # that is already enabled, so skipping it would leave every existing
  # installation with a relay that outlives its session.
  printf '%s\n' '[Unit]' 'Requires=hdw4s@eve.service' 'After=hdw4s@eve.service' \
    > "${SB}/units/hdw4s-proxy@eve.service.d/30-session.conf"
  blk="$(pick "${ROOT}/debian/postinst")"
  # Stubbed because the shipped block calls it; reached only through the eval.
  # shellcheck disable=SC2317
  systemctl() { :; }
  ( ETCDIR="${SB}/etc/hdw4s" UNITDIR="${SB}/units"; eval "${blk}" )
  case "$(cat "${SB}/units/hdw4s-proxy@alice.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo=hdw4s@alice.service'*) ok 'an instance with no drop-in gets one';;
    *) bad 'an instance with no drop-in gets one' 'missing or wrong';;
  esac
  # BindsTo=, not Requires=: Requires= does not end a relay whose session exits on
  # its own, which is what a GNOME logout does, and the relay then forwards to a
  # dead port for every later visitor. Measured HTTP 000 against HTTP 200.
  case "$(cat "${SB}/units/hdw4s-proxy@alice.service.d/30-session.conf" 2>/dev/null)" in
    *'Requires='*) bad 'the drop-in binds rather than requires' 'still Requires=';;
    *) ok 'the drop-in binds rather than requires';;
  esac
  # The third field of the instances file is the type. Ignoring it named the
  # desktop unit for an ephemeral slot, and the relay then failed every start
  # with result 'dependency' while the front door went on listening.
  case "$(cat "${SB}/units/hdw4s-proxy@dave.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo=hdw4s-ephemeral@dave.service'*) ok 'an ephemeral slot names the ephemeral unit';;
    *) bad 'an ephemeral slot names the ephemeral unit' 'missing or wrong';;
  esac
  # The fourth type, in the same run. The installers cannot call the CLI's
  # ephemeral_shaped() -- they may be repairing a tree whose hdw4s does not run
  # yet -- so they carry their own copy of the list, and this is what keeps the
  # copy honest. A template row on the default arm got BindsTo=hdw4s@tmpl,
  # which never starts an authoring session: the relay listens and every start
  # fails on the dependency, with the front door still accepting.
  case "$(cat "${SB}/units/hdw4s-proxy@tmpl.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo=hdw4s-ephemeral@tmpl.service'*) ok 'and so does the template slot';;
    *) bad 'and so does the template slot' 'missing or wrong';;
  esac
  case "$(cat "${SB}/units/hdw4s-proxy@eve.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo=hdw4s@eve.service'*) ok 'an old Requires= drop-in is migrated';;
    *) bad 'an old Requires= drop-in is migrated' 'not migrated';;
  esac
  is 'an existing drop-in is left alone' \
     "$(cat "${SB}/units/hdw4s-proxy@bob.service.d/30-session.conf")" 'keep me'
  is 'an instance with no relay directory is skipped' \
     "$(set -- "${SB}/units"/*carol*; [ -e "$1" ] && echo present || echo absent)" 'absent'
)

echo '== what the reaper tells someone whose session it just stopped =='
( set +e; sandbox; . "${SB}/setup.sh"
  # An ephemeral slot keeps its home and its profile in memory, so stopping it
  # destroys both. The reaper was written for named desktops, where stopping is
  # reversible, and printed the named-desktop reassurance -- "Its files and
  # settings are untouched" -- at the moment an ephemeral session's files
  # stopped existing. Reproduced on a live slot on 2026-09-19: a marker file
  # written into the home, and read back, was gone after the run that printed
  # that line; a control run in which the slot was not selected left it there.
  #
  # Selecting ephemeral slots is deliberate and stays: the ephemeral unit
  # carries no RuntimeMaxSec on purpose and names this window as the cap that
  # frees a slot. What had to become true is the sentence, not the choice.
  #
  # Nothing exercised cmd_reap before this, which is why the message was wrong
  # for half the session types for as long as both types existed.
  unset JOURNAL_STREAM
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/hdw4s-reap"
  printf '%s\n' '0 dora' '1 eph0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/hdw4s/dora" "${RUNDIR}/hdw4s/eph0" "${REAPDIR}"

  # Nobody is connected: ss reports nothing, and the proxy exists, so that
  # "nothing" means "nobody there" rather than "we could not look".
  ss() { :; }
  STOPPED="${SB}/stopped"; : > "${STOPPED}"
  # "${3:-}", not "$3". The script under test runs under "set -o nounset", the
  # stub inherits it, and "systemctl is-active <unit>" has no third argument:
  # the bare form aborted the stub with an unset-variable error that the
  # caller's 2>/dev/null swallowed. is-active then answered nothing, every
  # session was skipped, and this group passed its "nothing was stopped"
  # assertions while proving nothing whatever. That is why the positive is
  # asserted before any negative below.
  systemctl() {
    case "$1 ${3:-}" in
      'is-active ') echo 'active';;
      'show -p')    case "${4:-}" in MainPID) echo 4242;; *) echo '';; esac;;
      'stop '*)     printf '%s\n' "$2" >> "${STOPPED}";;
    esac
  }

  # A slot still inside its window is the control: if this one is stopped too,
  # the group says nothing about selection.
  back="$(( $(date +%s) - 86400 ))"
  printf '%s\n' "${back}" > "${REAPDIR}/eph0"
  printf '%s\n' "${back}" > "${REAPDIR}/dora"
  out="$(cmd_reap 2>/dev/null)"
  is 'a session inside its window is left alone' "${out}" ''
  is 'and nothing was stopped'                   "$(wc -l < "${STOPPED}")" '0'

  # Now past the window, set per instance -- never on the site default, which
  # would move every session at once.
  printf 'HDW4S_IDLE_DAYS=1\n' > "${SB}/etc/eph0.conf"
  out="$(cmd_reap 2>/dev/null)"
  has   'the ephemeral slot is now selected'  "${out}" 'stopping eph0'
  has   'and its unit is the one stopped'     "$(cat "${STOPPED}")" 'hdw4s-ephemeral@eph0.service'
  hasnt 'the desktop beside it is left alone' "${out}" 'stopping dora'

  # The defect itself. Read out of what the run printed, never grepped out of
  # the script: the comment recording this failure contains the same string.
  hasnt 'no promise that an ephemeral home survived' "${out}" 'untouched'
  hasnt 'and none that it comes back as it was'      "${out}" 'starts it again'
  has   'it says what was in memory is gone'         "${out}" 'gone'

  # And the reassurance is still given where it is true, so the fix cannot be
  # "delete the sentence".
  : > "${STOPPED}"
  printf 'HDW4S_IDLE_DAYS=1\n' > "${SB}/etc/dora.conf"
  out="$(cmd_reap 2>/dev/null)"
  has 'both kinds are reported in one run' "${out}" 'stopping dora'
  has 'and the ephemeral one still is too' "${out}" 'stopping eph0'
  is  'two sessions stopped'               "$(wc -l < "${STOPPED}")" '4'

  # That combined transcript carries both messages, so an assertion against it
  # is satisfied by either session -- swapping the branch over leaves every
  # string present. A desktop on its own is what pins the reassuring text to
  # the session type it is true of.
  printf '%s\n' '0 dora' > "${SLOTS}"
  out="$(cmd_reap 2>/dev/null)"
  has   'a desktop alone gets the reassurance' "${out}" 'untouched'
  has   'and is told it comes back'            "${out}" 'starts it again'
  hasnt 'and is never told its home is gone'   "${out}" 'gone'
)

echo '== the idle window is a duration, and nothing falls back to a week =='
( set +e; sandbox; . "${SB}/setup.sh"
  # HDW4S_IDLE_DAYS was typed as a plain number, so "24h" was refused before the
  # parser ever saw it, and anything the reaper could not read became seven days
  # through
  #
  #     case "${days}" in ''|*[!0-9]*) days=7;; esac
  #
  # with no message. The two are one change: teaching the parser units while
  # leaving that line in place is what would have let the m/M ambiguity bite for
  # the first time, silently, in the direction of a longer window.
  #
  # Asserted through idle_seconds rather than by reading the config back,
  # because what was wrong was the NUMBER OF SECONDS the reaper compared
  # against, and a file that records "30m" faithfully says nothing about that.
  secs() { idle_seconds "$1" >/dev/null 2>&1 && printf '%s' "${IDLE_SECONDS}" || printf 'REFUSED'; }

  is 'a bare number is still days'   "$(secs 7)"     '604800'
  is 'd is days'                     "$(secs 30d)"   '2592000'
  is 'h is hours'                    "$(secs 12h)"   '43200'
  is 'm is MINUTES'                  "$(secs 90m)"   '5400'
  is 'M is MONTHS, not minutes'      "$(secs 1M)"    '2629800'
  is 'w is weeks'                    "$(secs 1w)"    '604800'
  is 'y is years'                    "$(secs 1y)"    '31557600'
  # The case distinction is the whole reason the owner ruled on the letters. If
  # these two ever agree again, "30m" means a month and the reaper will not fire
  # for four weeks on a machine that asked for half an hour.
  #
  # 10, not 1: one minute is below the floor and is refused, so "1m" vs "1M"
  # would compare REFUSED against a month and pass for the wrong reason.
  is 'm and M are not the same unit' "$(secs 10m)x$(secs 10M)" '600x26298000'

  # Fractions, which is why the representation is seconds. Under the day
  # arithmetic this replaced, 0.5h truncated to zero and read as "never reap" --
  # the silent failure that inverted the setting.
  is 'a fraction is not truncated'   "$(secs 0.5h)"  '1800'

  # The mechanical dependency: this exact value was rejected by the 'number'
  # type, and the refusal read as the parser failing rather than the validator
  # refusing a form the parser would have taken.
  is 'the form that used to be rejected outright' "$(secs 24h)" '86400'

  # Nothing is guessed, and nothing falls back. Each of these used to become a
  # week without a word.
  is 'a spelled-out unit is refused'  "$(secs 30sec)" 'REFUSED'
  is 'the wrong case is refused'      "$(secs 30S)"   'REFUSED'
  is 'a compound duration is refused' "$(secs 1h30m)" 'REFUSED'
  is 'a bare word is refused'         "$(secs x)"     'REFUSED'
  is 'an empty value is refused'      "$(secs '')"    'REFUSED'

  # Zero is a statement and stays one; a NON-ZERO value that computes to less
  # than a second must not quietly become the same thing.
  is 'zero disables'                     "$(secs 0)"    '0'
  is 'zero with a unit disables too'     "$(secs 0s)"   '0'
  is 'sub-second is refused, not "off"'  "$(secs 0.4s)" 'REFUSED'

  # The floor. An ephemeral session takes up to 91 seconds to shut down, so a
  # window shorter than its own teardown cannot free a slot inside itself.
  is 'below the floor is refused'  "$(secs 60s)"  'REFUSED'
  is 'and just below it too'       "$(secs 119s)" 'REFUSED'
  is 'the floor itself is allowed' "$(secs 120s)" '120'

  # A refusal that names a spelling the tool then rejects is worse than one that
  # names none. Every example in the help text is run back through the parser,
  # so the remedy cannot rot away from the rule.
  for form in 7 30d 12h 90m 0.5h 0; do
    case "$(idle_syntax_help)" in
      *"${form}"*) :;;
      *) bad "the help text names ${form}"; continue;;
    esac
    case "$(secs "${form}")" in
      REFUSED) bad "the help text offers ${form} and the parser takes it";;
      *)       ok  "the help text offers ${form} and the parser takes it";;
    esac
  done

  # And the reason survives to the caller. The first version of this returned
  # the seconds on stdout, so every caller written as
  # window="$(idle_seconds ...)" read the reason back EMPTY -- the assignment
  # happened in the subshell of a command substitution. The refusal would have
  # printed a key, a colon and nothing, on the only path that ever prints it.
  idle_seconds '30sec' >/dev/null 2>&1
  case "${IDLE_WHY}" in
    '') bad 'the refusal reason reaches the caller';;
    *)  ok  'the refusal reason reaches the caller';;
  esac

  # A BROKEN PARSER IS NOT A BAD VALUE, and the two must not read alike. The
  # grammar now lives in a separate file, so "it is missing" is a new way for
  # this to fail -- and the failure that would be worst is the quiet one: a
  # helper that cannot be run, reported as though the administrator's value
  # were at fault, or worse, absorbed into a default. There is no default. The
  # message has to name the thing that could not be run, or nobody will look at
  # it.
  ( DURATION_TOOL="${SB}/there-is-no-such-parser"
    idle_seconds '7' >/dev/null 2>&1 \
      && bad 'a missing parser is a failure, not a week' \
      || ok  'a missing parser is a failure, not a week'
    is  'and it does not answer anyway' "${IDLE_SECONDS}" ''
    has 'and it names what could not be run' "${IDLE_WHY}" 'there-is-no-such-parser'
    hasnt 'and does not blame the value'    "${IDLE_WHY}" "'7' is" )
)

echo '== never reaping is a choice for a named session and a leak for a slot =='
( set +e; sandbox; . "${SB}/setup.sh"
  # 0 means "never reap". For a named session that is defensible: stopping one
  # is a nap and the next connection starts it again. For an ephemeral slot,
  # reaping is the ONLY thing that ever frees it -- a visitor who closes the tab
  # tells nothing -- so 0 means unattended desktops accumulate until the pool is
  # full and every visitor after that is refused, from one configuration line
  # with nothing anywhere reporting why.
  printf '%s\n' '0 dora' '1 eph0 ephemeral' > "${SLOTS}"

  ( cmd_set 'eph0' 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && bad 'a slot may not be told never to reap' \
    || ok  'a slot may not be told never to reap'
  out="$( ( cmd_set 'eph0' 'HDW4S_IDLE_DAYS=0' ) 2>&1 )"
  has 'and the refusal says what would happen' "${out}" '503'
  # The remedy has to be a command that works, not a sentence that reads well.
  has 'and names a longer window instead'      "${out}" 'HDW4S_IDLE_DAYS=30d'
  ( cmd_set 'eph0' 'HDW4S_IDLE_DAYS=30d' ) >/dev/null 2>&1 \
    && ok  'and that command is accepted' \
    || bad 'and that command is accepted'
  # The refusal must leave nothing behind, or the value it refused is in force.
  hasnt 'and nothing was written' "$(cat "${SB}/etc/eph0.conf" 2>/dev/null)" 'HDW4S_IDLE_DAYS=0'

  # The control, and it is the point of keying this on type rather than banning
  # the value: a named session may still be told never to stop.
  ( cmd_set 'dora' 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'a named session still may' \
    || bad 'a named session still may'

  # And so may the authoring slot, which is the whole reason this guard asks
  # in_ephemeral_pool() rather than "is it ephemeral". Every sentence in the
  # refusal above is about the NEXT VISITOR -- the pool filling, the 503 -- and
  # nobody is ever minted onto a template row. Refusing it would be this
  # project's own recurring shape: a guard firing on a resemblance rather than
  # on the property it was written for.
  printf '%s\n' '0 dora' '1 eph0 ephemeral' '2 tmpl template' > "${SLOTS}"
  ( cmd_set 'tmpl' 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'and so may the template-authoring slot' \
    || bad 'and so may the template-authoring slot' 'it was refused'
  # CONTROL, in the same table, so the permit above cannot be a broken guard:
  # the pooled row beside it must still be refused.
  ( cmd_set 'eph0' 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && bad 'CONTROL: the pooled slot beside it is still refused' 'it was accepted' \
    || ok  'CONTROL: the pooled slot beside it is still refused'

  # Machine-wide, the value reaches the slots too, so it is refused -- but only
  # on a machine that HAS slots. A check that fails on a correct state is one
  # somebody turns off.
  ( cmd_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && bad 'machine-wide is refused where there is a pool' \
    || ok  'machine-wide is refused where there is a pool'
  printf '%s\n' '0 dora' > "${SLOTS}"
  ( cmd_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'and allowed where there is not' \
    || bad 'and allowed where there is not'
)

echo '== the reaper works in seconds, and refuses to guess =='
( set +e; sandbox; . "${SB}/setup.sh"
  unset JOURNAL_STREAM
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/hdw4s-reap"
  printf '%s\n' '0 dora' '1 eph0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/hdw4s/dora" "${RUNDIR}/hdw4s/eph0" "${REAPDIR}"
  ss() { :; }
  STOPPED="${SB}/stopped"; : > "${STOPPED}"
  systemctl() {
    case "$1 ${3:-}" in
      'is-active ') echo 'active';;
      'show -p')    case "${4:-}" in MainPID) echo 4242;; *) echo '';; esac;;
      'stop '*)     printf '%s\n' "$2" >> "${STOPPED}";;
    esac
  }

  # Idle for an hour. Under the day arithmetic this replaced, the age was
  # (now - last) / 86400 = 0 and a sub-day window could never fire at all, so a
  # setting the tool accepted did nothing whatever.
  back="$(( $(date +%s) - 3600 ))"
  printf '%s\n' "${back}" > "${REAPDIR}/dora"
  printf '%s\n' "${back}" > "${REAPDIR}/eph0"
  printf 'HDW4S_IDLE_DAYS=30m\n' > "${SB}/etc/dora.conf"
  printf 'HDW4S_IDLE_DAYS=2h\n'  > "${SB}/etc/eph0.conf"
  out="$(cmd_reap 2>/dev/null)"
  has   'a window shorter than a day fires'  "${out}" 'stopping dora'
  hasnt 'and one still inside it does not'   "${out}" 'stopping eph0'
  # Read back out of the message, so the arithmetic is asserted and not just the
  # selection: "1 hour", never "0 days".
  has   'and the age is reported in its own unit' "${out}" 'for 1 hour'

  # The silent fallback. "30m" used to be read as seven days with no message --
  # the ambiguity the unit letters were ruled on, masked by the very line that
  # would have made it visible. Anything unreadable must now stop the session
  # from being considered AND say so, rather than reaping on a number nobody
  # wrote: one leaves a desktop running, the other destroys an ephemeral
  # session on a guess.
  : > "${STOPPED}"
  printf 'HDW4S_IDLE_DAYS=30sec\n' > "${SB}/etc/dora.conf"
  rm -f "${SB}/etc/eph0.conf"
  printf '%s\n' "$(( $(date +%s) - 864000 ))" > "${REAPDIR}/dora"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'an unreadable window does not fall back to a week' "${out}" 'stopping dora'
  is    'and nothing was stopped'  "$(wc -l < "${STOPPED}")" '0'
  has   'and the reaper says why'  "${out}" 'not considered'
  has   'and names a value that works' "${out}" 'HDW4S_IDLE_DAYS=7'

  # A slot hand-edited to 0 is legal to the reaper and invisible otherwise: the
  # pool filling up has no other symptom to trace back to a configuration line.
  : > "${STOPPED}"
  rm -f "${SB}/etc/dora.conf"
  printf 'HDW4S_IDLE_DAYS=0\n' > "${SB}/etc/eph0.conf"
  printf '%s\n' "$(( $(date +%s) - 864000 ))" > "${REAPDIR}/eph0"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a slot set to 0 is not reaped'      "${out}" 'stopping eph0'
  has   'but the reaper says it never will be' "${out}" 'never be freed'
)

echo '== the router is a second witness to idleness, and may only ever extend a life =='
# The reaper's own stamp comes from a poll every few minutes, so a visitor who
# connects, works and leaves inside one gap is invisible to every sample taken.
# The router writes its record where the connection is ACCEPTED and cannot miss
# one. Taking the maximum of the two is what stops a desktop being destroyed out
# from under somebody with the journal saying nothing connected for a week --
# and the destruction is silent, so nothing else would ever have gone red.
#
# Every arm below is paired. An extension that cannot be seen NOT happening
# would pass just as well if this simply stopped reaping altogether, which is
# the failure that empties the pool instead of the desktop.
( set +e; sandbox; . "${SB}/setup.sh"
  unset JOURNAL_STREAM
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/hdw4s-reap"
  POOLDIR="${SB}/run/hdw4s-demux"
  printf '%s\n' '1 eph0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/hdw4s/eph0" "${REAPDIR}" "${POOLDIR}/last-request"
  ss() { :; }
  STOPPED="${SB}/stopped"; : > "${STOPPED}"
  systemctl() {
    case "$1 ${3:-}" in
      'is-active ') echo 'active';;
      'show -p')    case "${4:-}" in MainPID) echo 4242;; *) echo '';; esac;;
      'stop '*)     printf '%s\n' "$2" >> "${STOPPED}";;
    esac
  }
  printf 'HDW4S_IDLE_DAYS=1h\n' > "${SB}/etc/eph0.conf"
  now="$(date +%s)"
  stale="$(( now - 86400 ))"
  rstamp="${POOLDIR}/last-request/eph0"

  # POSITIVE CONTROL FIRST. Without it every "not reaped" below is satisfied by
  # a reaper that no longer reaps anything, and the whole block would be green
  # on a pool that never frees a slot.
  printf '%s\n' "${stale}" > "${REAPDIR}/eph0"
  rm -f "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'a stale slot with no router record is still reaped' "${out}" 'stopping eph0'
  # Which is also the arm that matters when the router is DOWN: it contributes
  # nothing to the maximum, so the reaper falls back to its own sample rather
  # than treating silence as "nobody connected". Absence is no opinion.

  # THE FIX. Same stale sample, and a router that saw somebody a minute ago.
  : > "${STOPPED}"
  printf '%s\n' "${stale}" > "${REAPDIR}/eph0"
  printf '%s\n' "$(( now - 60 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a request the poll missed keeps the desktop alive' "${out}" 'stopping eph0'
  is    'and nothing was stopped' "$(wc -l < "${STOPPED}")" '0'

  # AND IT MAY ONLY EXTEND. An old router record against a fresh sample must not
  # pull the deadline forward: this witness is a reason to believe somebody was
  # here, never a reason to believe nobody was.
  : > "${STOPPED}"
  printf '%s\n' "$(( now - 60 ))" > "${REAPDIR}/eph0"
  printf '%s\n' "${stale}" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'an old router record does not shorten a life' "${out}" 'stopping eph0'

  # A record in the future is a fault, not an observation. Clamping it to now
  # would re-clamp on every later run and the slot would never reap again, with
  # no other symptom -- so it is dropped, and said out loud because a slot that
  # stops reaping has nothing else to trace it back to.
  : > "${STOPPED}"
  printf '%s\n' "${stale}" > "${REAPDIR}/eph0"
  printf '%s\n' "$(( now + 86400 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'a router record in the future is ignored' "${out}" 'stopping eph0'
  has 'and the reaper says so'                   "${out}" 'in the future'

  # Not a timestamp. Guessing at one on the destruction side is how a desktop
  # gets stopped on a number nobody wrote.
  : > "${STOPPED}"
  printf 'yesterday\n' > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'an unreadable router record is ignored' "${out}" 'stopping eph0'
  has 'and the reaper says so'                 "${out}" 'not a timestamp'

  # A symlink is refused outright. The router only ever os.replace()s a regular
  # file here, so a symlink is a fault rather than a shape to support -- and the
  # reaper runs as root, so following one is how a read becomes a disclosure.
  : > "${STOPPED}"
  # No "$" in the stand-in hash: a literal one here is flagged as a variable
  # that will not expand, and the point of the file is only that its contents
  # are recognisable if they ever reach the journal.
  secret="${SB}/pretend-shadow"; printf 'root:verysecret:1::\n' > "${secret}"
  rm -f "${rstamp}"; ln -s "${secret}" "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has   'a symlinked router record is refused' "${out}" 'symlink'
  has   'and the slot is reaped on the sample alone' "${out}" 'stopping eph0'
  hasnt 'and nothing of what it pointed at is printed' "${out}" 'verysecret'
)

echo '== the arrival and sharing arms are chosen at generation, and a bad one is refused =='
# Written from the failure: a QA matrix once tested one transport twice because a
# mis-set knob was silently ignored, so the generator must REFUSE a value it does not
# know rather than fall back to a default nobody chose. The input here is a synthetic
# one-line document, not the packaged client: what is under test is the generator's
# choice of arm, and the packaged tree is a build artifact this suite cannot have.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  gen() { "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" >/dev/null 2>"${d}/err"; }

  HDW4S_GATE_MODE=mint  gen && has 'the gate arm reaches the page' \
    "$(cat "${d}/out.html")" '"gate": "mint"'
  HDW4S_SHARE_MODE=view gen && has 'the share arm reaches the page' \
    "$(cat "${d}/out.html")" '"share": "view"'

  # The default must be the behaviour that already shipped, so that installing this
  # changes nothing until somebody asks for an arm.
  gen; a="$(cat "${d}/out.html")"
  HDW4S_GATE_MODE=takeover HDW4S_SHARE_MODE=off gen; b="$(cat "${d}/out.html")"
  is 'the default is the shipped behaviour' "${a}" "${b}"

  # Seen to go red, in both knobs, with the positive control above proving the same
  # command succeeds when the arm is one it knows.
  HDW4S_GATE_MODE=banana gen && bad 'a bad gate arm is refused' 'it was accepted' \
    || has 'a bad gate arm is refused' "$(cat "${d}/err")" 'is not one of'
  HDW4S_SHARE_MODE=banana gen && bad 'a bad share arm is refused' 'it was accepted' \
    || has 'a bad share arm is refused' "$(cat "${d}/err")" 'is not one of'

  # The arms are markup and script only. Restoring an auto-loading module tag would
  # un-gate every arm at once, and hdw4s-webroot would then refuse the tree.
  HDW4S_GATE_MODE=off gen
  hasnt 'no arm restores an auto-loading module tag' "$(cat "${d}/out.html")" \
    '<script type="module" src='
)

echo '== the fresh-desktop card tells the truth about how long the desktop lasts =='
# Written from the failure: the card said "nothing in it survives being closed" and that
# was false for as long as it shipped. Closing a tab does not stop a session -- it is
# held alive and reclaimed later -- so a person who signed into webmail and closed the
# tab left it signed in. Nothing could have gone red: a page that promises destruction
# and does not destroy behaves exactly like a correct one, which is why the guard is at
# generation and why it is tested from both sides here.
#
# What this can and cannot see: it catches the warning being DELETED and the old claim
# RETURNING. It cannot tell whether a reworded card is true. It is a guard on a decision
# somebody made, not a proof about the product.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"

  # The positive control comes first, so that the three refusals below are known to be
  # refusals of the thing under test rather than of the input.
  HDW4S_GATE_MODE=mint "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" \
    >/dev/null 2>"${d}/err" \
    && has 'the card warns that closing the tab does not end the desktop' \
       "$(cat "${d}/out.html")" 'Closing this tab does not end it' \
    || bad 'the card warns that closing the tab does not end the desktop' \
       "the generator refused a good page: $(cat "${d}/err")"

  # No duration is baked into the page. The reclaim period is a per-instance setting an
  # administrator changes with "set", while this page is generated once per web-root
  # build and no rebuild follows that change -- so a figure here would be a claim that
  # goes stale silently and breaks nothing, which is this project's commonest defect.
  hasnt 'the card names no number of days' "$(cat "${d}/out.html")" ' days'

  # Three red arms, each broken on purpose in a COPY, each seen to refuse and to write
  # no page. The third is the one that matters most: it proves the guard cannot pass by
  # failing to find the thing it checks.
  #
  # EACH PATTERN IS SCOPED SO THAT IT CANNOT EDIT THE GUARD ITSELF, and that is not
  # fussiness -- it is how these arms first came up green against a broken build. The
  # guard names the words it requires, so a blunt substitution across the file rewrites
  # the card AND the sentence the guard looks for, leaving the two agreeing with each
  # other about the wrong thing. Two of the three arms passed that way. So each pattern
  # below matches only the card's markup, which the guard's own literals do not carry:
  # the card writes "<b>Closing ..." and "var MINT = '", the guard writes them bare.
  red() { sed "$1" "${ROOT}/hdw4s-gate-index" > "${d}/red"
          python3 "${d}/red" "${d}/in.html" "${d}/redout.html" >/dev/null 2>"${d}/rederr"; }

  rm -f "${d}/redout.html"
  red 's|<b>Closing this tab does not end it\.</b>|<b>It is yours alone.</b>|' \
    && bad 'a card without the warning is refused' 'it was accepted' \
    || has 'a card without the warning is refused' "$(cat "${d}/rederr")" \
       'no longer warns'
  hasnt 'a refused card writes no page' "$(ls "${d}")" 'redout.html'

  red "s/Nothing from anyone else is in it\./Nothing from anyone else is in it, and nothing in it survives being closed./" \
    && bad 'the retracted promise is refused if it comes back' 'it was accepted' \
    || has 'the retracted promise is refused if it comes back' "$(cat "${d}/rederr")" \
       'survives being closed'

  red "s/var MINT = '/var MINT_CARD = '/" \
    && bad 'a card the guard cannot find is refused' 'it was accepted' \
    || has 'a card the guard cannot find is refused' "$(cat "${d}/rederr")" \
       'could not be found'
)

echo '== BOTH session kinds publish an identity, or the gate refuses forever =='
# THE ARM THAT WAS MISSING, AND WHY IT WAS MISSING. The gate's resume path
# compares the identity a tab connected to against the one published in the web
# root, and treats a MISSING file as a refusal -- failing closed, which is
# correct. Every test of that path used an ephemeral slot, and every rig that
# validated the repair drove the pool. So nobody noticed that hdw4s@.service
# carried no publisher at all.
#
# MEASURED on a live named desktop 2026-09-25: a hidden tab coming back met the
# card EVERY time, with "/hdw4s-incarnation 404" on the first line of its
# console. The repair worked for the pool and could not work here, and the one
# thing a named desktop has that an ephemeral one does not is the ABSENCE of
# that file -- which is exactly the shape a test comparing the two would have
# caught and a test of either alone could not.
#
# Asserting on the UNIT FILES rather than on a running system: this is the
# workstation half of the tier, and the claim is about what ships.
for u in hdw4s@.service hdw4s-ephemeral@.service; do
  case "$(cat "${ROOT}/${u}" 2>/dev/null)" in
    *'Wants=hdw4s-incarnation@%i.service'*'After=hdw4s-incarnation@%i.service'*)
      ok "${u} publishes an incarnation";;
    *) bad "${u} publishes an incarnation" \
           'no Wants=/After= pair -- its gate can only ever refuse a resume';;
  esac
done

echo '== a rebuild of a running slot keeps its published identity =='
# Written from the failure: a re-mint stripped hdw4s-incarnation from a LIVE web root
# and nothing noticed for a day. Nothing can notice -- the builder never passes an
# instance, so the token is not one of the things "check" looks at, and the next
# session start quietly republishes one. The packaged client is stubbed here because
# it is a build artifact this suite cannot have; what is under test is the swap, not
# the client.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  mkdir -p "${d}/pkg" "${d}/slot"
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/pkg/index.html"
  : > "${d}/pkg/x.js"
  printf '#!/bin/bash\ncat >/dev/null\necho %s\n' "${d}/pkg" > "${d}/py"
  chmod +x "${d}/py"
  # The run record is what says "this session is RUNNING". It lives on a tmpfs
  # in production and dies with the session; the published token does not. This
  # suite used to express "running" by leaving a token in the web root, which
  # is the same conflation that produced the bug below -- so it now sets the
  # record explicitly, and the reboot case gets a test of its own.
  mkdir -p "${d}/run"
  build() {
    HDW4S_SELKIES_PY="${d}/py" HDW4S_LIBDIR="${ROOT}" \
    HDW4S_INCARNATION_DIR="${d}/run" \
      "${ROOT}/hdw4s-webroot" build probe "${d}/slot" probe >/dev/null 2>"${d}/err"
  }

  printf '%s\n' 'tok-before-the-rebuild' > "${d}/slot/hdw4s-incarnation"
  printf '%s\n' 'tok-before-the-rebuild' > "${d}/run/probe"
  build
  is 'a rebuild carries the running identity across unchanged' \
     "$(cat "${d}/slot/hdw4s-incarnation" 2>/dev/null)" 'tok-before-the-rebuild'

  # THE REBOOT CASE, which had no test and is the bug. /run is a tmpfs, so a
  # reboot takes the record and leaves the published token -- and the published
  # copy is the one a returning tab reads to decide "this is the desktop I had".
  # Carrying it forward makes a dead session look like the live one, which is
  # the logged-out row of the arrival table collapsing into the resume row.
  # Measured across a real reboot on a test container before this was fixed.
  rm -f "${d}/run/probe"
  printf '%s\n' 'tok-from-before-the-reboot' > "${d}/slot/hdw4s-incarnation"
  build
  is 'but DROPS it when the run record is gone, because the session is gone' \
     "$(cat "${d}/slot/hdw4s-incarnation" 2>/dev/null)" ''
  printf '%s\n' 'tok-before-the-rebuild' > "${d}/run/probe"
  has 'and still swaps in a freshly gated client' \
      "$(cat "${d}/slot/index.html" 2>/dev/null)" 'hdw4s-gate'

  # A token is preserved, never minted: a rebuild does not restart the session, so
  # inventing one here would tell every returning tab its desktop had been replaced.
  rm -rf "${d}/slot"; mkdir -p "${d}/slot"
  build && ok 'a first build with no predecessor still succeeds' \
        || bad 'a first build with no predecessor still succeeds' "$(cat "${d}/err")"
  [ ! -e "${d}/slot/hdw4s-incarnation" ] \
    && ok 'and does not invent an identity of its own' \
    || bad 'and does not invent an identity of its own' 'a token appeared from nowhere'
)

echo '== every path the session hides must be one something creates first =='
# Written from the failure: InaccessiblePaths= carries no "-" prefix, so a path that
# does not exist is FATAL -- the session dies 226/NAMESPACE naming a directory, which
# points at neither the unit nor whatever was supposed to create it. One of these was
# being created by a side effect of the filesystem transport and by nothing else, so
# switching a slot to TCP and rebooting took the whole feature down.
#
# What this can and cannot say: it resolves the paths the minter's "install -d" lines
# name, and compares them against the paths the session hides. It does not run the
# minter -- that writes userdb records and reloads systemd, so it belongs on a real
# machine. This catches the drift; a reboot catches the behaviour.
(
  unit="${ROOT}/hdw4s-ephemeral@.service"
  minter="${ROOT}/hdw4s-ephemeral-slots"
  created="$( grep -hE '^install -d' "${minter}" | grep -oE '[{][A-Z0-9_]+[}]' | tr -d '{}' |
             while read -r v; do
               sed -n "s|^${v}=\"[$]{[A-Z0-9_]*:-\([^}]*\)}\"|\\1|p" "${minter}"
             done)"
  hidden="$(grep -hE '^InaccessiblePaths=' "${unit}" | sed 's/^InaccessiblePaths=//' |
            tr ' ' '\n' | grep '^%t/' | sed 's|^%t|/run|')"

  # A harness that selects nothing passes every negative, so say what was selected
  # before saying it was fine.
  n="$(printf '%s\n' "${hidden}" | grep -c . || :)"
  [ "${n}" -ge 2 ] && ok "the unit's hidden runtime paths were found (${n})" \
    || bad "the unit's hidden runtime paths were found" "found ${n}, expected at least 2"

  missing=''
  for h in ${hidden}; do
    grep -qxF "${h}" <<<"${created}" || missing="${missing} ${h}"
  done
  is 'and every one of them is created by the slot minter' "${missing}" ''
)

echo '== the ephemeral unit may not run a command with the "+" prefix =='
# Written from the failure: "ExecStartPre=+/usr/lib/hdw4s/hdw4s-webroot gate %i" took
# every ephemeral session on a test container down with
#   Failed to set up mount namespacing: /home/user: No such file or directory
#   Control process exited, code=exited, status=226/NAMESPACE
#
# The manual says "+" skips "the various file system namespacing options", which reads
# as "this command gets no namespace". It is narrower than that, measured on systemd
# 255.4-1ubuntu8.17 with findmnt from inside a transient unit: "+" drops ProtectHome=
# and ProtectSystem=, and KEEPS BindPaths= and TemporaryFileSystem=. So the per-slot
# drop-in's TemporaryFileSystem=/home/user is still applied -- but with the real /home
# underneath it instead of the tmpfs ProtectHome= would have put there, and the mount
# point has to be created on the real home filesystem. On an NFS home that squashes
# root, it cannot be, and the unit dies before the desktop exists. On a machine with a
# local /home it silently succeeds and leaves an empty /home/user behind, which is a
# filesystem trace this session type promises not to leave -- which is exactly why the
# line passed its first test and failed in production.
#
# "!" is the prefix that works here: elevated privilege, namespace intact.
(
  unit="${ROOT}/hdw4s-ephemeral@.service"
  minter="${ROOT}/hdw4s-ephemeral-slots"

  # The reason has to still be true, or this test outlives it as a rule nobody can
  # explain. If the minter stops mounting under /home, revisit this, do not delete it.
  grep -qE '^TemporaryFileSystem=/home/' "${minter}" \
    && ok 'the slot minter still mounts a tmpfs under /home' \
    || bad 'the slot minter still mounts a tmpfs under /home' \
           'the reason this test exists has moved; re-derive it before editing'

  # A harness that greps for something absent from every unit proves nothing, so show
  # it can see a "+" at all before reporting that there is none.
  probe="$(printf 'ExecStartPre=+/bin/true\n' | grep -cE '^Exec[A-Za-z]*=[+]')"
  is 'the probe can see a "+"-prefixed Exec line' "${probe}" '1'

  found="$(grep -nE '^Exec[A-Za-z]*=[+]' "${unit}" || :)"
  is 'and the ephemeral unit carries none' "${found}" ''
)

echo '== a unit with an [Install] section is no use until something enables it =='
# Written from the failure: hdw4s-ephemeral-slots.service declares
# WantedBy=sysinit.target and was enabled by neither installer -- install.sh only
# symlinked it into /etc/systemd/system, which makes a unit loadable and not enabled,
# and debian/rules passed --no-enable for it along with the templates, which is right
# for a template and wrong for this. The unit read "linked" and never ran at boot, so
# after a reboot there were no slot accounts and no runtime directories at all. Both
# installers ran the minter directly at install time, which repaired it until the next
# boot and hid it behind itself.
#
# Derived from the unit files rather than from a list, because a list is the thing
# that drifted: this unit was missing from the same enumeration in two places.
(
  units=''
  for u in "${ROOT}"/*.service "${ROOT}"/*.socket "${ROOT}"/*.timer; do
    b="$(basename "${u}")"
    case "${b}" in *@*) continue;; esac
    grep -qE '^WantedBy=' "${u}" || continue
    units="${units} ${b}"
  done

  # A harness that selects nothing passes every negative.
  n="$(printf '%s' "${units}" | wc -w)"
  [ "${n}" -ge 4 ] && ok "units with an [Install] section were found (${n})" \
    || bad "units with an [Install] section were found" "found ${n}, expected at least 4"

  missing=''
  for b in ${units}; do
    grep -qE "systemctl enable( --now)? ${b}\$" "${ROOT}/install.sh" || missing="${missing} ${b}"
  done
  is 'install.sh enables every one of them' "${missing}" ''

  noenable=''
  for b in ${units}; do
    grep -qE -- "--no-enable[^#]*${b}\$" "${ROOT}/debian/rules" && noenable="${noenable} ${b}"
  done
  is 'and the package does not ship one disabled' "${noenable}" ''
)

echo '== a credential is refused where it can exclude nobody =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Written from the failure, measured on the test container on 2026-09-22:
  # ephemeral0 carried HDW4S_AUTH=basic in /etc/hdw4s/ephemeral0.conf while
  # ephemeral1 and ephemeral2 did not, all three on the filesystem socket. A
  # demultiplexer opening ephemeral0.sock got a 401 and its two neighbours
  # answered, so the same routing test passed against one slot of a pool and
  # failed against the next -- a real, reproducible failure attributed to the
  # thing under test rather than to the slot.
  #
  # The credential itself is stood in for: sealing one needs root and
  # /var/lib/systemd/credential.secret, which this suite has neither of. What is
  # under test is which calls reach that point, so standing it in is the point
  # rather than a compromise.
  # shellcheck disable=SC2317
  require_slot() { :; }
  # STILL PRINTS, and that is the point of the assertion below rather than an
  # oversight. The real make_credential has no return channel any more -- it
  # used to print the plaintext and both callers discarded it. A stub that also
  # printed nothing would make the test below pass for free, on a stand-in
  # rather than on the code. This one emits a secret the caller must NOT pass
  # on, so the assertion is about cmd_auth's handling rather than about the
  # stub's silence.
  # shellcheck disable=SC2317
  make_credential() { echo 'stub-secret'; }
  printf '%s\n' '0 eph0 ephemeral' '1 alice' '2 bob' > "${SLOTS}"

  # The positive control FIRST, because a guard that refuses everything looks
  # exactly like one that refuses the right thing. A session on the network is
  # where a credential has something to keep out, and it must still be written.
  printf 'HDW4S_TRANSPORT=tcp\n' > "${ETCDIR}/alice.conf"
  out="$( ( cmd_auth alice ) 2>&1 )"; rc=$?
  is 'a session on the network may still have one' "${rc}" '0'
  has 'and the setting is written' \
      "$(cat "${ETCDIR}/alice.conf")" 'HDW4S_AUTH=basic'

  # THE SECRET MUST NOT COME BACK OUT. cmd_auth used to capture the plaintext
  # into a variable it only ever unset, so it crossed a subshell boundary for no
  # consumer. It now calls make_credential without capturing, which means
  # anything the callee prints goes straight to the user's terminal -- so this
  # assertion is also what stops the return channel being reinstated by
  # somebody who assumes the caller is still swallowing it.
  hasnt 'and the secret never reaches the user' "${out}" 'stub-secret'

  # Now the refusal.
  printf 'HDW4S_TRANSPORT=unix\n' > "${ETCDIR}/eph0.conf"
  out="$( ( cmd_auth eph0 ) 2>&1 )"; rc=$?
  is 'a session on a filesystem socket may not' "${rc}" '1'
  has 'and is told why the secret would keep nobody out' \
      "${out}" 'nothing can present a credential to it'
  # The assertion this replaced required the message to contain
  # "hdw4s transport eph0 tcp" -- a command this same suite asserts exits 1 for
  # an ephemeral slot, about 470 lines above. Two green groups jointly
  # certifying a dead end: the tool printed an instruction it refuses to obey,
  # and the tests held it in place. The refusal must offer no remedy it will
  # then refuse.
  hasnt 'and offers no remedy the tool itself refuses' \
        "${out}" 'hdw4s transport eph0 tcp'
  has 'and says a named desktop is a different case' \
      "${out}" 'A named desktop is a different thing'
  # A refusal, not a diagnostic printed on the way through. This is the whole
  # defect: the message would have been fine, the written line is what 401s.
  hasnt 'and nothing was written to its file' \
        "$(cat "${ETCDIR}/eph0.conf")" 'HDW4S_AUTH'

  # THE ARM THAT SEPARATES THE TWO REASONS. Above, eph0 is BOTH ephemeral and on
  # a filesystem socket, so its refusal cannot say which fact caused it -- and
  # the code used to key on the transport, which made a NAMED session on a
  # socket refuse too.
  #
  # The owner ruled that wrong: "if the admin configures named sessions to run
  # over a unix domain socket, because they installed the reverse proxy in the
  # same container, then that's a defensible choice and we should make it
  # possible." A credential there is neither required nor encouraged, but it is
  # allowed, and refusing it made a supported configuration fail safely instead
  # of working.
  #
  # So the refusal belongs to the session TYPE, not the transport: an ephemeral
  # slot is refused because the demultiplexer holds no credential and cannot
  # present one, so a slot carrying one answers 401 alone while its neighbours
  # work. A named session has a reverse proxy that can be told the secret.
  printf 'HDW4S_TRANSPORT=unix\n' > "${ETCDIR}/bob.conf"
  out="$( ( cmd_auth bob ) 2>&1 )"; rc=$?
  is 'a NAMED session on a filesystem socket may have one' "${rc}" '0'
  has 'and the setting is written for it too' \
      "$(cat "${ETCDIR}/bob.conf")" 'HDW4S_AUTH=basic'

  # BOTH ARMS BELOW ASSERTED THE OPPOSITE and were left to fail before being
  # rewritten, because the behaviour they encoded is the one the owner ruled
  # against. They said the TRANSPORT decides, so a named desktop moved onto a
  # socket was refused and a site-wide transport default refused every session.
  #
  # The type decides now. Keeping the arms rather than deleting them, inverted,
  # because the risk they were written against is real and has not gone away:
  # the guard must not be satisfiable by testing a NAME. It is satisfied by
  # asking the instance table what kind of session this is, which is the same
  # authority "enable" and the slot minter use.
  printf 'HDW4S_TRANSPORT=unix\n' > "${ETCDIR}/alice.conf"
  out="$( ( cmd_auth alice ) 2>&1 )"; rc=$?
  is 'a named desktop moved onto a socket may still have one' "${rc}" '0'

  # A site-wide transport no longer drags every session into the refusal either.
  # The ephemeral arm above is the control: it must STILL refuse with this same
  # site default in place, or this arm is passing because the guard stopped
  # working rather than because it got narrower.
  : > "${ETCDIR}/alice.conf"
  printf 'HDW4S_TRANSPORT=unix\n' > "${CONF}"
  out="$( ( cmd_auth alice ) 2>&1 )"; rc=$?
  is 'a site-wide socket default does not refuse a named session' "${rc}" '0'
  rm -f "${ETCDIR}/eph0.conf"
  out="$( ( cmd_auth eph0 ) 2>&1 )"; rc=$?
  is 'CONTROL: the ephemeral slot still refuses under that same default' "${rc}" '1'
)

echo '== a running session that publishes no identity is a failure, not a quiet pass =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Written from the failure, measured on the test container on 2026-09-22:
  # ephemeral2 was active with no token in its web root and none recorded under
  # /run/hdw4s-incarnation, while ephemeral0 and ephemeral1 had both. The wiring
  # was right on all three -- Wants= and After= name the publisher -- and the
  # slot had simply started at 15:08, before the publisher first ran at 16:26,
  # and had never been restarted. Nothing was broken; something was old. Every
  # listing called it active, because it was.
  #
  # What makes it worth a check rather than a restart: the arrival rule says an
  # unknown input must gate, and in code that becomes a comparison. A slot
  # publishing nothing makes both sides of that comparison empty, which reads as
  # "unchanged" -- so the riskiest input takes the quietest path.
  RUNDIR="${SB}/run"
  HDW4S_INCARNATION_DIR="${SB}/run/hdw4s-incarnation"
  HDW4S_WEBROOT_DIR="${SB}/webroot"
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}/eph0" "${HDW4S_WEBROOT_DIR}/eph1"
  # A running NAMED desktop in the table throughout, and it is not decoration.
  # Only hdw4s-ephemeral@.service pulls in the publisher, and only an ephemeral
  # slot gets a web root to publish into, so a named desktop can never satisfy
  # this check. Without the restriction the command reported every running
  # desktop as broken -- measured against a real machine, where it buried the
  # one slot that was actually wrong among rows that never could be right.
  printf '%s\n' '0 eph0 ephemeral' '1 eph1 ephemeral' '2 alice desktop' > "${SLOTS}"

  # THE POOL AROUND THE SESSIONS, stood in for so this group can go on being
  # about incarnation tokens. "hdw4s check" now asks first whether the machine
  # can hand out a desktop at all, and a sandbox has no listening doors -- so
  # without these stubs every assertion below would be red for a reason that has
  # nothing to do with what it is testing. Each stand-in is named here because a
  # constant in a comparison is a claim: the doors, the front-door port and the
  # failed-unit list are ASSUMED sound in this group and are exercised, in both
  # directions, in the group that follows.
  STUB_DOORS="${RUNDIR}/hdw4s-proxy/eph0.sock ${RUNDIR}/hdw4s-proxy/eph1.sock"
  STUB_PORT='7280'
  STUB_FAILED=''
  STUB_SLOTS='active'
  # shellcheck disable=SC2317
  ss() {
    case "$*" in
      *'sport = :'*) [ -n "${STUB_PORT}" ] && echo 'LISTEN 0 4096 *:7280 *:*';;
      *'src = '*)
        for d in ${STUB_DOORS}; do
          case "$*" in *"${d}") echo "u_str LISTEN 0 4096 ${d} 1 * 0";; esac
        done;;
    esac
    return 0
  }
  # Every slot running. "${2:-}" rather than "$2": the script runs under
  # nounset, the stub inherits it, and a bare positional aborts the stub with an
  # unset-variable error the caller's redirection swallows -- after which every
  # session looks inactive and the group passes while checking nothing.
  # shellcheck disable=SC2317
  systemctl() {
    case "$*" in
      *'list-units --failed'*) printf '%s' "${STUB_FAILED}";;
      *'-p Listen --value hdw4s-demux.socket'*) echo "[::]:${STUB_PORT} (Stream)";;
      *'hdw4s-ephemeral-slots.service'*) echo "${STUB_SLOTS}";;
      *) case "$1 ${2:-}" in 'show -p') echo "${STUB_STATE:-active}";; esac;;
    esac
    return 0
  }

  # The positive control first: a check that cannot pass proves nothing when it
  # fails. Both slots sound.
  printf '%s\n' 'aaaa' > "${HDW4S_WEBROOT_DIR}/eph0/hdw4s-incarnation"
  printf '%s\n' 'aaaa' > "${HDW4S_INCARNATION_DIR}/eph0"
  printf '%s\n' 'bbbb' > "${HDW4S_WEBROOT_DIR}/eph1/hdw4s-incarnation"
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a sound pool passes'            "${rc}" '0'
  # Two, not three: the named desktop beside them is running and is not counted.
  # The number is the whole control here -- a restriction that skipped everything
  # would pass this group just as quietly, and would say "0".
  has 'and says how many it looked at'  "${out}" '2 running'
  # The door count is the half that was missing: "0 running" used to be printed
  # by an idle pool AND by a pool that could not start anything.
  has 'and how many doors are listening' "${out}" '2 ephemeral slot(s), 2 with a listening door'
  hasnt 'the running named desktop is not accused' "${out}" 'alice'

  # The defect itself: a live slot publishing nothing.
  rm -f "${HDW4S_WEBROOT_DIR}/eph1/hdw4s-incarnation" "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is    'a live slot with no token fails'   "${rc}" '1'
  has   'and the message names the slot'    "${out}" 'eph1 is running and publishes no incarnation token'
  has   'and names the repair'              "${out}" 'systemctl restart hdw4s-ephemeral@eph1.service'
  hasnt 'and does not accuse the sound one' "${out}" 'eph0 is running and publishes'
  # Which way it fails is the property. It reports; it does not restart, because
  # a check that repairs what it finds is one nobody reads, and the fact worth
  # having is that a slot ran for two hours without a publisher.
  has   'it counts the failures against the total' "${out}" '1 of 2 running session(s) failed'

  # Pinned independently of the half below it. With the record left in place the
  # served file is the only thing missing, so this cannot be satisfied by the
  # "recorded nothing" branch -- which is what happened: blinding the served
  # check alone left every assertion above this one green, because both halves
  # were absent together and the second branch caught what the first no longer
  # did. One sufficient cause is not the cause.
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a missing served token fails on its own' "${rc}" '1'
  has 'and is named as the published half'      "${out}" 'publishes no incarnation token'

  # An empty file is not a token, and is the shape a truncating write leaves
  # behind for as long as it takes to finish.
  : > "${HDW4S_WEBROOT_DIR}/eph1/hdw4s-incarnation"
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is 'an empty published file is not a token' "${rc}" '1'

  # Serving a value nobody recorded is its own failure: it is what a slot looks
  # like when the previous session's token was left in a rebuilt web root.
  printf '%s\n' 'bbbb' > "${HDW4S_WEBROOT_DIR}/eph1/hdw4s-incarnation"
  rm -f "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a served token this start did not record fails' "${rc}" '1'
  has 'and says which half is missing' "${out}" 'recorded no incarnation token'

  # And a mismatch, which is the same bug one step further along: the tab is
  # told this is the desktop it had, and it is not.
  printf '%s\n' 'cccc' > "${HDW4S_INCARNATION_DIR}/eph1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a token that does not match the record fails' "${rc}" '1'
  has 'and says so in those terms' "${out}" 'did not publish'

  # A slot that is not running is not this command's business: it publishes
  # nothing because nothing is there to publish, and reporting it would bury
  # the one row that matters.
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/eph1"
  STUB_STATE='inactive'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'an IDLE pool with its doors open passes' "${rc}" '0'
  has 'having looked at no running slots'       "${out}" '0 running'
  # THE STATE THE WHOLE SERVICEABILITY ARM EXISTS FOR, asserted here because it
  # is the one an operator reads: an idle pool and a dead one must not print the
  # same line. This is the green half; the red half is the group below.
  has 'and saying the doors are open'           "${out}" '2 with a listening door'
)

echo '== a pool that cannot hand out a desktop is not a healthy pool =='
# MEASURED, on a development container, 2026-09-24, BEFORE this arm existed:
# with every slot door stopped, a visitor got no answer at all three slots and
# "hdw4s check" printed "0 running ephemeral session(s)" and exited 0. With
# every session start broken instead, the visitor got 503 at all three, three
# units sat in "failed", and it printed the same sentence and exited 0 again.
# The command was doing its documented job -- it asks about sessions that are
# RUNNING, and a pool that can start nothing has none -- which is exactly why
# the silence was total: an operator, this command's own timer and any monitor
# above it all saw a pass on a machine nobody could get a desktop from.
#
# EVERY ARM BELOW IS RUN IN BOTH DIRECTIONS. A predicate is only worth what its
# red arm is worth, and a serviceability check that reddened on an idle pool
# would be switched off within a week -- so each state is broken, seen red, and
# repaired, seen green, against the same sandbox.
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s" > "${SB}/lib.sh"
  HDW4S_ETCDIR="${SB}/etc"; mkdir -p "${HDW4S_ETCDIR}"
  SLOTS="${HDW4S_ETCDIR}/instances"
  RUNDIR="${SB}/run"
  HDW4S_INCARNATION_DIR="${SB}/run/hdw4s-incarnation"
  HDW4S_WEBROOT_DIR="${SB}/webroot"
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}"
  export HDW4S_ETCDIR HDW4S_RUNDIR="${RUNDIR}" HDW4S_INCARNATION_DIR HDW4S_WEBROOT_DIR
  # shellcheck source=/dev/null
  . "${SB}/lib.sh" 2>/dev/null || :
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  SLOTS="${HDW4S_ETCDIR}/instances"; RUNDIR="${SB}/run"
  printf '%s\n' '0 eph0 ephemeral' '1 eph1 ephemeral' > "${SLOTS}"

  STUB_DOORS="${RUNDIR}/hdw4s-proxy/eph0.sock ${RUNDIR}/hdw4s-proxy/eph1.sock"
  STUB_PORT='7280'; STUB_FAILED=''; STUB_SLOTS='active'
  # shellcheck disable=SC2317
  ss() {
    case "$*" in
      *'sport = :'*) [ -n "${STUB_PORT}" ] && echo 'LISTEN 0 4096 *:7280 *:*';;
      *'src = '*)
        for d in ${STUB_DOORS}; do
          case "$*" in *"${d}") echo "u_str LISTEN 0 4096 ${d} 1 * 0";; esac
        done;;
    esac
    return 0
  }
  # shellcheck disable=SC2317
  systemctl() {
    case "$*" in
      *'list-units --failed'*) printf '%s' "${STUB_FAILED}";;
      *'-p Listen --value hdw4s-demux.socket'*) echo "[::]:${STUB_PORT} (Stream)";;
      *'hdw4s-ephemeral-slots.service'*) echo "${STUB_SLOTS}";;
      *) echo 'inactive';;
    esac
    return 0
  }

  # THE POSITIVE CONTROL FIRST. A sound idle pool -- doors listening, nothing
  # running -- must pass, or every red below it is just a check that is always
  # red, which is read as noise and switched off.
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a sound idle pool passes'   "${rc}" '0'
  has 'and says the doors are open' "${out}" '2 ephemeral slot(s), 2 with a listening door, 0 running'

  # Every door shut: the state a teardown that does not re-arm the sockets
  # leaves behind, and the state with no witness anywhere else on the box --
  # nothing failed, nothing running, the table still listing the slots.
  STUB_DOORS=''
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a pool with no listening door fails' "${rc}" '1'
  has 'and says so in the visitor''s terms' "${out}" 'none of the 2 ephemeral slot(s) has a listening door'
  has 'and names the repair'                "${out}" 'systemctl start hdw4s-proxy@'

  # One door shut. Not a capacity shortfall: the router mints a visitor onto the
  # name and the request fails with the slot consumed.
  STUB_DOORS="${RUNDIR}/hdw4s-proxy/eph0.sock"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'one slot with no listener fails'  "${rc}" '1'
  has 'and names WHICH slot'             "${out}" 'Not listening: eph1'
  STUB_DOORS="${RUNDIR}/hdw4s-proxy/eph0.sock ${RUNDIR}/hdw4s-proxy/eph1.sock"

  # The front door. Asked of the kernel, not of systemd: a socket unit can be
  # active while nothing is bound.
  STUB_PORT=''
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a front door with no address fails' "${rc}" '1'
  has 'and says which door'                "${out}" 'front door has no listening address'
  STUB_PORT='7280'

  # A latched unit. This is the shape the pool fails into when a relay's start
  # limit fires, and it stays that way until somebody clears it.
  STUB_FAILED='hdw4s-ephemeral@eph0.service failed failed'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a latched pool unit fails the check' "${rc}" '1'
  has 'and names the unit'                  "${out}" 'hdw4s-ephemeral@eph0.service'
  has 'and names the repair'                "${out}" 'reset-failed'
  STUB_FAILED=''

  # The identities the slots run as. Without them User= does not resolve and
  # every start dies 217/USER, naming nothing anybody would search for.
  STUB_SLOTS='inactive'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'unminted slot identities fail' "${rc}" '1'
  has 'and say what breaks'           "${out}" '217/USER'
  STUB_SLOTS='active'

  # A table that EXISTS and cannot be read is not "no sessions to check": the
  # router answers every arrival 503 in exactly that state.
  chmod 000 "${SLOTS}"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  chmod 644 "${SLOTS}"
  if [ "$(id -u)" = '0' ]; then
    skip 'an unreadable slot table fails' 'root reads anything'
  else
    is  'an unreadable slot table fails' "${rc}" '1'
    has 'and does not call it "no sessions"' "${out}" 'exists and cannot be read'
  fi

  # And a machine that was never configured at all is NOT broken. This is the
  # arm that keeps the check off boxes it has no business reddening.
  rm -f "${SLOTS}"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a machine with no slot table passes' "${rc}" '0'
  has 'and says why'                        "${out}" 'no slot table'

  # A box with named desktops and no pool is not a pool: no doors, no front
  # door, and it must still pass.
  printf '%s\n' '0 alice desktop' > "${SLOTS}"
  STUB_DOORS=''; STUB_PORT=''
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a box with no ephemeral slots passes' "${rc}" '0'
  has 'and says there is no pool'            "${out}" 'no ephemeral slots configured'
)

echo '== the tool and the router agree about what a setting means =='
# HDW4S_IDLE_DAYS was read by both and parsed differently: the tool took "30d"
# and the router read the same line with int(), swallowed the failure and used
# seven days. The value is the one our own sample configuration and manual tell
# an administrator to type. Nothing caught it because nothing anywhere compared
# the two readers, and a test for that one setting would have caught that one
# setting.
#
# So the checker is a class check and it lives in its own file: it derives which
# settings the router reads out of a conf file, derives the values from the
# documentation that tells people to type them, and asks both sides. It is run
# from here rather than left beside the other harnesses, because the other half
# of this defect is that .github/live/demux.py had never been invoked by
# anything at all.
(
  out="$("${ROOT}/.github/setting-grammar.py" "${ROOT}" 2>&1)"; rc=$?
  is  'the two readers agree on every setting they share' "${rc}" '0'
  [ "${rc}" -eq 0 ] || printf '%s\n' "${out}"
  # The positive controls, asserted HERE as well as inside the checker. An
  # empty class and an empty corpus both produce a clean pass, and a clean pass
  # is what this whole subject is about.
  has 'and the class it derived is not empty'   "${out}" 'class: 1 setting(s)'
  has 'and the corpus came from our own manual' "${out}" 'documented value(s)'
  # A green here is worth what the red behind it was worth, and only one member
  # has ever been seen to fail. The checker says which; this makes sure it
  # keeps saying it, because that distinction is the first thing a tidy-up
  # deletes.
  has 'and it says which members were ever seen to fail' "${out}" 'seen to fail'
)

echo '== the router, against stand-in slots =='
# NOT a live test, despite living under .github/live: it spawns the real
# hdw4s-demux against UNIX-socket backends on loopback and needs no systemd, no
# session and no browser. It ran in three seconds on the workstation.
#
# IT WAS INVOKED BY NOTHING. Not by checks.sh, not by this file. It was
# syntax-parsed as one of the Python files in the package and never executed --
# a whole tier believed green that had never been seen green at all, which is
# how a router that discarded its own configuration passed everything. Wiring
# it in is the repair; a suite nobody runs is not a weak suite, it is no suite.
(
  # THIS FILE IS "#!/bin/bash -e", so a bare assignment from a failing command
  # KILLS THE SCRIPT BEFORE rc IS READ -- silently, with no assertion recorded
  # and no message. Measured at the merge: the router suite went non-zero for a
  # known reason and the whole run died after printing this group's header,
  # which made the assertion below unreachable. A guard for "the suite failed"
  # that cannot run when the suite fails is the defect it was written against.
  rc=0
  out="$("${ROOT}/.github/live/demux.py" 2>&1)" || rc=$?
  is 'the router suite passes' "${rc}" '0'
  [ "${rc}" -eq 0 ] || printf '%s\n' "${out}"
  # A suite that silently ran nothing exits 0 too. Its own summary is the only
  # thing that can tell the difference, so it is asserted rather than trusted.
  #
  # THE SECOND ARM WAS WIRED TO THE WRONG SIGNAL and was measured firing on a
  # perfectly good run. It looked for the substring "0 passed" in the summary,
  # which every count ending in a zero contains: a thirty-test suite reports
  # "30 passed" and was failed for having run nothing. A guard that cries wolf
  # on an ordinary state is removed, and this one had the additional property
  # of being untestable by the person who tripped it -- adding one test made it
  # green again for no reason they could see. So it now reads the number.
  has 'and it actually ran its checks' "${out}" '0 failed'
  ran="$(printf '%s\n' "${out}" | sed -n 's/^\([0-9][0-9]*\) passed.*/\1/p' | tail -1)"
  if [ -n "${ran}" ] && [ "${ran}" -gt 0 ]; then
    ok 'and none of them was skipped away'
  else
    bad 'and none of them was skipped away' "the suite reported [${ran:-no}] passing tests"
  fi
)

echo
# A group that dies partway leaves its remaining assertions unrecorded, which
# looks identical to a shorter suite. Counting them is the only way to notice.
EXPECTED=368   # update when tests are added; a wrong number is the point
pass="$(grep -c '^ok$'   "${RESULTS}" || :)"
fail="$(grep -c '^fail$' "${RESULTS}" || :)"
if [ $(( pass + fail )) -ne "${EXPECTED}" ]; then
  echo "$(( pass + fail )) of ${EXPECTED} tests ran -- a group exited early." >&2
  exit 1
elif [ "${fail:-0}" -eq 0 ] && [ "${pass:-0}" -gt 0 ]; then
  echo "All ${pass} tests passed."
elif [ "${pass:-0}" -eq 0 ]; then
  echo 'No tests ran.' >&2
  exit 1
else
  echo "${fail} of $(( pass + fail )) tests failed." >&2
  exit 1
fi
