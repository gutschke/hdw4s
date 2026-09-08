#!/bin/bash -e
# Four findings are inherent to what this file is, and are named rather than
# silenced wholesale:
#   SC2034  variables assigned here are read by the code sourced from hdw4s,
#           which the linter cannot see across the source boundary.
#   SC2154  "user" and "session" are outputs of split_name, set as globals.
#   SC2030/SC2031  each group runs in its own subshell on purpose, so that one
#           failure cannot derail the rest; the linter reads the isolation as
#           an accident.
#   SC2015  "cond && ok ... || bad ..." is the assertion idiom here. The
#           warning is about C running when A is true, which needs B to fail;
#           ok() is an echo and a printf and does not.
#   SC1091  setup.sh is written by sandbox() at run time, so there is nothing
#           on disk for the linter to follow.
# shellcheck disable=SC2034,SC2154,SC2030,SC2031,SC2015,SC1091
export LC_ALL='C'
set -o nounset -o pipefail

# Behaviour tests. Every one of these exists because the behaviour it checks
# was once wrong -- each is written from the failure, not from the code, so
# that it still means something after the code is rewritten.
#
#   .github/tests.sh
#
# Needs nothing but bash and coreutils. Anything that would need systemd, nft
# or a live session is deliberately not here; those belong on a real machine.

cd "$(dirname "$0")/.."
ROOT="${PWD}"

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
  user=''; session=''
  split_name 'alice:2' 2>/dev/null || :; is 'colon selects a session' "${user}:${session}" 'alice:2'
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

echo '== settings lookup =='
( set +e; sandbox; . "${SB}/setup.sh"
  printf 'HDW4S_TRANSPORT=unix\n' > "${CONF}"
  is 'global is read'            "$(setting_of alice HDW4S_TRANSPORT tcp)" 'unix'
  printf 'HDW4S_TRANSPORT=tcp\n' > "${SB}/etc/alice.conf"
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
  is 'one row per instance' "$(grep -c ' alice$' "${SLOTS}")" '1'
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
  is 'and one table row'           "$(grep -c ' shared$' "${SLOTS}")" '1'
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

  # generate() emits one of two media chains depending on whether this machine
  # can match a cgroup, so a test of its output only ever exercises one of them.
  # Every variant has to carry the guard, so count them in the source.
  chains="$(grep -c 'chain media {' "${ROOT}/hdw4s-firewall")"
  guards="$(grep -c 'meta l4proto != { tcp, udp } accept' "${ROOT}/hdw4s-firewall")"
  is 'every media chain has a protocol guard' "${guards}" "${chains}"

  HDW4S_MEDIA_PORTS='direct'; out="$(generate 2>/dev/null)"
  hasnt 'direct omits the media chain' "${out}" 'chain media'
  has   'direct keeps the input chain' "${out}" 'chain input'
)

echo '== the check reads the slot table =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc"
  export HDW4S_ETCDIR="${SB}/etc"
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s-firewall" > "${SB}/fw.sh"
  # shellcheck source=/dev/null
  . "${SB}/fw.sh" 2>/dev/null || :
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  HDW4S_BASE_PORT=7300; HDW4S_BLOCK_SIZE=4; HDW4S_PROXIES=''
  # Redirect the configuration directory the way an operator would, and let the
  # script derive its own paths. Setting SLOTS here directly is what let this
  # group pass while the shipped script died on an unbound variable.
  # "every session is filtered" was documented and never computed: the check
  # never opened this file. A slot beyond the block the table was built from is
  # a session listening with nothing in front of it.
  printf '# comment\n0 alice\n1 bob\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'counts the sessions it found'   "${out}" 'sessions    2, all within 7300-7303'
  printf '# comment\n0 alice\n9 carol\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'names a session outside the block' "${out}" 'carol was allocated port 7309'
  has 'and says how many'                 "${out}" '1 of 2 not covered'
  printf '# only comments\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'reports none when none exist'   "${out}" 'sessions    none allocated'
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

echo
# A group that dies partway leaves its remaining assertions unrecorded, which
# looks identical to a shorter suite. Counting them is the only way to notice.
EXPECTED=53   # update when tests are added; a wrong number is the point
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
