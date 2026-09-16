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

  # Machine-wide is a different thing and has to keep working: hdw4s.conf and
  # the manual both document setting HDW4S_AUTH=basic there so that every
  # session created afterwards gets a credential. Refusing that left the
  # documented flow with no command behind it.
  ( cmd_set 'HDW4S_AUTH=basic' ) >/dev/null 2>&1 \
    && ok  'the same setting is accepted machine-wide' \
    || bad 'the same setting is accepted machine-wide'
  out="$( ( cmd_set 'HDW4S_AUTH=basic' ) 2>&1 )"
  has 'and warns about sessions that have no credential yet' \
      "${out}" 'hdw4s auth'

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

  rm -f "${SLOTS}"
  alloc_slot newone ephemeral >/dev/null
  is 'alloc_slot records the type' "$(awk '$2=="newone"{print $3}' "${SLOTS}")" 'ephemeral'
  alloc_slot plain >/dev/null
  is 'and defaults it when not given' "$(awk '$2=="plain"{print $3}' "${SLOTS}")" 'desktop'

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

echo '== a slot table written by an older version still works =='
( set +e; sandbox; . "${SB}/setup.sh"
  # The deployed machines have a two-field table written by 2.2.0, and the
  # install puts readers in front of it that were written for three. If a
  # two-field row mishandles, "list", "reap" and the firewall break for real
  # users -- on upgrade, which is the worst moment. This is that table.
  printf '%s\n' \
    '# Session slots. One line per session: <index> <instance>.' \
    '0 alice' '1 INSTANCE' '2 carol' > "${SLOTS}"

  is 'every old row reads as a desktop' \
     "$(for i in alice INSTANCE carol; do type_of "${i}"; done | sort -u | tr '\n' ' ')" \
     'desktop '
  is 'and resolves to the desktop unit' "$(unit_of INSTANCE)" 'hdw4s@INSTANCE.service'
  is 'slot_of still finds a two-field row' "$(slot_of carol)" '2'
  is 'and alloc_slot is idempotent against one' "$(alloc_slot INSTANCE)" '1'
  is 'which did not rewrite the row' \
     "$(awk '$2=="INSTANCE"{print NF}' "${SLOTS}" | head -1)" '2'

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
           "${SB}/units/hdw4s-proxy@bob.service.d"
  printf '%s\n' '# comment' '0 alice' '1 bob' '2 carol' > "${SB}/etc/hdw4s/instances"
  printf 'keep me\n' > "${SB}/units/hdw4s-proxy@bob.service.d/30-session.conf"
  blk="$(pick "${ROOT}/debian/postinst")"
  # Stubbed because the shipped block calls it; reached only through the eval.
  # shellcheck disable=SC2317
  systemctl() { :; }
  ( ETCDIR="${SB}/etc/hdw4s" UNITDIR="${SB}/units"; eval "${blk}" )
  case "$(cat "${SB}/units/hdw4s-proxy@alice.service.d/30-session.conf" 2>/dev/null)" in
    *'Requires=hdw4s@alice.service'*) ok 'an instance with no drop-in gets one';;
    *) bad 'an instance with no drop-in gets one' 'missing or wrong';;
  esac
  is 'an existing drop-in is left alone' \
     "$(cat "${SB}/units/hdw4s-proxy@bob.service.d/30-session.conf")" 'keep me'
  is 'an instance with no relay directory is skipped' \
     "$(set -- "${SB}/units"/*carol*; [ -e "$1" ] && echo present || echo absent)" 'absent'
)

echo
# A group that dies partway leaves its remaining assertions unrecorded, which
# looks identical to a shorter suite. Counting them is the only way to notice.
EXPECTED=167   # update when tests are added; a wrong number is the point
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
