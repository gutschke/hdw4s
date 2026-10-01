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
  # The front door's port, for a session on the tcp transport. The streaming
  # server has no port at all: it listens on a path (hdw4s-stream-dir).
  is 'external port'  "$(port_of 0)"          '7300'
)

echo '== the stream listens on a path, never a port =='
( set +e; sandbox; TMP="${SB}"
  # A loopback port is a name any desktop on the machine may take first, and on a
  # systemd without its BPF framework nothing can stop that bind -- so the stream
  # is a unix socket in a directory only its session and its relay may enter
  # (hdw4s-stream-dir). What this guards is the regression: a port coming back.
  # Only the lines that START the streaming server are read, from the invocation
  # to the backgrounding "&", because the file is full of prose about ports.
  # shellcheck disable=SC2016  # matching the literal source text, not expanding it
  stream_argv() { sed -n '/^"\${stream\[@\]}" \\$/,/&$/p' "$1"; }
  # A pattern on the captured text, not "| grep -q": under pipefail an early
  # exit of grep reads as a miss.
  gives_no_port() {
    local argv
    argv="$(stream_argv "$1")"
    [ -n "${argv}" ] || return 1
    case "${argv}" in *--port=*|*--addr=*) return 1;; esac
  }
  # shellcheck disable=SC2016  # likewise: the literal argument in the script
  case "$(stream_argv "${ROOT}/hdw4s-run-session")" in
    *'--unix-socket="${HDW4S_STREAM_SOCKET}"'*) ok 'the streaming server is given its socket path';;
    *) bad 'the streaming server is given its socket path' 'no --unix-socket in its argv';;
  esac
  if gives_no_port "${ROOT}/hdw4s-run-session"; then
    ok 'and no port or address'
  else
    bad 'and no port or address' 'a --port= or --addr= is back in its argv'
  fi
  # RED ARM: the same check, against a copy with the port put back.
  # shellcheck disable=SC2016  # the literal line to insert, not an expansion
  sed 's|^  --unix-socket=.*|&\n  --port="${HDW4S_PORT}" \\|' \
    "${ROOT}/hdw4s-run-session" > "${TMP}/run-session-with-port"
  if gives_no_port "${TMP}/run-session-with-port"; then
    bad 'RED ARM: a port put back is caught' 'the check passed it'
  else
    ok 'RED ARM: a port put back is caught'
  fi
  # The relay names the path for every instance, and nothing writes a port over it.
  case "$(grep '^ExecStart=' "${ROOT}/hdw4s-proxy@.service")" in
    *'systemd-socket-proxyd /run/hdw4s-stream/%i/s/stream.sock') ok 'the relay connects to the path';;
    *) bad 'the relay connects to the path' 'its ExecStart= names something else';;
  esac
  is 'nothing in the CLI writes a loopback upstream' \
     "$(grep -c 'socket-proxyd 127\.0\.0\.1' "${ROOT}/hdw4s")" '0'
  # The helper runs as root and removes a directory by name, so a name that is
  # a path is refused before anything is touched.
  for name in '../x' '.' 'a/b'; do
    if HDW4S_STREAM_DIR="${TMP}/no-such" "${ROOT}/hdw4s-stream-dir" remove "${name}" \
         2>/dev/null; then
      bad "the stream helper refuses the name '${name}'" 'accepted'
    else
      ok "the stream helper refuses the name '${name}'"
    fi
  done
)

echo '== the WebRTC signalling adapter refuses code it does not recognise =='
( set +e
  # The adapter reroutes one aiohttp.ClientSession; any other one in the module
  # would bypass it unseen. Its module check, run against the shape 2.0.0rc1 has
  # and against doctored copies (the red arms).
  out="$(python3 - "${ROOT}/hdw4s-selkies-webrtc" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("a", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("a", l)); l.exec_module(m)
good = ("import aiohttp\nfrom aiohttp import ClientWebSocketResponse, WSMsgType\n"
        "x: Optional[aiohttp.ClientSession] = None\ns = aiohttp.ClientSession()\n")
print("good", m.module_source_problem(good) is None)
print("second", m.module_source_problem(good + "t = aiohttp.ClientSession()\n") is not None)
print("fromimport", m.module_source_problem(good.replace("WSMsgType\n", "WSMsgType, TCPConnector\n")) is not None)
print("alias", m.module_source_problem(good + "import aiohttp as h\n") is not None)
PY
)"
  has 'the code 2.0.0rc1 has is accepted'           "${out}" 'good True'
  has 'RED: a second ClientSession is refused'      "${out}" 'second True'
  has 'RED: another name imported from aiohttp is refused' "${out}" 'fromimport True'
  has 'RED: aiohttp under another name is refused'  "${out}" 'alias True'
)

echo '== an adapter that does not recognise Selkies degrades to websockets alone =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  # Every desktop that offers WebRTC starts through the adapter. It used to
  # REFUSE TO START when Selkies moved the code it adapts, which, with WebRTC
  # offered by default, takes every desktop down at the next version raise. It now starts the
  # desktop with WebRTC unreachable instead. What has to hold on that path is
  # that NOTHING can reach WebRTC -- the TCP signalling connection the adapter
  # exists to prevent is made only by WebRTC -- and that the TURN pin is still
  # on the command line anyway.
  #
  # A stand-in Selkies, because the real one cannot be imported here: a package
  # whose signalling client is shaped like a FUTURE release (a second
  # ClientSession), and whose entry point records the argv and environment it
  # was handed instead of starting a server. The adapter, its checks and its
  # rewrite are the real ones.
  mkdir -p "${SB}/py/selkies" "${SB}/py/aiohttp" "${SB}/run"
  : > "${SB}/py/selkies/__init__.py"
  cat > "${SB}/py/selkies/webrtc_signaling_client.py" <<'PY'
import aiohttp
from aiohttp import ClientWebSocketResponse, WSMsgType
class WebRTCSignalingClient:
    session: "aiohttp.ClientSession" = None
    async def connect_and_listen(self):
        self.session = aiohttp.ClientSession()
        self.other = aiohttp.ClientSession()
        await self.session.ws_connect(self.url)
PY
  cat > "${SB}/py/selkies/webrtc_mode.py" <<'PY'
class WebRTCService:
    def create_signaling_client(self):
        return f"ws://localhost:{self.args.port}/api/ws"
PY
  cat > "${SB}/py/selkies/__main__.py" <<'PY'
import json, os, sys
def main():
    with open(os.environ["STUB_OUT"], "w") as fh:
        json.dump({"argv": sys.argv[1:],
                   "env": sorted(k for k in os.environ if k.startswith("SELKIES_"))}, fh)
    return 0
PY
  # An aiohttp stand-in too, so the group does not depend on one being
  # installed. Only the names the adapter and the stand-in module touch.
  printf '%s\n' 'class ClientSession: pass' 'class ClientWebSocketResponse: pass' \
    'class WSMsgType: pass' 'class UnixConnector:' \
    '    def __init__(self, path): self.path = path' > "${SB}/py/aiohttp/__init__.py"

  # The arguments hdw4s-run-session hands the adapter for HDW4S_WEBRTC=yes, read
  # out of the script rather than retyped, so a change to that arm reaches this
  # test. Only the case arm's array; the rest of the command line does not bear
  # on what this asserts.
  args="$(sed -n '/^  yes)$/,/^    ;;$/p' "${ROOT}/hdw4s-run-session" |
          command grep -o -- "--[a-z-]*='[^']*'" | tr -d "'")"
  has 'the run-session yes arm was found'        "${args}" '--enable-dual-mode=true|locked'
  has 'and carries the ice-lite pin'             "${args}" '--webrtc-ice-lite=true|locked'
  # Then a bare flag, an underscore spelling and an explicit start mode, which
  # nothing passes today: the rewrite has to remove what the parser would read
  # and leave everything else, and a bare bool does NOT consume the next token.
  # shellcheck disable=SC2086
  set -- ${args} --turn-host=turn.invalid --unix-socket="${SB}/run/s.sock" \
         --enable-dual-mode '--webrtc-ice-lite=true|locked' \
         '--enable_dual_mode=true|locked' --mode webrtc
  run() {
    STUB_OUT="${SB}/out.json" XDG_RUNTIME_DIR="${SB}/run" PYTHONPATH="${SB}/py" \
    SELKIES_ENABLE_DUAL_MODE='true' SELKIES_MODE='webrtc' \
      python3 "${ROOT}/hdw4s-selkies-webrtc" "$@" 2>&1
  }
  rm -f "${SB}/out.json"
  out="$(run "$@")"; rc=$?
  is  'the desktop STARTS'                       "${rc}" '0'
  has 'and the journal is told, loudly'          "${out}" 'WEBRTC IS OFF FOR THIS SESSION'
  has 'with the reason'                          "${out}" 'ClientSession 3 time(s)'
  got="$(python3 - "${SB}/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
a = d["argv"]
def all_of(name):
    return [x for x in a if x.startswith("--")
            and x[2:].split("=", 1)[0].replace("-", "_") == name]
print("dual", all_of("enable_dual_mode"))
print("mode", all_of("mode"))
print("last", a[-2:])
print("pin", "--turn-host=turn.invalid" in a, a.count("--webrtc-ice-lite=true|locked"))
print("stray", "webrtc" in a)
print("env", d["env"])
PY
)"
  has 'dual mode is locked OFF, once'            "${got}" "dual ['--enable-dual-mode=false|locked']"
  has 'the start mode is websockets, once'       "${got}" "mode ['--mode=websockets']"
  has 'and both come last, where the parser takes them' \
      "${got}" "last ['--enable-dual-mode=false|locked', '--mode=websockets']"
  has 'the TURN pin and both ice-lite pins survive' "${got}" 'pin True 2'
  has 'no stray value is left to read as a flag' "${got}" 'stray False'
  has 'the environment cannot ask for WebRTC'    "${got}" 'env []'
  is  'and hdw4s check is told' \
      "$(cat "${SB}/run/webrtc-degraded" 2>/dev/null)" \
      "Selkies' signalling client module is not the code this adapts: it names ClientSession 3 time(s), not 2"

  # The positive control: the shape the adapter knows applies, keeps dual mode,
  # and clears a report left by an earlier start of the server in this session.
  # Without it, a rewrite that fired on EVERY start would pass everything above.
  sed -i '/self.other/d' "${SB}/py/selkies/webrtc_signaling_client.py"
  out="$(run "$@")"; rc=$?
  is  'a recognised Selkies starts too'          "${rc}" '0'
  has 'and is adapted'                           "${out}" 'WebRTC signalling goes through'
  hasnt 'and nothing says WebRTC is off'         "${out}" 'WEBRTC IS OFF'
  has 'dual mode is left as configured'          "$(cat "${SB}/out.json")" '--enable-dual-mode=true|locked'
  [ ! -e "${SB}/run/webrtc-degraded" ] && ok 'and the stale report is gone' \
    || bad 'and the stale report is gone' 'still there'

  # A failure that is not one of the named refusals -- here the module is gone
  # -- degrades the same way rather than taking the desktop down.
  rm -f "${SB}/py/selkies/webrtc_signaling_client.py"
  out="$(run "$@")"; rc=$?
  is  'an adapter that cannot even import still starts the desktop' "${rc}" '0'
  has 'on websockets alone' "$(cat "${SB}/out.json")" '--enable-dual-mode=false|locked'
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
  # The pool's size used to be "set" like any other number, which wrote it and
  # nothing else: lowered that way, the next boot stopped minting seats the
  # router still offered. It is refused now, by set AND unset, and points at the
  # command that changes the seats with it -- and the file is not touched.
  printf 'HDW4S_EPHEMERAL_SLOTS=3\n' > "${CONF}"
  out="$( (cmd_set 'HDW4S_EPHEMERAL_SLOTS=4') 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'set refuses the pool size' || bad 'set refuses the pool size' "rc ${rc}"
  has   'and names the command that sizes it' "${out}" 'hdw4s pool size <N>'
  out="$( (cmd_unset 'HDW4S_EPHEMERAL_SLOTS') 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and so does unset' || bad 'and so does unset' "rc ${rc}"
  is    'neither touched the file' "$(cat "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=3'
  out="$(set_hint '' 'HDW4S_EPHEMERAL_HOME_SIZE=2G' 2>&1)"
  has   'a seat size points at a reboot'       "${out}" 'reboot to use it'
  hasnt 'and not at a restart'                 "${out}" 'estart'
  hasnt 'and says nothing about seats'         "${out}" 'pool size'
)

echo '== a pool seat or the authoring slot is not a person'"'"'s desktop =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Every refusal here stood in front of a command that used to do its damage
  # quietly: "enable ephemeral3" wrote a person's drop-ins into the pool unit,
  # and "disable"/"release" shrank the pool with nothing saying so. Each case
  # asserts the refusal AND that nothing was written, because a refusal that
  # prints after the damage is the half-apply this tree has shipped before.
  NSDIR="${SB}/ns"
  mkdir -p "${NSDIR}/eph0" "${NSDIR}/eph1" "${NSDIR}/tmpl"
  : > "${NSDIR}/eph0/passwd"; : > "${NSDIR}/eph1/passwd"; : > "${NSDIR}/tmpl/passwd"
  printf '%s\n' '# comment' '0 alice' '1 eph0 ephemeral' '2 tmpl template' \
    '3 root template' > "${SLOTS}"
  table="$(cat "${SLOTS}")"
  CALLS="${SB}/calls"; : > "${CALLS}"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; }
  RUNDIR="${SB}/run"

  # The seat's account is stood in for, as the minter would have made it. Without
  # it the enable died later, at the account lookup, and "nothing was written"
  # passed with the guard removed -- measured, by removing it.
  seat() { getent() { printf 'eph0:x:60900:60900::/home/user:/bin/bash\n'; }; "$@"; }
  out="$( (seat cmd_enable eph0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'enable refuses a pool seat' || bad 'enable refuses a pool seat' "rc ${rc}"
  has   'and says what it is'           "${out}" 'seat of the ephemeral pool'
  has   'and what to do instead'        "${out}" 'hdw4s enable <user>'
  is    'and writes no drop-in'         "$(find "${DROPIN}" -mindepth 1 | wc -l | tr -d ' ')" '0'
  out="$( (cmd_enable eph1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and a minted seat with no row yet' \
    || bad 'and a minted seat with no row yet' "rc ${rc}"
  out="$( (cmd_enable tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'enable refuses the authoring slot' || bad 'enable refuses the authoring slot' "rc ${rc}"
  has   'and points at template edit'   "${out}" 'hdw4s template edit'
  out="$( (cmd_enable "${TEMPLATE_SLOT}") 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and the reserved name before anything provisions it' \
    || bad 'and the reserved name before anything provisions it' "rc ${rc}"
  # The row an earlier "enable --template root" could leave on a real account.
  out="$( (cmd_enable root) 2>&1 )"; rc=$?
  has   'a template row on a real account names the way out' \
        "${out}" 'hdw4s release --internal root'
  # Seats are added by "pool size" alone; the per-seat spelling is a usage error
  # from the real dispatcher, before anything is looked up or written.
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" enable --ephemeral ephemeral3 >/dev/null 2>&1
  is    'enable --ephemeral is a usage error' "$?" '2'
  is    'no enable changed the table'   "$(cat "${SLOTS}")" "${table}"

  out="$( (seat cmd_disable eph0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'disable refuses a pool seat' || bad 'disable refuses a pool seat' "rc ${rc}"
  has   'and says how to end one desktop' "${out}" 'systemctl stop hdw4s-ephemeral@eph0.service'
  out="$( (cmd_disable tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and the authoring slot' || bad 'and the authoring slot' "rc ${rc}"
  out="$( (cmd_release eph0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'release refuses a pool seat' || bad 'release refuses a pool seat' "rc ${rc}"
  has   'and names the command that sizes the pool' "${out}" 'hdw4s pool size <N>'
  hasnt 'and no longer offers a way past' "${out}" 'release --internal'
  out="$( (cmd_release --internal eph0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'not even with --internal' || bad 'not even with --internal' "rc ${rc}"
  has   'which points at pool size too' "${out}" 'hdw4s pool size <N>'
  out="$( (cmd_release tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and the authoring slot, too' || bad 'and the authoring slot, too' "rc ${rc}"
  has   'and points at template reset' "${out}" 'hdw4s template reset'
  out="$( (cmd_release --internal alice) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok '--internal is refused on a person'"'"'s desktop' \
    || bad '--internal is refused on a person'"'"'s desktop' "rc ${rc}"
  is    'no refusal touched the table or a unit' \
        "$(cat "${SLOTS}"; cat "${CALLS}")" "${table}"

  # The one way past, for the authoring slot, which must actually work -- and
  # take the identity the minter made with it, or the next mint dies on "uid
  # already belongs to" (measured on a box 2026-09-30, releasing a template
  # row). Only records that name this slot: 60901 below belongs to another and
  # must survive. And the EPHEMERAL unit's drop-ins, by name.
  USERDB="${SB}/userdb"; mkdir -p "${USERDB}"
  for f in tmpl.user 60999.user tmpl.group 60999.group; do
    printf '{"userName":"tmpl","uid":60999,"gid":60999}\n' > "${USERDB}/${f}"
  done
  printf '{"userName":"eph1","uid":60901,"gid":60901}\n' > "${USERDB}/60901.user"
  mkdir -p "${DROPIN}/hdw4s-ephemeral@tmpl.service.d"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; [ "$1" != is-active ]; }
  (cmd_release --internal tmpl) >/dev/null 2>&1
  is    'release --internal removes the authoring slot' "$(slot_of tmpl)" ''
  is    'and only that row' "$(slot_of alice):$(slot_of eph0)" '0:1'
  has   'and keeps the comments' "$(cat "${SLOTS}")" '# comment'
  is    'and the identity the minter made for it' \
        "$(find "${USERDB}" -mindepth 1 -printf '%f ')" '60901.user '
  is    'and its namespace' "$([ -e "${NSDIR}/tmpl" ] && echo left || echo gone)" 'gone'
  is    'and its drop-ins' "$(find "${DROPIN}" -mindepth 1 | wc -l | tr -d ' ')" '0'
)

echo '== the pool is sized as one thing, and never takes a visitor'"'"'s seat =='
( set +e; sandbox; . "${SB}/setup.sh"
  # "hdw4s pool size N" replaced a reboot and a seat-by-seat procedure. What it
  # must keep true: the setting, the identities and the rows agree; a seat with
  # a desktop in it is never taken; and an interruption leaves at worst a seat
  # that is minted and not offered, never one offered that cannot start.
  #
  # STOOD IN FOR, and named so nobody reads more into a green run: the minter
  # (a script that records its calls and writes the namespace file the real one
  # writes), enable_slot (appends the row, which is the part the router reads),
  # systemctl, and the wait for the router. Runs nothing on a machine. Whether a
  # seat added live actually serves a desktop is a question for a real box.
  NSDIR="${SB}/ns"; USERDB="${SB}/userdb"; RUNDIR="${SB}/run"
  POOLDIR="${SB}/demux"; TEARDOWNDIR="${SB}/teardown"
  mkdir -p "${NSDIR}" "${USERDB}" "${RUNDIR}/hdw4s" "${POOLDIR}/reserved" "${TEARDOWNDIR}"
  CALLS="${SB}/calls"; : > "${CALLS}"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; [ "$1" != is-active ]; }
  enable_slot() { echo "enable_slot $*" >> "${CALLS}"; alloc_slot "$2" "$1" >/dev/null; }
  sleep() { :; }
  mkdir -p "${SB}/lib"
  cat > "${SB}/lib/hdw4s-ephemeral-slots" <<'MINT'
#!/bin/bash
case "$1" in
  --pool-max) echo "${POOL_MAX:-10}" ;;
  --seat)
    [ "$2" != "${MINT_FAILS:-}" ] || { echo "minter refused $2" >&2; exit 1; }
    echo "minted $2 when the file said $(grep -h '^HDW4S_EPHEMERAL_SLOTS=' "${HDW4S_ETCDIR}/hdw4s.conf")" >> "${HDW4S_ETCDIR}/../calls"
    mkdir -p "${NSDIR_FOR_STUB}/$2"; : > "${NSDIR_FOR_STUB}/$2/passwd" ;;
esac
MINT
  chmod +x "${SB}/lib/hdw4s-ephemeral-slots"
  export HDW4S_LIBDIR="${SB}/lib" NSDIR_FOR_STUB="${NSDIR}"
  rm -f "${SLOTS}"
  printf '#HDW4S_EPHEMERAL_SLOTS=1\n' > "${CONF}"
  rows() { awk '$1 !~ /^#/ && $3 == "ephemeral" { printf "%s ", $2 }' "${SLOTS}"; }

  # GROWING, live: the setting first, then each seat minted, then its row.
  (pool_resize 3) >/dev/null 2>&1
  is  'growing offers the new seats' "$(rows)" 'ephemeral0 ephemeral1 ephemeral2 '
  is  'and writes the setting the next boot reads' \
      "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=3'
  has 'and the setting was written BEFORE a seat was minted' \
      "$(cat "${CALLS}")" 'minted ephemeral0 when the file said HDW4S_EPHEMERAL_SLOTS=3'
  # Mint, then row, for every seat: a row before its identity is the one
  # disagreement that costs a visitor a desktop.
  is  'and every seat was minted before its row was written' \
      "$(command grep -E '^(minted|enable_slot)' "${CALLS}" | cut -d' ' -f1-3 | tr '\n' ';')" \
      'minted ephemeral0 when;enable_slot ephemeral ephemeral0;minted ephemeral1 when;enable_slot ephemeral ephemeral1;minted ephemeral2 when;enable_slot ephemeral ephemeral2;'
  # Again with the same number changes nothing.
  : > "${CALLS}"
  (pool_resize 3) >/dev/null 2>&1
  hasnt 'the same size again mints nothing' "$(cat "${CALLS}")" 'minted'
  out="$(pool_show)"
  has 'pool size with no number reports the size' "${out}" 'has 3 seat(s); 0 in use'

  # SHRINKING PAST A VISITOR. ephemeral2 has a desktop running, whoever is or
  # is not looking at it: nothing may be taken, and the command says so.
  mkdir -p "${RUNDIR}/hdw4s/ephemeral2"
  out="$( (pool_resize 1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'shrinking past a busy seat fails' || bad 'shrinking past a busy seat fails' "rc ${rc}"
  is  'and takes no seat' "$(rows)" 'ephemeral0 ephemeral1 ephemeral2 '
  is  'and leaves its identity' "$([ -f "${NSDIR}/ephemeral2/passwd" ] && echo kept)" 'kept'
  has 'and names the seat and why' "${out}" 'ephemeral2: a desktop is running in it'
  has 'and how to end it, if that is the decision' "${out}" 'systemctl stop hdw4s-ephemeral@ephemeral2.service'
  hasnt 'and stopped no desktop' "$(cat "${CALLS}")" 'stop hdw4s-ephemeral@ephemeral2'
  is  'and the setting still says 3' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=3'
  has 'pool size shows it in use' "$(pool_show)" 'ephemeral2       a desktop is running in it'

  # A busy seat LOWER down holds the pool one above it; seats above it go.
  rmdir "${RUNDIR}/hdw4s/ephemeral2"; mkdir -p "${RUNDIR}/hdw4s/ephemeral1"
  : > "${CALLS}"
  out="$( (pool_resize 0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a busy seat lower down still fails the command' \
    || bad 'a busy seat lower down still fails the command' "rc ${rc}"
  is  'the seats above it go, the seats below it stay' "$(rows)" 'ephemeral0 ephemeral1 '
  is  'and the setting says what the pool is' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=2'
  is  'and the identity of the seat that went is gone' "$([ -e "${NSDIR}/ephemeral2" ] && echo left || echo gone)" 'gone'
  has 'and its own unit was stopped, by name' "$(cat "${CALLS}")" 'stop hdw4s-proxy@ephemeral2.service hdw4s-ephemeral@ephemeral2.service'
  has 'and its watchers' "$(cat "${CALLS}")" 'stop hdw4s-teardown@ephemeral2.path hdw4s-start@ephemeral2.path'
  has 'and it says it is 2, not 0' "${out}" 'has 2 seat(s)'
  rmdir "${RUNDIR}/hdw4s/ephemeral1"

  # THE OTHER THREE KINDS OF BUSY. A fresh reservation is a visitor on the way;
  # a stale one is not. A unit starting has no runtime directory yet.
  touch "${POOLDIR}/reserved/ephemeral1"
  out="$( (pool_resize 1) 2>&1 )"
  is  'a fresh reservation holds its seat' "$(rows)" 'ephemeral0 ephemeral1 '
  has 'and says so' "${out}" 'a visitor has just been handed it'
  touch -d '-1 hour' "${POOLDIR}/reserved/ephemeral1"
  is  'a stale one does not' "$(seat_busy ephemeral1)" ''
  systemctl() { echo "systemctl $*" >> "${CALLS}"
                case "$*" in *'ActiveState'*ephemeral1*) echo activating;; esac
                [ "$1" != is-active ]; }
  out="$( (pool_resize 1) 2>&1 )"
  is  'a starting unit holds its seat' "$(rows)" 'ephemeral0 ephemeral1 '
  has 'and says so' "${out}" 'its desktop is activating'
  systemctl() { echo "systemctl $*" >> "${CALLS}"; [ "$1" != is-active ]; }
  mkdir -p "${TEARDOWNDIR}/ending"; : > "${TEARDOWNDIR}/ending/ephemeral1"
  out="$( (pool_resize 1) 2>&1 )"
  is  'a seat being torn down holds too' "$(rows)" 'ephemeral0 ephemeral1 '
  rm -f "${TEARDOWNDIR}/ending/ephemeral1"

  # THE ROUTER LETTING A SEAT WHILE IT IS BEING TAKEN. The row goes first, then
  # the wait, then a second look: a letting that read the table before the row
  # went shows up as a reservation, and the seat goes back on offer as it was.
  before="$(grep ephemeral1 "${SLOTS}")"
  sleep() { touch "${POOLDIR}/reserved/ephemeral1"; }
  out="$( (pool_resize 1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat let during the wait fails the command' \
    || bad 'a seat let during the wait fails the command' "rc ${rc}"
  is  'and its row is put back exactly' "$(grep ephemeral1 "${SLOTS}")" "${before}"
  is  'and its identity is kept' "$([ -f "${NSDIR}/ephemeral1/passwd" ] && echo kept)" 'kept'
  sleep() { :; }
  rm -f "${POOLDIR}/reserved/ephemeral1"
  (pool_resize 1) >/dev/null 2>&1
  is  'once it is idle, it goes' "$(rows)" 'ephemeral0 '

  # ONE AT A TIME: a second run is refused while the first holds the lock, and
  # changes nothing.
  out="$( exec {held}>"${RUNDIR}/hdw4s-pool.lock"; flock "${held}"; (pool_resize 3) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a second pool size at once is refused' \
    || bad 'a second pool size at once is refused' "rc ${rc}"
  has 'and says why' "${out}" 'another "hdw4s pool size" is running'
  is  'and changed nothing' "$(rows)" 'ephemeral0 '

  # LARGER THAN THE MINTER CAN MAKE: refused before anything is written.
  out="$( (POOL_MAX=2 pool_resize 3) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a size beyond the uid window is refused' \
    || bad 'a size beyond the uid window is refused' "rc ${rc}"
  is  'and nothing was written' "$(rows):$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'ephemeral0 :HDW4S_EPHEMERAL_SLOTS=1'

  # A SEAT THAT CANNOT BE MINTED (a real account by that name, say) ends the
  # growth there, and the setting comes back down: left at the larger number,
  # the boot's minter would die on it and take every seat with it.
  out="$( (MINT_FAILS=ephemeral2 pool_resize 4) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a failed mint fails the command' || bad 'a failed mint fails the command' "rc ${rc}"
  is  'the seats before it are offered' "$(rows)" 'ephemeral0 ephemeral1 '
  is  'and the setting matches them' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=2'
  has 'and says where it stopped' "${out}" 'stopped growing at 2'
  # And a row above it with no identity -- what the old procedure could leave --
  # is not left offered with nothing behind it.
  printf '%s\n' '9 ephemeral3 ephemeral' >> "${SLOTS}"
  out="$( (MINT_FAILS=ephemeral2 pool_resize 4) 2>&1 )"
  is  'a row above the stop with no identity is taken back' "$(rows)" 'ephemeral0 ephemeral1 '

  # AN INSTALL SIZED THE OLD WAY, half done: rows above the setting, a row the
  # minter never makes, a seat minted with no row. "pool size" reports it and
  # the same number settles it.
  printf '%s\n' '0 alice' '1 ephemeral0 ephemeral' '2 ephemeral1 ephemeral' \
    '3 ephemeral2 ephemeral' '4 ephemeral3 ephemeral' '5 oddseat ephemeral' > "${SLOTS}"
  printf 'HDW4S_EPHEMERAL_SLOTS=2\n' > "${CONF}"; HDW4S_EPHEMERAL_SLOTS=2
  mkdir -p "${NSDIR}/ephemeral5"; : > "${NSDIR}/ephemeral5/passwd"
  out="$(pool_show)"
  has 'pool size reports rows the next boot will not mint' "${out}" 'ephemeral2 ephemeral3 oddseat'
  has 'and the command that settles it' "${out}" 'hdw4s pool size 2'
  (pool_resize 2) >/dev/null 2>&1
  is  'and settling it leaves exactly the seats' "$(rows)" 'ephemeral0 ephemeral1 '
  is  'and a person'"'"'s desktop alone' "$(slot_of alice)" '0'
  is  'and the identity above the size is gone' "$([ -e "${NSDIR}/ephemeral5" ] && echo left || echo gone)" 'gone'

  # The real dispatcher: a word other than "size" is a usage error.
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" pool grow 3 >/dev/null 2>&1
  is  'pool takes only size' "$?" '2'
)

echo '== the minter mints one seat only inside the configured pool =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  # These refusals all come BEFORE the minter writes anything -- that is the
  # point of settling the arguments first -- so the real script can be run here.
  mkdir -p "${SB}/etc"
  printf 'HDW4S_EPHEMERAL_SLOTS=3\n' > "${SB}/etc/hdw4s.conf"
  m() { HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s-ephemeral-slots" "$@" 2>&1; }
  is  'the largest pool keeps one uid for the authoring slot' "$(m --pool-max)" '99'
  printf '%s\n' '0 a template' '1 b template' > "${SB}/etc/instances"
  is  'and one per template row' "$(m --pool-max)" '98'
  out="$(m --seat ephemeral3)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat beyond the setting is refused' || bad 'a seat beyond the setting is refused' "rc ${rc}"
  has 'and says to raise the setting first' "${out}" 'raise the'
  out="$(m --seat ephemeral01)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat number written another way is refused' \
    || bad 'a seat number written another way is refused' "rc ${rc}"
  out="$(m --seat alice)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a name that is not a seat is refused' || bad 'a name that is not a seat is refused' "rc ${rc}"
  printf 'HDW4S_EPHEMERAL_SLOTS=99\n' > "${SB}/etc/hdw4s.conf"
  out="$(m --seat ephemeral98)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a pool grown into the template uids is refused' \
    || bad 'a pool grown into the template uids is refused' "rc ${rc}"
  has 'and names the largest it can be' "${out}" 'largest pool here is'
  # A pool of zero is a machine that serves only named desktops.
  printf 'HDW4S_EPHEMERAL_SLOTS=0\n' > "${SB}/etc/hdw4s.conf"
  out="$(m --seat ephemeral0)"
  has 'zero is a size, and has no seats' "${out}" 'beyond HDW4S_EPHEMERAL_SLOTS=0'
)

echo '== template edit needs no prior step, and a failed mint leaves no row =='
( set +e; sandbox; . "${SB}/setup.sh"
  systemctl() { :; }
  # provision_template is judged by what it hands enable_slot, which is stood in
  # for: the real one needs systemd, the minter and an account, and its own
  # behaviour for a template row is covered where the slot types are.
  CALLS="${SB}/calls"; : > "${CALLS}"
  enable_slot() { echo "$*" >> "${CALLS}"; }
  rm -f "${SLOTS}"
  provision_template >/dev/null
  is 'a fresh install gets the reserved authoring slot' "$(cat "${CALLS}")" "template ${TEMPLATE_SLOT}"
  : > "${CALLS}"
  printf '%s\n' '0 alice' '1 eph0 ephemeral' > "${SLOTS}"
  provision_template >/dev/null
  is 'so does one with only people and seats' "$(cat "${CALLS}")" "template ${TEMPLATE_SLOT}"
  # AN UPGRADE: a row the retired "enable --template" made is used as it is.
  : > "${CALLS}"
  printf '%s\n' '0 alice' '1 author template' '2 eph0 ephemeral' > "${SLOTS}"
  provision_template >/dev/null
  is 'an existing template row is kept, not replaced' "$(cat "${CALLS}")" ''
  unset -f enable_slot
  . "${SB}/setup.sh"
  systemctl() { :; }

  # F1: the minter reads the row, so the row is written first -- and a failed
  # mint used to leave it, typed "template", for good.
  mkdir -p "${SB}/lib"
  printf '#!/bin/sh\necho "minter refused $*" >&2\nexit 1\n' > "${SB}/lib/hdw4s-ephemeral-slots"
  chmod +x "${SB}/lib/hdw4s-ephemeral-slots"
  printf '%s\n' '0 alice' > "${SLOTS}"
  out="$( (HDW4S_LIBDIR="${SB}/lib" enable_slot template "${TEMPLATE_SLOT}") 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a failed mint fails the provisioning' || bad 'a failed mint fails the provisioning' "rc ${rc}"
  has 'and it was the minter that failed' "${out}" 'minter refused --template'
  is  'and the row it wrote is taken back' "$(slot_of "${TEMPLATE_SLOT}")" ''
  is  'and nothing else is'                "$(slot_of alice)" '0'
  # A row that was there BEFORE this call is not this call's to remove.
  printf '%s\n' '0 alice' '1 author template' > "${SLOTS}"
  (HDW4S_LIBDIR="${SB}/lib" enable_slot template author) >/dev/null 2>&1
  is  'a row that predates the call is kept' "$(slot_of author)" '1'

  # The command line no longer offers the type at all: the retired spelling is a
  # usage error from the real dispatcher, before anything is looked up.
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" enable --template x >/dev/null 2>&1
  is 'enable --template is a usage error' "$?" '2'
)

echo '== the template editor refuses a row the minter did not make =='
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc" "${SB}/ns/_hdw4s_author"
  # "root" stands in for a person: an account that resolves, which the minter
  # did not make. Starting the authoring desktop there would start it as them.
  printf '%s\n' '0 root template' > "${SB}/etc/instances"
  out="$(HDW4S_ETCDIR="${SB}/etc" HDW4S_NS_DIR="${SB}/ns" python3 - "${ROOT}/hdw4s-template" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("tmpl", sys.argv[1])
spec = importlib.util.spec_from_loader("tmpl", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
m.cmd_edit(False)
print("STARTED")
PY
)"
  hasnt 'it does not go on to start the desktop' "${out}" 'STARTED'
  has   'it says why'                            "${out}" 'no identity this boot'
  has   'and names the way out'                  "${out}" 'hdw4s release --internal root'
  printf '%s\n' '# nothing' > "${SB}/etc/instances"
  out="$(HDW4S_ETCDIR="${SB}/etc" HDW4S_NS_DIR="${SB}/ns" python3 - "${ROOT}/hdw4s-template" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("tmpl", sys.argv[1])
spec = importlib.util.spec_from_loader("tmpl", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
m.cmd_edit(False)
PY
)"
  hasnt 'with no row it no longer asks for a name' "${out}" 'enable --template'
  has   'it points at the command that sets one up' "${out}" 'hdw4s template edit'
)

echo '== a published Chrome forgets its extension service workers =='
( set +e
  # The worker database is not carried, so a record saying an extension's
  # worker is registered stops Chrome registering it: uBlock Origin Lite showed
  # an error in every new desktop until reloaded. Everything else is kept.
  out="$(python3 - "${ROOT}/hdw4s-template" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("tmpl", sys.argv[1])
spec = importlib.util.spec_from_loader("tmpl", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
p = {"extensions": {"settings": {
        "a": {"path": "x", "service_worker_registration_info": {"version": "1"},
              "has_started_service_worker": True, "serviceworkerevents": ["e"]},
        "b": {"path": "y"}}}, "other": 1}
print("removed=%d" % m.forget_extension_workers(p))
print("a=%s b=%s other=%s" % (sorted(p["extensions"]["settings"]["a"]),
                              sorted(p["extensions"]["settings"]["b"]), p["other"]))
PY
)"
  has 'it removes the three worker records' "${out}" 'removed=3'
  has 'and keeps everything else'          "${out}" "a=['path'] b=['path'] other=1"
)

echo '== a user-dirs file edited in the home is published, if it is the newer =='
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  run() {
    HDW4S_ETCDIR="${T}/etc" python3 - "${ROOT}/hdw4s-template" "${T}" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys, os
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m); m.normalise = lambda tree: None
T = sys.argv[2]
gen, _, _ = m.harvest(T + "/author", T + "/home", "x")
print(open(os.path.join(gen, "profile/config/user-dirs.dirs")).read())
print("folders=" + ",".join(sorted(os.listdir(os.path.join(gen, "home")))))
PY
  }
  mkdir -p "${T}/etc" "${T}/root" "${T}/author/config" "${T}/home/.config" \
           "${T}/home/.Music" "${T}/home/Music" "${T}/home/Downloads"
  echo "HDW4S_TEMPLATE_DIR=${T}/root" > "${T}/etc/hdw4s.conf"
  printf 'XDG_MUSIC_DIR="$HOME/Music"\n' > "${T}/author/config/user-dirs.dirs"
  printf 'XDG_MUSIC_DIR="$HOME/.Music"\n' > "${T}/home/.config/user-dirs.dirs"
  touch -d '-1 hour' "${T}/author/config/user-dirs.dirs"
  out="$(run)"
  has 'the home'"'"'s newer file is published' "${out}" 'XDG_MUSIC_DIR="$HOME/.Music"'
  has 'with the hidden folder it names'       "${out}" 'folders=.Music'
  touch -d '-2 hours' "${T}/home/.config/user-dirs.dirs"
  out="$(run)"
  has 'an older one in the home is not'       "${out}" 'XDG_MUSIC_DIR="$HOME/Music"'
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
    # '/.d', not '.d': the refusal quotes the sandbox path, which mktemp names
    # /tmp/tmp.XXXXXXXXXX, so a bare '.d' failed a correct refusal whenever the
    # random suffix began with a d -- about one run in sixty. The defect it
    # guards produced "${DROPIN}/.d", which always has the slash.
    hasnt 'and no command got far enough to build a unit name' "${out}" '/.d'
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
           "${SB}/units/hdw4s-proxy@tmpl.service.d" \
           "${SB}/units/hdw4s-proxy@fred.service.d" \
           "${SB}/units/hdw4s-proxy@gwen.service.d"
  printf '%s\n' '# comment' '0 alice' '1 bob' '2 carol' '3 dave ephemeral' '4 eve' \
                 '5 tmpl template' '6 fred ephemeral' '7 gwen' \
    > "${SB}/etc/hdw4s/instances"
  # A POOL SLOT'S DROP-IN FROM BEFORE ONLY THE MINT STARTED A DESKTOP: BindsTo=,
  # which starts the session on every connection. The upgrade must turn it into
  # Requisite=, or an upgraded box keeps starting desktops for nobody. And a
  # named desktop's BindsTo= is its design and must be left exactly as it is.
  printf '%s\n' '[Unit]' 'BindsTo=hdw4s-ephemeral@fred.service' \
                 'After=hdw4s-ephemeral@fred.service' \
    > "${SB}/units/hdw4s-proxy@fred.service.d/30-session.conf"
  printf '%s\n' '[Unit]' 'BindsTo=hdw4s@gwen.service' 'After=hdw4s@gwen.service' \
    > "${SB}/units/hdw4s-proxy@gwen.service.d/30-session.conf"
  printf 'keep me\n' > "${SB}/units/hdw4s-proxy@bob.service.d/30-session.conf"
  # A drop-in from before the BindsTo fix. An upgrade has to correct it, because
  # nothing else rewrites the file -- "hdw4s enable" is not re-run on a machine
  # that is already enabled, so skipping it would leave every existing
  # installation with a relay that outlives its session.
  printf '%s\n' '[Unit]' 'Requires=hdw4s@eve.service' 'After=hdw4s@eve.service' \
    > "${SB}/units/hdw4s-proxy@eve.service.d/30-session.conf"
  # THE PORT DROP-IN AN EARLIER "hdw4s enable" WROTE. It replaces the relay's
  # ExecStart= with a loopback port, so an upgrade that left it would put the
  # relay back on the squattable shape with nothing to show it. One that is NOT
  # ours -- an upstream that is not a loopback port -- is somebody's decision and
  # stays. The instance file's HDW4S_PORT goes; its other lines do not.
  printf '%s\n' '# Written by "hdw4s enable".' '[Service]' 'ExecStart=' \
                 'ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:7364' \
    > "${SB}/units/hdw4s-proxy@alice.service.d/50-port.conf"
  printf '%s\n' '[Service]' 'ExecStart=' \
                 'ExecStart=/usr/lib/systemd/systemd-socket-proxyd /srv/elsewhere.sock' \
    > "${SB}/units/hdw4s-proxy@gwen.service.d/50-port.conf"
  printf '%s\n' 'HDW4S_IDLE_DAYS=3' 'HDW4S_PORT=7364' > "${SB}/etc/hdw4s/alice.conf"
  blk="$(pick "${ROOT}/debian/postinst")"
  # Stubbed because the shipped block calls it; reached only through the eval.
  # shellcheck disable=SC2317
  systemctl() { :; }
  ( ETCDIR="${SB}/etc/hdw4s" UNITDIR="${SB}/units"; eval "${blk}" )
  if [ ! -e "${SB}/units/hdw4s-proxy@alice.service.d/50-port.conf" ]; then
    ok 'a relay drop-in naming a loopback port is removed'
  else
    bad 'a relay drop-in naming a loopback port is removed' 'still there'
  fi
  if [ -e "${SB}/units/hdw4s-proxy@gwen.service.d/50-port.conf" ]; then
    ok 'one naming anything else is left alone'
  else
    bad 'one naming anything else is left alone' 'removed'
  fi
  is 'the instance file loses HDW4S_PORT' \
     "$(grep -c '^HDW4S_PORT=' "${SB}/etc/hdw4s/alice.conf")" '0'
  is 'and keeps its other settings' \
     "$(grep -c '^HDW4S_IDLE_DAYS=3$' "${SB}/etc/hdw4s/alice.conf")" '1'
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
    *'Requisite=hdw4s-ephemeral@dave.service'*) ok 'an ephemeral slot names the ephemeral unit';;
    *) bad 'an ephemeral slot names the ephemeral unit' 'missing or wrong';;
  esac
  # The fourth type, in the same run. The installers cannot call the CLI's
  # ephemeral_shaped() -- they may be repairing a tree whose hdw4s does not run
  # yet -- so they carry their own copy of the list, and this is what keeps the
  # copy honest. A template row on the default arm got BindsTo=hdw4s@tmpl,
  # which never starts an authoring session: the relay listens and every start
  # fails on the dependency, with the front door still accepting.
  case "$(cat "${SB}/units/hdw4s-proxy@tmpl.service.d/30-session.conf" 2>/dev/null)" in
    *'Requisite=hdw4s-ephemeral@tmpl.service'*) ok 'and so does the template slot';;
    *) bad 'and so does the template slot' 'missing or wrong';;
  esac
  case "$(cat "${SB}/units/hdw4s-proxy@eve.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo=hdw4s@eve.service'*) ok 'an old Requires= drop-in is migrated';;
    *) bad 'an old Requires= drop-in is migrated' 'not migrated';;
  esac
  case "$(cat "${SB}/units/hdw4s-proxy@fred.service.d/30-session.conf" 2>/dev/null)" in
    *'BindsTo='*) bad 'a pool slot bound to its session is migrated to Requisite=' \
                  'still BindsTo=: every connection can start a desktop';;
    *'Requisite=hdw4s-ephemeral@fred.service'*)
                  ok 'a pool slot bound to its session is migrated to Requisite=';;
    *) bad 'a pool slot bound to its session is migrated to Requisite=' 'missing or wrong';;
  esac
  is 'a named desktop keeps its BindsTo=' \
     "$(grep -c '^BindsTo=hdw4s@gwen.service' "${SB}/units/hdw4s-proxy@gwen.service.d/30-session.conf")" '1'
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

echo '== the fresh-mint marker is spelled the same in the router and the page =='
# THE ONE RULE WITH TWO HOMES IN THIS TREE, and it is here because it has to be.
# Dropping the owner's second click works by hdw4s-demux writing a cookie beside the
# redirect and hdw4s-gate-index reading it on the page that lands. Neither file can
# import the other -- one is python run as a service, the other generates a document --
# so the name is written twice, and two spellings of one name is two names the moment
# either is edited.
#
# The failure it catches is SILENT IN THE SAFE-LOOKING DIRECTION: a renamed cookie means
# the page never finds a marker, so the card comes back and every check in this tier
# stays green. The owner would simply be clicking twice again, which is exactly the
# report that started this.
#
# WHAT THIS CANNOT SEE, said plainly: whether the page does the right thing with the
# marker it finds. That is asserted against a running router in .github/live/demux.py
# (test_a_desktop_just_MINTED_is_marked_and_a_resumed_one_is_not, with its red arm).
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" >/dev/null 2>&1

  # DERIVED FROM THE ROUTER, never typed here: a literal in this file would be a third
  # home for the name and would agree with neither when somebody renames it.
  name="$(sed -n 's/^FRESH_COOKIE = "\(.*\)"$/\1/p' "${ROOT}/hdw4s-demux")"
  # The positive control for the derivation itself. An empty name makes every "has"
  # below match anything, so a broken sed would report the two files agreeing.
  case "${name}" in
    '') bad 'the router names the marker' 'FRESH_COOKIE was not found in hdw4s-demux' ;;
    *)  ok  'the router names the marker' ;;
  esac

  # EVERY SITE, counted rather than eyeballed. There are exactly four -- the front
  # door's mint, the directory's create, the directory's Resume, and the press on
  # a template invite (a single-use link the administrator was handed, minting
  # the authoring desktop nobody else is in) -- and a marker attached at fewer
  # brings the second click back on whichever path was missed, with nothing going
  # red; one attached at MORE is a silent connect somewhere nobody asked for.
  sites="$(grep -c 'asked_marker_header(' "${ROOT}/hdw4s-demux")"
  is 'the router attaches it at its four sites (and defines it once)' \
    "${sites}" '5'
  has 'the page reads the same name' "$(cat "${d}/out.html")" "'${name}'"
  # And it is read from the address the page is serving rather than taken on trust, so
  # it cannot authorise an arrival at a desktop somebody else may be watching.
  has 'the page checks the marker against its own address' \
    "$(cat "${d}/out.html")" 'location.pathname'
  # And consumed. Without this the one-shot is a standing permission.
  has 'the page deletes the marker before connecting' \
    "$(cat "${d}/out.html")" 'Max-Age=0'
  # NOT HttpOnly, because its only reader is script. Asserted on the router, where the
  # header is composed: a marker the page cannot read brings the card back silently.
  hasnt 'the marker is not hidden from the page' \
    "$(sed -n '/^def asked_marker_header/,/^$/p' "${ROOT}/hdw4s-demux")" 'HttpOnly'
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

echo '== the stall backstop does not read a deliberately stopped stream as a loss =='
# THE DEFECT, from the owner on a live desktop with his own console log as the
# evidence: the reconnect card appeared ON THE LIVE PAGE WITH NO RELOAD, and the log
# read "Tab hidden: Sent STOP_VIDEO". Hiding a tab makes the client stop the stream, and
# the backstop read ten quiet seconds as a disconnection. Its two existing guards are
# about a viewer that never receives video and about video that has not started; the
# state where video is working and was PAUSED ON PURPOSE had no guard.
#
# WHAT THIS TESTS AND WHAT IT DOES NOT. It tests that the page refuses to be built when
# the question stops being asked, or is asked too late, or cannot be found. It does NOT
# test that streamPaused() answers correctly -- that needs a browser, a hidden tab and
# more than ten seconds, and it is recorded as unmeasured with its experiment named in
# private/create-evidence/README.md rather than asserted here.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"

  # The positive control FIRST, so the three refusals below are known to refuse the
  # thing under test rather than the input.
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" >/dev/null 2>"${d}/err" \
    && has 'the shipped backstop asks before it counts' "$(cat "${d}/out.html")" \
       'streamPaused()' \
    || bad 'the shipped backstop asks before it counts' \
       "the generator refused a good page: $(cat "${d}/err")"

  redb() { python3 "$1" "${d}/in.html" "${d}/redout.html" >/dev/null 2>"${d}/rederr"; }

  # 1. The question deleted -- which is what a tidy-up of an odd-looking early return
  #    looks like in a diff, and it is the exact shape that shipped the defect.
  rm -f "${d}/redout.html"
  sed 's|if (streamPaused()) { still = 0; last = -1; return; }|// tidied away|' \
    "${ROOT}/hdw4s-gate-index" > "${d}/red1"
  redb "${d}/red1" \
    && bad 'a backstop that stopped asking is refused' 'it was accepted' \
    || has 'a backstop that stopped asking is refused' "$(cat "${d}/rederr")" \
       'STOPPED the stream before counting'
  hasnt 'a refused backstop writes no page' "$(ls "${d}")" 'redout.html'

  # 2. The question asked AFTER the count, which reads as a fix and is not one: the
  #    card is already up by the time the counter is reset.
  rm -f "${d}/redout.html"
  sed -e 's|    if (streamPaused()) { still = 0; last = -1; return; }||' \
      -e "s|    if (everMoved \&\& still >= 20) lost('stalled');.*|    if (everMoved \&\& still >= 20) lost('stalled');\n    if (streamPaused()) { still = 0; }|" \
    "${ROOT}/hdw4s-gate-index" > "${d}/red2"
  redb "${d}/red2" \
    && bad 'a backstop that asks too late is refused' 'it was accepted' \
    || has 'a backstop that asks too late is refused' "$(cat "${d}/rederr")" \
       'counts before it asks'

  # 3. THE ARM THAT MATTERS MOST: the guard cannot pass by failing to find its subject.
  #    A guard whose search silently stops matching reports a clean bill of health
  #    forever, which is this project's commonest defect rather than a hypothetical.
  rm -f "${d}/redout.html"
  sed 's|}, 500);|}, 501);|' "${ROOT}/hdw4s-gate-index" > "${d}/red3"
  redb "${d}/red3" \
    && bad 'a backstop the guard cannot find is refused' 'it was accepted' \
    || has 'a backstop the guard cannot find is refused' "$(cat "${d}/rederr")" \
       'could not be found'
)

echo '== the starting veil keeps every way out it claims to have =='
# THE DEFECT, reported by the owner 2026-09-26: "frequently, i just get a black
# streaming desktop. if i discard and retry, it eventually works. meanwhile, other
# sessions continue working fine. so, this is only a problem at startup".
#
# MEASURED the same day on a development box, through the real proxy hostname in a real browser
# across four runs including three concurrent mints: the streamed picture was at ONE
# distinct colour at the moment of hand-over EVERY time, and climbed to 2114-3161
# colours nine to eleven seconds later with nothing discarded or restarted. From the
# other end, a slot whose X root read one colour was painted twenty minutes later
# having never been touched. The session reports READY when the streaming server binds
# its port, about a second into a start whose desktop needs another nine -- or far
# longer on a loaded box. Nothing was broken; the visitor was handed the desktop before
# it existed to look at.
#
# The veil that now covers that gap is a FULL-SCREEN overlay, so what these arms are
# about is its three ways out. Each is a line that reads as defensive clutter, none is
# exercised by any browser test here, and losing one puts a visitor behind a reassuring
# sentence with either a working desktop or a permanently black one underneath.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s\n' '<html><body><script type="module" src="/x.js"></script></body></html>' \
    > "${d}/in.html"

  # THE POSITIVE CONTROL FIRST, so the four refusals below are known to refuse the
  # thing under test rather than the input.
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" >/dev/null 2>"${d}/err" \
    && has 'the shipped veil is built' "$(cat "${d}/out.html")" 'hdw4s-starting' \
    || bad 'the shipped veil is built' \
       "the generator refused a good page: $(cat "${d}/err")"
  has 'the shipped veil reveals when it cannot sample' \
    "$(cat "${d}/out.html")" 'cannot sample the picture'
  # A veil that swallowed the pointer would turn a cosmetic failure into a locked-out
  # visitor, and the property is one CSS declaration nothing else would notice.
  has 'the shipped veil never swallows the pointer' \
    "$(cat "${d}/out.html")" 'pointer-events:none'
  # THE OWNER'S REQUEST, 2026-09-26: *"it makes the product feel slow, if it comes up,
  # stays for 1 or 2 seconds and then disappears ... suppress the interstitial for a
  # short while."* The number is his decision to change; that there IS a suppression
  # is the request, and it is one line somebody tidying up would not miss.
  has 'the shipped veil suppresses the card at first' \
    "$(cat "${d}/out.html")" 'VEIL_SUPPRESS'
  # AND THE CLOCK NO LONGER REVEALS. This is the defect being repaired rather than a
  # new property: with a 90s clock and an 89s healthy start, the old exit tore the card
  # away one second before the desktop arrived. The sentence it used to log is the
  # cheapest evidence that the behaviour is gone.
  hasnt 'the clock no longer reveals a black desktop' \
    "$(cat "${d}/out.html")" 'revealing anyway'
  has 'the clock stops the card PROMISING instead' \
    "$(cat "${d}/out.html")" 'stops promising'

  redv() { python3 "$1" "${d}/in.html" "${d}/redout.html" >/dev/null 2>"${d}/rederr"; }

  # 1. The cannot-sample exit removed. This is the dangerous one: it looks like dead
  #    code, because on a working build paintedColours() always returns a number.
  rm -f "${d}/redout.html"
  sed "s|if (n === null) { stop('cannot sample the picture; revealing'); return; }|// tidied away|" \
    "${ROOT}/hdw4s-gate-index" > "${d}/redv1"
  redv "${d}/redv1" \
    && bad 'a veil that cannot fail open is refused' 'it was accepted' \
    || has 'a veil that cannot fail open is refused' "$(cat "${d}/rederr")" \
       'CANNOT SAMPLE'
  hasnt 'a refused veil writes no page' "$(ls "${d}")" 'redout.html'

  # 2. The clock removed. A wedged compositor is black for the life of the session, so
  #    without this the card goes on saying "it is coming up now" for ever -- which is
  #    a permanent reassuring message nobody would report. NOTE WHAT CHANGED HERE,
  #    2026-09-26: the clock used to REVEAL the desktop, and the threshold was 90s
  #    against a measured healthy cold start of 89.0s on the production box. It now
  #    changes the card's WORDS instead, which is why the arm's needle moved.
  rm -f "${d}/redout.html"
  sed 's|if (!gaveUp && Date.now() - t0 >= patience) {|if (false) {|' \
    "${ROOT}/hdw4s-gate-index" > "${d}/redv2"
  redv "${d}/redv2" \
    && bad 'a veil that waits forever is refused' 'it was accepted' \
    || has 'a veil that waits forever is refused' "$(cat "${d}/rederr")" \
       'gives up on a clock'

  # 3. The paused-stream question removed -- the same repair the stall backstop above
  #    already needed, and the same way of losing it.
  rm -f "${d}/redout.html"
  # THE ANCHOR MOVED ONCE, 2026-09-26, and this arm is why that was noticed. The
  # guarded line gained a body -- it now re-arms the card's suppression window
  # before returning, so that being unable to sample cannot itself guarantee the
  # card. The sed above matched a literal that no longer existed, mutated
  # nothing, and the unmutated page was accepted: the exact shape arm 5 below
  # exists to catch, arriving in arm 3. When that line changes again, change this
  # with it, and check the mutation still REMOVES the question rather than merely
  # failing to match.
  sed "s|      if (document.visibilityState === 'hidden' \|\| streamPaused()) { armCard(); return; }|      if (false) { armCard(); return; }|" \
    "${ROOT}/hdw4s-gate-index" > "${d}/redv3"
  redv "${d}/redv3" \
    && bad 'a veil that counts a stopped stream is refused' 'it was accepted' \
    || has 'a veil that counts a stopped stream is refused' "$(cat "${d}/rederr")" \
       'stopped on purpose'

  # 4. The two not-a-number cases collapsed back into one. This is the defect the
  #    repair itself shipped with and it was invisible to every assertion: the veil
  #    flashed under a second and the visitor got the black screen anyway.
  rm -f "${d}/redout.html"
  # BOTH occurrences, because removing one leaves the distinction intact and the guard
  # is right to accept that. The defect is collapsing the third outcome away entirely.
  sed "s|return 'waiting';|return null;|g" \
    "${ROOT}/hdw4s-gate-index" > "${d}/redv5"
  redv "${d}/redv5" \
    && bad 'a veil that cannot wait for the canvas is refused' 'it was accepted' \
    || has 'a veil that cannot wait for the canvas is refused' "$(cat "${d}/rederr")" \
       'has not made its surface yet'

  # 5. THE ARM THAT MATTERS MOST: the guard must not pass by failing to find its
  #    subject. A search that silently stops matching reports health forever.
  rm -f "${d}/redout.html"
  sed 's|function veilUp()|function veilRaise()|' \
    "${ROOT}/hdw4s-gate-index" > "${d}/redv4"
  redv "${d}/redv4" \
    && bad "a veil the guard cannot find is refused" 'it was accepted' \
    || has "a veil the guard cannot find is refused" "$(cat "${d}/rederr")" \
       'could not be found'
)

echo '== a page whose own session is gone leaves for the ended page =='
# THE DEFECT, measured on production 2026-09-27 after a restart of the router: every
# path under the owner's session was answered 410, this page read the 410 on its own
# identity as "nothing published", showed the card, and on the click loaded a client
# script that was answered 410 too -- so the starting veil said "Your desktop is
# starting" for ever. The console showed the 410s; nothing on the page acted on them.
#
# WHAT IS REAL AND WHAT IS STOOD IN FOR. Real: the two functions the page runs, cut
# out of the page the generator WRITES rather than out of its template. Stood in for:
# the browser -- fetch() is a promise that answers one status, location is an object
# that records replace(). Nothing here shows a browser navigating; the ended page
# itself is the router's, and the router suite asserts what it answers.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  if ! command -v node >/dev/null; then
    bad 'the page-script tests can run' 'node is needed to run the page script'
    exit 0
  fi
  # Runs the page's fetchIncarnation() against one answer. Prints what the page
  # was handed and where, if anywhere, it went.
  page_meets() {
    rm -f "${d}/out.html"
    python3 "${2:-${ROOT}/hdw4s-gate-index}" "${d}/in.html" "${d}/out.html" >/dev/null 2>&1 \
      || { echo 'the generator refused the page'; return; }
    python3 - "${d}/out.html" > "${d}/fns.js" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
out = []
for name in ("ended", "fetchIncarnation"):
    m = re.search(r"\n  function %s\(.*?\n  \}\n" % name, html, re.S)
    if m:
        out.append(m.group(0))
m = re.search(r"\n  var endedGoing = false;\n", html)
if m:
    out.insert(0, m.group(0))
print("".join(out))
PY
    node - "${d}/fns.js" "$1" <<'JS'
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const status = Number(process.argv[3]);
let went = 'nowhere';
const location = {pathname: '/s/abc/', replace: u => { went = u; }};
const fetch = () => Promise.resolve({status, ok: status >= 200 && status < 300,
                                     text: () => Promise.resolve('tok')});
const setTimeout = () => 0;
const console = {log: () => {}};
if (!/function fetchIncarnation/.test(src)) { console.log(); process.stdout.write('no fetchIncarnation in the page'); process.exit(0); }
const f = new Function('fetch', 'location', 'setTimeout', 'console',
                       src + '\nreturn fetchIncarnation;')(fetch, location, setTimeout, console);
f(v => setImmediate(() => process.stdout.write('got=' + v + ' went=' + went)));
JS
  }

  # THE CONTROL FIRST: a published identity is read and nothing navigates, so the
  # stand-in can be seen handing the page an answer.
  is 'a published identity is read, and the page stays' "$(page_meets 200)" 'got=tok went=nowhere'
  # THE DEFECT.
  is 'a 410 on its own session sends the page to the ended page' \
    "$(page_meets 410)" 'got=null went=/s/abc/?hdw4s_ended=1'
  # THE PERMIT ARM: any other failure is still only "no identity", which gates.
  is 'a 404 is still only a missing identity' "$(page_meets 404)" 'got=null went=nowhere'

  # RED ARM: the page as it was, reading a 410 as a missing file, must stay put.
  sed 's/if (r.status === 410) { ended(); return once(null); }//' \
    "${ROOT}/hdw4s-gate-index" > "${d}/red"
  if cmp -s "${ROOT}/hdw4s-gate-index" "${d}/red"; then
    bad 'the red arm mutates the page' 'the sed matched nothing'
  else
    is 'a page that ignores the 410 stays on a dead desktop' \
      "$(page_meets 410 "${d}/red")" 'got=null went=nowhere'
  fi
)

echo '== the page fits the desktop to its tab only after a start that is known to be over =='
# THE PROBLEM: a first start often shows the desktop at the wrong size until the
# visitor resizes the window. THE RULE, the owner's: resize only when the startup
# hold ended on the desktop's own end-of-startup signal; never after a fallback
# release; unknown means no resize ("first, do no harm" -- a resize inside GNOME 46's
# startup can leave the desktop black, a wrong size cannot).
#
# Run on the functions the generator WRITES. Stood in for: the browser -- fetch() is a
# promise with one status and one body, postMessage records what it was asked to send.
# Nothing here shows the streaming client acting on the message, nor a screen
# changing size; that needs a real desktop and a real browser.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  if ! command -v node >/dev/null; then
    bad 'the page-script tests can run' 'node is needed to run the page script'
    exit 0
  fi
  # One page, one answer from the server. Prints what the page posted, if anything.
  #   $1 status  $2 body  $3 extra setup (JS)  $4 generator (default: the real one)
  fits() {
    rm -f "${d}/out.html"
    python3 "${4:-${ROOT}/hdw4s-gate-index}" "${d}/in.html" "${d}/out.html" >/dev/null 2>&1 \
      || { echo 'the generator refused the page'; return; }
    python3 - "${d}/out.html" > "${d}/fns.js" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
out = []
for pat in (r"\n  var OUTCOME = .*?;\n", r"\n  var fitAsked = false;\n",
            r"\n  function fetchOutcome\(.*?\n  \}\n", r"\n  function fitAfterStart\(.*?\n  \}\n"):
    m = re.search(pat, html, re.S)
    if m:
        out.append(m.group(0))
print("".join(out))
PY
    node - "${d}/fns.js" "$1" "$2" "${3:-}" <<'JS'
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const status = Number(process.argv[3]), body = process.argv[4], setup = process.argv[5];
if (!/function fitAfterStart/.test(src)) { process.stdout.write('no fitAfterStart in the page'); process.exit(0); }
const posted = [];
let asked = '';
const window = {postMessage: (m, o) => posted.push(m.type + '@' + o)};
const location = {origin: 'https://door.example'};
const fetch = (u) => { asked = u; return status < 0 ? Promise.reject(new Error('net'))
  : Promise.resolve({status, ok: status >= 200 && status < 300, text: () => Promise.resolve(body)}); };
const setTimeout = () => 0;
const console = {log: () => {}};
let SECONDARY = false;
eval(setup);
const f = new Function('fetch', 'location', 'setTimeout', 'console', 'window', 'SECONDARY',
                       src + '\nreturn fitAfterStart;')(fetch, location, setTimeout, console, window, SECONDARY);
f(); f();
setTimeout; setImmediate(() => setImmediate(() =>
  process.stdout.write('posted=[' + posted.join(',') + '] asked=' + asked)));
JS
  }

  # THE POSITIVE CONTROL, and the problem itself: a real release fits, once, through
  # the client's own message and to the page's own origin.
  is 'a start released on the real end-of-startup mark fits the desktop, once' \
    "$(fits 200 $'started\n')" \
    'posted=[resetResolutionToWindow@https://door.example] asked=hdw4s-startup/outcome'
  # EVERY FALLBACK, AND EVERY WAY OF NOT KNOWING, DOES NOT.
  for w in bound none deadline off unknown '' 'Started' 'started now'; do
    is "the outcome [${w}] does not resize" "$(fits 200 "${w}")" \
      'posted=[] asked=hdw4s-startup/outcome'
  done
  is 'a missing outcome (404) does not resize' "$(fits 404 'started')" \
    'posted=[] asked=hdw4s-startup/outcome'
  is 'a failed fetch does not resize' "$(fits -1 '')" 'posted=[] asked=hdw4s-startup/outcome'
  # The visitor's own choice, and the pages that do not own the size.
  is 'a manual resolution (websockets client) is left alone' \
    "$(fits 200 started 'window.manual_resolution = true;')" \
    'posted=[] asked=hdw4s-startup/outcome'
  is 'a manual resolution (webrtc client) is left alone' \
    "$(fits 200 started 'window.manualResolution = true;')" \
    'posted=[] asked=hdw4s-startup/outcome'
  is 'a secondary page never asks' "$(fits 200 started 'SECONDARY = true;')" 'posted=[] asked='

  # RED ARM: a page that resizes on anything it is told must be caught resizing
  # after a fallback release. Seen red here, or the arms above prove nothing.
  sed "s/if (word !== 'started') {/if (word === null) {/" \
    "${ROOT}/hdw4s-gate-index" > "${d}/red"
  if cmp -s "${ROOT}/hdw4s-gate-index" "${d}/red"; then
    bad 'the red arm mutates the page' 'the sed matched nothing'
  else
    is 'RED ARM: a page that ignores the outcome resizes after the 18 s fallback' \
      "$(fits 200 bound '' "${d}/red")" \
      'posted=[resetResolutionToWindow@https://door.example] asked=hdw4s-startup/outcome'
  fi
  # And the page is asked to do it at all: only the paint may trigger it.
  n="$(grep -c 'fitAfterStart();' "${ROOT}/hdw4s-gate-index" || :)"
  is 'the fit is asked for in exactly one place' "${n}" '1'
  paint="$(sed -n "/stop('desktop painted/,/return;/p" "${ROOT}/hdw4s-gate-index")"
  has 'and that place is the veil seeing the desktop painted' "${paint}" 'fitAfterStart();'
)

echo '== the boot card offers the session directory only where a door serves one =='
# THE DEFECT, reported by the owner 2026-09-25: "named sessions now have a link to where
# the user can see all their sessions ... and that link doesn't work."
#
# It did not work and it could not have. /sessions/ is a route of hdw4s-demux, the
# EPHEMERAL front door. A named desktop is reached reverse proxy ->
# hdw4s-proxy@<inst>.socket -> systemd-socket-proxyd -> Selkies' own aiohttp server, and
# nothing of ours is anywhere in that path. Measured through a named session's own front door: GET / -> 200 with the gate marker and the words "Your
# desktops" (the positive control, so the empty answer below is about the path and not
# about a rig that could not reach the box), GET /sessions/ -> 404, zero-length body,
# "Server: Python/3.12 aiohttp/3.14.3". A blank page.
#
# WHAT THIS TESTS: that the link is absent by default, present when the builder says the
# door serves one, and that the generator REFUSES a page whose offer and whose flag
# disagree. What it cannot test is whether the flag is TRUE of the real door -- that
# claim lives with the two callers and is checked by eye, once, in each.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"

  # DEFAULT FIRST, because the default is the safety property: a caller that says
  # nothing must get no link. This is the named desktop's case, and it is the one that
  # shipped broken.
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/plain.html" >/dev/null 2>"${d}/err" \
    || bad 'a card with no directory builds' "the generator refused: $(cat "${d}/err")"
  hasnt 'a door with no session directory offers no link to one' \
    "$(cat "${d}/plain.html")" '/sessions/'
  hasnt 'and the words are not in the document either, hidden or otherwise' \
    "$(cat "${d}/plain.html")" 'Your desktops'
  # The positive control for the two assertions above: the same search, on a page that
  # DOES carry the link, must find it. Without this, a typo in the needle would report
  # a clean pass on every page forever.
  HDW4S_DIRECTORY=yes "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/dir.html" \
    >/dev/null 2>"${d}/err2" \
    || bad 'a card with a directory builds' "the generator refused: $(cat "${d}/err2")"
  has 'a door that serves the directory does offer the link' \
    "$(cat "${d}/dir.html")" 'href="/sessions/"'
  has 'and it is the outlined button on Connect'"'"'s row' \
    "$(cat "${d}/dir.html")" 'id="hdw4s-more"'

  # A value that is neither arm is REFUSED, not clamped. "no" is the safe branch, so a
  # typo quietly taking it would hide a caller that meant to say yes and did not --
  # the page would be right by accident on the pool and nobody would know the flag had
  # stopped being read.
  HDW4S_DIRECTORY=true "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/bad.html" \
    >/dev/null 2>"${d}/err3" \
    && bad 'a misspelled HDW4S_DIRECTORY is refused' 'it was accepted' \
    || has 'a misspelled HDW4S_DIRECTORY is refused' "$(cat "${d}/err3")" \
       'is not one of no/yes'
  hasnt 'a refused value writes no page' "$(ls "${d}")" 'bad.html'

  # THE ARM THAT MATTERS: the link put back into the static markup by hand. That is not
  # a hypothetical edit -- it is what "tidying away" a placeholder and an empty string
  # looks like to somebody who does not know why the condition is there, and it puts
  # the 404 back on every named desktop while changing nothing any other test reads.
  rm -f "${d}/redout.html"
  sed 's|^__MORE__$|  <p id="hdw4s-more"><a href="/sessions/">Your desktops</a></p>|' \
    "${ROOT}/hdw4s-gate-index" > "${d}/red"
  python3 "${d}/red" "${d}/in.html" "${d}/redout.html" >/dev/null 2>"${d}/rederr" \
    && bad 'a card that offers a directory its door lacks is refused' 'it was accepted' \
    || has 'a card that offers a directory its door lacks is refused' \
       "$(cat "${d}/rederr")" 'cannot serve'
  hasnt 'and no page is written' "$(ls "${d}")" 'redout.html'

  # The other direction, which is the one a guard usually cannot do: told the door
  # serves a directory, and emitting no link. A caller whose flag stopped being read
  # would look exactly like this, and a page that silently drops the way out of the
  # card is a rescue path quietly removed.
  rm -f "${d}/redout2.html"
  sed 's|^__MORE__$||' "${ROOT}/hdw4s-gate-index" > "${d}/red2"
  HDW4S_DIRECTORY=yes python3 "${d}/red2" "${d}/in.html" "${d}/redout2.html" \
    >/dev/null 2>"${d}/rederr2" \
    && bad 'a card that drops a directory its door serves is refused' 'it was accepted' \
    || has 'a card that drops a directory its door serves is refused' \
       "$(cat "${d}/rederr2")" 'carries no link'
)

echo '== a desktop is never named after its slot, and a browser numbers its own =='
# THE DEFECT, 2026-09-27, three novices of three: a pool desktop was named after its
# SLOT ("19 . Desktop"), a slot is reused, and a visitor told "everything that was in
# it is gone" was handed a new desktop called "19" and doubted the word "gone". The
# owner's ruling: a small per-browser number -- the lowest this browser is not using
# and has not used in fifteen minutes -- plus an optional name of the visitor's own,
# both in browser storage. hdw4s-names.js is that rule; .github/names-test.js drives
# it with no browser, and the arms below make both halves go red once.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  # (1) THE MINTER'S LABEL, which is the text every page shows with no script. Its
  # slot loop is run as written, with the pool's arithmetic supplied, and every label
  # it produces must be free of digits. A loop that produced nothing would pass that,
  # so the number of rows is asserted first.
  labels() {
    ( HDW4S_EPHEMERAL_SLOTS=20 HDW4S_EPHEMERAL_PREFIX=ephemeral HDW4S_EPHEMERAL_UID_BASE=900
      eval "$(sed -n "/^  SLOT_SPECS=''\$/,/^  done\$/p" "$1")"
      printf '%s' "${SLOT_SPECS}" | cut -f3 )
  }
  got="$(labels "${ROOT}/hdw4s-ephemeral-slots")"
  is 'the slot loop was found and labels all twenty slots' \
    "$(printf '%s\n' "${got}" | grep -c .)" '20'
  is 'and no label carries a number' "$(printf '%s\n' "${got}" | grep -c '[0-9]' || :)" '0'
  # The old label, put back verbatim: its $(( )) is the minter's, not ours to expand.
  # shellcheck disable=SC2016
  sed 's|^      '"'"'Desktop'"'"')$|      "$(( i + 1 )) · Desktop")|' \
    "${ROOT}/hdw4s-ephemeral-slots" > "${d}/red-minter"
  is 'RED ARM: the old slot-numbered label is caught' \
    "$(labels "${d}/red-minter" | grep -c '[0-9]' || :)" '20'

  # (2) THE ALLOCATION, and its two red arms: no decay window, and a count that does
  # not start at the lowest number. Each must turn the suite red, or the suite is
  # not watching what it names.
  if ! command -v node >/dev/null; then
    bad 'the page-script tests can run' 'node is needed for .github/names-test.js'
    bad 'RED ARM: a number reused inside fifteen minutes is caught' 'node missing'
    bad 'RED ARM: a count that skips the lowest free number is caught' 'node missing'
  else
    out="$(node "${ROOT}/.github/names-test.js" 2>&1)" && rc=0 || rc=$?
    is 'the per-browser numbering behaves as ruled' "${rc}" '0'
    [ "${rc}" -eq 0 ] || printf '%s\n' "${out}"
    sed 's|^  var WINDOW_MS = 15 \* 60 \* 1000;|  var WINDOW_MS = 0;|' \
      "${ROOT}/hdw4s-names.js" > "${d}/red1.js"
    has 'RED ARM: a number reused inside fifteen minutes is caught' \
      "$(node "${ROOT}/.github/names-test.js" "${d}/red1.js" 2>&1 || :)" \
      'FAIL an ended desktop keeps its number out of use'
    sed 's|^    var n = 1;$|    var n = 2;|' "${ROOT}/hdw4s-names.js" > "${d}/red2.js"
    has 'RED ARM: a count that skips the lowest free number is caught' \
      "$(node "${ROOT}/.github/names-test.js" "${d}/red2.js" 2>&1 || :)" \
      'FAIL the first desktop is 1'
  fi
  # A name is text a person typed; the script may only ever set it as text.
  is 'the names script never writes markup' \
    "$(grep -cE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write' "${ROOT}/hdw4s-names.js" || :)" '0'

  # (3) BOTH READERS CARRY IT, and only where the door is the pool's.
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  HDW4S_DIRECTORY=yes HDW4S_SESSION_NAME=Desktop "${ROOT}/hdw4s-gate-index" \
    "${d}/in.html" "${d}/pool.html" >/dev/null 2>&1 || bad 'a pool page builds'
  has 'a pool session page names itself from this browser' \
    "$(cat "${d}/pool.html")" 'hdw4sNames.sessionPage("Desktop")'
  has 'on the card heading the script looks for' "$(cat "${d}/pool.html")" 'id="hdw4s-name"'
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/named.html" >/dev/null 2>&1 \
    || bad 'a named page builds'
  hasnt 'a named desktop keeps its administrator'"'"'s name, no script' \
    "$(cat "${d}/named.html")" 'hdw4sNames'
  hasnt 'the in-page starting card guesses no cause' "$(cat "${d}/pool.html")" 'busy machine'

  pages="$(python3 - "${ROOT}/hdw4s-demux" <<'PY'
import importlib.machinery, importlib.util, sys
sys.dont_write_bytecode = True
l = importlib.machinery.SourceFileLoader("demux", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("demux", l))
l.exec_module(m)
row = dict(sid="ab" * 16, name=None, age=60, memory_mb=10, pids=3, started=True,
           discarding=False, idle_window=3600)
for name, body in (("dir", m.console_page([row])), ("ended", m.ended_page([row], True)),
                   ("full", m.create_refused_page([row], 4)),
                   ("starting", m.starting_page())):
    print("%s\t%s" % (name, body.decode().replace("\n", " ")))
PY
)"
  for p in dir ended full; do
    b="$(printf '%s\n' "${pages}" | sed -n "s/^${p}\t//p")"
    has "the ${p} page names its row by session, for the script" "${b}" \
      "data-hdw4s-sid=\"$(printf 'ab%.0s' $(seq 16))\">Desktop</div>"
    has "and runs the names script" "${b}" 'hdw4sNames.directory()'
  done
  # (4) A NAME THAT CAN BE RENAMED SAYS SO UNDER THE POINTER. The owner, 2026-09-27:
  # the rounded outline "only happens after an edit has succeeded. it should also
  # happen before doing the first edit ... as they move the mouse pointer over the
  # list". What he saw was the browser's focus ring, drawn because the script
  # refocuses the name after Enter; hover drew only a dotted underline. So the rule
  # asserted is the stylesheet's, per state: hover and keyboard focus outline the
  # name, and at rest nothing does (he asked for a hint, not a box on every row).
  css="$(python3 - "${ROOT}/hdw4s-demux" <<'PY'
import importlib.machinery, importlib.util, re, sys
sys.dont_write_bytecode = True
l = importlib.machinery.SourceFileLoader("demux", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("demux", l))
l.exec_module(m)
for sels, decls in re.findall(r"([^{}]+)\{([^{}]*)\}", m.PAGE_CSS):
    for s in sels.split(","):
        print("%s\t%s" % (s.strip(), decls))
PY
)"
  rule() { printf '%s\n' "${css}" | sed -n "s/^$1\t//p"; }
  has 'the stylesheet was read (control: .renamable has its cursor)' \
    "$(rule '\.renamable')" 'cursor:text'
  has 'hovering a renamable name outlines it' "$(rule '\.renamable:hover')" 'outline'
  has 'keyboard focus on a renamable name outlines it' \
    "$(rule '\.renamable:focus-visible')" 'outline'
  hasnt 'and at rest the outline is not drawn' "$(rule '\.renamable')" 'solid #'

  b="$(printf '%s\n' "${pages}" | sed -n 's/^starting\t//p')"
  hasnt 'the starting page guesses no cause' "${b}" 'busy'
  has 'the starting page is on the shared card' "${b}" '<div class="card">'
  has 'and shows a sign of life' "${b}" 'class="alive"'
)

echo '== the tab strip never names upstream, and says when a tab is idle =='
# THE DEFECT, the owner, 2026-09-27: a background tab the client had reloaded to
# recover read "Selkies" -- a word the people using this never otherwise see, for a
# product they do not know is there -- and "knowing that a tab is idle is useful, but
# the title should stay". Upstream's page is titled with that word and a page held
# behind the gate never loads the client that would replace it; and when the client
# does load it writes the word itself and only then asks the manifest. MEASURED in a
# real browser against the tree before this (.github/live/tab_title.py): a named card
# read "Selkies" for as long as it stood, and a pool page whose manifest could not be
# fetched ended on "Selkies" after its own name. Both kinds are asserted: the named
# one is where nothing replaced it at all.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  cat > "${d}/in.html" <<'HTML'
<!doctype html><html><head><meta charset="UTF-8" /><title>Selkies</title>
<link rel="manifest" href="manifest.json"><link rel="icon" href="icon.png" />
<script type="module" crossorigin src="./assets/x.js"></script></head>
<body><div id="root"></div></body></html>
HTML
  title_of() { python3 -c 'import re,sys; print("|".join(re.findall(r"<title\b[^>]*>(.*?)</title>", open(sys.argv[1]).read(), re.S | re.I)))' "$1"; }
  HDW4S_SESSION_NAME='Desktop' "${ROOT}/hdw4s-gate-index" \
    "${d}/in.html" "${d}/named.html" >/dev/null 2>&1 || bad 'a named page builds'
  HDW4S_DIRECTORY=yes HDW4S_SESSION_NAME='Desktop' "${ROOT}/hdw4s-gate-index" \
    "${d}/in.html" "${d}/pool.html" >/dev/null 2>&1 || bad 'a pool page builds'
  HDW4S_SESSION_NAME='Mail & <b>' "${ROOT}/hdw4s-gate-index" \
    "${d}/in.html" "${d}/odd.html" >/dev/null 2>&1 || bad 'an odd name builds'
  is 'a named session page is titled with its own name, once' "$(title_of "${d}/named.html")" 'Desktop'
  is 'so is a pool one' "$(title_of "${d}/pool.html")" 'Desktop'
  is 'and a name is text, never markup' "$(title_of "${d}/odd.html")" 'Mail &amp; &lt;b&gt;'
  for k in named pool; do
    has "the ${k} page keeps its title in its head" \
      "$(sed -n '1,/<\/head>/p' "${d}/${k}.html")" 'hdw4sTitle.install("Desktop", "./assets/x.js")'
  done
  # THE GUARD, seen refusing: a generator whose rewrite no longer matches upstream's
  # title leaves the word beside ours, and must refuse rather than ship it.
  sed 's/^if _titles:$/if False:/' "${ROOT}/hdw4s-gate-index" > "${d}/red-gate"
  chmod +x "${d}/red-gate"
  HDW4S_LIBDIR="${ROOT}" "${d}/red-gate" "${d}/in.html" "${d}/red.html" > "${d}/red.err" 2>&1 \
    && rc=0 || rc=$?
  is 'RED ARM: a page still titled by upstream is refused' "${rc}" '1'
  has 'and says why' "$(cat "${d}/red.err")" 'names somebody else'"'"'s product'
  if ! command -v node >/dev/null; then
    bad 'the title keeper tests can run' 'node is needed for .github/title-test.js'
    bad 'RED ARM: a client write that stands is caught' 'node missing'
    bad 'RED ARM: an idle marker blind to the card is caught' 'node missing'
  else
    out="$(node "${ROOT}/.github/title-test.js" 2>&1)" && rc=0 || rc=$?
    is 'the title keeper behaves as ruled' "${rc}" '0'
    [ "${rc}" -eq 0 ] || printf '%s\n' "${out}"
    python3 - "${ROOT}/hdw4s-title.js" "${d}/red1.js" <<'PY'
import sys
s = open(sys.argv[1]).read()
a = s.index("    if (desc) {\n      try {\n        Object.defineProperty")
b = s.index("    function look()")
open(sys.argv[2], "w").write(s[:a] + s[b:])
PY
    has 'RED ARM: a client write that stands is caught' \
      "$(node "${ROOT}/.github/title-test.js" "${d}/red1.js" 2>&1 || :)" \
      'FAIL a foreign write lands as ours'
    sed 's|return modules.indexOf(src) >= 0 \&\& gateHidden !== false;|return modules.indexOf(src) >= 0;|' \
      "${ROOT}/hdw4s-title.js" > "${d}/red2.js"
    has 'RED ARM: an idle marker blind to the card is caught' \
      "$(node "${ROOT}/.github/title-test.js" "${d}/red2.js" 2>&1 || :)" \
      'FAIL not connected while the card is up'
  fi
)

echo '== the installed app is never named upstream, on either kind of desktop =='
# The owner, 2026-09-27: the people using this must never meet the upstream name --
# "either in the tab strip or in the pwa". An installed app is named from the web
# manifest the page LINKS, so that is the file asserted, for a named desktop
# (provisioned with no name, as hdw4s@.service does) and a pool one. The fixture
# links a RENAMED manifest: rewriting only manifest.json, as the builder used to,
# leaves the linked one saying "Selkies" in the app launcher, where nothing looks.
# The icons are asserted UNCHANGED: the one icon everywhere is upstream's, and a
# rewrite that dropped them would leave the installed app with none.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  mkdir -p "${d}/pkg" "${d}/web" "${d}/run"
  up='{"name":"Selkies","short_name":"Selkies","icons":[{"src":"icon-512.png","type":"image/png","sizes":"512x512"}],"start_url":"."}'
  printf '%s' "${up}" > "${d}/pkg/manifest.json"
  printf '%s' "${up}" > "${d}/pkg/app.webmanifest"
  : > "${d}/pkg/x.js"; : > "${d}/pkg/icon-512.png"
  page() {
    printf '<html><head><title>Selkies</title><link rel="manifest" href="%s" crossorigin="use-credentials"></head><body><script type="module" src="./x.js"></script></body></html>' \
      "$1" > "${d}/pkg/index.html"
  }
  printf '#!/bin/bash\ncat >/dev/null\necho %s\n' "${d}/pkg" > "${d}/py"
  chmod +x "${d}/py"
  run() {
    HDW4S_SELKIES_PY="${d}/py" HDW4S_LIBDIR="${ROOT}" HDW4S_WEBROOT_DIR="${d}/web" \
    HDW4S_INCARNATION_DIR="${d}/run" "${ROOT}/hdw4s-webroot" "$@" >/dev/null 2>"${d}/err"
  }
  field() { python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print("%s|%s" % (m.get("name"), m.get("short_name")) if sys.argv[2]=="name" else json.dumps(m.get("icons")))' "$1" "$2" 2>/dev/null; }

  page manifest.json
  run provision named1 || bad 'a named desktop provisions' "$(cat "${d}/err")"
  is 'a named desktop'"'"'s app is named after it' \
    "$(field "${d}/web/named1/manifest.json" name)" 'Desktop|Desktop'

  page app.webmanifest
  run provision named2 || bad 'a named desktop provisions' "$(cat "${d}/err")"
  is 'and so is the manifest its page LINKS, whatever it is called' \
    "$(field "${d}/web/named2/app.webmanifest" name)" 'Desktop|Desktop'
  is 'and the packaged one beside it' \
    "$(field "${d}/web/named2/manifest.json" name)" 'Desktop|Desktop'
  run build --directory ephemeral0 "${d}/web/ephemeral0" Desktop \
    || bad 'a pool slot builds' "$(cat "${d}/err")"
  is 'a pool desktop'"'"'s app too' \
    "$(field "${d}/web/ephemeral0/app.webmanifest" name)" 'Desktop|Desktop'
  is 'and its icon is upstream'"'"'s, untouched' \
    "$(field "${d}/web/ephemeral0/app.webmanifest" icons)" \
    '[{"src": "icon-512.png", "type": "image/png", "sizes": "512x512"}]'

  # Seen refusing: a manifest the tree does not hold cannot be rewritten, so the
  # tree is not built at all. The file EXISTS beside the tree, so the asset check
  # (every reference resolves) passes and only the manifest rule can refuse.
  printf '%s' "${up}" > "${d}/web/elsewhere.json"
  page ../elsewhere.json
  run provision named3 && rc=0 || rc=$?
  is 'RED ARM: a page linking a manifest outside its tree is refused' "${rc}" '1'
)

echo '== our own pages carry the session page'"'"'s icon, and ask for nothing =='
# The owner, 2026-09-27: one icon in the tab strip and the installed app, never two.
# The session page shows upstream's; these pages had none, so the browser asked for
# /favicon.ico (a request that once minted a desktop) and drew a blank globe. The
# icon is DERIVED from a built slot's gated page and inlined, so the assertion is on
# the bytes: the fixture's icon file must be the one every page carries, and the
# page's apple-touch-icon (a different file) must not be the one taken.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  mkdir -p "${d}/web/ephemeral0"
  printf '<html><head><link rel="apple-touch-icon" href="big.png"><link rel="icon" type="image/png" href="icon.png" /></head></html>' \
    > "${d}/web/ephemeral0/index.html"
  printf 'the-small-icon' > "${d}/web/ephemeral0/icon.png"
  printf 'the-big-icon' > "${d}/web/ephemeral0/big.png"
  want="<link rel=\"icon\" href=\"data:image/png;base64,$(printf 'the-small-icon' | base64 -w0)\">"
  pages() {
    HDW4S_WEBROOT_DIR="$1" python3 - "${ROOT}/hdw4s-demux" <<'PY'
import importlib.machinery, importlib.util, sys
sys.dont_write_bytecode = True
l = importlib.machinery.SourceFileLoader("demux", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("demux", l))
l.exec_module(m)
row = dict(sid="ab" * 16, name=None, age=60, memory_mb=10, pids=3, started=True,
           discarding=False, idle_window=3600)
for name, body in (("dir", m.console_page([row])), ("ended", m.ended_page([row], True)),
                   ("full", m.create_refused_page([row], 4)),
                   ("starting", m.starting_page()),
                   ("plain", m.page("Nothing here", "x"))):
    print("%s\t%s" % (name, body.decode().replace("\n", " ")))
PY
  }
  got="$(pages "${d}/web")"
  for p in dir ended full starting plain; do
    has "the ${p} page carries the session page's icon" \
      "$(printf '%s\n' "${got}" | sed -n "s/^${p}\t//p")" "${want}"
  done
  hasnt 'and names no icon URL a browser would fetch' "${got}" 'rel="icon" href="/'
  got="$(pages "${d}/nothing-built-yet")"
  hasnt 'with no slot built, the pages are as they were' "${got}" 'rel="icon"'
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
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}/eph0" \
           "${HDW4S_WEBROOT_DIR}/eph1" "${HDW4S_WEBROOT_DIR}/alice"
  # A running NAMED desktop in the table throughout, and it IS the census now.
  #
  # This group used to assert the opposite: that alice was skipped, because
  # "only hdw4s-ephemeral@.service pulls in the publisher, and only an ephemeral
  # slot gets a web root to publish into". Both halves stopped being true --
  # hdw4s@.service has Wants=/After= the publisher since ea4f6f6 and a web root
  # since 78e12c6 -- and while they were false and this restriction was still in
  # place, the check reported green at all six timer ticks through an outage in
  # which every named desktop with basic auth was failing to start.
  #
  # The old comment's warning is kept, because it is still the failure mode to
  # watch: on a machine whose named desktops predate those commits, every one of
  # them is reported broken at once, and a check that is always red is read as
  # noise. The difference is that those rows are now TRUE and a restart repairs
  # them. The arms below assert both directions on alice for exactly that reason.
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
  printf '%s\n' 'cccc' > "${HDW4S_WEBROOT_DIR}/alice/hdw4s-incarnation"
  printf '%s\n' 'cccc' > "${HDW4S_INCARNATION_DIR}/alice"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a sound pool and a sound named desktop pass' "${rc}" '0'
  # THREE, and the number is the whole control here: a census that skipped a
  # kind of session would pass this group just as quietly, and would say two.
  # It said two until 2026-09-26, with the named desktop unexamined.
  has 'and says how many it looked at'  "${out}" '3 running'
  # The door count is the half that was missing: "0 running" used to be printed
  # by an idle pool AND by a pool that could not start anything. It still counts
  # the POOL only, which is what it says -- alice has no door of this kind.
  has 'and how many doors are listening' "${out}" '2 ephemeral slot(s), 2 with a listening door'
  hasnt 'a sound named desktop is not accused' "${out}" 'alice is running and publishes'

  # THE RED ARM OF THE WIDENING, and it is the state the outage was in: a named
  # desktop running with nothing published. It is the row that was invisible.
  rm -f "${HDW4S_WEBROOT_DIR}/alice/hdw4s-incarnation"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a named desktop publishing nothing FAILS the check' "${rc}" '1'
  has 'and is named'                                       "${out}" 'alice is running and publishes no incarnation token'
  # The repair has to name the unit that runs a NAMED desktop. A message naming
  # the ephemeral unit sends somebody to restart something that does not exist.
  has 'and names the named unit, not the ephemeral one'    "${out}" 'systemctl restart hdw4s@alice.service'
  printf '%s\n' 'cccc' > "${HDW4S_WEBROOT_DIR}/alice/hdw4s-incarnation"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'and passes again once it publishes one' "${rc}" '0'

  # A desktop that started without the WebRTC it is configured for. The adapter
  # no longer refuses to start it -- as the default, that would take every
  # desktop down at the next streaming server update -- so this report is what
  # turns "it quietly lost a transport" into a red timer.
  mkdir -p "${RUNDIR}/hdw4s/alice"
  printf '%s\n' 'it names ClientSession 3 time(s), not 2' \
    > "${RUNDIR}/hdw4s/alice/webrtc-degraded"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a desktop that degraded to websockets FAILS the check' "${rc}" '1'
  has 'and is named'                        "${out}" 'alice is running WITHOUT WebRTC'
  has 'and carries the reason it was given' "${out}" 'ClientSession 3 time(s)'
  # Its own count, because it is not the token arm's failure and the same
  # session can fail both: one counter would report two failures of one session.
  has 'and has its own summary' "${out}" '1 of 3 running session(s) started without the WebRTC'
  hasnt 'and is not counted as a token failure' "${out}" 'failed this check'
  rm -f "${RUNDIR}/hdw4s/alice/webrtc-degraded"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'and passes again once it has WebRTC' "${rc}" '0'

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
  has   'it counts the failures against the total' "${out}" '1 of 3 running session(s) failed'

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

echo '== the web-root check reads THIS start, and silence is never a pass =='
# Written from the failure, 2026-09-25: the check that stood here fetched the
# session's own front door over HTTP, needed a basic-auth credential to do it,
# and could not get one -- in a unit with mount namespacing the FIRST
# ExecStartPost= has no credential directory. It asked anyway, got a 401,
# reported it as "could not fetch", and tore a HEALTHY desktop down 55 times in
# an hour. Every named desktop with "hdw4s auth" configured was broken on a
# stock install.
#
# It reads the streaming server's own startup announcement now. The failure that
# matters about THAT shape is the opposite one: a read that finds nothing looks
# exactly like a server that said nothing, and treating either as acceptance is
# the defect this whole area cost a day to. Measured on a development container with
# private/measure-invocation-journal.sh: journalctl exits 1 both when nothing
# matched and when it could not read the journal at all, so the status cannot
# tell them apart -- which is why the check prints a probe of its own and
# requires it back.
#
# journalctl is stubbed, so this group tests the DECISION and not systemd. What
# it cannot test is the position and the namespace; those are measured on a real
# machine by private/measure-invocation-journal.sh and by a live start.
#
# "set +e": every arm here runs a command that is MEANT to fail, and under this
# file's errexit the first refusal takes the whole run with it -- which showed as
# a group that stopped after its two green lines, and a suite that reported
# nothing for everything after it.
( set +e
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  mkdir -p "${d}/webroot/probe" "${d}/bin"
  # THE STUB IS A JOURNAL, not a switch: it answers the --grep pattern the check
  # actually passes, and echoes the probe line back only when PROBE=yes -- which
  # is how the "I could not read the journal" arm is expressed without needing an
  # unreadable journal.
  cat > "${d}/bin/journalctl" <<'STUB'
#!/bin/bash
pat=''; ns=''
for a in "$@"; do case "${a}" in --grep=*) pat="${a#--grep=}";; --namespace=\*) ns='all';; esac; done
# An ephemeral desktop logs into its own journal namespace, so a query without
# --namespace='*' reads a journal that holds none of its lines: the stub then
# returns nothing, as the real journal would, and every arm below goes red.
[ "${ns}" = 'all' ] || exit 0
# The check builds its pattern as "<nonce>|<sentence>|<sentence>", so the nonce
# is the first alternative. Taking it from the pattern is what lets the stub
# play the journal back rather than be told the answer.
nonce="${pat%%|*}"
[ "${PROBE:-yes}" = 'yes' ] && echo "hdw4s-webroot: probe ${nonce}"
[ -z "${SAID:-}" ] || printf '%s\n' "${SAID}"
exit 0
STUB
  chmod +x "${d}/bin/journalctl"
  gate() {
    env INVOCATION_ID='abcd1234' \
        HDW4S_JOURNALCTL="${d}/bin/journalctl" \
        HDW4S_WEBROOT_DIR="${d}/webroot" \
        HDW4S_ANNOUNCED_GATE_WAIT='1' \
        PROBE="${PROBE:-yes}" SAID="${SAID:-}" \
        "${ROOT}/hdw4s-webroot" announced-gate probe 2>&1
  }

  # THE POSITIVE CONTROL FIRST. If acceptance does not pass, every refusal below
  # is a check that is always red and says nothing.
  SAID="INFO:server:Using custom web_root directory: ${d}/webroot/probe"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is  'the announced acceptance of OUR web root passes' "${rc}" '0'
  has 'and says which directory'                        "${out}" "${d}/webroot/probe"

  # THE PATH, NOT JUST THE WORDS. "Using custom web_root directory:" proves the
  # server accepted SOME directory; an instance pointed at another session's tree
  # would pass a check that matched only the sentence.
  SAID="INFO:server:Using custom web_root directory: ${d}/webroot/somebody-else"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is  'acceptance of a DIFFERENT directory fails' "${rc}" '1'
  has 'and names both paths'                      "${out}" 'somebody-else'
  has 'and says which one was expected'           "${out}" "${d}/webroot/probe"

  # The refusal. This is the sentence the whole layer exists to catch: the server
  # declines the web root, logs one warning, and serves the stock ungated client
  # while every other check on the machine reports health.
  SAID="WARNING:server:web_root directory ${d}/webroot/probe not found or missing index.html"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is  'an announced refusal fails'      "${rc}" '1'
  has 'and says the client is ungated'  "${out}" 'stock, ungated client'
  has 'and quotes what the server said' "${out}" 'not found or missing index.html'

  # SILENCE, WITH THE INSTRUMENT PROVEN. The probe comes back, so the read works
  # and the sentence genuinely is not there -- which is not acceptance.
  SAID=''
  out="$( ( gate ) 2>&1 )"; rc=$?
  is  'a server that said nothing about its web root fails' "${rc}" '1'
  has 'and says it could not tell, not that it was fine'    "${out}" 'said nothing about its web root'

  # SILENCE, WITH THE INSTRUMENT UNPROVEN, and this is the arm that separates two
  # things journalctl's exit status cannot. The two messages must differ, because
  # the repairs differ: one is "look for an earlier failure in this start", the
  # other is "the reader is broken".
  PROBE='no' SAID=''
  out="$( ( PROBE='no' gate ) 2>&1 )"; rc=$?
  is    'a journal read that cannot even find its own probe fails' "${rc}" '1'
  has   'and blames the instrument'                                "${out}" 'could not read this start'
  hasnt 'and does NOT say the server was silent'                   "${out}" 'said nothing about its web root'
  PROBE='yes'

  # THE STARTUP HOLD'S OUTCOME, published for the page by the same read. The page
  # fits the desktop to its tab only on "started", so what matters is that nothing
  # but a real "started" line ever publishes that word, that a stale one never
  # survives into a new start, and that no failure here ever fails the session.
  mkdir -p "${d}/webroot/probe/hdw4s-startup"
  out_f="${d}/webroot/probe/hdw4s-startup/outcome"
  ACC="INFO:server:Using custom web_root directory: ${d}/webroot/probe"
  published() { cat "${out_f}" 2>/dev/null || echo '(none)'; }
  for w in started bound none deadline off unknown; do
    SAID="hdw4s: startup hold outcome: ${w}"$'\n'"${ACC}"
    out="$( ( gate ) 2>&1 )"; rc=$?
    is "the outcome [${w}] is published as itself, and the start passes" \
       "${rc} $(published)" "0 ${w}"
  done
  is 'published readable by the streaming server, which serves it as the occupant' \
     "$(stat -c %a "${out_f}")" '644'
  # Words it does not know, and a line that is not the outcome's shape, are UNKNOWN.
  for said in 'hdw4s: startup hold outcome: startedx' \
              'hdw4s: startup hold outcome: started; rm -rf /' \
              'hdw4s: startup hold outcome: STARTED'; do
    SAID="${said}"$'\n'"${ACC}"
    out="$( ( gate ) 2>&1 )"; rc=$?
    is "[${said#hdw4s: }] publishes unknown" "${rc} $(published)" '0 unknown'
  done
  # No outcome line at all: an older run-session, or one that died first.
  SAID="${ACC}"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is 'no outcome line publishes unknown' "${rc} $(published)" '0 unknown'
  # A STALE "started" from an earlier start must not survive a start that fails.
  printf 'started\n' > "${out_f}"
  SAID="WARNING:server:web_root directory ${d}/webroot/probe not found or missing index.html"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is 'a start that fails still clears the last start'"'"'s outcome' "${rc} $(published)" '1 (none)'
  # Nowhere to write -- a tree from an older package, or a unit that did not make the
  # directory writable -- is silence, NEVER a failed start.
  chmod 0555 "${d}/webroot/probe/hdw4s-startup"
  SAID="hdw4s: startup hold outcome: started"$'\n'"${ACC}"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is 'an unwritable outcome directory does not fail the start' "${rc} $(published)" '0 (none)'
  has 'and says the page will not resize' "${out}" 'will not resize'
  chmod 0755 "${d}/webroot/probe/hdw4s-startup"
  rm -rf "${d}/webroot/probe/hdw4s-startup"
  out="$( ( gate ) 2>&1 )"; rc=$?
  is 'a tree with no outcome directory does not fail the start' "${rc}" '0'
  has 'and says so' "${out}" 'will not resize'
  # RED ARM: a publisher that trusts whatever word it reads must be caught
  # publishing one it does not know.
  sed 's/    \*) word=.unknown. ;;/    *) ;;/' "${ROOT}/hdw4s-webroot" > "${d}/red-webroot"
  if cmp -s "${ROOT}/hdw4s-webroot" "${d}/red-webroot"; then
    bad 'the outcome red arm mutates the publisher' 'the sed matched nothing'
  else
    chmod +x "${d}/red-webroot"
    mkdir -p "${d}/webroot/probe/hdw4s-startup"
    SAID='hdw4s: startup hold outcome: startedx'$'\n'"${ACC}"
    ( env INVOCATION_ID='abcd1234' HDW4S_JOURNALCTL="${d}/bin/journalctl" \
          HDW4S_WEBROOT_DIR="${d}/webroot" HDW4S_ANNOUNCED_GATE_WAIT='1' \
          PROBE=yes SAID="${SAID}" "${d}/red-webroot" announced-gate probe ) >/dev/null 2>&1
    is 'RED ARM: a publisher without the word list publishes a word the page never asked for' \
       "$(published)" 'startedx'
  fi
  SAID=''

  # No invocation to read. Without it the query would return whatever the journal
  # holds for every start the unit has ever had, which is how two wrong
  # conclusions were reached on 2026-09-25.
  out="$( ( env INVOCATION_ID='' HDW4S_JOURNALCTL="${d}/bin/journalctl" \
                HDW4S_WEBROOT_DIR="${d}/webroot" HDW4S_ANNOUNCED_GATE_WAIT='1' \
                "${ROOT}/hdw4s-webroot" announced-gate probe ) 2>&1 )"; rc=$?
  is  'a run with no INVOCATION_ID refuses'   "${rc}" '1'
  has 'and says it will not read mixed starts' "${out}" 'mixes starts'
)

echo '== both session units check the web root, and neither needs a credential to =='
# Written from the failure twice over. The named unit never ran
# "hdw4s-webroot gate" at all, so the layer that asserts this start's published
# identity -- the one whose absence gives the owner's own desktop a reconnect
# card on every returning tab -- was running on ephemeral slots only. And the
# check that DID run there was an HTTP fetch that could not get its credential.
( set +e
  for u in hdw4s@.service hdw4s-ephemeral@.service; do
    f="${ROOT}/${u}"
    # A harness that greps for something absent from every file proves nothing,
    # so show the pattern can match before reporting that it does.
    probe="$(printf 'ExecStartPre=!/usr/lib/hdw4s/hdw4s-webroot gate %%i\n' |
             grep -c 'hdw4s-webroot gate')"
    is "the probe can see a gate line (${u})" "${probe}" '1'
    grep -qE '^ExecStartPre=!/usr/lib/hdw4s/hdw4s-webroot gate %i$' "${f}" \
      && ok "${u} checks the web root it was given" \
      || bad "${u} checks the web root it was given" \
             'no "ExecStartPre=!hdw4s-webroot gate %i" -- nothing asserts this start'"'"'s identity'
    grep -qE '^ExecStartPost=!/usr/lib/hdw4s/hdw4s-webroot announced-gate %i$' "${f}" \
      && ok "${u} reads what the server accepted" \
      || bad "${u} reads what the server accepted" 'no announced-gate line'
    # THE NAME THAT WAS REMOVED, searched for deliberately. A unit still calling
    # "serving-gate" would fail at start with "usage:", which is loud -- but a
    # COMMENT still describing a fetch that no longer happens is silent, and that
    # is the thing this project keeps paying for.
    found="$(grep -n 'serving-gate' "${f}" || :)"
    case "${found}" in
      ''|*'until 2026-09-26'*) ok "${u} does not cite the removed serving-gate as current" ;;
      *) bad "${u} does not cite the removed serving-gate as current" "${found}" ;;
    esac
  done
)

echo '== a session start that keeps failing has to stop, and this one could not =='
# MEASURED 2026-09-25: hdw4s@.service looped 55 times in an hour and would have
# gone on for ever. Its failure cycle is about ninety-five seconds -- up to
# TimeoutStartSec= to fail, then RestartSec= before the next try -- against
# systemd's DEFAULT start-limit window of ten seconds, so the burst was never
# reached inside the window and NRestarts went 1, 2, back to 1. Nothing would
# ever have latched it; a person noticed.
#
# So the property is not "there is a StartLimit line". It is that the window is
# long enough to hold a burst of this unit's OWN cycles, derived from the unit's
# own timeouts rather than compared against a number somebody typed here.
( set +e
  f="${ROOT}/hdw4s@.service"
  # The reason has to still be true, or this test outlives it as a rule nobody
  # can explain: with Restart=no there is no loop to latch.
  grep -qE '^Restart=on-failure$' "${f}" \
    && ok 'the named unit still restarts on failure' \
    || bad 'the named unit still restarts on failure' \
           'the reason this test exists has moved; re-derive it before editing'

  # SECTION-AWARE, because that is where this went first: StartLimitIntervalSec=
  # and StartLimitBurst= are [Unit] directives, and a copy in [Service] is a line
  # that looks like a guard and is not one. systemd-analyze verify does not say
  # so, so nothing else here would notice.
  sect="$(awk -F= '/^\[/ { s=$0; next }
                   /^StartLimit(IntervalSec|Burst)=/ { print s, $1 }' "${f}" | sort -u)"
  is 'both start-limit directives are in [Unit]' \
     "$(printf '%s\n' "${sect}" | grep -cv '^\[Unit\]')" '0'

  secs() {  # a systemd time span, in seconds, for the three spellings used here
    case "$1" in
      *min) echo $(( ${1%min} * 60 ));;
      *h)   echo $(( ${1%h} * 3600 ));;
      *s)   echo "${1%s}";;
      *)    echo "$1";;
    esac
  }
  get() { sed -n "s/^$1=//p" "${f}" | tail -n1; }
  window="$(secs "$(get StartLimitIntervalSec)")"
  burst="$(get StartLimitBurst)"
  cycle=$(( $(secs "$(get TimeoutStartSec)") + $(secs "$(get RestartSec)") ))
  need=$(( burst * cycle ))

  # The harness has to have read real numbers, or every comparison below is
  # arithmetic on empty strings that happens to come out true.
  [ "${window}" -gt 0 ] && [ "${burst}" -gt 1 ] && [ "${cycle}" -gt 0 ] \
    && ok "the unit's own numbers were read (window ${window}s, burst ${burst}, cycle ${cycle}s)" \
    || bad "the unit's own numbers were read" \
           "window [${window}] burst [${burst}] cycle [${cycle}]"

  [ "${window}" -ge "${need}" ] \
    && ok "and the window holds ${burst} of them (${window}s >= ${need}s)" \
    || bad 'and the window holds a burst of them' \
           "window ${window}s cannot hold ${burst} cycles of ${cycle}s: this unit
       would loop for ever, which is what it did on 2026-09-25"

  # THE RED ARM, against systemd's own default, which is the value this unit
  # carried while it looped. If the arithmetic above cannot fail, it is not a
  # check -- and a default is exactly the number nobody writes down.
  window='10'
  [ "${window}" -ge "${need}" ] \
    && bad 'CONTROL: the default ten-second window is rejected' 'it passed' \
    || ok  'CONTROL: the default ten-second window is rejected'
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

echo '== the startup hold fails open, and its deadline matches the gate =='
# The hold in hdw4s-run-session ends before the unit's ExecStartPost gives up
# waiting for the stream, and both read HDW4S_ANNOUNCED_GATE_WAIT with a
# default of their own. Two copies of one number drift the moment one is
# edited, and a hold whose default outlived the gate's would fail every start
# whose desktop is never shown.
#
# Under -e and nounset, arithmetic on a value that is not a number ENDS the
# script, and a named session then restarts in a loop -- over a timing aid. The
# values come from the environment (an older hdw4s-session, across an upgrade,
# exports none) and from /proc. "09" is the quiet one: it passes a digits-only
# check and is then an invalid OCTAL number to bash's arithmetic.
( set +e
  # A sed expression that matches a literal "${...}", not an expansion.
  # shellcheck disable=SC2016
  default_of='s/.*"\${HDW4S_ANNOUNCED_GATE_WAIT:-\([0-9]*\)}".*/\1/p'
  gate_default="$(sed -n "${default_of}" "${ROOT}/hdw4s-webroot" | sort -u)"
  hold_default="$(sed -n "${default_of}" "${ROOT}/hdw4s-run-session" | sort -u)"
  is 'the gate has exactly one default wait' "$(printf '%s\n' "${gate_default}" | grep -c .)" '1'
  is 'and the hold assumes the same one' "${hold_default}" "${gate_default}"

  fns="$(sed -n '/^is_seconds() {/,/^}/p; /^uptime_s() {/,/^}/p' "${ROOT}/hdw4s-run-session")"
  has 'the number checks are where this test looks for them' "${fns}" 'uptime_s() {'
  # The probe is a script for "bash -c", so its "$1" is meant literally here.
  # shellcheck disable=SC2016
  probe='is_seconds "$1" && echo "$(( 10#$1 + 1 ))" || echo no'
  verdicts=''
  for v in '' '60s' 'x' '1 2' '-5' '1234567890123' '09' '60'; do
    if said="$(bash -c "set -eu; ${fns}; ${probe}" _ "${v}" 2>/dev/null)"; then
      verdicts="${verdicts}${said}/"
    else
      verdicts="${verdicts}DIED/"
    fi
  done
  is 'only whole numbers are numbers, and none of them kills the script' \
     "${verdicts}" 'no/no/no/no/no/no/10/61/'
  now="$(bash -c "set -eu; ${fns}; uptime_s")"
  case "${now}" in ''|*[!0-9]*) bad 'the clock reads as whole seconds' "got [${now}]" ;;
                   *) ok 'the clock reads as whole seconds' ;; esac

  # The watcher fails open by saying nothing: no X server, or an argument it
  # cannot read, must end it quickly with nothing on stdout -- not a traceback
  # that reaches Ubuntu's crash handler, which takes seconds the unit's start
  # is waiting on.
  for args in '' 'x' '3 y'; do
    start="${SECONDS}"
    # shellcheck disable=SC2086
    out="$(env -u DISPLAY python3 -I "${ROOT}/hdw4s-stage-wait" ${args} 2>/dev/null)"
    rc=$?
    is "the watcher with no display and arguments [${args}] exits non-zero" "$([ "${rc}" -ne 0 ] && echo yes)" 'yes'
    is '  and says nothing on stdout' "${out}" ''
    is '  and does it at once' "$([ $(( SECONDS - start )) -le 2 ] && echo yes)" 'yes'
  done
)

echo '== the session says, in one word, how the startup hold ended =='
# The page fits the desktop to its tab only when this word is "started" (see the
# page's fitAfterStart and hdw4s-webroot's publish_outcome), so the word must be
# "started" for the desktop's own end-of-startup signal and for NOTHING else.
#
# Real: hdw4s-run-session's own hold loop and verdict, cut out of the script.
# Stood in for: the watcher, by a file of the lines it would print, and the clock.
( set +e
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  cut_hold() {
    sed -n '/^is_seconds() {/,/^}/p; /^uptime_s() {/,/^}/p; /^quoted() {/,/^}/p' "$1"
    # The SECOND "if stage_fd": the first one only starts the desktop.
    awk '/^if \[ -n "\$\{stage_fd\}" \]; then$/ { prev = $0; next_is = 1; next }
         next_is { next_is = 0; if ($0 ~ /stage_armed/) { on = 1; print prev } }
         on { print } on && /^echo "hdw4s: startup hold outcome: / { on = 0 }' "$1"
  }
  cut_hold "${ROOT}/hdw4s-run-session" > "${d}/hold.sh"
  has 'the hold is where this test looks for it' "$(cat "${d}/hold.sh")" 'startup hold outcome'
  # $1: the watcher's lines. Prints the outcome line only.
  outcome_for() {
    printf '%b' "$1" > "${d}/lines"
    bash -c 'set -eu
      HDW4S_STARTUP_HOLD=on; stopping=""; hold_bound=18; hold_gate=60; hold_margin=6
      hold_outcome=unknown; stage_armed="${ARMED}"; stage_pid=999999999
      hold_outer=$(( $(cut -d. -f1 /proc/uptime) + 3 ))
      exec {stage_fd}< "'"${d}"'/lines"
      . "'"${2:-${d}/hold.sh}"'"' 2>&1 | grep 'startup hold outcome'
  }
  ARMED=1; export ARMED
  is 'the desktop signalled the end of its startup -> started' \
    "$(outcome_for 'shown 10 id=1 parent=2 name=x\nready 2000 shown=10\n')" \
    'hdw4s: startup hold outcome: started'
  is 'the 18 s fallback -> bound' \
    "$(outcome_for 'shown 10 id=1 parent=2 name=x\nbound 18010 shown=10\n')" \
    'hdw4s: startup hold outcome: bound'
  is 'nothing to watch -> none' "$(outcome_for 'none no SHAPE extension\n')" \
    'hdw4s: startup hold outcome: none'
  is 'a watcher that dies -> unknown' "$(outcome_for 'shown 10 id=1 parent=2 name=x\n')" \
    'hdw4s: startup hold outcome: unknown'
  is 'a line nobody knows -> unknown' "$(outcome_for 'ready-ish 5\n')" \
    'hdw4s: startup hold outcome: unknown'
  ARMED=''
  is 'a watcher that never armed -> unknown, even with "ready" in its pipe' \
    "$(outcome_for 'ready 2000 shown=10\n')" 'hdw4s: startup hold outcome: unknown'
  ARMED=1
  # RED ARM: a script that calls a fallback "started" must be caught.
  sed "s/hold_outcome='bound'/hold_outcome='started'/" "${ROOT}/hdw4s-run-session" > "${d}/red"
  if cmp -s "${ROOT}/hdw4s-run-session" "${d}/red"; then
    bad 'the hold red arm mutates the script' 'the sed matched nothing'
  else
    cut_hold "${d}/red" > "${d}/red-hold.sh"
    is 'RED ARM: a fallback release reported as started is caught' \
      "$(outcome_for 'shown 10 id=1 parent=2 name=x\nbound 18010 shown=10\n' "${d}/red-hold.sh")" \
      'hdw4s: startup hold outcome: started'
  fi
)

echo '== a logout ends an ephemeral desktop cleanly, and anything else is still a failure =='
# THE DEFECT, measured twice on 2026-09-27: after a GNOME logout the ephemeral unit
# stayed "failed", so "hdw4s check" exited 1 until somebody ran reset-failed. The
# session script answered every exit of GNOME with status 1.
#
# Real: hdw4s-run-session's own gnome_exited, cut out of the script. Stood in for:
# GNOME, by a child that exits with a chosen status. Nothing here shows what status
# a real gnome-session returns on logout, nor what systemd then records.
( set +e
  fn="$(sed -n '/^gnome_exited() {/,/^}/p' "${ROOT}/hdw4s-run-session")"
  has 'the exit decision is where this test looks for it' "${fn}" 'gnome_exited() {'
  # $1 the kind, $2 what the stand-in GNOME does. Prints the exit status.
  ended() {
    HDW4S_SESSION_TYPE="$1" bash -c "set -eu; ${fn}
      $2 & session_pid=\$!; sleep 0.2; gnome_exited" >/dev/null 2>&1
    echo "$?"
  }
  is 'an ephemeral desktop logged out of ends with success'  "$(ended ephemeral 'exit 0')" '0'
  is 'an ephemeral desktop whose GNOME failed still fails'   "$(ended ephemeral 'exit 1')" '1'
  # shellcheck disable=SC2016 # expanded by the stand-in's own shell, on purpose
  is 'an ephemeral desktop whose GNOME was killed still fails' \
     "$(ended ephemeral 'kill -KILL $BASHPID')" '1'
  is 'a named desktop logged out of still exits 1, so its unit restarts it' \
     "$(ended '' 'exit 0')" '1'
)

echo '== the teardown ends a desktop that is still starting =='
# THE DEFECT, measured on production 2026-09-27: a GNOME logout with the tab open,
# the tab's reconnect socket-activated a fresh desktop in the slot, the router asked
# for it to be reclaimed, and hdw4s-teardown answered "ephemeral20 is activating, so
# there is nothing to end". The desktop came up six seconds later, owned by nobody.
#
# WHAT IS REAL AND WHAT IS STOOD IN FOR. Real: hdw4s-teardown itself, unmodified,
# its decision and its ladder. Stood in for: systemctl, by an exported shell function
# (the script pins PATH, and a function is found before PATH is searched), and the
# session's cgroup, by a directory with a cgroup.procs naming a pid that does not
# exist -- so nothing is signalled and no compositor is found. Nothing here shows
# that systemd stops anything; it shows what this script ASKS for.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  systemctl() {
    printf '%s\n' "$*" >> "${STUB_LOG}"
    case "$*" in
      'show -p ActiveState --value '*) printf '%s\n' "${STUB_STATE}";;
    esac
  }
  export -f systemctl
  # One run of the script against a fresh stand-in, in STATE. Prints what it said.
  teardown_in() {
    rm -rf "${d}/req" "${d}/cg"; : > "${d}/log"
    mkdir -p "${d}/req" "${d}/cg/hdw4s-ephemeral0.slice"
    echo 999999999 > "${d}/cg/hdw4s-ephemeral0.slice/cgroup.procs"
    : > "${d}/cg/hdw4s-ephemeral0.slice/cgroup.kill"
    STUB_LOG="${d}/log" STUB_STATE="$1" \
      HDW4S_TEARDOWN_DIR="${d}/req" HDW4S_SESSION_CGROUP_ROOT="${d}/cg" \
      bash "${2:-${ROOT}/hdw4s-teardown}" ephemeral0 2>&1
  }
  killed() { cat "${d}/cg/hdw4s-ephemeral0.slice/cgroup.kill"; }

  # THE CONTROL FIRST: an active desktop is ended, so the rig can see an ending.
  out="$(teardown_in active)"
  is 'an active desktop is ended through its own cgroup' "$(killed)" '1'
  has 'and its unit is stopped' "$(cat "${d}/log")" 'stop hdw4s-ephemeral@ephemeral0.service'

  # THE DEFECT: an activating desktop is ended too.
  out="$(teardown_in activating)"
  hasnt 'an activating desktop is not "nothing to end"' "${out}" 'nothing to end'
  is 'an activating desktop is ended through its own cgroup' "$(killed)" '1'
  has 'and its start is cancelled by a stop' "$(cat "${d}/log")" 'stop hdw4s-ephemeral@ephemeral0.service'

  # THE PERMIT ARM: a unit that is not running is not killed, but any start still
  # queued for it is replaced by a stop.
  out="$(teardown_in inactive)"
  has 'an inactive desktop is nothing to end' "${out}" 'nothing to end'
  is 'and nothing is killed' "$(killed)" ''
  has 'but a pending start is still cancelled' "$(cat "${d}/log")" 'stop --no-block hdw4s-ephemeral@ephemeral0.service'

  # RED ARM: the defect put back -- only "active" is worth ending -- must lose the
  # activating desktop, or the arms above are not about this line.
  sed 's/^  active|activating|deactivating|reloading|refreshing) ;;$/  active) ;;/' \
    "${ROOT}/hdw4s-teardown" > "${d}/red"
  if cmp -s "${ROOT}/hdw4s-teardown" "${d}/red"; then
    bad 'the red arm mutates the teardown' 'the sed matched nothing'
  else
    teardown_in activating "${d}/red" >/dev/null
    is 'a teardown that ends only active desktops leaves an activating one' "$(killed)" ''
  fi
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
EXPECTED=705   # update when tests are added; a wrong number is the point
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
