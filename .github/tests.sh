#!/bin/bash -e
# Four findings are inherent to what this file is, and are named rather than
# silenced wholesale:
#   SC2034  variables assigned here are read by the code sourced from hdw4s,
#           which the linter cannot see across the source boundary.
#   SC2154  "user" is an output of split_name, set as a global.
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
# Needs bash, coreutils, python3, xdg-user-dirs and a loopback interface. The
# last but one is the real xdg-user-dirs-update, run against the guard that
# keeps it from recreating a home's folders; a stand-in would agree with
# whatever the guard was written to expect. Anything that would
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

# No bytecode cache, for every python3 this suite starts. The components have no
# ".py" suffix, so a loader caches them as __pycache__/<name>cpython-*.pyc in the
# TREE, and a cache is trusted when the source's size and mtime-in-seconds match.
# A red arm that swaps two names in a file keeps its size, and is put back within
# the same second it was applied -- so the next run loaded the DOCTORED router
# from the cache and failed a test the arm had not touched. Measured here, on
# 2026-09-30. A few groups set sys.dont_write_bytecode themselves; this covers
# the ones that do not, and anything added later.
export PYTHONDONTWRITEBYTECODE=1

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
# An assertion that cannot mean anything here (as root, "unreadable" is not):
# recorded, so the count stays honest, and printed as a skip with the reason.
# It was CALLED below for weeks and defined nowhere -- the group died at it
# whenever the suite ran as root, which it never had (2026-10-03, on a dev box).
skip() { echo "ok" >> "${RESULTS}"; printf '  skip %s (%s)\n' "$1" "$2"; }

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
  # THE SANDBOX'S CONFIGURATION, BEFORE THE CLI IS LOADED. Loading it sources
  # ${HDW4S_ETCDIR:-/etc/hdw4s}/hdw4s.conf at once, and this used to happen
  # with the variable unset -- so on a machine with hdw4s configured, every
  # group started from that machine's real settings (on a dev box: /shared
  # "source" and "external", and seven assertions about tmpfs and a local
  # sweep failed). On a workstation the file is absent, which hid it.
  export HDW4S_ETCDIR="${SB}/etc"
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
  # The root namespace's /shared, which "hdw4s check" asks the minter about:
  # here, never the machine's own.
  export HDW4S_SHARED_MARK="${SB}/shared-mark" HDW4S_SHARED_MOUNTPOINT="${SB}/shared-point" \
         HDW4S_SHARED_VIEW_STATE="${SB}/shared-view"
  : > "${CONF}"
SETUP
}

echo '== instance names =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Not "split_name … && is …": if the call fails the assertion never runs and
  # nothing is recorded, so making split_name reject every name looked like a
  # pass.
  user=''
  split_name 'alice'   2>/dev/null || :; is 'plain name accepted' "${user}" 'alice'
  split_name 'alice:2' 2>/dev/null && bad 'colon rejected' || ok 'colon rejected'
  # A name reaches file paths, so it is checked even where the account need not exist.
  split_name '../../root/x' 2>/dev/null && bad 'path traversal rejected' || ok 'path traversal rejected'
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
    *'systemd-socket-proxyd /run/hdw4s/stream/%i/s/stream.sock') ok 'the relay connects to the path';;
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

echo '== a named desktop'"'"'s web root is built when it is enabled, before its door opens =='
( set +e; sandbox; . "${SB}/setup.sh"
  # A desktop that had never started had nowhere to publish its identity: the
  # session builds its web root only in ExecStartPre, AFTER hdw4s-incarnation@
  # publishes into it, so its first start failed the gate and the first visit
  # after "enable" was refused (seen on a dev box, 2026-10-03; released since
  # the incarnation gate). enable now builds it, before the socket is enabled.
  CALLS="${SB}/calls"; : > "${CALLS}"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; }
  getent() { [ "$1" = passwd ] && printf 'alice:x:1500:1500::/home/alice:/bin/bash\n'; }
  mkdir -p "${SB}/lib"
  # shellcheck disable=SC2016  # $* and WEBROOT_FAILS belong to the stub, not here
  printf '#!/bin/sh\necho "webroot $*" >> "%s"\n[ -z "${WEBROOT_FAILS:-}" ] || { echo "no bundle" >&2; exit 1; }\n' \
    "${CALLS}" > "${SB}/lib/hdw4s-webroot"
  chmod +x "${SB}/lib/hdw4s-webroot"
  export HDW4S_LIBDIR="${SB}/lib"
  rm -f "${SLOTS}"
  ( cmd_enable alice ) >/dev/null 2>&1
  is  'enable builds the web root of the desktop it enables' \
      "$(command grep -c '^webroot provision alice$' "${CALLS}")" '1'
  is  'before the door is opened' \
      "$(command grep -n -E '^webroot provision alice$|^systemctl enable --now hdw4s-proxy@alice.socket$' "${CALLS}" | cut -d: -f2- | cut -c1-9 | tr '\n' ';')" \
      'webroot p;systemctl;'
  : > "${CALLS}"; rm -f "${SLOTS}"
  out="$( (WEBROOT_FAILS=1 cmd_enable alice) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a web root that cannot be built fails the enable' \
    || bad 'a web root that cannot be built fails the enable' "rc ${rc}"
  has   'and says the first start would fail' "${out}" 'its first start'
  hasnt 'and the door is not opened'          "$(cat "${CALLS}")" 'enable --now hdw4s-proxy@alice.socket'
  # A pool seat's web root is the minter's, built at boot with --directory.
  : > "${CALLS}"; rm -f "${SLOTS}"
  ( enable_slot ephemeral _hdw4s_0 ) >/dev/null 2>&1
  hasnt 'a pool seat is not provisioned here' "$(cat "${CALLS}")" 'webroot provision'
  # THE RELAY'S HOLD ON ITS SESSION. A named desktop's is BindsTo=: reached at
  # its own hostname, coming back on connect is its design, and Requires= would
  # not end a relay whose session exits on its own. A pool seat's is Requisite=,
  # which starts nothing, so a connection can never start a desktop for nobody.
  dep() { command grep -E '^(Requires|BindsTo|Requisite)=' \
            "${DROPIN}/hdw4s-proxy@$1.service.d/30-session.conf" 2>/dev/null; }
  is 'a named desktop'"'"'s relay binds to its session' "$(dep alice)" 'BindsTo=hdw4s@alice.service'
  is 'a pool seat'"'"'s relay requires a running one and starts none' \
     "$(dep _hdw4s_0)" 'Requisite=hdw4s-ephemeral@_hdw4s_0.service'
)

echo '== a pool seat or the authoring slot is not a person'"'"'s desktop =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Every refusal here stood in front of a command that used to do its damage
  # quietly: "enable ephemeral3" wrote a person's drop-ins into the pool unit,
  # and "disable"/"release" shrank the pool with nothing saying so. Each case
  # asserts the refusal AND that nothing was written, because a refusal that
  # prints after the damage is the half-apply this tree has shipped before.
  NSDIR="${SB}/ns"
  mkdir -p "${NSDIR}/_hdw4s_0" "${NSDIR}/_hdw4s_1" "${NSDIR}/tmpl"
  : > "${NSDIR}/_hdw4s_0/passwd"; : > "${NSDIR}/_hdw4s_1/passwd"; : > "${NSDIR}/tmpl/passwd"
  printf '%s\n' '# comment' '0 alice' '1 _hdw4s_0 ephemeral' '2 tmpl template' \
    '3 root template' > "${SLOTS}"
  table="$(cat "${SLOTS}")"
  CALLS="${SB}/calls"; : > "${CALLS}"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; }
  RUNDIR="${SB}/run"

  # The seat's account is stood in for, as the minter would have made it. Without
  # it the enable died later, at the account lookup, and "nothing was written"
  # passed with the guard removed -- measured, by removing it.
  seat() { getent() { printf '_hdw4s_0:x:60900:60900::/home/user:/bin/bash\n'; }; "$@"; }
  out="$( (seat cmd_enable _hdw4s_0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'enable refuses a pool seat' || bad 'enable refuses a pool seat' "rc ${rc}"
  has   'and says what it is'           "${out}" 'seat of the ephemeral pool'
  has   'and what to do instead'        "${out}" 'hdw4s enable <user>'
  is    'and writes no drop-in'         "$(find "${DROPIN}" -mindepth 1 | wc -l | tr -d ' ')" '0'
  out="$( (cmd_enable _hdw4s_1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and a minted seat with no row yet' \
    || bad 'and a minted seat with no row yet' "rc ${rc}"
  out="$( (cmd_enable tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'enable refuses the authoring slot' || bad 'enable refuses the authoring slot' "rc ${rc}"
  has   'and points at template edit'   "${out}" 'hdw4s template edit'
  out="$( (cmd_enable "${TEMPLATE_SLOT}") 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and the reserved name before anything provisions it' \
    || bad 'and the reserved name before anything provisions it' "rc ${rc}"
  # A template row is refused by its type, whatever account the name resolves to.
  out="$( (cmd_enable root) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a template row on a real account is refused too' \
    || bad 'a template row on a real account is refused too' "rc ${rc}"
  has   'and for being the authoring slot'  "${out}" 'hdw4s template edit'
  # Seats are added by "pool size" alone; the per-seat spelling is a usage error
  # from the real dispatcher, before anything is looked up or written.
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" enable --ephemeral _hdw4s_3 >/dev/null 2>&1
  is    'enable --ephemeral is a usage error' "$?" '2'
  is    'no enable changed the table'   "$(cat "${SLOTS}")" "${table}"

  out="$( (seat cmd_disable _hdw4s_0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'disable refuses a pool seat' || bad 'disable refuses a pool seat' "rc ${rc}"
  has   'and says how to end one desktop' "${out}" 'systemctl stop hdw4s-ephemeral@_hdw4s_0.service'
  out="$( (cmd_disable tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and the authoring slot' || bad 'and the authoring slot' "rc ${rc}"
  out="$( (cmd_release _hdw4s_0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'release refuses a pool seat' || bad 'release refuses a pool seat' "rc ${rc}"
  has   'and names the command that sizes the pool' "${out}" 'hdw4s pool size <N>'
  hasnt 'and no longer offers a way past' "${out}" 'release --internal'
  out="$( (cmd_release --internal _hdw4s_0) 2>&1 )"; rc=$?
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
  printf '{"userName":"_hdw4s_1","uid":60901,"gid":60901}\n' > "${USERDB}/60901.user"
  mkdir -p "${DROPIN}/hdw4s-ephemeral@tmpl.service.d"
  systemctl() { echo "systemctl $*" >> "${CALLS}"; [ "$1" != is-active ]; }
  (cmd_release --internal tmpl) >/dev/null 2>&1
  is    'release --internal removes the authoring slot' "$(slot_of tmpl)" ''
  is    'and only that row' "$(slot_of alice):$(slot_of _hdw4s_0)" '0:1'
  has   'and keeps the comments' "$(cat "${SLOTS}")" '# comment'
  is    'and the identity the minter made for it' \
        "$(find "${USERDB}" -mindepth 1 -printf '%f ')" '60901.user '
  is    'and its namespace' "$([ -e "${NSDIR}/tmpl" ] && echo left || echo gone)" 'gone'
  is    'and its drop-ins' "$(find "${DROPIN}" -mindepth 1 | wc -l | tr -d ' ')" '0'
)

echo '== the pool'"'"'s settings are one thing, not one per seat =='
( set +e; sandbox; . "${SB}/setup.sh"
  # A visitor is handed whichever seat is free, so a setting on one seat made
  # what a visitor got depend on a draw nobody could see -- and the never-reap
  # refusal used to recommend exactly that ("hdw4s set <seat> ..."). Per-seat
  # settings are refused now, and the pool has one file every seat reads.
  NSDIR="${SB}/ns"; mkdir -p "${NSDIR}/_hdw4s_1"; : > "${NSDIR}/_hdw4s_1/passwd"
  printf '%s\n' '0 dora' '1 _hdw4s_0 ephemeral' '2 tmpl template' > "${SLOTS}"
  printf 'HDW4S_TRANSPORT=unix\n' > "${ETCDIR}/_hdw4s_0.conf"
  before="$(cd "${ETCDIR}" && find . -type f -exec md5sum {} + | sort)"
  for who in _hdw4s_0 _hdw4s_1 tmpl; do
    out="$( (cmd_set "${who}" 'HDW4S_FRAMERATE=24') 2>&1 )"; rc=$?
    [ "${rc}" -ne 0 ] && ok "set refuses ${who}" || bad "set refuses ${who}" "rc ${rc}"
    has "and points at pool set" "${out}" 'hdw4s pool set KEY=VALUE'
    out="$( (cmd_unset "${who}" 'HDW4S_FRAMERATE') 2>&1 )"; rc=$?
    [ "${rc}" -ne 0 ] && ok "unset refuses ${who}" || bad "unset refuses ${who}" "rc ${rc}"
    has "and points at pool unset" "${out}" 'hdw4s pool unset KEY'
  done
  is 'no refusal wrote anything' "$(cd "${ETCDIR}" && find . -type f -exec md5sum {} + | sort)" "${before}"
  # CONTROL: a person's desktop is still set one by one.
  (cmd_set dora 'HDW4S_FRAMERATE=24') >/dev/null 2>&1
  has 'a named desktop is still set one by one' "$(cat "${ETCDIR}/dora.conf" 2>/dev/null)" 'HDW4S_FRAMERATE=24'

  # pool set writes the pool's file, and every seat -- not a named desktop --
  # reads it, between the machine's file and its own.
  printf 'HDW4S_FRAMERATE=30\n' > "${CONF}"
  out="$( (pool_set 'HDW4S_FRAMERATE=20') 2>&1 )"
  has 'pool set writes the pool'"'"'s file' "$(cat "$(pool_conf)")" 'HDW4S_FRAMERATE=20'
  has 'and says it applies to desktops that start from now on' "${out}" 'starts from now on'
  hasnt 'and tells nobody to restart a visitor'"'"'s desktop' "${out}" 'estart'
  r="$(setting_with_source _hdw4s_0 HDW4S_FRAMERATE x)"
  is 'a seat reads the pool'"'"'s value' "${r}" "20	$(pool_conf)"
  r="$(setting_with_source tmpl HDW4S_FRAMERATE x)"
  is 'so does the authoring desktop' "${r}" "20	$(pool_conf)"
  rm -f "${ETCDIR}/dora.conf"
  r="$(setting_with_source dora HDW4S_FRAMERATE x)"
  is 'a named desktop does not' "${r}" "30	${CONF}"
  ( pool_set 'HDW4S_FRAMERATE=25' ) >/dev/null 2>&1
  out="$(pool_show_all 2>&1)"
  has 'and shows the pool'"'"'s value and where it came from' "${out}" "HDW4S_FRAMERATE              25                     $(pool_conf)"
  has 'and the built-in default where nothing says' "${out}" 'built-in default'

  # Settings a pool desktop has a fixed answer to are refused, with the reason,
  # and write nothing; machine-wide ones point at "set"; the size at "size".
  before="$(cat "$(pool_conf)" "${CONF}")"
  out="$( (pool_set 'HDW4S_PROFILE_DIR=/var/tmp') 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a profile directory for the pool is refused' \
    || bad 'a profile directory for the pool is refused' "rc ${rc}"
  has 'and says why' "${out}" 'nothing of it is left on disk'
  out="$( (pool_set 'HDW4S_PROXIES=10.0.0.1') 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a machine-wide setting is refused' \
    || bad 'a machine-wide setting is refused' "rc ${rc}"
  has 'and names the command for it' "${out}" 'hdw4s set HDW4S_PROXIES=10.0.0.1'
  out="$( (pool_set 'HDW4S_EPHEMERAL_SLOTS=4') 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'so is the size' || bad 'so is the size' "rc ${rc}"
  has 'which names pool size' "${out}" 'hdw4s pool size <N>'
  is 'none of them wrote anything' "$(cat "$(pool_conf)" "${CONF}")" "${before}"
  # Read once for the machine: written where its reader reads it.
  out="$( (pool_set 'HDW4S_EPHEMERAL_HOME_SIZE=2G') 2>&1 )"
  has 'a seat'"'"'s home size goes where the minter reads it' "$(cat "${CONF}")" 'HDW4S_EPHEMERAL_HOME_SIZE=2G'
  hasnt 'and not into a file the minter never reads' "$(cat "$(pool_conf)")" 'HOME_SIZE'
  has 'and says when it applies' "${out}" 'reboot to use it'

  (pool_unset 'HDW4S_FRAMERATE') >/dev/null 2>&1
  r="$(setting_with_source _hdw4s_1 HDW4S_FRAMERATE x)"
  is 'pool unset hands the pool the machine'"'"'s value again' "${r}" "30	${CONF}"

  # The proxy, as one thing too.
  out="$( (cmd_proxy tmpl) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'proxy refuses the authoring slot' || bad 'proxy refuses the authoring slot' "rc ${rc}"
  has 'and points at the pool'"'"'s block' "${out}" 'hdw4s pool proxy'

  # The other readers of the same file, which have no ETCDIR to derive it from
  # and spell it out. One name in four places: each is read here, and the unit's
  # ORDER is asserted, because the file wins only by coming between.
  name="$(sed -n "s/^POOL_CONF_NAME='\(.*\)'$/\1/p" "${ROOT}/hdw4s")"
  is 'the tool names the file' "${name}" '_hdw4s_pool.conf'
  is 'the unit reads it between the machine'"'"'s and the seat'"'"'s' \
     "$(sed -n 's/^EnvironmentFile=-//p' "${ROOT}/hdw4s-ephemeral@.service" | tr '\n' ' ')" \
     "/etc/hdw4s/hdw4s.conf /etc/hdw4s/${name} /etc/hdw4s/%i.conf "
  has 'the session sources it' "$(cat "${ROOT}/hdw4s-session")" "pool_conf='/etc/hdw4s/${name}'"
  has 'the router reads it'    "$(cat "${ROOT}/hdw4s-demux")" "POOL_CONF_NAME = \"${name}\""
  # The router's reading, in the same order: seat, pool, machine.
  printf 'HDW4S_IDLE_DAYS=3h\n' > "$(pool_conf)"
  printf 'HDW4S_IDLE_DAYS=9h\n' > "${CONF}"
  rm -f "${ETCDIR}/_hdw4s_0.conf"
  got="$(HDW4S_ETCDIR="${ETCDIR}" python3 - "${ROOT}/hdw4s-demux" <<'PY'
import importlib.machinery, importlib.util, sys
sys.dont_write_bytecode = True
l = importlib.machinery.SourceFileLoader("demux", sys.argv[1])
m = importlib.util.module_from_spec(importlib.util.spec_from_loader("demux", l))
l.exec_module(m)
print(m.read_idle_window("_hdw4s_0")[0])
PY
)"
  is 'the router reads the pool'"'"'s window before the machine'"'"'s' "${got}" '10800'

  # The real dispatcher: each sub-command's shape.
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" pool set >/dev/null 2>&1
  is 'pool set with nothing is a usage error' "$?" '2'
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" pool proxy extra >/dev/null 2>&1
  is 'pool proxy takes nothing' "$?" '2'
)

echo '== list sums the pool up in one line, and lists seats only when asked =='
( set +e; sandbox; . "${SB}/setup.sh"
  # The people table used to carry every seat of the pool as if it were a person
  # called "ephemeral3", and said nothing about how full the pool was -- the one
  # thing about it an administrator acts on, and only in time if told before it
  # is full.
  me="$(id -un)"
  RUNDIR="${SB}/run"; POOLDIR="${SB}/demux"; TEARDOWNDIR="${SB}/teardown"
  ENDINGDIR="${SB}/ending"
  mkdir -p "${RUNDIR}/session/_hdw4s_1"; printf ':12\n' > "${RUNDIR}/session/_hdw4s_1/display"
  printf '%s\n' "0 ${me}" '1000 _hdw4s_0 ephemeral' '1001 _hdw4s_1 ephemeral' \
    '1002 _hdw4s_2 ephemeral' '1003 _hdw4s_3 ephemeral' '1004 _hdw4s_4 ephemeral' \
    '1005 tmpl template' > "${SLOTS}"
  CALLS="${SB}/calls"; : > "${CALLS}"
  systemctl() { echo "systemctl $*" >> "${CALLS}"
    case "$*" in show*) for u in "${@:8}"; do
      printf 'Id=%s\nActiveState=%s\nEnvironment=\n\n' "${u}" \
        "$(case "${u}" in *_hdw4s_1*) echo active;; *) echo inactive;; esac)"; done;; esac; }
  out="$(cmd_list 2>/dev/null)"
  has   'the person'"'"'s desktop is listed' "${out}" "${me}"
  hasnt 'no seat is listed as a desktop'   "${out}" '_hdw4s_0 '
  hasnt 'nor the authoring slot'           "${out}" 'tmpl'
  has   'the pool is one line'             "${out}" 'Ephemeral pool: 5 seat(s), 1 in use.'
  hasnt 'and is not called nearly full at 1 of 5' "${out}" 'Nearly full'
  has   'and says how to see the seats'    "${out}" 'hdw4s list --seats'
  # FAST: one question to systemd for the whole table, seats included. The pool
  # line asks whether each seat is busy, and must not ask systemd again per seat.
  is    'one systemctl call for the whole listing' "$(command grep -c '^systemctl' "${CALLS}")" '1'
  # 80%, and the other kinds of busy the pool's own sizing reads: a fresh
  # reservation and a teardown make 3 of 5, which is not yet 80%; a fourth is.
  mkdir -p "${POOLDIR}/reserved" "${TEARDOWNDIR}"
  : > "${POOLDIR}/reserved/_hdw4s_2"; : > "${TEARDOWNDIR}/_hdw4s_3"
  out="$(cmd_list 2>/dev/null)"
  has   'every kind of busy counts'           "${out}" '5 seat(s), 3 in use.'
  hasnt 'and 60% is not nearly full'          "${out}" 'Nearly full'
  mkdir -p "${RUNDIR}/session/_hdw4s_4"
  out="$(cmd_list 2>/dev/null)"
  has   'at 80% it says the pool is nearly full' "${out}" 'Nearly full'
  has   'and how to add seats'                    "${out}" 'hdw4s pool size <N>'
  # --seats: every seat and the authoring slot, with display and what holds it.
  out="$(cmd_list --seats 2>/dev/null)"
  has   'list --seats shows each seat'          "${out}" '_hdw4s_0'
  has   'and the authoring slot'                "${out}" 'tmpl               template'
  # The LETTING column sits between them: "(root)" unprivileged, and as root
  # whatever the machine's router says -- so it is skipped, not asserted, here.
  row="$(awk '$5 != "" { $5 = "X" } { print }' <<<"$(command grep ':12 ' <<<"${out}")")"
  has   'and a seat'"'"'s display and why it is held' "${row}" ':12 X a desktop is running in it'
  hasnt 'and not the person'"'"'s desktop'      "${out}" "${me} "
  HDW4S_ETCDIR="${SB}/etc" bash "${ROOT}/hdw4s" list --bogus >/dev/null 2>&1
  is    'list takes only --seats' "$?" '2'
)

echo '== seats take no index from the port block =='
( set +e; sandbox; . "${SB}/setup.sh"
  # A pool of 70 failed at its 64th seat with "all 64 session slots are in use",
  # on a machine with no named desktops at all: every seat took an index from
  # the block although no seat ever listens on a port.
  rm -f "${SLOTS}"; HDW4S_BLOCK_SIZE=4
  for i in $(seq 0 69); do alloc_slot "eph${i}" ephemeral >/dev/null 2>&1 || break; done
  is  'seventy seats fit beside a block of four' "$(awk '$3 == "ephemeral"' "${SLOTS}" | wc -l | tr -d ' ')" '70'
  is  'and none is numbered inside the block' \
      "$(awk '$1 !~ /^#/ && $1 < 4' "${SLOTS}" | wc -l | tr -d ' ')" '0'
  alloc_slot tmpl template >/dev/null 2>&1
  is  'nor is the authoring slot' "$(slot_of tmpl)" '1070'
  for p in a b c d; do alloc_slot "${p}" desktop >/dev/null 2>&1; done
  is  'a person'"'"'s desktop still takes the block, from the bottom' "$(slot_of a):$(slot_of d)" '0:3'
  alloc_slot e desktop >/dev/null 2>&1; rc=$?
  [ "${rc}" -ne 0 ] && ok 'and a fifth is refused at a block of four' \
    || bad 'and a fifth is refused at a block of four' "rc ${rc}"
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
  POOLDIR="${SB}/demux"; TEARDOWNDIR="${SB}/teardown"; ENDINGDIR="${SB}/ending"
  mkdir -p "${NSDIR}" "${USERDB}" "${RUNDIR}/session" "${POOLDIR}/reserved" "${TEARDOWNDIR}"
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
  is  'growing offers the new seats' "$(rows)" '_hdw4s_0 _hdw4s_1 _hdw4s_2 '
  is  'and writes the setting the next boot reads' \
      "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=3'
  has 'and the setting was written BEFORE a seat was minted' \
      "$(cat "${CALLS}")" 'minted _hdw4s_0 when the file said HDW4S_EPHEMERAL_SLOTS=3'
  # Mint, then row, for every seat: a row before its identity is the one
  # disagreement that costs a visitor a desktop.
  is  'and every seat was minted before its row was written' \
      "$(command grep -E '^(minted|enable_slot)' "${CALLS}" | cut -d' ' -f1-3 | tr '\n' ';')" \
      'minted _hdw4s_0 when;enable_slot ephemeral _hdw4s_0;minted _hdw4s_1 when;enable_slot ephemeral _hdw4s_1;minted _hdw4s_2 when;enable_slot ephemeral _hdw4s_2;'
  # Again with the same number changes nothing.
  : > "${CALLS}"
  (pool_resize 3) >/dev/null 2>&1
  hasnt 'the same size again mints nothing' "$(cat "${CALLS}")" 'minted'
  out="$(pool_show)"
  has 'pool size with no number reports the size' "${out}" 'has 3 seat(s); 0 in use'

  # SHRINKING PAST A VISITOR. _hdw4s_2 has a desktop running, whoever is or
  # is not looking at it: nothing may be taken, and the command says so.
  mkdir -p "${RUNDIR}/session/_hdw4s_2"
  out="$( (pool_resize 1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'shrinking past a busy seat fails' || bad 'shrinking past a busy seat fails' "rc ${rc}"
  is  'and takes no seat' "$(rows)" '_hdw4s_0 _hdw4s_1 _hdw4s_2 '
  is  'and leaves its identity' "$([ -f "${NSDIR}/_hdw4s_2/passwd" ] && echo kept)" 'kept'
  has 'and names the seat and why' "${out}" '_hdw4s_2: a desktop is running in it'
  has 'and how to end it, if that is the decision' "${out}" 'systemctl stop hdw4s-ephemeral@_hdw4s_2.service'
  hasnt 'and stopped no desktop' "$(cat "${CALLS}")" 'stop hdw4s-ephemeral@_hdw4s_2'
  is  'and the setting still says 3' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=3'
  has 'pool size shows it in use' "$(pool_show)" '_hdw4s_2         a desktop is running in it'

  # A busy seat LOWER down holds the pool one above it; seats above it go.
  rmdir "${RUNDIR}/session/_hdw4s_2"; mkdir -p "${RUNDIR}/session/_hdw4s_1"
  : > "${CALLS}"
  out="$( (pool_resize 0) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a busy seat lower down still fails the command' \
    || bad 'a busy seat lower down still fails the command' "rc ${rc}"
  is  'the seats above it go, the seats below it stay' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  is  'and the setting says what the pool is' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=2'
  is  'and the identity of the seat that went is gone' "$([ -e "${NSDIR}/_hdw4s_2" ] && echo left || echo gone)" 'gone'
  has 'and its own unit was stopped, by name' "$(cat "${CALLS}")" 'stop hdw4s-proxy@_hdw4s_2.service hdw4s-ephemeral@_hdw4s_2.service'
  has 'and its watchers' "$(cat "${CALLS}")" 'stop hdw4s-teardown@_hdw4s_2.path hdw4s-start@_hdw4s_2.path'
  has 'and it says it is 2, not 0' "${out}" 'has 2 seat(s)'
  rmdir "${RUNDIR}/session/_hdw4s_1"

  # THE OTHER THREE KINDS OF BUSY. A fresh reservation is a visitor on the way;
  # a stale one is not. A unit starting has no runtime directory yet.
  touch "${POOLDIR}/reserved/_hdw4s_1"
  out="$( (pool_resize 1) 2>&1 )"
  is  'a fresh reservation holds its seat' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  has 'and says so' "${out}" 'a visitor has just been handed it'
  touch -d '-1 hour' "${POOLDIR}/reserved/_hdw4s_1"
  is  'a stale one does not' "$(seat_busy _hdw4s_1)" ''
  systemctl() { echo "systemctl $*" >> "${CALLS}"
                case "$*" in *'ActiveState'*_hdw4s_1*) echo activating;; esac
                [ "$1" != is-active ]; }
  out="$( (pool_resize 1) 2>&1 )"
  is  'a starting unit holds its seat' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  has 'and says so' "${out}" 'its desktop is activating'
  systemctl() { echo "systemctl $*" >> "${CALLS}"; [ "$1" != is-active ]; }
  mkdir -p "${ENDINGDIR}"; : > "${ENDINGDIR}/_hdw4s_1"
  out="$( (pool_resize 1) 2>&1 )"
  is  'a seat being torn down holds too' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  rm -f "${ENDINGDIR}/_hdw4s_1"

  # THE ROUTER LETTING A SEAT WHILE IT IS BEING TAKEN. The row goes first, then
  # the wait, then a second look: a letting that read the table before the row
  # went shows up as a reservation, and the seat goes back on offer as it was.
  before="$(grep _hdw4s_1 "${SLOTS}")"
  sleep() { touch "${POOLDIR}/reserved/_hdw4s_1"; }
  out="$( (pool_resize 1) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat let during the wait fails the command' \
    || bad 'a seat let during the wait fails the command' "rc ${rc}"
  is  'and its row is put back exactly' "$(grep _hdw4s_1 "${SLOTS}")" "${before}"
  is  'and its identity is kept' "$([ -f "${NSDIR}/_hdw4s_1/passwd" ] && echo kept)" 'kept'
  sleep() { :; }
  rm -f "${POOLDIR}/reserved/_hdw4s_1"
  (pool_resize 1) >/dev/null 2>&1
  is  'once it is idle, it goes' "$(rows)" '_hdw4s_0 '

  # THE LOCK IS ROOT'S ALONE. flock needs only a read descriptor, so a lock file
  # anybody can read is one anybody can hold, and every resize is then refused.
  is  'the pool lock is 0600' "$(stat -c %a "${RUNDIR}/pool.lock")" '600'

  # ONE AT A TIME: a second run is refused while the first holds the lock, and
  # changes nothing.
  out="$( exec {held}>"${RUNDIR}/pool.lock"; flock "${held}"; (pool_resize 3) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a second pool size at once is refused' \
    || bad 'a second pool size at once is refused' "rc ${rc}"
  has 'and says why' "${out}" 'another "hdw4s pool size" is running'
  is  'and changed nothing' "$(rows)" '_hdw4s_0 '

  # LARGER THAN THE MINTER CAN MAKE: refused before anything is written.
  out="$( (POOL_MAX=2 pool_resize 3) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a size beyond the uid window is refused' \
    || bad 'a size beyond the uid window is refused' "rc ${rc}"
  is  'and nothing was written' "$(rows):$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" '_hdw4s_0 :HDW4S_EPHEMERAL_SLOTS=1'

  # A SEAT THAT CANNOT BE MINTED (a real account by that name, say) ends the
  # growth there, and the setting comes back down: left at the larger number,
  # the boot's minter would die on it and take every seat with it.
  out="$( (MINT_FAILS=_hdw4s_2 pool_resize 4) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a failed mint fails the command' || bad 'a failed mint fails the command' "rc ${rc}"
  is  'the seats before it are offered' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  is  'and the setting matches them' "$(grep '^HDW4S_EPHEMERAL_SLOTS=' "${CONF}")" 'HDW4S_EPHEMERAL_SLOTS=2'
  has 'and says where it stopped' "${out}" 'stopped growing at 2'
  # And a row above it with no identity -- what the old procedure could leave --
  # is not left offered with nothing behind it.
  printf '%s\n' '9 _hdw4s_3 ephemeral' >> "${SLOTS}"
  out="$( (MINT_FAILS=_hdw4s_2 pool_resize 4) 2>&1 )"
  is  'a row above the stop with no identity is taken back' "$(rows)" '_hdw4s_0 _hdw4s_1 '

  # AN INSTALL SIZED THE OLD WAY, half done: rows above the setting, a row the
  # minter never makes, a seat minted with no row. "pool size" reports it and
  # the same number settles it.
  printf '%s\n' '0 alice' '1 _hdw4s_0 ephemeral' '2 _hdw4s_1 ephemeral' \
    '3 _hdw4s_2 ephemeral' '4 _hdw4s_3 ephemeral' '5 oddseat ephemeral' > "${SLOTS}"
  printf 'HDW4S_EPHEMERAL_SLOTS=2\n' > "${CONF}"; HDW4S_EPHEMERAL_SLOTS=2
  mkdir -p "${NSDIR}/_hdw4s_5"; : > "${NSDIR}/_hdw4s_5/passwd"
  out="$(pool_show)"
  has 'pool size reports rows the next boot will not mint' "${out}" '_hdw4s_2 _hdw4s_3 oddseat'
  has 'and the command that settles it' "${out}" 'hdw4s pool size 2'
  (pool_resize 2) >/dev/null 2>&1
  is  'and settling it leaves exactly the seats' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  is  'and a person'"'"'s desktop alone' "$(slot_of alice)" '0'
  is  'and the identity above the size is gone' "$([ -e "${NSDIR}/_hdw4s_5" ] && echo left || echo gone)" 'gone'

  # A TABLE OFFERING ROWS THAT ARE NOT SEATS. "pool size" with the same
  # number replaces them, because
  # a row that is not a seat is the first thing it takes away -- and that is
  # the repair the boot's refusal and "hdw4s check" both name.
  printf '%s\n' '0 alice' '1 ephemeral0 ephemeral' '2 ephemeral1 ephemeral' > "${SLOTS}"
  printf 'HDW4S_EPHEMERAL_SLOTS=2\n' > "${CONF}"; HDW4S_EPHEMERAL_SLOTS=2
  rm -rf "${NSDIR:?}"/*; : > "${CALLS}"
  out="$(pool_show)"
  has 'pool size names the rows that are not seats' "${out}" 'not minted at the next boot: ephemeral0 ephemeral1'
  has 'and says what seats are called now' "${out}" 'Seats are named _hdw4s_0, _hdw4s_1, ...'
  (pool_resize 2) >/dev/null 2>&1
  is  'and the same size replaces them with seats' "$(rows)" '_hdw4s_0 _hdw4s_1 '
  has 'and the old seats'"'"' units were stopped by name' "$(cat "${CALLS}")" \
      'stop hdw4s-proxy@ephemeral0.service hdw4s-ephemeral@ephemeral0.service'
  is  'and a person'"'"'s desktop is left alone' "$(slot_of alice)" '0'
  # The CLI's own reading of a name, both ways round.
  is  'an old name is no seat' "$(seat_index ephemeral0)" ''
  is  'a new one is' "$(seat_index _hdw4s_7)" '7'
  is  'and the authoring slot is not one' "$(seat_index _hdw4s_author)" ''

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
  out="$(m --seat _hdw4s_3)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat beyond the setting is refused' || bad 'a seat beyond the setting is refused' "rc ${rc}"
  has 'and says to raise the setting first' "${out}" 'raise the'
  out="$(m --seat _hdw4s_01)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a seat number written another way is refused' \
    || bad 'a seat number written another way is refused' "rc ${rc}"
  out="$(m --seat alice)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a name that is not a seat is refused' || bad 'a name that is not a seat is refused' "rc ${rc}"
  printf 'HDW4S_EPHEMERAL_SLOTS=99\n' > "${SB}/etc/hdw4s.conf"
  out="$(m --seat _hdw4s_98)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a pool grown into the template uids is refused' \
    || bad 'a pool grown into the template uids is refused' "rc ${rc}"
  has 'and names the largest it can be' "${out}" 'largest pool here is'
  # A pool of zero is a machine that serves only named desktops.
  printf 'HDW4S_EPHEMERAL_SLOTS=0\n' > "${SB}/etc/hdw4s.conf"
  out="$(m --seat _hdw4s_0)"
  has 'zero is a size, and has no seats' "${out}" 'beyond HDW4S_EPHEMERAL_SLOTS=0'
)

echo '== the boot run refuses a table that offers rows that are not seats =='
# THE OWNER'S RULING, 2026-09-30: the seats are _hdw4s_0 .. _hdw4s_N-1, so a table
# offering any other name ("ephemeral0" here) must fail LOUDLY rather than
# half-work -- the router offering rows nothing mints, while the seats are minted
# for nobody. The whole boot run is executed here, in a
# sandbox: every path it writes is a variable pointed below ${SB}, and the three
# commands that would reach the machine are functions exported over the real ones
# (bash prefers a function to anything on the PATH the script pins). A pool of ZERO
# keeps the minting loop empty, so the one thing that varies between the arms below
# is the table.
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc" "${SB}/dconf"
  printf 'HDW4S_EPHEMERAL_SLOTS=0\n' > "${SB}/etc/hdw4s.conf"
  systemctl() { echo "systemctl $*" >> "${SB}/calls"; }
  getent() { [ "$1 $2" = 'group hdw4s-relay' ] && echo 'hdw4s-relay:x:999:' && return 0
             command getent "$@"; }
  # The real install, without the group: an unprivileged caller cannot chgrp.
  install() { local args=(); while [ $# -gt 0 ]; do
                case "$1" in -g) shift 2;; *) args+=("$1"); shift;; esac; done
              command install "${args[@]}"; }
  export -f systemctl getent install
  boot() { HDW4S_ETCDIR="${SB}/etc" HDW4S_USERDB_DIR="${SB}/userdb" \
           HDW4S_NS_DIR="${SB}/ns" HDW4S_PROFILE_ROOT="${SB}/profile" \
           HDW4S_DROPIN_DIR="${SB}/system" HDW4S_PROXY_RUNDIR="${SB}/proxy" \
           HDW4S_TEARDOWN_DIR="${SB}/teardown" HDW4S_START_DIR="${SB}/start" \
           HDW4S_INVITE_DIR="${SB}/invite" HDW4S_INCARNATION_DIR="${SB}/incarn" \
           HDW4S_STREAM_DIR="${SB}/stream" HDW4S_DCONF_DB_DIR="${SB}/no-dconf" \
           "${1:-${ROOT}/hdw4s-ephemeral-slots}" 2>&1; }

  # THE CONTROL: the same run, a table with only a person and a seat-shaped row.
  printf '%s\n' '0 alice' '1 _hdw4s_0 ephemeral' > "${SB}/etc/instances"
  out="$(boot)"; rc=$?
  is  'a table of seats boots' "${rc}" '0'
  has 'and says what it minted' "${out}" 'minted 0 ephemeral slot(s) from _hdw4s_0'

  # THE OLD NAMES, as an upgraded install has them.
  printf '%s\n' '0 alice' '1 ephemeral0 ephemeral' '2 ephemeral1 ephemeral' \
    '3 _hdw4s_01 ephemeral' > "${SB}/etc/instances"
  rm -f "${SB}/calls"
  out="$(boot)"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'a table with rows that are not seats fails the boot run' \
    || bad 'a table with rows that are not seats fails the boot run' "rc ${rc}: ${out}"
  has 'and names every row that is not a seat' "${out}" 'never mints: ephemeral0 ephemeral1 _hdw4s_01'
  has 'and what the seats are called now' "${out}" 'named _hdw4s_0, _hdw4s_1, ...'
  has 'and the command that replaces them' "${out}" 'hdw4s pool size 0'
  has 'and how to start the pool after' "${out}" 'systemctl start hdw4s-ephemeral-slots.service'
  hasnt 'and does not claim to have minted anything' "${out}" 'minted 0 ephemeral'
  # Everything that is the WHOLE MACHINE'S was still done: named desktops need
  # the run directories and the slice's brake whatever the pool's state.
  is  'but the run directories were made first' \
    "$([ -d "${SB}/stream" ] && [ -d "${SB}/proxy" ] && echo made)" 'made'
  is  'and the slice memory brake was still written' \
    "$([ -s "${SB}/system/hdw4s.slice.d/10-memory-high.conf" ] && echo written)" 'written'

  # NOTHING OF THE POOL IS MINTED while the old rows are there: on a machine
  # upgraded without a reboot the old seats still hold the same uids.
  printf 'HDW4S_EPHEMERAL_SLOTS=2\n' > "${SB}/etc/hdw4s.conf"
  printf '%s\n' '1 ephemeral0 ephemeral' > "${SB}/etc/instances"
  out="$(boot)"
  is  'and no seat identity is written beside them' \
    "$(n=0; for f in "${SB}"/ns/_hdw4s_* "${SB}"/userdb/_hdw4s_*; do
         [ ! -e "${f}" ] || n=$(( n + 1 )); done; echo "${n}")" '0'
  has 'and the size it names is the configured one' "${out}" 'hdw4s pool size 2'

  # RED ARM: the refusal taken out, the same table boots quietly -- the
  # half-working shape this exists to stop.
  # shellcheck disable=SC2016  # the pattern names the script's own ${RETIRED}
  sed 's|^  \[ -z "\${RETIRED}" \] \|\| i=|  : \|\| i=|; s|^elif \[ -n "\${RETIRED}" \]; then$|elif false; then|' \
    "${ROOT}/hdw4s-ephemeral-slots" > "${SB}/red-minter"
  chmod +x "${SB}/red-minter"
  is  'RED ARM: the edit took' "$(grep -c 'elif false; then' "${SB}/red-minter")" '1'
  printf 'HDW4S_EPHEMERAL_SLOTS=0\n' > "${SB}/etc/hdw4s.conf"
  printf '%s\n' '1 ephemeral0 ephemeral' > "${SB}/etc/instances"
  boot "${SB}/red-minter" >/dev/null; rc=$?
  is  'RED ARM: without the refusal the same table boots silently' "${rc}" '0'

  # The --seat path, which "pool size" uses, and the CLI's own reading of a name.
  out="$(boot "${ROOT}/hdw4s-ephemeral-slots" 2>&1; HDW4S_ETCDIR="${SB}/etc" \
         "${ROOT}/hdw4s-ephemeral-slots" --seat ephemeral0 2>&1)"
  has 'the minter refuses to mint an old name as a seat' "${out}" \
    'ephemeral0 is not a seat of this pool; seats are _hdw4s_0, _hdw4s_1'

  # TWO COPIES OF ONE NAME, because "hdw4s" has no other way to know it: held
  # together here, so that editing one turns this red.
  cli="$(sed -n "s/^SEAT_PREFIX=//p" "${ROOT}/hdw4s")"
  is  'the CLI spells the seat prefix' "${cli}" "'_hdw4s_'"
  is  'and the minter spells it the same' "$(sed -n "s/^SEAT_PREFIX=//p" "${ROOT}/hdw4s-ephemeral-slots")" "${cli}"
)


# THE /SHARED WIRING (seat B's group): the boot run's drop-ins and knobs, the
# tmpfiles line, the expose service's decisions, and the "hdw4s check" rows.
# The guard itself is hdw4s-shared-sweep's and is tested with it; here it is a
# stand-in that answers as told, so that every branch of the CALLERS is seen
# taking both directions. Real mounts are not made here (the suite runs
# unprivileged, in CI too); what a mount, a bind and propagation do is the
# integration's to show on a machine.
group_shared_wiring() {
echo '== /shared: the boot run binds it only when asked, never optionally, and takes it away =='
# Off means NONE of its files: a drop-in left behind is a /shared nobody turned
# on. On means the desktops bind /run/hdw4s/shared, which always exists, and
# NEVER with "-": an optional bind whose source is missing leaves an existing
# /shared on the root filesystem writable from every desktop (systemd 255).
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc" "${SB}/var"
  printf '%s\n' '1 _hdw4s_0 ephemeral' > "${SB}/etc/instances"
  # list-units answers from ${SB}/units, as systemctl prints it, and fails
  # when ${SB}/units-fail exists: systemd that cannot be asked.
  systemctl() { echo "systemctl $*" >> "${SB}/calls"
                [ "$1" != 'list-units' ] ||
                  { [ ! -e "${SB}/units" ] || cat "${SB}/units"; [ ! -e "${SB}/units-fail" ]; }; }
  getent() { [ "$1 $2" = 'group hdw4s-relay' ] && echo 'hdw4s-relay:x:999:' && return 0
             command getent "$@"; }
  install() { local args=(); while [ $# -gt 0 ]; do
                case "$1" in -g) shift 2;; *) args+=("$1"); shift;; esac; done
              command install "${args[@]}"; }
  # SB exported: the stand-ins run inside the boot run, which has nounset on,
  # and one naming an unset SB fails the run instead of recording the call.
  export -f systemctl getent install; export SB
  boot() { : > "${SB}/calls"
           HDW4S_ETCDIR="${SB}/etc" HDW4S_USERDB_DIR="${SB}/userdb" \
           HDW4S_NS_DIR="${SB}/ns" HDW4S_PROFILE_ROOT="${SB}/profile" \
           HDW4S_DROPIN_DIR="${SB}/system" HDW4S_PROXY_RUNDIR="${SB}/proxy" \
           HDW4S_TEARDOWN_DIR="${SB}/teardown" HDW4S_START_DIR="${SB}/start" \
           HDW4S_INVITE_DIR="${SB}/invite" HDW4S_INCARNATION_DIR="${SB}/incarn" \
           HDW4S_STREAM_DIR="${SB}/stream" HDW4S_DCONF_DB_DIR="${SB}/no-dconf" \
           HDW4S_SHARED_MARK="${SB}/var/.shared-mountpoint" \
           HDW4S_SHARED_MOUNTPOINT="${SB}/shared" \
           HDW4S_SHARED_EXPOSE="${SB}/run/hdw4s/shared" HDW4S_SHARED_VIEW_STATE="${SB}/view" \
           "${ROOT}/hdw4s-ephemeral-slots" 2>&1; }
  conf() { printf '%s\n' 'HDW4S_EPHEMERAL_SLOTS=0' "$@" > "${SB}/etc/hdw4s.conf"; }
  d1="${SB}/system/hdw4s@.service.d/50-shared.conf"
  d2="${SB}/system/hdw4s-ephemeral@.service.d/50-shared.conf"
  tmpfs_knobs="${SB}/system/hdw4s-shared-sweep@run-hdw4s-shared\\x2dstore.service.d/50-knobs.conf"
  any() { local f; for f in "$@"; do [ -e "${f}" ] && { echo there; return; }; done; echo absent; }

  conf; out="$(boot)"; rc=$?
  is  'off by default: the boot run succeeds' "${rc}" '0'
  is  'and writes no drop-in for either desktop' "$(any "${d1}" "${d2}")" 'absent'
  is  'and no sweep settings' "$(any "${SB}"/system/hdw4s-shared-sweep@*)" 'absent'
  hasnt 'and starts nothing every 30 seconds' "$(cat "${SB}/calls")" 'hdw4s-shared-expose'
  hasnt 'and says nothing about /shared' "${out}" 'HDW4S_SHARED'

  conf HDW4S_SHARED=tmpfs HDW4S_SHARED_IDLE=45m HDW4S_SHARED_MAX_AGE=3d
  out="$(boot)"; rc=$?
  is  'tmpfs: the boot run succeeds' "${rc}" '0'
  is  'named desktops bind /run/hdw4s/shared as /shared' \
    "$(grep '^BindPaths=' "${d1}" 2>/dev/null)" 'BindPaths=/run/hdw4s/shared:/shared'
  is  'and so do ephemeral ones' \
    "$(grep '^BindPaths=' "${d2}" 2>/dev/null)" 'BindPaths=/run/hdw4s/shared:/shared'
  # RED ARM in the assertion: "-/" anywhere in a directive line is the optional
  # form, whatever path follows it.
  hasnt 'never the optional form' "$(grep -h '^[A-Za-z]*Paths=' "${d1}" "${d2}" 2>/dev/null)" '=-'
  hasnt 'and never the store, which may be absent or dead' "$(cat "${d1}" "${d2}" 2>/dev/null)" 'shared-store'
  has 'the expose timer is started, with the first run' "$(cat "${SB}/calls")" \
    'start --no-block hdw4s-shared-expose.timer hdw4s-shared-expose.service'
  hasnt 'and never enabled' "$(cat "${SB}/calls")" 'enable'
  has 'the sweep gets IDLE verbatim, under the store root it is named after' \
    "$(cat "${tmpfs_knobs}" 2>/dev/null)" 'Environment=HDW4S_SHARED_IDLE=45m'
  has 'and MAX_AGE' "$(cat "${tmpfs_knobs}" 2>/dev/null)" 'Environment=HDW4S_SHARED_MAX_AGE=3d'
  is  'the mount point is marked as this feature'"'"'s to remove' \
    "$(any "${SB}/var/.shared-mountpoint")" 'there'

  conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SWEEP=external; boot >/dev/null
  is  'SWEEP=external: no sweep settings on this machine' \
    "$(any "${SB}"/system/hdw4s-shared-sweep@*/50-knobs.conf)" 'absent'
  is  'but the desktops still bind it' "$(any "${d1}")" 'there'

  conf HDW4S_SHARED=source HDW4S_SHARED_SOURCE=/srv/hdw4s-shared; boot >/dev/null
  is  'source: the sweep is named after HDW4S_SHARED_SOURCE' \
    "$(any "${SB}/system/hdw4s-shared-sweep@srv-hdw4s\\x2dshared.service.d/50-knobs.conf")" 'there'
  is  'and the tmpfs store'"'"'s settings went with the change' "$(any "${tmpfs_knobs}")" 'absent'

  # A value that could be a "%" specifier or a quote never reaches a unit file.
  conf HDW4S_SHARED=tmpfs 'HDW4S_SHARED_IDLE=30m%n'; out="$(boot)"
  hasnt 'a duration with a stray character is not written' "$(cat "${tmpfs_knobs}" 2>/dev/null)" 'IDLE'
  has 'and is refused out loud' "${out}" 'is not a duration'

  # A size is not a switch: only HDW4S_SHARED turns the feature on.
  conf HDW4S_SHARED_SIZE=1G; out="$(boot)"; rc=$?
  is  'HDW4S_SHARED_SIZE alone does not turn it on' "$(any "${d1}" "${d2}")" 'absent'
  is  'and the boot succeeds' "${rc}" '0'

  # A typo in an optional feature must not take the pool down with it.
  conf HDW4S_SHARED=yes; out="$(boot)"; rc=$?
  is  'an unknown mode does not fail the boot run that mints the pool' "${rc}" '0'
  has 'it is refused out loud' "${out}" "not 'yes'"
  is  'and /shared stays off' "$(any "${d1}" "${d2}")" 'absent'

  # Back to off, from on, without a reboot (an upgrade re-runs this).
  conf HDW4S_SHARED=tmpfs; boot >/dev/null
  mkdir -p "${SB}/shared"
  conf; boot >/dev/null
  is  'turned off: every drop-in is gone' "$(any "${d1}" "${d2}" "${tmpfs_knobs}")" 'absent'
  is  'and the empty mount point this feature made' "$(any "${SB}/shared")" 'absent'
  is  'and its mark' "$(any "${SB}/var/.shared-mountpoint")" 'absent'
  # One that was there before the feature was turned on is not ours.
  mkdir -p "${SB}/shared"; conf HDW4S_SHARED=tmpfs; boot >/dev/null; conf; boot >/dev/null
  is  'a /shared that existed before is left alone' "$(any "${SB}/shared")" 'there'
  rmdir "${SB}/shared"

  # THE MARK GOES ONLY WITH THE DIRECTORY. It is the only record that /shared
  # is this feature's; dropped while the directory stays, the next boot reads
  # /shared as the administrator's and never touches it again.
  conf HDW4S_SHARED=tmpfs; boot >/dev/null; mkdir -p "${SB}/shared"; : > "${SB}/shared/kept"
  conf; out="$(boot)"; rc=$?
  is  'turned off with /shared not empty: the boot run still succeeds' "${rc}" '0'
  is  'and /shared is kept (rmdir, never rm)' "$(any "${SB}/shared/kept")" 'there'
  is  'RED ARM: and so is its mark, because the rmdir failed' "$(any "${SB}/var/.shared-mountpoint")" 'there'
  has 'and it says so' "${out}" 'could not be removed'
  rm -f "${SB}/shared/kept"; rmdir "${SB}/shared"; rm -f "${SB}/var/.shared-mountpoint"

  # NEVER WHILE A DESKTOP RUNS (design M4, measured): removing a directory that
  # is a mount point in a desktop's namespace succeeds, and DETACHES /shared
  # from that desktop. An upgrade re-runs this live, after HDW4S_SHARED=off was
  # written and before the reboot that was to apply it.
  conf HDW4S_SHARED=tmpfs; boot >/dev/null; mkdir -p "${SB}/shared"
  printf '%s\n' 'hdw4s-ephemeral@_hdw4s_0.service loaded active running hdw4s ephemeral desktop _hdw4s_0' \
    > "${SB}/units"
  conf; out="$(boot)"; rc=$?
  is  'turned off with a desktop active: the boot run still succeeds' "${rc}" '0'
  is  'RED ARM: and /shared is NOT removed from under it' "$(any "${SB}/shared")" 'there'
  is  'and its mark is kept for the run that can' "$(any "${SB}/var/.shared-mountpoint")" 'there'
  has 'and it says which desktop' "${out}" 'hdw4s-ephemeral@_hdw4s_0.service'
  has 'and that the boot run with it off will remove it' "${out}" 'The next boot with HDW4S_SHARED off removes it'
  # Every state but inactive and failed is a desktop that holds the mount.
  for st in activating deactivating reloading; do
    printf '%s\n' "  hdw4s@alice.service loaded ${st} start hdw4s desktop alice" > "${SB}/units"
    boot >/dev/null
    is  "a desktop ${st} also keeps it" "$(any "${SB}/shared")" 'there'
  done
  # systemctl marks a failed unit with a bullet; it is still not running.
  printf '%s\n' '\xe2\x97\x8f hdw4s@bob.service loaded failed failed hdw4s desktop bob' \
         'hdw4s-ephemeral@_hdw4s_1.service loaded inactive dead hdw4s ephemeral desktop' > "${SB}/units"
  printf '%b' "$(cat "${SB}/units")" > "${SB}/units.b"; mv "${SB}/units.b" "${SB}/units"
  : > "${SB}/units-fail"
  out="$(boot)"
  is  'systemd that cannot be asked keeps it too' "$(any "${SB}/shared" "${SB}/var/.shared-mountpoint")" 'there'
  has 'and says why' "${out}" 'could not ask systemd'
  rm -f "${SB}/units-fail"; boot >/dev/null
  is  'only inactive and failed desktops: /shared goes' "$(any "${SB}/shared")" 'absent'
  is  'and only then its mark' "$(any "${SB}/var/.shared-mountpoint")" 'absent'
  rm -f "${SB}/units"

  # ONE IMPLEMENTATION FOR ALL THREE CALLERS. postrm runs after the package's
  # files are gone, so the removal belongs to prerm, where the code still
  # exists; uninstall.sh calls the same code. A copy in either would be the
  # mark-before-rmdir defect again, kept in step by hand.
  hasnt 'RED ARM: postrm no longer removes the mark itself' \
    "$(cat "${ROOT}/debian/postrm")" 'rm -f /var/lib/hdw4s/.shared-mountpoint'
  hasnt 'RED ARM: nor does uninstall.sh' "$(cat "${ROOT}/uninstall.sh")" \
    'rm -f /var/lib/hdw4s/.shared-mountpoint'
  has 'prerm calls the one implementation' "$(cat "${ROOT}/debian/prerm")" \
    'hdw4s-ephemeral-slots --shared-view release-for-removal'
  has 'and so does uninstall.sh' "$(cat "${ROOT}/uninstall.sh")" \
    'hdw4s-ephemeral-slots" --shared-view release-for-removal'
)

echo '== the /shared tool: its guard, its sweep and its relay =='
# hdw4s-shared-sweep is the ONE implementation of the /shared guard: the expose
# service and "hdw4s check" call it rather than repeat it. So its refusals are
# pinned here clause by clause, by the clause TOKEN it prints and never by a
# word of its prose, because a guard refusing for the wrong reason passes every
# test that only asks whether it refused.
#
# Most of this needs real mounts with real flags, which an unprivileged user
# gets only inside a user namespace of its own (unshare -Urm). Where the kernel
# refuses one -- Ubuntu's kernel.apparmor_restrict_unprivileged_userns=1, which
# is the GitHub runner's default until the workflow turns it off -- every
# assertion that needed it is recorded as FAILED with that reason, never
# skipped: a guard nobody has seen refuse is not known to refuse.
( set +e
  W="${ROOT}/hdw4s-shared-sweep"
  T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  # The parser, the source check and the rate limit, with the resolver stood
  # in for: each layer has to be seen refusing on its own (threat T2), or a
  # broken one hides behind the other for ever.
  out="$(python3 - "${W}" <<'PY' 2>&1
import importlib.machinery, importlib.util, os, random, struct, sys
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
H = m.REC_HEAD
def rec(kind, name, fileid=7, flags=0):
    return H.pack(kind, flags, len(name), fileid) + name
V = bytes([1])
good = V + rec(1, b"a/b.txt") + rec(2, b"", 0)
print("accept", len(m.parse_datagram(good)))
bad = {
  "empty": b"", "version": bytes([2]) + rec(1, b"x"), "kind": V + rec(3, b"x"),
  "flags": V + rec(1, b"x", flags=1),
  "length": V + H.pack(1, 0, 9, 7) + b"x",
  "trailing": V + rec(1, b"x") + b"\0",
  "nul": V + rec(1, b"a\0b"), "dotdot": V + rec(1, b"a/../b"),
  "absolute": V + rec(1, b"/etc/hostname"), "emptyname": V + rec(1, b""),
  "dot": V + rec(1, b"./a"), "emptycomp": V + rec(1, b"a//b"),
  "trailslash": V + rec(1, b"a/"), "utf8": V + rec(1, b"\xff\xfe"),
  "long": V + rec(1, b"a" * 4097), "hbname": V + rec(2, b"x", 0),
  "hbfileid": V + rec(2, b"", 5), "oversize": V + rec(1, b"a" * 4000) * 3,
}
taken = []
for k, d in sorted(bad.items()):
    try:
        m.parse_datagram(d); taken.append(k)
    except m.Malformed:
        pass
print("taken", ",".join(taken) or "none", len(bad))
print("mapped", m.source_address(("::ffff:192.0.2.10", 1, 0, 0)))
print("scoped", m.source_address(("fe80::1%eth0", 1, 0, 0)))
class Stub:
    def __init__(self): self.n = 0
    def touch(self, name, fileid): self.n += 1; return "touched"
allow = m.parse_allow("192.0.2.10")
st = Stub(); srv = m.Server(-1, allow, st)
for i in range(10000):
    srv.handle(good, ("::ffff:198.51.%d.%d" % (i // 250, i % 250), 1, 0, 0))
print("strangers", len(srv.sources), srv.other["received"], st.n)
srv.handle(V + rec(1, b"a/../b"), ("192.0.2.10", 1))
print("malformed-acts", st.n)
big = V + b"".join(rec(1, b"f%03d" % i) for i in range(400))
for _ in range(6):
    srv.handle(big, ("192.0.2.10", 1))
print("rate", st.n, srv.counts.get("drop-rate-source", 0))
random.seed(1)
st2 = Stub(); srv2 = m.Server(-1, allow, st2)
for i in range(3000):
    blob = bytes(random.getrandbits(8) for _ in range(random.randrange(0, 64)))
    if i % 2: blob = V + blob
    srv2.handle(blob, ("192.0.2.10", 1))
print("fuzz", sum(v for k, v in srv2.counts.items() if k == "received"),
      len([k for k in srv2.counts if k.startswith("drop-internal")]))
import tempfile
d = tempfile.mkdtemp(); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
open(os.path.join(d, "x"), "w").close(); os.mkdir(os.path.join(d, "sub"))
g = m.Gate(fd); refused = []
for n in ("sub/../x", "..", ".", "", "a/b", "x\0"):
    try:
        g.unlink(fd, n, None)
    except m.Unsafe:
        refused.append(1)
print("names", len(refused), os.path.exists(os.path.join(d, "x")))
srv3 = m.Server(-1, m.parse_allow("192.0.2.10"), Stub()); srv3.started -= 200
print("silence", srv3.silent(120), srv3.silent(1800))
print("sandbox", m.unsandboxed(0, True, False), m.unsandboxed(0, True, True),
      m.unsandboxed(0, False, False), m.unsandboxed(1000, True, False))
m.initial_userns = lambda: True
host = sorted(m._root_uids())
m.initial_userns = lambda: False
# The store rule accepting a root owned by the overflow uid says NOTHING: it is
# every container's steady state and the guard runs there every 30 seconds.
import io, types
ov = int(open("/proc/sys/kernel/overflowuid").read())
sd = tempfile.mkdtemp(); os.mkdir(os.path.join(sd, "table")); sfd = os.open(sd, os.O_RDONLY | os.O_DIRECTORY)
err, sys.stderr = sys.stderr, io.StringIO()
m._store_rule(sfd, types.SimpleNamespace(uid=ov, mode=0o40755), types.SimpleNamespace(root="/"))
said, sys.stderr = sys.stderr.getvalue(), err
print("overflow-quiet", len(said))
print("rootuids", host, sorted(m._root_uids()) == [0, int(open("/proc/sys/kernel/overflowuid").read())])
PY
)"
  is  'the relay parser takes a well-formed batch' "$(sed -n 's/^accept //p' <<<"${out}")" '2'
  is  'and refuses every malformed case, the whole datagram' \
      "$(sed -n 's/^taken //p' <<<"${out}")" 'none 18'
  is  'a v4-mapped source is judged as the v4 address it is' \
      "$(sed -n 's/^mapped //p' <<<"${out}")" '192.0.2.10'
  is  'and a link-local source without its scope' "$(sed -n 's/^scoped //p' <<<"${out}")" 'fe80::1'
  is  '10000 spoofed strangers: one bucket, nothing parsed, nothing touched' \
      "$(sed -n 's/^strangers //p' <<<"${out}")" '0 10000 0'
  is  'a malformed datagram from an allowed source touches nothing' \
      "$(sed -n 's/^malformed-acts //p' <<<"${out}")" '0'
  is  'the rate limit counts announcements, not datagrams' \
      "$(sed -n 's/^rate //p' <<<"${out}")" '2000 400'
  is  'random bytes never escape the per-datagram handler' \
      "$(sed -n 's/^fuzz //p' <<<"${out}")" '3000 0'
  is  'the deletion gate refuses every name that is not one component' \
      "$(sed -n 's/^names //p' <<<"${out}")" '6 True'
  is  'a silent allowed client is warned about after --silence, not before' \
      "$(sed -n 's/^silence //p' <<<"${out}")" "['192.0.2.10'] []"
  is  'root on the host with a writable / is seen as unsandboxed, nothing else' \
      "$(sed -n 's/^sandbox //p' <<<"${out}")" 'True False False False'
  is  'on the host only uid 0 owns a store root; in a container also the overflow uid' \
      "$(sed -n 's/^rootuids //p' <<<"${out}")" '[0] True'
  is  'a store root owned by the overflow uid is accepted without a word' \
      "$(sed -n 's/^overflow-quiet //p' <<<"${out}")" '0'
  is  'and the overflow uid is read from the kernel, never written down' \
      "$(grep -c '65534' "${W}")" '0'

  # PM P12: ProtectSystem=strict leaves /run WRITABLE inside the unit
  # (measured on systemd 255, G3). Every unit of the tool's package that runs
  # as root or holds a DAC/FOWNER capability must say ReadOnlyPaths=/run.
  # harden@ is exempt by design: it remounts in the host's namespace.
  need_ro='' missing_ro=''
  while read -r u; do
    case "${u}" in hdw4s-shared-harden@.service) continue;; esac
    f="${ROOT}/${u}"
    # One grep, no pipe: under pipefail "grep | grep -q" reads as false when
    # the first grep is killed by SIGPIPE after the second has matched.
    if ! grep -qx 'DynamicUser=yes' "${f}" ||
       grep -qE '^(CapabilityBoundingSet|AmbientCapabilities)=.*(DAC_|FOWNER)' "${f}"; then
      need_ro="${need_ro} ${u}"
      grep -qx 'ReadOnlyPaths=/run' "${f}" || missing_ro="${missing_ro} ${u}"
    fi
  done < <(awk '!/^#/ && $2 == "usr/lib/systemd/system" && $1 ~ /\.service$/ {print $1}' \
               "${ROOT}/debian/hdw4s-shared-sweep.install")
  is  'the units that run as root or hold DAC/FOWNER are found' \
      "${need_ro}" ' hdw4s-shared-sweep@.service hdw4s-shared-watch@.service hdw4s-shared-relay-server@.service'
  is  'and every one makes /run read-only, which strict does not' "${missing_ro}" ''

  # No state of the tree, however churned between the look and the call,
  # raises out of a pass (S-fuzz on a box, 2026-10-02: the watcher died of an
  # IsADirectoryError out of its fast path, which a visitor can cause at
  # will). Every errno a racing tree can produce is forced AT each call the
  # sweep, the watcher's pass and its fast path make.
  out="$(python3 - "${W}" <<'PY' 2>&1
# Every per-entry OSError the kernel can return at a call the sweep, the
# watcher's pass or its fast path makes, injected AT the call: none may escape.
import errno, importlib.machinery, importlib.util, os, shutil, sys, tempfile, time
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
ERRNOS = ("EISDIR", "ENOTDIR", "ENOTEMPTY", "ENOENT", "ELOOP", "EBUSY",
          "EPERM", "EACCES", "EROFS", "EIO", "ENAMETOOLONG", "ESTALE")
real = {"unlink": os.unlink, "rmdir": os.rmdir, "fchmod": os.fchmod,
        "listdir": os.listdir, "open": os.open, "statx": m.statx}
fired = {}
def build():
    d = tempfile.mkdtemp()
    os.mkfifo(os.path.join(d, "fifo")); os.symlink("/etc", os.path.join(d, "ln"))
    open(os.path.join(d, "f"), "w").close(); os.chmod(os.path.join(d, "f"), 0o600)
    os.makedirs(os.path.join(d, "a", "b")); os.chmod(os.path.join(d, "a"), 0o700)
    open(os.path.join(d, "a", "g"), "w").close()
    return d
def inject(site, code):
    def boom(*a, **k):
        # Only per-entry calls: never the table's own setup (statx of b"",
        # listdir/open of the table fd itself before the walk starts).
        if site == "statx" and a[1] in (b"", ""):
            return real[site](*a, **k)
        fired[site] = fired.get(site, 0) + 1
        raise OSError(getattr(errno, code), os.strerror(getattr(errno, code)))
    if site == "statx":
        m.statx = boom
    else:
        setattr(os, site, boom)
def restore():
    for k in ("unlink", "rmdir", "fchmod", "listdir", "open"):
        setattr(os, k, real[k])
    m.statx = real["statx"]
escapes = []
for site in ("unlink", "rmdir", "fchmod", "statx", "listdir", "open"):
    for code in ERRNOS:
        for mode in ("sweep", "pass", "fast"):
            d = build(); fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            mnt = m.fstatx(fd).mnt_id
            gate_table = fd
            inject(site, code)
            try:
                c = m.Counts()
                if mode == "sweep":
                    m.sweep(fd, mnt, 1800, 86400, time.time() + 86400, c)
                elif mode == "pass":
                    m.sweep(fd, mnt, 0, 0, time.time(), c, expire=False)
                else:
                    m.fast_path(fd, [b"fifo", b"ln", b"f", b"a"], c)
            except Exception as e:
                escapes.append("%s/%s/%s:%s" % (site, code, mode, type(e).__name__))
            finally:
                restore(); os.close(fd); shutil.rmtree(d, ignore_errors=True)
print("escapes", len(escapes), " ".join(escapes))
print("fired", " ".join("%s=%s" % (k, "yes" if v else "no") for k, v in sorted(fired.items())))
PY
)"
  is  'no errno forced at any call escapes the sweep, the pass or the fast path' \
      "$(sed -n 's/^escapes //p' <<<"${out}" | sed 's/ *$//')" '0'
  is  '  and every call site was actually reached by the fault' \
      "$(sed -n 's/^fired //p' <<<"${out}")" 'fchmod=yes listdir=yes open=yes rmdir=yes statx=yes unlink=yes'

  # The package's maintainer scripts (PM P14): debhelper does not act on
  # template instances, so an upgrade restarts what is RUNNING onto the new
  # code and starts nothing that was not; a removal stops every instance.
  # systemctl is a stand-in that reports one active, one inactive and one
  # failed instance and records everything else it is asked.
  mkdir -p "${T}/bin"
  cat > "${T}/bin/systemctl" <<'SH'
#!/bin/sh
if [ "$1" = 'list-units' ]; then
  printf '%s\n' 'hdw4s-shared-watch@s.service loaded active running w' \
                 'hdw4s-shared-relay-server@s.service loaded inactive dead r' \
                 'hdw4s-shared-relay-client@s.service loaded failed failed c'
  exit 0
fi
echo "$*" >> "${CALLS}"
SH
  chmod +x "${T}/bin/systemctl"
  mscript() { CALLS="${T}/calls" PATH="${T}/bin:${PATH}" sh "${ROOT}/debian/hdw4s-shared-sweep.$1" "$2" >/dev/null 2>&1
              tr '\n' ';' < "${T}/calls" 2>/dev/null; rm -f "${T}/calls"; }
  if [ -d /run/systemd/system ]; then
    is  'an upgrade restarts exactly the instances that were running' \
        "$(mscript postinst configure)" 'daemon-reload;try-restart hdw4s-shared-watch@s.service;'
    is  'a removal stops every instance' "$(mscript prerm remove)" \
        'stop hdw4s-shared-watch@s.service;stop hdw4s-shared-relay-server@s.service;stop hdw4s-shared-relay-client@s.service;'
    is  'and an upgrade stops none' "$(mscript prerm upgrade)" ''
  else
    for _ in 1 2 3; do bad 'maintainer scripts' 'no /run/systemd/system here: the scripts would do nothing'; done
  fi

  # IN-UNIT POSITIVE CONTROL for the calls each role makes (PM P15/P16). The
  # packaged relay server dropped every announcement as resolve-ENOSYS while
  # the same tool by hand worked: RestrictSUIDSGID= turns openat2 into ENOSYS.
  # So each role's real calls run in a transient unit carrying that role's
  # OWN syscall-shaping settings, read from its unit file, not retyped. What
  # this cannot carry (DynamicUser, ProtectSystem, ReadWritePaths, the
  # capability sets) needs root, and is the box's job: private/unit-probe.sh.
  cat > "${T}/sysprobe.py" <<'PY'
# Run each role's REAL system calls inside a transient unit carrying that
# role's OWN syscall-shaping settings, read from its unit file, so a filter
# (or an option that installs one) blocking a call the role needs goes red.
# argv: tool  root(the tree with the unit files)  outer [EXTRA=VALUE]
# EXTRA is one more property for every role: the control that shows the probe
# can go red (RestrictSUIDSGID=yes reproduces the relay's ENOSYS).
import importlib.machinery, importlib.util, os, socket, stat, subprocess, sys, tempfile, time
TOOL, ROOT = sys.argv[1], sys.argv[2]
# Settings that install seccomp filters or otherwise change which calls work.
KEYS = ("SystemCallFilter", "SystemCallErrorNumber", "SystemCallArchitectures",
        "RestrictSUIDSGID", "MemoryDenyWriteExecute", "RestrictNamespaces",
        "LockPersonality", "RestrictRealtime", "PrivateDevices", "ProtectClock",
        "ProtectKernelModules", "ProtectKernelLogs", "ProtectHostname",
        "RestrictAddressFamilies", "NoNewPrivileges")
ROLES = {"server": "hdw4s-shared-relay-server@.service",
         "sweep": "hdw4s-shared-sweep@.service",
         "watch": "hdw4s-shared-watch@.service",
         "client": "hdw4s-shared-relay-client@.service"}

def load():
    l = importlib.machinery.SourceFileLoader("sweep", TOOL)
    sp = importlib.util.spec_from_loader("sweep", l)
    m = importlib.util.module_from_spec(sp); l.exec_module(m); return m

def role(name):
    """The calls the role makes, on scratch files; prints one verdict."""
    m = load()
    d = tempfile.mkdtemp(dir=os.environ.get("PROBE_DIR"))
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    open(os.path.join(d, "f"), "w").close()
    if name == "server":
        ino = os.stat(os.path.join(d, "f")).st_ino
        r = m.Resolver(fd).touch(b"f", ino)
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", 0))
        # The multicast START path, as the server runs it: enumerate the
        # interfaces, open the wildcard socket, join. Under the unit's own
        # RestrictAddressFamilies= -- the real server died EAFNOSUPPORT here.
        try:
            srv = m.Server(-1, [], resolver=object(), group=m.RELAY_GROUP)
            ms = m.multicast_socket(0)
            names, _, _ = m.rejoin(ms, srv, None)
            j = "joined" if names else "joined-none"
        except OSError as e:
            j = "start-%s" % e.strerror
        print(name, r, j)
    elif name in ("sweep", "watch"):
        os.mkfifo(os.path.join(d, "fifo")); os.mkdir(os.path.join(d, "sub"))
        os.chmod(os.path.join(d, "f"), 0o600)
        c = m.Counts()
        m.sweep(fd, m.fstatx(fd).mnt_id, 1800, 86400, time.time() + 86400, c)
        bad = c.errors + sum(c.refused.values())
        if name == "watch":
            m.handle_of(fd); m.capabilities(); m.raise_fd_limit()
            m.fast_path(fd, [b"x"], m.Counts())
            # fanotify_init needs CAP_SYS_ADMIN; EPERM is "allowed, not
            # privileged", ENOSYS is "the filter took it away".
            r = m._libc.fanotify_init(0x1, os.O_RDONLY)
            import ctypes
            if r < 0 and ctypes.get_errno() != 1:
                bad += 1
        print(name, "ok" if bad == 0 and os.listdir(d) == [] else
              "BLOCKED errors=%d left=%s" % (bad, os.listdir(d)))
    else:
        ino = m._libc.inotify_init1(0o2000000 | 0o4000)
        w = m._libc.inotify_add_watch(ino, ("/proc/self/fd/%d" % fd).encode(), 0x20)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x", ("127.0.0.1", 9))
        print(name, "ok" if ino >= 0 and w >= 0 else "BLOCKED")

def props(unit):
    out = []
    for line in open(os.path.join(ROOT, unit)):
        k, _, v = line.strip().partition("=")
        if k in KEYS:
            out += ["-p", "%s=%s" % (k, v)]
    return out

if sys.argv[3] == "probe":
    role(sys.argv[4]); sys.exit(0)
for name, unit in ROLES.items():
    extra = ["-p", sys.argv[4]] if len(sys.argv) > 4 else []
    cmd = ["systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect",
           "-E", "PROBE_DIR=%s" % os.environ["PROBE_DIR"]] + props(unit) + extra + \
          [sys.executable, "-I", os.path.abspath(__file__), TOOL, ROOT, "probe", name]
    r = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if l.startswith(name + " ")]
    print(lines[-1] if lines else "%s NORUN %s" % (name, (r.stderr.strip().splitlines() or ["?"])[-1]))
PY
  if systemd-run --user --quiet --wait --pipe --collect true 2>/dev/null; then
    mkdir -p "${T}/probe"
    out="$(PROBE_DIR="${T}/probe" python3 "${T}/sysprobe.py" "${W}" "${ROOT}" outer 2>&1)"
    is  'in its own unit settings, the relay server touches an atime and joins its group' "$(sed -n 's/^server //p' <<<"${out}")" 'touched joined'
    is  'and the sweep expires, widens and drops non-files' "$(sed -n 's/^sweep //p' <<<"${out}")" 'ok'
    is  'and the watcher makes its calls' "$(sed -n 's/^watch //p' <<<"${out}")" 'ok'
    is  'and the relay client watches and sends' "$(sed -n 's/^client //p' <<<"${out}")" 'ok'
    out="$(PROBE_DIR="${T}/probe" python3 "${T}/sysprobe.py" "${W}" "${ROOT}" outer RestrictSUIDSGID=yes 2>&1)"
    is  '  control: with RestrictSUIDSGID= it is red, as on the box' \
        "$(sed -n 's/^server //p' <<<"${out}" | cut -d" " -f1)" 'resolve-ENOSYS'
  else
    for _ in 1 2 3 4 5; do
      bad 'in-unit syscall control' 'systemd-run --user does not work here, so it did not run'
    done
  fi
  # EFFECTIVE, not declared (systemd seat F7d). DynamicUser= implies
  # RestrictSUIDSGID=, which answers openat2 with ENOSYS; a check reading the
  # unit file missed it, twice. systemd-analyze security --offline computes
  # the effective value from the file with no root. The relay SERVER runs
  # openat2, so in its unit it must be off; the relay CLIENT is a DynamicUser
  # unit, so in its unit it must read on -- the positive control that the
  # analysis does see implications.
  eff() { systemd-analyze security --offline=true --json=short "$1" 2>/dev/null |
            python3 -c "import json,sys; print(*[x['set'] for x in json.load(sys.stdin) if x.get('json_field') == 'RestrictSUIDSGID'])" 2>/dev/null; }
  is  'the relay client (DynamicUser=) reads RestrictSUIDSGID on, effectively' \
      "$(eff "${ROOT}/hdw4s-shared-relay-client@.service")" 'True'
  is  'and the relay server, which needs openat2, reads it off, effectively' \
      "$(eff "${ROOT}/hdw4s-shared-relay-server@.service")" 'False'

  # Every unit of the package an administrator ENABLES must have an [Install]
  # section wanting it by its store's mount (%i.mount): without one it is
  # "static", "systemctl enable" refuses it, and an enabled instance does not
  # come back after a boot -- the relay units shipped that way. The ONE
  # deliberately static unit is the sweep's service, which its timer starts.
  static='hdw4s-shared-sweep@.service'
  no_install=''
  while read -r u; do
    case " ${static} " in *" ${u} "*) continue;; esac
    awk '/^\[Install\]/{f=1; next} /^\[/{f=0} f && $0 == "WantedBy=%i.mount" {found=1} END {exit !found}' \
        "${ROOT}/${u}" || no_install="${no_install} ${u}"
  done < <(awk '!/^#/ && $2 == "usr/lib/systemd/system" {print $1}' \
               "${ROOT}/debian/hdw4s-shared-sweep.install")
  is  'every unit an administrator enables is wanted by its store mount, the rest named static' \
      "${no_install}" ''

  # harden@ carries no setting that removes a system call, so what it does by
  # hand is what it does in its unit; this pins that, so adding one makes
  # somebody add its in-unit control first.
  is  'harden@ has no syscall-shaping setting to run its control under' \
      "$(grep -cE '^(SystemCallFilter|RestrictSUIDSGID|MemoryDenyWriteExecute|SystemCallArchitectures|RestrictNamespaces|PrivateDevices|ProtectClock|ProtectKernelModules)=' "${ROOT}/hdw4s-shared-harden@.service")" '0'

  # PM P18: the relay server binds ONE named address, never a wildcard.
  # (Multicast is the default since P19: an empty --listen means multicast.
  # Unicast, configured by --listen, still names one address and its clients.)
  "${W}" --relay-server --dir "${T}" --listen 127.0.0.1 >/dev/null 2>&1; rc=$?
  "${W}" --relay-server --dir "${T}" --group 10.0.0.1 >/dev/null 2>&1; rc2=$?
  is  'unicast without --allow is refused, and so is a group that is not multicast' \
      "${rc} ${rc2}" '2 2'
  n=0
  for wild in '::' '0.0.0.0'; do
    "${W}" --relay-server --dir "${T}" --allow 192.0.2.10 --listen="${wild}" >/dev/null 2>&1
    [ "$?" = 2 ] && n=$((n + 1))
  done
  is  'and refuses a wildcard, v4 or v6' "${n}" '2'
  "${W}" --dir "${T}" --idle 0 --max-age 7d >/dev/null 2>&1
  is  'an idle window of 0 is refused as a usage error' "$?" '2'
  "${W}" --dir "${T}" --idle 1m --max-age 7d >/dev/null 2>&1
  is  'and so is one below the grammar floor' "$?" '2'
  "${W}" --idle 30m --max-age 7d >/dev/null 2>&1
  is  'and a missing directory' "$?" '2'
  # Threat T7: noexec does not stop an import, so a root tool must never put
  # its working directory on the import path.
  mkdir "${T}/cwd"; printf 'open(%s, "w").write("x")\n' "'${T}/planted'" > "${T}/cwd/struct.py"
  # Run as a script, Python puts the SCRIPT's directory first, not the working
  # directory -- so the route that matters is the environment: PYTHONPATH.
  (cd "${T}/cwd" && PYTHONPATH="${T}/cwd" "${W}" --version >/dev/null 2>&1)
  is  'a struct.py in the working directory is never imported' \
      "$([ -e "${T}/planted" ] && echo imported || echo not)" 'not'

  # Form (i) on NFS (measured on a cluster): a bind of a SUBDIRECTORY of an
  # NFS mount records mountinfo root "/" -- the path is in the source field --
  # so the exposure of a store's table reads root "/", not "/table". It is
  # recognised by IDENTITY: its root is the very inode (dev, ino) of the table
  # of a sibling mount that passes form (ii). Fixture: the mountinfo and stat
  # of that shape, with the guard of the sibling's table stood in for.
  out="$(python3 - "${W}" <<'PY' 2>&1
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
# The REAL lines, as captured inside the container (PM P23).
STORE = ("1356 1324 0:251 / /srv/hdw4s-shared rw,nosuid,nodev,noexec,nosymfollow "
         "master:3169 - nfs4 192.0.2.1:/export/shared rw,vers=4.2,soft,addr=192.0.2.1")
EXPO = ("3417 987 0:251 / /run/hdw4s/shared rw,nosuid,nodev,noexec,nosymfollow "
        "master:3169 - nfs4 192.0.2.1:/export/shared/table rw,vers=4.2,soft,addr=192.0.2.1")
P = m.parse_mountinfo
class St(object):
    def __init__(self, dev, ino): self.dev, self.ino = dev, ino
TABLE = St((0, 251), 9)
def judge(path):
    if path == "/srv/hdw4s-shared/table": return TABLE
    raise m.Refused("open", "not a store")
def proved(line, st, others=()):
    x = P(line)
    return m.exposure_proved(x, st, [P(STORE), x] + [P(o) for o in others], judge)
LOCAL_STORE = "20 1 0:40 / /run/s rw,nosuid,nodev,noexec,nosymfollow - tmpfs s rw"
def ljudge(path):
    if path == "/run/s/table": return St((0, 40), 5)
    raise m.Refused("open", "not a store")
def lproved(line, st):
    x = P(line)
    return m.exposure_proved(x, st, [P(LOCAL_STORE), x], ljudge)
try:
    print("real", proved(EXPO, St((0, 251), 9)))
    print("tablex", proved(EXPO.replace("/export/shared/table", "/export/shared/tablex"), St((0, 251), 9)))
    print("export", proved(EXPO.replace("/export/shared/table", "/other/table"), St((0, 251), 9)))
    print("identity", proved(EXPO, St((0, 251), 2)))
    print("normalised", proved(EXPO.replace("/export/shared/table", "//export/shared//table/"), St((0, 251), 9)))
    LOC = "30 1 0:40 /table /run/hdw4s/shared rw,nosuid,nodev,noexec,nosymfollow - tmpfs s rw"
    print("local", lproved(LOC, St((0, 40), 5)), lproved(LOC, St((0, 40), 6)),
          lproved(LOC.replace(" /table ", " / "), St((0, 40), 5)))
except Exception as e:
    print("real ERROR", type(e).__name__)
PY
)"
  is  'the real NFS exposure (root "/", source .../table) is proved by identity and source' \
      "$(sed -n 's/^real //p' <<<"${out}")" 'True'
  is  '  an NFS mount there with source .../tablex is refused' "$(sed -n 's/^tablex //p' <<<"${out}")" 'False'
  is  '  so is one of another export' "$(sed -n 's/^export //p' <<<"${out}")" 'False'
  is  '  so is the right source on the wrong inode' "$(sed -n 's/^identity //p' <<<"${out}")" 'False'
  is  '  sources compare after normalising slashes' "$(sed -n 's/^normalised //p' <<<"${out}")" 'True'
  is  'a local exposure needs root /table AND the identity; either alone is refused' \
      "$(sed -n 's/^local //p' <<<"${out}")" 'True False False'

  # ---- the relay's multicast receive path (owner, PM P19) ------------------
  # Each layer alone, in-process (the logic), then on real sockets in a
  # network namespace of its own (the kernel's part). Red, for each: the
  # accept counter moves for what that layer must drop.
  out="$(python3 - "${W}" <<'PY' 2>&1
import importlib.machinery, importlib.util, ipaddress, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
class Stub:
    def touch(self, name, fileid): return "touched"
V = bytes([1]); H = m.REC_HEAD
use = V + H.pack(1, 0, 1, 7) + b"f"; hb = V + H.pack(2, 0, 0, 0)
NET = ipaddress.ip_network("10.200.0.0/24")
def srv(allow=None):
    s = m.Server(-1, [ipaddress.ip_network(a) for a in (allow or [])], Stub(), group=m.RELAY_GROUP)
    s.joined = {5: [NET]}
    return s
def acc(s): return s.counts.get("accepted", 0)
s = srv(); s.handle(use, ("10.200.0.2", 1), 5, m.RELAY_GROUP); print("positive", acc(s))
s = srv(); s.handle(use, ("10.200.0.2", 1), 5, "10.200.0.1"); s.handle(use, ("10.200.0.2", 1), 5, "10.200.0.255")
print("dst", acc(s), s.counts.get("drop-not-group", 0))
s = srv(); s.handle(use, ("10.200.0.2", 1), 6, m.RELAY_GROUP); print("iface", acc(s), s.counts.get("drop-not-joined-interface", 0))
s = srv(); s.handle(use, ("192.0.2.5", 1), 5, m.RELAY_GROUP); print("onlink", acc(s), s.counts.get("drop-not-on-link", 0))
s = srv(["10.200.0.9/32"]); s.handle(use, ("10.200.0.2", 1), 5, m.RELAY_GROUP); print("allow", acc(s), s.counts.get("drop-not-allowed", 0))
# M2: a million routed spoofers leave no per-source state.
s = srv()
for i in range(100000):
    s.handle(hb, ("198.51.%d.%d" % (i // 250 % 250, i % 250), 1), 5, m.RELAY_GROUP)
print("spoofed", len(s.sources), s.other["received"])
# The log property, on a clock of the test's own. One named client, heard at
# t=0, then silent for two hours; then heard again.
def run(s, until, step=60, hbeat=600, silence=1800, start=0):
    lines = []
    t = start
    while t <= until:
        lines += [(t, lv, tx) for lv, tx in s.tick(t, silence, hbeat)]
        t += step
    return lines
s = m.Server(-1, [ipaddress.ip_network("10.200.0.2/32")], Stub(), group=m.RELAY_GROUP, now=0)
s.joined = {5: [NET]}; s.handle(hb, ("10.200.0.2", 1), 5, m.RELAY_GROUP, now=0)
fail = run(s, 3600 + 1200)
first = min([t for t, lv, _ in fail if lv == "warning"] or [10**9])
print("fail-hour", len([1 for t, lv, _ in fail if 1200 <= t < 4800]), "first-warning-by", first <= 2 * 600 + 120)
s.handle(hb, ("10.200.0.2", 1), 5, m.RELAY_GROUP, now=4900)
rec = run(s, 5100, start=4920)
print("recovered", len([1 for _, lv, _ in rec if lv == "notice"]))
# M1: a thousand LEARNED on-link sources, one heartbeat each, then silence.
s = m.Server(-1, [], Stub(), group=m.RELAY_GROUP, now=0); s.joined = {5: [NET]}
for i in range(1000):
    s.handle(hb, ("10.200.0.%d" % (i % 250 + 1), 1), 5, m.RELAY_GROUP, now=0)
print("learned-hour", len(run(s, 3600 + 1200)))
# Nothing ever received: one setup line in the first hour, never again.
s = m.Server(-1, [], Stub(), group=m.RELAY_GROUP, now=0)
print("never", len(run(s, 3 * 3600)))
# The client: an hour of failing sends, then one that works.
c = m.SendLog(); lines = []
for i in range(200):
    lines += c.result(False, 101, i * 20)
lines += c.result(True, 0, 4100)
print("client", len(lines), "ENETUNREACH" in lines[0][1], lines[-1][0])
# A4: /proc/self/net unreadable (a sandbox that hides it) is an ERROR, never
# "no interfaces": listing raises, and a rescan keeps the joins it has and
# says so once.
real_open = open
def hidden(path, *a, **k):
    if str(path) == "/proc/self/net/dev":
        raise PermissionError(13, "Permission denied")
    return real_open(path, *a, **k)
m.open = hidden
try:
    m.multicast_interfaces(None); listing = "silent-empty"
except OSError:
    listing = "raises"
said = []; m.log = lambda t, lv=None: said.append(t)
s = srv(); s.joined = {5: [NET]}
class Sock:
    def setsockopt(self, *a): raise AssertionError("must not touch memberships")
r1 = m.rejoin(Sock(), s, None); r2 = m.rejoin(Sock(), s, None)
print("a4", listing, sorted(s.joined), len([x for x in said if "cannot list" in x]))
del m.open
g = ipaddress.ip_address(m.RELAY_GROUP)
print("group", g in ipaddress.ip_network("239.255.0.0/16") and g not in ipaddress.ip_network("239.255.255.0/24"), m.RELAY_PORT != 4747)
PY
)"
  is  'multicast: a group datagram from an on-link client on a joined interface is accepted' "$(sed -n 's/^positive //p' <<<"${out}")" '1'
  is  '  layer PKTINFO destination alone: unicast and broadcast to the port are dropped' "$(sed -n 's/^dst //p' <<<"${out}")" '0 2'
  is  '  layer PKTINFO interface alone: arrival on a non-joined interface is dropped' "$(sed -n 's/^iface //p' <<<"${out}")" '0 1'
  is  '  layer on-link alone: a routed source is dropped with no --allow' "$(sed -n 's/^onlink //p' <<<"${out}")" '0 1'
  is  '  and --allow narrows the on-link set' "$(sed -n 's/^allow //p' <<<"${out}")" '0 1'
  is  'spoofed sources leave no per-source state (one bucket)' "$(sed -n 's/^spoofed //p' <<<"${out}")" '0 100000'
  is  'a silent client: warned within two intervals, at most 3 lines in the failing hour' \
      "$(sed -n 's/^fail-hour //p' <<<"${out}" | awk '{print ($1 <= 3 && $1 >= 1) ? "bounded" : "count=" $1, $3}')" 'bounded True'
  is  '  and recovery is said, once per episode' "$(sed -n 's/^recovered //p' <<<"${out}")" '2'
  is  '1000 learned spoofed sources going silent cost at most 3 lines in the hour' \
      "$(sed -n 's/^learned-hour //p' <<<"${out}" | awk '{print ($1 <= 3) ? "bounded" : "count=" $1}')" 'bounded'
  is  'nothing ever received: one setup line, never repeated' "$(sed -n 's/^never //p' <<<"${out}")" '1'
  is  'the client: first error with its errno, hourly counts, one recovery line' \
      "$(sed -n 's/^client //p' <<<"${out}")" '3 True notice'
  is  'an unreadable /proc/self/net is an error: listing raises, a rescan keeps its joins and says so once' \
      "$(sed -n 's/^a4 //p' <<<"${out}")" 'raises [5] 1'
  is  'the default group is local scope, off the relative block; the port is not a registered one' \
      "$(sed -n 's/^group //p' <<<"${out}")" 'True True'

  # R7 (P28 M4): a burst of opens. Measured before the client had a pace, in
  # the real units: 5000 opens sent 5000 records at once, the server took 2035
  # and dropped 2965 for rate -- files already marked announced, so they would
  # expire early. Properties, on a clock of the test's own: the client never
  # sends faster than one source is accepted (the server's own bucket, fed
  # what the client sends, drops nothing); a burst is DEFERRED, never dropped
  # and never marked announced before it is sent; an overflow announces
  # nothing and is said once.
  out="$(python3 - "${W}" "${T}" <<'PY' 2>&1
import importlib.machinery, importlib.util, os, struct, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
d = os.path.join(sys.argv[2], "r7"); os.makedirs(d)
for i in range(5000):
    open(os.path.join(d, "f%04d" % i), "w").close()
fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
said = []; m.log = lambda t, lv=None: said.append(t)
c = m.Client(fd, 7200)
c.pace = m.Bucket(m.CLIENT_RATE, m.CLIENT_BURST); c.pace.t = 0.0
srv = m.Bucket(m.RATE_SOURCE, m.BURST_SOURCE); srv.t = 0.0
for i in range(5000):
    c.pending[b"f%04d" % i] = True
sent = dropped = 0; first = None; t = 0.0
while t <= 70.0:
    recs = c.records(t, c.pace.room(t))
    if recs:
        c.pace.take(len(recs), t)
        if not srv.take(len(recs), t):
            dropped += len(recs)
        sent += len(recs)
    if first is None:
        first = (sent, len(c.pending), len(c.announced))
    t += 0.2
print("pace", dropped, sent, len(c.pending))
print("deferred", first[0], first[0] + first[1] == 5000, first[2] == first[0])
ov = struct.pack("<iIII", -1, m.IN_Q_OVERFLOW, 0, 0)
c.pending.clear()
for _ in range(3):
    c.events(ov)
print("overflow", len(c.pending), len([x for x in said if "overflowed" in x]), c.counts.get("overflow"))
PY
)"
  is  'R7: paced, the client never sends faster than one source is accepted; all 5000 go out' \
      "$(sed -n 's/^pace //p' <<<"${out}")" '0 5000 0'
  is  '  a burst is deferred: what does not fit stays pending and is not marked announced' \
      "$(sed -n 's/^deferred //p' <<<"${out}")" '1000 True True'
  is  '  an overflow announces nothing, and three of them are said once' \
      "$(sed -n 's/^overflow //p' <<<"${out}")" '0 1 3'

  # On real sockets, in a network namespace with a veth pair.
  MC_TESTS=7
  if unshare -Urnm true 2>/dev/null; then
    export W T
    # shellcheck disable=SC2016  # expanded by the shell inside the namespace
    out="$(unshare -Urnm bash -c '
      set +e
      # The sender is in a network namespace of its own, at the far end of a
      # veth pair: a datagram whose source is one of the OWN addresses of the
      # receiver is a martian and never reaches a socket.
      ip link set lo up; ip link add va type veth peer name vb
      ip addr add 10.200.0.1/24 dev va; ip link set va up
      sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.va.rp_filter=0
      unshare -n sleep 120 & P=$!; sleep 0.3
      ip link set vb netns "${P}"
      nsenter -t "${P}" -n sh -c "ip link set lo up; ip addr add 10.200.0.2/24 dev vb; ip addr add 10.201.0.2/24 dev vb; ip link set vb up"
      export P
      M="${T}/mcstore"; mkdir -p "${M}"
      mount -t tmpfs -o nosymfollow,nodev,noexec,nosuid,strictatime,mode=0755 m "${M}"
      mkdir -m 0777 "${M}/table"; printf x > "${M}/table/f"
      python3 - "${W}" "${M}" <<"PY"
import importlib.machinery, importlib.util, os, socket, subprocess, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
table = os.path.join(sys.argv[2], "table")
fd = os.open(table, os.O_RDONLY | os.O_DIRECTORY)
srv = m.Server(fd, [], group=m.RELAY_GROUP)
sock = m.multicast_socket(0); port = sock.getsockname()[1]
names, _, _ = m.rejoin(sock, srv, ["va"])
ino = os.stat(os.path.join(table, "f")).st_ino
SEND = """
import socket, struct, sys
dst, src, port, ino = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.IPPROTO_IP, 32, socket.inet_aton("0.0.0.0") + bytes(4) + struct.pack("@i", socket.if_nametoindex("vb")))
s.bind((src, 0))
s.sendto(bytes([1]) + struct.pack(">BBHQ", 1, 0, 1, ino) + b"f", (dst, port))
"""
def tx(dst, src="10.200.0.2"):
    subprocess.check_call(["nsenter", "-t", os.environ["P"], "-n", sys.executable,
                           "-c", SEND, dst, src, str(port), str(ino)])
def drain():
    buf = bytearray(9000)
    while m.select.select([sock], [], [], 0.3)[0]:
        n, anc, fl, addr = sock.recvmsg_into([buf], socket.CMSG_SPACE(12), socket.MSG_TRUNC)
        i, d = m.pktinfo(anc); srv.handle(memoryview(buf)[:n], addr, i, d)
c = lambda k: srv.counts.get(k, 0)
tx(m.RELAY_GROUP); drain(); print("e2e", names, c("accepted"))
# Another group joined on this host by another socket: its traffic reaches
# the host (the other socket receives it on its own port -- the positive
# control), and the same group sent to OUR port must not reach this socket.
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.bind(("0.0.0.0", 0)); oport = other.getsockname()[1]
other.setsockopt(socket.IPPROTO_IP, m.IP_ADD_MEMBERSHIP, m.mreqn("239.255.99.99", socket.if_nametoindex("va")))
subprocess.check_call(["nsenter", "-t", os.environ["P"], "-n", sys.executable,
                       "-c", SEND, "239.255.99.99", "10.200.0.2", str(oport), str(ino)])
got = bool(m.select.select([other], [], [], 0.5)[0])
r0 = c("received"); tx("239.255.99.99"); drain()
print("other-group", c("received") - r0, got)
other.close()
a0, g0 = c("accepted"), c("drop-not-group")
tx("10.200.0.1"); tx("10.200.0.255"); drain()
print("unicast-broadcast", c("accepted") - a0, c("drop-not-group") - g0)
a0, o0 = c("accepted"), c("drop-not-on-link"); tx(m.RELAY_GROUP, src="10.201.0.2"); drain()
print("routed", c("accepted") - a0, c("drop-not-on-link") - o0)
PY
      # --relay-interfaces: read-only, every interface accounted for. Here:
      # lo (loopback), va (joined), and a dummy that is up but not
      # multicast-capable and one with multicast but no address.
      ip link add nomc type dummy; ip link set nomc up
      ip link add noaddr type dummy; ip link set noaddr multicast on; ip link set noaddr up
      "${W}" --relay-interfaces | awk "{print \"ri\", \$1, \$2}" | sort -u
      "${W}" --relay-interfaces | awk "\$2 == \"lo\" {print \"ri-lo-why\", \$5}"
      "${W}" --relay-interfaces --interface noaddr >/dev/null; echo "ri-narrow-rc $?"
      ip link del nomc; ip link del noaddr
      # A bridge: the master carries the address, its port carries none. The
      # server must join on the MASTER -- with IGMP snooping a join on a port
      # receives nothing, silently (measured on two real storage hosts).
      ip link add br9 type bridge; ip link add p9 type veth peer name q9
      ip link set p9 master br9; ip addr add 10.209.0.1/24 dev br9
      ip link set br9 up; ip link set p9 up
      "${W}" --relay-interfaces | awk "\$2 == \"br9\" || \$2 == \"p9\" {print \"rb\", \$1, \$2}"
      ip link del p9; ip link del br9
      # M3: past igmp_max_memberships (20 per socket), a refused join is
      # said ONCE and never again at a re-join; nothing dies.
      for i in $(seq 0 24); do
        ip link add "d${i}" type dummy; ip link set "d${i}" multicast on
        ip addr add "10.210.${i}.1/24" dev "d${i}"; ip link set "d${i}" up
      done
      python3 - "${W}" <<"PY"
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
lines = []; m.log = lambda t, lv=None: lines.append(t)
class Stub:
    def touch(self, *a): return "touched"
srv = m.Server(-1, [], Stub(), group=m.RELAY_GROUP); sock = m.multicast_socket(0)
try:
    for _ in range(3): m.rejoin(sock, srv, None)
    print("joinlimit", len(srv.joined), len([x for x in lines if "could not join" in x]))
except Exception as e:
    print("joinlimit CRASH", type(e).__name__)
PY
      kill "${P}" 2>/dev/null
    ' 2>&1)"
    is  'multicast on real sockets: a group datagram is accepted, joined on the one named interface' \
        "$(sed -n 's/^e2e //p' <<<"${out}")" "['va'] 1"
    is  '  layer IP_MULTICAST_ALL=0 alone: another group joined on the host never arrives' \
        "$(sed -n 's/^other-group //p' <<<"${out}")" '0 True'
    is  '  unicast and broadcast to the port, sent for real, are dropped as not the group' \
        "$(sed -n 's/^unicast-broadcast //p' <<<"${out}")" '0 2'
    is  '  a routed source, sent for real, accepts nothing' "$(sed -n 's/^routed //p' <<<"${out}")" '0 1'
    is  '--relay-interfaces says what it would join and skip, and why, joining nothing' \
        "$(grep "^ri " <<<"${out}" | grep -E " (va|lo|nomc|noaddr)$" | paste -sd ";") $(sed -n 's/^ri-narrow-rc //p' <<<"${out}") $(sed -n 's/^ri-lo-why //p' <<<"${out}")" \
        "ri join va;ri skip lo;ri skip noaddr;ri skip nomc 1 loopback"
    is  'on a bridge it joins the master, never a port (a port carries no subnet)' \
        "$(grep "^rb " <<<"${out}" | sort | paste -sd ";")" "rb join br9;rb skip p9"
    is  'past the membership limit: joined 20, one line, no crash, however often it re-joins' \
        "$(sed -n 's/^joinlimit //p' <<<"${out}")" '20 1'
  else
    for _ in $(seq "${MC_TESTS}"); do
      bad 'the multicast relay on real sockets' 'unshare -Urnm is refused here, so none of them ran'
    done
  fi

  # ---- everything below needs mounts --------------------------------------
  NS_TESTS=72
  # Deletion review F2 (P8 B3): a mount that reaches the WALKED table mid-walk
  # through the exposure's mount peer group, not through the store. The
  # reviewer's script, verbatim.
  cat > "${T}/peer.py" <<'PY'
# Mid-walk mount that arrives in the walked table BY WAY OF THE EXPOSURE'S peer
# group (P8 B3). Run inside unshare -Urm. argv: tool base weaken(none|all) private(0|1)
import importlib.machinery, importlib.util, os, subprocess, sys, time
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
B, weaken, private = sys.argv[2], sys.argv[3], sys.argv[4] == "1"
run = lambda *a: subprocess.check_call(list(a))
P = os.path.join(B, "run"); os.makedirs(P, exist_ok=True)
run("mount", "-t", "tmpfs", "run", P); run("mount", "--make-shared", P)
ST, E = os.path.join(P, "store"), os.path.join(P, "expose")
os.mkdir(ST); os.mkdir(E)
run("mount", "-t", "tmpfs", "-o", "nosymfollow,nodev,noexec,nosuid,strictatime,mode=0755", "s", ST)
if private: run("mount", "--make-private", ST)
os.mkdir(os.path.join(ST, "table")); os.chmod(os.path.join(ST, "table"), 0o777)
os.mkdir(os.path.join(ST, "table", "m"))
run("mount", "--bind", os.path.join(ST, "table"), E)
H = os.path.join(B, "home"); os.makedirs(H, exist_ok=True)
run("mount", "-t", "tmpfs", "-o", "nosymfollow,nodev,noexec,nosuid", "h", H)
with open(os.path.join(H, "precious"), "w") as f: f.write("x")
os.chmod(os.path.join(H, "precious"), 0o600)
if weaken == "all":
    m.open_dir = lambda dfd, name, ino, mnt_id=None: os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dfd)
    m.Gate.beneath = lambda self, fd: True
    m.Gate.entry = lambda self, dfd, name, ino: m.statx(dfd, name)
inner = m.open_dir
def hook(dfd, name, ino, mnt_id=None):
    if name == "m":   # the "home" bound through the EXPOSURE, not the store
        run("mount", "--bind", H, os.path.join(E, "m"))
    return inner(dfd, name, ino, mnt_id)
m.open_dir = hook
g = m.guard(os.path.join(ST, "table"), "ii")
c = m.Counts()
m.sweep(g.fd, g.stx.mnt_id, 1800, 7 * 86400, time.time() + 86400 * 30, c)
seen = os.path.exists(os.path.join(ST, "table", "m", "precious"))
print("private=%d weaken=%s appeared-in-store=%s precious=%s refused=%s" % (
    private, weaken, seen, "kept" if os.path.exists(os.path.join(H, "precious")) else "DELETED",
    ",".join(sorted(c.refused)) or "none"))
PY
  # The depth budget (PM P10, A5): a 12-deep tree, a budget of 8.
  cat > "${T}/budget.py" <<'PY'
import importlib.machinery, importlib.util, os, sys, time
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
d = os.dup(fd)
for _ in range(12):
    os.mkdir("d", dir_fd=d); n = os.open("d", os.O_RDONLY, dir_fd=d); os.close(d); d = n
os.close(d)
before = len(os.listdir("/proc/self/fd"))
c = m.Counts()
try:
    m.sweep(fd, m.fstatx(fd).mnt_id, 1800, 86400, time.time() + 3600, c, max_depth=8)
    crashed = "no"
except Exception as e:
    crashed = type(e).__name__
print("budget", crashed, c.too_deep, len(os.listdir("/proc/self/fd")) - before)
PY
  # The owner's worry is deletion outside the table. These run the sweep
  # directly on a filesystem that is NOT dedicated (an "outside" beside the
  # table), i.e. as if the guard and the store rule had both failed, and
  # plant the escape mid-walk. Each case runs with the full gate, then with
  # one layer weakened, so that a green result cannot come from a case that
  # never reached a destructive call.
  cat > "${T}/escape.py" <<'PY'
import importlib.machinery, importlib.util, os, subprocess, sys, time
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
F, case, weaken = sys.argv[2], sys.argv[3], sys.argv[4].split(",")
T, O = os.path.join(F, "table"), os.path.join(F, "outside")
later = time.time() + 86400
def put(p, mode=0o644):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f: f.write("canary")
    os.chmod(p, mode)
real_open_dir = m.open_dir
if "beneath" in weaken:
    m.Gate.beneath = lambda self, fd: True
if "opendir" in weaken:
    m.open_dir = lambda dfd, name, ino, mnt_id=None: os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dfd)
if "entrymnt" in weaken:
    m.Gate.entry = lambda self, dfd, name, ino: m.statx(dfd, name)
if "nlink" in weaken:
    def fchmod(self, fd, mode): os.fchmod(fd, mode)
    m.Gate.fchmod = fchmod
if case == "rename-out":
    put(os.path.join(T, "victim", "f1")); os.makedirs(O, exist_ok=True)
    inner = m.open_dir
    def hook(dfd, name, ino, mnt_id=None):
        fd = inner(dfd, name, ino, mnt_id)
        if name == "victim":
            os.rename(os.path.join(T, "victim"), os.path.join(O, "victim"))
        return fd
    m.open_dir = hook
elif case == "mount-in":
    os.makedirs(os.path.join(T, "m"))
    inner = m.open_dir
    def hook(dfd, name, ino, mnt_id=None):
        if name == "m":
            subprocess.check_call(["mount", "-t", "tmpfs", "x", os.path.join(T, "m")])
            put(os.path.join(T, "m", "f1"))
        return inner(dfd, name, ino, mnt_id)
    m.open_dir = hook
elif case == "hardlink":
    put(os.path.join(O, "f1"), 0o600)
    os.link(os.path.join(O, "f1"), os.path.join(T, "hl"))
fd = os.open(T, os.O_RDONLY | os.O_DIRECTORY)
c = m.Counts()
m.sweep(fd, m.fstatx(fd).mnt_id, 1800, 7 * 86400, later if case != "hardlink" else time.time(), c)
if case == "rename-out":
    print("outside", "kept" if os.path.exists(os.path.join(O, "victim", "f1")) else "deleted")
elif case == "mount-in":
    print("outside", "kept" if os.path.exists(os.path.join(T, "m", "f1")) else "deleted")
    subprocess.call(["umount", os.path.join(T, "m")])
else:
    print("outside", "%o" % (os.stat(os.path.join(O, "f1")).st_mode & 0o777))
print("refused", ",".join(sorted(c.refused)) or "none")
PY
  cat > "${T}/onepass.py" <<'PY'
import importlib.machinery, importlib.util, os, sys, time
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
m.sweep(fd, m.fstatx(fd).mnt_id, 1.5, 86400, time.time(), m.Counts())
PY
  # The resolver with the parser bypassed (threat T2 (iii)): every name below
  # would be refused by the parser first, which is exactly why it is not used.
  cat > "${T}/resolver.py" <<'PY'
import importlib.machinery, importlib.util, os, sys
loader = importlib.machinery.SourceFileLoader("sweep", sys.argv[1])
spec = importlib.util.spec_from_loader("sweep", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
r = m.Resolver(fd)
ino = os.stat(os.path.join(sys.argv[2], "f")).st_ino
for name in (b"/etc/hostname", b"ln/g", b".", b"m/f"):
    print(name.decode(), r.touch(name, ino))
# "..", from a table that is a SUBDIRECTORY of its mount, so leaving it does
# not also cross a mount: otherwise RESOLVE_NO_XDEV refuses it and hides
# whether RESOLVE_BENEATH does.
sub = m.Resolver(os.open(os.path.join(sys.argv[2], "sub"), os.O_RDONLY | os.O_DIRECTORY))
print("updot", sub.touch(b"../f", ino))
before = os.stat(os.path.join(sys.argv[2], "f"))
print("f", r.touch(b"f", ino))
after = os.stat(os.path.join(sys.argv[2], "f"))
print("moved", after.st_atime_ns > before.st_atime_ns, after.st_mtime_ns == before.st_mtime_ns)
print("wrong", r.touch(b"f", ino + 1))
PY
  if ! unshare -Urm true 2>/dev/null; then
    for _ in $(seq "${NS_TESTS}"); do
      bad 'the /shared guard and sweep in a user namespace' \
          'unshare -Urm is refused here, so none of them ran (kernel.apparmor_restrict_unprivileged_userns?)'
    done
    exit 0
  fi
  export -f ok bad is has hasnt
  export RESULTS W T
  # shellcheck disable=SC2016  # expanded by the shell inside the namespace
  unshare -Urm bash -c '
  set +e
  fl=nosymfollow,nodev,noexec,nosuid,strictatime
  store() { mkdir -p "$1"; mount -t tmpfs -o "${2:-${fl}},mode=0755" s "$1"; mkdir -m 0777 "$1/table"; }
  clause() { "${W}" --guard "$@" 2>&1 >/dev/null | sed -n "s/^hdw4s-shared-sweep: refused [^:]*: \([a-z-]*\): .*/\1/p"; }
  S="${T}/store"; D="${S}/table"; store "${S}"
  out="$("${W}" --guard "${D}")"
  has "the store table passes form (ii)" "${out}" " form=ii "
  mkdir "${T}/exposure"; mount --bind "${D}" "${T}/exposure"
  has "its bind passes form (i)" "$("${W}" --guard "${T}/exposure" --form i)" " form=i "
  mkdir "${T}/stack"; mount -t tmpfs -o ${fl} t "${T}/stack"; mkdir "${T}/stack/x"
  mkdir "${T}/s2"; store "${T}/s2"; mount --bind "${T}/stack/x" "${T}/s2/table"
  is  "a mount stacked on the table is refused" "$(clause "${T}/s2/table" --form ii)" "stacked"
  mkdir "${T}/unmounted"
  is  "an unmounted store (its empty mount point) is refused" "$(clause "${T}/unmounted/table")" "open"
  mkdir -p "${T}/stack/sub/table"; chmod 755 "${T}/stack/sub"
  is  "a directory of a larger filesystem is refused" "$(clause "${T}/stack/sub/table" --form ii)" "not-mount-child"
  mkdir "${T}/s3"; mount -t tmpfs -o ${fl} t "${T}/s3"; mkdir -p "${T}/s3/x/table"
  mkdir "${T}/s3b"; mount --bind "${T}/s3/x" "${T}/s3b"
  is  "a store that is not a whole filesystem is refused" "$(clause "${T}/s3b/table" --form ii)" "fs-root"
  touch "${S}/extra"
  is  "a store root holding anything else is refused" "$(clause "${D}")" "store-extra"
  rm "${S}/extra"; chmod 775 "${S}"
  is  "a group-writable store root is refused" "$(clause "${D}")" "store-owner"
  chmod 755 "${S}"
  for f in nosymfollow nodev noexec nosuid; do
    o="$(printf %s "${fl}" | tr , "\n" | grep -vx "${f}" | paste -sd,)"
    store "${T}/no-${f}" "${o}"
    is "a store without ${f} is refused, naming it" \
       "$("${W}" --guard "${T}/no-${f}/table" 2>&1 | sed -n "s/.*: flags: the mount lacks //p")" "${f}"
  done
  store "${T}/relatime" nosymfollow,nodev,noexec,nosuid,relatime
  is  "a store without strictatime is refused, naming it" \
      "$("${W}" --guard "${T}/relatime/table" 2>&1 | sed -n "s/.*: flags: the mount lacks //p")" "strictatime"
  mkdir "${D}/notable"; mkdir "${T}/wrongbind"; mount --bind "${D}/notable" "${T}/wrongbind"
  is  "a bind of anything but the table is refused" "$(clause "${T}/wrongbind")" "no-sibling"
  rmdir "${D}/notable" 2>/dev/null; umount "${T}/wrongbind"
  is  "--harden refuses / before remounting anything" \
      "$("${W}" --harden / 2>&1 | sed -n "s/^hdw4s-shared-sweep: refused [^:]*: \([a-z-]*\): .*/\1/p")" "store-extra"
  store "${T}/soft" nodev,noexec,nosuid,strictatime
  "${W}" --harden "${T}/soft" >/dev/null 2>&1
  is  "--harden adds a missing nosymfollow, and the guard then accepts" "$?" "0"

  # The sweep. Times are judged with --now, because ctime -- part of "last
  # used" -- cannot be set back from user space.
  now="$(date +%s)"; later=$((now + 3600))
  sw() { "${W}" --dir "${D}" --idle 30m --max-age 7d "$@" 2>&1; }
  ln -s /etc/hostname "${D}/link"; mkfifo "${D}/fifo"
  printf p > "${D}/private"; chmod 6700 "${D}/private"
  mkdir -m 700 "${D}/d"; mkdir -m 000 "${D}/zero"
  out="$(sw)"
  is  "a symlink and a fifo are removed, the link never followed" \
      "$([ -e "${D}/link" ] || [ -L "${D}/link" ] || [ -e "${D}/fifo" ] && echo kept || echo gone) $(cat /etc/hostname >/dev/null && echo intact)" "gone intact"
  is  "a private file is widened to rw for all, set-id bits gone" "$(stat -c %a "${D}/private")" "766"
  is  "a private directory is widened to 0777" "$(stat -c %a "${D}/d")" "777"
  is  "and so is a 0000 one" "$(stat -c %a "${D}/zero")" "777"
  is  "nothing in use is expired" "$(ls -A "${D}" | sort | paste -sd " ")" "d private zero"
  sw --now "${later}" >/dev/null
  is  "an hour later, everything idle is gone" "$(ls -A "${D}" | wc -l)" "0"
  # ONE pass, because a directory is judged on its times from BEFORE the pass
  # removed its children. Judged after, each removal makes its parent look
  # fresh and a nest goes one level per idle window. The CLI floor is two
  # minutes, so this calls the sweep directly with a window of 1.5 s.
  mkdir -p "${D}/a/b/c/e"; sleep 2
  python3 "${T}/onepass.py" "${W}" "${D}"
  is  "a nest of empty directories goes in ONE pass" "$(ls -A "${D}" | wc -l)" "0"
  printf x > "${D}/young"
  "${W}" --dir "${D}" --idle 30d --max-age 2m --now "${later}" >/dev/null 2>&1
  is  "an item older than the maximum age goes however recently used" \
      "$([ -e "${D}/young" ] && echo kept || echo gone)" "gone"
  printf x > "${D}/future"; touch -d "@$((now + 400 * 86400))" "${D}/future"
  sw --now "${later}" >/dev/null
  is  "a timestamp in the future does not keep an item for ever" \
      "$([ -e "${D}/future" ] && echo kept || echo gone)" "gone"
  # A DIRECTORY is judged idle by its mtime and ctime, never its atime: any
  # listing moves that, and the rescans of the relay client on an NFS mount
  # were seen moving the atime of an empty directory on the server (R1c) --
  # counted, it would keep every watched empty directory for ever. For a file
  # the atime does count; the file beside it, read as recently, is the
  # positive control. (No apostrophes: this is inside a single-quoted bash -c.)
  mkdir "${D}/listed"; touch -a -d "@$((later - 60))" "${D}/listed"
  printf x > "${D}/read"; touch -a -d "@$((later - 60))" "${D}/read"
  sw --now "${later}" >/dev/null
  is  "an empty directory whose only recent time is its atime is expired" \
      "$([ -e "${D}/listed" ] && echo kept || echo gone)" "gone"
  is  "  while a file whose atime is as recent is kept" \
      "$([ -e "${D}/read" ] && echo kept || echo gone)" "kept"
  rm -f "${D}/read"; rmdir "${D}/listed" 2>/dev/null
  mkdir "${D}/m"; mkdir "${T}/other"; mount -t tmpfs -o ${fl} o "${T}/other"
  printf k > "${T}/other/keep"; mount --bind "${T}/other" "${D}/m"
  sw --now "${later}" >/dev/null
  is  "nothing on another mount inside the table is touched" "$(cat "${T}/other/keep")" "k"
  umount "${D}/m"; rmdir "${D}/m"
  canary="CANARY$$x"; printf x > "${D}/${canary}"; printf x > "${D}/$(printf "${canary}\377\nz")"
  out="$(sw --now "${later}")"
  is  "names that are not UTF-8 or carry a newline are swept" "$(ls -A "${D}" | wc -l)" "0"
  hasnt "and no name from the table is ever logged" "${out}" "${canary}"
  python3 -c "
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
for i in range(3000):
    os.mkdir(\"d\", dir_fd=fd); nfd = os.open(\"d\", os.O_RDONLY, dir_fd=fd); os.close(fd); fd = nfd
open(\"/proc/self/fd/%d/leaf\" % fd, \"w\").write(\"x\")
" "${D}"
  out="$(sw --now "${later}")"; rc=$?
  is  "a 3000-deep tree neither crashes the sweep nor survives it" "${rc} $(ls -A "${D}" | wc -l)" "0 0"
  "${W}" --check --dir "${D}" --idle 30m >/dev/null; rc=$?
  is  "--check is green on a tidy table" "${rc}" "0"
  esc() { local F; F="$(mktemp -d -p "${T}")"; mount -t tmpfs -o ${fl} f "${F}"
          mkdir -m 777 "${F}/table"
          python3 "${T}/escape.py" "${W}" "${F}" "$1" "$2" 2>&1 | paste -sd " "
          umount -l "${F}"; }
  is  "a directory renamed OUT of the table mid-walk: nothing in it is touched" \
      "$(esc rename-out none)" "outside kept refused escaped"
  is  "  control: without the beneath check it would have been deleted" \
      "$(esc rename-out beneath | cut -d" " -f1-2)" "outside deleted"
  is  "a mount appearing on a name mid-walk: nothing on it is touched" \
      "$(esc mount-in none | cut -d" " -f1-2)" "outside kept"
  is  "  with the open-time check gone, the gate still refuses it" \
      "$(esc mount-in opendir | cut -d" " -f1-2)" "outside kept"
  is  "  and with the beneath check gone too, the entry mount check does" \
      "$(esc mount-in opendir,beneath | cut -d" " -f1-2)" "outside kept"
  is  "  control: with all three gone it would have been deleted" \
      "$(esc mount-in opendir,beneath,entrymnt | cut -d" " -f1-2)" "outside deleted"
  is  "a hard link from outside is never re-moded through the table" \
      "$(esc hardlink none)" "outside 600 refused linked"
  is  "  control: without the link-count check it would have been widened" \
      "$(esc hardlink nlink | cut -d" " -f1-2)" "outside 666"
  ln -s "${S}" "${T}/via"
  is  "--dir through a symbolic link in its path is refused" "$(clause "${T}/via/table")" "path"
  # On a mount WITHOUT nosymfollow, so the flag cannot do the resolver its
  # job: each layer has to be seen refusing on its own.
  R="${T}/resolve"; mkdir "${R}"; mount -t tmpfs -o nodev,noexec,nosuid r "${R}"
  printf x > "${R}/f"; touch -a -d "2 hours ago" "${R}/f"; mkdir "${R}/sub"
  printf x > "${R}/sub/g"; ln -s sub "${R}/ln"
  printf x > "${T}/x"; mkdir "${R}/m"; mount -t tmpfs -o ${fl} o "${R}/m"; printf x > "${R}/m/f"
  out="$(python3 "${T}/resolver.py" "${W}" "${R}")"
  is  "the resolver alone refuses ../x"           "$(sed -n "s|^updot ||p" <<<"${out}")" "resolve-EXDEV"
  is  "and an absolute name"                     "$(sed -n "s|^/etc/hostname ||p" <<<"${out}")" "resolve-EXDEV"
  is  "and a symlink as an intermediate component" "$(sed -n "s|^ln/g ||p" <<<"${out}")" "resolve-ELOOP"
  is  "and a directory"                          "$(sed -n "s|^\. ||p" <<<"${out}")" "not-regular"
  is  "and a mount crossing"                     "$(sed -n "s|^m/f ||p" <<<"${out}")" "resolve-EXDEV"
  is  "it moves the atime of a regular file and nothing else" \
      "$(sed -n "s/^f //p; s/^moved //p" <<<"${out}" | paste -sd " ")" "touched True True"
  is  "and refuses a wrong fileid"               "$(sed -n "s/^wrong //p" <<<"${out}")" "fileid"
  umount "${R}/m"
  printf x > "${D}/stale"
  out="$("${W}" --check --dir "${D}" --idle 30m --now "${later}")"; rc=$?
  is  "--check is red when nobody is sweeping" "${rc} $(cut -d: -f1 <<<"${out}")" "1 red"
  "${W}" --check --dir "${T}/unmounted" --idle 30m >/dev/null; rc=$?
  is  "--check is red on a directory the guard refuses" "${rc}" "1"
  rm -f "${D}/stale"

  # PM P10, A7: a destructive mode accepts form (ii) only, and form (i) needs
  # a sibling that is a store. The case: a flagged /table directory of a
  # filesystem that is NOT a store (here, it holds something else at its
  # root), bound where an exposure would be.
  X="${T}/notstore"; mkdir "${X}"; mount -t tmpfs -o ${fl} x "${X}"
  mkdir -m 777 "${X}/table"; printf h > "${X}/home-file"; printf k > "${X}/table/keep"
  mkdir "${T}/fake"; mount --bind "${X}/table" "${T}/fake"
  is  "a /table of a filesystem that is not a store has no sibling: refused" \
      "$(clause "${T}/fake" --form i)" "no-sibling"
  "${W}" --dir "${T}/fake" --idle 30m --max-age 7d --now "${later}" >/dev/null 2>&1; rc=$?
  is  "and the sweep refuses it, touching nothing" "${rc} $(cat "${X}/table/keep")" "1 k"
  "${W}" --check --dir "${T}/fake" --idle 30m >/dev/null; rc=$?
  is  "and --check is red on it" "${rc}" "1"
  printf k > "${D}/keep"
  "${W}" --dir "${T}/exposure" --idle 30m --max-age 7d --now "${later}" >/dev/null 2>&1; rc=$?
  is  "even a real exposure (form i) is refused by the sweep: form (ii) only" \
      "${rc} $(cat "${D}/keep")" "1 k"
  rm -f "${D}/keep"

  # A5: the depth budget. Iterative, no crash, no descriptor left open, and
  # what it did not enter is counted -- and --check says so.
  B="${T}/budget"; store "${B}"
  is  "a tree deeper than the budget: no crash, counted, no fd leaked" \
      "$(python3 "${T}/budget.py" "${W}" "${B}/table" | sed -n "s/^budget //p")" "no 1 0"
  out="$("${W}" --check --dir "${B}/table" --idle 30m --max-depth 8)"; rc=$?
  is  "and --check warns about it" "${rc} $(cut -d: -f1 <<<"${out}")" "3 warn"

  # F2: full gate keeps it; with the three mount/beneath/entry checks off it
  # is deleted (so the case does reach a destructive call); and with the
  # store --make-private it never reaches the store at all.
  peer() { local B; B="$(mktemp -d -p "${T}")"; python3 "${T}/peer.py" "${W}" "${B}" "$1" "$2" 2>&1 | tail -1; }
  is  "a mount arriving through the exposure peer group mid-walk is not touched" \
      "$(peer none 0 | cut -d" " -f3-4)" "appeared-in-store=True precious=kept"
  # (appeared-in-store is read AFTER the sweep, so here it is False: the
  # file it looks for is the one that was deleted.)
  is  "  control: with the three checks removed it would have been deleted" \
      "$(peer all 0 | cut -d" " -f4)" "precious=DELETED"
  is  "  and a private store never receives it, gate or no gate" \
      "$(peer none 1 | cut -d" " -f3-4) $(peer all 1 | cut -d" " -f3-4)" \
      "appeared-in-store=False precious=kept appeared-in-store=False precious=kept"

  # The budget is computed after the descriptor limit is raised: a 1000-deep
  # tree is expired completely from the default soft limit of 1024, where the
  # budget once came out at 768 and left the bottom unexpired at every pass.
  L="${T}/limit"; store "${L}"
  python3 -c "
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
for i in range(1000):
    os.mkdir(\"d\", dir_fd=fd); n = os.open(\"d\", os.O_RDONLY, dir_fd=fd); os.close(fd); fd = n
" "${L}/table"
  ( ulimit -Sn 1024; "${W}" --dir "${L}/table" --idle 30m --max-age 7d --now "${later}" >/dev/null 2>&1 )
  is  "a tree deeper than the default soft fd limit allows still expires completely" \
      "$(ls -A "${L}/table" | wc -l)" "0"

  # A rename puts a directory deeper than mkdir can (measured: two 2100-deep
  # chains, one renamed into the bottom of the other). Where the kernel then
  # refuses to resolve it (AppArmor, about 8 KiB of path), the sweep cannot
  # reach it -- and must SAY so: either everything expires, or --check warns.
  N="${T}/renamed"; store "${N}"
  python3 -c "
import os, sys
root = os.open(sys.argv[1], os.O_RDONLY)
def chain(name, n):
    os.mkdir(name, dir_fd=root); fd = os.open(name, os.O_RDONLY, dir_fd=root)
    for i in range(n):
        os.mkdir(\"d\", dir_fd=fd); x = os.open(\"d\", os.O_RDONLY, dir_fd=fd); os.close(fd); fd = x
    return fd
a = chain(\"A\", 2100); os.close(chain(\"B\", 2100))
os.rename(\"B\", \"B\", src_dir_fd=root, dst_dir_fd=a)
" "${N}/table"
  "${W}" --dir "${N}/table" --idle 30m --max-age 7d --now "${later}" >/dev/null 2>&1
  "${W}" --check --dir "${N}/table" --idle 30m >/dev/null 2>&1; rc=$?
  is  "a tree renamed deeper than reach is expired, or --check warns: never silent" \
      "$([ "$(ls -A "${N}/table" | wc -l)" = 0 ] || [ "${rc}" = 3 ] && echo said || echo silent)" "said"

  # The in-unit probe (systemd seat F5): role-aware, never red or green by
  # construction. The sweep files /etc/shadow (root with DAC_OVERRIDE reads
  # it, P12) instead of counting it, and the watcher passes when the KERNEL
  # refuses its mark outside the initial user namespace -- said as such.
  PS="${T}/probestore"; store "${PS}"
  out="$("${W}" --probe-sandbox --dir "${PS}/table" --probe-role sweep 2>&1)"; rc=$?
  is  "the sweep probe files /etc/shadow, expires its canary and passes" \
      "${rc} $(grep -c "^filed r /etc/shadow" <<<"${out}") $(grep -c "control sweep: expired=1 left=0" <<<"${out}")" "0 1 1"
  out="$(python3 - "${W}" "${PS}/table" <<"PY" 2>&1
import ctypes, errno, importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
class Libc(object):
    def __getattr__(self, n): return getattr(m._libc_real, n)
    def fanotify_mark(self, *a):
        ctypes.set_errno(errno.EPERM); return -1
m._libc_real, m._libc = m._libc, Libc()
m.initial_userns = lambda: False
print("good", m._probe_role(sys.argv[2], "watch", None, 0))
PY
)"
  is  "the watch probe passes on a kernel-refused mark, and says so" \
      "$(grep -c "mark=EPERM-by-kernel" <<<"${out}") $(sed -n "s/^good //p" <<<"${out}")" "1 True"

  # And binds exactly the address given, not a wildcard: read from the
  # socket table of the kernel while it runs.
  RL="${T}/relaylisten"; store "${RL}"
  port=$((30000 + RANDOM % 20000))
  "${W}" --relay-server --dir "${RL}/table" --allow 127.0.0.1 --listen 127.0.0.1 --port "${port}" >/dev/null 2>&1 &
  rp=$!; sleep 1
  hexport="$(printf %04X "${port}")"
  bound="$(awk -v p=":${hexport}" "\$2 ~ p\"\$\" {print \$2}" /proc/net/udp /proc/net/udp6 2>/dev/null | paste -sd " ")"
  kill "${rp}" 2>/dev/null; wait "${rp}" 2>/dev/null
  is  "the relay server binds exactly the address it was given" "${bound}" "0100007F:${hexport}"

  # DRY RUN (owner, first switch-on): every change that passes the checks is
  # logged as "would ..." and NOT made -- names logged only here, on request.
  DR="${T}/dryrun"; store "${DR}"; DT="${DR}/table"
  mkdir -m 700 "${DT}/d"; printf x > "${DT}/d/old"; chmod 600 "${DT}/d/old"
  mkdir "${DT}/empty"; ln -s /etc "${DT}/ln"; mkfifo "${DT}/fifo"
  before="$(cd "${DT}" && find . -printf "%p %m %y %i\n" | sort)"
  out="$("${W}" --dir "${DT}" --idle 2m --max-age 10m --dry-run --now "${later}" 2>&1)"; rc=$?
  after="$(cd "${DT}" && find . -printf "%p %m %y %i\n" | sort)"
  is  "--dry-run changes nothing: every name, type and mode as before" \
      "${rc} $([ "${before}" = "${after}" ] && echo unchanged || echo CHANGED)" "0 unchanged"
  is  "and logs what it would do, each kind, by table-relative name" \
      "$(grep -c "would expire d/old" <<<"${out}") $(grep -c "would remove-non-file ln" <<<"${out}") $(grep -c "would rmdir empty" <<<"${out}") $(grep -c "would widen d$" <<<"${out}")" "1 1 1 1"
  is  "and its summary says nothing was changed" "$(grep -c "dry-run: would have .* NOTHING was changed" <<<"${out}")" "1"
  "${W}" --dir "${DT}" --idle 2m --max-age 10m --dry-run=2 >/dev/null 2>&1
  is  "a dry-run value that is neither on nor off is refused, not guessed" "$?" "2"
  out="$("${W}" --dir "${DT}" --idle 2m --max-age 10m --now "${later}" 2>&1)"
  is  "without it the same pass is real, and logs no name" \
      "$(ls -A "${DT}" | wc -l) $(grep -c "would\|d/old" <<<"${out}")" "0 0"

  # A6: the test clock says it is a test clock.
  has "--now warns that it is not the real time" \
      "$("${W}" --dir "${D}" --idle 30m --max-age 7d --now "${later}" 2>&1)" "WARNING: --now"

  # A8: --any-fstype widens the fstype list and nothing else.
  n=0
  for st in no-nosymfollow no-nodev no-noexec no-nosuid relatime; do
    o="$(timeout 10 "${W}" --relay-client --store "${T}/${st}" --idle 30m --to 127.0.0.1 --port 9 --any-fstype 2>&1)"
    [ "$?" = 1 ] && grep -q ": flags: the mount lacks " <<<"${o}" && n=$((n + 1))
  done
  is  "--any-fstype still refuses each missing flag" "${n}" "5"

  # A2: inside a user namespace the overflow uid is accepted as root, read
  # from the kernel.
  is  "in a user namespace, the overflow uid of the kernel is accepted as root" \
      "$(python3 -c "
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader(\"s\", sys.argv[1]); sp = importlib.util.spec_from_loader(\"s\", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m); print(sorted(m._root_uids()))" "${W}")" \
      "[0, $(cat /proc/sys/kernel/overflowuid)]"
  '
)

echo '== the relay: a burst is paced to what the server'"'"'s socket holds, and every loss is counted (P36) =='
# Measured on an NFS client and its ZFS server, 2026-10-03 (R7): 50000 opens
# in 20 s; the client sent its first ~1000 records as the opens arrived, ONE
# RECORD PER DATAGRAM, and the server's socket -- at rmem_default, 212992
# bytes, about 220 such datagrams -- dropped 278 of them while the server was
# busy on ZFS.
# The kernel's drop counter said 278; nothing the server or the client logged
# did, and the client could not even say what it had sent. Written from that:
# the burst must arrive whole at a SLOW server with a DEFAULT-sized buffer,
# the server's own counts must carry the kernel's drops, and the client must
# count every open it does not send and say so on demand and at exit.
( set +e
  W="${ROOT}/hdw4s-shared-sweep"
  T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  out="$(python3 - "${W}" "${T}" <<'PY' 2>&1
import importlib.machinery, importlib.util, os, socket, struct, sys
l = importlib.machinery.SourceFileLoader("s", sys.argv[1]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
d = os.path.join(sys.argv[2], "p36"); os.makedirs(os.path.join(d, "sub"))
for i in range(5000):
    open(os.path.join(d, "f%04d" % i), "w").close()
long = [b"L%03d" % i + b"x" * 246 for i in range(300)]
for n in long:
    open(os.path.join(d, os.fsdecode(n)), "w").close()
fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
m.log = lambda t, lv=None: None
def drive(c, names, until=70.0):
    c.pace.t = c.grams.t = 0.0
    for n in names:
        c.pending[n] = True
    t, sent, most, charge, first, tally = 0.0, 0, 0, 0, None, True
    while t <= until:
        recs = c.records(t, c.pace.room(t), c.grams.room(t))
        sizes = []; grams = m.pack(recs, sizes)
        if recs:
            c.pace.take(len(recs), t); c.grams.take(len(grams), t)
        tally = tally and sum(sizes) == len(recs)
        most = max(most, len(grams)); charge = max(charge, len(grams) * m.GRAM_CHARGE)
        sent += len(recs)
        if first is None:
            first = len(recs)
        t += m.CLIENT_TICK
    return sent, most, charge, first, len(c.pending), tally
c = m.Client(fd, 7200)
sent, most, charge, first, left, tally = drive(c, [b"f%04d" % i for i in range(5000)])
print("short", sent, left, most <= m.CLIENT_GRAM_BURST, charge <= m.SERVER_RCVBUF, tally)
c = m.Client(fd, 7200)
sent, most, charge, first, left, tally = drive(c, long, 20.0)
print("long", first, sent, most <= m.CLIENT_GRAM_BURST, charge <= m.SERVER_RCVBUF)
print("stock", m.SERVER_RCVBUF <= 2 * 212992)
c = m.Client(fd, 7200)
for n in (b"gone", b"sub", b"f0001", b"\xff"):
    c.pending[n] = True
c.announced[b"f0001"] = 0.5
c.records(1.0)
c.events(struct.pack("<iIII", 999, m.IN_OPEN, 0, 8) + b"f0002\0\0\0")
print("discards", " ".join("%s=%d" % kv for kv in sorted(c.counts.items())), len(c.pending))
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); r.bind(("127.0.0.1", 0))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(2000):
    s.sendto(b"x", r.getsockname())
hexport = "%04X" % r.getsockname()[1]
proc = [l.split()[-1] for l in open("/proc/net/udp") if l.split()[1].endswith(":" + hexport)]
kd = m.kernel_drops(r)
print("kdrops", kd is not None and kd > 0, [str(kd)] == proc)
big = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
big.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
had = big.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
small = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
small.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
print("grow", had > m.SERVER_RCVBUF and m.size_receive(big) == had, m.size_receive(small) >= m.SERVER_RCVBUF)
PY
)"
  is  'paced in datagrams: 5000 queued opens all go out, never more datagrams at once than the server is sized for' \
      "$(sed -n 's/^short //p' <<<"${out}")" '5000 0 True True True'
  is  '  and with long names the DATAGRAM cap binds, not the record cap' \
      "$(sed -n 's/^long //p' <<<"${out}")" '80 300 True True'
  is  '  and the server'"'"'s buffer for that burst is what a stock rmem_max grants' \
      "$(sed -n 's/^stock //p' <<<"${out}")" 'True'
  is  'every pending open the client does not send is counted, by reason' \
      "$(sed -n 's/^discards //p' <<<"${out}")" \
      'coalesced=1 discard-not-regular=1 discard-not-utf8=1 discard-stat-ENOENT=1 discard-unknown-wd=1 0'
  is  'the server reads its socket'"'"'s kernel drops from the socket, the same number /proc/net/udp shows' \
      "$(sed -n 's/^kdrops //p' <<<"${out}")" 'True True'
  is  'the server grows a small receive buffer to the burst, and never shrinks a larger one' \
      "$(sed -n 's/^grow //p' <<<"${out}")" 'True True'

  # The real client and the real server, run through main() as their units
  # run them, multicast across a veth pair. The ONE stand-in: the server's
  # touch sleeps 8 ms first (the measured server was committing to ZFS). And
  # the server is held at the kernel's DEFAULT buffer (rmem_default, 212992 on
  # the measured server and on a stock kernel): its size_receive is replaced
  # by a read, so the burst test proves the CLIENT's pacing alone -- the
  # server's own enlargement is a second, separate layer. Red on the unpaced
  # client: the burst overflows the socket.
  P36_TESTS=6
  if unshare -Urnm true 2>/dev/null; then
    export W T
    # shellcheck disable=SC2016  # expanded by the shell inside the namespace
    out="$(unshare -Urnm bash -c '
      set +e
      ip link set lo up; ip link add va type veth peer name vb
      ip addr add 10.200.0.1/24 dev va; ip link set va up
      unshare -n sleep 300 & P=$!; sleep 0.3
      ip link set vb netns "${P}"
      nsenter -t "${P}" -n sh -c "ip link set lo up; ip addr add 10.200.0.2/24 dev vb; ip link set vb up"
      S="${T}/p36store"; mkdir -p "${S}"
      mount -t tmpfs -o nosymfollow,nodev,noexec,nosuid,strictatime,mode=0755 s "${S}"
      mkdir -m 0777 "${S}/table"; D="${S}/table"; N=1200
      python3 -c "
import os, sys
for i in range(int(sys.argv[2])):
    p = os.path.join(sys.argv[1], \"f%06d\" % i); open(p, \"w\").close(); os.utime(p, (1e9, 1e9))
open(os.path.join(sys.argv[1], \"forced\"), \"w\").close()
" "${D}" "${N}"
      cat > "${T}/p36run.py" <<"PY"
import errno, importlib.machinery, importlib.util, os, sys, time
l = importlib.machinery.SourceFileLoader("s", os.environ["W"]); sp = importlib.util.spec_from_loader("s", l)
m = importlib.util.module_from_spec(sp); l.exec_module(m)
if sys.argv[1] == "server":
    real = m.Resolver.touch
    def slow(self, name, fileid):
        time.sleep(0.008); return real(self, name, fileid)
    m.Resolver.touch = slow
    # HELD at 212992 bytes, the default of the boxes this was measured on, and
    # not at whatever default the kernel running it has: on a CI runner the
    # default was 1 MiB, which made the slow-server test an easy one and failed
    # its label (2026-10-03). The kernel doubles a request, so 106496 asks for it.
    def held(sock):
        sock.setsockopt(m.socket.SOL_SOCKET, m.socket.SO_RCVBUF, 106496)
        return sock.getsockopt(m.socket.SOL_SOCKET, m.socket.SO_RCVBUF)
    m.size_receive = held
else:
    # The red arm the brief asks for: ONE forced stat failure.
    stat = os.stat
    def forced(p, *a, **k):
        if p == b"forced":
            raise OSError(errno.EIO, "forced")
        return stat(p, *a, **k)
    m.os.stat = forced
sys.exit(m.main(["hdw4s-shared-sweep"] + sys.argv[2:]))
PY
      fresh() { python3 -c "
import os, sys
print(sum(os.stat(os.path.join(sys.argv[1], \"f%06d\" % i)).st_atime > 1.5e9 for i in range(int(sys.argv[2]))))" "${D}" "${N}"; }
      port=$((30000 + RANDOM % 20000)); hexport="$(printf %04X "${port}")"
      drops() { awk -v p=":${hexport}" "\$2 ~ p\"\$\" {print \$NF}" /proc/net/udp; }
      python3 "${T}/p36run.py" server --relay-server --dir "${D}" --interface=va --port "${port}" 2>"${T}/p36s.log" & SP=$!
      sleep 1
      nsenter -t "${P}" -n python3 "${T}/p36run.py" client --relay-client --store "${S}" --idle 30m \
        --port "${port}" --interface=vb --any-fstype 2>"${T}/p36c.log" & CP=$!
      sleep 2
      python3 -c "
import os, sys, time
t0 = time.monotonic()
for i in range(int(sys.argv[2])):
    d = t0 + i / 2500.0 - time.monotonic()
    if d > 0: time.sleep(d)
    os.close(os.open(os.path.join(sys.argv[1], \"f%06d\" % i), os.O_RDONLY | os.O_NOATIME))
os.close(os.open(os.path.join(sys.argv[1], \"forced\"), os.O_RDONLY | os.O_NOATIME))
" "${D}" "${N}"
      for _ in $(seq 30); do [ "$(fresh)" = "${N}" ] && break; sleep 1; done
      echo "burst $(fresh)/${N} $(drops) $(ss -uamn "sport = :${port}" | sed -n "s/.*skmem:(.*,rb\([0-9]*\),.*/\1/p")"
      kill -USR1 "${CP}"; sleep 1.5
      kill -TERM "${CP}"; wait "${CP}"; echo "client-exit $?"
      echo "client-usr1 $(grep -c "counts: .*pending [0-9]*$" "${T}/p36c.log")"
      echo "client-exit-line $(grep -c "(at exit)" "${T}/p36c.log") $(grep "(at exit)" "${T}/p36c.log" | grep -o "discard-stat-EIO=[0-9]*\|records-sent=[0-9]*" | paste -sd " ")"
      # The old shape, on purpose: one record per datagram, back to back.
      nsenter -t "${P}" -n python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 32, socket.inet_aton(\"0.0.0.0\") + bytes(4) + struct.pack(\"@i\", socket.if_nametoindex(\"vb\")))
for i in range(1500):
    s.sendto(bytes([1]) + struct.pack(\">BBHQ\", 1, 0, 7, 0) + b\"f000000\", (\"239.255.47.48\", int(sys.argv[1])))
" "${port}"
      sleep 1; d2="$(drops)"; kill -USR1 "${SP}"; sleep 6
      echo "flood ${d2} $(grep "counts:" "${T}/p36s.log" | tail -1 | grep -o "drop-kernel-datagrams=[0-9]*")"
      kill "${SP}"; wait "${SP}" 2>/dev/null
      kill "${P}" 2>/dev/null; umount "${S}"
    ' 2>&1)"
    is  'a burst of 1200 opens at a slow server held at a 212992-byte buffer: every file announced, the socket drops none' \
        "$(sed -n 's/^burst //p' <<<"${out}" | awk '{print $1, $2, "rb=" $3}')" '1200/1200 0 rb=212992'
    is  'the client logs its counts on SIGUSR1' "$(sed -n 's/^client-usr1 //p' <<<"${out}")" '1'
    is  'a stopped client exits 0' "$(sed -n 's/^client-exit //p' <<<"${out}")" '0'
    is  '  and logs its counts once at exit, with the forced stat failure counted' \
        "$(sed -n 's/^client-exit-line //p' <<<"${out}")" '1 discard-stat-EIO=1 records-sent=1200'
    flood="$(sed -n 's/^flood //p' <<<"${out}")"
    is  'flooded the old way, the socket drops datagrams' "$(awk '{print ($1 > 0)}' <<<"${flood}")" '1'
    is  '  and the server'"'"'s own counts line carries the same number' \
        "$(awk '{print "drop-kernel-datagrams=" $1 == $2}' <<<"${flood}")" '1'
  else
    for _ in $(seq "${P36_TESTS}"); do
      bad 'the relay burst on real sockets' 'unshare -Urnm is refused here, so none of them ran'
    done
  fi
)

echo '== /shared: the bind source is made with no mode, so tmpfiles never re-modes the table =='
# A mode on this line would make every "systemd-tmpfiles --create" -- a package
# upgrade runs one -- chmod the TABLE bound there back to 0755.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  # THIS line, by its path: the file also makes the named desktops' failure
  # ledger (since 2026-10-03), which is never bound over and does take a mode.
  line="$(grep -v '^#' "${ROOT}/hdw4s-tmpfiles.conf" | grep ' /run/hdw4s/shared ')"
  is 'one line for it, no mode, no owner, no age' "${line}" 'd /run/hdw4s/shared - - - -'
  mkdir -p "${T}/run/hdw4s/shared"; chmod 0777 "${T}/run/hdw4s/shared"
  printf '%s\n' "${line}" | systemd-tmpfiles --create --root="${T}" - 2>/dev/null
  is 'a table bound there stays 0777 through a tmpfiles run' "$(stat -c %a "${T}/run/hdw4s/shared")" '777'
  # RED ARM: the same run with a mode on the line does re-mode it, so the
  # assertion above can fail.
  printf '%s\n' 'd /run/hdw4s/shared 0755 - - -' | systemd-tmpfiles --create --root="${T}" - 2>/dev/null
  is 'RED ARM: a mode on the line would have made it 0755' "$(stat -c %a "${T}/run/hdw4s/shared")" '755'
  rmdir "${T}/run/hdw4s/shared"
  printf '%s\n' "${line}" | systemd-tmpfiles --create --root="${T}" - 2>/dev/null
  is 'made fresh, it is 0755: nobody writes to /shared before a store is bound' \
    "$(stat -c %a "${T}/run/hdw4s/shared")" '755'
)

echo '== /shared: the expose service binds only what the guard accepts, and unmounts only its own =='
# mount and umount are stand-ins that edit a stand-in of the kernel's mount
# table; the guard is a stand-in answering as told, and naming the mount id it
# was asked about the way the real one does. Every refusal must leave nothing
# of ours bound and exit non-zero; every acceptance must bind exactly once; and
# NOTHING this service did not mount itself may ever be unmounted by it -- on a
# desktop host /home may be a bind of a homes server, and a lazy unmount aimed
# at the wrong mount is the other way to lose what is on it.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/etc" "${T}/run/hdw4s/shared" "${T}/elsewhere" "${T}/run/hdw4s/shared-store/table"
  printf 'MemTotal:       16777216 kB\n' > "${T}/meminfo"
  printf '%s\n' '1 0 0:1 / / rw - ext4 /dev/root rw' > "${T}/mountinfo"
  E="${T}/run/hdw4s/shared"; S="${T}/run/hdw4s/shared-store"
  # The stand-ins' shared helpers: the topmost mount at a path, and adding one.
  cat > "${T}/mi.sh" <<'MI'
mi_top() { awk -v p="$1" '$5 == p { on[$1] = $2 } END { for (i in on) { t = 1
           for (j in on) if (on[j] == i) t = 0; if (t) print i } }' "${T}/mountinfo"; }
# mi_add ROOT PATH [OPTS] [FSTYPE SOURCE DEV]: a mount on top of whatever is at PATH.
mi_add() { local id parent; id=$(( $(awk '{print $1}' "${T}/mountinfo" | sort -n | tail -1) + 1 ))
           parent="$(mi_top "$2")"
           echo "${id} ${parent:-1} ${6:-0:9} $1 $2 rw${3:-} - ${4:-tmpfs} ${5:-hdw4s-shared} rw" >> "${T}/mountinfo"; }
MI
  cat > "${T}/guard" <<'STUB'
#!/bin/bash
. "${T}/mi.sh"
echo "$(pwd) $*" >> "${T}/guard.log"
case "$1" in
  --harden) [ ! -e "${T}/harden-says" ] || cat "${T}/harden-says" >&2
            [ "$(cat "${T}/harden" 2>/dev/null || echo 0)" = 0 ] && exit 0
            echo "hdw4s-shared-sweep: refused $2: store-extra: stand-in" >&2; exit 1;;
  --guard)  id="$(mi_top "$2")"
            [ -n "${id}" ] || { echo "hdw4s-shared-sweep: refused $2: form-i: not a mount root" >&2; exit 1; }
            v="$(cat "${T}/guard-$4" 2>/dev/null || echo 0)"
            [ "${v}" = 0 ] && { echo "accepted $2 form=$4 fstype=tmpfs mount=${id}"; exit 0; }
            echo "hdw4s-shared-sweep: refused $2: $(cat "${T}/clause" 2>/dev/null || echo flags): stand-in" >&2
            exit "${v}";;
esac
exit 2
STUB
  chmod +x "${T}/guard"
  # shellcheck source=/dev/null
  mount()  { . "${T}/mi.sh"; echo "mount $*" >> "${T}/mounts"
             case "$*" in
               # A bind of an NFS store's table shows root "/" and the path in
               # its SOURCE, as the kernel lists it (measured on a box).
               *--bind*) if [ -e "${T}/nfs-store" ]; then
                           mi_add / "${*: -1}" ',nosymfollow' nfs4 "$(cat "${T}/nfs-store")/table" 0:251
                         else mi_add /table "${*: -1}" ',nosymfollow'; fi;;
               *tmpfs*)  mi_add / "${*: -1}" ',nosymfollow' tmpfs;;
             esac; }
  umount() { . "${T}/mi.sh"; echo "umount $*" >> "${T}/mounts"
             local top; top="$(mi_top "${*: -1}")"
             [ -n "${top}" ] && sed -i "/^${top} /d" "${T}/mountinfo"; }
  # systemctl: a start marks a unit active; show answers from that, and from
  # what a test says about how a stopped unit last ended.
  systemctl()  { echo "systemctl $*" >> "${T}/mounts"
                 local u
                 case "$1" in
                   show) case "$3" in
                           ActiveState) if grep -xF -- "$5" "${T}/active" >/dev/null 2>&1
                                        then echo active; else echo inactive; fi;;
                           ExecMainCode)   cat "${T}/code" 2>/dev/null || echo 2;;
                           ExecMainStatus) cat "${T}/status" 2>/dev/null || echo 15;;
                         esac;;
                   start) shift; [ "$1" != --no-block ] || shift
                          for u in "$@"; do echo "${u}" >> "${T}/active"; done;;
                 esac; }
  export -f mount umount systemctl
  export T HDW4S_ETCDIR="${T}/etc" HDW4S_MEMINFO="${T}/meminfo" \
         HDW4S_MOUNTINFO="${T}/mountinfo" HDW4S_SHARED_STATE="${T}/state" \
         HDW4S_SHARED_EXPOSE="${E}" HDW4S_SHARED_STORE="${S}" HDW4S_SHARED_TOOL="${T}/guard"
  conf() { printf '%s\n' "$@" > "${T}/etc/hdw4s.conf"; }
  # Run from inside a directory that is not /, as an administrator might: the
  # guard must still be run from /, so nothing here is on its import path.
  expose() { : > "${T}/mounts"; : > "${T}/guard.log"
             ( cd "${T}/elsewhere" && "${ROOT}/hdw4s-shared-expose" "$@" 2>&1 ); }
  at() { awk -v p="$1" '$5 == p' "${T}/mountinfo" | wc -l; }
  reset() { printf '%s\n' '1 0 0:1 / / rw - ext4 /dev/root rw' > "${T}/mountinfo"
            rm -rf "${T}/state" "${T}/harden" "${T}/guard-i" "${T}/clause" \
                   "${T}/active" "${T}/code" "${T}/status"; }
  # A mount somebody else made, at the exposure's path, on top of whatever is there.
  foreign() { . "${T}/mi.sh"; mi_add / "${E}" '' tmpfs foreign 0:99; }

  conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=10%
  echo 1 > "${T}/guard-i"   # form (i) refuses even what was just bound
  out="$(expose)"; rc=$?
  m="$(cat "${T}/mounts")"
  # 10% of 16 GiB, in bytes: the kernel would have taken 10% of the HOST.
  has 'a percentage is worked out from meminfo, not handed to the kernel' "${m}" 'size=1717986918,'
  has 'with an inode cap derived from it' "${m}" 'nr_inodes=104858,'
  has 'and every flag' "${m}" 'nosymfollow,nodev,noexec,nosuid,strictatime'
  # A store root only root can pass through: no desktop reaches the table by
  # the store's own path (ls /run/hdw4s/shared-store/table as a seat fails).
  has 'the tmpfs store root is 0700' "${m}" ',mode=0700,'
  has 'and the store is made private before anything is bound from it' \
    "$(sed -n '/tmpfs/,/--bind/p' "${T}/mounts")" "mount --make-private -- ${S}"
  hasnt 'never a percentage on the mount' "${m}" 'size=10%'
  has 'the table is bound onto /run/hdw4s/shared' "${m}" "mount --bind -- ${S}/table ${E}"
  # What was bound is not trusted for having been bound.
  is  'what was bound is judged, and taken away when it fails' "$(at "${E}")" '0'
  has 'by a lazy unmount that does not resolve the path through the store' "${m}" "umount -l -c -- ${E}"
  is  'and the run fails' "${rc}" '1'
  is  'the guard ran from /, never from where it was started' \
    "$(cut -d' ' -f1 "${T}/guard.log" | sort -u)" '/'

  reset; out="$(expose)"; rc=$?
  is  'accepted: the run succeeds' "${rc}" '0'
  is  'and binds exactly once' "$(grep -c -- '--bind' "${T}/mounts")" '1'
  is  'and records which mount it made, as the kernel lists it' "$(cat "${T}/state/exposure" 2>/dev/null)" \
    "$(awk -v p="${E}" '$5 == p {print $1, $3, $4, $8, $9}' "${T}/mountinfo")"
  has 'and starts the local sweep of that store' "$(cat "${T}/mounts")" \
    'start --no-block hdw4s-shared-sweep@'
  out="$(expose)"; rc=$?
  is  'already exposed and accepted: nothing to do' "$(grep -c -- 'mount' "${T}/mounts")" '0'
  is  'and nothing to say' "${out}" ''
  hasnt 'and a running sweep and watcher are not started again' "$(cat "${T}/mounts")" ' start '

  # KEPT RUNNING, not only started at the bind (measured on a box: a deploy
  # stopped the watcher, the table stayed bound, nothing started it again).
  inst="$(systemd-escape --path -- "${S}")"
  W="hdw4s-shared-watch@${inst}.service"; TM="hdw4s-shared-sweep@${inst}.timer"
  sed -i "/^hdw4s-shared-watch@/d" "${T}/active"; echo 2 > "${T}/code"; echo 15 > "${T}/status"
  out="$(expose)"; rc=$?
  has 'a watcher stopped while the table stays bound is started by the next run' \
    "$(cat "${T}/mounts")" "start --no-block ${W}"
  is  'and that run binds nothing' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  has 'and says so' "${out}" 'which was not running'
  sed -i "/^hdw4s-shared-sweep@/d" "${T}/active"; out="$(expose)"
  has 'so is a sweep timer that was stopped' "$(cat "${T}/mounts")" "start --no-block ${TM}"
  # Ended by itself with status 0: the kernel refused it a watch here.
  sed -i "/^hdw4s-shared-watch@/d" "${T}/active"; echo 1 > "${T}/code"; echo 0 > "${T}/status"
  out="$(expose)"
  hasnt 'a watcher that ended by itself with status 0 is left alone' "$(cat "${T}/mounts")" "start --no-block ${W}"

  # DRIFT: the exposure loses a flag. Its own mount, refused for its flags
  # alone: unmounted, and NOT rebound in the same run.
  echo 1 > "${T}/guard-i"; out="$(expose)"; rc=$?
  is  'drift: the exposure is unmounted' "$(at "${E}")" '0'
  is  'and not rebound in the same run' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  is  'and the run fails' "${rc}" '1'
  has 'naming the clause' "${out}" 'flags: stand-in'
  is  'and the heal is marked, so it is never invisible' \
    "$([ -s "${T}/state/drift" ] && echo marked || echo unmarked)" 'marked'
  rm -f "${T}/guard-i"; expose >/dev/null

  # IDENTITY IS THREE FACTS FROM THE MOUNT TABLE, each enough to refuse.
  # Our recorded mount, but the kernel now says it has a different root:
  rm -f "${T}/state/drift"
  sed -i "s| /table ${E} | /elsewhere ${E} |" "${T}/mountinfo"
  sed -i "s| /table | /elsewhere |" "${T}/state/exposure"
  echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'a recorded mount whose root is not /table is NOT unmounted' "$(at "${E}")" '1'
  has 'and why is said' "${out}" 'not /table'
  is  'and no heal is marked' "$([ -e "${T}/state/drift" ] && echo marked || echo unmarked)" 'unmarked'
  reset; expose >/dev/null
  # Our recorded mount, but the store now mounted there is another filesystem:
  sed -i "s|^\([0-9]*\) \([0-9]*\) 0:9 / ${S} \(.*\) - tmpfs hdw4s-shared rw$|\1 \2 0:7 / ${S} \3 - nfs4 server:/other rw|" "${T}/mountinfo"
  echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'an exposure that no longer shows the store'"'"'s filesystem is NOT unmounted' "$(at "${E}")" '1'
  has 'and why is said' "${out}" 'the store is nfs4'
  # And the record and the kernel must agree on the whole entry, not the id alone.
  reset; expose >/dev/null; sed -i 's/ 0:9 / 0:8 /' "${T}/state/exposure"
  echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'a mount whose id matches but whose device does not is NOT unmounted' "$(at "${E}")" '1'
  reset; expose >/dev/null

  # THE DELETION-SAFETY ARMS. A mount stacked on top of the live exposure is
  # somebody else's: left where it is, and so is ours beneath it.
  foreign; out="$(expose)"; rc=$?
  is  'a mount stacked on the exposure is NOT unmounted' "$(at "${E}")" '2'
  is  'no unmount is even attempted' "$(grep -c 'umount' "${T}/mounts")" '0'
  is  'nothing is bound on top of it either' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  is  'and the run fails' "${rc}" '1'
  has 'saying whose it is not' "${out}" 'is not one this service made'
  out="$(conf HDW4S_SHARED=off; expose)"; rc=$?
  is  'not even when /shared is turned off' "$(at "${E}")" '2'
  is  'which then fails, rather than claiming it is clean' "${rc}" '1'
  conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=10%

  # A foreign mount alone there, with nothing of ours: the same.
  reset; foreign; out="$(expose)"; rc=$?
  is  'a mount this service did not make is NOT unmounted' "$(at "${E}")" '1'
  is  'nor bound over' "$(grep -c -- '--bind' "${T}/mounts")" '0'

  # Our own mount, but the guard says it is not even shaped like the exposure:
  # left in place -- only a lost FLAG on our own mount is a reason to unmount.
  reset; expose >/dev/null; echo 1 > "${T}/guard-i"; echo form-i > "${T}/clause"
  out="$(expose)"; rc=$?
  is  'our own mount refused for its shape is left in place' "$(at "${E}")" '1'
  has 'and the refusal is named' "${out}" 'form-i'
  # And a guard that could not tell (2) is no licence to unmount.
  echo 2 > "${T}/guard-i"; rm -f "${T}/clause"; out="$(expose)"; rc=$?
  is  'a guard that could not tell unmounts nothing' "$(at "${E}")" '1'
  is  'and the run fails' "${rc}" '1'

  # A flag the tool added back in place is a repair, and it is said.
  reset; expose >/dev/null
  echo 'hdw4s-shared-sweep: added nosymfollow to the store.' > "${T}/harden-says"
  out="$(expose)"; rm -f "${T}/harden-says"
  has 'a repair --harden made is said' "${out}" 'added nosymfollow'

  echo 1 > "${T}/harden"; out="$(expose)"; rc=$?
  is  'a store the guard refuses is unbound' "$(at "${E}")" '0'
  is  'and nothing is bound in its place' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  is  'and the run fails' "${rc}" '1'

  # A STORE THAT DOES NOT ANSWER: a stat that hangs, as on a dead NFS mount.
  # The stat is a stand-in that sleeps; the run must not wait for it, and takes
  # its own mount away on the recorded identity, without a guard that would
  # block on the same dead store.
  reset; expose >/dev/null
  stat() { sleep 20; }; export -f stat
  start="${SECONDS}"; out="$(HDW4S_SHARED_HEALTH_SECONDS=1 expose)"; rc=$?
  unset -f stat
  is  'a store that does not answer is given up on, not waited for' \
    "$([ $(( SECONDS - start )) -lt 10 ] && echo promptly || echo "after $(( SECONDS - start ))s")" 'promptly'
  is  'and the table is unbound' "$(at "${E}")" '0'
  is  'and the run fails' "${rc}" '1'
  hasnt 'and the shell does not announce the abandoned child' "${out}" 'Killed'
  has 'saying the guard was skipped, and why' "${out}" 'the guard is SKIPPED'
  is  'without ever asking the guard about the exposure' "$(grep -c -- '--guard' "${T}/guard.log")" '0'
  # Even then, only our own.
  reset; expose >/dev/null; foreign
  stat() { sleep 20; }; export -f stat
  out="$(HDW4S_SHARED_HEALTH_SECONDS=1 expose)"; unset -f stat
  is  'a dead store is no licence to unmount a foreign mount either' "$(at "${E}")" '2'

  reset; conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=lots; out="$(expose)"; rc=$?
  is  'a size that is not one mounts nothing' "$(grep -c 'tmpfs' "${T}/mounts")" '0'
  is  'and fails' "${rc}" '1'

  reset; conf HDW4S_SHARED=source; out="$(expose)"; rc=$?
  is  'source with no HDW4S_SHARED_SOURCE binds nothing' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  is  'and fails' "${rc}" '1'

  reset; conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SWEEP=external; out="$(expose)"
  hasnt 'SWEEP=external starts no sweep here' "$(cat "${T}/mounts")" 'hdw4s-shared-sweep@'
  out="$(expose)"
  hasnt 'nor keeps one running' "$(cat "${T}/mounts")" ' start '

  out="$(conf HDW4S_SHARED=off; expose)"; rc=$?
  is  'off: our table is taken away' "$(at "${E}")" '0'
  is  'and that is a success' "${rc}" '0'

  # AN NFS STORE, as a container sees one bound in: the exposure's root is "/"
  # and its source is the store's source plus /table. That is this service's
  # own bind, and it must be recognised as one -- and nothing else with root
  # "/" may be.
  reset; mkdir -p "${T}/src/table"; echo '192.0.2.1:/export/shared' > "${T}/nfs-store"
  mi_add / "${T}/src" ',nosymfollow' nfs4 192.0.2.1:/export/shared 0:251
  conf HDW4S_SHARED=source "HDW4S_SHARED_SOURCE=${T}/src" HDW4S_SHARED_SWEEP=external
  out="$(expose)"; rc=$?
  is  'NFS: this service'"'"'s own bind of the table is accepted' "${rc}:$(at "${E}")" '0:1'
  out="$(expose)"; rc=$?
  is  'NFS: and recognised as its own on the next run' "${rc}:$(grep -c -- 'mount' "${T}/mounts")" '0:0'
  echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'NFS: and taken away when it loses a flag' "$(at "${E}")" '0'
  rm -f "${T}/guard-i"; expose >/dev/null
  # Recorded, but now showing a different directory of the same server.
  sed -i "s#:/export/shared/table\\( \\|\$\\)#:/export/shared/other\\1#" "${T}/mountinfo" "${T}/state/exposure"
  echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'NFS: an exposure that does not show the store'"'"'s table is NOT unmounted' "$(at "${E}")" '1'
  has 'and why is said' "${out}" 'not the store'"'"'s table 192.0.2.1:/export/shared/table'
  rm -f "${T}/nfs-store"; rm -rf "${T}/src"; conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=10%

  # THE REAL LINES, captured from the kernel's mount table in a container on a
  # development box (store an NFSv4 mount bound in; this service's bind of its
  # table on top of /run/hdw4s/shared), with only the two mount POINTS moved
  # into this sandbox. Every other field -- ids, device, root, optional fields,
  # type, source -- is as read. The code before this rule refused its own bind
  # here ("has root /, not /table") and left it stranded.
  reset; mkdir -p "${T}/src/table"
  conf HDW4S_SHARED=source "HDW4S_SHARED_SOURCE=${T}/src" HDW4S_SHARED_SWEEP=external
  fixture() { printf '%s\n' \
    '1 0 0:1 / / rw - ext4 /dev/root rw' \
    "1356 1324 0:251 / ${T}/src rw,nosuid,nodev,noexec,nosymfollow master:412 - nfs4 192.0.2.1:/export/shared rw,vers=4.2,soft,proto=tcp" \
    "3417 987 0:251 / ${E} rw,nosuid,nodev,noexec,nosymfollow shared:900 master:412 - nfs4 ${1:-192.0.2.1:/export/shared/table} rw,vers=4.2,soft,proto=tcp" \
    > "${T}/mountinfo"
    mkdir -p "${T}/state"; echo "3417 0:251 / nfs4 ${1:-192.0.2.1:/export/shared/table}" > "${T}/state/exposure"; }
  fixture; out="$(expose)"; rc=$?
  is  'real NFS lines: the exposure is recognised as this service'"'"'s own' "${rc}:$(at "${E}")" '0:1'
  hasnt 'and not refused for its root' "${out}" 'has root /'
  fixture; echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'real NFS lines: and taken away when the guard finds a flag gone' "$(at "${E}")" '0'
  rm -f "${T}/guard-i"
  # Recorded (so the mount id matches), but showing something that is not the
  # store's table: the SECOND proof alone must refuse to unmount it.
  for other in 192.0.2.1:/export/shared/tablex 192.0.2.1:/other-export/table 192.0.2.2:/export/shared/table; do
    fixture "${other}"; echo 1 > "${T}/guard-i"; out="$(expose)"
    is  "real NFS lines: an exposure showing ${other} is NOT unmounted" "$(at "${E}")" '1'
  done
  # Spelled with a doubled or a trailing "/", it is still the store's table.
  fixture '192.0.2.1://export/shared//table/'; echo 1 > "${T}/guard-i"; out="$(expose)"
  is  'real NFS lines: a doubled or trailing "/" does not hide the store'"'"'s table' "$(at "${E}")" '0'
  # A mount stacked on the exposure from a different export: not ours, left.
  fixture; rm -f "${T}/guard-i"
  echo "3500 3417 0:252 / ${E} rw - nfs4 192.0.2.1:/export/shared/tablex rw" >> "${T}/mountinfo"
  out="$(expose)"
  is  'real NFS lines: an NFS mount stacked on the exposure is NOT unmounted' "$(at "${E}")" '2'
  rm -f "${T}/guard-i"; rm -rf "${T}/src"; conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=10%

  # Uninstall's withdrawal: exactly what was recorded, the table and the tmpfs
  # store, and not a mount that merely sits at the store's path.
  reset; conf HDW4S_SHARED=tmpfs; expose >/dev/null
  out="$(expose --withdraw)"; rc=$?
  is  'withdraw: the table and the tmpfs store this service mounted go' "$(at "${E}") $(at "${S}")" '0 0'
  is  'and that is a success' "${rc}" '0'
  reset; . "${T}/mi.sh"; mi_add / "${S}" '' tmpfs foreign 0:99
  out="$(expose --withdraw)"; rc=$?
  is  'withdraw leaves a store mount it has no record of' "$(at "${S}")" '1'

  # The bind source deleted by hand: refused, and NOT recreated -- a desktop
  # start fails 226 in that state, loudly, and that is the safe way round.
  reset; conf HDW4S_SHARED=tmpfs; rmdir "${E}"; out="$(expose)"; rc=$?
  is  'a missing bind source binds nothing' "$(grep -c -- '--bind' "${T}/mounts")" '0'
  is  'and is not quietly recreated' "$([ -e "${E}" ] && echo recreated || echo absent)" 'absent'
  has 'and says what desktops will do' "${out}" '226'
)

echo '== /shared: the expose service against the REAL guard, with real mounts =='
# The groups above stub the guard, so a change in what the guard answers cannot
# reach them -- and one did: a new refusal clause ("no-sibling") turned "the
# store was taken away" into "left mounted", and nothing went red until a
# reviewer ran the real tool. These run hdw4s-shared-expose with the tool
# beside it, on real tmpfs mounts, in a user namespace (unshare -Urm). Where
# that is refused every assertion FAILS rather than skips, as the tool's own
# real-mount group does.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  N=16
  if ! unshare -Urm true 2>/dev/null; then
    for _ in $(seq "${N}"); do
      bad 'the expose service against the real guard' \
          'unshare -Urm is refused here, so none of these ran (kernel.apparmor_restrict_unprivileged_userns?)'
    done
    exit 0
  fi
  export -f ok bad is has hasnt
  export RESULTS T ROOT
  # shellcheck disable=SC2016  # expanded by the shell inside the namespace
  unshare -Urm --propagation private bash -c '
  set +e
  mkdir -p "${T}/run" "${T}/etc" "${T}/src"
  mount -t tmpfs run "${T}/run"; mount --make-shared "${T}/run"
  install -d -m 0755 "${T}/run/hdw4s/shared"
  E="${T}/run/hdw4s/shared"; S="${T}/run/hdw4s/shared-store"
  export HDW4S_SHARED_STATE="${T}/state" HDW4S_ETCDIR="${T}/etc" HDW4S_SHARED_EXPOSE="${E}" \
         HDW4S_SHARED_STORE="${S}" HDW4S_SHARED_TOOL="${ROOT}/hdw4s-shared-sweep"
  conf() { printf "%s\n" "$@" > "${T}/etc/hdw4s.conf"; }
  expose() { "${ROOT}/hdw4s-shared-expose" "$@" 2>&1; }
  n_at() { findmnt -n --mountpoint "$1" | wc -l; }
  # Each case starts clean, so that one failing does not decide the next: the
  # TEST takes away whatever is left, here, in its own namespace.
  fresh() { local d; for d in "${E}" "${S}"; do
              while [ "$(n_at "${d}")" -gt 0 ]; do umount -l "${d}"; done; done
            rm -rf "${T}/state"; }

  # SOURCE MODE: the store taken away under a bound table (F1).
  mount -t tmpfs -o nosymfollow,nodev,noexec,nosuid,strictatime,mode=0755 store "${T}/src"
  install -d -m 0777 "${T}/src/table"; : > "${T}/src/table/item"
  conf HDW4S_SHARED=source "HDW4S_SHARED_SOURCE=${T}/src" HDW4S_SHARED_SWEEP=external
  expose >/dev/null
  is  "real guard: a source store is bound" "$(n_at "${E}")" 1
  umount -l "${T}/src"
  out="$(expose)"; rc=$?
  is  "real guard: a store taken away is unbound (no-sibling)" "$(n_at "${E}")" 0
  is  "and the item is no longer shown" "$(ls -A "${E}")" ""
  is  "and the run fails" "${rc}" 1

  # TMPFS MODE: the store root is 0700, and the real guard accepts it.
  fresh
  conf HDW4S_SHARED=tmpfs HDW4S_SHARED_SIZE=1M HDW4S_SHARED_SWEEP=external
  out="$(expose)"; rc=$?
  is  "real guard: a 0700 tmpfs store is accepted and bound" "${rc}:$(n_at "${E}")" 0:1
  is  "its root is 0700" "$(stat -c %a "${S}")" 700

  # DRIFT: a flag cleared on the exposure is unbound, marked, and healed.
  mount -o remount,bind,symfollow,nodev,noexec,nosuid "${E}"
  expose >/dev/null
  is  "real guard: an exposure that lost nosymfollow is unbound" "$(n_at "${E}")" 0
  is  "and the heal is marked" "$([ -s "${T}/state/drift" ] && echo marked)" marked
  expose >/dev/null
  is  "and the next run binds it again" "$(n_at "${E}")" 1

  # P7: a foreign mount stacked on the exposure is left in place, and (the
  # store being private) does not reach the table the sweep walks.
  mount -t tmpfs foreign "${E}"; : > "${E}/FOREIGN"
  out="$(expose)"
  is  "real guard: a foreign mount stacked on the exposure is NOT unmounted" "$(n_at "${E}")" 2
  is  "and its file is still there" "$([ -e "${E}/FOREIGN" ] && echo kept)" kept
  is  "and it did not reach the store table (store is private)" "$(n_at "${S}/table")" 0
  umount "${E}"

  # TMPFS MODE, THE STORE UNMOUNTED BY HAND (F1, the other mode). The next run
  # mounts a fresh store; the old exposure shows a filesystem no store holds
  # any more, and must go -- and only then is the new one bound.
  fresh; expose >/dev/null; : > "${E}/old-item"
  umount -l "${S}"
  out="$(expose)"; rc=$?
  is  "real guard: after the tmpfs store is unmounted by hand, the old exposure is unbound" "$(n_at "${E}")" 0
  is  "and its items are no longer shown" "$(ls -A "${E}")" ""
  is  "and that run fails" "${rc}" 1
  expose >/dev/null
  is  "and the next run binds the fresh store" "$(n_at "${E}"):$(ls -A "${E}")" "1:"
  '
)

echo '== /shared: the expose service never latches, and a reload does not run it =='
# Measured on a box during a package install: each daemon-reload started the
# expose service again, it hit its start limit a dozen times and showed failed.
# Measured here (systemd 255, a user timer): OnActiveSec=0 re-fires at every
# reload; OnUnitActiveSec= alone does not.
( set +e
  u="${ROOT}/hdw4s-shared-expose.service"; t="${ROOT}/hdw4s-shared-expose.timer"
  is  'the service has no start limit to hit' \
    "$(sed -n '/^\[Unit\]/,/^\[/p' "${u}" | grep -c '^StartLimitIntervalSec=0$')" '1'
  is  'the timer has no OnActiveSec=, which re-fires at every daemon-reload' \
    "$(grep -c '^OnActiveSec=' "${t}")" '0'
  is  'and counts 30 seconds from the last run' "$(grep '^OnUnitActiveSec=' "${t}")" 'OnUnitActiveSec=30s'
)

echo '== desktops do not share /run/lock with the host or with each other =='
# Measured from inside a pool seat: /run/lock was writable and a file planted
# there was visible on the host, and so to every later occupant of every seat.
# Both desktop units give the session a tmpfs of its own there. Read from the
# unit files: the live reading is from inside a seat on a box.
( set +e
  for u in hdw4s@.service hdw4s-ephemeral@.service; do
    is  "${u}: one private tmpfs at /run/lock" \
      "$(grep -c '^TemporaryFileSystem=/run/lock:' "${ROOT}/${u}")" '1'
    has "${u}: writable by every program, as the host's is" \
      "$(grep '^TemporaryFileSystem=/run/lock:' "${ROOT}/${u}")" 'mode=1777'
    # Nothing else may mount at or beneath it: namespace mounts are applied
    # sorted by destination, and a second one there could land on either side.
    is  "${u}: and nothing else is mounted there" \
      "$(grep -E '^[A-Za-z]+(Paths|FileSystem)=.*-?/(run|var)/lock' "${ROOT}/${u}" | grep -vc '^TemporaryFileSystem=/run/lock:')" '0'
  done
)

echo '== /shared: hdw4s check is red when desktops should have it and do not =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Every unit reads active unless a test says otherwise for the sweep's two.
  systemctl() { case "$1 ${*: -1}" in
                  'show hdw4s-shared-sweep@'*) echo "${STUB_TIMER:-active}";;
                  'show hdw4s-shared-watch@'*) echo "${STUB_WATCH:-active}";;
                  show*) echo active;;
                esac; }
  : > "${SLOTS}"
  mkdir -p "${SB}/plain" "${SB}/cwd"
  cat > "${SB}/tool" <<'STUB'
#!/bin/bash
echo "$(pwd) $*" >> "${STUB_LOG}"
[ -z "${STUB_OUT:-}" ] || echo "${STUB_OUT}"
exit "${STUB_RC:-0}"
STUB
  chmod +x "${SB}/tool"
  export STUB_LOG="${SB}/tool.log" HDW4S_SHARED_TOOL="${SB}/tool"
  chk() { ( cd "${SB}/cwd" && cmd_check ) 2>&1; }

  out="$(chk)"; rc=$?
  is  'off: check is not affected' "${rc}" '0'
  hasnt 'and says nothing about /shared' "${out}" '/shared'


  HDW4S_SHARED=sometimes; out="$(chk)"; rc=$?
  is  'a mode that is not one is red' "${rc}" '1'
  has 'and named' "${out}" "HDW4S_SHARED is 'sometimes'"
  # The early return for a machine with no slot table must not skip /shared.
  rm -f "${SLOTS}"; out="$(chk)"; rc=$?; : > "${SLOTS}"
  is  'and red with no slot table to check too' "${rc}" '1'
  has 'saying so' "${out}" 'thing(s) are wrong with /shared'

  HDW4S_SHARED=tmpfs; HDW4S_SHARED_EXPOSE="${SB}/plain"; export HDW4S_SHARED_EXPOSE
  out="$(chk)"; rc=$?
  is  'on and nothing bound is red' "${rc}" '1'
  has 'and says what desktops see' "${out}" 'empty /shared'
  has 'and where the reason is' "${out}" 'journalctl -u hdw4s-shared-expose.service'

  # A mount point that certainly exists, standing in for a bound table; the
  # tool is a stand-in answering as told.
  HDW4S_SHARED_EXPOSE=/proc
  : > "${STUB_LOG}"; out="$(chk)"; rc=$?
  is  'bound and the tool is content: green' "${rc}" '0'
  has 'the tool is asked about the exposure, with IDLE verbatim' "$(cat "${STUB_LOG}")" \
    '--check --dir /proc --idle 30m'
  is  'and from /, whatever directory check was run in' "$(cut -d' ' -f1 "${STUB_LOG}")" '/'
  STUB_RC=3 STUB_OUT='warn: the store is over 90% full'; export STUB_RC STUB_OUT
  out="$(chk)"; rc=$?
  is  'a warning is said, and not counted' "${rc}" '0'
  has 'and passed on' "${out}" 'over 90% full'
  STUB_RC=1 STUB_OUT='red: nobody is sweeping'
  out="$(chk)"; rc=$?
  is  'a red row from the tool is red' "${rc}" '1'
  has 'and passed on' "${out}" 'nobody is sweeping'
  # The sweep this machine runs itself: its timer down is red, nothing would
  # ever expire; the watcher down is a warning, the timer widens instead.
  unset STUB_RC STUB_OUT
  STUB_TIMER=inactive; out="$(chk)"; rc=$?; STUB_TIMER=active
  is  'the sweep timer not running is red' "${rc}" '1'
  has 'and named' "${out}" 'the sweep of /shared is not running'
  STUB_WATCH=inactive; out="$(chk)"; rc=$?; STUB_WATCH=active
  is  'the watcher not running is said, and not counted' "${rc}" '0'
  has 'and named' "${out}" 'the watcher of /shared is not running'
  HDW4S_SHARED_SWEEP=external STUB_TIMER=inactive; out="$(chk)"; rc=$?
  HDW4S_SHARED_SWEEP=local STUB_TIMER=active
  is  'with SWEEP=external there is no local sweep to miss' "${rc}" '0'

  STUB_RC=2 STUB_OUT='Traceback'; export STUB_RC STUB_OUT
  out="$(chk)"; rc=$?
  is  'a tool that could not tell is red, not green' "${rc}" '1'
  has 'and says it could not tell' "${out}" 'could not be told'
  unset STUB_RC STUB_OUT

  # The effective size of a tmpfs table is said, the default included.
  out="$(chk)"
  has 'the effective size is said' "${out}" 'tmpfs table of'
  has 'and that it is the default' "${out}" '10% of this machine'"'"'s memory, the default'
  HDW4S_SHARED_SIZE=lots; out="$(chk)"; rc=$?; unset HDW4S_SHARED_SIZE
  is  'a size that is not one is red' "${rc}" '1'

  # A HEAL IS NEVER INVISIBLE: a drift mark under a day old is said, not counted.
  mkdir -p "${SB}/state"; export HDW4S_SHARED_STATE="${SB}/state"
  date +%s > "${SB}/state/drift"
  out="$(chk)"; rc=$?
  is  'a recent heal is not a failure' "${rc}" '0'
  has 'but is said, with when' "${out}" 'drift healed at'
  echo $(( $(date +%s) - 90000 )) > "${SB}/state/drift"
  out="$(chk)"
  hasnt 'a heal over a day old is no longer said' "${out}" 'drift healed'
  date +%s > "${SB}/state/drift"
  HDW4S_SHARED_EXPOSE="${SB}/plain"; out="$(chk)"; rc=$?; HDW4S_SHARED_EXPOSE=/proc
  is  'unbound is red, mark or no mark' "${rc}" '1'
  rm -f "${SB}/state/drift"

  HDW4S_SHARED_IDLE=soon; out="$(chk)"; rc=$?
  is  'an IDLE that cannot be read is red' "${rc}" '1'
  unset HDW4S_SHARED_IDLE
  HDW4S_SHARED_MAX_AGE=0; out="$(chk)"; rc=$?
  is  'a MAX_AGE of 0 is red: expiry is a promise' "${rc}" '1'
  unset HDW4S_SHARED_MAX_AGE
)

echo '== /shared: the settings are machine-wide and read at boot =='
( set +e; sandbox; . "${SB}/setup.sh"
  for k in HDW4S_SHARED HDW4S_SHARED_SIZE HDW4S_SHARED_SOURCE HDW4S_SHARED_SWEEP \
           HDW4S_SHARED_IDLE HDW4S_SHARED_MAX_AGE; do
    [ -n "${GLOBAL_ONLY[${k}]:-}" ] && ok "${k} is machine-wide only" \
      || bad "${k} is machine-wide only" 'not in GLOBAL_ONLY'
  done
  has 'the hint says reboot' "$(set_hint '' HDW4S_SHARED_IDLE=1h)" 'reboot to use it'
  ( check_value HDW4S_SHARED_MAX_AGE 0 ) 2>/dev/null && bad 'MAX_AGE 0 is refused by set' \
    || ok 'MAX_AGE 0 is refused by set'
  ( check_value HDW4S_SHARED_MAX_AGE 7d ) 2>/dev/null && ok 'and 7d is accepted' \
    || bad 'and 7d is accepted'
  ( check_value HDW4S_SHARED tmpfs ) 2>/dev/null && ok 'tmpfs is a mode' || bad 'tmpfs is a mode'
  ( check_value HDW4S_SHARED on ) 2>/dev/null && bad '"on" is not a mode' || ok '"on" is not a mode'
)
}
group_shared_wiring

echo '== /shared in the root namespace: the read-only view, on real mounts, by the shipped boot run =='
# Design C2 (PM P33): root's /shared is a read-only SLAVE bind of the plain
# /run/hdw4s/shared, so the table arrives there with the exposure and leaves
# with it. Its one trap is order -- made while a table is already shown, the
# bind takes the table itself and PINS it -- so every refusal and the shape
# check are exercised HERE, by the shipped script, on real mounts in a user
# namespace: /run a shared tmpfs, the store a private tmpfs, the expose
# service's bind and lazy unbind done as it does them. Where the namespace is
# refused every assertion FAILS rather than skips.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  N=224
  if ! unshare -Urm true 2>/dev/null; then
    for _ in $(seq "${N}"); do
      bad '/shared in the root namespace, on real mounts' \
          'unshare -Urm is refused here, so none of these ran (kernel.apparmor_restrict_unprivileged_userns?)'
    done
    exit 0
  fi
  # RED COPIES, made out here where quoting is plain. Each must have taken.
  # (1) the check after the bind removed: whatever the bind came out as is kept.
  # shellcheck disable=SC2016  # the pattern names the script's own variables
  sed 's/^  made="\$(echo "\${shape}" | cut -d. . -f2)"$/&; printf "bound %s\\n" "${made}" > "${SHARED_VIEW_STATE}"; return 0/' \
    "${ROOT}/hdw4s-ephemeral-slots" > "${T}/red-noverify"
  # (2) the refusal while exposed removed.
  # shellcheck disable=SC2016  # the pattern names the script's own ${SHARED_EXPOSE}
  sed 's/^  if mounted_at "${SHARED_EXPOSE}"; then$/  if false; then/' \
    "${ROOT}/hdw4s-ephemeral-slots" > "${T}/red-norefuse"
  chmod +x "${T}/red-noverify" "${T}/red-norefuse"
  is  'RED ARM: the edit removing the check after the bind took' \
    "$(grep -c '; return 0$' "${T}/red-noverify")" "$(( $(grep -c '; return 0$' "${ROOT}/hdw4s-ephemeral-slots") + 1 ))"
  # THE RACE INJECTOR: a table bound at the exposure at one chosen instant of
  # the bind, as an expose run would. For the bind made with mount(8) (the
  # previous mechanism): before the bind, or before its make-slave. For the
  # bind made with the mount API: before the syscall named in INJECT_AT, by a
  # sitecustomize the minter's python3 picks up from PYTHONPATH. Both are
  # armed at once, so the same assertions judge either mechanism.
  mkdir -p "${T}/inject"
  cat > "${T}/inject/sitecustomize.py" <<'PY'
import ctypes, os, subprocess
# INJECT_AT=<syscall>[#<n>]: before the n-th call of it (default the first).
_name, _, _nth = os.environ.get("INJECT_AT", "").partition("#")
_at = {"open_tree": 428, "mount_setattr": 442, "move_mount": 429}.get(_name)
_nth = int(_nth or 1)
_seen = [0]
if _at is not None:
    _CDLL = ctypes.CDLL
    class CDLL(_CDLL):
        def __getattr__(self, name):
            f = _CDLL.__getattr__(self, name)
            if name != "syscall":
                return f
            def syscall(*args):
                if args and args[0] == _at:
                    _seen[0] += 1
                if args and args[0] == _at and _seen[0] == _nth and not os.environ.get("INJECTED"):
                    os.environ["INJECTED"] = "1"
                    subprocess.run(["mount", "--bind", os.environ["S"] + "/table", os.environ["E"]], check=True)
                return f(*args)
            # CDLL caches what it hands out on the instance: cache this one
            # instead, or the second call bypasses it.
            f.restype = ctypes.c_long
            setattr(self, name, syscall)
            return syscall
    ctypes.CDLL = CDLL
PY
  is  'RED ARM: the edit removing the refusal while exposed took' \
    "$(grep -c '^  if false; then$' "${T}/red-norefuse")" '1'
  export -f ok bad is has hasnt
  export RESULTS T ROOT
  # shellcheck disable=SC2016  # expanded by the shell inside the namespace
  # IN FOUR TOPOLOGIES (PM P35), each named in every line it prints:
  #   private  the namespace's mounts private;
  #   shared   shared, as on every machine this ships to, where / is shared
  #            (systemd on a stock host, and LXC), with no peers;
  #   peer     shared, with a PEER: a second mount namespace copied from this
  #            one and left shared, so /shared's parent has a peer there;
  #   desktop  shared, with a desktop already running when the bind is made:
  #            a SLAVE namespace with its own bind of the exposure at /shared.
  # Under a shared parent move_mount makes what it attaches shared again; the
  # first mount-API cut was green with private mounts only and never made the
  # bind on any real target (review of 16e9d96, S1).
  for V in private shared peer desktop; do
  export V
  case "${V}" in private) prop=private;; *) prop=shared;; esac
  unshare -Urm --propagation "${prop}" bash -c '
  set +e
  ok()  { echo ok >> "${RESULTS}"; printf "  ok   [parent %s] %s\n" "${V}" "$1"; }
  bad() { echo fail >> "${RESULTS}"; printf "  FAIL [parent %s] %s\n" "${V}" "$1"; [ $# -lt 2 ] || printf "       %s\n" "$2"; }
  SB="${T}/sb-${V}"; mkdir -p "${SB}/etc" "${SB}/var" "${T}/run"
  printf "%s\n" "1 _hdw4s_0 ephemeral" > "${SB}/etc/instances"
  mount -t tmpfs run "${T}/run"; mount --make-shared "${T}/run"
  E="${T}/run/hdw4s/shared"; S="${T}/run/hdw4s/shared-store"; P="${T}/shared-${V}"
  MARK="${SB}/var/.shared-mountpoint"; VIEW="${SB}/view"
  mkdir -p "${E}" "${S}"
  mount -t tmpfs -o mode=0700,nosymfollow,nodev,noexec,nosuid,strictatime store "${S}"
  mount --make-private "${S}"; mkdir -m 0777 "${S}/table"; echo item > "${S}/table/f"
  # As hdw4s-shared-expose binds and unbinds.
  expose() { mount --bind "${S}/table" "${E}"; }
  unexpose() { umount -l -c "${E}"; }
  n_at() { awk -v p="$1" "\$5 == p { n++ } END { print n + 0 }" /proc/self/mountinfo; }
  # The expose timer starts last; record whether /shared was bound by then.
  systemctl() { echo "systemctl $*" >> "${SB}/calls"
                if [ "${1:-} ${2:-}" = "start --no-block" ]; then
                  [ "$(n_at "${P}")" -gt 0 ] && echo bound-before-start >> "${SB}/calls"; fi
                [ "${1:-}" != list-units ] || { [ ! -e "${SB}/units" ] || cat "${SB}/units"; }; }
  getent() { [ "$1 $2" = "group hdw4s-relay" ] && echo "hdw4s-relay:x:999:" && return 0
             command getent "$@"; }
  install() { local args=(); while [ $# -gt 0 ]; do
                case "$1" in -g) shift 2;; *) args+=("$1"); shift;; esac; done
              command install "${args[@]}"; }
  export -f systemctl getent install n_at; export SB P
  env_() { env HDW4S_ETCDIR="${SB}/etc" HDW4S_USERDB_DIR="${SB}/userdb" \
           HDW4S_NS_DIR="${SB}/ns" HDW4S_PROFILE_ROOT="${SB}/profile" \
           HDW4S_DROPIN_DIR="${SB}/system" HDW4S_PROXY_RUNDIR="${SB}/proxy" \
           HDW4S_TEARDOWN_DIR="${SB}/teardown" HDW4S_START_DIR="${SB}/start" \
           HDW4S_INVITE_DIR="${SB}/invite" HDW4S_INCARNATION_DIR="${SB}/incarn" \
           HDW4S_STREAM_DIR="${SB}/stream" HDW4S_DCONF_DB_DIR="${SB}/no-dconf" \
           HDW4S_SHARED_MARK="${MARK}" HDW4S_SHARED_MOUNTPOINT="${P}" \
           HDW4S_SHARED_EXPOSE="${E}" HDW4S_SHARED_VIEW_STATE="${VIEW}" "$@"; }
  boot() { : > "${SB}/calls"; env_ "${1:-${ROOT}/hdw4s-ephemeral-slots}" 2>&1; }
  view() { env_ "${ROOT}/hdw4s-ephemeral-slots" --shared-view "$1" 2>&1; }
  checkrc() { view check >/dev/null; echo $?; }
  # "<exit>:<shape>" -- the shape word the check names, so that a red is told
  # apart from a script that merely failed (which also exits 1).
  vc() { local o r; o="$(view check)"; r=$?
         printf "%s:%s\n" "${r}" "$(printf "%s\n" "${o}" | sed -n "s/^  \([a-z-]*\) [-0-9].*/\1/p" | head -n 1)"; }
  conf() { printf "%s\n" HDW4S_EPHEMERAL_SLOTS=0 HDW4S_SHARED_SWEEP=external "$@" > "${SB}/etc/hdw4s.conf"; }
  # The DESKTOP stand-in: started on our own /shared (so it is marked), with
  # BindPaths= done as an rbind of the exposure, as systemd does; and the
  # systemctl stand-in then lists it as running.
  # Its pid in a file: arms call fresh inside $(...), where a variable dies.
  desk() { nsenter -t "$(cat "${SB}/desk.pid")" -m -- "$@"; }
  start_desktop() {
    mkdir -p "${P}"; : > "${MARK}"
    unshare -m --propagation slave -- sleep 900 </dev/null >/dev/null 2>&1 & D=$!
    echo "${D}" > "${SB}/desk.pid"
    until [ "$(readlink "/proc/${D}/ns/mnt")" != "$(readlink /proc/self/ns/mnt)" ]; do sleep 0.05; done
    desk mount --rbind "${E}" "${P}"
    printf "%s\n" "hdw4s-ephemeral@_hdw4s_0.service loaded active running stand-in" > "${SB}/units"
    desk awk -v p="${P}" "\$5 == p { on[\$1] = \$2 } END { for (a in on) { t = 1; for (b in on) if (on[b] == a) t = 0; if (t) print a } }" \
      /proc/self/mountinfo > "${SB}/desk-top"; }
  # An arm that needs the bind made by the boot run does not run where the
  # topology declines it -- and says so, by name, in place of a result.
  needbind() { [ "${V}" != peer ] && return 0
               echo "  skip [parent peer] $1: it presupposes the bind, which this topology declines"; return 1; }
  # Each case starts clean: whatever is left is taken away here, by the test.
  fresh() { [ ! -s "${SB}/desk.pid" ] || { kill "$(cat "${SB}/desk.pid")"; rm -f "${SB}/desk.pid"; }
            while [ "$(n_at "${P}")" -gt 0 ]; do umount -l "${P}"; done
            while [ "$(n_at "${E}")" -gt 0 ]; do umount -l "${E}"; done
            rmdir "${P}" 2>/dev/null; rm -f "${MARK}" "${VIEW}" "${SB}/units"
            [ "${V}" != desktop ] || start_desktop; }
  # The PEER: a copy of this namespace, left shared, so every shared mount
  # here -- /shared'"'"'s parent included -- has a peer there.
  if [ "${V}" = peer ]; then
    unshare -m --propagation unchanged -- sleep 900 </dev/null >/dev/null 2>&1 & PEER=$!
    until [ "$(readlink "/proc/${PEER}/ns/mnt")" != "$(readlink /proc/self/ns/mnt)" ]; do sleep 0.05; done
  fi
  # Say the topology from the mount table, not from the variable.
  parent="$(findmnt -n -o TARGET -T "${P%/*}")"
  ptag="$(awk -v m="${parent}" "\$5 == m { for (i = 7; \$i != \"-\"; i++) printf \"%s \", \$i }" /proc/self/mountinfo)"
  pid="$(awk -v m="${parent}" "\$5 == m { print \$3 }" /proc/self/mountinfo)"
  peers=0; [ -z "${PEER:-}" ] ||
    peers="$(awk -v t="${ptag%% *}" "{ for (i = 7; \$i != \"-\"; i++) if (\$i == t) n++ } END { print n + 0 }" "/proc/${PEER}/mountinfo")"
  echo "  topology [parent ${V}]: /shared'"'"'s parent ${parent} is [${ptag% }], with ${peers} peer(s) in another namespace"
  fresh

  # THE ORDERING C2 IS FOR (positive control: if this is not green, nothing
  # below means anything).
  conf HDW4S_SHARED=tmpfs; out="$(boot)"; rc=$?
  is  "the boot run with /shared on succeeds" "${rc}" 0
  if [ "${V}" = peer ]; then
    # WITH A PEER, the bind is NOT made, and that is measured, not wished: the
    # second make-slave makes it a slave of its own new group (whose other
    # member is the peer'"'"'s copy), so it reads "master:<its group>
    # propagate_from:<run>" and the shape check refuses it. It fails SAFE
    # (PM P35 P-d): declined, nothing left mounted, the check red and naming
    # why. Whether any target has such a peer is a census on the boxes.
    is  "with a peer: the bind is declined, and nothing is left at /shared" "$(n_at "${P}")" 0
    is  "and it is recorded why" "$(cat "${VIEW}")" "declined not-slave"
    has "and the check is red and names it" "$(view check)" "(not-slave)"
    is  "red, not a warning" "$(checkrc)" 1
  else
  [ "${rc}" -eq 0 ] || printf "       %s\n" "${out}" | tail -n 5
  is  "root /shared is bound, by the boot run, before the expose timer starts" \
    "$(grep -c bound-before-start "${SB}/calls")" 1
  is  "and marked as this feature'"'"'s" "$([ -e "${MARK}" ] && echo marked)" marked
  is  "its shape passes the check" "$(checkrc)" 0
  is  "unexposed, root sees nothing there" "$(ls -A "${P}")" ""
  touch "${P}/x" 2>/dev/null && w=WRITABLE || w=refused
  is  "and cannot write there (the bind is read-only)" "${w}" refused
  expose
  is  "exposed, the table arrives at root /shared" "$(ls -A "${P}")" f
  touch "${P}/y" 2>/dev/null && w=WRITABLE || w=refused
  is  "and root writes reach the table" "${w}:$(ls "${S}/table" | tr "\n" " ")" "WRITABLE:f y "
  is  "and the shape still passes" "$(checkrc)" 0
  rm -f "${S}/table/y"; unexpose
  is  "unexposed again, it leaves root /shared too" "$(ls -A "${P}")" ""
  boot >/dev/null
  is  "a second run leaves the one bind alone" "$(n_at "${P}"):$(checkrc)" 1:0
  fi
  if [ "${V}" = desktop ]; then
    # P-e: the desktop running when the bind was made keeps its view.
    is  "the running desktop'"'"'s own /shared is still the top there" \
      "$(desk awk -v p="${P}" "\$5 == p { on[\$1] = \$2 } END { for (a in on) { t = 1; for (b in on) if (on[b] == a) t = 0; if (t) print a } }" /proc/self/mountinfo)" \
      "$(cat "${SB}/desk-top")"
    expose
    is  "exposed, the running desktop sees the table" "$(desk ls -A "${P}")" f
    desk touch "${P}/from-desktop" 2>/dev/null && w=WRITABLE || w=refused
    is  "and writes reach it" "${w}:$(ls "${S}/table" | tr "\n" " ")" "WRITABLE:f from-desktop "
    rm -f "${S}/table/from-desktop"; unexpose
    is  "unexposed, it leaves the desktop too" "$(desk ls -A "${P}")" ""
  fi

  # C2-1: REFUSED WHILE EXPOSED -- a live postinst, an off->on upgrade, a hand run.
  fresh; expose; out="$(boot)"; rc=$?
  is  "with a table already shown, the run still succeeds" "${rc}" 0
  is  "RED ARM: and makes no bind (it would pin the table)" "$(n_at "${P}")" 0
  has "and says it takes effect at the next boot" "${out}" "It takes effect at the next boot"
  is  "and the check warns rather than fails" "$(checkrc)" 3
  out="$(boot "${T}/red-norefuse")"
  has "RED ARM: without the refusal, the bind is made and found pinned" "${out}" "came out wrong (foreign"
  is  "and taken away again by the check after it" "$(n_at "${P}")" 0
  unexpose

  # C2-1: THE RACE -- an expose run that binds between the look and the bind.
  # THE PROPERTY (review of the first cut, R1): at no instant attached at
  # /shared is the bind a PEER of /run, so nothing unmounted at /shared can
  # propagate back and take the table off /run/hdw4s/shared. The first cut
  # attached, then made it a slave by path; a table bound in between landed on
  # it, and the clean-up unmounted the EXPOSURE (measured, reviewer e2b.sh).
  export S E
  race() {  # race <mount(8) word to inject before> <syscall to inject before>
    fresh
    eval "mount() { case \" \$* \" in *\" $1 \"*) command mount --bind \"\${S}/table\" \"\${E}\";; esac
                     command mount \"\$@\"; }"
    export -f mount
    out="$(INJECT_AT="$2" PYTHONPATH="${T}/inject" boot)"
    unset -f mount
    printf "%s:%s" "$(n_at "${E}")" "$(n_at "${P}")"; }
  r="$(race --make-slave mount_setattr)"
  is  "RED ARM: a table bound after the bind is made and before it is a slave: the EXPOSURE survives" \
    "${r%%:*}" 1
  unexpose
  is  "and root /shared keeps no table once it is taken away" "$(ls -A "${P}" 2>/dev/null)" ""
  is  "and what is left at /shared passes the check, or is none" "$(c=$(checkrc); [ "${c}" != 1 ] && echo ok)" ok
  r="$(race -- open_tree)"
  is  "a table bound between the look and the bind: the exposure survives" "${r%%:*}" 1
  is  "and the bind, which took the table, is taken away" "${r#*:}" 0
  has "and it says so" "${out}" "came out wrong (foreign"
  is  "and it is recorded as waiting for the next boot" "$(cat "${VIEW}")" "declined exposed"
  unexpose
  # After the attach and before it is made a slave again (shared parent): the
  # table arrives on it as a copy; the fd-made slave keeps it, and nothing of
  # /run is ever unmounted.
  r="$(race --never-a-word "mount_setattr#2")"
  is  "a table bound after the attach, before the second make-slave: the exposure survives" "${r%%:*}" 1
  if [ "${V}" = peer ]; then
    # With a peer the bind is not a slave of /run (see above). With a table on
    # it, it is not taken away (R2: what is stacked on it is left, and said);
    # it shows the table, follows it away, and the check is red.
    is  "with a peer: root /shared shows it, and the check is RED" "$(ls -A "${P}"):$(checkrc)" f:1
  else
    is  "and root /shared shows it, and passes the check" "$(ls -A "${P}"):$(checkrc)" f:0
  fi
  unexpose
  is  "and it leaves root /shared with it (no pin)" "$(ls -A "${P}")" ""
  r="$(race --never-a-word move_mount)"
  is  "a table bound just before the bind is attached: the exposure survives" "${r%%:*}" 1
  unexpose
  is  "and root /shared keeps no table once it is taken away" "$(ls -A "${P}" 2>/dev/null)" ""
  # R2: when the bind cannot be taken away again, the log must not say it was.
  fresh; umount() { return 1; }
  mount() { case " $* " in *" -o ro -- "*) command mount --bind "${S}/table" "${E}";; esac
            command mount "$@"; }
  export -f umount mount
  out="$(INJECT_AT=open_tree PYTHONPATH="${T}/inject" boot)"
  unset -f umount mount
  has "a wrong bind that cannot be taken away is said to be still there" "${out}" "could NOT be taken"
  hasnt "and never said to be taken away" "${out}" "was taken away"
  is  "and the check is red on it" "$(vc)" 1:foreign
  unexpose
  fresh; mount() { case " $* " in *" -o ro -- "*) command mount --bind "${S}/table" "${E}";; esac
                   command mount "$@"; }; export -f mount
  INJECT_AT=open_tree PYTHONPATH="${T}/inject" boot "${T}/red-noverify" >/dev/null
  unset -f mount
  is  "RED ARM: without the check after the bind, the race leaves it bound" "$(n_at "${P}")" 1
  unexpose
  is  "RED ARM: and PINNED: the table stays in root after it was taken away" "$(ls -A "${P}")" f

  # FINDING 1: NEVER ON A MISSING SOURCE.
  fresh; rmdir "${E}"; out="$(boot)"
  has "with no /run/hdw4s/shared the bind is not attempted" "${out}" "does not exist"
  is  "and nothing is mounted at /shared" "$(n_at "${P}")" 0
  is  "and the check is RED: a boot that left no bind" "$(checkrc)" 1
  has "and says why" "$(view check)" "is not bound to the"
  mkdir "${E}"

  # C2-3: EVERY SHAPE BUT THE BIND IS RED, on real mounts.
  fresh; conf HDW4S_SHARED=tmpfs; mkdir -p "${P}"; : > "${MARK}"
  is  "no bind at all (feature on, /shared ours) is red" "$(checkrc)" 1
  has "and says so" "$(view check)" "is not bound to the"
  expose; mount --bind -o ro "${E}" "${P}"; mount --make-slave "${P}"; unexpose
  is  "a PINNED bind is red, named as not /run" "$(vc)" 1:foreign
  fresh; conf HDW4S_SHARED=tmpfs; boot >/dev/null; rmdir "${E}"; mkdir "${E}"
  needbind "the deleted-source arm" &&
  is  "a bind whose source was removed and remade is red, as deleted" "$(vc)" 1:deleted
  fresh; mkdir -p "${P}"; : > "${MARK}"; mount -t tmpfs foreign "${P}"
  is  "a foreign filesystem at the bottom is red" "$(vc)" 1:foreign
  fresh; mkdir -p "${P}"; : > "${MARK}"; mount --bind "${E}" "${P}"; mount --make-slave "${P}"
  is  "a writable bind is red" "$(vc)" 1:rw
  fresh; mkdir -p "${P}"; : > "${MARK}"; mount --bind -o ro "${E}" "${P}"
  is  "a bind that is a peer of /run, not its slave, is red" "$(vc)" 1:not-slave
  fresh; boot >/dev/null; mount -t tmpfs stray "${P}"
  needbind "the stray-mount arm" &&
  is  "a mount on top of the bind that is not the table is red" "$(vc)" 1:stray
  fresh; conf; mkdir -p "${P}"; : > "${MARK}"; expose; mount --bind -o ro "${E}" "${P}"
  mount --make-slave "${P}"; unexpose
  is  "pinned is red with /shared OFF too" "$(vc)" 1:foreign
  fresh; conf HDW4S_SHARED=tmpfs; mkdir -p "${P}"; rm -f "${MARK}"
  out="$(view check)"; rc=$?
  is  "an administrator'"'"'s /shared (no mark) is not red" "${rc}" 0
  has "and is named, with the path to use instead" "${out}" "Use ${E}"

  # C2-4: TAKEN AWAY BY ITS RECORDED IDENTITY, never under a desktop or a table.
  if needbind "the release arms (C2-4)"; then
  fresh; conf HDW4S_SHARED=tmpfs; boot >/dev/null
  printf "%s\n" "hdw4s-ephemeral@_hdw4s_0.service loaded active running x" > "${SB}/units"
  out="$(view release-for-removal)"
  is  "RED ARM: release with a desktop running keeps the bind, /shared and its mark" \
    "$(n_at "${P}"):$([ -d "${P}" ] && [ -e "${MARK}" ] && echo kept)" 1:kept
  has "and says which" "${out}" "hdw4s-ephemeral@_hdw4s_0.service"
  hasnt "and, called by the package going, never promises a boot run that will not come" \
    "${out}" "The next boot"
  has "but says nothing will remove it" "${out}" "Nothing removes it once the package is gone"
  out="$(view release)"
  has "run by hand, with the package installed, it says the boot run will" "${out}" "The next boot with HDW4S_SHARED off"
  [ "${V}" = desktop ] || rm -f "${SB}/units"; expose; out="$(view release)"
  is  "release while a table is shown keeps it all" \
    "$(n_at "${P}"):$([ -d "${P}" ] && [ -e "${MARK}" ] && echo kept)" 2:kept
  unexpose; echo "bound 999999" > "${VIEW}"; out="$(view release)"
  is  "release of a bind it did not record making keeps it all" \
    "$(n_at "${P}"):$([ -e "${MARK}" ] && echo kept)" 1:kept
  if [ "${V}" = desktop ]; then
    has "and says why: the desktop" "${out}" "while these desktops are running"
  else
    has "and says so" "${out}" "not the bind this feature recorded making"
  fi
  rm -f "${VIEW}"; boot >/dev/null; conf; out="$(boot)"
  if [ "${V}" = desktop ]; then
    is  "turned off with the desktop running: the bind, /shared, its mark and its record are kept" \
      "$(n_at "${P}"):$([ -e "${P}" ] && echo P)$([ -e "${MARK}" ] && echo M)$([ -e "${VIEW}" ] && echo V)" 1:PMV
  else
    is  "turned off with nothing running: the boot run unmounts it, removes /shared, then the mark" \
      "$(n_at "${P}"):$([ -e "${P}" ] && echo P)$([ -e "${MARK}" ] && echo M)$([ -e "${VIEW}" ] && echo V)" 0:
  fi
  is  "and /run/hdw4s/shared is untouched" "$([ -d "${E}" ] && echo there)" there
  fi
  # Leave nothing running: fresh would start another desktop stand-in.
  V=done fresh; [ -z "${PEER:-}" ] || kill "${PEER}"
  '
  done
)

echo '== /shared in the root namespace: the shape check, on the mount table a container really has =='
# The NFS case (PM P23): there the exposure is nfs4 with root "/", so a pin is
# NOT "root /table" and a check that looked for that would pass it. The lines
# are the real ones captured inside the container; the bottom is found by
# parent id, never by position, because propagation tucks mounts beneath.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  : > "${T}/mark"
  RUN='25 1 0:25 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,mode=755'
  EXPO='3417 25 0:251 / /run/hdw4s/shared rw,nosuid,nodev,noexec,nosymfollow master:3169 - nfs4 192.0.2.1:/export/shared/table rw,vers=4.2,soft,addr=192.0.2.1'
  # NESTED: the exposure is /run/hdw4s/shared, two levels below the mount that
  # holds it, so the bind's root on /run's device is "/hdw4s/shared".
  GOOD='3500 1 0:25 /hdw4s/shared /shared ro,relatime master:5 - tmpfs tmpfs rw,mode=755'
  COPY='3501 3500 0:251 / /shared rw,nosuid,nodev,noexec,nosymfollow master:3169 - nfs4 192.0.2.1:/export/shared/table rw,vers=4.2,soft,addr=192.0.2.1'
  PIN='3502 1 0:251 / /shared ro,nosuid,nodev,noexec,nosymfollow master:3169 - nfs4 192.0.2.1:/export/shared/table rw,vers=4.2,soft,addr=192.0.2.1'
  # "<exit>:<shape word>": a red must NAME its shape, or a script that merely
  # failed (exit 1 too) would pass for one.
  chk() { local o r; printf '%s\n' "$@" > "${T}/mountinfo"
          o="$(HDW4S_ETCDIR="${T}" HDW4S_SHARED=source HDW4S_SHARED_MARK="${T}/mark" \
               HDW4S_SHARED_VIEW_STATE="${T}/view" HDW4S_MOUNTINFO="${T}/mountinfo" \
               "${ROOT}/hdw4s-ephemeral-slots" --shared-view check 2>&1)"; r=$?
          printf '%s:%s\n' "${r}" "$(printf '%s\n' "${o}" | sed -n 's/^  \([a-z-]*\) [-0-9].*/\1/p' | head -n 1)"; }
  is  'NFS, exposed, the bind with the table propagated onto it: good' \
    "$(chk "${RUN}" "${EXPO}" "${GOOD}" "${COPY}")" '0:'
  is  'the same lines in the other order: still good (bottom by parent id)' \
    "$(chk "${RUN}" "${EXPO}" "${COPY}" "${GOOD}")" '0:'
  is  'RED ARM: an NFS PIN (root "/", not "/table") is red' "$(chk "${RUN}" "${EXPO}" "${PIN}")" '1:foreign'
  is  'the same pin after the store was taken away is red' "$(chk "${RUN}" "${PIN}")" '1:foreign'
  # Propagation tucked the pin BENEATH the bind: the bind's parent is now the
  # pin, and the pin is the bottom whatever order the lines come in.
  is  'a pin TUCKED BENEATH the bind is red' \
    "$(chk "${RUN}" "${EXPO}" "${GOOD/3500 1 /3500 3502 }" "${PIN}")" '1:foreign'
  is  'a bind that is also a peer of its own group is red' \
    "$(chk "${RUN}" "${GOOD/ro,relatime/ro,relatime shared:77}")" '1:not-slave'
  is  'with /run not shared nothing can ever arrive: red' "$(chk "${RUN/shared:5 /}" "${GOOD}")" '1:unshared'
  is  'a deleted source is red, by name' \
    "$(chk "${RUN}" "${GOOD/\/hdw4s\/shared \/shared/\/hdw4s\/shared\/\/deleted \/shared}")" '1:deleted'
  is  'the good bind alone, unexposed: good' "$(chk "${RUN}" "${GOOD}")" '0:'
  # A view from a LOOKALIKE path is not this one: /run/hdw4s-shared shares a
  # prefix with the exposure and nothing else, and must read as foreign.
  is  'a view of a lookalike path is foreign, not good' \
    "$(chk "${RUN}" "${GOOD/\/hdw4s\/shared \/shared/\/hdw4s-shared \/shared}")" '1:foreign'
  # Unmounted by hand (shape pass F1): the record says bound, nothing is there.
  # It strands table copies in every slave namespace, which no read here can
  # see; the record is the only witness, so it is red, with the remedy.
  echo 'bound 3500' > "${T}/view"
  is  'a recorded bind found unmounted is red (it was before, as "not bound")' "$(chk "${RUN}" "${EXPO}")" '1:'
  o="$(HDW4S_ETCDIR="${T}" HDW4S_SHARED_MARK="${T}/mark" HDW4S_SHARED_VIEW_STATE="${T}/view" \
       HDW4S_MOUNTINFO="${T}/mountinfo" "${ROOT}/hdw4s-ephemeral-slots" --shared-view check 2>&1)"
  has 'RED ARM: and says what to do: restart them, or reboot' "${o}" 'restart them, or reboot'
  has 'with /shared off too' "${o}" 'unmounted
  by hand'
  rm -f "${T}/view"
)

echo '== /shared: hdw4s check counts what the minter says about root /shared =='
# The shape check's only channel to the administrator is "hdw4s check" reading
# the minter's exit status; this is that mapping, end to end. HDW4S_SHARED is
# written to the configuration, because the minter reads it from there and
# never from the caller's environment -- as in production.
( set +e; sandbox; . "${SB}/setup.sh"
  systemctl() { case "$1 ${*: -1}" in show*) echo active;; esac; }
  : > "${SLOTS}"; mkdir -p "${SB}/cwd"
  printf '#!/bin/bash\nexit 0\n' > "${SB}/tool"; chmod +x "${SB}/tool"; export HDW4S_SHARED_TOOL="${SB}/tool"
  HDW4S_SHARED_EXPOSE=/proc; export HDW4S_SHARED_EXPOSE
  chk() { ( cd "${SB}/cwd" && cmd_check ) 2>&1; }
  HDW4S_SHARED=tmpfs; echo HDW4S_SHARED=tmpfs > "${CONF}"
  out="$(chk)"; rc=$?
  is  'control: on, no mark, no /shared: a warning, green' "${rc}" '0'
  has 'and says next boot' "${out}" 'made at the next boot'
  : > "${HDW4S_SHARED_MARK}"; mkdir -p "${HDW4S_SHARED_MOUNTPOINT}"
  out="$(chk)"; rc=$?
  is  'RED ARM: ours and NOT bound: hdw4s check is RED (exit 1)' "${rc}" '1'
  has 'and names it' "${out}" 'is not bound to the'
  HDW4S_SHARED=off; echo HDW4S_SHARED=off > "${CONF}"; out="$(chk)"; rc=$?
  is  'off, ours, not bound: green' "${rc}" '0'
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
  printf '%s\n' '0 alice' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  provision_template >/dev/null
  is 'so does one with only people and seats' "$(cat "${CALLS}")" "template ${TEMPLATE_SLOT}"
  # AN UPGRADE: a row the retired "enable --template" made is used as it is.
  : > "${CALLS}"
  printf '%s\n' '0 alice' '1 author template' '2 _hdw4s_0 ephemeral' > "${SLOTS}"
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
# The "$HOME" in this group is the literal text a user-dirs file carries, never an
# expansion, so single quotes are the point rather than a slip.
# shellcheck disable=SC2016
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
  # The literal "$HOME" is what a user-dirs file holds; it must not expand here.
  # shellcheck disable=SC2016
  printf 'XDG_MUSIC_DIR="$HOME/Music"\n' > "${T}/author/config/user-dirs.dirs"
  # shellcheck disable=SC2016
  printf 'XDG_MUSIC_DIR="$HOME/.Music"\n' > "${T}/home/.config/user-dirs.dirs"
  touch -d '-1 hour' "${T}/author/config/user-dirs.dirs"
  out="$(run)"
  # shellcheck disable=SC2016
  has 'the home'"'"'s newer file is published' "${out}" 'XDG_MUSIC_DIR="$HOME/.Music"'
  has 'with the hidden folder it names'       "${out}" 'folders=.Music'
  touch -d '-2 hours' "${T}/home/.config/user-dirs.dirs"
  out="$(run)"
  # shellcheck disable=SC2016
  has 'an older one in the home is not'       "${out}" 'XDG_MUSIC_DIR="$HOME/Music"'
)

echo '== a named desktop keeps its standard folders where its owner puts them =='
# Owner, 2026-10-03: folders moved into ~/.local came back at the next login, and
# no answer in the "Update standard folders" dialog would stick -- a one-way copy
# from the home over the profile undid, at every start, whatever was done inside
# the desktop. Three profiles stand for three machines sharing one home; "start"
# and "loop" are the two places hdw4s-run-session calls the sync from. The
# "$HOME" here is the literal text a user-dirs file carries, never an expansion.
# AS ROOT THIS GROUP IS SKIPPED, and says so: the sync refuses to run as root
# by design (it would follow a link in a home as root), so as root every case
# here would test a state the product refuses. Its cover as root is this same
# group run unprivileged (the workstation suite, which is CI's shape) and the
# throwaway named desktop on a dev box (private arm). UD_N is how many results
# the group records; the last assertion checks it unprivileged, so adding a
# case without raising UD_N goes red where it can be seen.
# shellcheck disable=SC2016
( set +e; UD_N=29
  if [ "${EUID}" -eq 0 ]; then
    for _ in $(seq 0 "${UD_N}"); do echo ok >> "${RESULTS}"; done
    printf '  skip %s (%s)\n' "${UD_N} user-dirs sync assertions, and their count" \
      'the sync refuses root by design; covered unprivileged and on a throwaway desktop'
    exit 0
  fi
  T="$(mktemp -d)"; trap 'chmod -R u+w "${T}"; rm -rf "${T}"' EXIT
  blk="$(sed -n '/^user_dirs_absent=/,/^user_dirs_kept=..$/p' "${ROOT}/hdw4s-run-session" | sed '$d')"
  ud_before="$(grep -c . "${RESULTS}")"
  case "${blk}" in
    *'user_dirs_sync() {'*'user_dirs_guard() {'*) ok 'the sync is found in hdw4s-run-session';;
    *) bad 'the sync is found in hdw4s-run-session' 'sed found no user_dirs_sync';;
  esac
  # sync <home> <profile> <"start", "loop", or several, one process> [PATH dir]
  sync() { env -i PATH="${4:+${4}:}${PATH}" HOME="${T}/$1" XDG_CONFIG_HOME="${T}/$2/config" \
             XDG_STATE_HOME="${T}/$2/state" bash -c "${blk}"'
           for m in $0; do user_dirs_sync "${m}" || exit; done' "$3" 2>&1; }
  # Everything in the home EXCEPT the two files the sync may write: path, type,
  # mode, size, and the content of every file.
  snap() { ( cd "${T}/$1" &&
             find . \( -path ./.config/user-dirs.dirs -o -path ./.config/user-dirs.locale \) \
                    -prune -o -printf '%p %y %m %s\n' | sort &&
             find . -type f ! -path ./.config/user-dirs.dirs ! -path ./.config/user-dirs.locale \
                    -exec sha256sum {} + | sort ); }
  stock="$(printf '%s\n' 'XDG_DESKTOP_DIR="$HOME/Desktop"' 'XDG_MUSIC_DIR="$HOME/Music"')"
  moved="$(printf '%s\n' 'XDG_DESKTOP_DIR="$HOME/.local/Desktop"' 'XDG_MUSIC_DIR="$HOME/.local/Music"')"
  H="${T}/home/.config"
  # hdw4s-session makes each profile's config directory before any of this runs.
  mkdir -p "${H}" "${T}/home/Documents" "${T}/home/dotfiles" "${T}/A/config" "${T}/B/config" "${T}/C/config"
  echo 'a letter' > "${T}/home/Documents/letter.txt"
  echo 'other=1' > "${H}/other.conf"
  printf '%s\n' "${stock}" > "${H}/user-dirs.dirs"
  echo 'en_US.UTF-8' > "${H}/user-dirs.locale"
  sync home A start >/dev/null; sync home B start >/dev/null; sync home C start >/dev/null
  is  'a new profile is given the home'"'"'s folders' "$(cat "${T}/A/config/user-dirs.dirs")" "${stock}"
  before="$(snap home)"

  # "xdg-user-dirs-update --set" inside the desktop on machine A, with the home's
  # file looking a day NEWER by the clock: content decides, not time.
  printf '%s\n' "${moved}" > "${T}/A/config/user-dirs.dirs"
  touch -d '+1 day' "${H}/user-dirs.dirs"
  sync home A loop >/dev/null
  is  'a folder moved inside one desktop reaches the home, whatever the clocks say' \
      "$(cat "${H}/user-dirs.dirs")" "${moved}"
  sync home B start >/dev/null
  is  'the next desktop started on another machine has it' "$(cat "${T}/B/config/user-dirs.dirs")" "${moved}"
  sync home C loop >/dev/null
  is  'and one already running there follows it within a tick' "$(cat "${T}/C/config/user-dirs.dirs")" "${moved}"
  sync home A start >/dev/null
  is  'and the desktop that moved it keeps it across a restart' "$(cat "${T}/A/config/user-dirs.dirs")" "${moved}"

  # The dialog's "Keep Old Names" writes the stripped locale over a home copy
  # that says en_US.UTF-8, and the dialog asks whenever the two differ.
  echo 'en_US' > "${T}/A/config/user-dirs.locale"
  sync home A loop >/dev/null; sync home A start >/dev/null
  is  'an answer given in the dialog sticks across a restart' "$(cat "${T}/A/config/user-dirs.locale")" 'en_US'
  is  'and is the home'"'"'s answer now' "$(cat "${H}/user-dirs.locale")" 'en_US'

  # Both changed since they last agreed: the home wins, and says so.
  printf '%s\n' 'XDG_MUSIC_DIR="$HOME/Profile"' > "${T}/A/config/user-dirs.dirs"
  printf '%s\n' 'XDG_MUSIC_DIR="$HOME/ByHand"' > "${H}/user-dirs.dirs"
  out="$(sync home A start)"
  is  'on a conflict the home'"'"'s copy wins' "$(cat "${T}/A/config/user-dirs.dirs")" 'XDG_MUSIC_DIR="$HOME/ByHand"'
  is  'and the home is not overwritten' "$(cat "${H}/user-dirs.dirs")" 'XDG_MUSIC_DIR="$HOME/ByHand"'
  has 'and the start logs it' "${out}" "the home's wins"

  # A write to the home that fails half-way leaves nothing behind in it. "mv" is
  # stood in for, so this needs no permission a root run would ignore.
  mkdir -p "${T}/bin"; printf '#!/bin/sh\nexit 1\n' > "${T}/bin/mv"; chmod +x "${T}/bin/mv"
  printf '%s\n' "${moved}" > "${T}/A/config/user-dirs.dirs"
  out="$(sync home A loop "${T}/bin")"
  is  'a failed write leaves the home'"'"'s file as it was' "$(cat "${H}/user-dirs.dirs")" 'XDG_MUSIC_DIR="$HOME/ByHand"'
  has 'and says it could not write it' "${out}" 'could not write'
  sync home A loop >/dev/null
  is  'and the next tick writes it' "$(cat "${H}/user-dirs.dirs")" "${moved}"

  # A user-dirs file that is a symbolic link in the home is its owner's
  # arrangement: never replaced, and the profile follows what it points at.
  echo 'en_US' > "${T}/home/dotfiles/locale"
  rm -f "${H}/user-dirs.locale"; ln -s ../dotfiles/locale "${H}/user-dirs.locale"
  before="$(snap home)"
  echo 'de_DE' > "${T}/A/config/user-dirs.locale"
  sync home A loop >/dev/null
  is  'a link in the home is not replaced' "$(readlink "${H}/user-dirs.locale")" '../dotfiles/locale'
  is  'nor is what it points at written' "$(cat "${T}/home/dotfiles/locale")" 'en_US'
  is  'the profile follows it instead' "$(cat "${T}/A/config/user-dirs.locale")" 'en_US'
  rm -f "${H}/user-dirs.locale"; echo 'en_US' > "${H}/user-dirs.locale"
  before="$(snap home)"

  # THE CROWN JEWEL. After all of the above, everything in the home other than
  # the two files is exactly as it was, and no temporary file is left.
  sync home A loop >/dev/null; sync home B loop >/dev/null; sync home C start >/dev/null
  is  'nothing else in the home was written' "$(snap home)" "${before}"
  is  'and no temporary file was left there' "$(find "${T}/home" -name '*.hdw4s-*' | wc -l)" '0'

  # A brand-new home: the stock first run writes the profile's copy, and the
  # sync carries it home.
  mkdir -p "${T}/new/.config" "${T}/E/config"
  printf '%s\n' "${stock}" > "${T}/E/config/user-dirs.dirs"
  sync new E loop >/dev/null
  is  'a brand-new home gets the first run'"'"'s file' "$(cat "${T}/new/.config/user-dirs.dirs" 2>&1)" "${stock}"
  # And a home with no ~/.config is not given one.
  mkdir -p "${T}/bare" "${T}/F/config"
  printf '%s\n' "${stock}" > "${T}/F/config/user-dirs.dirs"
  out="$(sync bare F 'loop loop')"
  is  'a home with no ~/.config is not given one' "$(find "${T}/bare" -mindepth 1 | wc -l)" '0'
  is  'which is said once, not every tick' "$(grep -c 'no ~/.config' <<<"${out}")" '1'
  # Nor through a ~/.config that is a link to nowhere: nothing is made at the
  # far end of it.
  mkdir -p "${T}/dangle" "${T}/G/config"; ln -s ../nowhere/.config "${T}/dangle/.config"
  printf '%s\n' "${stock}" > "${T}/G/config/user-dirs.dirs"
  sync dangle G start >/dev/null; rc="$?"
  is  'a dangling ~/.config is left dangling' "$([ -e "${T}/nowhere" ] && echo made || echo none)" 'none'
  is  'and the start goes on' "${rc}" '0'

  # A HOME FILE NOBODY CAN READ MUST NOT FAIL A START, on any machine sharing
  # the home: one line, never the content, status 0, and both copies left as
  # they are. chmod 000 does not stop root, so a run as root uses a directory
  # in the file's place, which no account can read as a file.
  cp "${T}/A/config/user-dirs.dirs" "${T}/A-before"
  echo 'SECRET-LOOKING' > "${H}/user-dirs.dirs"; chmod 000 "${H}/user-dirs.dirs"
  if [ -r "${H}/user-dirs.dirs" ]; then
    printf '  --   %s\n' 'reading as root; a directory stands in for the unreadable file'
    chmod 644 "${H}/user-dirs.dirs"; rm -f "${H}/user-dirs.dirs"; mkdir "${H}/user-dirs.dirs"
  fi
  ino="$(stat -c '%i %f' "${H}/user-dirs.dirs")"
  out="$(sync home A start)"; rc="$?"
  is  'an unreadable home file does not fail the start' "${rc}" '0'
  is  'nor is it replaced, as though it were absent' "$(stat -c '%i %f' "${H}/user-dirs.dirs")" "${ino}"
  is  'it is said in one line' "$(grep -c . <<<"${out}")" '1'
  hasnt 'which does not carry the content' "${out}" 'SECRET-LOOKING'
  is  'and this desktop'"'"'s copy is left as it was' "$(cat "${T}/A/config/user-dirs.dirs")" "$(cat "${T}/A-before")"
  is  'this group records exactly UD_N results' "$(( $(grep -c . "${RESULTS}") - ud_before ))" "${UD_N}"
)

echo '== the guard keeps the login run from recreating folders in a home that has its own list =='
# The real xdg-user-dirs-update, over a STALE profile copy that names only one
# folder, in a home whose folders were moved under ~/.local: measured, it
# recreates the rest. A runner without the program FAILS here with that reason,
# rather than skipping: a guard nobody has seen refuse is not known to refuse.
# shellcheck disable=SC2016
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  blk="$(sed -n '/^user_dirs_absent=/,/^user_dirs_kept=..$/p' "${ROOT}/hdw4s-run-session" | sed '$d')"
  guard() { env -i PATH="${PATH}" HOME="${T}/home" XDG_CONFIG_HOME="${T}/prof" \
              XDG_STATE_HOME="${T}/state" bash -c "${blk}"'
            user_dirs_guard' 2>&1; }
  login() { env -i PATH="${PATH}" HOME="${T}/home" XDG_CONFIG_HOME="${T}/prof" LANG=C.UTF-8 \
              xdg-user-dirs-update >/dev/null 2>&1; }
  defaults() { for d in Desktop Documents Music Pictures Public Templates Videos; do
                 [ ! -e "${T}/home/${d}" ] || printf '%s ' "${d}"; done; }
  mkdir -p "${T}/home/.config" "${T}/prof" "${T}/home/Downloads"
  for d in Desktop Documents Music Pictures Public Templates Videos; do mkdir -p "${T}/home/.local/${d}"; done
  printf '%s\n' 'XDG_MUSIC_DIR="$HOME/.local/Music"' > "${T}/home/.config/user-dirs.dirs"
  stale='XDG_DOWNLOAD_DIR="$HOME/Downloads"'
  if ! command -v xdg-user-dirs-update >/dev/null; then
    for t in 'the guard is written' 'with the guard on, the login run recreates no folder' \
             'RED ARM: without it, the same run does' 'a home with no list of its own is not guarded' \
             'a guard of ours is taken back there' 'but an administrator'"'"'s user-dirs.conf is not'; do
      bad "${t}" 'xdg-user-dirs-update is not installed (package xdg-user-dirs); the guard was NOT exercised'
    done
  else
    guard >/dev/null
    has 'the guard is written' "$(cat "${T}/prof/user-dirs.conf" 2>&1)" 'enabled=False'
    printf '%s\n' "${stale}" > "${T}/prof/user-dirs.dirs"
    login
    is  'with the guard on, the login run recreates no folder' "$(defaults)" ''
    # RED ARM, built in: the program really does recreate them, so the line
    # above can fail.
    rm -f "${T}/prof/user-dirs.conf"; printf '%s\n' "${stale}" > "${T}/prof/user-dirs.dirs"
    login
    is  'RED ARM: without it, the same run does' "$(defaults)" 'Desktop Documents Music Pictures Public Templates Videos '
    rm -f "${T}/home/.config/user-dirs.dirs"
    guard >/dev/null
    is  'a home with no list of its own is not guarded' "$(ls "${T}/prof")" 'user-dirs.dirs'
    printf '%s\n' 'x' > "${T}/home/.config/user-dirs.dirs"; guard >/dev/null
    rm -f "${T}/home/.config/user-dirs.dirs"; guard >/dev/null
    is  'a guard of ours is taken back there' "$([ -e "${T}/prof/user-dirs.conf" ] && echo kept || echo gone)" 'gone'
    echo 'filename_encoding=locale' > "${T}/prof/user-dirs.conf"; guard >/dev/null
    is  'but an administrator'"'"'s user-dirs.conf is not' "$(cat "${T}/prof/user-dirs.conf")" 'filename_encoding=locale'
  fi
)

echo '== only a named desktop with its own profile keeps the two copies in step =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-run-session
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  gate="$(sed -n '/^user_dirs_kept=..$/,/^fi$/p' "${ROOT}/hdw4s-run-session")"
  [ -n "${gate}" ] && ok 'the gate is found' || bad 'the gate is found' 'sed found nothing'
  mkdir -p "${T}/home/.config" "${T}/prof"
  run() { env -i PATH="${PATH}" HOME="${T}/home" "$@" bash -c '
          user_dirs_sync() { echo "sync $1"; }; user_dirs_guard() { echo guard; }
          '"${gate}"'
          echo "kept=${user_dirs_kept}"' | paste -sd ' '; }
  is  'a named, isolated desktop syncs and guards at start' \
      "$(run HDW4S_ISOLATION=profile XDG_CONFIG_HOME="${T}/prof")" 'sync start guard kept=1'
  is  'an ephemeral one does not' \
      "$(run HDW4S_SESSION_TYPE=ephemeral HDW4S_ISOLATION=profile XDG_CONFIG_HOME="${T}/prof")" 'kept='
  is  'nor one without isolation' "$(run XDG_CONFIG_HOME="${T}/prof")" 'kept='
  is  'nor one whose config home IS the home'"'"'s' \
      "$(run HDW4S_ISOLATION=profile XDG_CONFIG_HOME="${T}/home/.config")" 'kept='
  # And the loop at the end calls it every tick.
  loop="$(sed -n '/^while :; do$/,/^done$/p' "${ROOT}/hdw4s-run-session")"
  has 'the main loop keeps them in step while the desktop runs' "${loop}" \
      '[ -z "${user_dirs_kept}" ] || user_dirs_sync loop || :'
)

echo '== every write into a named profile is one somebody decided on =='
# Property 4 of the user-dirs ruling: a one-way copy into the profile silently
# undoes what a person changed inside the desktop, and nothing fails. So every
# line of the two session scripts that writes into $XDG_CONFIG_HOME or
# $XDG_DATA_HOME -- a cp, mv or ln whose last word is there, a redirection, or
# the sync's own writer; making a directory writes nothing a person edits -- is
# listed here with the reason it may, and a new one fails
# until somebody adds it, and its reason, on purpose.
# shellcheck disable=SC2016
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  scan() { for f in "$@"; do
             awk -v F="${f##*/}" -v P='"[^"]*(XDG_(CONFIG|DATA)_HOME|profile[}]/(config|data))' '
               /^[[:space:]]*#/ { next }
               $0 ~ ("(^|[^[:alnum:]_-])(cp|mv|ln)[[:space:]].*" P "[^\"]*\"[[:space:]]*([|][|]|&&|;)?[[:space:]]*$") ||
               $0 ~ ("user_dirs_put[[:space:]]+" P) || $0 ~ (">[[:space:]]*" P) {
                 sub(/^[[:space:]]+/, ""); print F ": " $0 }' "${f}"
           done | sort; }
  allowed='hdw4s-session: if ! cp -R --update=none "${profile}/data/." "${XDG_DATA_HOME}/" ||  ## ephemeral only: the template'"'"'s data half, into a home made for this visitor
hdw4s-session: ln -s "${trash}" "${XDG_DATA_HOME}/Trash" ||  ## a link to the home'"'"'s own trash; it copies nothing
hdw4s-session: > "${XDG_CONFIG_HOME}/autostart/tracker-miner-fs-3.desktop"  ## the product'"'"'s own file: the indexer is off (HDW4S_INDEXING)
hdw4s-session: > "${XDG_DATA_HOME}/dbus-1/services/${svc}.service"  ## the product'"'"'s own shadow of the indexer'"'"'s service
hdw4s-session: > "${XDG_CONFIG_HOME}/autostart/gnome-initial-setup-first-login.desktop"  ## ephemeral only: no first-run wizard for a visitor
hdw4s-session: : > "${XDG_CONFIG_HOME}/${d}/First Run"  ## ephemeral only: the browsers'"'"' first-run markers
hdw4s-session: > "${XDG_CONFIG_HOME}/autostart/pulseaudio.desktop"  ## the product'"'"'s own file: PipeWire is the audio server
hdw4s-session: > "${XDG_CONFIG_HOME}/autostart/${entry}.desktop"  ## the product'"'"'s own files: autostart entries a remote desktop must not run
hdw4s-run-session: user_dirs_put "${XDG_CONFIG_HOME}/${f}" "${HOME}/.config/${f}" || {  ## the user-dirs sync: refreshed from the home only when the profile did not change
hdw4s-run-session: user_dirs_put "${XDG_CONFIG_HOME}/user-dirs.conf" \  ## the user-dirs guard: the product'"'"'s own file'
  want="$(while IFS= read -r l; do printf '%s\n' "${l%%  ## *}"; done <<<"${allowed}" | sort)"
  got="$(scan "${ROOT}/hdw4s-session" "${ROOT}/hdw4s-run-session")"
  is  'every write into the profile is on the list' "$(comm -13 <(printf '%s\n' "${want}") <(printf '%s\n' "${got}"))" ''
  is  'and every line on the list is still there' "$(comm -23 <(printf '%s\n' "${want}") <(printf '%s\n' "${got}"))" ''
  is  'each with its reason' "$(grep -vc '  ## [^ ]' <<<"${allowed}")" '0'
  # RED ARM: one more copy, of the shape that cost the owner his folders.
  cp "${ROOT}/hdw4s-session" "${T}/hdw4s-session"
  echo '  cp -f "${HOME}/.config/x" "${XDG_CONFIG_HOME}/x"' >> "${T}/hdw4s-session"
  is  'RED ARM: a new one-way copy is caught' \
      "$(comm -13 <(printf '%s\n' "${want}") <(scan "${T}/hdw4s-session" "${ROOT}/hdw4s-run-session"))" \
      'hdw4s-session: cp -f "${HOME}/.config/x" "${XDG_CONFIG_HOME}/x"'
)

echo '== a named desktop gets a composed dconf profile unless it may lock =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-session
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  blk="$(sed -n '/^if \[ "${HDW4S_SESSION_TYPE:-}" != .ephemeral. \] &&$/,/^fi$/p' "${ROOT}/hdw4s-session")"
  [ -n "${blk}" ] && ok 'the block is found in hdw4s-session' || bad 'the block is found in hdw4s-session' 'sed found nothing'
  mkdir -p "${T}/run"
  printf '# machine comment\nuser-db:user\nsystem-db:local\n' > "${T}/machine"
  run() { env -i PATH="${PATH}" XDG_RUNTIME_DIR="${T}/run" "$@" bash -c "${blk}"'
          printf "%s" "${DCONF_PROFILE:-unset}"'; }
  rm -f "${T}/run/hdw4s-dconf-profile"
  out="$(run DCONF_PROFILE="${T}/machine")"
  is  'off by default: the profile is the composed one' "${out}" "${T}/run/hdw4s-dconf-profile"
  is  'which keeps the machine'"'"'s layers and adds ours beneath' \
      "$(tr '\n' ' ' < "${T}/run/hdw4s-dconf-profile")" 'user-db:user system-db:local system-db:hdw4s-named '
  rm -f "${T}/run/hdw4s-dconf-profile"
  out="$(run DCONF_PROFILE="${T}/machine" HDW4S_SCREEN_LOCK=on)"
  is  'on: the machine'"'"'s profile is left as it is' "${out}" "${T}/machine"
  out="$(run DCONF_PROFILE="${T}/machine" HDW4S_SESSION_TYPE=ephemeral)"
  is  'an ephemeral desktop is left to its own profile' "${out}" "${T}/machine"
)

echo '== where a desktop prints: the browser, unless a named one is told otherwise =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-run-session
( set +e
  blk="$(awk '/A NAMED DESKTOP PRINTS THERE TOO/{f=1} f{print; if ($0 ~ /^fi$/) exit}' \
         "${ROOT}/hdw4s-run-session")"
  has 'the block is found in hdw4s-run-session' "${blk}" 'export CUPS_SERVER='
  run() { env -i PATH="${PATH}" XDG_RUNTIME_DIR=/r "$@" bash -c "${blk}"'
          printf "%s" "${CUPS_SERVER:-unset}"'; }
  q=/r/selkies-cups/cups.sock
  is 'a named desktop prints to the browser by default' "$(run HDW4S_PRINTING=browser)" "${q}"
  is 'and with the setting absent' "$(run)" "${q}"
  is 'HDW4S_PRINTING=machine leaves a named desktop on the machine'"'"'s printers' \
     "$(run HDW4S_PRINTING=machine)" 'unset'
  is 'an ephemeral desktop ignores it and prints to the browser' \
     "$(run HDW4S_PRINTING=machine HDW4S_SESSION_TYPE=ephemeral)" "${q}"
)

echo '== printed documents wait in the desktop'"'"'s own state, not in the home =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-run-session
( set +e
  line="$(grep -m1 '^export SELKIES_PRINT_SPOOL_PATH=' "${ROOT}/hdw4s-run-session")"
  has 'the spool is set in hdw4s-run-session' "${line}" 'SELKIES_PRINT_SPOOL_PATH'
  run() { env -i HOME=/h "$@" bash -c "${line}"'; printf "%s" "${SELKIES_PRINT_SPOOL_PATH}"'; }
  is 'it follows XDG_STATE_HOME, the profile'"'"'s' "$(run XDG_STATE_HOME=/p/state)" '/p/state/selkies/print'
  is 'and falls back to the home only without one' "$(run)" '/h/.local/state/selkies/print'
)

echo '== the browser print queue follows the machine'"'"'s paper size =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-run-session
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  blk="$(awk '/^if \[ "\$\{CUPS_SERVER:-\}" = /{f=1} f{print; if ($0 ~ /^fi$/) exit}' \
         "${ROOT}/hdw4s-run-session")"
  has 'the block is found in hdw4s-run-session' "${blk}" 'lpadmin -h'
  q="${T}/run/selkies-cups"; mkdir -p "${q}/ppd" "${T}/bin"
  python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${q}/cups.sock"
  printf '*DefaultPageSize: A4\n*PageSize A4/A4: "x"\n*PageSize Letter/US Letter: "x"\n' > "${q}/ppd/Selkies.ppd"
  # A stand-in that records what it was asked, and does nothing else.
  printf '#!/bin/sh\necho "$*" >> %s/asked\n' "${T}" > "${T}/bin/lpadmin"; chmod +x "${T}/bin/lpadmin"
  run() { rm -f "${T}/asked"; printf '%b' "$1" > "${T}/papersize"; shift
          env -i PATH="${T}/bin:${PATH}" XDG_RUNTIME_DIR="${T}/run" PAPERCONF="${T}/papersize" \
              CUPS_SERVER="${q}/cups.sock" "$@" bash -c 'children=(); '"${blk}"'; wait' 2>&1; }
  out="$(run 'letter\n')"
  is  'a Letter machine sets the queue'"'"'s A4 default to Letter' "$(cat "${T}/asked" 2>/dev/null)" \
      "-h ${q}/cups.sock -p Selkies -o PageSize=Letter"
  has 'and says so once' "${out}" 'now defaults to Letter, the machine'"'"'s paper size (it was A4)'
  out="$(run 'a4\n')"
  is  'a machine that agrees with the queue changes nothing' "$(cat "${T}/asked" 2>/dev/null)" ''
  is  'and says nothing' "${out}" ''
  out="$(run 'a4\n' PAPERSIZE=legal)"
  has 'a size the queue does not offer is reported, not set' "${out}" 'does not offer'
  run 'a4\n' PAPERSIZE=letter >/dev/null
  is  'PAPERSIZE wins over the file, as libpaper has it' "$(cat "${T}/asked" 2>/dev/null)" \
      "-h ${q}/cups.sock -p Selkies -o PageSize=Letter"
  run '# the machine'"'"'s paper\nletter\n' >/dev/null
  is  'a comment before the size is skipped' "$(cat "${T}/asked" 2>/dev/null)" \
      "-h ${q}/cups.sock -p Selkies -o PageSize=Letter"
  run 'letter\n' CUPS_SERVER= >/dev/null
  is  'a desktop on the machine'"'"'s printers is left alone' "$(cat "${T}/asked" 2>/dev/null)" ''
)

echo '== a named desktop'"'"'s trash is linked to the home'"'"'s own =='
# shellcheck disable=SC2016  # matched as literal text in hdw4s-session
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  # From the marker comment to the end of its one if-block.
  blk="$(awk '/A NAMED DESKTOP.S TRASH/{f=1} f{print; if ($0 ~ /^  fi$/) exit}' \
         "${ROOT}/hdw4s-session")"
  has 'the block is found in hdw4s-session' "${blk}" 'ln -s "${trash}"'
  mkdir -p "${T}/home" "${T}/data/Trash/files"
  HOME="${T}/home" XDG_DATA_HOME="${T}/data" bash -c "${blk}" 2>/dev/null
  is  'a named desktop'"'"'s empty profile Trash becomes a link to ~/.local/share/Trash' \
      "$(readlink "${T}/data/Trash")" "${T}/home/.local/share/Trash"
  rm -rf "${T}/data/Trash"; mkdir -p "${T}/data/Trash/files"; : > "${T}/data/Trash/files/kept"
  HOME="${T}/home" XDG_DATA_HOME="${T}/data" bash -c "${blk}" 2>/dev/null
  is  'a Trash holding files is left alone' "$([ -L "${T}/data/Trash" ] && echo link || echo dir)" 'dir'
  rm -rf "${T}/data/Trash"; mkdir -p "${T}/data/Trash/files"
  HOME="${T}/home" XDG_DATA_HOME="${T}/data" HDW4S_SESSION_TYPE=ephemeral bash -c "${blk}" 2>/dev/null
  is  'an ephemeral desktop gets no link: its data is in its home' \
      "$([ -L "${T}/data/Trash" ] && echo link || echo dir)" 'dir'
)

echo '== a published Chrome keeps no rule checksum without its rules =='
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/Default/DNR Extension Rules/kept"
  out="$(python3 - "${ROOT}/hdw4s-template" "${T}/Default" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m)
p = {"extensions": {"settings": {
        "kept": {"dnr_dynamic_ruleset": {"checksum": 1}, "path": "a"},
        "gone": {"dnr_dynamic_ruleset": {"checksum": 2}, "path": "b"}}}}
print("dropped=%d" % m.forget_missing_dnr_rules(p, sys.argv[2]))
print("kept=%s gone=%s" % (sorted(p["extensions"]["settings"]["kept"]),
                           sorted(p["extensions"]["settings"]["gone"])))
PY
)"
  has 'a checksum whose rules are missing is dropped' "${out}" 'dropped=1'
  has 'and one whose rules are carried is kept'       "${out}" "kept=['dnr_dynamic_ruleset', 'path'] gone=['path']"
)

echo '== an ephemeral desktop'"'"'s data is published from its home, and never its trash =='
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/etc" "${T}/root" "${T}/author/config" \
           "${T}/home/.local/share/gnome-shell/extensions/ext@x" \
           "${T}/home/.local/share/Trash/files" "${T}/home/.local/share/Trash/info" \
           "${T}/home/.local/share/backgrounds"
  echo "HDW4S_TEMPLATE_DIR=${T}/root" > "${T}/etc/hdw4s.conf"
  echo '{}' > "${T}/home/.local/share/gnome-shell/extensions/ext@x/metadata.json"
  echo secret > "${T}/home/.local/share/Trash/files/deleted.txt"
  echo img > "${T}/home/.local/share/backgrounds/mine.jpg"
  out="$(HDW4S_ETCDIR="${T}/etc" python3 - "${ROOT}/hdw4s-template" "${T}" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys, os
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m); m.normalise = lambda tree: None
T = sys.argv[2]
gen, _, _ = m.harvest(T + "/author", T + "/home", "x")
found = [os.path.relpath(os.path.join(d, f), gen) for d, _, fs in os.walk(gen) for f in fs]
print("ext=%s" % any(p.endswith("ext@x/metadata.json") for p in found))
print("trash=%s" % any("Trash" in p or "deleted.txt" in p for p in found))
# Only backgrounds a setting names are kept, and this sandbox has no settings
# database to name one: what is asserted is WHERE the author's are looked for.
print("bg=%s" % (m.author_path(T + "/author", T + "/home", "data/backgrounds")[0]
                 == T + "/home/.local/share/backgrounds"))
e = m.filter_dconf([("org/gnome/desktop/background", "picture-uri",
                     "'file:///home/user/.local/share/backgrounds/mine.jpg'")], "x", [])
print("uri=%s" % (e[0][2] if e else "dropped"))
PY
)"
  has   'an extension in the home'"'"'s ~/.local/share is published' "${out}" 'ext=True'
  has   'the trash is never published'                       "${out}" 'trash=False'
  has   'backgrounds are looked for there'                   "${out}" 'bg=True'
  has   'and the setting points at the published copy'       "${out}" "/backgrounds/mine.jpg'"
  hasnt 'not at the author'"'"'s home'                        "${out}" 'uri=.*home/user'
)

echo '== a Files bookmark carries what it names, empty, and never follows a link =='
# THE DEFECT (owner, 2026-10-02): a bookmark to ~/.local/Shared, a link to
# /shared, was published without the link, and the bookmark not at all --
# config/gtk-3.0/bookmarks was not on the allow-list.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/etc" "${T}/author/config/gtk-3.0" "${T}/home/.local" \
           "${T}/home/Projects" "${T}/host-etc"
  echo "HDW4S_TEMPLATE_DIR=${T}/root" > "${T}/etc/hdw4s.conf"
  echo private > "${T}/home/Projects/notes.txt"
  echo hostsecret > "${T}/host-etc/shadow"
  ln -s /shared "${T}/home/.local/Shared"
  ln -s Projects "${T}/home/via"
  ln -s loop2 "${T}/home/loop"; ln -s loop "${T}/home/loop2"
  ln -s ../../elsewhere "${T}/home/esc"
  ln -s "${T}/host-etc" "${T}/home/evil"
  printf '%s\n' 'file:///home/user/.local/Shared Shared' \
    'file:///home/user/Projects' 'file:///home/user/Gone' \
    'sftp://example.invalid/x Remote' 'file:///home/user/loop' \
    'file:///home/user/via' 'file:///home/user/esc' \
    'file:///home/user/evil/sub' 'file:///shared' \
    'file:///home/user/a%00b' 'sftp://admin:hunter2@internal.invalid/ R' \
    'file:///home/user' \
    > "${T}/author/config/gtk-3.0/bookmarks"
  mkdir -p "${T}/home2" "${T}/gen3/home" "${T}/outside" "${T}/home3/A/B"
  ln -s /shared/x "${T}/home2/.local"
  ln -s "${T}/outside" "${T}/gen3/home/A"
  out="$(HDW4S_ETCDIR="${T}/etc" python3 - "${ROOT}/hdw4s-template" "${T}" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys, os
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m); m.normalise = lambda tree: None
T = sys.argv[2]
gen, _, notes = m.harvest(T + "/author", T + "/home", "x")
h = gen + "/home"
link = lambda p: os.readlink(h + p) if os.path.islink(h + p) else "none"
print("shared=%s" % link("/.local/Shared"))
print("projects=%s" % (sorted(os.listdir(h + "/Projects")) if os.path.isdir(h + "/Projects") else "none"))
print("via=%s esc=%s evil=%s" % (link("/via"), link("/esc"),
                                 "link" if os.path.islink(h + "/evil") else "none"))
found = [os.path.join(d, f) for d, _, fs in os.walk(gen) for f in fs]
print("leaked=%s" % any(open(p, errors="replace").read().strip() in ("private", "hostsecret")
                        for p in found if not os.path.islink(p)))
print("marks=%s" % "|".join(l.split(" ")[0].replace("file:///home/user", "~")
                            for l in open(gen + "/profile/config/gtk-3.0/bookmarks").read().splitlines()))
print("residue=%s" % [p for p in ("loop", "loop2") if os.path.lexists(h + "/" + p)])
print("dotlocal=%s" % m.carry_home_path(T + "/gen2", T + "/home2", ".local/foo", []))
print("guard=%s outside=%s" % (m.carry_home_path(T + "/gen3", T + "/home3", "A/B", []),
                               os.listdir(T + "/outside")))
for n in notes:
    print("note: " + n)
PY
)"
  has   'a bookmarked link is carried as the link'          "${out}" 'shared=/shared'
  has   'a bookmarked folder is carried EMPTY'              "${out}" 'projects=[]'
  has   'its contents, and no host file, are never carried' "${out}" 'leaked=False'
  has   'a chain of links inside the home is chased'        "${out}" 'via=Projects esc=../../elsewhere evil=link'
  has   'kept: home, network, outside, chased, escaping'    "${out}" 'marks=~/.local/Shared|~/Projects|sftp://example.invalid/x|~/via|~/esc|~/evil/sub|file:///shared|~'
  has   'a folder that is gone drops its bookmark, said so' "${out}" 'note: left out the bookmark file:///home/user/Gone: ~/Gone is not there'
  has   'a loop of links ends, said so'                     "${out}" 'note: left out the bookmark file:///home/user/loop: more than 8'
  has   'the author is told what was emptied'               "${out}" 'note: carried ~/Projects EMPTY'
  has   'a dropped bookmark leaves nothing behind'          "${out}" 'residue=[]'
  has   'a malformed bookmark is left out, not a crash'     "${out}" 'note: left out the bookmark file:///home/user/a%00b'
  has   'a bookmark with a password is left out'            "${out}" 'note: left out a sftp bookmark to internal.invalid: it carries a user'
  hasnt 'and the password is never printed'                 "${out}" 'hunter2'
  has   'a link at ~/.local is refused'                     "${out}" 'dotlocal=~/.local is a symbolic link'
  has   'nothing is created through a link already carried' "${out}" "guard=~/A/B is reached through a link already carried outside=[]"
)

echo '== a template goes across as one archive, and a doctored one is refused =='
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/etc" "${T}/root/gen-1/dconf" "${T}/root/gen-1/home/Downloads"
  echo "HDW4S_TEMPLATE_DIR=${T}/root" > "${T}/etc/hdw4s.conf"
  echo '[org/gnome/x]' > "${T}/root/gen-1/dconf/50-template"
  ln -s gen-1 "${T}/root/current"
  out="$(HDW4S_ETCDIR="${T}/etc" python3 - "${ROOT}/hdw4s-template" "${T}" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys, os, tarfile, io
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m); T = sys.argv[2]
m.cmd_export(T + "/t.tgz")
try:
    m.cmd_export(T + "/t.tgz"); print("second export: written")
except SystemExit: print("second export: refused")
m.fetch_from_file(T + "/t.tgz", T + "/stage")
print("roundtrip=%s" % sorted(os.path.relpath(os.path.join(d, f), T + "/stage")
                              for d, ds, fs in os.walk(T + "/stage") for f in fs + ds))
bad = io.BytesIO()
with tarfile.open(fileobj=bad, mode="w:gz") as t:
    data = b"x"; i = tarfile.TarInfo("../escape.txt"); i.size = 1
    t.addfile(i, io.BytesIO(data))
open(T + "/bad.tgz", "wb").write(bad.getvalue())
try:
    m.fetch_from_file(T + "/bad.tgz", T + "/stage2"); print("doctored: unpacked")
except SystemExit: print("doctored: refused")
print("escaped=%s stage2=%s" % (os.path.exists(T + "/escape.txt"), os.path.exists(T + "/stage2")))
PY
)"
  has 'an existing archive is not overwritten' "${out}" 'second export: refused'
  has 'the archive carries the template'       "${out}" "roundtrip=['dconf', 'dconf/50-template', 'home', 'home/Downloads']"
  has 'an archive reaching outside is refused' "${out}" 'doctored: refused'
  has 'and wrote nothing, outside or staged'   "${out}" 'escaped=False stage2=False'
)

echo '== a template archive carries absolute symbolic links, never anything written through one =='
# THE DEFECT (owner, 2026-10-03): "template copyfrom" refused a template whose
# home held ~/.local/Shared -> /shared -- the "data" filter rejects every link to
# an absolute path, and a Files bookmark legitimately carries one.
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  mkdir -p "${T}/etc" "${T}/outside"
  echo "HDW4S_TEMPLATE_DIR=${T}/root" > "${T}/etc/hdw4s.conf"
  out="$(HDW4S_ETCDIR="${T}/etc" python3 - "${ROOT}/hdw4s-template" "${T}" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys, os, tarfile, io
l = importlib.machinery.SourceFileLoader("t", sys.argv[1])
s = importlib.util.spec_from_loader("t", l); m = importlib.util.module_from_spec(s)
l.exec_module(m); T = sys.argv[2]
def archive(name, members):
    with tarfile.open(T + "/" + name, "w:gz") as t:
        for kind, path, extra in members:
            i = tarfile.TarInfo(path)
            if kind == "dir": i.type = tarfile.DIRTYPE; t.addfile(i)
            elif kind == "sym": i.type = tarfile.SYMTYPE; i.linkname = extra; t.addfile(i)
            elif kind == "hard": i.type = tarfile.LNKTYPE; i.linkname = extra; t.addfile(i)
            else: d = extra.encode(); i.size = len(d); t.addfile(i, io.BytesIO(d))
    return T + "/" + name
def unpack(label, path):
    stage = T + "/stage-" + label
    try:
        m.fetch_from_file(path, stage); r = "unpacked"
    except SystemExit:
        r = "refused"
    print("%s: %s stage=%s outside=%s" % (label, r, os.path.exists(stage), sorted(os.listdir(T + "/outside"))))
    return stage
st = unpack("bookmark", archive("ok.tgz", [("dir", "home", None), ("dir", "home/.local", None),
                                           ("sym", "home/.local/Shared", "/shared"), ("file", "dconf/50-template", "[x]")]))
print("link=%s" % (os.readlink(st + "/home/.local/Shared") if os.path.islink(st + "/home/.local/Shared") else "none"))
unpack("through", archive("bad1.tgz", [("sym", "evil", T + "/outside"), ("file", "evil/x", "pwn")]))
unpack("hardlink", archive("bad2.tgz", [("hard", "h", "/etc/hostname")]))
st = unpack("absname", archive("bad3.tgz", [("sym", "/abs", "/shared")]))
# the filter STRIPS a leading "/" from a member's name: it lands INSIDE the stage
print("absname-inside=%s" % os.path.islink(st + "/abs"))
unpack("dotdot", archive("bad4.tgz", [("sym", "../up", "/shared")]))
PY
)"
  has 'an absolute symbolic link is carried'         "${out}" 'bookmark: unpacked stage=True'
  has 'as the link, not its target'                  "${out}" 'link=/shared'
  has 'nothing is written THROUGH such a link'       "${out}" 'through: refused stage=False outside=[]'
  has 'a hard link outside is still refused'         "${out}" 'hardlink: refused stage=False'
  has 'a link with an absolute NAME lands inside'    "${out}" 'absname-inside=True'
  has 'a link named with .. is refused'              "${out}" 'dotdot: refused stage=False'
)

echo '== the background generator reads its knobs when it draws, not when it loads =='
# THE DEFECT: the arc's ends were derived from COOL_EXTENSION and WARM_EXTENSION
# once, at import, so a rating sheet that assigned an extension afterwards
# showed the shipped arc under another sheet's name, and nothing said so.
( set +e
  out="$(python3 - "${ROOT}/hdw4s-background" 2>&1 <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("g", sys.argv[1])
s = importlib.util.spec_from_loader("g", l); g = importlib.util.module_from_spec(s)
l.exec_module(g)
tok = b"tests-sh-token"
dye = lambda: g.choose("hdw4s-ephemeral1", tok, "ephemeral")["base"]
before = dye()
g.COOL_EXTENSION = 80.0
print("extension=%s" % ("moved" if dye() != before else "ignored"))
g.COOL_EXTENSION = 34.9
print("restored=%s" % (dye() == before))
floor = g.LADDER_FLOOR
g.LADDER_FLOOR = floor + 10.0
print("ladder=%s" % ("moved" if dye() != before else "ignored"))
g.LADDER_FLOOR = floor
g.HUE_DRAW = g.WEIGHT_DRAW = "rungs"
dyes = lambda: len({g.choose("hdw4s-ephemeral1", b"t%d" % i, "ephemeral")["base"]
                    for i in range(60)})
print("rungs_distinct_le_40=%s" % (dyes() <= g.RUNGS * g.WEIGHTS))
g.HUE_DRAW = g.WEIGHT_DRAW = "continuous"
print("continuous_distinct_gt_40=%s" % (dyes() > g.RUNGS * g.WEIGHTS))
pic = lambda: g.svg(g.choose("hdw4s-ephemeral1", tok, "ephemeral"))
print("relief_shipped=%s" % ("rdark" in pic() and "rlight" in pic()))
relief = g.RELIEF
g.RELIEF = 0.0
off = pic()
print("relief_off_emits_nothing=%s" % ("rdark" not in off and "rlight" not in off))
g.RELIEF = relief
on = pic()
print("relief_on_draws=%s" % ("rdark" in on and "rlight" in on and on != off))
g.SWEEP_CHROMA = 1.0
print("sweep_chroma=%s" % ("moved" if pic() != on else "ignored"))
import contextlib, io
def check():
    with contextlib.redirect_stdout(io.StringIO()), \
         contextlib.redirect_stderr(io.StringIO()):
        return g.main(["check"])
print("relief_at_ceiling_check=%d" % check())
g.RELIEF_LIGHT_L = g.SPEC_CEILING + 5.0
print("relief_above_ceiling_check=%d" % check())
# Every slot is checked against the real cap, not the slot before it's colour.
# Relief OFF: with it on, every slot's brightest colour is the cap itself, and
# the defect cannot show.
g.RELIEF = 0.0
g.RELIEF_LIGHT_L = None
out = io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
    g.main(["check"])
rows = [r.split() for r in out.getvalue().splitlines()[1:] if r[:1].isdigit()]
print("each_slot_own_cap=%s" % (len(rows) > 1 and all(
    abs(float(r[-1]) - g.spec_for(int(r[1]), int(r[0]) % g.WEIGHTS, 0x5eed5eed,
                                  top=g.TOP_L)["top_L"]) < 0.05 for r in rows)))
PY
)"
  has 'an arc extension assigned after loading moves the dye' "${out}" 'extension=moved'
  has 'and putting it back puts the dye back'                 "${out}" 'restored=True'
  has 'the lightness ladder is read at call time too'         "${out}" 'ladder=moved'
  has 'the stepped draw has at most rungs x weights dyes'     "${out}" 'rungs_distinct_le_40=True'
  has 'the continuous draw is not stepped'                    "${out}" 'continuous_distinct_gt_40=True'
  # Lightness relief: shipped on; off draws nothing, on draws, and its light
  # sections count against the white-label ceiling like every other colour.
  has 'lightness relief is drawn as shipped'                   "${out}" 'relief_shipped=True'
  has 'switched off it draws nothing'                          "${out}" 'relief_off_emits_nothing=True'
  has 'and switched on draws light and dark sections'          "${out}" 'relief_on_draws=True'
  has 'the ramp chroma is read at call time'                   "${out}" 'sweep_chroma=moved'
  has 'relief at the ceiling passes the ceiling check'         "${out}" 'relief_at_ceiling_check=0'
  has 'relief brighter than the ceiling is refused'            "${out}" 'relief_above_ceiling_check=1'
  has 'the check holds each slot to the cap, not to the last slot' "${out}" 'each_slot_own_cap=True'
  "${ROOT}/hdw4s-background" check >/dev/null 2>&1
  is 'the shipped field passes its own ceiling check' "$?" '0'
  "${ROOT}/hdw4s-background" check --top-lightness 55 >/dev/null 2>&1
  is 'and a field allowed above it is refused'        "$?" '1'
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

  # A seat of the pool and the authoring slot have no port, and their index is
  # numbered from far above the block on purpose: not counted, not "uncovered".
  printf '0 alice\n1000 _hdw4s_0 ephemeral\n1001 tmpl template\n' > "${SLOTS}"
  out="$(cmd_check 2>&1)"
  has 'rows with no port are not counted as sessions on a port' \
      "${out}" 'sessions    1, all within the loaded range 7300-7303'

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
  printf '%s\n' '# comment' '0 alice desktop' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  is 'a desktop row is read'           "$(type_of alice)"  'desktop'
  is 'a three-field row is read'       "$(type_of _hdw4s_0)"   'ephemeral'
  is 'an unknown instance defaults'    "$(type_of nobody)" 'desktop'
  is 'the desktop unit'   "$(unit_of alice)" 'hdw4s@alice.service'
  is 'the ephemeral unit' "$(unit_of _hdw4s_0)"  'hdw4s-ephemeral@_hdw4s_0.service'
  is 'drop-ins follow the unit' "$(dropin_of _hdw4s_0)" \
     "${DROPIN}/hdw4s-ephemeral@_hdw4s_0.service.d"

  # -- the fourth type ------------------------------------------------------
  #
  # WHY THESE ARE HERE AND NOT BESIDE THE FEATURE. "template" is not a feature
  # of its own; it is a value that seventeen existing readers of this table each
  # decide something from, and every one of them used to fall through to the
  # named-desktop arm. The damage was never in one place, so neither is the
  # check: what is asserted below is that each reader asks one of the two
  # NAMED questions, and that the two questions give different answers.
  printf '%s\n' '# comment' '0 alice' '1 _hdw4s_0 ephemeral' '2 tmpl template' \
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
    is 'an unreadable table is not "desktop"' "$(type_of _hdw4s_0)" 'unreadable'

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
    out="$( ( HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" show _hdw4s_0 ) 2>&1 )"; rc=$?
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
  printf '%s\n' '1 _hdw4s_0 ephemeral' '0 alice' > "${SLOTS}"
  printf 'HDW4S_ISOLATION=none\n' > "${CONF}"
  # Stubbed: the real answer needs a loaded unit. Reached through the function
  # under test, not called directly.
  # shellcheck disable=SC2317
  systemctl() { echo 'HDW4S_ISOLATION=profile HDW4S_PROFILE_DIR=/run/hdw4s'; }
  r="$(setting_with_source _hdw4s_0 HDW4S_ISOLATION none)"
  is 'an ephemeral slot is always profile-isolated' "${r%%$'	'*}" 'profile'
  is 'and says the session fixes it, not a file or the unit' "${r#*$'	'}" \
     'hdw4s-session (fixed for this kind of desktop)'
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

  # And "hdw4s proxy" must never describe one seat: it is refused, and points at
  # the pool's block, which describes the POOL.
  #
  # The assertion this replaced required the block to contain
  # "proxy_pass http://unix:" -- pointing nginx straight at one slot's socket,
  # which is the bypass. It was correct when a session's own socket was the only
  # kind there was, and it went on passing after the pool shipped, pinning the
  # defect in place exactly as the auth group's assertion pinned the dead end.
  #
  # A conf that says "tcp" is put in front of it: the refusal follows the row's
  # type, whatever the slot's own file says.
  printf '%s\n' "0 ${me} ephemeral" > "${SLOTS}"
  printf 'HDW4S_TRANSPORT=tcp\n' > "${ETCDIR}/${me}.conf"
  out="$( ( cmd_proxy "${me}" ) 2>&1 )"; rc=$?
  [ "${rc}" -ne 0 ] && ok 'proxy refuses a seat of the pool' || bad 'proxy refuses a seat of the pool' "rc ${rc}"
  has   'and points at the pool'"'"'s block' "${out}" 'hdw4s pool proxy'
  hasnt 'and prints no block for the seat' "${out}" 'server {'
  out="$(pool_proxy)"
  hasnt 'the pool block does NOT point nginx at a seat socket' \
        "${out}" "proxy_pass http://unix:"
  hasnt 'and names no port'                "${out}" "HOST_RUNNING_HDW4S"
  hasnt 'and names no seat'                "${out}" "${me}"
  has 'and speaks of the pool, not our internals' "${out}" 'the pool chooses'
)

echo '== the slot table readers take the type as a third field =='
( set +e; sandbox; . "${SB}/setup.sh"
  printf '%s\n' '0 alice desktop' '3 _hdw4s_0 ephemeral' > "${SLOTS}"
  # The readers walk the table with "read -r idx inst _". Prove that shape is
  # required, by showing what a two-variable form does to a three-field row: it
  # does not drop the type, it appends it to the name, so the slot is indexed
  # under a session that does not exist.
  old_form="$(while read -r idx inst; do [ "${idx}" = '3' ] && echo "${inst}"; done < "${SLOTS}")"
  new_form="$(while read -r idx inst _; do [ "${idx}" = '3' ] && echo "${inst}"; done < "${SLOTS}")"
  is 'a two-variable reader corrupts the name' "${old_form}" '_hdw4s_0 ephemeral'
  is 'and the shape the readers use does not' "${new_form}" '_hdw4s_0'
  is 'the desktop row resolves to its unit'   "$(unit_of alice)" 'hdw4s@alice.service'
  is 'and the ephemeral one to its own'       "$(unit_of _hdw4s_0)" 'hdw4s-ephemeral@_hdw4s_0.service'
)

echo '== the relay names no session unit, and enable supplies one =='
( set +e
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
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/reap"
  printf '%s\n' '0 dora' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/session/dora" "${RUNDIR}/session/_hdw4s_0" "${REAPDIR}"

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
  printf '%s\n' "${back}" > "${REAPDIR}/_hdw4s_0"
  printf '%s\n' "${back}" > "${REAPDIR}/dora"
  out="$(cmd_reap 2>/dev/null)"
  is 'a session inside its window is left alone' "${out}" ''
  is 'and nothing was stopped'                   "$(wc -l < "${STOPPED}")" '0'

  # Now past the window, set per instance -- never on the site default, which
  # would move every session at once.
  printf 'HDW4S_IDLE_DAYS=1\n' > "${SB}/etc/_hdw4s_0.conf"
  out="$(cmd_reap 2>/dev/null)"
  has   'the ephemeral slot is now selected'  "${out}" 'stopping _hdw4s_0'
  has   'and its unit is the one stopped'     "$(cat "${STOPPED}")" 'hdw4s-ephemeral@_hdw4s_0.service'
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
  has 'and the ephemeral one still is too' "${out}" 'stopping _hdw4s_0'
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
  printf '%s\n' '0 dora' '1 _hdw4s_0 ephemeral' > "${SLOTS}"

  # The pool is told as one thing, so it is refused there -- and per seat it is
  # refused for every setting (the group on per-seat settings), so no seat can
  # be given a window the others do not have.
  ( pool_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && bad 'the pool may not be told never to reap' \
    || ok  'the pool may not be told never to reap'
  out="$( ( pool_set 'HDW4S_IDLE_DAYS=0' ) 2>&1 )"
  has 'and the refusal says what would happen' "${out}" '503'
  # The remedy has to be a command that works, not a sentence that reads well.
  has 'and names a longer window instead'      "${out}" 'hdw4s pool set HDW4S_IDLE_DAYS=30d'
  hasnt 'and nothing was written' "$(cat "$(pool_conf)" 2>/dev/null)" 'HDW4S_IDLE_DAYS=0'
  ( pool_set 'HDW4S_IDLE_DAYS=30d' ) >/dev/null 2>&1 \
    && ok  'and that command is accepted' \
    || bad 'and that command is accepted'
  has 'into the pool'"'"'s own file' "$(cat "$(pool_conf)")" 'HDW4S_IDLE_DAYS=30d'

  # The control, and it is the point of keying this on type rather than banning
  # the value: a named session may still be told never to stop.
  ( cmd_set 'dora' 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'a named session still may' \
    || bad 'a named session still may'

  # Machine-wide, the value reaches the pool too, so it is refused -- unless the
  # pool has a window of its own, which it reads after the machine's. Only on a
  # machine that HAS a pool: a check that fails on a correct state is one
  # somebody turns off.
  rm -f "$(pool_conf)"
  ( cmd_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && bad 'machine-wide is refused where there is a pool' \
    || ok  'machine-wide is refused where there is a pool'
  out="$( ( cmd_set 'HDW4S_IDLE_DAYS=0' ) 2>&1 )"
  has 'and says how to give the pool its own window' "${out}" 'hdw4s pool set HDW4S_IDLE_DAYS=1d'
  ( pool_set 'HDW4S_IDLE_DAYS=1d' ) >/dev/null 2>&1
  ( cmd_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'and accepted once the pool has its own' \
    || bad 'and accepted once the pool has its own'
  # The other side of the same rule: taking the pool's window away now would
  # hand it the machine's "never".
  ( pool_unset 'HDW4S_IDLE_DAYS' ) >/dev/null 2>&1 \
    && bad 'the pool'"'"'s window cannot then be unset' \
    || ok  'the pool'"'"'s window cannot then be unset'
  has 'and it is still there' "$(cat "$(pool_conf)")" $'\nHDW4S_IDLE_DAYS=1d'
  printf '%s\n' '0 dora' > "${SLOTS}"; : > "${CONF}"
  ( cmd_set 'HDW4S_IDLE_DAYS=0' ) >/dev/null 2>&1 \
    && ok  'and allowed where there is no pool' \
    || bad 'and allowed where there is no pool'
)

echo '== the reaper works in seconds, and refuses to guess =='
( set +e; sandbox; . "${SB}/setup.sh"
  unset JOURNAL_STREAM
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/reap"
  printf '%s\n' '0 dora' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/session/dora" "${RUNDIR}/session/_hdw4s_0" "${REAPDIR}"
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
  printf '%s\n' "${back}" > "${REAPDIR}/_hdw4s_0"
  printf 'HDW4S_IDLE_DAYS=30m\n' > "${SB}/etc/dora.conf"
  printf 'HDW4S_IDLE_DAYS=2h\n'  > "${SB}/etc/_hdw4s_0.conf"
  out="$(cmd_reap 2>/dev/null)"
  has   'a window shorter than a day fires'  "${out}" 'stopping dora'
  hasnt 'and one still inside it does not'   "${out}" 'stopping _hdw4s_0'
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
  rm -f "${SB}/etc/_hdw4s_0.conf"
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
  printf 'HDW4S_IDLE_DAYS=0\n' > "${SB}/etc/_hdw4s_0.conf"
  printf '%s\n' "$(( $(date +%s) - 864000 ))" > "${REAPDIR}/_hdw4s_0"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a slot set to 0 is not reaped'      "${out}" 'stopping _hdw4s_0'
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
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/reap"
  POOLDIR="${SB}/run/demux"
  printf '%s\n' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/session/_hdw4s_0" "${REAPDIR}" "${POOLDIR}/last-request"
  ss() { :; }
  STOPPED="${SB}/stopped"; : > "${STOPPED}"
  systemctl() {
    case "$1 ${3:-}" in
      'is-active ') echo 'active';;
      'show -p')    case "${4:-}" in MainPID) echo 4242;; *) echo '';; esac;;
      'stop '*)     printf '%s\n' "$2" >> "${STOPPED}";;
    esac
  }
  printf 'HDW4S_IDLE_DAYS=1h\n' > "${SB}/etc/_hdw4s_0.conf"
  now="$(date +%s)"
  stale="$(( now - 86400 ))"
  rstamp="${POOLDIR}/last-request/_hdw4s_0"

  # POSITIVE CONTROL FIRST. Without it every "not reaped" below is satisfied by
  # a reaper that no longer reaps anything, and the whole block would be green
  # on a pool that never frees a slot.
  printf '%s\n' "${stale}" > "${REAPDIR}/_hdw4s_0"
  rm -f "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'a stale slot with no router record is still reaped' "${out}" 'stopping _hdw4s_0'
  # Which is also the arm that matters when the router is DOWN: it contributes
  # nothing to the maximum, so the reaper falls back to its own sample rather
  # than treating silence as "nobody connected". Absence is no opinion.

  # THE FIX. Same stale sample, and a router that saw somebody a minute ago.
  : > "${STOPPED}"
  printf '%s\n' "${stale}" > "${REAPDIR}/_hdw4s_0"
  printf '%s\n' "$(( now - 60 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a request the poll missed keeps the desktop alive' "${out}" 'stopping _hdw4s_0'
  is    'and nothing was stopped' "$(wc -l < "${STOPPED}")" '0'

  # AND IT MAY ONLY EXTEND. An old router record against a fresh sample must not
  # pull the deadline forward: this witness is a reason to believe somebody was
  # here, never a reason to believe nobody was.
  : > "${STOPPED}"
  printf '%s\n' "$(( now - 60 ))" > "${REAPDIR}/_hdw4s_0"
  printf '%s\n' "${stale}" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'an old router record does not shorten a life' "${out}" 'stopping _hdw4s_0'

  # A record in the future is a fault, not an observation. Clamping it to now
  # would re-clamp on every later run and the slot would never reap again, with
  # no other symptom -- so it is dropped, and said out loud because a slot that
  # stops reaping has nothing else to trace it back to.
  : > "${STOPPED}"
  printf '%s\n' "${stale}" > "${REAPDIR}/_hdw4s_0"
  printf '%s\n' "$(( now + 86400 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'a router record in the future is ignored' "${out}" 'stopping _hdw4s_0'
  has 'and the reaper says so'                   "${out}" 'in the future'

  # Not a timestamp. Guessing at one on the destruction side is how a desktop
  # gets stopped on a number nobody wrote.
  : > "${STOPPED}"
  printf 'yesterday\n' > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'an unreadable router record is ignored' "${out}" 'stopping _hdw4s_0'
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
  has   'and the slot is reaped on the sample alone' "${out}" 'stopping _hdw4s_0'
  hasnt 'and nothing of what it pointed at is printed' "${out}" 'verysecret'
)

echo '== a pool desktop nobody opened is discarded after five minutes =='
# Minting costs one cookieless GET, so a tab closed during startup -- or a fetch
# of the front door that stops there -- used to hold a seat for the whole idle
# window. Both witnesses are judged against THIS desktop's start, because a
# seat's records survive from its previous visitor; the arms that use a record
# from before the start are the ones that pin that down.
( set +e; sandbox; . "${SB}/setup.sh"
  unset JOURNAL_STREAM
  RUNDIR="${SB}/run"; REAPDIR="${SB}/run/reap"
  POOLDIR="${SB}/run/demux"
  printf '%s\n' '1 _hdw4s_0 ephemeral' > "${SLOTS}"
  mkdir -p "${RUNDIR}/session/_hdw4s_0" "${REAPDIR}" "${POOLDIR}/last-request" \
           "${POOLDIR}/last-attach"
  now="$(date +%s)"
  START="$(( now - 600 ))"
  CLIENTS=0
  clients_of() { echo "${CLIENTS}"; }
  STOPPED="${SB}/stopped"
  systemctl() {
    case "$1 ${3:-}" in
      'is-active ') echo 'active';;
      'show -P')    echo "@${START}";;
      'stop '*)     printf '%s\n' "$2" >> "${STOPPED}";;
    esac
  }
  printf 'HDW4S_IDLE_DAYS=7d\n' > "${SB}/etc/_hdw4s_0.conf"
  rstamp="${POOLDIR}/last-attach/_hdw4s_0"
  lastreq="${POOLDIR}/last-request/_hdw4s_0"
  marker="${REAPDIR}/_hdw4s_0.attached"
  fresh() { : > "${STOPPED}"; rm -f "${rstamp}" "${lastreq}" "${marker}"
            printf '%s\n' "$(( now - 60 ))" > "${REAPDIR}/_hdw4s_0"; }

  # POSITIVE CONTROL: a fresh idle stamp, so the seven-day window alone would
  # keep it; only the new rule can stop it.
  fresh
  out="$(cmd_reap 2>/dev/null)"
  has 'a desktop nobody opened in ten minutes is stopped' "${out}" 'nobody has opened it'
  is  'its proxy and its desktop both' "$(wc -l < "${STOPPED}")" '2'

  fresh; printf '%s\n' "$(( START + 30 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a stream the router saw opened since the start keeps it' "${out}" 'stopping'

  # MEASURED on a development box: a tab given up during startup still leaves a request
  # record, because the router forwards the held request once the desktop
  # answers. A forwarded request is not an opened desktop.
  fresh; printf '%s\n' "$(( START + 30 ))" > "${lastreq}"
  out="$(cmd_reap 2>/dev/null)"
  has 'a forwarded page request alone does not' "${out}" 'nobody has opened it'

  fresh; printf '%s\n' "$(( START - 30 ))" > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  has 'the previous visitor'"'"'s stream does not' "${out}" 'nobody has opened it'

  fresh; printf '%s\n' "${START}" > "${marker}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a connection a sample saw in this start keeps it' "${out}" 'stopping'

  fresh; printf '%s\n' "$(( START - 9999 ))" > "${marker}"
  out="$(cmd_reap 2>/dev/null)"
  has 'one seen in an earlier start does not' "${out}" 'nobody has opened it'

  fresh; printf 'yesterday\n' > "${rstamp}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'an unusable attach record is no opinion' "${out}" 'nobody has opened it'

  fresh; CLIENTS=1
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a connected desktop is left alone' "${out}" 'stopping'
  is    'and the sample records the start it was seen in' "$(cat "${marker}" 2>/dev/null)" "${START}"
  CLIENTS=0

  fresh; START="$(( now - 120 ))"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'a desktop up for two minutes is left alone' "${out}" 'stopping'
  START="$(( now - 600 ))"

  fresh; START=''
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'an unknown start is no opinion' "${out}" 'stopping'
  START="$(( now - 600 ))"

  fresh; printf '%s\n' '1 _hdw4s_0 template' > "${SLOTS}"
  out="$(cmd_reap 2>/dev/null)"
  hasnt 'the template editor is not pool capacity' "${out}" 'nobody has opened it'
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

echo '== the arrival decision keeps its order =='
# WRITTEN BECAUSE NOTHING ASSERTED IT. A review of a proposed reconnect after a
# transport switch found that every safety property of arrival rests on the ORDER of a dozen lines in
# hdw4s-gate-index -- which markers are spent before anything connects, which paths
# connect unconditionally, and which one compares the desktop and waits for a hidden
# tab -- and that a change reordering them would turn nothing red. These pin the order
# as shipped. A deliberate reorder updates this list; an accidental one fails here.
#
# Checked on the GENERATED page, and the red arms below edit the generated page rather
# than the generator, so that they test this check and not the build-time guards,
# which refuse some of the same edits earlier and are tested in the next group.
#
# WHAT IT CANNOT SEE: whether the page behaves as its order says in a browser. It is a
# check on the text the browser is handed.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  "${ROOT}/hdw4s-gate-index" "${d}/in.html" "${d}/out.html" >/dev/null 2>&1
  order() { python3 - "$1" <<'PY'
import re, sys
h = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"go\.addEventListener\('click', boot\);(.*?)\n\}\)\(\);", h, re.S)
if not m:
    sys.exit(print("the arrival decision was not found"))
a = m.group(1)
steps = (
    ("the switch marker is spent first", "var switched = takeSwitch();"),
    ("EXPECT is read", "expected = sessionStorage.getItem(EXPECT)==='1';"),
    ("EXPECT is deleted before it is used", "sessionStorage.removeItem(EXPECT);"),
    ("EXPECT connects", "if (expected) return boot();"),
    ("the fresh cookie must name this desktop", "return c.trim() === want;"),
    ("the fresh cookie is deleted", "document.cookie = FRESH + '=; Path=/; Max-Age=0"),
    ("the fresh cookie connects", "announceFresh();\n        return boot();"),
    ("a viewer connects", "if (/^#(shared|player[2-4]|display2)/.test(location.hash)) "
                          "return boot();"),
    ("gate=off connects", "if (GATE === 'off') return boot();"),
    ("the resume branch opens", "if ((LOADED_HIDDEN || switched) && knownInc) {"),
    ("the incarnation is compared", "var same = !!served && served === knownInc;"),
    ("only the comparison connects", "if (same) return boot();"),
    ("a hidden tab waits", "if (!document.hidden) return decide();"),
    ("the card is what is left", "if (GATE === 'mint') return show(MINT, MINT_GO);\n"
                                 "  show(COLD, COLD_GO);"))
at = -1
for what, needle in steps:
    n = a.count(needle)
    if n != 1:
        sys.exit(print("%s: found %d times" % (what, n)))
    i = a.index(needle)
    if i < at:
        sys.exit(print("%s: out of order" % what))
    at = i
if not a.rstrip().endswith("show(COLD, COLD_GO);"):
    sys.exit(print("the card is what is left: something follows it"))
if a.count("return boot()") != 5:
    sys.exit(print("connecting paths: %d, want 5" % a.count("return boot()")))
s = h.index("var LOADED_HIDDEN = (document.visibilityState === 'hidden');") \
    if "var LOADED_HIDDEN = (document.visibilityState === 'hidden');" in h else -1
if s < 0 or s > h.index("var gate = document.getElementById('hdw4s-gate');"):
    sys.exit(print("whether anyone was looking is not read first"))
print("ok")
PY
  }
  # The positive control, on the page as shipped.
  is 'the shipped page decides arrival in the pinned order' "$(order "${d}/out.html")" 'ok'

  # Each red arm edits one line of a COPY of the generated page and must turn red.
  arm() { python3 - "${d}/out.html" "${d}/red.html" "$@" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read()
pairs = sys.argv[3:]
for old, new in zip(pairs[::2], pairs[1::2]):
    if s.count(old) != 1:
        sys.exit("red arm does not apply: %r found %d times" % (old, s.count(old)))
    s = s.replace(old, new)
open(sys.argv[2], "w", encoding="utf-8").write(s)
PY
  }
  # Red for the RIGHT reason: the check must name the step the arm broke, so an arm
  # that went red because the section could not be found does not count.
  redorder() { arm "${@:3}" 2>"${d}/armerr" \
                 && r="$(order "${d}/red.html")" \
                 || r="the arm did not apply: $(cat "${d}/armerr")"
               case "${r}" in
                 ok) bad "$1" 'the check stayed green' ;;
                 *'the arm did not apply'*) bad "$1" "${r}" ;;
                 *) has "$1" "${r}" "$2" ;;
               esac; }

  # EXPECT deleted only after it is honoured: the product's own one-shot reload would
  # stay armed for the next F5, which is the steal the owner found.
  redorder 'EXPECT consumed after it connects is caught' \
    'EXPECT connects: out of order' \
    "    sessionStorage.removeItem(EXPECT);
" '' \
    'if (expected) return boot();' \
    'if (expected) return boot();
  try { sessionStorage.removeItem(EXPECT); } catch(e){}'
  # The fresh cookie never deleted: a one-shot becomes a standing permission.
  redorder 'a fresh cookie that is never deleted is caught' \
    'the fresh cookie is deleted: found 0 times' \
    "document.cookie = FRESH + '=; Path=/; Max-Age=0; SameSite=Lax; Secure';" ''
  # A viewer's unconditional boot moved below the resume branch.
  redorder 'a viewer decided after the resume branch is caught' \
    'gate=off connects: out of order' \
    "  if (/^#(shared|player[2-4]|display2)/.test(location.hash)) return boot();
" '' \
    "  if (GATE === 'mint') return show(MINT, MINT_GO);" \
    "  if (/^#(shared|player[2-4]|display2)/.test(location.hash)) return boot();
  if (GATE === 'mint') return show(MINT, MINT_GO);"
  # A hidden tab that no longer waits to be seen.
  redorder 'a resume that does not wait for a hidden tab is caught' \
    'a hidden tab waits: found 0 times' \
    'if (!document.hidden) return decide();' 'return decide();'
  # A resume that no longer compares the desktop.
  redorder 'a resume that does not compare the incarnation is caught' \
    'the incarnation is compared: found 0 times' \
    'var same = !!served && served === knownInc;' 'var same = !!served;'
  # The switch marker spent only after an earlier exit.
  redorder 'a switch marker spent after a connecting path is caught' \
    'EXPECT is read: out of order' \
    '  var switched = takeSwitch();
' '' \
    'if (expected) return boot();' \
    'if (expected) return boot();
  var switched = takeSwitch();'
  # A sixth way to connect.
  redorder 'an extra unconditional connect is caught' \
    'connecting paths: 6, want 5' \
    "  if (GATE === 'off') return boot();" \
    "  if (GATE === 'off') return boot();
  if (knownInc) return boot();"
)

echo '== a transport switch may skip one arrival check and no other =='
# THE FEATURE: switching between WebRTC and websockets in the client's side menu makes
# upstream reload the page two seconds later, and that reload used to meet the card.
# hdw4s-gate-index now lets that one reload through the resume branch, in place of
# "nobody was looking" and nothing else. A review found the obvious version (arm EXPECT
# on the switch message) unsafe and named the shape a safe one must keep; the generator
# refuses a page that loses it, and these are that refusal seen to happen.
#
# Each arm edits a COPY of the generator INSIDE ITS PAGE TEMPLATE ONLY. The guards name
# the very lines they require, so an edit across the whole file rewrites the guard's
# needle along with the page and the two agree about the wrong thing -- the trap the
# lifetime guard's arms above fell into first.
#
# AND THE UPSTREAM HALF: the generator looks in the client beside the index for the
# handler that reloads after a switch. Not finding it is NOT a refusal -- it builds the
# page that shipped before this feature, where a switch costs a click -- and says so.
(
  d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  printf '%s' '<html><body><script type="module" src="./x.js"></script></body></html>' \
    > "${d}/in.html"
  # The client's shape, from upstream's own source: the entry loads the core as a
  # chunk, and the core reloads two seconds after a {type:"mode"} message.
  printf '%s\n' 'await import("./core.js");' > "${d}/x.js"
  cat > "${d}/core.src" <<'JS'
function handleMessage(event) {
    if (event.origin !== window.location.origin) return;
    let message = event.data;
    if (message.mode !== undefined && message.type === "mode") {
        if (![STREAM_MODE_WEBRTC, STREAM_MODE_WEBSOCKETS].includes(message.mode)) return;
        console.log(`Switching streaming mode to: ${message.mode}`);
        safeSetItem(getPrefixedKey('stream_mode'), message.mode);

        setTimeout(() => {
            window.location.reload();
        }, 2000)
    }
}
window.addEventListener("message", handleMessage)
JS
  cp "${d}/core.src" "${d}/core.js"
  gen() { python3 "${1:-${ROOT}/hdw4s-gate-index}" "${d}/in.html" "${d}/out.html" \
            >"${d}/stdout" 2>"${d}/err"; }

  # The positive control FIRST: with upstream's handler present the page is armed and
  # the build says where it looked.
  rm -f "${d}/out.html"
  gen && has 'the switch is armed when upstream reloads after it' \
           "$(cat "${d}/out.html")" 'var SWITCH_UPSTREAM = true;' \
      || bad 'the switch is armed when upstream reloads after it' "$(cat "${d}/err")"
  has 'and the build names the file it found the reload in' "$(cat "${d}/stdout")" 'core.js'

  # The same handler as the bundler writes it, which is what is actually installed.
  # The ${...} in it is JavaScript's, so it must stay unexpanded.
  # shellcheck disable=SC2016
  printf '%s' 'function In(e){if(e.origin!==window.location.origin)return;let t=e.data;if(t.mode!==void 0&&t.type===`mode`){if(![On,kn].includes(t.mode))return;console.log(`Switching streaming mode to: ${t.mode}`),Nn(Mn(`stream_mode`),t.mode),setTimeout(()=>{window.location.reload()},2e3)}}typeof window<`u`&&(window.addEventListener(`message`,In))' \
    > "${d}/core.js"
  gen && has 'and it is found in the minified bundle' \
           "$(cat "${d}/out.html")" 'var SWITCH_UPSTREAM = true;' \
      || bad 'and it is found in the minified bundle' "$(cat "${d}/err")"

  # Upstream stops reloading: the page builds, unarmed, and says so.
  sed 's|window.location.reload();|/* in place now */|' "${d}/core.src" > "${d}/core.js"
  gen && has 'an upstream that no longer reloads leaves the switch unarmed' \
           "$(cat "${d}/out.html")" 'var SWITCH_UPSTREAM = false;' \
      || bad 'an upstream that no longer reloads leaves the switch unarmed' \
           "the build refused: $(cat "${d}/err")"
  has 'and the build says the card is back' "$(cat "${d}/err")" 'will show the card again'
  # Upstream reloads too late for the marker to be alive.
  sed 's|}, 2000)|}, 20000)|' "${d}/core.src" > "${d}/core.js"
  gen; has 'an upstream that reloads too late leaves the switch unarmed' \
         "$(cat "${d}/out.html")" 'var SWITCH_UPSTREAM = false;'
  # Upstream no longer listens for window messages at all.
  sed 's|window.addEventListener("message", handleMessage)||' "${d}/core.src" \
    > "${d}/core.js"
  gen; has 'an upstream that no longer listens leaves the switch unarmed' \
         "$(cat "${d}/out.html")" 'var SWITCH_UPSTREAM = false;'
  cp "${d}/core.src" "${d}/core.js"

  # Our own half: each arm must be REFUSED, write no page, and say why.
  tarm() { python3 - "${ROOT}/hdw4s-gate-index" "${d}/red" "$@" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read()
a = s.index('OVERLAY = r"""'); b = s.index('__NAMES__"""', a)
t = s[a:b]
pairs = sys.argv[3:]
for old, new in zip(pairs[::2], pairs[1::2]):
    if t.count(old) != 1:
        sys.exit("red arm does not apply: %r found %d times in the template"
                 % (old, t.count(old)))
    t = t.replace(old, new)
open(sys.argv[2], "w", encoding="utf-8").write(s[:a] + t + s[b:])
PY
  }
  refused() { rm -f "${d}/out.html"
              if ! tarm "${@:3}" 2>"${d}/armerr"; then
                bad "$1" "the arm did not apply: $(cat "${d}/armerr")"; return; fi
              if gen "${d}/red"; then bad "$1" 'it was accepted'; return; fi
              if [ -e "${d}/out.html" ]; then bad "$1" 'a refused build wrote a page'
              else has "$1" "$(cat "${d}/err")" "$2"; fi; }

  # The review's unsafe shape: the marker connects before anything is checked.
  refused 'a switch marker that connects unconditionally is refused' \
    'consulted somewhere other than the resume' \
    'if (expected) return boot();' 'if (switched || expected) return boot();'
  refused 'a resume branch that stops comparing the desktop is refused' \
    'no longer compares the served desktop' \
    'var same = !!served && served === knownInc;' 'var same = !!served;'
  refused 'a resume branch that stops waiting for a hidden tab is refused' \
    'no longer waits while the tab is hidden' \
    'if (!document.hidden) return decide();' 'return decide();'
  refused 'a marker taken after a connecting path is refused' \
    'taken after a path that connects' \
    '  var switched = takeSwitch();
' '' \
    'if (expected) return boot();' 'if (expected) return boot();
  var switched = takeSwitch();'
  refused 'a marker that is not deleted on read is refused' \
    'no longer checks removeItem(SWITCH)' \
    '      sessionStorage.removeItem(SWITCH);
' ''
  refused 'a marker without its own clock is refused' \
    'no longer checks age <= SWITCH_TTL' \
    ' && age <= SWITCH_TTL' ''
  refused 'a marker written for a message from another window is refused' \
    'event.source !== window' \
    ' || event.source !== window' ''
  refused 'a marker written for a page whose card is up is refused' \
    '!gate.hidden' \
    'if (SECONDARY || !booted || !gate.hidden) return;' \
    'if (SECONDARY || !booted) return;'
  refused 'a marker kept outside sessionStorage is refused' \
    'not to sessionStorage' \
    'sessionStorage.setItem(SWITCH' 'localStorage.setItem(SWITCH'
  # And the guard cannot pass by failing to find what it checks.
  refused 'a marker reader the guard cannot find is refused' \
    'could not be found' \
    'function takeSwitch(){' 'function takeSwitchNow(){' \
    'var switched = takeSwitch();' 'var switched = takeSwitchNow();'
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
    ( HDW4S_EPHEMERAL_SLOTS=20 SEAT_PREFIX=_hdw4s_ HDW4S_EPHEMERAL_UID_BASE=900 ETCDIR=/nonexistent
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
  # THE BUILD LOCK IS ROOT'S ALONE: it sits where every account can read, and
  # flock needs only a descriptor, so a readable one stalls every later build.
  is 'the web root build lock is 0600' "$(stat -c %a "${d}/web/.hdw4s-webroot.lock")" '600'
  is 'a named desktop'"'"'s app is named after it' \
    "$(field "${d}/web/named1/manifest.json" name)" 'Desktop|Desktop'

  page app.webmanifest
  run provision named2 || bad 'a named desktop provisions' "$(cat "${d}/err")"
  is 'and so is the manifest its page LINKS, whatever it is called' \
    "$(field "${d}/web/named2/app.webmanifest" name)" 'Desktop|Desktop'
  is 'and the packaged one beside it' \
    "$(field "${d}/web/named2/manifest.json" name)" 'Desktop|Desktop'
  run build --directory _hdw4s_0 "${d}/web/_hdw4s_0" Desktop \
    || bad 'a pool slot builds' "$(cat "${d}/err")"
  is 'a pool desktop'"'"'s app too' \
    "$(field "${d}/web/_hdw4s_0/app.webmanifest" name)" 'Desktop|Desktop'
  is 'and its icon is upstream'"'"'s, untouched' \
    "$(field "${d}/web/_hdw4s_0/app.webmanifest" icons)" \
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
  mkdir -p "${d}/web/_hdw4s_0"
  printf '<html><head><link rel="apple-touch-icon" href="big.png"><link rel="icon" type="image/png" href="icon.png" /></head></html>' \
    > "${d}/web/_hdw4s_0/index.html"
  printf 'the-small-icon' > "${d}/web/_hdw4s_0/icon.png"
  printf 'the-big-icon' > "${d}/web/_hdw4s_0/big.png"
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
  # Each directory as the minter itself resolves it, with nothing in the
  # environment: its own assignment lines, evaluated in order. A default may be
  # derived from another (everything under RUNDIR), so reading the literal after
  # ":-" would find "${RUNDIR}/proxy", which names nothing.
  # shellcheck disable=SC2016  # expanded by the inner shell, not here
  created="$(env -i bash -c '
    eval "$(grep -E "^[A-Z_]+=\"[$][{]HDW4S_[A-Z_]+:-.*[}]\"$" "$1")"
    for v in $(grep -hE "^install -d" "$1" | grep -oE "[{][A-Z0-9_]+[}]" | tr -d "{}"); do
      eval "printf \"%s\\n\" \"\${${v}}\""
    done' _ "${minter}")"
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
  printf '%s\n' '0 _hdw4s_0 ephemeral' '1 alice' '2 bob' > "${SLOTS}"

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
  printf 'HDW4S_TRANSPORT=unix\n' > "${ETCDIR}/_hdw4s_0.conf"
  out="$( ( cmd_auth _hdw4s_0 ) 2>&1 )"; rc=$?
  is 'a session on a filesystem socket may not' "${rc}" '1'
  has 'and is told why the secret would keep nobody out' \
      "${out}" 'nothing can present a credential to it'
  # The assertion this replaced required the message to contain
  # "hdw4s transport _hdw4s_0 tcp" -- a command this same suite asserts exits 1 for
  # an ephemeral slot, about 470 lines above. Two green groups jointly
  # certifying a dead end: the tool printed an instruction it refuses to obey,
  # and the tests held it in place. The refusal must offer no remedy it will
  # then refuse.
  hasnt 'and offers no remedy the tool itself refuses' \
        "${out}" 'hdw4s transport _hdw4s_0 tcp'
  has 'and says a named desktop is a different case' \
      "${out}" 'A named desktop is a different thing'
  # A refusal, not a diagnostic printed on the way through. This is the whole
  # defect: the message would have been fine, the written line is what 401s.
  hasnt 'and nothing was written to its file' \
        "$(cat "${ETCDIR}/_hdw4s_0.conf")" 'HDW4S_AUTH'

  # THE ARM THAT SEPARATES THE TWO REASONS. Above, _hdw4s_0 is BOTH ephemeral and on
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
  rm -f "${ETCDIR}/_hdw4s_0.conf"
  out="$( ( cmd_auth _hdw4s_0 ) 2>&1 )"; rc=$?
  is 'CONTROL: the ephemeral slot still refuses under that same default' "${rc}" '1'
)

echo '== a running session that publishes no identity is a failure, not a quiet pass =='
( set +e; sandbox; . "${SB}/setup.sh"
  # Written from the failure, measured on the test container on 2026-09-22:
  # ephemeral2 was active with no token in its web root and none recorded under
  # /run/hdw4s/incarnation, while ephemeral0 and ephemeral1 had both. The wiring
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
  HDW4S_INCARNATION_DIR="${SB}/run/incarnation"
  HDW4S_WEBROOT_DIR="${SB}/webroot"
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}/_hdw4s_0" \
           "${HDW4S_WEBROOT_DIR}/_hdw4s_1" "${HDW4S_WEBROOT_DIR}/alice"
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
  printf '%s\n' '0 _hdw4s_0 ephemeral' '1 _hdw4s_1 ephemeral' '2 alice desktop' > "${SLOTS}"

  # THE POOL AROUND THE SESSIONS, stood in for so this group can go on being
  # about incarnation tokens. "hdw4s check" now asks first whether the machine
  # can hand out a desktop at all, and a sandbox has no listening doors -- so
  # without these stubs every assertion below would be red for a reason that has
  # nothing to do with what it is testing. Each stand-in is named here because a
  # constant in a comparison is a claim: the doors, the front-door port and the
  # failed-unit list are ASSUMED sound in this group and are exercised, in both
  # directions, in the group that follows.
  STUB_DOORS="${RUNDIR}/proxy/_hdw4s_0.sock ${RUNDIR}/proxy/_hdw4s_1.sock"
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
  printf '%s\n' 'aaaa' > "${HDW4S_WEBROOT_DIR}/_hdw4s_0/hdw4s-incarnation"
  printf '%s\n' 'aaaa' > "${HDW4S_INCARNATION_DIR}/_hdw4s_0"
  printf '%s\n' 'bbbb' > "${HDW4S_WEBROOT_DIR}/_hdw4s_1/hdw4s-incarnation"
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
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
  mkdir -p "${RUNDIR}/session/alice"
  printf '%s\n' 'it names ClientSession 3 time(s), not 2' \
    > "${RUNDIR}/session/alice/webrtc-degraded"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a desktop that degraded to websockets FAILS the check' "${rc}" '1'
  has 'and is named'                        "${out}" 'alice is running WITHOUT WebRTC'
  has 'and carries the reason it was given' "${out}" 'ClientSession 3 time(s)'
  # Its own count, because it is not the token arm's failure and the same
  # session can fail both: one counter would report two failures of one session.
  has 'and has its own summary' "${out}" '1 of 3 running session(s) started without the WebRTC'
  hasnt 'and is not counted as a token failure' "${out}" 'failed this check'
  rm -f "${RUNDIR}/session/alice/webrtc-degraded"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'and passes again once it has WebRTC' "${rc}" '0'

  # The defect itself: a live slot publishing nothing.
  rm -f "${HDW4S_WEBROOT_DIR}/_hdw4s_1/hdw4s-incarnation" "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is    'a live slot with no token fails'   "${rc}" '1'
  has   'and the message names the slot'    "${out}" '_hdw4s_1 is running and publishes no incarnation token'
  has   'and names the repair'              "${out}" 'systemctl restart hdw4s-ephemeral@_hdw4s_1.service'
  hasnt 'and does not accuse the sound one' "${out}" '_hdw4s_0 is running and publishes'
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
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a missing served token fails on its own' "${rc}" '1'
  has 'and is named as the published half'      "${out}" 'publishes no incarnation token'

  # An empty file is not a token, and is the shape a truncating write leaves
  # behind for as long as it takes to finish.
  : > "${HDW4S_WEBROOT_DIR}/_hdw4s_1/hdw4s-incarnation"
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is 'an empty published file is not a token' "${rc}" '1'

  # Serving a value nobody recorded is its own failure: it is what a slot looks
  # like when the previous session's token was left in a rebuilt web root.
  printf '%s\n' 'bbbb' > "${HDW4S_WEBROOT_DIR}/_hdw4s_1/hdw4s-incarnation"
  rm -f "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a served token this start did not record fails' "${rc}" '1'
  has 'and says which half is missing' "${out}" 'recorded no incarnation token'

  # And a mismatch, which is the same bug one step further along: the tab is
  # told this is the desktop it had, and it is not.
  printf '%s\n' 'cccc' > "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a token that does not match the record fails' "${rc}" '1'
  has 'and says so in those terms' "${out}" 'did not publish'

  # A slot that is not running is not this command's business: it publishes
  # nothing because nothing is there to publish, and reporting it would bury
  # the one row that matters.
  printf '%s\n' 'bbbb' > "${HDW4S_INCARNATION_DIR}/_hdw4s_1"
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
  HDW4S_INCARNATION_DIR="${SB}/run/incarnation"
  HDW4S_WEBROOT_DIR="${SB}/webroot"
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}"
  export HDW4S_ETCDIR HDW4S_RUNDIR="${RUNDIR}" HDW4S_INCARNATION_DIR HDW4S_WEBROOT_DIR
  # shellcheck source=/dev/null
  . "${SB}/lib.sh" 2>/dev/null || :
  # The root namespace's /shared, which "hdw4s check" asks the minter about:
  # the sandbox's, never the machine's (as sandbox() sets it). Without these,
  # on a machine with /shared, check compared the real bind with a sandbox
  # path and called it foreign (seen as root on a dev box, 2026-10-04).
  export HDW4S_SHARED_MARK="${SB}/shared-mark" HDW4S_SHARED_MOUNTPOINT="${SB}/shared-point" \
         HDW4S_SHARED_VIEW_STATE="${SB}/shared-view"
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  SLOTS="${HDW4S_ETCDIR}/instances"; RUNDIR="${SB}/run"
  printf '%s\n' '0 _hdw4s_0 ephemeral' '1 _hdw4s_1 ephemeral' > "${SLOTS}"

  STUB_DOORS="${RUNDIR}/proxy/_hdw4s_0.sock ${RUNDIR}/proxy/_hdw4s_1.sock"
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
  STUB_DOORS="${RUNDIR}/proxy/_hdw4s_0.sock"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'one slot with no listener fails'  "${rc}" '1'
  has 'and names WHICH slot'             "${out}" 'Not listening: _hdw4s_1'
  STUB_DOORS="${RUNDIR}/proxy/_hdw4s_0.sock ${RUNDIR}/proxy/_hdw4s_1.sock"

  # The front door. Asked of the kernel, not of systemd: a socket unit can be
  # active while nothing is bound.
  STUB_PORT=''
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a front door with no address fails' "${rc}" '1'
  has 'and says which door'                "${out}" 'front door has no listening address'
  STUB_PORT='7280'

  # A latched unit. This is the shape the pool fails into when a relay's start
  # limit fires, and it stays that way until somebody clears it.
  STUB_FAILED='hdw4s-ephemeral@_hdw4s_0.service failed failed'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a latched pool unit fails the check' "${rc}" '1'
  has 'and names the unit'                  "${out}" 'hdw4s-ephemeral@_hdw4s_0.service'
  has 'and names the repair'                "${out}" 'reset-failed'
  STUB_FAILED=''

  # The identities the slots run as. Without them User= does not resolve and
  # every start dies 217/USER, naming nothing anybody would search for.
  STUB_SLOTS='inactive'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'unminted slot identities fail' "${rc}" '1'
  has 'and say what breaks'           "${out}" '217/USER'
  STUB_SLOTS='active'

  # A TABLE OFFERING A ROW THAT IS NOT A SEAT. Everything else about the pool
  # is sound here -- doors listening, the minter active -- so the only thing
  # this arm can be red about is the name.
  printf '%s\n' '0 ephemeral0 ephemeral' '1 _hdw4s_1 ephemeral' > "${SLOTS}"
  STUB_DOORS="${RUNDIR}/proxy/ephemeral0.sock ${RUNDIR}/proxy/_hdw4s_1.sock"
  HDW4S_EPHEMERAL_SLOTS=2
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a row that is not a seat fails the check' "${rc}" '1'
  has 'and names it' "${out}" 'rows the minter never mints: ephemeral0'
  hasnt 'and not the seat beside it' "$(printf '%s\n' "${out}" | grep 'never mints')" '_hdw4s_1'
  has 'and the repair, at the configured size' "${out}" 'hdw4s pool size 2'
  printf '%s\n' '0 _hdw4s_0 ephemeral' '1 _hdw4s_1 ephemeral' > "${SLOTS}"
  STUB_DOORS="${RUNDIR}/proxy/_hdw4s_0.sock ${RUNDIR}/proxy/_hdw4s_1.sock"

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
  export HDW4S_WEBROOT_DIR="${SB}/webroot"; mkdir -p "${HDW4S_WEBROOT_DIR}/alice"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a box with no ephemeral slots passes' "${rc}" '0'
  has 'and says there is no pool'            "${out}" 'no ephemeral slots configured'

  # The same box, with alice's web root gone: her next start would fail the
  # gate, though nothing is running and nothing has failed yet. The pass just
  # above is this arm's control.
  rmdir "${HDW4S_WEBROOT_DIR}/alice"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a named desktop with no web root fails the check' "${rc}" '1'
  has 'and names the repair' "${out}" 'hdw4s enable alice'
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
  real_window="${window}"
  window='10'
  [ "${window}" -ge "${need}" ] \
    && bad 'CONTROL: the default ten-second window is rejected' 'it passed' \
    || ok  'CONTROL: the default ten-second window is rejected'
  window="${real_window}"

  # AND THE OTHER END, since 2026-10-03: ORDINARY USE MUST NOT REACH IT. The
  # limit counts start-job DISPATCHES, not visible starts -- measured on systemd
  # 255, 2 charges per logout and revisit, 3 while a logout was a failure that
  # restarted. Five in twenty minutes therefore latched the owner out of his own
  # desktop after two logouts. The hidden term is the larger measured figure,
  # as margin; six logouts is the number the unit's real-unit arm drives.
  charges_per_logout=3; logouts=6
  ordinary=$(( 1 + logouts * charges_per_logout ))
  [ "${ordinary}" -lt "${burst}" ] \
    && ok "six logouts and revisits do not reach it (${ordinary} charges < ${burst})" \
    || bad 'six logouts and revisits do not reach it' \
           "${ordinary} charges reach a burst of ${burst}: ordinary use latches the desktop"
  # The failure ledger must refuse before the fuse trips, or the page that names
  # the latch is never the one shown: each failed run costs up to 3 charges
  # (dispatch, entering auto-restart, the restart).
  threshold="$(sed -n 's/^THRESHOLD=\([0-9]*\)$/\1/p' "${ROOT}/hdw4s-ledger")"
  [ -n "${threshold}" ] && [ $(( threshold * 3 + 1 )) -lt "${burst}" ] \
    && ok "the ledger refuses before the fuse trips ($(( threshold * 3 + 1 )) < ${burst})" \
    || bad 'the ledger refuses before the fuse trips' "threshold [${threshold}] burst [${burst}]"
  # RED ARM: the numbers that latched the owner out.
  burst=5
  [ "${ordinary}" -lt "${burst}" ] \
    && bad 'CONTROL: the 5-in-20-minutes limit that latched the owner is rejected' 'it passed' \
    || ok  'CONTROL: the 5-in-20-minutes limit that latched the owner is rejected'
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
# values come from the environment and from /proc. "09" is the quiet one: it passes a digits-only
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

echo '== a logout ends a desktop cleanly, of either kind, and anything else is still a failure =='
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
  # A NAMED DESKTOP TOO, since 2026-10-03. It used to exit 1 on purpose so that
  # Restart=on-failure would hand its owner a fresh desktop; the start limit
  # counted every one of those, and two logouts latched the owner out of his own
  # desktop. A logout now ends it, and the next visit starts it.
  is 'a named desktop logged out of ends with success, and is not restarted' \
     "$(ended '' 'exit 0')" '0'
  is 'a named desktop whose GNOME failed still fails'   "$(ended '' 'exit 1')" '1'
  # shellcheck disable=SC2016 # expanded by the stand-in's own shell, on purpose
  is 'a named desktop whose GNOME was killed still fails' \
     "$(ended '' 'kill -KILL $BASHPID')" '1'
  # RED ARM: an exit decision that says "success" for everything must be caught
  # by the assertion above -- the cheap wrong repair for the lockout.
  red="${fn//exit 1/exit 0}"
  if [ "${red}" = "${fn}" ]; then
    bad 'the logout red arm mutates the exit decision' 'nothing was replaced'
  else
    redrc="$(HDW4S_SESSION_TYPE='' bash -c "set -eu; ${red}
      exit 1 & session_pid=\$!; sleep 0.2; gnome_exited" >/dev/null 2>&1; echo "$?")"
    is 'RED ARM: an exit decision that always succeeds would be caught' "${redrc}" '0'
  fi
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
      'show -p ActiveState --value '*)
        printf '%s\n' "${STUB_STATE}"
        # Where the in-progress marker is while the script is at work: every
        # file under the stand-in's /run, as the script's first question sees it.
        # shellcheck disable=SC2153  # STUB_RUN is set per call, by teardown_in
        (cd "${STUB_RUN}" && find . -type f | sort) > "${STUB_SEEN}";;
    esac
  }
  export -f systemctl
  # One run of the script against a fresh stand-in, in STATE. Prints what it said.
  teardown_in() {
    rm -rf "${d}/run" "${d}/cg"; : > "${d}/log"
    mkdir -p "${d}/run/req" "${d}/cg/hdw4s-_hdw4s_0.slice"
    echo 999999999 > "${d}/cg/hdw4s-_hdw4s_0.slice/cgroup.procs"
    : > "${d}/cg/hdw4s-_hdw4s_0.slice/cgroup.kill"
    : > "${d}/run/req/_hdw4s_0"
    STUB_LOG="${d}/log" STUB_STATE="$1" STUB_RUN="${d}/run" STUB_SEEN="${d}/seen" \
      HDW4S_TEARDOWN_DIR="${d}/run/req" HDW4S_ENDING_DIR="${d}/run/ending" \
      HDW4S_SESSION_CGROUP_ROOT="${d}/cg" \
      bash "${2:-${ROOT}/hdw4s-teardown}" _hdw4s_0 2>&1
  }
  killed() { cat "${d}/cg/hdw4s-_hdw4s_0.slice/cgroup.kill"; }

  # THE CONTROL FIRST: an active desktop is ended, so the rig can see an ending.
  out="$(teardown_in active)"
  is 'an active desktop is ended through its own cgroup' "$(killed)" '1'
  has 'and its unit is stopped' "$(cat "${d}/log")" 'stop hdw4s-ephemeral@_hdw4s_0.service'

  # THE DEFECT: an activating desktop is ended too.
  out="$(teardown_in activating)"
  hasnt 'an activating desktop is not "nothing to end"' "${out}" 'nothing to end'
  is 'an activating desktop is ended through its own cgroup' "$(killed)" '1'
  has 'and its start is cancelled by a stop' "$(cat "${d}/log")" 'stop hdw4s-ephemeral@_hdw4s_0.service'

  # THE PERMIT ARM: a unit that is not running is not killed, but any start still
  # queued for it is replaced by a stop.
  out="$(teardown_in inactive)"
  has 'an inactive desktop is nothing to end' "${out}" 'nothing to end'
  is 'and nothing is killed' "$(killed)" ''
  has 'but a pending start is still cancelled' "$(cat "${d}/log")" 'stop --no-block hdw4s-ephemeral@_hdw4s_0.service'

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

  # THE IN-PROGRESS MARKER IS ROOT'S, OUT OF THE FRONT DOOR'S REACH. The request
  # directory is writable by the router's group, so a marker kept inside it could
  # be removed, planted or replaced by the process that reads it. Asserted from
  # what the script actually did -- the files present when it first asked about
  # the unit -- not from its text.
  teardown_in active >/dev/null
  is 'while a teardown runs, its marker is in the marker directory and nowhere else' \
     "$(tr '\n' ' ' < "${d}/seen")" './ending/_hdw4s_0 '
  is 'and it is gone when the teardown ends' \
     "$(cd "${d}/run" && find . -type f | tr '\n' ' ')" ''
  # RED ARM: the marker put back inside the request directory must be seen.
  # shellcheck disable=SC2016  # the script's own text, not an expansion here
  sed 's|^ENDDIR=.*|ENDDIR="${REQDIR}/ending"|' "${ROOT}/hdw4s-teardown" > "${d}/red"
  if cmp -s "${ROOT}/hdw4s-teardown" "${d}/red"; then
    bad 'the marker red arm mutates the teardown' 'the sed matched nothing'
  else
    teardown_in active "${d}/red" >/dev/null
    is 'RED ARM: a marker inside the request directory is caught' \
       "$(tr '\n' ' ' < "${d}/seen")" './req/ending/_hdw4s_0 '
  fi

  # "ending" IS AN ORDINARY NAME NOW. It was reserved while the markers lived in
  # "<requests>/ending"; with them in a directory of their own a request by that
  # name is handled like any other (the pool, whose seats are _hdw4s_N, never
  # makes one) and leaves the marker directory, and the markers in it, alone.
  rm -rf "${d}/run"; mkdir -p "${d}/run/req" "${d}/run/ending"
  : > "${d}/run/req/ending"; : > "${d}/run/ending/_hdw4s_1"; : > "${d}/log"
  STUB_LOG="${d}/log" STUB_STATE=inactive STUB_RUN="${d}/run" STUB_SEEN="${d}/seen" \
    HDW4S_TEARDOWN_DIR="${d}/run/req" HDW4S_ENDING_DIR="${d}/run/ending" \
    HDW4S_SESSION_CGROUP_ROOT="${d}/cg" bash "${ROOT}/hdw4s-teardown" ending >/dev/null 2>&1
  is 'a request named "ending" is an ordinary one, and the marker directory is untouched' \
     "$(cd "${d}/run" && find . | sort | tr '\n' ' ')" '. ./ending ./ending/_hdw4s_1 ./req '
)

echo "== root's lock files can be opened by root alone =="
# flock(2) needs only a descriptor, and a descriptor only read permission. So a
# lock file in /run that anybody can read is one any account -- a desktop's
# occupant included -- can hold for ever, stalling whatever root wanted it for:
# for the firewall, the 15-minute self-heal. Each lock is taken by the real code
# that takes it, against a path in a scratch directory, and its mode is read.
( set +e; d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  # The firewall: its own take_lock(), with the dispatcher cut off.
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s-firewall" > "${d}/fw.sh"
  fw_lock() {  # take the lock in a scratch path, in a subshell; print its mode
    # shellcheck disable=SC1090  # a copy of hdw4s-firewall, made just above
    ( HDW4S_ETCDIR="${d}/etc"; . "$1" >/dev/null 2>&1; trap - EXIT ERR
      LOCK="${d}/run/firewall.lock"; take_lock; stat -c %a "${LOCK}" )
  }
  is 'the firewall lock is 0600' "$(fw_lock "${d}/fw.sh")" '600'
  rm -rf "${d}/run"
  # RED ARM: without the umask the lock comes out as the umask leaves it,
  # which is what shipped.
  sed -e '/^  umask 077$/d' "${d}/fw.sh" > "${d}/fw-red.sh"
  if cmp -s "${d}/fw.sh" "${d}/fw-red.sh"; then
    bad 'the firewall red arm mutates take_lock' 'the sed matched nothing'
  else
    (umask 022; is 'RED ARM: a lock taken without it is caught' \
       "$(fw_lock "${d}/fw-red.sh")" '644')
  fi
  # The template tool's lock, through its own take_lock().
  mode="$(HDW4S_ETCDIR="${d}/etc" python3 - "${ROOT}/hdw4s-template" "${d}/template.lock" 2>&1 <<'PY'
import importlib.machinery, importlib.util, os, sys
loader = importlib.machinery.SourceFileLoader("tmpl", sys.argv[1])
spec = importlib.util.spec_from_loader("tmpl", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
m.LOCK = sys.argv[2]
m.take_lock()
print("%o" % (os.stat(m.LOCK).st_mode & 0o7777))
PY
)"
  is 'the template lock is 0600' "${mode}" '600'
)

echo '== every runtime file is under /run/hdw4s, and nothing names the old places =='
# ONE DIRECTORY, /run/hdw4s: each desktop's own runtime directory at
# session/<instance> and everything else a sibling of "session", never of the
# sessions -- their names are account names, so an account called "proxy" would
# otherwise BE root's front-door directory. Read over every file that ships
# (the changelog excepted: it is history), so that a path put back by a later
# edit, a merge or a copied line is caught here rather than on a box.
( set +e; d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
  # What ships: the tree, less the tests, the changelog and anything that is
  # not part of the repository's own content.
  shipped() {
    (cd "$1" && find . \( -path ./.git -o -path ./.github -o -path ./private \
                          -o -path ./.claude -o -name __pycache__ \) -prune \
                 -o -type f ! -path ./debian/changelog -print | sort)
  }
  # The old spellings, each the form one of the programs used: the literal
  # path (and its roff-escaped form in the man page), the unit specifier, the
  # CLI's variable, and systemd's directive.
  OLD='/run/hdw4s[-.][A-Za-z]|/run/hdw4s\\-|%t/hdw4s-|RUNDIR\}?/hdw4s-|RuntimeDirectory=hdw4s-|/run/lock/hdw4s-'
  old_hits() { (cd "$1" && shipped . | xargs -d '\n' grep -nIE "${OLD}" 2>/dev/null); }
  # THE SEARCH CAN SEE WHAT IT SEARCHES: an empty list would pass everything
  # below. The red arms further down plant into a copy made from this same list.
  list="$(shipped "${ROOT}")"
  has 'the files searched include the man page' "${list}" './hdw4s.8'
  has 'and the units' "${list}" './hdw4s-proxy@.service'
  is 'no shipped file names a runtime path outside /run/hdw4s' "$(old_hits "${ROOT}")" ''
  # A sandbox directive naming the PARENT itself, or the sessions' directory, is
  # a hole of a different kind: write access to, a bind of, or a mask over every
  # runtime file the package has. Only a named child may be named.
  broad() {
    (cd "$1" && shipped . | xargs -d '\n' grep -ohIE \
       "(ReadWritePaths|ReadOnlyPaths|BindPaths|BindReadOnlyPaths|InaccessiblePaths|TemporaryFileSystem)=[^'\"]*" 2>/dev/null) |
      awk '{ sub(/^[A-Za-z]*=/, "")
             for (i = 1; i <= NF; i++) { t = $i; sub(/^[-+]/, "", t); sub(/:.*/, "", t); sub(/\/$/, "", t)
               if (t ~ /^(\/run|%t)\/hdw4s(\/session)?$/) print t } }'
  }
  is 'no sandbox directive names /run/hdw4s, or its sessions, as a whole' "$(broad "${ROOT}")" ''
  # RED ARMS, on a copy: each old spelling planted once must be seen, and so
  # must a broad directive.
  mkdir -p "${d}/t"
  (cd "${ROOT}" && shipped . | tar -cf - -T -) | tar -xf - -C "${d}/t"
  # shellcheck disable=SC2016  # planted literally, as a script would spell them
  for plant in '/run/hdw4s-x' '%t/hdw4s-x' '/run/hdw4s-proxy/x.sock' '%t/hdw4s-ns/%i' \
               'RuntimeDirectory=hdw4s-demux' '"${RUNDIR}/hdw4s-pool.lock"' \
               '\fB/run/hdw4s\-ledger\fR' '/run/lock/hdw4s-update.lock'; do
    cp "${ROOT}/hdw4s-teardown" "${d}/t/hdw4s-teardown"
    printf '# %s\n' "${plant}" >> "${d}/t/hdw4s-teardown"
    [ -n "$(old_hits "${d}/t")" ] && ok "RED ARM: a planted ${plant} is seen" \
      || bad "RED ARM: a planted ${plant} is seen" 'the check passed it'
  done
  cp "${ROOT}/hdw4s-teardown" "${d}/t/hdw4s-teardown"
  for plant in 'ReadWritePaths=/run/hdw4s' 'InaccessiblePaths=-%t/hdw4s/' \
               'BindPaths=/run/hdw4s/session:/x'; do
    cp "${ROOT}/hdw4s-demux.service" "${d}/t/hdw4s-demux.service"
    printf '%s\n' "${plant}" >> "${d}/t/hdw4s-demux.service"
    [ -n "$(broad "${d}/t")" ] && ok "RED ARM: a planted ${plant} is seen" \
      || bad "RED ARM: a planted ${plant} is seen" 'the check passed it'
  done

  # THE RELAY SEES ONE STREAM DIRECTORY AND NOTHING ELSE UNDER /run. An empty
  # /run with exactly two paths bound back: its own stream directory and the
  # notify socket. A bind of the stream ROOT would hand it every desktop's
  # stream -- the redirect the barrier exists to stop.
  relay_paths() {
    grep -E '^(TemporaryFileSystem|BindPaths|BindReadOnlyPaths|ReadWritePaths|ReadOnlyPaths)=' "$1" | sort | tr '\n' ' '
  }
  want='BindReadOnlyPaths=/run/hdw4s/stream/%i BindReadOnlyPaths=/run/systemd/notify TemporaryFileSystem=/run '
  is 'the relay binds its own stream and notify, under an empty /run, and nothing else' \
     "$(relay_paths "${ROOT}/hdw4s-proxy@.service")" "${want}"
  sed 's|^BindReadOnlyPaths=/run/hdw4s/stream/%i$|BindReadOnlyPaths=/run/hdw4s/stream|' \
    "${ROOT}/hdw4s-proxy@.service" > "${d}/relay-red"
  if cmp -s "${ROOT}/hdw4s-proxy@.service" "${d}/relay-red"; then
    bad 'the relay red arm mutates the unit' 'the sed matched nothing'
  else
    [ "$(relay_paths "${d}/relay-red")" != "${want}" ] \
      && ok 'RED ARM: a relay binding the whole stream root is seen' \
      || bad 'RED ARM: a relay binding the whole stream root is seen' 'the check passed it'
  fi

  # NOTHING REMOVES THE PARENT, OR ANY ANCESTOR OF A SHARED MOUNT, RECURSIVELY.
  # /run/hdw4s/shared is the bind source of every desktop's /shared, and in tmpfs
  # mode a store is mounted at /run/hdw4s/shared-store: a recursive removal of
  # either, or of anything above them, walks into whatever is mounted there --
  # on an NFS box, the table. Per-child removal, then rmdir.
  rm_r() {  # every recursive rm whose target is such a path, one per line
    for f in "$@"; do
      sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' "${f}" |
        awk -v f="${f##*/}" '/(^|[;&|( ])rm / && /(^|[ \t])-[A-Za-z]*[rR]|--recursive/ {
          for (i = 1; i <= NF; i++) { t = $i; gsub(/["'"'"']/, "", t); sub(/\/\*?$/, "", t)
            if (t ~ /^(\/|\/run|\/run\/hdw4s|\/run\/hdw4s\/shared|\/run\/hdw4s\/shared-store|\/shared)$/) print f ": " $0 } }'
    done
  }
  rmfiles=("${ROOT}/uninstall.sh" "${ROOT}"/debian/*postrm "${ROOT}"/debian/*prerm)
  is 'no removal script deletes /run/hdw4s or a shared mount'"'"'s ancestor recursively' \
     "$(rm_r "${rmfiles[@]}")" ''
  cp "${ROOT}/debian/postrm" "${d}/postrm"
  printf '%s\n' '  rm -rf /run/hdw4s' >> "${d}/postrm"
  [ -n "$(rm_r "${d}/postrm")" ] && ok 'RED ARM: a planted rm -rf /run/hdw4s is seen' \
    || bad 'RED ARM: a planted rm -rf /run/hdw4s is seen' 'the check passed it'
  printf '%s\n' "  rm -rf --one-file-system '/run/hdw4s/'*" > "${d}/postrm"
  [ -n "$(rm_r "${d}/postrm")" ] && ok 'RED ARM: a planted rm of everything under it is seen' \
    || bad 'RED ARM: a planted rm of everything under it is seen' 'the check passed it'
  # And the parent is asserted once, root's and 0755, by tmpfiles -- never a
  # mount, never given an age.
  is 'tmpfiles makes /run/hdw4s root'"'"'s and 0755, with no age' \
     "$(grep -cx 'd /run/hdw4s 0755 root root -' "${ROOT}/hdw4s-tmpfiles.conf")" '1'
  # The sessions' runtime directories sit in session/, in both kinds of unit.
  for u in hdw4s@.service hdw4s-ephemeral@.service; do
    is "${u} puts its runtime directory under session/" \
       "$(grep -E '^(RuntimeDirectory|Environment=XDG_RUNTIME_DIR)=' "${ROOT}/${u}" | tr '\n' ' ')" \
       'Environment=XDG_RUNTIME_DIR=%t/hdw4s/session/%i RuntimeDirectory=hdw4s/session/%i '
  done
  is 'the router keeps its records under /run/hdw4s' \
     "$(grep -E '^RuntimeDirectory=' "${ROOT}/hdw4s-demux.service")" 'RuntimeDirectory=hdw4s/demux'
  # The one network-facing process has no use for the /shared table.
  is 'the router cannot see the /shared table' \
     "$(grep -cx 'InaccessiblePaths=-/run/hdw4s/shared' "${ROOT}/hdw4s-demux.service")" '1'

  # THE UPDATER'S LOCK, out of the world-writable /run/lock and root's alone:
  # the lines that take it, run against a scratch path.
  # shellcheck disable=SC2016  # the script's own text, matched literally
  lk="$(sed -n '/^mkdir -p "\${LOCKFILE%\/\*}"$/,/^umask "\${was}"$/p' "${ROOT}/hdw4s-update")"
  is 'the updater lock is taken in four lines' "$(printf '%s\n' "${lk}" | grep -c .)" '4'
  is 'and defaults to /run/hdw4s/update.lock' \
     "$(unset HDW4S_RUNDIR; eval "$(grep '^LOCKFILE=' "${ROOT}/hdw4s-update")"; echo "${LOCKFILE}")" '/run/hdw4s/update.lock'
  is 'and is made 0600' "$( (LOCKFILE="${d}/u/update.lock"; umask 022; eval "${lk}"; stat -c %a "${LOCKFILE}") )" '600'
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

echo '== bash completion offers what the commands accept, and nothing they refuse =='
# Driven without the bash-completion package: its three helpers are stood in
# for, so this judges OUR choices (which words, from which table), not theirs.
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  mkdir -p "${SB}/etc" "${SB}/bin"
  printf '# slots\n0 alice\n3 _hdw4s_0\n4 bob\n' > "${SB}/etc/instances"
  ln -s "${ROOT}/hdw4s" "${SB}/bin/hdw4s"
  c() {
    PATH="${SB}/bin:${PATH}" HDW4S_ETCDIR="${SB}/etc" bash -c '
      _init_completion() { cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"
                           words=("${COMP_WORDS[@]}"); cword=${COMP_CWORD}; }
      _filedir() { :; }; _known_hosts_real() { :; }; compopt() { :; }
      COMP_WORDBREAKS="${HDW4S_WB- =:}"  # "=" breaks words, as in bash'"'"'s default
      complete() { :; }
      . "$1"; shift
      read -ra COMP_WORDS <<<"$1"; [[ "$1" == *" " ]] && COMP_WORDS+=("")
      COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); COMPREPLY=()
      _hdw4s; [ "${#COMPREPLY[@]}" -eq 0 ] || printf "%s\n" "${COMPREPLY[@]}" | sort | tr "\n" " "' _ "${ROOT}/bash-completion/hdw4s" "$1"
  }
  is  'an instance is offered, a pool seat is not' "$(c 'hdw4s show ')" 'alice bob '
  # Readline replaces only what follows the last word break, and "=" is one by
  # default: the value alone, or a real terminal types the key twice.
  is  'a setting with fixed values offers exactly those' "$(c 'hdw4s set HDW4S_SHARED=')" \
      'off source tmpfs '
  is  'with the key itself where "=" breaks no word' "$(HDW4S_WB=' ' c 'hdw4s set HDW4S_SHARED=')" \
      'HDW4S_SHARED=off HDW4S_SHARED=source HDW4S_SHARED=tmpfs '
  is  'an instance is not offered a machine-wide setting' "$(c 'hdw4s set alice HDW4S_PROX')" 'HDW4S_PROXY_GROUP= '
  is  'the pool is not offered a setting it fixes' "$(c 'hdw4s pool set HDW4S_ISO')" ''
  is  'nor one that applies only to the whole machine' "$(c 'hdw4s pool set HDW4S_PROX')" ''
  is  'but is offered one it reads from the machine file' "$(c 'hdw4s pool set HDW4S_EPHEMERAL_U')" 'HDW4S_EPHEMERAL_URL= '
  # Every name offered is one "set" itself accepts: one table, two readers.
  n=0
  for k in $(PATH="${SB}/bin:${PATH}" HDW4S_ETCDIR="${SB}/etc" hdw4s __complete keys machine); do
    HDW4S_ETCDIR="${SB}/etc" "${ROOT}/hdw4s" set "${k}=" 2>&1 | grep -q 'cannot be set from the command line' && n=$((n + 1))
  done
  is  'no offered name is one "set" refuses as unknown' "${n}" '0'
  is  'every command in the usage is offered' \
      "$(offered=" $(c 'hdw4s ') "
         sed -n "/^Usage: hdw4s/,/^An instance/p" "${ROOT}/hdw4s" | awk '/^  [-a-z]/ { print $1 }' | sort -u |
         while read -r w; do case "${offered}" in *" ${w} "*) ;; *) echo "${w}";; esac; done)" ''
)

echo '== a named desktop latches on failed runs, never on starts or logouts =='
# THE DEFECT, 2026-10-03, on the owner's own desktop: two logouts and the start
# limit refused every later visit until somebody ran reset-failed. The limit
# counted STARTS. What latches now is hdw4s-ledger, which counts runs that ended
# WITHOUT SUCCESS, three in twenty minutes.
#
# Real: hdw4s-ledger itself. Stood in for: systemd, by the three variables it
# hands an ExecStopPost= ($SERVICE_RESULT, $EXIT_CODE, $EXIT_STATUS), and
# /run/hdw4s/ledger, by a temporary directory. Nothing here shows that systemd
# runs the writer, nor which values it really passes -- that is the real-unit arm.
( set +e
  # One level down, so that a name escaping it would still land in OUR temporary
  # directory -- where the test can see it -- and not in the machine's /tmp.
  T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  L="${T}/l"; mkdir "${L}"
  export HDW4S_LEDGER_DIR="${L}"
  led="${ROOT}/hdw4s-ledger"
  rec() { SERVICE_RESULT="$1" EXIT_CODE="$2" EXIT_STATUS="$3" "${led}" record alice 2>/dev/null; }
  chk() { "${led}" check alice 2>/dev/null; echo "$?"; }
  entries() { [ -e "${L}/alice" ] && grep -c . "${L}/alice" || echo 0; }

  # Positive control first: nothing recorded, nothing refused.
  is 'an empty ledger refuses nothing' "$(chk)" '0'
  # SUCCESSES NEVER COUNT, however many: a logout, a stop, a restart.
  for _ in 1 2 3 4 5 6; do rec success exited 0; done
  is 'six successful ends refuse nothing'  "$(chk)" '0'
  is 'and record nothing'                  "$(entries)" '0'
  rec exit-code exited 1; rec exit-code exited 1
  is 'two failed runs refuse nothing'      "$(chk)" '0'
  rec signal killed SEGV
  is 'the third failed run refuses the next start with 75' "$(chk)" '75'
  is 'and the record holds three entries'  "$(entries)" '3'
  # FIXED FORMAT (threat review L-a): epoch, systemd's result word, code/status.
  is 'every entry is epoch, result, code/status' \
     "$(grep -cvE '^[0-9]+ [a-z-]+ [a-z]*/[A-Z0-9]*$' "${L}/alice")" '0'
  is 'the record is readable by its owner and written by nobody else' \
     "$(stat -c %a "${L}/alice")" '644'
  # A REFUSAL IS NOT A FAILURE (threat review L-c): otherwise every knock on the
  # door -- the owner's own reconnecting tab -- keeps the latch alive for ever,
  # and the time the page says it lifts is false.
  st1="$("${led}" state alice)"
  for _ in 1 2 3 4 5; do rec exit-code exited 75; done
  is 'refused starts append nothing'       "$(entries)" '3'
  is 'and do not move when it lifts'       "$("${led}" state alice)" "${st1:-none}"
  read -r w n th win last lifts <<< "${st1}"
  is 'the state line says latched, three of three, in twenty minutes' "${w} ${n} ${th} ${win}" 'latched 3 3 1200'
  # Lifts when the oldest of the three leaves the window: stated, then seen.
  first="$(head -n1 "${L}/alice" | cut -d' ' -f1)"
  is 'it lifts twenty minutes after the oldest counted failure' "${lifts}" "$(( first + 1200 ))"
  sed -i "s/^[0-9]*/$(( $(date +%s) - 1201 ))/" "${L}/alice"
  is 'and once the entries expire, the next start is allowed' "$(chk)" '0'
  # Expired entries stop counting, but fresh ones beside them still do.
  rec exit-code exited 1; rec exit-code exited 1
  is 'two fresh failures beside three expired ones refuse nothing' "$(chk)" '0'
  rec timeout '' ''
  is 'a third fresh one does'                "$(chk)" '75'
  is 'and the writer pruned the expired ones' "$(entries)" '3'

  # ONE WARNING LINE, AT THE LATCH: the run that crosses the threshold says so at
  # priority 4 when there is a journal to say it to; the runs before it do not.
  rm -f "${L}/alice"
  w1="$(SERVICE_RESULT=exit-code EXIT_CODE=exited EXIT_STATUS=1 JOURNAL_STREAM=x "${led}" record alice 2>&1)"
  SERVICE_RESULT=exit-code EXIT_CODE=exited EXIT_STATUS=1 "${led}" record alice 2>/dev/null
  w3="$(SERVICE_RESULT=exit-code EXIT_CODE=exited EXIT_STATUS=1 JOURNAL_STREAM=x "${led}" record alice 2>&1)"
  hasnt 'the first failure is not a warning'   "${w1}" '<4>'
  is  'the third is exactly one warning line'  "$(printf '%s\n' "${w3}" | grep -c '^<4>')" '1'
  has 'and it names the commands that clear it' "${w3}" 'systemctl reset-failed hdw4s@alice.service; rm -f'

  # A name that would leave the directory is refused, not written.
  SERVICE_RESULT=exit-code EXIT_CODE=exited EXIT_STATUS=1 "${led}" record '../x' 2>/dev/null
  is 'a name with a slash is refused'      "$?" '2'
  [ ! -e "${L}/../x" ] && ok 'and writes nothing outside the ledger' \
                       || bad 'and writes nothing outside the ledger' "${L}/../x exists"
)

echo '== the named session refuses before READY, from its main process, and only when latched =='
# Real: hdw4s-session's own refuse_if_latched, cut out of the script, and the
# real hdw4s-ledger. Stood in for: the ledger directory.
( set +e
  L="$(mktemp -d)"; trap 'rm -rf "${L}"' EXIT
  fn="$(sed -n '/^refuse_if_latched() {/,/^}/p' "${ROOT}/hdw4s-session")"
  has 'the refusal is where this test looks for it' "${fn}" 'refuse_if_latched() {'
  run() {  # $1 the kind, $2 the ledger directory; prints the exit status
    HDW4S_SESSION_TYPE="$1" HDW4S_LEDGER_DIR="$2" instance=alice \
      bash -c "set -eu; ${fn}
      refuse_if_latched; exit 0" >/dev/null 2>&1
    echo "$?"
  }
  is 'a named desktop with no failures starts' "$(run desktop "${L}")" '0'
  now="$(date +%s)"
  printf '%s exit-code exited/1\n' "${now}" "${now}" "${now}" > "${L}/alice"
  is 'a latched named desktop exits 75'        "$(run desktop "${L}")" '75'
  # Named only (threat review L-d): a pool slot is reused, and one visitor's
  # crashes must not refuse the next visitor.
  is 'an ephemeral desktop is never refused by it' "$(run ephemeral "${L}")" '0'
  # Fails open: a ledger it cannot read is no reason to refuse a desktop.
  is 'an unreadable ledger starts the desktop'  "$(run desktop /nonexistent/dir)" '0'
  # It must run before anything else the main process does that could report
  # ready or fail for another reason -- the X server, the bus.
  is 'it runs before the X server is started' \
     "$(awk '/^refuse_if_latched$/ { r = NR } /\/usr\/lib\/xorg\/Xorg / { x = NR }
             END { print (r && x && r < x) ? "before" : "not" }' "${ROOT}/hdw4s-session")" 'before'
)

echo '== the unit wires the ledger as measured: writer after, check in the main process =='
( set +e
  f="${ROOT}/hdw4s@.service"
  refused="$(sed -n 's/^REFUSED=\([0-9]*\)$/\1/p' "${ROOT}/hdw4s-ledger")"
  # "none" for an empty read, or two missing values would compare equal.
  is 'the unit does not restart the refusal status the ledger exits with' \
     "$(sed -n 's/^RestartPreventExitStatus=//p' "${f}")" "${refused:-none}"
  is 'and the session exits with that same status' \
     "$(grep -c "^    ${refused}) exit ${refused} ;;$" "${ROOT}/hdw4s-session")" '1'
  # "!" not "+": "+" keeps TemporaryFileSystem=, so the write could land in a
  # namespace and never latch (threat review L-b). "-": a ledger that cannot be
  # written must never make a clean end a failure.
  is 'the writer runs after every run, as root in the namespace, never fatal' \
     "$(grep -cx 'ExecStopPost=-!/usr/lib/hdw4s/hdw4s-ledger record %i' "${f}")" '1'
  is 'and may write the host ledger directory' \
     "$(grep -cx 'ReadWritePaths=-/run/hdw4s/ledger' "${f}")" '1'
  # MEASURED: a refusing ExecStartPre= is restarted for ever.
  is 'the check is not an ExecStartPre=' "$(grep -c '^ExecStartPre=.*hdw4s-ledger' "${f}")" '0'
  # 0711, not 0755: a record is opened by name, and the set of desktops that
  # have one is nobody's to list.
  is 'tmpfiles makes the ledger directory root'"'"'s, enterable and unlistable' \
     "$(grep -cx 'd /run/hdw4s/ledger 0711 root root -' "${ROOT}/hdw4s-tmpfiles.conf")" '1'
  is 'the refusal unit is told which desktop it is refusing' \
     "$(grep -cx 'ExecStart=/usr/lib/hdw4s/hdw4s-refuse %i' "${ROOT}/hdw4s-refuse@.service")" '1'
  # NAMED ONLY (threat review L-d), with its red arm: a planted line is seen.
  e="${ROOT}/hdw4s-ephemeral@.service"
  is 'the ephemeral unit carries no ledger writer or check' "$(grep -c 'hdw4s-ledger' "${e}")" '0'
  is 'RED ARM: a planted ledger line in the ephemeral unit is seen' \
     "$( { cat "${e}"; echo 'ExecStopPost=-!/usr/lib/hdw4s/hdw4s-ledger record %i'; } | grep -c 'hdw4s-ledger')" '1'
)

echo '== a latched desktop gets a page that says so; anything else, the ordinary one =='
# THE DEFECT: "Reload in a moment" into a refusal that lasts twenty minutes. Real:
# hdw4s-refuse, run as systemd runs it -- a listening socket on fd 3, LISTEN_FDS=1
# -- with a connection already queued, and the real hdw4s-ledger. Stood in for:
# the ledger directory.
( set +e
  L="$(mktemp -d)"; trap 'rm -rf "${L}"' EXIT
  page() {  # $1 the instance argument (may be empty); prints the response body
    HDW4S_LEDGER_DIR="${L}" python3 - "${ROOT}/hdw4s-refuse" "$1" <<'PY'
import os, socket, subprocess, sys, tempfile
d = tempfile.mkdtemp()
path = os.path.join(d, "s")
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(8)
cli = socket.socket(socket.AF_UNIX); cli.connect(path)
def child():
    os.dup2(srv.fileno(), 3)
argv = [sys.argv[1]] + ([sys.argv[2]] if sys.argv[2] else [])
env = dict(os.environ, LISTEN_FDS="1", LISTEN_PID="0")
p = subprocess.Popen(argv, preexec_fn=child, env=env, pass_fds=(srv.fileno(),),
                     stdout=subprocess.DEVNULL)
data = b""
while True:
    b = cli.recv(65536)
    if not b:
        break
    data += b
p.wait(10)
sys.stdout.write(data.decode().split("\r\n\r\n", 1)[-1])
sys.stdout.write("\nRC=%d\n" % p.returncode)
PY
  }
  transient="$(page alice)"
  has 'the ordinary page still says to reload'  "${transient}" 'Reload in a moment'
  now="$(date +%s)"
  printf '%s exit-code exited/1\n' "${now}" "${now}" "${now}" > "${L}/alice"
  latched="$(page alice)"
  [ "${latched}" != "${transient}" ] && ok 'a latched desktop gets a different page' \
                                     || bad 'a latched desktop gets a different page' 'the bodies are identical'
  has   'it names the unit'                 "${latched}" 'hdw4s@alice.service'
  has   'and the exact command'             "${latched}" 'systemctl reset-failed hdw4s@alice.service'
  has   'and how the record is cleared'     "${latched}" 'rm -f /run/hdw4s/ledger/alice'
  has   'and when it lifts by itself'       "${latched}" "$(date -d "@$(( now + 1200 ))" '+%Y-%m-%d %H:%M')"
  hasnt 'and does not say to reload in a moment' "${latched}" 'Reload in a moment'
  has   'and the responder exits cleanly'   "${latched}" 'RC=0'
  # SHARED WITH THE POOL (threat review L-e): no instance, a malformed ledger, a
  # name that must be escaped -- the ordinary page, never a crash, which would
  # latch the door.
  is 'with no instance it is the ordinary page' "$(page '')" "${transient}"
  printf 'garbage\n<script>\n' > "${L}/alice"
  is 'a malformed ledger gives the ordinary page' "$(page alice)" "${transient}"
  # A name carrying markup is refused by the ledger, so it never reaches the page
  # at all -- and the page still answers.
  is 'a name carrying markup gives the ordinary page' "$(page '<b>x')" "${transient}"
)

echo '== hdw4s check sees a named desktop that will not start =='
# THE DEFECT: the failed-unit query named only the pool's units and the session
# loop looked only at running ones, so the owner's latched desktop left this
# command -- and its timer -- green.
( set +e; SB="$(mktemp -d)"; trap 'rm -rf "${SB}"' EXIT
  sed '/^case "${1:-}" in/,$d' "${ROOT}/hdw4s" > "${SB}/lib.sh"
  HDW4S_ETCDIR="${SB}/etc"; mkdir -p "${HDW4S_ETCDIR}" "${SB}/ledger"
  RUNDIR="${SB}/run"
  HDW4S_INCARNATION_DIR="${SB}/run/incarnation"
  HDW4S_WEBROOT_DIR="${SB}/webroot"
  mkdir -p "${HDW4S_INCARNATION_DIR}" "${HDW4S_WEBROOT_DIR}"
  export HDW4S_ETCDIR HDW4S_RUNDIR="${RUNDIR}" HDW4S_INCARNATION_DIR HDW4S_WEBROOT_DIR
  export HDW4S_LEDGER_DIR="${SB}/ledger"
  # shellcheck source=/dev/null
  . "${SB}/lib.sh" 2>/dev/null || :
  # The root namespace's /shared, which "hdw4s check" asks the minter about:
  # the sandbox's, never the machine's (as sandbox() sets it). Without these,
  # on a machine with /shared, check compared the real bind with a sandbox
  # path and called it foreign (seen as root on a dev box, 2026-10-04).
  export HDW4S_SHARED_MARK="${SB}/shared-mark" HDW4S_SHARED_MOUNTPOINT="${SB}/shared-point" \
         HDW4S_SHARED_VIEW_STATE="${SB}/shared-view"
  trap - ERR
  trap 'rm -rf "${SB}"' INT TERM QUIT HUP EXIT
  SLOTS="${HDW4S_ETCDIR}/instances"; RUNDIR="${SB}/run"
  # A named desktop and no pool: the shape of the owner's machine, and the shape
  # in which the pool's failed-unit query never runs at all. Its web root is
  # there, as "enable" leaves it; a missing one is its own failure, tested with
  # the pool's check.
  printf '%s\n' '0 alice desktop' > "${SLOTS}"
  mkdir -p "${HDW4S_WEBROOT_DIR}/alice"
  STUB_FAILED=''
  # shellcheck disable=SC2317
  systemctl() {
    case "$*" in
      *'list-units --failed'*) printf '%s' "${STUB_FAILED}";;
      *) echo 'inactive';;
    esac
    return 0
  }
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a named desktop at rest passes' "${rc}" '0'
  STUB_FAILED='hdw4s@alice.service failed failed'
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a failed named desktop fails the check' "${rc}" '1'
  has 'and names it'           "${out}" 'hdw4s@alice.service has failed'
  has 'and names the remedy'   "${out}" 'systemctl reset-failed hdw4s@alice.service'
  STUB_FAILED=''
  now="$(date +%s)"
  printf '%s exit-code exited/1\n' "${now}" "${now}" "${now}" > "${SB}/ledger/alice"
  out="$( ( cmd_check ) 2>&1 )"; rc=$?
  is  'a latched named desktop fails the check, even after reset-failed' "${rc}" '1'
  has 'and says it is refusing to start' "${out}" 'alice is refusing to start: it failed 3 times'
  has 'and how the record is cleared'    "${out}" 'rm -f /run/hdw4s/ledger/alice'
)

echo '== an upgrade never stops the router, and restarts it onto the new code =='
( set +e
  # debhelper's prerm would stop hdw4s-demux.service on every upgrade, leaving
  # the front door to the next arrival's socket activation.
  line="$(command grep -E 'dh_installsystemd .*hdw4s-demux\.service' "${ROOT}/debian/rules")"
  case "${line}" in *--no-stop-on-upgrade*) ok 'the router service is not stopped on upgrade';;
    *) bad 'the router service is not stopped on upgrade' "${line:-no line}";; esac
  has   'postinst restarts the router onto the new code' "$(cat "${ROOT}/debian/postinst")" 'try-restart hdw4s-demux.service'
  is    'and nowhere else in postinst' "$(command grep -c 'hdw4s-demux.service' "${ROOT}/debian/postinst")" '1'
  # AFTER systemd has read the new unit files: debhelper's own reload comes at
  # the end of postinst, so a restart before a reload of postinst's own would
  # run the router under its old definition until the next reboot.
  rl="$(command grep -n 'systemctl daemon-reload' "${ROOT}/debian/postinst" | head -1 | cut -d: -f1)"
  rs="$(command grep -n 'try-restart hdw4s-demux.service' "${ROOT}/debian/postinst" | head -1 | cut -d: -f1)"
  if [ -n "${rl}" ] && [ -n "${rs}" ] && [ "${rl}" -lt "${rs}" ]; then
    ok 'and only after postinst has reloaded systemd'
  else
    bad 'and only after postinst has reloaded systemd' "reload at line ${rl:-none}, restart at ${rs:-none}"
  fi
  # Removal stops the router itself, not only its socket: the service holds the
  # socket's descriptor and kept answering after the package was gone.
  rm_blk="$(sed -n "/^if \[ \"\$1\" = 'remove' \]/,/^fi$/p" "${ROOT}/debian/prerm")"
  has   'removal stops the router service itself' "${rm_blk}" 'systemctl stop hdw4s-demux.service'
)

echo '== install.sh ships every library file the package does =='
( set +e
  # Two lists of the same files, and they had drifted: the package shipped
  # hdw4s-background and hdw4s-stage-wait, install.sh did not, so on an
  # install.sh install a visitor desktop came up on the flat fallback colour
  # and never armed the startup hold (read from hdw4s-run-session, not
  # measured: neither is fatal there). Nothing compared the lists.
  src="${ROOT}"; eval "$(sed -n '/^SOURCES=(/,/LICENSE)$/p' "${ROOT}/install.sh")"
  missing="$(awk '$1 !~ /^#/ && NF == 2 && $2 == "usr/lib/hdw4s" { print $1 }' "${ROOT}/debian/install" |
             while read -r f; do printf '%s\n' "${SOURCES[@]}" | command grep -qx -- "${f}" || echo "${f}"; done)"
  is 'install.sh ships every library file the package does' "${missing}" ''
)

echo '== exec: a visitor address resolves only to its own letting and desktop =='
( set +e
  # hdw4s exec names a pool desktop by the address its visitor holds. Seats are
  # let again, so every way a seat comes to hold somebody else's desktop must
  # refuse -- proved by the router's own self-check, and that self-check proved
  # by doctored lookups it must catch (each one dropped one condition).
  out="$(python3 - "${ROOT}/hdw4s-demux" <<'PY'
import importlib.machinery, importlib.util, json, os, sys, tempfile
l = importlib.machinery.SourceFileLoader("demux", sys.argv[1])
d = importlib.util.module_from_spec(importlib.util.spec_from_loader("demux", l)); l.exec_module(d)
def arm(name, f):
    try:
        d.assert_admin_lookup_refuses(d.Ownership, f); print(name, "GREEN")
    except AssertionError:
        print(name, "red")
arm("real", d.admin_letting)
def no_inc(own, sid, auth=None, now=None):
    rec = own.lookup(sid); why = d.still_this_letting(own, sid, grace=False)
    return (None, why) if why or not rec.get("live") else (rec["instance"], None)
def no_live(own, sid, auth=None, now=None):
    rec = own.lookup(sid); why = d.still_this_letting(own, sid, grace=False)
    if why: return None, why
    was, now_ = rec.get("incarnation"), d.authoritative_incarnation(rec["instance"], auth)
    return (rec["instance"], None) if was == now_ else (None, "x")
# Without the router's letting rules (ended, re-let): a seat let again while
# its desktop identity still agrees must be refused by them alone. (Minting a
# new letting marks the earlier one ended, so "re-let" is not a case apart.)
def no_rules(own, sid, auth=None, now=None):
    rec = own.lookup(sid)
    if not rec.get("live"): return None, "x"
    return (rec["instance"], None) if rec["incarnation"] == d.authoritative_incarnation(rec["instance"], auth) else (None, "x")
def absent_equal(own, sid, auth=None, now=None):
    rec = own.lookup(sid); why = d.still_this_letting(own, sid, grace=False)
    if why or not rec.get("live"): return None, "x"
    now_ = d.authoritative_incarnation(rec["instance"], auth)
    return (rec["instance"], None) if now_ in (None, rec["incarnation"]) else (None, "x")
def no_occupancy(own, sid, auth=None, rundir=None):
    rec = own.lookup(sid); why = d.still_this_letting(own, sid, grace=False)
    if why or not rec.get("live"): return None, "x"
    now_ = d.authoritative_incarnation(rec["instance"], auth)
    return (rec["instance"], None) if now_ is not None and now_ == rec["incarnation"] else (None, "x")
arm("no-incarnation", no_inc); arm("no-live", no_live); arm("no-occupancy", no_occupancy)
arm("no-rules", no_rules); arm("absent-equal", absent_equal)
arm("refuse-all", lambda own, sid, auth=None, now=None: (None, "no"))
# What an administrator types.
own = d.Ownership(); a = own.mint_session(own.mint_identity(), "_hdw4s_1")
print("short", d.admin_resolve(own, "abc")[2] is not None and d.admin_resolve(own, "abc")[1] is None)
print("url", "no desktop has come up" in d.admin_resolve(own, "https://h.example/s/%s/" % a)[2])
print("prefix", "no desktop has come up" in d.admin_resolve(own, a[:8])[2])
print("unknown", "no visitor" in d.admin_resolve(own, "0" * 32 if not a.startswith("0") else "f" * 32)[2])
# The table as the router writes it, read the way --lettings and --resolve read
# it: the identity cookie is in every row and must never be printed.
with tempfile.TemporaryDirectory() as t:
    auth = os.path.join(t, "inc"); os.mkdir(auth)
    with open(os.path.join(auth, "_hdw4s_1"), "w") as f: f.write("abcd\n")
    rows = {"%032x" % 7: {"identity": "SECRETIDENTITY", "instance": "_hdw4s_1",
                          "minted": 1000.0, "live": True, "incarnation": "abcd",
                          "ended": None, "ended_at": None}}
    path = os.path.join(t, "ownership.json")
    with open(path, "w") as f: json.dump({"version": 1, "sessions": rows}, f)
    run = os.path.join(t, "session"); os.makedirs(os.path.join(run, "_hdw4s_1"))
    d.OWNERSHIP_FILE, d.INCARNATION_AUTHORITY, d.SESSION_RUNDIR = path, auth, run
    real = d.os.geteuid; d.os.geteuid = lambda: 0
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r1 = d.admin_main(["--lettings"]); r2 = d.admin_main(["--resolve", "%08x" % 0])
    d.os.geteuid = lambda: 1000
    with contextlib.redirect_stderr(io.StringIO()):
        r3 = d.admin_main(["--lettings"])
    d.os.geteuid = real
    o = buf.getvalue()
    print("lettings", r1 == 0 and "_hdw4s_1 %032x 1000" % 7 in o)
    print("resolve", r2 == 0 and "_hdw4s_1 abcd" in o)
    print("noidentity", "SECRETIDENTITY" not in o)
    print("nonroot", r3 == 1)
PY
)"
  has 'the router self-check passes the real lookup'            "${out}" 'real GREEN'
  has 'RED: a lookup ignoring the desktop identity is caught'    "${out}" 'no-incarnation red'
  has 'RED: a lookup admitting a never-answered letting is caught' "${out}" 'no-live red'
  has 'RED: a lookup ignoring ended and re-let lettings is caught' "${out}" 'no-rules red'
  has 'RED: a lookup reading absent as equal is caught'           "${out}" 'absent-equal red'
  has 'RED: a lookup naming a seat with nothing running is caught' "${out}" 'no-occupancy red'
  has 'RED: a lookup refusing everything is caught'               "${out}" 'refuse-all red'
  has 'a too-short token is refused before any lookup'           "${out}" 'short True'
  has 'the visitor URL is accepted as written'                    "${out}" 'url True'
  has 'and so is an 8-character prefix'                           "${out}" 'prefix True'
  has 'an address nobody had is refused as such'                  "${out}" 'unknown True'
  has '--lettings prints seat, sid and mint time'                 "${out}" 'lettings True'
  has '--resolve prints the seat and its desktop identity'        "${out}" 'resolve True'
  has 'and neither ever prints the identity cookie'               "${out}" 'noidentity True'
  has 'the lookup is for root only'                               "${out}" 'nonroot True'
)

echo '== exec: the desktop entered is the one systemd started, never the occupant'"'"'s =='
( set +e
  # Entering a process's mount namespace as root runs the next binary from the
  # view THAT process chose. Measured 2026-10-05: an occupant's own unshare'd
  # namespace with a fake /usr/bin ran "setpriv" as uid 0. So the namespaces
  # come from systemd's main process, the environment from its direct child,
  # and each is checked. A fake /proc stands in; every arm names its case.
  out="$(python3 - "${ROOT}/hdw4s-enter" "${ROOT}/hdw4s-session-environment" <<'PY'
import importlib.machinery, importlib.util, os, sys, tempfile
l = importlib.machinery.SourceFileLoader("enter", sys.argv[1])
e = importlib.util.module_from_spec(importlib.util.spec_from_loader("enter", l)); l.exec_module(e)
CG = "/hdw4s.slice/hdw4s-ephemeral@_hdw4s_0.service"
def proc(t, pids, children):
    os.makedirs(os.path.join(t, "self", "ns"))
    os.symlink("user:[1]", os.path.join(t, "self", "ns", "user"))
    for pid, (mnt, user, uid, cg, env) in pids.items():
        b = os.path.join(t, str(pid)); os.makedirs(os.path.join(b, "ns"))
        os.makedirs(os.path.join(b, "task", str(pid)))
        os.symlink("mnt:[%s]" % mnt, os.path.join(b, "ns", "mnt"))
        os.symlink("user:[%s]" % user, os.path.join(b, "ns", "user"))
        open(os.path.join(b, "status"), "w").write(
            "Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nCapBnd:\t0\nUmask:\t0077\n" % ((uid,) * 8))
        # Started 100 s after boot: field 22 of stat, in clock ticks.
        open(os.path.join(b, "stat"), "w").write(
            "%d (x) S" % pid + " 0" * 18 + " %d 0\n" % (100 * os.sysconf("SC_CLK_TCK")))
        open(os.path.join(b, "limits"), "w").write("Max open files 1024 4096 files\n")
        open(os.path.join(b, "cgroup"), "w").write("0::%s\n" % cg)
        open(os.path.join(b, "environ"), "wb").write(b"\0".join(k.encode() + b"=x" for k in env) + b"\0")
        open(os.path.join(b, "task", str(pid), "children"), "w").write(" ".join(map(str, children.get(pid, []))))
def run(name, pids, children, state="active", main=10, execmain=10, started=100.0):
    with tempfile.TemporaryDirectory() as t:
        proc(t, pids, children)
        try:
            m, src, pa, pb = e.choose("u", proc=t, facts=lambda u: {
                "state": state, "main": main, "execmain": execmain,
                "cgroup": CG, "started": started},
                pidfd_open=lambda p: os.pidfd_open(os.getpid()))
            os.close(pa); os.close(pb)
            print(name, "chose", m, src)
        except e.Refusal:
            print(name, "refused")
BUS = ["DBUS_SESSION_BUS_ADDRESS", "DCONF_PROFILE"]
MAIN = (5, 1, 900, CG, ["DCONF_PROFILE"])
run("permit", {10: MAIN, 11: (5, 1, 900, CG, BUS)}, {10: [11]})
# The occupant's own namespace, as the only child carrying the bus: refused.
run("forged", {10: MAIN, 11: (6, 2, 900, CG, BUS)}, {10: [11]})
# Same namespaces, but a grandchild: the occupant's process, never chosen.
run("grandchild", {10: MAIN, 11: (5, 1, 900, CG, []), 12: (5, 1, 900, CG, BUS)}, {10: [11], 11: [12]})
run("othercg", {10: (5, 1, 900, "/elsewhere", ["DCONF_PROFILE"]), 11: (5, 1, 900, CG, BUS)}, {10: [11]})
run("userns", {10: (5, 2, 900, CG, ["DCONF_PROFILE"]), 11: (5, 2, 900, CG, BUS)}, {10: [11]})
run("inactive", {10: MAIN, 11: (5, 1, 900, CG, BUS)}, {10: [11]}, state="inactive")
# systemd's MainPID moved by a MAINPID= message from inside (NotifyAccess=all).
run("moved", {10: MAIN, 11: (5, 1, 900, CG, BUS)}, {10: [11]}, execmain=9)
# The number reused: the process at it started long after systemd's fork.
run("reused", {10: MAIN, 11: (5, 1, 900, CG, BUS)}, {10: [11]}, started=30.0)
run("nostart", {10: MAIN, 11: (5, 1, 900, CG, BUS)}, {10: [11]}, started=0)
# A desktop whose user is root: never entered.
with tempfile.TemporaryDirectory() as t:
    proc(t, {10: (5, 1, 0, CG, ["DCONF_PROFILE"]), 11: (5, 1, 0, CG, BUS)}, {10: [11]})
    try:
        pf = os.pidfd_open(os.getpid())
        e.gather(10, 11, pf, pf, proc=t)
        print("root", "entered")
    except e.Refusal:
        print("root", "refused")
# The environment: by the list, display withheld, the credential never.
names = e.read_env_list(sys.argv[2])
src = {"DCONF_PROFILE": "p", "DISPLAY": ":5", "XAUTHORITY": "/x",
       "SELKIES_BASIC_AUTH_PASSWORD": "S3CRET", "HOME": "/home/user",
       "DBUS_SESSION_BUS_ADDRESS": "unix:path=/b"}
env, held = e.filtered_env(src, names)
print("env", sorted(env), sorted(held))
print("secret", "S3CRET" not in env.values())
env2, _ = e.filtered_env(src, names, display=True)
print("display-optin", "DISPLAY" in env2)
# The seat let again between the lookup and the entry.
with tempfile.TemporaryDirectory() as t:
    open(os.path.join(t, "_hdw4s_0"), "w").write("new\n")
    try:
        e.check_incarnation("_hdw4s_0", "old", 1, authority=t); print("relet", "admitted")
    except e.Refusal:
        print("relet", "refused")
PY
)"
  has 'the main process and its bus-carrying child are entered' "${out}" 'permit chose 10 11'
  has 'RED: a child in a namespace of its own is refused'        "${out}" 'forged refused'
  has 'RED: an occupant-started grandchild is never chosen'      "${out}" 'grandchild refused'
  has 'RED: a main process outside the unit cgroup is refused'   "${out}" 'othercg refused'
  has 'RED: a main process in another user namespace is refused' "${out}" 'userns refused'
  has 'a desktop that is not running is refused, never started'  "${out}" 'inactive refused'
  has 'RED: a main process moved away from the one systemd forked' "${out}" 'moved refused'
  has 'RED: a main process number that has been reused is refused' "${out}" 'reused refused'
  has 'RED: a desktop running as root is never entered'           "${out}" 'root refused'
  has 'a unit with no recorded start is refused'                  "${out}" 'nostart refused'

  has 'the environment is the allow-list, display withheld'      "${out}" "env ['DBUS_SESSION_BUS_ADDRESS', 'DCONF_PROFILE', 'HOME'] ['DISPLAY', 'XAUTHORITY']"
  has 'the session credential is never handed over'              "${out}" 'secret True'
  has 'the display variables are flagged, not missing'           "${out}" 'display-optin True'
  has 'a seat let again since the lookup is refused'             "${out}" 'relet refused'
  # One list, two readers: the session uploads to its bus what exec hands over.
  has 'hdw4s-run-session reads the same list' "$(cat "${ROOT}/hdw4s-run-session")" 'hdw4s-session-environment"'
  has 'and the package installs it'           "$(cat "${ROOT}/debian/install")" 'hdw4s-session-environment'
  # The bus address goes to the command and never to the bus itself: the
  # session start skips what is marked "exec". Read the way it reads the list.
  up="$(while read -r name flag; do case "${name}" in ''|\#*) continue;; esac
        [ "${flag}" = exec ] && continue; echo "${name}"; done < "${ROOT}/hdw4s-session-environment")"
  hasnt 'the session start does not upload the bus address' "${up}" 'DBUS_SESSION_BUS_ADDRESS'
  has   'but still uploads what programs need'               "${up}" 'DCONF_PROFILE'
  # The session start's own loop, run: it skips "exec" as a WORD among the
  # flags, and a missing list costs a warning, never the session ("bash -e").
  loop="$(sed -n '/^activation=()$/,/could not read the list/p' "${ROOT}/hdw4s-run-session")"
  d="$(mktemp -d)"; printf 'A\nB display exec\nC exec display\nD display\n' > "${d}/hdw4s-session-environment"
  got="$(HDW4S_LIBDIR="${d}" bash -e -c "${loop}"$'\n''echo "${activation[*]}"' 2>&1)"
  is 'the session start uploads exactly the names not marked exec' "${got}" 'A D'
  got="$(HDW4S_LIBDIR="${d}/none" bash -e -c "${loop}"$'\n''echo "survived ${#activation[@]}"' 2>&1)"
  has 'a missing list is a warning, and the session goes on' "${got}" 'survived 0'
  rm -rf "${d}"
)

echo '== exec: a command gets its streams byte for byte, and lets go of them =='
( set +e; T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
  # The real relay and the real child set-up, with only the ENTRY stood in for
  # (it needs root and a desktop). Through a terminal, input was cut at 4095
  # bytes a line and output gained carriage returns and the report, exit 0
  # (found in review); a leftover holding root's own pipes kept exec waiting.
  cat > "${T}/drive.py" <<'PY'
import importlib.machinery, importlib.util, os, sys
l = importlib.machinery.SourceFileLoader("enter", sys.argv[1])
e = importlib.util.module_from_spec(importlib.util.spec_from_loader("enter", l)); l.exec_module(e)
e.enter = lambda f: None
e.report = lambda *a, **k: sys.stderr.write("REPORT\n")
fd = os.open("/dev/null", os.O_RDONLY); os.dup2(fd, 7)   # inheritable, like a caller's
sys.exit(e.exit_code(e.spawn(1, 1, {"env": dict(os.environ), "snapshot": None, "withheld": [], "pf_main": os.pidfd_open(os.getpid())}, sys.argv[2:])))
PY
  d() { python3 "${T}/drive.py" "${ROOT}/hdw4s-enter" "$@"; }
  head -c 10000 /dev/zero | tr '\0' x > "${T}/line"; echo >> "${T}/line"
  is 'a long line through a pipe arrives whole' "$(d wc -c < "${T}/line" 2>/dev/null | tr -d ' ')" '10001'
  d sh -c 'printf "a\001b\n"' > "${T}/out" 2>/dev/null
  is 'output to a file is byte for byte, report kept apart' "$(od -An -c "${T}/out" | tr -s ' ')" ' a 001 b \n'
  d sh -c 'exit 7' </dev/null >/dev/null 2>&1
  is 'the command'"'"'s exit status comes back' "$?" '7'
  is 'a descriptor the caller left open does not reach the command' \
     "$(d sh -c 'test -e /proc/self/fd/7 && echo LEAKED || echo closed' </dev/null 2>/dev/null)" 'closed'
  s="$(date +%s)"; d sh -c 'sleep 20 & echo started' </dev/null > "${T}/bg" 2>&1
  is 'a leftover in the background does not hold exec' "$(( $(date +%s) - s < 5 ))" '1'
  has 'and what the command printed before it exited arrives' "$(cat "${T}/bg")" 'started'
  # Found in review, each measured on the relay before it was rebuilt: a
  # command that fills its output before reading its input deadlocked it past
  # any signal; a reader that leaves early killed it by SIGPIPE, losing output.
  out="$(head -c 1000000 /dev/zero | timeout 30 python3 "${T}/drive.py" "${ROOT}/hdw4s-enter" \
           sh -c 'head -c 1000000 /dev/zero; cat >/dev/null' 2>/dev/null | wc -c; echo "rc=${PIPESTATUS[1]}")"
  is 'output before input does not deadlock the relay' "${out//$'\n'/ }" '1000000 rc=0'
  out="$(yes 2>/dev/null | timeout 30 python3 "${T}/drive.py" "${ROOT}/hdw4s-enter" head -1 2>/dev/null; echo "rc=${PIPESTATUS[1]}")"
  is 'a command that stops reading early still has its output delivered' "${out//$'\n'/ }" 'y rc=0'
  is 'a caller that closed stdin is no obstacle' "$(d sh -c 'echo ok' <&- 2>/dev/null)" 'ok'
  # A reader slower than the command: everything it wrote before exiting
  # arrives. A 2 s drain cap delivered 65536 of 150000 bytes, exit 0 (review).
  out="$(d sh -c 'head -c 150000 /dev/zero' 2>/dev/null | (sleep 3; wc -c); echo "rc=${PIPESTATUS[0]}")"
  is 'a slow reader still gets all the command wrote' "${out//$'\n'/ }" '150000 rc=0'
  if command -v script >/dev/null; then
    # A reader of root's output that leaves early: root's terminal comes back.
    out="$(timeout 30 script -qec "stty -g; python3 '${T}/drive.py' '${ROOT}/hdw4s-enter' seq 1 300000 2>/dev/null | head -1 >/dev/null; stty -g" /dev/null < /dev/null 2>&1 | tr -d '\r')"
    is "root's terminal is restored when its reader leaves early" "$(sort -u <<<"${out}" | wc -l)" '1'
    # Keyboard a terminal, output a pipe that closes early: the terminal is
    # not hung up under the command (it was: SIGHUP, 129 -- review).
    out="$( (sleep 1; printf 'abc'; sleep 1; printf 'def'; sleep 3) | timeout 30 script -qec "python3 '${T}/drive.py' '${ROOT}/hdw4s-enter' sh -c 'sleep 3; exit 0' 2>&1 | head -c 1 >/dev/null; echo rc=\${PIPESTATUS[0]}" /dev/null 2>&1 | tr -d '\r')"
    has 'a closed output pipe does not hang up the command'"'"'s terminal' "${out}" 'rc=0'
    # Root's OUTPUT a terminal, its input a pipe: the input still goes as a pipe.
    out="$(script -qec "python3 '${T}/drive.py' '${ROOT}/hdw4s-enter' sh -c 'wc -c; tty <&2' < '${T}/line'" /dev/null < /dev/null 2>&1 | tr -d '\r')"
    has 'with a terminal for output, piped input still arrives whole' "${out}" '10001'
    has 'and, not being interactive, the command gets no terminal'     "${out}" 'not a tty'
    # Keyboard a terminal, output a pipe ("exec ... | less"): the relay leaves
    # the keyboard alone -- every key went to the command (review) -- and the
    # command reads end-of-file at once.
    out="$( (sleep 1; printf 'abc'; sleep 4) | timeout 30 script -qec "python3 '${T}/drive.py' '${ROOT}/hdw4s-enter' sh -c 'cat; echo EOF-\$?; sleep 2' 2>/dev/null | cat; read -t 5 -n 3 x; echo GOT=\$x" /dev/null 2>&1 | tr -d '\r')"
    has 'with output piped, the command reads end-of-file, not the keyboard' "${out}" 'EOF-0'
    has 'and keys typed meanwhile are left for the next reader'               "${out}" 'GOT=abc'
    # Root's INPUT a terminal: what is typed before the relay starts is kept.
    # Typed ahead, then Ctrl-D while the command runs. (Not both at once: with a
    # PIPE for its own input, script(1) gives its terminal all-zero settings,
    # so a Ctrl-D typed that early is not an end-of-file on any real terminal.)
    out="$( (printf 'typed-ahead\n'; sleep 2; printf '\004'; sleep 2) |
            timeout 20 script -qec "python3 '${T}/drive.py' '${ROOT}/hdw4s-enter' sh -c 'cat; echo CAT-ENDED'" /dev/null 2>&1 | tr -d '\r')"
    # Echoed by the terminal and printed back by cat: the line at least twice.
    is  'input typed before the relay starts is not thrown away' "$(( $(command grep -c 'typed-ahead' <<<"${out}") >= 2 ))" '1'
    has 'and Ctrl-D ends the command'                           "${out}" 'CAT-ENDED'
  else
    skip 'with a terminal for output, piped input still arrives whole' 'no script(1)'
    skip 'and, not being interactive, the command gets no terminal' 'no script(1)'
    skip 'with output piped, the command reads end-of-file, not the keyboard' 'no script(1)'
    skip 'and keys typed meanwhile are left for the next reader' 'no script(1)'
    skip 'input typed before the relay starts is not thrown away' 'no script(1)'
    skip 'and Ctrl-D ends the command' 'no script(1)'
    skip "root's terminal is restored when its reader leaves early" 'no script(1)'
    skip 'a closed output pipe does not hang up the command'"'"'s terminal' 'no script(1)'
  fi
)

echo '== exec: what an administrator types reaches the right unit, or nothing =='
( set +e; sandbox; . "${SB}/setup.sh"
  mkdir -p "${SB}/lib"
  printf '#!/bin/sh\necho "enter $*" > "%s/called"\n' "${SB}" > "${SB}/lib/hdw4s-enter"
  cat > "${SB}/lib/hdw4s-demux" <<STUB
#!/bin/sh
echo "demux \$*" >> "${SB}/demux-called"
case "\$2" in */s/0123456789abcdef*|01234567*) echo '_hdw4s_2 cafe'; exit 0;; esac
echo 'hdw4s: no visitor desktop has had that address since the last boot' >&2; exit 3
STUB
  chmod +x "${SB}/lib/hdw4s-enter" "${SB}/lib/hdw4s-demux"
  printf '0 alice desktop\n1 _hdw4s_2 ephemeral\n' > "${SLOTS}"
  id() { [ "${1:-}" = -u ] && echo "${FAKE_UID:-0}" || command id "$@"; }
  ex() { rm -f "${SB}/called"; ( HDW4S_LIBDIR="${SB}/lib" cmd_exec "$@" ) 2>&1; echo "rc=$?"; }
  r="$(ex alice -- gsettings get a b)"
  is 'a named desktop enters its own unit, with no letting check' "$(cat "${SB}/called" 2>/dev/null)" 'enter hdw4s@alice.service -- gsettings get a b'
  r="$(ex _hdw4s_2 true)"
  is 'a pool seat by name enters the pool unit' "$(cat "${SB}/called" 2>/dev/null)" 'enter hdw4s-ephemeral@_hdw4s_2.service -- true'
  r="$(ex 'https://pool.example/s/0123456789abcdef0123456789abcdef/' -- id)"
  is 'a visitor address enters its seat and re-checks the desktop' "$(cat "${SB}/called" 2>/dev/null)" 'enter hdw4s-ephemeral@_hdw4s_2.service --incarnation _hdw4s_2=cafe -- id'
  r="$(ex deadbeef99 -- id)"
  has 'an address the router refuses stops with its reason' "${r}" 'no visitor desktop has had that address'
  has 'and exit status 125'                                  "${r}" 'rc=125'
  [ -e "${SB}/called" ] && bad 'and nothing is entered' 'hdw4s-enter ran' || ok 'and nothing is entered'
  # Through the real script and its real exit trap, which the sandbox drops:
  # a refusal that explained itself must not also say "failed unexpectedly".
  r="$(HDW4S_ETCDIR="${SB}/etc" HDW4S_LIBDIR="${SB}/lib" PATH="${SB}/bin:${PATH}" \
        bash -c 'id() { [ "${1:-}" = -u ] && echo 0 || command id "$@"; }; export -f id
                 exec "$0" exec deadbeef99 -- true' "${ROOT}/hdw4s" 2>&1; echo "rc=$?")"
  has   'through the real script the refusal is still exit 125' "${r}" 'rc=125'
  hasnt 'and is not reported as an unexpected failure'        "${r}" 'failed unexpectedly'
  rm -f "${SB}/demux-called"
  r="$(ex bob -- id)"
  has 'a name that is no desktop says where names come from' "${r}" "hdw4s list --seats"
  [ -e "${SB}/demux-called" ] && bad 'and asks the router nothing' 'demux was asked' || ok 'and asks the router nothing'
  r="$(FAKE_UID=1000 ex alice -- id)"
  has 'exec is refused to anybody but root' "${r}" 'only root'
  [ -e "${SB}/called" ] && bad 'and enters nothing' 'hdw4s-enter ran' || ok 'and enters nothing'

  # list --seats: the LETTING column is how an address leads to a seat.
  printf '0 alice desktop\n1 _hdw4s_2 ephemeral\n2 _hdw4s_3 ephemeral\n' > "${SLOTS}"
  printf '#!/bin/sh\necho "_hdw4s_2 0123456789abcdef0123456789abcdef 1000"\n' > "${SB}/lib/hdw4s-demux"
  out="$(HDW4S_LIBDIR="${SB}/lib" list_seats 2>&1)"
  has 'list --seats has a LETTING column'                   "${out}" 'LETTING'
  has 'a let seat shows its token prefix' "$(command grep '^_hdw4s_2 ' <<<"${out}")" ' 01234567 '
  hasnt 'and never the whole token'                          "${out}" '0123456789abcdef0123'
  has 'an unlet seat shows -' "$(command grep '^_hdw4s_3 ' <<<"${out}")" ' -  '
  printf '#!/bin/sh\nexit 1\n' > "${SB}/lib/hdw4s-demux"
  out="$(HDW4S_LIBDIR="${SB}/lib" list_seats 2>&1)"
  has 'a failed lookup shows ?, never -' "$(command grep '^_hdw4s_3 ' <<<"${out}")" ' ?  '
  out="$(FAKE_UID=1000 HDW4S_LIBDIR="${SB}/lib" list_seats 2>&1)"
  has 'and without root it says so' "$(command grep '^_hdw4s_3 ' <<<"${out}")" '(root)'
)

echo
# A group that dies partway leaves its remaining assertions unrecorded, which
# looks identical to a shorter suite. Counting them is the only way to notice.
EXPECTED=1725  # update when tests are added; a wrong number is the point
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
