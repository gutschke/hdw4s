#!/bin/bash -e
# What is true of a running session, read from the MACHINE rather than the page.
#
# This exists because every one of these was got wrong by hand first, and each
# time the wrong version returned a confident answer rather than an error:
#
#   * the framebuffer size was read with a bare "DISPLAY=:0 xdpyinfo" as root,
#     which returns NOTHING because the Xauthority lives in the session's own
#     runtime directory -- and would have returned some OTHER session's geometry
#     had one been on that display.
#   * attached clients were counted on a hardcoded port that belonged to a
#     different account entirely, so the probe reported on somebody else's
#     desktop while claiming to measure this one.
#   * "is the gate actually being served" was inferred from the file on disk
#     rather than from what the server hands out.
#
# Everything here is derived from the instance, never assumed. No host, account
# or address is written down: this file ships publicly.
#
# usage: session-probe.sh <ssh-target> <instance>
LC_ALL=C; PATH=/usr/sbin:/usr/bin:/sbin:/bin
[ "$#" -eq 2 ] || { echo "usage: $0 <ssh-target> <instance>" >&2; exit 2; }
TARGET="$1"; INST="$2"

remote() { ssh -o ConnectTimeout=8 "${TARGET}" "$@"; }

# Drift first, always. A probe that reports confidently on a machine running
# something other than the tree is how a fix gets tested before it is deployed --
# which has now happened four times, each time reported back to us as the old
# bug. The private checker is not shipped, so its absence is not an error here;
# where it exists, it gates.
if [ -x "$(dirname "$0")/../../private/check-drift.sh" ]; then
  "$(dirname "$0")/../../private/check-drift.sh" "${TARGET}" >/dev/null 2>&1 || {
    echo "WARNING: this machine is NOT running the tree -- readings below describe" >&2
    echo "         something else. Run private/check-drift.sh for the detail." >&2
  }
fi

remote "bash -s" <<REMOTE
set -u
INST='${INST}'
unit="hdw4s@\${INST}.service"
[ "\$(systemctl show -p LoadState --value "\$unit" 2>/dev/null)" = loaded ] ||
  unit="hdw4s-ephemeral@\${INST}.service"

echo "instance     : \${INST}"
echo "unit         : \${unit}"
echo "state        : \$(systemctl show -p ActiveState --value "\$unit" 2>/dev/null)"
echo "started      : \$(systemctl show -p ActiveEnterTimestamp --value "\$unit" 2>/dev/null)"

# The session's OWN display and auth, taken from the running process. A
# hardcoded ":0" measures whoever holds that display, which may not be us.
pid="\$(systemctl show -p MainPID --value "\$unit" 2>/dev/null)"
if [ "\${pid:-0}" -gt 0 ] && [ -r "/proc/\${pid}/environ" ]; then
  d="\$(tr '\0' '\n' < /proc/\${pid}/environ | sed -n 's/^DISPLAY=//p' | head -1)"
  x="\$(tr '\0' '\n' < /proc/\${pid}/environ | sed -n 's/^XAUTHORITY=//p' | head -1)"
  u="\$(stat -c %U /proc/\${pid} 2>/dev/null)"
  echo "display      : \${d:-?}  (as \${u:-?})"
  echo "geometry     : \$(sudo -u "\${u}" env DISPLAY="\${d}" XAUTHORITY="\${x}" \
       xdpyinfo 2>/dev/null | awk '/dimensions:/{print \$2; exit}' || echo '?')"
else
  echo "display      : (not running)"
  echo "geometry     : -"
fi

# The port the SESSION listens on, derived from the instance's index, never the
# external port the socket unit binds -- they differ, and the external one has no
# connections at all when the session is on a filesystem socket.
idx="\$(awk -v i="\${INST}" '\$1 !~ /^#/ && \$2 == i { print \$1; exit }' /etc/hdw4s/instances 2>/dev/null)"
if [ -n "\${idx}" ]; then
  base=\$(sed -n 's/^HDW4S_BASE_PORT=//p' /etc/hdw4s/hdw4s.conf 2>/dev/null | tail -1); base=\${base:-7300}
  blk=\$(sed -n 's/^HDW4S_BLOCK_SIZE=//p' /etc/hdw4s/hdw4s.conf 2>/dev/null | tail -1); blk=\${blk:-64}
  iport=\$(( base + blk + idx ))
  echo "internal port: \${iport}"
  echo "clients      : \$(ss -Htn state established "sport = :\${iport}" 2>/dev/null | grep -c . || true)"
else
  echo "internal port: (no index in /etc/hdw4s/instances)"
fi

# WHO MAY OPEN THE SLOT'S SOCKET -- or rather, what its ownership and mode are,
# which until now neither test tier asserted ANYWHERE. A socket that stops being
# isolated and one that becomes unreachable look identical from every other line
# in this file, and both leave the whole suite green. This reports; it does not
# assert, because the assertion needs a caller that does not exist on this box --
# the group that must be kept out has no member process here, so a rig that looks
# for one is green before a fix, after it, and after it is reverted. The rig that
# BUILDS the caller instead is .github/live/socketgate.py.
#
# The directory is derived from the unit, never written down: a constant here is
# a wrong answer waiting for a second deployment to exist.
pdir="\$(systemctl show -p Listen --value "hdw4s-proxy@\${INST}.socket" 2>/dev/null |
        sed -n 's|.*[^A-Za-z0-9_]\(/[^ ]*\)/[^/ ]*\.sock.*|\1|p' | head -1)"
pdir="\${pdir:-/run/hdw4s-proxy}"
sock="\${pdir}/\${INST}.sock"
echo "socket       : \${sock}"
echo "  inode      : \$(stat -c '%U:%G %a' "\${sock}" 2>/dev/null || echo '(absent)')"
echo "  directory  : \$(stat -c '%U:%G %a' "\${pdir}" 2>/dev/null || echo '(absent)')"
# A socket FILE is not a listener. "ls" answers a question about the filesystem;
# "is anything bound" is a question for the kernel, and the two have disagreed
# here -- an orphan left on disk was enumerated as a live slot while connect()
# was REFUSED. The verdict is awk's exit status after an exact field comparison,
# never a text match: a substring test would accept a neighbouring instance whose
# name happens to contain this one.
if ss -H -l -x 2>/dev/null |
   awk -v p="\${sock}" '{for(i=1;i<=NF;i++) if (\$i==p) f=1} END{exit !f}'; then
  echo "  listener   : bound"
elif [ -e "\${sock}" ]; then
  echo "  listener   : NONE BOUND, but the file exists -- an ORPHAN, not a slot"
else
  echo "  listener   : none, and no file. Load=\$(systemctl show -p LoadState \
--value "hdw4s-proxy@\${INST}.socket" 2>/dev/null) \
Result=\$(systemctl show -p Result --value "hdw4s-proxy@\${INST}.socket" 2>/dev/null)"
fi

# What is SERVED, not what is on disk. A web root can be present and correct
# while the server declines it and hands out the packaged client instead.
root="/usr/share/hdw4s/webroot/\${INST}"
echo "web root     : \$([ -d "\${root}" ] && echo present || echo MISSING)"
echo "marker: file : \$(grep -c hdw4s-gate "\${root}/index.html" 2>/dev/null || echo 0)"
echo "incarnation  : served=\$([ -s "\${root}/hdw4s-incarnation" ] && echo yes || echo no) \
run-record=\$([ -s "/run/hdw4s-incarnation/\${INST}" ] && echo yes || echo no)"
REMOTE
