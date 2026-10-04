#!/bin/bash -e
# Restart a session and report whether it REACHED READY -- correctly.
#
# Written after getting this wrong three times in one evening, each time with a
# control that failed and therefore a measurement that meant nothing:
#
#   * a synthetic account with /nonexistent as its home cannot bring up a
#     desktop at all, so both arms failed for a reason unrelated to the test.
#   * giving it a local home was not enough either; the account still could not
#     start a session.
#   * backgrounding "systemctl start" and polling raced the next arm's stop,
#     which killed the session mid-startup and reported status 143. The unit is
#     Type=notify: start BLOCKS until the session is ready, and polling it is
#     both unnecessary and wrong.
#
# So: use a session type that demonstrably starts, start it SYNCHRONOUSLY, and
# report the three facts that distinguish "the product refused" from "the rig
# broke" -- the active state, the result, and the exit status.
#
# usage: session-restart.sh <ssh-target> <unit> [timeout-seconds]
LC_ALL=C; PATH=/usr/sbin:/usr/bin:/sbin:/bin
[ "$#" -ge 2 ] || { echo "usage: $0 <ssh-target> <unit> [timeout]" >&2; exit 2; }
TARGET="$1"; UNIT="$2"; T="${3:-120}"

# The unit and the timeout are expanded HERE, on purpose; everything the far
# side must expand is escaped.
# shellcheck disable=SC2087
ssh -o ConnectTimeout=10 "${TARGET}" "bash -s" <<REMOTE
set -u
unit='${UNIT}'
systemctl stop "\$unit" >/dev/null 2>&1 || :
systemctl reset-failed "\$unit" >/dev/null 2>&1 || :
sleep 2
# Synchronous, with systemd's own timeout doing the waiting. A non-zero exit
# here is the product refusing; a timeout is the rig being too impatient, and
# the two must not look alike.
timeout ${T} systemctl start "\$unit" >/tmp/sr.out 2>&1; rc=\$?
printf 'unit          : %s\n' "\$unit"
printf 'start exit    : %s%s\n' "\$rc" "\$([ \$rc -eq 124 ] && echo '  <- TIMED OUT, rig too impatient' || true)"
printf 'ActiveState   : %s\n' "\$(systemctl show -p ActiveState --value "\$unit")"
printf 'Result        : %s\n' "\$(systemctl show -p Result --value "\$unit")"
printf 'ExecMainStatus: %s\n' "\$(systemctl show -p ExecMainStatus --value "\$unit")"
[ -s /tmp/sr.out ] && { echo 'systemctl said:'; sed 's/^/  /' /tmp/sr.out; }
rm -f /tmp/sr.out
REMOTE
