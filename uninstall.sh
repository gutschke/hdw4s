#!/bin/bash -e
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# shellcheck disable=SC2154  # rc is assigned inside the trap itself
trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ "${rc}" -eq 0 ] || {
      tput bel
      echo
      echo "Script ${0} failed unexpectedly" >&2; }
      exit "${rc}"' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root"'
  exit 1
}

# Work out where the installation lives before destroying the units that say so.
dst=''
[ -z "$(systemctl cat hdw4s@.service 2>/dev/null)" ] ||
  dst="$(systemctl cat hdw4s@.service 2>/dev/null |
         sed -n 's|^ExecStart=\(.*\)/hdw4s[^/ ]* .*|\1|p' | head -n1)"
if [ -z "${dst}" ] || [ ! -d "${dst}" ]; then
  # Fall back to resolving the symlink that install.sh left on the PATH.
  link="$(command -v hdw4s 2>/dev/null || :)"
  [ -z "${link}" ] || dst="$(dirname "$(readlink -f "${link}")")"
fi
if [ -z "${dst}" ] || [ ! -d "${dst}" ]; then
  read -r -p 'Install path [/usr/local/lib/hdw4s]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/hdw4s'
fi
# Canonicalised before any guard looks at it. Every check below compares this
# string against a known path, and "/usr/lib/./hdw4s", "//usr/lib/hdw4s" and
# "/usr/lib/hdw4s/" all name the directory the guards mean to protect while
# matching none of them. readlink -m normalises a path that need not exist.
dst="$(readlink -m -- "${dst}")"

# Before anything is stopped or removed. This used to sit beside the other
# guards, hundreds of lines down, where it protected the final "rm -rf" and
# nothing else -- so a .deb install was already missing its units, its firewall
# table, its sysctl drop-in and /opt/selkies by the time the script announced it
# was refusing to touch anything. README offers this script and "apt remove"
# next to each other, so picking the wrong one is an ordinary mistake.
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -S "${dst}" >/dev/null 2>&1; then
  pkg="$(dpkg-query -S "${dst}" 2>/dev/null | head -n1 | cut -d: -f1)"
  echo "hdw4s: ${dst} belongs to the package ${pkg}." >&2
  echo '  This installation came from a package. Removing it here would take' >&2
  echo '  the files out from under dpkg, which would go on reporting the' >&2
  echo '  package as installed and correct. Use instead:' >&2
  echo "    apt remove ${pkg}      # or 'apt purge' to take the configuration too" >&2
  trap '' INT TERM QUIT HUP EXIT ERR
  exit 1
fi

echo -n 'Stopping sessions...'
mapfile -t units < <(systemctl list-units --plain --no-legend --all \
                       'hdw4s@*' 'hdw4s-ephemeral@*' | awk '{print $1}')
[ "${#units[@]}" -eq 0 ] || systemctl disable --now "${units[@]}" >/dev/null 2>&1 || :
# Everything install.sh turned on, in the same order and with nothing left out.
# hdw4s-ephemeral-slots.service was enabled by install.sh from the day the
# feature existed and disabled by nothing, so every uninstall left a dangling
# sysinit.target.wants symlink into a directory it had just deleted -- measured,
# not deduced. That costs a warning at every boot for software that is gone, and
# it is the same defect as the two units below it: two lists that are supposed to
# be each other's inverse, kept by hand, differing by one entry.
#
# .github/checks.sh now fails when this set and the one install.sh enables are
# not the same, and the sweep after the units are removed catches whatever a
# future edit still manages to forget.
systemctl disable --now hdw4s-updater.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-firewall.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-reaper.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-check.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-firewall.service >/dev/null 2>&1 || :
systemctl disable --now hdw4s-ephemeral-slots.service >/dev/null 2>&1 || :
systemctl disable --now hdw4s-demux.socket >/dev/null 2>&1 || :
# The router itself is socket-activated and never enabled, so there is nothing
# to disable -- but it may be RUNNING, and leaving it holding the port would
# outlive the uninstall.
systemctl stop hdw4s-demux.service >/dev/null 2>&1 || :
# The /shared tool's units are templates on a store's path, enabled per store
# (by an administrator, or by hdw4s at boot under /run) and never by
# install.sh, so they are found by their enable links rather than listed. A
# link in a mount unit's .wants is invisible to the target.wants sweep below,
# and an instance left enabled would point into a directory about to go.
for u in $(find /etc/systemd/system /run/systemd/system -path '*.wants/hdw4s-shared-*@*' \
             -printf '%f\n' 2>/dev/null | sort -u) \
         $(systemctl list-units --plain --no-legend --all 'hdw4s-shared-*@*' 2>/dev/null |
           awk '{print $1}'); do
  systemctl disable --now "${u}" >/dev/null 2>&1 || :
done
# The relay sockets, which hold the public ports open until they are stopped.
for u in $(systemctl list-units --plain --no-legend 'hdw4s-proxy@*' 2>/dev/null |
           awk '{print $1}'); do
  systemctl disable --now "${u}" >/dev/null 2>&1 || :
done
echo ' done.'

echo -n 'Removing the firewall table...'
# Only our own table is touched; anything else on the machine is left alone.
if nft list table inet hdw4s >/dev/null 2>&1; then
  nft delete table inet hdw4s || :
fi
echo ' done.'

echo -n 'Removing units...'
# The units install.sh linked, found rather than listed. The list this replaces
# named thirteen of the fifteen: hdw4s-incarnation@.service and
# hdw4s-refuse@.service were linked by install.sh and never unlinked here, so an
# uninstall left two units behind pointing into a directory it had just deleted
# -- "systemctl cat" still answering for software that is gone. Nothing failed,
# which is why it survived a week after being spotted.
#
# Only our own symlinks are touched, and the test is what the link POINTS AT: a
# link into some .../hdw4s/<same name> is one this installer planted, whatever
# path the administrator chose and whatever an earlier install chose before it.
# A regular file of the same name is somebody else's and is left alone, as are
# the drop-in directories "hdw4s enable" writes -- those end in ".service.d"
# and ".socket.d" and are removed by name below.
for u in /etc/systemd/system/hdw4s*.service /etc/systemd/system/hdw4s*.socket \
         /etc/systemd/system/hdw4s*.timer /etc/systemd/system/hdw4s*.slice; do
  [ -L "${u}" ] || continue
  name="$(basename -- "${u}")"
  # readlink, not readlink -f: the target directory has usually been removed by
  # a previous run or is about to be by this one, and -f on a dangling link
  # still resolves but drops the very component being tested for.
  target="$(readlink -- "${u}")"
  [ "${target}" = "${target%"/hdw4s/${name}"}" ] || rm -f -- "${u}"
done
# And the enable state, by the same rule. "systemctl disable" above unlinks a
# unit systemd can still load; once the unit file itself is gone, systemd does
# not know the name any more and disable is a no-op, so a link missed by the
# list is a link nothing will ever remove. This runs after the units precisely
# so that it catches those, and it is the part that does not have to be kept in
# step with anything.
for u in /etc/systemd/system/*.target.wants/hdw4s*; do
  [ -L "${u}" ] || continue
  name="$(basename -- "${u}")"
  target="$(readlink -- "${u}")"
  [ "${target}" = "${target%"/hdw4s/${name}"}" ] || rm -f -- "${u}"
done
# Per-instance state. The glob below never matched anything -- hdw4s@.service
# has no [Install] section, so nothing is ever linked into multi-user.target --
# while the drop-ins and the socket links that "hdw4s enable" really does write
# were left behind. Reinstalling then came back up with stale User= and port
# assignments for slots that had since been handed to somebody else.
rm -f /etc/systemd/system/multi-user.target.wants/hdw4s@*.service \
      /etc/systemd/system/multi-user.target.wants/hdw4s-ephemeral@*.service
rm -f /etc/systemd/system/sockets.target.wants/hdw4s-proxy@*.socket
rm -rf /etc/systemd/system/hdw4s@*.service.d \
       /etc/systemd/system/hdw4s-ephemeral@*.service.d \
       /etc/systemd/system/hdw4s-proxy@*.service.d \
       /etc/systemd/system/hdw4s-proxy@*.socket.d

# Written by "hdw4s firewall --apply" to keep the session ports out of the
# ephemeral range. Nothing else owns it, and leaving it behind reserves ports
# for a package that is no longer installed.
if [ -e /etc/sysctl.d/60-hdw4s.conf ]; then
  rm -f /etc/sysctl.d/60-hdw4s.conf
  sysctl -q --system 2>/dev/null || :
fi
# The relay's group declaration, copied there by install.sh. The group itself is
# left: systemd-sysusers never deletes one, and a gid removed while anything on
# the machine still carries it is a gid the next group created may inherit.
rm -f /etc/sysusers.d/hdw4s-sysusers.conf /etc/sysusers.d/hdw4s-shared-sysusers.conf
# The stream directories, made per session start. /run clears at a reboot; an
# uninstall should not wait for one.
rm -rf --one-file-system /run/hdw4s-stream
# /shared: the timer that re-binds the table, then the table itself and a tmpfs
# store, then the directory desktops bound it from and its tmpfiles line.
#
# NOT UNMOUNTED HERE BY PATH. hdw4s-shared-expose --withdraw takes away only the
# mounts it recorded making, each checked to be the one on top at its path, and
# leaves anything else mounted there where it is: a lazy unmount aimed at the
# wrong mount on a desktop host can take a homes server's bind with it. What it
# leaves, a reboot clears; a tmpfs table's contents go with it, as they would
# then anyway. The /shared mount point on the root filesystem goes only if this
# package made it (the mark) and it is empty -- rmdir, never rm.
systemctl stop hdw4s-shared-expose.timer hdw4s-shared-expose.service >/dev/null 2>&1 || :
if [ -x "${dst}/hdw4s-shared-expose" ]; then
  "${dst}/hdw4s-shared-expose" --withdraw ||
    echo 'Note: something is still mounted under /run/hdw4s-shared*; it was not ours to remove.'
fi
# The root namespace's /shared FIRST, by the same code the package's prerm
# runs: it unmounts only the bind it recorded making, keeps /shared while a
# desktop still runs, and drops the mark only with the directory.
if [ -x "${dst}/hdw4s-ephemeral-slots" ]; then
  "${dst}/hdw4s-ephemeral-slots" --shared-view release-for-removal || :
fi
# Then the directory that bind is made from -- but not while the mark says the
# bind may still stand: removing its source succeeds, and leaves /shared
# showing a deleted directory for ever after.
[ -e /var/lib/hdw4s/.shared-mountpoint ] || rmdir /run/hdw4s-shared 2>/dev/null || :
rmdir /run/hdw4s-shared-store 2>/dev/null || :
rm -f /etc/tmpfiles.d/hdw4s-tmpfiles.conf
# The slot identities and the per-slot drop-ins the minting writes. They live in
# /run and a reboot would clear them, but an uninstall that leaves accounts
# resolving is a surprise nobody needs. /run/userdb is shared with any other
# record provider on the machine, so only records this package wrote are
# touched, matched on the realName this package stamps into them.
for f in /run/userdb/*.user; do
  [ -e "${f}" ] || continue
  grep -q '"realName":"Ephemeral session"' "${f}" 2>/dev/null || continue
  slot="${f%.user}"
  rm -f "${slot}.user" "${slot}.group"
done
rm -rf /run/hdw4s-ns /run/hdw4s-profile /run/systemd/system/hdw4s-ephemeral@*.service.d \
       /run/systemd/journald@hdw4s-*.conf.d /run/systemd/system/systemd-journald@hdw4s-*.service.d
# The settings layer and the policy. Only our own profile and database are
# touched; /etc/dconf/profile/user belongs to every session on the machine.
rm -rf /etc/dconf/db/hdw4s-ephemeral.d /etc/dconf/db/hdw4s-ephemeral \
       /etc/dconf/db/hdw4s-named.d /etc/dconf/db/hdw4s-named \
       /etc/dconf/db/hdw4s-template.d /etc/dconf/db/hdw4s-template \
       /etc/dconf/profile/hdw4s-author \
       /etc/dconf/profile/hdw4s-ephemeral /etc/hdw4s/chrome-policies \
       /etc/hdw4s/chrome-author-policy.json /etc/polkit-1/rules.d/60-hdw4s-slots.rules
rmdir --ignore-fail-on-non-empty /etc/opt/chrome/policies/managed \
      /etc/opt/chrome/policies 2>/dev/null || :
if command -v dconf >/dev/null 2>&1; then dconf update 2>/dev/null || :; fi

systemctl daemon-reload
echo ' done.'

echo -n 'Removing files...'
# The install path is discovered rather than known, so check it before handing
# it to rm. Three tests, because refusing a list of obvious names is not enough:
# the thing that must never happen is deleting somebody's home directory, and a
# home directory is not a fixed name.
unsafe=''
# 0. Never a path some package owns. Without this the fallback below happily
#    resolves to the directory the .deb installs into, and rm -rf takes the
#    package's payload out from under dpkg, which goes on reporting it as
#    installed. README offers this script and "apt remove" side by side, so
#    reaching for the wrong one is an ordinary mistake, not an exotic one.
# 1. Never a directory that holds other things: only ever our own.
[ "$(basename -- "${dst}")" = 'hdw4s' ] ||
  unsafe="it is not a directory named hdw4s"
# 2. Never a well-known location, however it was spelled.
case "${dst}" in
  /|/usr|/usr/bin|/usr/sbin|/usr/lib|/usr/local|/usr/local/bin|/usr/local/sbin|/usr/local/lib|/etc|/var|/var/lib|/home|/root|/srv|/opt|/boot|/dev|/proc|/sys)
    unsafe='it is a system location'
    ;;
esac
# 3. Never inside an account's home, whatever that account calls it.
if [ -z "${unsafe}" ]; then
  while IFS=: read -r _ _ _ _ _ home _; do
    case "${home}" in ''|/|/nonexistent|/dev/null) continue;; esac
    case "${dst}/" in
      "${home}"/*) unsafe='it is inside the home directory of an account'; break;;
    esac
  done < /etc/passwd
fi
if [ -n "${unsafe}" ]; then
  echo " skipped: refusing to remove ${dst}, ${unsafe}."
else
  rm -rf "${dst}"
  echo ' done.'
fi

# install.sh derives this prefix from the install path, so a tree under
# neither /usr nor /usr/local left its symlink and its manual page behind --
# a dangling link on the PATH, and a manual for software that is gone.
case "${dst}" in
  /usr/local/*) own='/usr/local';;
  /usr/*)       own='/usr';;
  *)            own="${dst%/lib/hdw4s}";;
esac
for sys in /usr/local /usr "${own}"; do
  [ -n "${sys}" ] || continue
  # install.sh links into sbin, so bin alone left the real symlink dangling.
  [ ! -L "${sys}/sbin/hdw4s" ] || rm -f "${sys}/sbin/hdw4s"
  [ ! -L "${sys}/sbin/hdw4s-shared-sweep" ] || rm -f "${sys}/sbin/hdw4s-shared-sweep"
  [ ! -L "${sys}/bin/hdw4s" ] || rm -f "${sys}/bin/hdw4s"
  [ ! -e "${sys}/share/man/man8/hdw4s.8.gz" ] ||
    rm -f "${sys}/share/man/man8/hdw4s.8.gz"
  [ ! -e "${sys}/share/man/man8/hdw4s-shared-sweep.8.gz" ] ||
    rm -f "${sys}/share/man/man8/hdw4s-shared-sweep.8.gz"
done
mandb -q 2>/dev/null || :

echo 'Removing Selkies...'
# /opt/selkies belongs to the "selkies" package now, not to us: upstream ships
# a distribution package and dpkg owns every file under that prefix. Removing it
# with rm would leave dpkg believing the package is installed while its files are
# gone, which breaks the next upgrade and is invisible until then.
#
# So the streaming server is removed the way it was installed, and only if it is
# actually there. This script runs on its own, not from inside a maintainer
# script, so it may call dpkg -- which is precisely why debian/postrm cannot,
# and prints an instruction instead.
#
# Not "|| :". A removal that fails and says nothing is how the package survived
# every purge before this: the message below is what tells somebody that
# 153MB of streaming server is still installed.
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -W -f='${Status}' selkies 2>/dev/null | grep -q 'install ok installed'; then
  if dpkg -P selkies; then
    echo '  Removed the selkies package.'
  else
    echo '  Could not remove the selkies package; it is still installed.' >&2
    echo '  Remove it with "apt-get purge selkies".' >&2
  fi
else
  echo '  The selkies package is not installed.'
fi
# Ours, with no other owner: the pre-2.0 browser client, the virtualenv the
# updater moved aside during the migration, and the cached .deb it kept so an
# upgrade had something to roll back to.
rm -rf /opt/gst-web /opt/gst-web.bak /opt/selkies.bak /opt/selkies.pre-2.0
rm -rf /var/lib/hdw4s/selkies
echo ' done.'

# Per-session settings and the profile directories under each home are left in
# place on purpose: they are the administrator's configuration and the users'
# desktop state, not ours to delete. Removing them silently would destroy work
# on a reinstall that was only meant to move the software.
cat <<EOF

Uninstalled.

Left behind deliberately:
  /etc/hdw4s/            per-session configuration
  /var/lib/hdw4s/        each session's separate desktop profile, if any

Remove them by hand if you are sure you want them gone.

EOF
