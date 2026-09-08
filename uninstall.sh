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
dst="${dst%/}"

echo -n 'Stopping sessions...'
mapfile -t units < <(systemctl list-units --plain --no-legend --all 'hdw4s@*' |
                     awk '{print $1}')
[ "${#units[@]}" -eq 0 ] || systemctl disable --now "${units[@]}" >/dev/null 2>&1 || :
systemctl disable --now hdw4s-updater.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-firewall.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-reaper.timer >/dev/null 2>&1 || :
systemctl disable --now hdw4s-firewall.service >/dev/null 2>&1 || :
systemctl disable --now hdw4s-updater.timer >/dev/null 2>&1 || :
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
rm -f /etc/systemd/system/hdw4s@.service \
      /etc/systemd/system/hdw4s-proxy@.service \
      /etc/systemd/system/hdw4s-proxy@.socket \
      /etc/systemd/system/hdw4s.slice \
      /etc/systemd/system/hdw4s-firewall.service \
      /etc/systemd/system/hdw4s-firewall-check.service \
      /etc/systemd/system/hdw4s-firewall.timer \
      /etc/systemd/system/hdw4s-updater.service \
      /etc/systemd/system/hdw4s-updater.timer \
      /etc/systemd/system/hdw4s-reaper.service \
      /etc/systemd/system/hdw4s-reaper.timer
# Per-instance state. The glob below never matched anything -- hdw4s@.service
# has no [Install] section, so nothing is ever linked into multi-user.target --
# while the drop-ins and the socket links that "hdw4s enable" really does write
# were left behind. Reinstalling then came back up with stale User= and port
# assignments for slots that had since been handed to somebody else.
rm -f /etc/systemd/system/multi-user.target.wants/hdw4s@*.service
rm -f /etc/systemd/system/sockets.target.wants/hdw4s-proxy@*.socket
rm -rf /etc/systemd/system/hdw4s@*.service.d \
       /etc/systemd/system/hdw4s-proxy@*.service.d \
       /etc/systemd/system/hdw4s-proxy@*.socket.d

# Written by "hdw4s firewall --apply" to keep the session ports out of the
# ephemeral range. Nothing else owns it, and leaving it behind reserves ports
# for a package that is no longer installed.
if [ -e /etc/sysctl.d/60-hdw4s.conf ]; then
  rm -f /etc/sysctl.d/60-hdw4s.conf
  sysctl -q --system 2>/dev/null || :
fi
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
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -S "${dst}" >/dev/null 2>&1; then
  unsafe="it belongs to the package $(dpkg-query -S "${dst}" 2>/dev/null |
                                      head -n1 | cut -d: -f1); use apt remove"
fi
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

for sys in /usr/local /usr; do
  # install.sh links into sbin, so bin alone left the real symlink dangling.
  [ ! -L "${sys}/sbin/hdw4s" ] || rm -f "${sys}/sbin/hdw4s"
  [ ! -L "${sys}/bin/hdw4s" ] || rm -f "${sys}/bin/hdw4s"
  [ ! -e "${sys}/share/man/man8/hdw4s.8.gz" ] ||
    rm -f "${sys}/share/man/man8/hdw4s.8.gz"
done
mandb -q 2>/dev/null || :

echo -n 'Removing Selkies...'
rm -rf /opt/selkies /opt/selkies.bak /opt/gst-web /opt/gst-web.bak
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
