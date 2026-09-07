#!/bin/bash -e
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

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
         sed -n 's|^ExecStart=\(.*\)/hdw4s .*|\1|p' | head -n1)"
[ -n "${dst}" ] && [ -d "${dst}" ] || {
  link="$(command -v hdw4s 2>/dev/null || :)"
  [ -z "${link}" ] || dst="$(dirname "$(readlink -f "${link}")")"
}
[ -n "${dst}" ] && [ -d "${dst}" ] || {
  read -p 'Install path [/usr/local/lib/hdw4s]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/hdw4s'
}
dst="${dst%/}"

echo -n 'Stopping sessions...'
mapfile -t units < <(systemctl list-units --plain --no-legend --all 'hdw4s@*' |
                     awk '{print $1}')
[ "${#units[@]}" -eq 0 ] || systemctl disable --now "${units[@]}" >/dev/null 2>&1 || :
systemctl disable --now hdw4s-updater.timer >/dev/null 2>&1 || :
echo ' done.'

echo -n 'Removing the firewall table...'
# Only our own table is touched; anything else on the machine is left alone.
nft list table inet hdw4s >/dev/null 2>&1 && nft delete table inet hdw4s || :
echo ' done.'

echo -n 'Removing units...'
rm -f /etc/systemd/system/hdw4s@.service \
      /etc/systemd/system/hdw4s-updater.service \
      /etc/systemd/system/hdw4s-updater.timer
rm -f /etc/systemd/system/multi-user.target.wants/hdw4s@*.service
systemctl daemon-reload
echo ' done.'

echo -n 'Removing files...'
case "${dst}" in
  /|/usr|/usr/bin|/usr/lib|/usr/local|/usr/local/bin|/usr/local/lib|/etc|/home)
    echo ' skipped (unsafe path).'
    ;;
  *)
    rm -rf "${dst}"
    echo ' done.'
    ;;
esac

for sys in /usr/local /usr; do
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
  ~/.local/state/hdw4s/  each user's separate desktop profile, if any

Remove them by hand if you are sure you want them gone.

EOF
