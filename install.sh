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

src="$(cd "$(dirname "$0")" && pwd)"
SOURCES=(hdw4s{,-session,-run-session,-firewall,-update,-wait}
         hdw4s{.8,.8.md,.xorg.conf,.conf,.slice}
         hdw4s@.service hdw4s-proxy@.socket hdw4s-proxy@.service
         hdw4s-firewall.service
         hdw4s-firewall-check.service hdw4s-firewall.timer
         hdw4s-updater.{service,timer} hdw4s-reaper.{service,timer}
         install.sh uninstall.sh LICENSE)

for f in "${SOURCES[@]}"; do
  [ -e "${src}/${f}" ] || {
    echo "Missing ${f}; run this script from a complete checkout." >&2
    exit 1
  }
done

# Dependency check. Everything here is in the Ubuntu/Debian archive, so name the
# package rather than making the admin work out what provides a binary.
declare -A NEEDS=(
  [/usr/lib/xorg/Xorg]='xserver-xorg-core'
  [/usr/lib/xorg/modules/drivers/dummy_drv.so]='xserver-xorg-video-dummy'
  [/usr/bin/xauth]='xauth'
  [/usr/bin/dbus-run-session]='dbus-daemon'
  [/usr/bin/dbus-update-activation-environment]='dbus-bin'
  [/usr/bin/gnome-session]='gnome-session'
  [/usr/sbin/nft]='nftables'
  [/usr/bin/curl]='curl'
)
missing=''
for path in "${!NEEDS[@]}"; do
  [ -e "${path}" ] || missing="${missing} ${NEEDS[${path}]}"
done

# The venv module is a separate package on Debian and Ubuntu, and its absence is
# the single most common reason a Python install fails here.
python3 -c 'import venv' >&/dev/null || missing="${missing} python3-venv"

# Selkies 1.6.x renders through GStreamer and reaches it through the system
# PyGObject bindings, which are not installable from PyPI.
python3 -c 'import gi' >&/dev/null || missing="${missing} python3-gi"
[ -e /usr/lib/x86_64-linux-gnu/girepository-1.0/Gst-1.0.typelib ] ||
  [ -e /usr/lib/girepository-1.0/Gst-1.0.typelib ] ||
  missing="${missing} gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0
           gstreamer1.0-plugins-base gstreamer1.0-plugins-good
           gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly
           gstreamer1.0-tools gstreamer1.0-x"

[ -z "${missing}" ] || {
  echo 'Error: required packages are missing. Install them with:'
  echo
  echo "  apt install$(printf '%s' "${missing}" | tr -s '[:space:]' ' ')"
  echo
  exit 1
}

# An audio server is optional: a session without one still streams video, and
# which of the two is present depends on the release.
[ -x /usr/bin/pulseaudio ] || [ -x /usr/bin/pipewire ] ||
  echo 'Warning: neither pulseaudio nor pipewire found; sessions will be silent.'

U="$(tput smul 2>/dev/null || :)"
R="$(tput rmul 2>/dev/null || :)"

while :; do
  read -r -p 'Install path [/usr/local/lib/hdw4s]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/hdw4s'
  case "${dst}" in
    /*) break;;
  esac
  echo 'Please give an absolute path.'
done
dst="${dst%/}"

# Derive the matching prefixes, so an install into /usr/local puts the symlink
# in /usr/local/bin and the man page in /usr/local/share/man.
case "${dst}" in
  /usr/local/*) sys='/usr/local';;
  /usr/*)       sys='/usr';;
  *)            sys="${dst%/lib/hdw4s}";;
esac
# Checked before anything is copied. A prefix that does not end in /lib/hdw4s
# left sys pointing at the payload directory itself, and the run failed at the
# symlink -- after the files were in place and before any unit was linked,
# which is the least useful moment to stop.
case "${dst}" in
  */lib/hdw4s) ;;
  *) echo >&2
     echo "hdw4s: the install path has to end in /lib/hdw4s; got '${dst}'." >&2
     echo "  Try /usr/lib/hdw4s or /usr/local/lib/hdw4s." >&2
     exit 1;;
esac
# The path is interpolated into a sed replacement and into unit files. A
# backslash becomes a back-reference and aborts the rewrite after the copy; a
# space makes systemd read ExecStart= as two words; a percent is a systemd
# specifier. Restrict to what is unambiguous in all three.
case "${dst}" in
  *[!A-Za-z0-9/._-]*)
    echo "hdw4s: the install path may only contain letters, digits, and / . _ -" >&2
    echo "  got '${dst}'" >&2
    exit 1;;
esac
[ -n "${sys}" ] || {
  echo "hdw4s: cannot derive a prefix from '${dst}'." >&2
  exit 1
}
man="${sys}/share/man/man8"

echo -n 'Installing files...'
install -d -m0755 "${dst}" "${dst}/wrappers" "${sys}/sbin" "${man}" /etc/hdw4s
# Re-running the installed copy and accepting the same path makes src and dst
# the same directory, and cp then refuses -- with the generic "failed
# unexpectedly" line, which says nothing about why.
if [ "${src}" != "${dst}" ]; then
  for f in "${SOURCES[@]}"; do
    cp -f "${src}/${f}" "${dst}/${f}"
  done
  cp -f "${src}"/wrappers/* "${dst}/wrappers/"
fi
chmod 0755 "${dst}"/hdw4s "${dst}"/hdw4s-{session,run-session,firewall,update,wait} \
           "${dst}"/{install,uninstall}.sh "${dst}"/wrappers/*
chmod 0644 "${dst}"/*.service "${dst}"/*.timer "${dst}"/*.slice \
           "${dst}"/*.conf "${dst}"/hdw4s.8*

# The configuration file is the administrator's once it exists; never overwrite
# an edited one on reinstall.
[ -e /etc/hdw4s/hdw4s.conf ] ||
  cp -f "${src}/hdw4s.conf" /etc/hdw4s/hdw4s.conf

# The units are symlinked rather than copied, so the shipped copy under ${dst}
# stays the single source of truth. That only works if the paths inside them
# point at wherever the administrator chose to install.
# Every file that mentions the path, found rather than listed. The list this
# replaces named four files and missed five, so a checkout installed anywhere
# but the packaging default produced a system where no session could start:
# hdw4s-session execs hdw4s-run-session by absolute path, and the proxy, reaper
# and firewall-restore units do the same. A list is exactly what goes stale
# when a file is added.
if [ "${dst}" != '/usr/lib/hdw4s' ]; then
  # Not this script: its own help text names the default path, and rewriting
  # that leaves the installed copy differing from the one in the repository for
  # no benefit.
  grep -rl -- '/usr/lib/hdw4s' "${dst}" 2>/dev/null |
    grep -v '/install\.sh$' | while IFS= read -r f; do
      sed -i "s|/usr/lib/hdw4s|${dst}|g" -- "${f}"
    done
  # Only meaningful when the new path does not itself contain the old one.
  # /srv/usr/lib/hdw4s rewrites correctly and then matches this grep, which
  # aborted a perfectly good install in exactly the half-finished state the
  # rewrite exists to avoid.
  case "${dst}" in
    */usr/lib/hdw4s) ;;
    *) if grep -rl -- '/usr/lib/hdw4s' "${dst}" 2>/dev/null |
            grep -qv '/install\.sh$'; then
         echo >&2
         echo "hdw4s: could not rewrite the install path in:" >&2
         grep -rl -- '/usr/lib/hdw4s' "${dst}" 2>/dev/null |
           grep -v '/install\.sh$' | sed 's|^|  |' >&2
         exit 1
       fi;;
  esac
fi
echo ' done.'

echo -n 'Linking...'
ln -sf "${dst}/hdw4s" "${sys}/sbin/hdw4s"
for u in hdw4s@.service hdw4s.slice hdw4s-firewall.service \
         hdw4s-proxy@.socket hdw4s-proxy@.service \
         hdw4s-firewall-check.service hdw4s-firewall.timer \
         hdw4s-updater.service hdw4s-updater.timer \
         hdw4s-reaper.service hdw4s-reaper.timer; do
  ln -sf "${dst}/${u}" "/etc/systemd/system/${u}"
done
echo ' done.'

echo -n 'Installing documentation...'
gzip -9c "${dst}/hdw4s.8" > "${man}/hdw4s.8.gz"
mandb -q 2>/dev/null || :
echo ' done.'

echo 'Fetching Selkies...'
"${dst}/hdw4s-update" || {
  echo 'Could not fetch Selkies now; the daily timer will retry.'
}

systemctl daemon-reload
systemctl enable --now hdw4s-firewall.service
systemctl enable --now hdw4s-firewall.timer
systemctl enable --now hdw4s-updater.timer
systemctl enable --now hdw4s-reaper.timer

# Deliberately no session is started: which accounts get a desktop is a
# decision for the administrator, not for an installer.
cat <<EOF

Installed into ${dst}.

Before starting a session, list the address of the reverse proxy that will
sit in front of these desktops:

  ${U}editor /etc/hdw4s/hdw4s.conf${R}      set HDW4S_PROXIES
  ${U}hdw4s firewall --apply${R}

Until that is done, sessions accept connections from this machine only. They
run with authentication switched off, so whatever can reach a session port
gets that user's desktop.

Then:

  1. Give an account a desktop:
       ${U}hdw4s enable <username>${R}

  2. See what it was assigned, and point the proxy at it:
       ${U}hdw4s list${R}

  3. Check on it:
       ${U}systemctl status hdw4s@<username>${R}
       ${U}journalctl -xeu hdw4s@<username>${R}

  4. If the account's home directory is shared with another desktop, set
     ${U}HDW4S_ISOLATION=profile${R} in /etc/hdw4s/<username>.conf and read
     the SHARED HOME DIRECTORIES section of:
       ${U}man hdw4s${R}

  5. To remove everything again:
       ${U}${dst}/uninstall.sh${R}

EOF
