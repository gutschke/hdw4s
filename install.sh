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
SOURCES=(hdw4s{,-session,-run-session,-firewall,-update,-wait,-duration,-template}
         hdw4s-is-slot hdw4s-slot-scrub 60-hdw4s-slots.rules
         hdw4s{.8,.8.md,.xorg.conf,.conf,.slice}
         hdw4s@.service hdw4s-ephemeral@.service hdw4s-ephemeral-slots.service
         hdw4s-ephemeral-slots hdw4s-webroot hdw4s-gate-index hdw4s-names.js
         hdw4s-title.js
         hdw4s-refuse hdw4s-refuse@.service
         hdw4s-teardown hdw4s-teardown@.service hdw4s-teardown@.path
         hdw4s-slot-scrub@.service
         hdw4s-start hdw4s-start@.service hdw4s-start@.path
         hdw4s-incarnation hdw4s-incarnation@.service
         hdw4s-stream-dir hdw4s-stream@.service hdw4s-sysusers.conf
         hdw4s-selkies-webrtc
         hdw4s-proxy@.socket hdw4s-proxy@.service
         hdw4s-demux hdw4s-demux.socket hdw4s-demux.service
         hdw4s-firewall.service
         hdw4s-firewall-check.service hdw4s-firewall.timer
         dconf/profile dconf/profile-author dconf/10-policy dconf/locks/10-policy \
         dconf/named-lock dconf/locks/named-lock
         chrome-policies/hdw4s-ephemeral.json chrome-policies/hdw4s-author.json
         chrome-author-policy.json
         hdw4s-updater.{service,timer} hdw4s-reaper.{service,timer}
         hdw4s-shared-sweep hdw4s-shared-sweep.8 hdw4s-shared-sweep@.{service,timer}
         hdw4s-shared-{harden,watch,relay-server,relay-client}@.service
         hdw4s-shared-sysusers.conf
         hdw4s-check.{service,timer}
         hdw4s-shared-expose hdw4s-shared-expose.{service,timer} hdw4s-tmpfiles.conf
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

# What the streaming server needs, which since Selkies 2.0 is not Python at
# all. It ships as a distribution package carrying its own interpreter, its own
# Xlib and its own encoders, so the whole GStreamer and PyGObject list that used
# to live here went with the virtualenv. What is left is the shared libraries
# its extension modules link against and the two programs it forks.
#
# The libraries are checked through the package manager rather than by looking
# for a file, because a missing one does not stop Selkies starting: it logs a
# single line about striped encoding being unavailable and then serves a desktop
# that cannot encode. libva-x11-2 is the one that actually goes missing on a
# server install.
for pkg in libpulse0 libxcb1 libxkbcommon0 libx11-xcb1 libva2 libva-drm2 \
           libva-x11-2 libdrm2 libgbm1 libegl1 libwayland-server0 \
           libpixman-1-0 libxcb-render0 libxcb-shm0 libxcb-dri3-0 libxfixes3 \
           libxext6 libice6 libsm6; do
  [ "$(dpkg-query -W -f='${db:Status-Status}' "${pkg}" 2>/dev/null)" = 'installed' ] ||
    missing="${missing} ${pkg}"
done

# Three programs the streaming server forks, which no library check can see.
# xdotool is the fallback for every keysym XTEST cannot inject directly, and
# xset and xrandr are read and driven by the input and resize paths. xsel is
# gone: the clipboard is handled in-process now.
command -v xdotool >/dev/null || missing="${missing} xdotool"
command -v xrandr  >/dev/null || missing="${missing} x11-xserver-utils"
command -v xset    >/dev/null || missing="${missing} x11-xserver-utils"

# Not fatal, so not in the list above: Selkies drives the sound server through
# its own bundled bindings and only falls back to forking pactl when those
# cannot connect.
command -v pactl >/dev/null ||
  echo 'Note: pulseaudio-utils is not installed. Selkies will not be able to
      fall back to "pactl" if its own sound-server bindings fail.'

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
install -d -m0755 "${dst}" "${dst}/wrappers" "${dst}/dconf/locks" \
                  "${dst}/chrome-policies" "${sys}/sbin" "${man}" /etc/hdw4s
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
           "${dst}"/hdw4s-duration "${dst}"/hdw4s-template \
           "${dst}"/hdw4s-is-slot "${dst}"/hdw4s-slot-scrub "${dst}"/hdw4s-shared-sweep \
           "${dst}"/hdw4s-ephemeral-slots "${dst}"/hdw4s-webroot \
           "${dst}"/hdw4s-gate-index "${dst}"/hdw4s-refuse \
           "${dst}"/hdw4s-incarnation "${dst}"/hdw4s-stream-dir \
           "${dst}"/hdw4s-shared-expose \
           "${dst}"/{install,uninstall}.sh "${dst}"/wrappers/*
# Imported, not executed: the systemd units, and the WebRTC signalling adapter
# that /opt/selkies/bin/python loads.
chmod 0644 "${dst}"/hdw4s-selkies-webrtc "${dst}"/*.service "${dst}"/*.timer "${dst}"/*.slice \
           "${dst}"/*.conf "${dst}"/hdw4s.8* "${dst}"/hdw4s-shared-sweep.8 \
           "${dst}"/hdw4s-names.js \
           "${dst}"/hdw4s-title.js

# The settings layer every ephemeral session starts from, and the Chrome policy
# that is visible only inside one.
#
# The dconf files are package-owned and are rewritten on every install: they are
# ours, the administrator's own additions belong in the hdw4s-template database
# above them ("hdw4s template edit"), and an install that left a stale lockdown
# in place would be the kind of difference nobody looks for.
install -d -m0755 /etc/dconf/profile /etc/dconf/db/hdw4s-ephemeral.d/locks \
                  /etc/dconf/db/hdw4s-template.d /etc/dconf/db/hdw4s-named.d/locks \
                  /etc/hdw4s/chrome-policies
install -m0644 "${dst}/dconf/profile"         /etc/dconf/profile/hdw4s-ephemeral
install -m0644 "${dst}/dconf/profile-author"  /etc/dconf/profile/hdw4s-author
install -m0644 "${dst}/dconf/10-policy"       /etc/dconf/db/hdw4s-ephemeral.d/10-policy
install -m0644 "${dst}/dconf/locks/10-policy" /etc/dconf/db/hdw4s-ephemeral.d/locks/10-policy
install -m0644 "${dst}/dconf/named-lock"       /etc/dconf/db/hdw4s-named.d/10-lock
install -m0644 "${dst}/dconf/locks/named-lock" /etc/dconf/db/hdw4s-named.d/locks/10-lock
install -m0644 "${dst}/chrome-policies/hdw4s-ephemeral.json" \
               /etc/hdw4s/chrome-policies/hdw4s-ephemeral.json
install -m0644 "${dst}/chrome-policies/hdw4s-author.json" \
               /etc/hdw4s/chrome-policies/hdw4s-author.json
install -m0644 "${dst}/chrome-author-policy.json" \
               /etc/hdw4s/chrome-author-policy.json

# The mount point the unit binds over. It must exist on the host or the
# namespace fails to build, and it must stay EMPTY: a policy file left here
# would apply to every Chrome on the machine, which is the opposite of the
# point. Chrome does not create this directory itself.
install -d -m0755 /etc/opt/chrome/policies/managed

# Compiles the text above into the binary database dconf memory-maps. A missing
# database is not an error -- dconf warns on stderr, returns 0, and silently
# falls back to schema defaults -- so a failure here has to be said out loud.
if command -v dconf >/dev/null; then
  dconf update 2>/dev/null ||
    echo 'Warning: "dconf update" failed; ephemeral sessions will start from
      stock GNOME defaults rather than the policy above.'
else
  echo 'Note: dconf is not installed, so the ephemeral policy database was not
      compiled. Install dconf-cli and run "dconf update".'
fi

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
# BEGIN path-rewrite (.github/tests.sh executes this block verbatim)
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
# END path-rewrite
echo ' done.'

echo -n 'Linking...'
ln -sf "${dst}/hdw4s" "${sys}/sbin/hdw4s"
# The /shared tool is run by hand on a machine that owns a store, so it is on
# the PATH too. Its units are templates on a store's path: none is enabled
# here; hdw4s starts the ones for a store it owns at boot.
ln -sf "${dst}/hdw4s-shared-sweep" "${sys}/sbin/hdw4s-shared-sweep"
# The units to link, taken from the list of files this script already copied
# rather than written out a second time. Two lists in one file is two lists: the
# copy above and the loop below disagreed about nothing for months and then a
# unit was added to one of them only. Anything in SOURCES that ends in a unit
# suffix is a unit, and there is nothing else for that test to catch.
for u in "${SOURCES[@]}"; do
  case "${u}" in
    # .path too: the teardown and start watchers are path units, and a list
    # without the suffix installed neither -- found when the start watcher
    # was added, and true of the teardown watcher since it was written.
    *.service|*.socket|*.timer|*.slice|*.path) ;;
    *) continue;;
  esac
  ln -sf "${dst}/${u}" "/etc/systemd/system/${u}"
done
echo ' done.'

echo -n 'Installing documentation...'
gzip -9c "${dst}/hdw4s.8" > "${man}/hdw4s.8.gz"
gzip -9c "${dst}/hdw4s-shared-sweep.8" > "${man}/hdw4s-shared-sweep.8.gz"
mandb -q 2>/dev/null || :
echo ' done.'

echo 'Fetching Selkies...'
"${dst}/hdw4s-update" || {
  echo 'Could not fetch Selkies now; the daily timer will retry.'
}

# The relay no longer names its session unit, so an installation over an
# existing one has to supply the drop-in for sessions that already exist --
# otherwise each one starts, finds nothing listening, and sits in hdw4s-wait
# until it times out, which reads as a broken desktop rather than a missing file.
#
# This is the same block as the one in debian/postinst, deliberately duplicated
# rather than sourced: packaging is not a dependency of this script. A test
# asserts the two are identical, so they cannot drift.
# BEGIN session-dropin-backfill (.github/tests.sh executes this block verbatim)
# The two roots are variables so the test can run this against a fixture
# rather than against a copy of it, which would only ever prove the copy works.
: "${ETCDIR:=/etc/hdw4s}"
: "${UNITDIR:=/etc/systemd/system}"
if [ -r "${ETCDIR}/instances" ]; then
  # The third field is the type. Reading only two of them wrote
  # "Requires=hdw4s@ephemeral0.service" for an ephemeral slot -- a named unit
  # that does not exist -- and the relay then failed every start with
  # "result 'dependency'" while the front door went on listening. A slot that
  # accepts connections and can never serve one is the worst shape available.
  while read -r idx inst type; do
    case "${idx}" in ''|\#*) continue;; esac
    d="${UNITDIR}/hdw4s-proxy@${inst}.service.d"
    [ -d "${d}" ] || continue
    # THE STREAM IS A PATH NOW, NOT A PORT (hdw4s-stream-dir), and the relay
    # template names it. An earlier "hdw4s enable" wrote the port as a drop-in
    # that REPLACES the relay's ExecStart=, so one left in place would put this
    # relay back on TCP -- the squattable shape the move exists to end, with
    # nothing to show it. Removed wherever it names a loopback port; the
    # instance file's HDW4S_PORT line, which nothing reads any more, goes too.
    if grep -qs '^ExecStart=.*systemd-socket-proxyd 127\.0\.0\.1:' "${d}/50-port.conf"; then
      rm -f -- "${d}/50-port.conf"
    fi
    [ ! -f "${ETCDIR}/${inst}.conf" ] ||
      sed -i '/^[[:space:]]*HDW4S_PORT=/d' "${ETCDIR}/${inst}.conf"
    # Both ephemeral-shaped types take the ephemeral unit. The CLI decides this
    # in ephemeral_shaped(); an installer cannot call it -- it may be repairing
    # a tree that has no working hdw4s yet -- so the list is spelled out, and
    # .github/tests.sh compares the two spellings so they cannot drift apart.
    # A "template" row left on the default arm got BindsTo=hdw4s@<inst>, which
    # is a named-desktop unit that will never run an authoring session: the
    # relay listens, every start fails on the dependency, and the front door
    # goes on accepting connections it can never serve.
    # An ephemeral-shaped relay is Requisite= on its session, a named one
    # BindsTo=: see "hdw4s enable". Requisite= starts nothing, so a connection
    # to a pool slot can never start a desktop -- only the router's start
    # request can (hdw4s-start@).
    case "${type}" in
      ephemeral|template) sunit="hdw4s-ephemeral@${inst}.service"; dep='Requisite';;
      *)                  sunit="hdw4s@${inst}.service"; dep='BindsTo';;
    esac
    # Existing drop-ins are migrated, not skipped, because nothing else rewrites
    # the file: "hdw4s enable" is not re-run on a machine that is already
    # enabled. Two older shapes: "Requires=", which does not end a relay whose
    # session EXITS ON ITS OWN (measured HTTP 000 against HTTP 200 with
    # BindsTo=); and, for a pool slot, "BindsTo=", which starts a desktop on
    # every connection. Anything else was written by somebody on purpose.
    if [ -e "${d}/30-session.conf" ]; then
      if ! grep -q '^Requires=' "${d}/30-session.conf" 2>/dev/null; then
        [ "${dep}" = 'Requisite' ] || continue
        grep -q '^BindsTo=' "${d}/30-session.conf" 2>/dev/null || continue
      fi
    fi
    printf '%s\n' \
      '# Written by "hdw4s enable": the session unit behind this relay.' \
      '[Unit]' \
      "${dep}=${sunit}" \
      "After=${sunit}" \
      > "${d}/30-session.conf"
  done < "${ETCDIR}/instances"
fi
# END session-dropin-backfill

systemctl daemon-reload
systemctl enable --now hdw4s-firewall.service
systemctl enable --now hdw4s-firewall.timer
systemctl enable --now hdw4s-updater.timer
systemctl enable --now hdw4s-reaper.timer
systemctl enable --now hdw4s-check.timer
# The ephemeral slots, and this one was missing from this list for as long as the
# feature has existed. Linking a unit into /etc/systemd/system makes it LOADABLE;
# it does not make it run. This unit declares WantedBy=sysinit.target, and that
# section does nothing at all until a sysinit.target.wants symlink exists, which
# only "systemctl enable" creates.
#
# Measured on a box installed this way: the unit read "linked", the minter never
# ran at boot, and /run/userdb, /run/hdw4s-ns, /run/hdw4s-profile, /run/hdw4s-proxy
# and /run/hdw4s-incarnation were all absent -- along with the slot accounts
# themselves, so "id ephemeral0" said no such user. The whole ephemeral feature was
# dead from the first reboot onward, and looked healthy until then only because
# installing runs the minter directly.
#
# Not one of the templates above it: those cannot be enabled without an instance
# name, and "hdw4s enable <account>" is what turns those on.
# The relay's group, before the minter that hands the stream root to it. Copied
# into the ADMINISTRATOR's sysusers directory because this is not a package: the
# packaged copy goes to /usr/lib/sysusers.d. systemd-sysusers also runs at every
# boot, so the group is there before anything that needs it.
install -d -m0755 /etc/sysusers.d
# The polkit rule keeping ephemeral slots from leaving state with the account
# daemons (60-hdw4s-slots.rules). The package ships it in polkit's vendor
# directory; this is not a package, so it goes where an administrator's go.
install -d -m0755 /etc/polkit-1/rules.d
install -m0644 "${dst}/60-hdw4s-slots.rules" /etc/polkit-1/rules.d/60-hdw4s-slots.rules
install -m0644 "${dst}/hdw4s-sysusers.conf" /etc/sysusers.d/hdw4s-sysusers.conf
systemd-sysusers /etc/sysusers.d/hdw4s-sysusers.conf
# The /shared relay server's fixed user, the same way.
install -m0644 "${dst}/hdw4s-shared-sysusers.conf" /etc/sysusers.d/hdw4s-shared-sysusers.conf
systemd-sysusers /etc/sysusers.d/hdw4s-shared-sysusers.conf
# The directory every desktop binds as /shared, which must exist before any
# desktop starts once the feature is on -- made at every boot by tmpfiles, and
# now, before the minter below writes the drop-ins that bind it. Copied into the
# ADMINISTRATOR's tmpfiles directory for the reason the sysusers file above is.
# The expose timer is not enabled: the minter starts it when /shared is on.
install -d -m0755 /etc/tmpfiles.d
install -m0644 "${dst}/hdw4s-tmpfiles.conf" /etc/tmpfiles.d/hdw4s-tmpfiles.conf
systemd-tmpfiles --create /etc/tmpfiles.d/hdw4s-tmpfiles.conf
systemctl enable --now hdw4s-ephemeral-slots.service
# The front door, enabled as a SOCKET only. The router behind it is started by
# the first connection and must not also be enabled, or a second copy races for
# the port at boot.
systemctl enable --now hdw4s-demux.socket

# And any ephemeral slot this machine already has comes off TCP, because the
# code change alone does not repair a deployment: the listener drop-in is
# written once by "hdw4s enable" and nothing re-reads it. The same block runs
# from the package's postinst; an install over an existing tree has the same
# slots and the same defect. Named desktops are left alone -- their reverse
# proxy is routinely on another machine, which cannot open a filesystem socket.
if [ -r /etc/hdw4s/instances ]; then
  while read -r idx inst type; do
    case "${idx}" in ''|\#*) continue;; esac
    # Ephemeral-shaped, not "ephemeral": an authoring session is reachable
    # only through the front door on this machine, so a port serves no caller
    # it has and every caller it must not have.
    case "${type:-desktop}" in ephemeral|template) ;; *) continue;; esac
    if grep -qs '^[[:space:]]*HDW4S_TRANSPORT=.*unix' \
            "/etc/hdw4s/${inst}.conf"; then
      continue
    fi
    "${sys}/sbin/hdw4s" transport "${inst}" unix >/dev/null ||
      echo "Warning: ${inst} is still on a port; run 'hdw4s transport ${inst} unix'." >&2
  done < /etc/hdw4s/instances
fi

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
