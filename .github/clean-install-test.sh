#!/bin/bash -e
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# Install the built package into a throwaway Ubuntu system and check that a
# session's code can actually load. Nothing else in this repository does that:
# CI builds the package and lints it, checks.sh reasons about the source, and
# both run on machines where the dependencies were already present. That gap
# shipped a release whose Depends was missing two GStreamer packages -- the
# install succeeded, every command reported success, and no desktop could ever
# start, because Selkies reaches those two through GObject introspection and
# the plugin loader rather than by name.
#
# This is deliberately NOT part of CI or checks.sh. It needs root, it downloads
# a few hundred megabytes, and it takes minutes. Run it when the dependency
# list changes, when the Selkies version moves, and before cutting a release.
#
#   sudo .github/clean-install-test.sh [--keep] [--tmpfs] [--suite noble]
#                                      [--inspect CMD] [--inspect-script F] [--shell]
#
#   --keep    leave the chroot behind for inspection; you must remove it
#   --tmpfs   build in a tmpfs, so a reboot cleans up whatever this misses
#   --inspect CMD        run CMD inside the finished system (repeatable)
#   --inspect-script F   copy F in and run it there
#   --shell              open an interactive shell inside it; implies --keep
#   --use-existing-deb   skip the rebuild and test whatever .deb is already
#                        beside the source tree
#
# The inspection hooks run after the checks and cannot change their verdict,
# so they are safe to use on a passing run as well as a failing one.
#
# HDW4S_TEST_DNS sets the resolver used inside the sandbox (default 1.1.1.1),
# and HDW4S_TEST_MIRROR the archive; the mirror otherwise follows this host.
#
# Downloads go through the host's /var/cache/apt/archives, so a second run is
# cheap and a plain "apt clean" on the host reclaims most of the space.

BASE="${HDW4S_TEST_BASE:-/var/tmp/hdw4s-clean-install}"
SUITE='noble'
# Default to the mirror this host already uses: it is known reachable, and the
# shared archive cache below then holds files the target actually wants.
host_mirror() {
  { grep -hE '^deb[[:space:]]+https?://' /etc/apt/sources.list 2>/dev/null |
      awk '{print $2}'
    awk '/^URIs:/ {print $2}' /etc/apt/sources.list.d/*.sources 2>/dev/null
  } | grep -E 'ubuntu' | grep -vE 'esm\.|security\.' | head -n1
}
MIRROR="${HDW4S_TEST_MIRROR:-$(host_mirror)}"
MIRROR="${MIRROR:-http://archive.ubuntu.com/ubuntu}"
# Hardcoded rather than copied from the host. A host resolv.conf is often a
# systemd-resolved stub naming 127.0.0.53, which resolves nothing inside a
# chroot that has no systemd-resolved -- the failure then looks like broken
# DNS on a machine whose own DNS is fine.
DNS="${HDW4S_TEST_DNS:-1.1.1.1}"
KEEP=''
TMPFS=''
TMPFS_MOUNTED=''
SHELL_IN=''
USE_EXISTING=''
INSPECT=()
INSPECT_SCRIPT=''
MARKER='.hdw4s-clean-install-root'   # written into BASE, not ROOT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep)  KEEP='yes';;
    --tmpfs) TMPFS='yes';;
    --suite) shift; SUITE="${1:?--suite needs a value}";;
    --inspect) shift; INSPECT+=("${1:?--inspect needs a command}");;
    --inspect-script) shift; INSPECT_SCRIPT="${1:?--inspect-script needs a path}";;
    --shell) SHELL_IN='yes'; KEEP='yes';;
    --use-existing-deb) USE_EXISTING='yes';;
    -h|--help) sed -n '/^#   sudo /,/^# Downloads/p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done

cd "$(dirname "$0")/.."

[ "$(id -u)" -eq 0 ] || {
  echo 'This must run as root: it bootstraps a system and mounts into it.' >&2
  exit 1
}

# debootstrap first, mmdebstrap only as a fallback. mmdebstrap is the nicer
# tool, but it runs apt against a target that is not yet a system, and on at
# least one ordinary Ubuntu 24.04 host every fetch then dies with
#
#   Could not create a socket for <ip> (f=2 t=1 p=6) - socket (13: Permission denied)
#
# on a machine whose own apt works. It is not the obvious suspects: the _apt
# user can create sockets there, and the kernel logs no AppArmor or seccomp
# denial. Disabling apt's seccomp, running its sandbox as root, and
# --mode=unshare all fail the same way. debootstrap fetches with wget from the
# host and never runs apt against a half-built root, so the question does not
# arise. If mmdebstrap works for you, it is still used when debootstrap is
# absent.
BOOTSTRAP="$(command -v debootstrap || command -v mmdebstrap || :)"
if [ -z "${BOOTSTRAP}" ]; then
  # Installed here rather than left as an instruction, because this script is
  # already running as root by the time it can tell, and stopping to say
  # "now run one more command" wastes the expensive half of the work. It is
  # the only thing this script installs on the host.
  echo 'debootstrap is not installed; installing it on this host.'
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    debootstrap >/dev/null 2>&1 || {
    echo 'Could not install debootstrap. Install it and re-run:' >&2
    echo '  apt install debootstrap' >&2
    exit 1
  }
  BOOTSTRAP="$(command -v debootstrap)"
fi
echo "Bootstrapper: ${BOOTSTRAP}"

find_deb() {
  find .. -maxdepth 1 -name 'hdw4s_*_all.deb' -printf '%T@ %p\n' 2>/dev/null |
    sort -rn | head -n1 | cut -d' ' -f2-
}
# Built every time, not reused. A test that takes ten minutes and a gigabyte
# is worthless if it silently reports on a package from an hour ago: this run
# said "python3-evdev is not installed" about a .deb built before that
# dependency was added, and passed its own smoke test because it extracted
# that test from the stale package it had just installed. The build is seconds
# against a bootstrap of minutes.
if [ -z "${USE_EXISTING}" ]; then
  echo -n 'Building the package...'
  .github/checks.sh --package >/dev/null || {
    echo ' failed.'
    echo 'Run ".github/checks.sh --package" to see why.' >&2
    exit 1
  }
  echo ' done.'
fi
deb="$(find_deb)"
[ -n "${deb}" ] || {
  echo 'No package to test; build one with ".github/checks.sh --package".' >&2
  exit 1
}
deb="$(readlink -f "${deb}")"
echo "Testing $(basename "${deb}") on a clean ${SUITE} system."

# --- the throwaway root ------------------------------------------------------
# Everything below removes files, so the target is derived here, once, and
# every removal is gated on the marker this script wrote. A run that is
# interrupted leaves the marker behind, which is what makes the next run's
# cleanup safe rather than a guess.
ROOT="${BASE}/${SUITE}"
mounted=''

# shellcheck disable=SC2317  # every line below runs from the trap
cleanup() {
  set +e
  # Unmount in reverse order, and only paths under our own root. A bind mount
  # left behind would make the rm -rf below eat the host's apt cache.
  local m
  for m in ${mounted}; do umount -l "${ROOT}${m}" 2>/dev/null; done
  # Our own tmpfs always comes down, on every path out of here. Refusing to
  # delete files is a safe outcome; leaving a 4G tmpfs mounted is not, and
  # that is what used to happen whenever the check below said no.
  drop_tmpfs() {
    [ -n "${TMPFS_MOUNTED}" ] || return 0
    umount -l "${BASE}" 2>/dev/null && TMPFS_MOUNTED=''
  }

  # Anything still mounted under ROOT is a reason to stop, not to force it.
  if awk -v r="${ROOT}/" '$2 ~ "^"r {found=1} END{exit !found}' /proc/mounts; then
    echo "hdw4s: mounts remain under ${ROOT}; not removing it." >&2
    awk -v r="${ROOT}/" '$2 ~ "^"r {print "  " $2}' /proc/mounts >&2
    return
  fi
  [ -z "${KEEP}" ] || {
    echo "Left in place: ${ROOT}"
    [ -z "${TMPFS_MOUNTED}" ] ||
      echo "  (on a tmpfs at ${BASE}; unmounting it discards the contents)"
    return
  }
  [ -e "${BASE}/${MARKER}" ] || {
    echo "hdw4s: ${BASE} has no ${MARKER}; refusing to remove ${ROOT}." >&2
    echo "  If it is left over from an interrupted run, remove it with:" >&2
    echo "    rm -rf ${ROOT}" >&2
    drop_tmpfs
    return
  }
  case "${ROOT}" in
    /|/usr|/etc|/var|/home|/root|/opt|"${BASE}") 
      echo "hdw4s: refusing to remove ${ROOT}." >&2; return;;
  esac
  echo -n 'Removing the test root...'
  rm -rf "${ROOT}"
  # The marker and the bootstrap log live in BASE, so removing only the root
  # left BASE behind on every run: the rmdir below failed silently because the
  # directory was not empty. The last twenty lines of the log have already
  # been printed if the bootstrap failed, and --keep preserves everything.
  rm -f "${BASE}/${MARKER}" "${BASE}/bootstrap.log"
  drop_tmpfs
  rmdir "${BASE}" 2>/dev/null || :
  if [ -e "${BASE}" ]; then
    echo
    echo "hdw4s: ${BASE} could not be removed; it still holds:" >&2
    find "${BASE}" -mindepth 1 -maxdepth 1 -printf '  %f\n' 2>/dev/null >&2
  else
    echo ' done.'
  fi
}
trap cleanup INT TERM QUIT HUP EXIT

mkdir -p "${BASE}"

# A stale root from an earlier run, removed before anything is mounted over
# it -- otherwise it stays on the underlying filesystem, invisible and still
# occupying the disk.
if [ -d "${ROOT}" ]; then
  echo 'Removing a previous test root...'
  rm -rf "${ROOT}"
fi

if [ -n "${TMPFS}" ] && ! mountpoint -q "${BASE}"; then
  # 4G is enough for a minimal system plus Selkies and its GStreamer stack.
  mount -t tmpfs -o size=4G,mode=0755 tmpfs "${BASE}"
  TMPFS_MOUNTED='yes'
fi

# After the mount, never before: written underneath a tmpfs the marker is
# hidden the moment it is mounted, and cleanup then refuses to remove a root
# it created -- and, worse, used to return before unmounting, leaking the
# mount and every gigabyte of RAM behind it.
touch "${BASE}/${MARKER}"
rm -rf "${ROOT}"
mkdir -p "${ROOT}"

# "$1" here is mmdebstrap's target directory, expanded by mmdebstrap when it
# runs the hook -- not a parameter of this script.
# shellcheck disable=SC2016
dns_hook='mkdir -p "$1/etc" && printf "nameserver DNSADDR\n" > "$1/etc/resolv.conf"'
dns_hook="${dns_hook/DNSADDR/${DNS}}"

bootstrap_failed() {
  echo ' FAILED.'
  echo "hdw4s: ${BOOTSTRAP##*/} could not build a ${SUITE} root. Last lines:" >&2
  tail -20 "${BASE}/bootstrap.log" >&2
  exit 1
}

mhost="${MIRROR#*://}"; mhost="${mhost%%/*}"
getent hosts "${mhost}" >/dev/null 2>&1 || {
  echo "hdw4s: this host cannot resolve ${mhost}; fix DNS before running." >&2
  exit 1
}
# Resolved here, on the host, where DNS demonstrably works. The bootstrap
# retries with this if the name fails: apt runs host-side against a target
# that is not yet a system, and on a host using a systemd-resolved stub in
# /etc/resolv.conf it can end up able to reach neither the stub nor the
# resolver written into the target. An address removes the question.
MIRROR_IP=''
mip="$(getent ahostsv4 "${mhost}" 2>/dev/null | awk '{print $1; exit}')"
[ -z "${mip}" ] || MIRROR_IP="${MIRROR/${mhost}/${mip}}"
echo "Mirror: ${MIRROR}${MIRROR_IP:+  (by address: ${MIRROR_IP})}"
echo "Resolver inside the sandbox: ${DNS}"

bootstrap_with() {
  case "${BOOTSTRAP}" in
  *mmdebstrap)
    # universe, because gir1.2-gst-plugins-bad-1.0 and gstreamer1.0-nice are
    # both there and neither is optional.
    #
    # The resolver is written into the target as a setup hook, and apt's
    # sandbox user is forced to root. Neither was enough on the host described
    # above; both are kept because they are correct in themselves and cost
    # nothing.
    "${BOOTSTRAP}" --variant=minbase \
      --components='main,universe' \
      --aptopt='Dir::Cache::archives "/var/cache/apt/archives"' \
      --aptopt='APT::Sandbox::User "root"' \
      --setup-hook="${dns_hook}" \
      "${SUITE}" "${ROOT}" "$1" > "${BASE}/bootstrap.log" 2>&1;;
  *)
    "${BOOTSTRAP}" --variant=minbase --components='main,universe' \
      "${SUITE}" "${ROOT}" "$1" > "${BASE}/bootstrap.log" 2>&1;;
  esac
}

echo -n "Bootstrapping ${SUITE}..."
if bootstrap_with "${MIRROR}"; then
  :
elif [ -n "${MIRROR_IP}" ] && grep -qi 'could not resolve' "${BASE}/bootstrap.log"; then
  echo -n ' name lookup failed, retrying by address...'
  rm -rf "${ROOT}"; mkdir -p "${ROOT}"
  bootstrap_with "${MIRROR_IP}" || bootstrap_failed
else
  bootstrap_failed
fi
# Whatever the bootstrap used, the finished system talks to the mirror by
# name: it has a resolver and a working libc by now, which the half-built
# target did not.
printf 'deb %s %s main universe\n' "${MIRROR}" "${SUITE}" \
  > "${ROOT}/etc/apt/sources.list"
rm -f "${ROOT}"/etc/apt/sources.list.d/*.sources 2>/dev/null || :
echo ' done.'

# --- mounts ------------------------------------------------------------------
# The host's archive cache is shared deliberately: the second run of this
# script costs almost nothing, and "apt clean" on the host reclaims the space
# without anybody having to remember a path that only this script knows.
mkdir -p "${ROOT}/var/cache/apt/archives" /var/cache/apt/archives
for m in /proc /sys /dev /dev/pts /var/cache/apt/archives; do
  mkdir -p "${ROOT}${m}"
  mount --bind "${m}" "${ROOT}${m}"
  mounted="${m} ${mounted}"
done
printf 'nameserver %s\n' "${DNS}" > "${ROOT}/etc/resolv.conf"
cp "${deb}" "${ROOT}/tmp/"

# Package installs must not try to talk to a service manager that is not here.
# The maintainer scripts already guard on /run/systemd/system, so this is
# belt and braces for anything they call.
printf '#!/bin/sh\nexit 101\n' > "${ROOT}/usr/sbin/policy-rc.d"
chmod 0755 "${ROOT}/usr/sbin/policy-rc.d"

run() { unshare --fork --pid --mount-proc="${ROOT}/proc" \
          chroot "${ROOT}" /usr/bin/env -i \
          PATH=/usr/sbin:/usr/bin:/sbin:/bin \
          DEBIAN_FRONTEND=noninteractive HOME=/root "$@"; }

echo -n 'Installing the package...'
run apt-get update -qq >/dev/null 2>&1
if ! run apt-get install -y --no-install-recommends "/tmp/$(basename "${deb}")" \
       > "${ROOT}/tmp/install.log" 2>&1; then
  echo ' FAILED.'
  tail -30 "${ROOT}/tmp/install.log" >&2
  exit 1
fi
echo ' done.'

# --- the checks that matter --------------------------------------------------
# Not "did apt succeed". It did, on the release that could never start a
# desktop, and it did again on an install where every Python dependency was
# missing -- the package's own postinst tolerates a failed Selkies fetch,
# because a machine being installed may legitimately have no network yet, so
# a broken install and a fine one look identical from the outside.
#
# Nor "does the package import". The first version of this checked
# "import selkies_gstreamer" and passed against exactly that broken install:
# the package's __init__ pulls in nothing but the standard library, so it
# succeeds whether or not a single dependency is present.
#
# What follows is what actually found the bugs, which was reading the
# installed system rather than asking it whether it was well.
rc=0
fail() { echo "  FAIL: $*" >&2; rc=1; }
VENV="${ROOT}/opt/selkies/lib/python3.12/site-packages"

echo 'Inspecting the installed system:'

# 1. The updater is allowed to fail quietly during installation. Here it is not.
if [ -d "${ROOT}/opt/selkies" ] &&
   find "${VENV}" -maxdepth 1 -name 'selkies_gstreamer-*.dist-info' \
        -print -quit 2>/dev/null | grep -q .; then
  echo '  selkies installed                 yes'
else
  fail 'Selkies is not installed -- the updater failed and the install went on'
  grep -iE 'error|failed|could not' "${ROOT}/tmp/install.log" 2>/dev/null |
    tail -5 | sed 's/^/    /' >&2
fi

# 2. Nothing may be installed from a git branch. This is the whole reason the
#    dependency list is explicit: a branch is whatever it says on the day it
#    is fetched, and its setup.py runs as root.
if grep -rl 'github\.com\|git+' "${VENV}"/*.dist-info/direct_url.json \
     >/dev/null 2>&1; then
  fail 'something in the venv was installed from a git URL:'
  grep -rl 'github\.com\|git+' "${VENV}"/*.dist-info/direct_url.json 2>/dev/null |
    sed 's/^/    /' >&2
else
  echo '  no git-sourced packages           confirmed'
fi

# 3. python-xlib must come from the distribution. A copy inside the venv
#    shadows it, and the one on PyPI lacks the randr fix, so resizing breaks
#    with nothing to show for it.
if [ -e "${VENV}/Xlib" ]; then
  fail 'a python-xlib inside the venv shadows the distro package'
elif [ -d "${ROOT}/usr/lib/python3/dist-packages/Xlib" ]; then
  echo '  python-xlib from the distro       yes'
else
  fail 'python-xlib is not installed at all'
fi

# 4. The dependencies that are reached through introspection and plugin
#    loading, which no amount of reading the scripts can reveal.
for pkg in gir1.2-gst-plugins-bad-1.0 gstreamer1.0-nice python3-xlib python3-evdev; do
  if grep -qx "Package: ${pkg}" "${ROOT}/var/lib/dpkg/status" 2>/dev/null &&
     grep -A3 -x "Package: ${pkg}" "${ROOT}/var/lib/dpkg/status" 2>/dev/null |
       grep -q '^Status: install ok installed'; then
    printf '  %-33s installed\n' "${pkg}"
  else
    fail "${pkg} is not installed"
  fi
done

# 5. Finally, run the shipped smoke test -- the installed one, not a copy, so
#    that the two can never drift apart. It imports the modules a session
#    actually loads and builds the elements a stream actually needs.
echo -n 'Loading what a session loads...'
if run /bin/bash -c '
  set -e
  PREFIX=/opt/selkies
  eval "$(sed -n "/^smoke_test() {/,/^}/p" /usr/lib/hdw4s/hdw4s-update)"
  smoke_test' > "${ROOT}/tmp/smoke.log" 2>&1; then
  echo ' done.'
else
  echo ' FAILED.'
  tail -20 "${ROOT}/tmp/smoke.log" >&2
  rc=1
fi

# The CLI has to work as installed, not just as a file in the source tree.
run hdw4s --version >/dev/null 2>&1 || fail 'hdw4s --version failed'

# --- what is actually there ---------------------------------------------------
# Filtered on purpose. A full dpkg listing or apt log is thousands of lines and
# nobody reads it, so what gets printed is the handful of facts that have
# actually mattered: versions, what pip put in the venv, whether the elements a
# stream needs exist, and any complaint the install made. Someone checking this
# run should be able to see whether it is healthy without trusting one word.
echo
echo '--- installed system -------------------------------------------------'
printf '  %-24s %s\n' 'hdw4s' \
  "$(awk '/^Package: hdw4s$/{f=1; next} f&&/^Version:/{print $2; exit} /^$/{f=0}' \
     "${ROOT}/var/lib/dpkg/status" 2>/dev/null)"
printf '  %-24s %s\n' 'selkies' \
  "$(find "${VENV}" -maxdepth 1 -name 'selkies_gstreamer-*.dist-info' \
     -printf '%f\n' 2>/dev/null | sed 's/^selkies_gstreamer-//;s/\.dist-info$//')"
printf '  %-24s %s\n' 'debs installed' \
  "$(grep -c '^Status: install ok installed' "${ROOT}/var/lib/dpkg/status" 2>/dev/null)"
printf '  %-24s %s\n' 'size on disk' "$(du -sh "${ROOT}" 2>/dev/null | cut -f1)"

echo '  packages pip put in the venv:'
find "${VENV}" -maxdepth 1 -name '*.dist-info' -printf '%f\n' 2>/dev/null |
  sed 's/\.dist-info$//' | sort | sed 's/^/    /'

echo '  GStreamer elements a stream needs:'
run /opt/selkies/bin/python -c '
import gi
gi.require_version("Gst", "1.0")
from gi.repository import Gst
Gst.init(None)
for el in ("webrtcbin","nicesrc","nicesink","x264enc","vp8enc","opusenc",
           "ximagesrc","videoconvert","audioconvert"):
    print("    %-16s %s" % (el, "ok" if Gst.ElementFactory.make(el, None) else "MISSING"))
' 2>/dev/null || echo '    (could not be listed)'

echo '  typelibs Selkies reaches by introspection:'
find "${ROOT}"/usr/lib -name 'Gst*.typelib' -printf '%f\n' 2>/dev/null |
  sort | tr '\n' ' ' | fold -s -w 66 | sed 's/^/    /'
echo

# Only complaints. dpkg is verbose and almost all of it is noise; these are the
# lines that have ever meant anything here.
warn="$(grep -iE '^(W|E): |error:|failed|not installed|cannot' \
        "${ROOT}/tmp/install.log" 2>/dev/null |
        grep -viE 'invoke-rc.d|policy-rc.d|Failed to (connect to|take) |dbus|systemd|dpkg-preconfigure|locale|unlockpt|apt-utils|delaying package configuration' |
        sort -u | head -8)"
if [ -n "${warn}" ]; then
  echo '  complaints during install (filtered):'
  printf '%s\n' "${warn}" | sed 's/^/    /'
else
  echo '  complaints during install     none'
fi
echo '----------------------------------------------------------------------'

# --- inspection hooks ---------------------------------------------------------
# run() scrubs the environment with "env -i" so that the install is reproducible
# and cannot inherit anything from the host. That is right for the test and
# wrong for a person poking around, who expects a normal-looking shell -- so
# these get a TERM and a sensible PATH, and a script is copied in rather than
# executed across the chroot boundary, where its interpreter would be looked up
# on the wrong side.
inspect_run() {
  unshare --fork --pid --mount-proc="${ROOT}/proc" chroot "${ROOT}" \
    /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root TERM="${TERM:-dumb}" DEBIAN_FRONTEND=noninteractive "$@"
}

for cmd in ${INSPECT+"${INSPECT[@]}"}; do
  echo "--- inspect: ${cmd}"
  inspect_run /bin/sh -c "${cmd}" || echo "  (exited $?)"
done

if [ -n "${INSPECT_SCRIPT}" ]; then
  if [ -r "${INSPECT_SCRIPT}" ]; then
    cp "${INSPECT_SCRIPT}" "${ROOT}/tmp/inspect-script"
    chmod 0755 "${ROOT}/tmp/inspect-script"
    echo "--- inspect-script: $(basename "${INSPECT_SCRIPT}")"
    inspect_run /tmp/inspect-script || echo "  (exited $?)"
  else
    echo "hdw4s: cannot read ${INSPECT_SCRIPT}" >&2
    rc=1
  fi
fi

if [ -n "${SHELL_IN}" ]; then
  echo "--- shell inside the installed system; exit when done ---"
  inspect_run /bin/bash -i || :
fi

if [ "${rc}" -eq 0 ]; then
  echo
  echo 'PASS: a clean system installs this package and can load a session.'
  echo 'Nothing is left behind except downloaded .debs in the host archive'
  echo "cache, which are shared deliberately; 'apt clean' reclaims them."
else
  echo
  echo 'FAIL: see the output above.' >&2
  echo "Re-run with --keep to leave the system at ${ROOT} and look at it" >&2
  echo '  yourself. Every check above was written after reading that tree by' >&2
  echo '  hand found something the automated check had passed over.' >&2
fi
exit "${rc}"
