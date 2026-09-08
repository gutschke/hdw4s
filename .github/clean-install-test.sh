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
#
#   --keep    leave the chroot behind for inspection; you must remove it
#   --tmpfs   build in a tmpfs, so a reboot cleans up whatever this misses
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
MARKER='.hdw4s-clean-install-root'   # written into BASE, not ROOT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep)  KEEP='yes';;
    --tmpfs) TMPFS='yes';;
    --suite) shift; SUITE="${1:?--suite needs a value}";;
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
deb="$(find_deb)"
if [ -z "${deb}" ]; then
  echo 'No package found; building one.'
  .github/checks.sh --package >/dev/null || {
    echo 'The build failed; run ".github/checks.sh --package" to see why.' >&2
    exit 1
  }
  deb="$(find_deb)"
fi
[ -n "${deb}" ] || { echo 'Still no package to test.' >&2; exit 1; }
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
  # Anything still mounted under ROOT is a reason to stop, not to force it.
  if awk -v r="${ROOT}/" '$2 ~ "^"r {found=1} END{exit !found}' /proc/mounts; then
    echo "hdw4s: mounts remain under ${ROOT}; not removing it." >&2
    awk -v r="${ROOT}/" '$2 ~ "^"r {print "  " $2}' /proc/mounts >&2
    return
  fi
  [ -z "${KEEP}" ] || { echo "Left in place: ${ROOT}"; return; }
  [ -e "${BASE}/${MARKER}" ] || {
    echo "hdw4s: ${BASE} has no ${MARKER}; refusing to remove ${ROOT}." >&2
    echo "  If it is left over from an interrupted run, remove it with:" >&2
    echo "    rm -rf ${ROOT}" >&2
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
  [ -z "${TMPFS}" ] || umount -l "${BASE}" 2>/dev/null
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
# Written before anything else, so that a bootstrap which dies half way still
# leaves a root this script is willing to clean up. It lives beside the root
# rather than inside it because the bootstrappers want an empty target.
touch "${BASE}/${MARKER}"

# A stale root from an interrupted run, removed under the same guard.
if [ -d "${ROOT}" ]; then
  echo 'Removing a previous test root...'
  rm -rf "${ROOT}"
fi
if [ -n "${TMPFS}" ] && ! mountpoint -q "${BASE}"; then
  # 4G is enough for a minimal system plus Selkies and its GStreamer stack.
  mount -t tmpfs -o size=4G,mode=0755 tmpfs "${BASE}"
fi
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

# --- the check that matters --------------------------------------------------
# Not "did apt succeed" -- it did, on the release that could never start a
# desktop. Import what the streaming server imports. A missing typelib or a
# GStreamer plugin that is not there fails exactly here and nowhere earlier.
rc=0
echo -n 'Loading what a session loads...'
if run /opt/selkies/bin/python -c '
import gi
gi.require_version("Gst", "1.0")
gi.require_version("GstWebRTC", "1.0")
from gi.repository import Gst, GstWebRTC, GstSdp, GstRtp
Gst.init(None)
import selkies_gstreamer
# webrtcbin comes from plugins-bad; the ICE agent it needs comes from
# gstreamer1.0-nice, and a missing one is only visible when the element is
# actually made rather than when the module imports.
assert Gst.ElementFactory.make("webrtcbin", None) is not None, "no webrtcbin"
assert Gst.ElementFactory.make("nicesrc", None) is not None, "no libnice (gstreamer1.0-nice)"
print("ok")
' > "${ROOT}/tmp/smoke.log" 2>&1; then
  echo ' done.'
else
  echo ' FAILED.'
  tail -20 "${ROOT}/tmp/smoke.log" >&2
  rc=1
fi

# The CLI has to work as installed, not just as a file in the source tree.
run hdw4s --version >/dev/null 2>&1 || { echo 'hdw4s --version failed' >&2; rc=1; }

if [ "${rc}" -eq 0 ]; then
  echo
  echo 'PASS: a clean system installs this package and can load a session.'
  echo 'Nothing is left behind except downloaded .debs in the host archive'
  echo "cache, which are shared deliberately; 'apt clean' reclaims them."
else
  echo
  echo 'FAIL: see the output above.' >&2
fi
exit "${rc}"
