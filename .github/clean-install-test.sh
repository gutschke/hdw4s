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
# Downloads go through the host's /var/cache/apt/archives, so a second run is
# cheap and a plain "apt clean" on the host reclaims most of the space.

BASE="${HDW4S_TEST_BASE:-/var/tmp/hdw4s-clean-install}"
SUITE='noble'
MIRROR="${HDW4S_TEST_MIRROR:-http://archive.ubuntu.com/ubuntu}"
KEEP=''
TMPFS=''
MARKER='.hdw4s-clean-install-root'

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

BOOTSTRAP="$(command -v mmdebstrap || command -v debootstrap || :)"
if [ -z "${BOOTSTRAP}" ]; then
  # Installed here rather than left as an instruction, because this script is
  # already running as root by the time it can tell, and stopping to say
  # "now run one more command" wastes the expensive half of the work. It is
  # the only thing this script installs on the host.
  echo 'mmdebstrap is not installed; installing it on this host.'
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    mmdebstrap >/dev/null 2>&1 || {
    echo 'Could not install mmdebstrap. Install it and re-run:' >&2
    echo '  apt install mmdebstrap' >&2
    exit 1
  }
  BOOTSTRAP="$(command -v mmdebstrap)"
fi

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
  [ -e "${ROOT}/${MARKER}" ] || {
    echo "hdw4s: ${ROOT} has no ${MARKER}; refusing to remove it." >&2
    return
  }
  case "${ROOT}" in
    /|/usr|/etc|/var|/home|/root|/opt|"${BASE}") 
      echo "hdw4s: refusing to remove ${ROOT}." >&2; return;;
  esac
  echo -n 'Removing the test root...'
  rm -rf "${ROOT}"
  [ -z "${TMPFS}" ] || umount -l "${BASE}" 2>/dev/null
  rmdir "${BASE}" 2>/dev/null || :
  echo ' done.'
}
trap cleanup INT TERM QUIT HUP EXIT

# A stale root from an interrupted run, removed under the same guard.
if [ -e "${ROOT}/${MARKER}" ]; then
  echo 'Removing a previous test root...'
  rm -rf "${ROOT}"
fi

mkdir -p "${BASE}"
if [ -n "${TMPFS}" ] && ! mountpoint -q "${BASE}"; then
  # 4G is enough for a minimal system plus Selkies and its GStreamer stack.
  mount -t tmpfs -o size=4G,mode=0755 tmpfs "${BASE}"
fi
mkdir -p "${ROOT}"

echo -n "Bootstrapping ${SUITE}..."
case "${BOOTSTRAP}" in
  *mmdebstrap)
    # universe, because gir1.2-gst-plugins-bad-1.0 and gstreamer1.0-nice are
    # both there and neither is optional.
    "${BOOTSTRAP}" --variant=minbase \
      --components='main,universe' \
      --aptopt='Dir::Cache::archives "/var/cache/apt/archives"' \
      "${SUITE}" "${ROOT}" "${MIRROR}" >/dev/null 2>&1;;
  *)
    "${BOOTSTRAP}" --variant=minbase --components='main,universe' \
      "${SUITE}" "${ROOT}" "${MIRROR}" >/dev/null 2>&1
    printf 'deb %s %s main universe\n' "${MIRROR}" "${SUITE}" \
      > "${ROOT}/etc/apt/sources.list";;
esac
touch "${ROOT}/${MARKER}"
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
cp /etc/resolv.conf "${ROOT}/etc/resolv.conf"
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
else
  echo
  echo 'FAIL: see the output above.' >&2
fi
exit "${rc}"
