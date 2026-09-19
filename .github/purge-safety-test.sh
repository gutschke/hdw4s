#!/bin/bash -e
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# What "apt purge hdw4s" destroys, and whether any of it had to survive.
#
#   sudo .github/purge-safety-test.sh [--deb FILE] [--dirty] [--no-self-test]
#
#   --deb FILE       the package to test (default: the newest beside the tree)
#   --dirty          do NOT blank the paths hdw4s owns before installing, so
#                    the run reports on the machine's accumulated state as
#                    well. Useful once; useless for attributing a leftover.
#   --no-self-test   skip the two control packages (see "Proving it can fail")
#
# The rule this exists for is that a lost profile is acceptable and a home
# directory is not. Nothing else in the repository tests removal at all:
# checks.sh reasons about the source, clean-install-test.sh installs and never
# removes, and the one time an explicit remove+purge was run by hand it took
# /etc/hdw4s/instances and every drop-in with it -- documented behaviour that
# still surprised everybody, because nobody had looked.
#
# Where it runs. Everything happens inside "unshare -m": a root composed of
# one overlayfs per top-level directory, each with its upper layer on a tmpfs,
# and a fresh empty tmpfs over /home, /root, /srv, /run and /tmp. The host's
# real home directories are not merely protected, they are not present in the
# namespace -- which the assertion below checks before anything is installed,
# because a mount that silently did not happen is the only way this could
# reach a real home. /run is blanked for a second reason: it removes
# /run/systemd/system, and with it every path in the maintainer scripts that
# would otherwise talk to the host's systemd and stop somebody's session.
#
# What is real and what is stood in for. Real: the built .deb, dpkg's own
# unpack and conffile handling, the maintainer scripts exactly as shipped, and
# the filesystem. Stood in for: systemd (absent by construction, so the
# systemctl branches are not exercised), the network, and any running session.
# The directories this script mounts a tmpfs over cannot be rmdir'd by dpkg,
# so "0 entries" for such a path means empty, not left behind.
#
# Proving it can fail. A purge test that passes because it touched nothing is
# worthless, so unless --no-self-test is given the run first repacks the same
# .deb twice: control A adds the two deletions a "clean it up properly" pass is
# most tempted to write, and must be REJECTED naming the homes it ate; control
# B repairs the two known defects and must be ACCEPTED. A run in which the
# controls do not behave reports the harness as broken and says nothing about
# the package.

DEB=''
CLEAN='yes'
SELFTEST='yes'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --deb) shift; DEB="${1:?--deb needs a path}";;
    --dirty) CLEAN='';;
    --no-self-test) SELFTEST='';;
    -h|--help) sed -n '/^#   sudo /,/^# Proving/p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done

cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || {
  echo 'This must run as root: it builds a throwaway root and mounts into it.' >&2
  echo 'Run it on a disposable machine -- never on one carrying a real home.' >&2
  exit 1
}
if [ -z "${DEB}" ]; then
  DEB="$(find .. private/build -maxdepth 1 -name 'hdw4s_*_all.deb' \
           -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n1 | cut -d' ' -f2-)"
fi
if [ -z "${DEB}" ] || [ ! -f "${DEB}" ]; then
  echo 'No package to test; build one with "private/build.sh --package".' >&2
  exit 1
fi
DEB="$(readlink -f "${DEB}")"

# --- the controls ------------------------------------------------------------
# Run before the package itself, so a broken harness is reported as a broken
# harness rather than as a verdict about the .deb. Both are the same package
# with its postrm rewritten and repacked -- nothing here rebuilds from source,
# so neither control can differ from the real package in any other way.
if [ -n "${SELFTEST}" ]; then
  ctl="$(mktemp -d)"
  trap 'rm -rf "${ctl}"' EXIT INT TERM QUIT HUP
  dpkg-deb -R "${DEB}" "${ctl}/A" >/dev/null
  cp -a "${ctl}/A" "${ctl}/B"
  # A: the two deletions a "clean up properly" pass is most tempted to write.
  #    One eats every profile directory, and with it the two accounts whose
  #    home is under /var/lib/hdw4s; the other eats a dot-directory in a home.
  awk '{ if ($0 ~ /^  rm -rf \/opt\/gst-web /) {
           print "  rm -rf /var/lib/hdw4s"; print "  rm -rf /home/alice/.config" }
         print }' "${ctl}/A/DEBIAN/postrm" > "${ctl}/postrm.a"
  mv "${ctl}/postrm.a" "${ctl}/A/DEBIAN/postrm"; chmod 0755 "${ctl}/A/DEBIAN/postrm"
  # B: the recorded defect repaired too, so the run has a package that should
  #    be accepted outright. The updater cache is identified by its contents
  #    rather than by a directory name an account can also have.
  # shellcheck disable=SC2016  # the ${} below is text being written into
  # another shell script, not an expansion this one wants.
  sed -e 's|^  rm -rf /var/lib/hdw4s/selkies$|  for d in /var/lib/hdw4s/selkies/*/; do [ -e "${d}sha256" ] \&\& rm -rf "${d}"; done\n  rmdir /var/lib/hdw4s/selkies 2>/dev/null \|\| :|' \
      "${ctl}/B/DEBIAN/postrm" > "${ctl}/postrm.b"
  mv "${ctl}/postrm.b" "${ctl}/B/DEBIAN/postrm"; chmod 0755 "${ctl}/B/DEBIAN/postrm"
  # A control byte-identical to the original tests nothing: if a rewrite above
  # stopped matching the postrm it edits, say so rather than report a green run.
  dpkg-deb -R "${DEB}" "${ctl}/orig" >/dev/null
  for v in A B; do
    if cmp -s "${ctl}/${v}/DEBIAN/postrm" "${ctl}/orig/DEBIAN/postrm"; then
      echo "harness: control ${v} is identical to the package; the rewrite no" >&2
      echo '  longer matches postrm. Fix it before trusting any verdict.' >&2
      exit 3
    fi
    dpkg-deb -b "${ctl}/${v}" "${ctl}/ctl-${v}.deb" >/dev/null
  done
  dirty=(); [ -n "${CLEAN}" ] || dirty=(--dirty)
  echo '=== control A: a postrm that eats homes. Must be REJECTED.'
  if "$0" --deb "${ctl}/ctl-A.deb" --no-self-test "${dirty[@]}" \
       > "${ctl}/A.out" 2>&1; then
    echo 'harness: control A PASSED. This test cannot see a deleted home and' >&2
    echo '  says nothing about the package. Its findings are void.' >&2
    sed 's/^/  /' "${ctl}/A.out" >&2
    exit 3
  fi
  grep -E '^FAIL.*(/home/alice|/var/lib/hdw4s/carol)' "${ctl}/A.out" |
    sed 's/^/      /' || {
      echo 'harness: control A failed, but not on the homes it ate.' >&2
      sed 's/^/  /' "${ctl}/A.out" >&2; exit 3; }
  echo '=== control B: a package with nothing left to find. Must be ACCEPTED.'
  if HDW4S_PURGE_TEST_NO_KNOWN=1 "$0" --deb "${ctl}/ctl-B.deb" --no-self-test \
       "${dirty[@]}" > "${ctl}/B.out" 2>&1; then
    echo '      control B passed, as it must.'
  else
    echo 'harness: control B FAILED. This test rejects a package that is' >&2
    echo '  correct, so a rejection of the real one means nothing.' >&2
    sed 's/^/  /' "${ctl}/B.out" >&2
    exit 3
  fi
  rm -rf "${ctl}"; trap - EXIT INT TERM QUIT HUP
  echo '=== the package itself'
fi

# The body runs in its own mount namespace, reading the package path and the
# switches from its argument list. Not a here-document inside ssh quoting and
# not a temporary file: this is the whole script re-entering itself.
if [ -z "${HDW4S_PURGE_TEST_INNER:-}" ]; then
  inner=(--deb "${DEB}" --no-self-test)
  [ -n "${CLEAN}" ] || inner+=(--dirty)
  HDW4S_PURGE_TEST_INNER=1 exec unshare -m --propagation private "$0" "${inner[@]}"
fi

R='/tmp/.hdw4s-purge-root'
fail=0
ok()  { printf 'ok    %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }

# Copied out before /tmp is replaced: the package is often under /tmp and the
# tmpfs below would hide it. This cost a run.
cp "${DEB}" /dev/shm/hdw4s-purge-test.deb

# overlayfs refuses "/" itself as a lowerdir, so the root is composed rather
# than overlaid in one piece. Every write lands in a tmpfs upper layer.
mount -t tmpfs -o size=4G tmpfs /tmp
mkdir -p "${R}" /tmp/ovl
for d in usr etc var opt; do
  mkdir -p "/tmp/ovl/${d}/up" "/tmp/ovl/${d}/work" "${R}/${d}"
  mount -t overlay "ovl-${d}" \
    -o "lowerdir=/${d},upperdir=/tmp/ovl/${d}/up,workdir=/tmp/ovl/${d}/work" \
    "${R}/${d}"
done
ln -sfn usr/bin "${R}/bin"; ln -sfn usr/sbin "${R}/sbin"
ln -sfn usr/lib "${R}/lib"; ln -sfn usr/lib64 "${R}/lib64"
mkdir -p "${R}/dev" "${R}/proc" "${R}/sys"
mount --rbind /dev "${R}/dev"
for d in home root srv run tmp media mnt; do
  mkdir -p "${R}/${d}"; mount -t tmpfs tmpfs "${R}/${d}"
done
chmod 1777 "${R}/tmp"
mount -t proc proc "${R}/proc" 2>/dev/null || :

# The guard, not a comment about one. A tmpfs that silently did not mount is
# the only way anything below could reach a real home, so it is checked.
for d in home root srv media mnt; do
  [ -z "$(ls -A "${R}/${d}")" ] ||
    { echo "ABORT: ${R}/${d} is not empty; the sandbox did not build." >&2; exit 9; }
done
[ ! -e "${R}/run/systemd/system" ] ||
  { echo 'ABORT: the host systemd is reachable from the sandbox.' >&2; exit 9; }

if [ -n "${CLEAN}" ]; then
  # A leftover cannot be attributed to this purge unless the directory started
  # empty, and a machine that has run hdw4s before is full of paths that look
  # like leftovers and are not.
  chroot "${R}" dpkg -P --force-depends hdw4s >/dev/null 2>&1 || :
  # Emptied by deleting them in the overlay, NOT by mounting a tmpfs over each.
  # A tmpfs mount point cannot be rmdir'd, which reported every one of these as
  # "left behind (0 entries)" when it was in fact empty, and -- far worse --
  # made "rm -rf /var/lib/hdw4s" in a control package return non-zero, so the
  # postrm's own "set -e" aborted it and the next line never ran. The control
  # then looked like it had spared a home it had never reached.
  for d in etc/hdw4s var/lib/hdw4s usr/lib/hdw4s usr/share/hdw4s etc/opt/chrome; do
    rm -rf "${R:?}/${d}"
  done
  rm -rf "${R}"/etc/systemd/system/hdw4s* "${R}"/etc/systemd/system/*/hdw4s* \
         "${R}"/etc/dconf/db/hdw4s* "${R}"/etc/dconf/profile/hdw4s* \
         "${R}"/etc/sysctl.d/60-hdw4s.conf
fi

# --- the fixture -------------------------------------------------------------
# Homes in the shapes that matter, because a home directory is not a fixed
# name and the two interesting ones are not under /home at all. "carol" and
# "selkies" sit INSIDE the package's own state directory; "selkies" is on the
# exact path postrm removes by name.
add_user() { # name uid home
  printf '%s:x:%s:%s:purge test:%s:/bin/bash\n' "$1" "$2" "$2" "$3" \
    >> "${R}/etc/passwd"
  mkdir -p "${R}$3"
}
add_user alice   4001 /home/alice
add_user bob     4002 /home/bob
add_user carol   4003 /var/lib/hdw4s/carol
add_user selkies 4004 /var/lib/hdw4s/selkies
add_user dave    4005 /srv/people/dave

# Everything here must be byte-identical after the purge, except the one entry
# marked as a profile, which the project says is expendable.
must_survive=(
  /home/alice/Maildir/cur/1.mail
  /home/alice/.config/dconf/user
  /home/alice/.config/hdw4s/notes
  /home/alice/Documents/thesis.txt
  /home/bob/.local/share/hdw4s/looks-like-a-profile/x
  /var/lib/hdw4s/carol/Maildir/cur/1.mail
  /var/lib/hdw4s/carol/Documents/x
  /srv/people/dave/Maildir/cur/1.mail
  /srv/mail/shared/1.mail
  # Not homes, but not ours either: files belonging to another administrator
  # or another package, sitting in directories this package also writes to.
  /etc/dconf/profile/user
  /etc/dconf/db/site.d/10-other
  /etc/opt/chrome/policies/managed/other-admin.json
  /etc/sysctl.d/99-someone-else.conf
)
expendable=( /var/lib/hdw4s/alice/dconf/user )   # a genuine hdw4s profile

# Recorded, decided, and not yet repaired. These are reported on every run and
# do not fail it -- but a run in which one of them STOPS reproducing fails
# instead, because that means it was fixed and its entry belongs up in
# must_survive rather than down here going quietly out of date.
#
# /var/lib/hdw4s/selkies: purge removes it by name as the updater's download
# cache (hdw4s-update sets CACHE to exactly that path), while /var/lib/hdw4s
# is also the default HDW4S_PROFILE_DIR -- so an instance named "selkies"
# keeps its profile on the same path. A profile is expendable by project rule
# and no home can land there unless an administrator puts one there, which is
# why this is recorded rather than fixed. The larger half is not here at all:
# "hdw4s enable" has no reserved-name check, so on an ordinary upgrade the
# updater would write its cached .deb INTO that account's live profile.
known_defect=(
  /var/lib/hdw4s/selkies/Maildir/cur/1.mail
  /var/lib/hdw4s/selkies/Documents/x
)
# Control B is a package with the recorded defect repaired as well, so for
# that run the entries are promoted and the list emptied -- otherwise the
# ratchet above would fail it for not reproducing what it had just fixed.
if [ -n "${HDW4S_PURGE_TEST_NO_KNOWN:-}" ]; then
  must_survive+=("${known_defect[@]}")
  known_defect=()
fi
for f in "${must_survive[@]}" "${expendable[@]}" "${known_defect[@]}"; do
  mkdir -p "${R}$(dirname "${f}")"; echo "canary ${f}" > "${R}${f}"
done
mkdir -p "${R}/run/userdb"
echo '{"userName":"someone","realName":"Not ours"}'        > "${R}/run/userdb/someone.user"
echo '{"userName":"eph","realName":"Ephemeral session"}'   > "${R}/run/userdb/eph.user"
echo '{}'                                                  > "${R}/run/userdb/eph.group"

hashes() {
  local f
  for f in "$@"; do
    if [ -e "${R}${f}" ]; then printf '%s %s\n' "$(md5sum < "${R}${f}" | cut -d' ' -f1)" "${f}"
    else printf 'MISSING %s\n' "${f}"; fi
  done
}
hashes "${must_survive[@]}" "${known_defect[@]}" > /tmp/before.hash

conf="${R}/etc/hdw4s/chrome-policies/hdw4s-ephemeral.json"

echo '--- install'
chroot "${R}" dpkg -i --force-depends /dev/shm/hdw4s-purge-test.deb \
  >/tmp/install.log 2>&1 || :
chroot "${R}" dpkg-query -W -f="\${Status}\n" hdw4s 2>&1 | sed 's/^/      status: /'
if [ -e "${conf}" ]; then
  ok 'the conffile was installed'
  # An administrator's local edit. dpkg's contract is that this survives
  # "remove" and goes only on "purge"; that is the whole point of a conffile.
  echo '{"LocalEdit": true}' > "${conf}"
else
  bad 'the conffile was not installed; the rest of this run proves nothing'
fi

echo '--- remove (the first half of "apt purge")'
chroot "${R}" dpkg -r --force-depends hdw4s >/tmp/remove.log 2>&1 || :
if [ -e "${conf}" ]; then
  ok 'the conffile survives remove'
else
  bad 'remove DESTROYED the conffile /etc/hdw4s/chrome-policies/hdw4s-ephemeral.json'
fi

echo '--- purge (the second half)'
chroot "${R}" dpkg -P --force-depends hdw4s >/tmp/purge.log 2>&1 || :
# The converse of the check above, and it needs saying: moving the deletion
# out of the remove block is only correct if purge still performs it.
if [ -e "${conf}" ]
then bad 'purge left the conffile /etc/hdw4s/chrome-policies behind'
else ok  'purge removed the conffile'; fi
hashes "${must_survive[@]}" "${known_defect[@]}" > /tmp/after.hash

echo '--- must-survive files'
known_seen=0
while read -r h f; do
  b="$(awk -v p=" ${f}" 'index($0, p)==length($0)-length(p)+1 {print $1}' /tmp/before.hash)"
  [ "${h}" = "${b}" ] && continue
  case " ${known_defect[*]} " in
    *" ${f} "*) printf 'KNOWN %s (recorded defect, see known_defect)\n' "${f}"
                known_seen=$((known_seen + 1));;
    *)          bad "purge changed or destroyed ${f}";;
  esac
done < /tmp/after.hash
if [ "${known_seen}" -eq 0 ] && [ "${#known_defect[@]}" -gt 0 ]; then
  bad "a recorded defect stopped reproducing; move its entry into must_survive"
fi

echo '--- other owners'
if [ -e "${R}/run/userdb/someone.user" ]
then ok  "another provider's userdb record survives"
else bad "another provider's userdb record was deleted"; fi
if [ -e "${R}/run/userdb/eph.user" ]
then bad 'our own ephemeral userdb record outlived the removal'
else ok  'our own ephemeral userdb record was cleaned up'; fi
if chroot "${R}" dpkg-query -W hdw4s >/dev/null 2>&1
then bad 'dpkg still knows the package after purge'
else ok  'dpkg has no record of the package after purge'; fi

echo '--- what purge left behind'
for p in /etc/hdw4s /var/lib/hdw4s /usr/lib/hdw4s /usr/share/hdw4s \
         /etc/opt/chrome/policies/managed /opt/gst-web \
         /etc/dconf/db/hdw4s-ephemeral /etc/dconf/profile/hdw4s-ephemeral \
         /etc/sysctl.d/60-hdw4s.conf; do
  if [ -d "${R}${p}" ]; then
    printf '      left  %s (%s entries)\n' "${p}" \
      "$(find "${R}${p}" -mindepth 1 -maxdepth 1 | wc -l)"
  elif [ -e "${R}${p}" ]; then printf '      left  %s\n' "${p}"
  else printf '      gone  %s\n' "${p}"; fi
done

echo
if [ "${fail}" -eq 0 ]; then echo 'PASS'; exit 0; else echo 'FAIL'; exit 1; fi
