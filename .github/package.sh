#!/bin/bash -e
# Build the .deb from the tree this is run in, and read back what it contains.
#
# usage: .github/package.sh [--dirty] [--no-lintian]
#
# THE BUILD ONLY. The checks and the behaviour tests are a separate question with
# a separate cost -- about six minutes against ten seconds for this -- and the
# deploy tool used to run them twice per box on the way to a package, because
# building went through checks.sh. Both callers now come here: checks.sh
# --package (CI, where the full run is the point) and private/build.sh (a
# deploy, where the checks run beside it instead of in front of it).
#
# A TREE THAT MATCHES NO COMMIT is refused unless --dirty says so on purpose: an
# artefact nobody can reproduce, and during mutation testing one that may carry a
# defect somebody injected to prove a check can fail. A copy of the tree with no
# .git of its own cannot be judged here and says so; its caller knows the source.
LC_ALL=C; PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

dirty_ok='' lint=1
for a in "$@"; do
  case "${a}" in
    --dirty) dirty_ok=1 ;;
    --no-lintian) lint='' ;;   # a deploy: lintian is informational, CI runs it
    *) echo "package.sh: unknown argument '${a}'" >&2; exit 1 ;;
  esac
done
note() { printf '%-28s %s\n' "$1" "$2"; }
die()  { note "$1" "FAIL: $2"; exit 1; }

top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "${top}" ] && [ "${top}" = "$(pwd -P)" ]; then
  dirty="$(git status --porcelain --untracked-files=no 2>/dev/null || true)"
  if [ -n "${dirty}" ]; then
    printf '%s\n' "${dirty}"
    [ -n "${dirty_ok}" ] ||
      die 'working tree' 'refusing to build: tracked files differ from HEAD (listed above); commit, stash, or pass --dirty on purpose'
    note 'build from dirty tree' 'ALLOWED by --dirty; this artefact matches no commit'
  fi
else
  note 'working tree' 'not judged here: this copy has no repository of its own'
fi

version="$(dpkg-parsechangelog -S Version)"
dpkg-buildpackage -us -uc -b >/dev/null
deb="../hdw4s_${version}_all.deb"
[ -f "${deb}" ] || die 'dpkg-buildpackage' "did not produce ${deb}"
note 'built' "$(basename "${deb}")"

# What the recipient actually receives. A glob in debian/install that matched
# nothing, a unit renamed in the tree but not in the file that copies it, a
# dh_install failure swallowed by the build -- none of those are visible from the
# source, and all of them end as a package that installs cleanly and is missing a
# unit. That is the shape once found on a live box: the file was absent, so
# "systemctl cat" did not answer, and nothing anywhere failed.
units=()
for u in hdw4s*.service hdw4s*.socket hdw4s*.timer hdw4s*.slice hdw4s*.path; do
  [ -e "${u}" ] && units+=("${u}")
done
# An empty list would make the loop below a silent pass.
[ "${#units[@]}" -gt 0 ] || die 'package contents' 'no unit files in this tree; wrong working directory?'
contents="$(dpkg-deb -c "${deb}" 2>/dev/null | awk '{print $NF}')"
[ -n "${contents}" ] || die 'package contents' 'dpkg-deb -c produced nothing'
missing=0
for u in "${units[@]}"; do
  grep -qxF "./usr/lib/systemd/system/${u}" <<<"${contents}" ||
    { note "${u}" 'FAIL: is not in the built package'; missing=$((missing + 1)); }
done
[ "${missing}" = 0 ] || exit 1
note 'every unit is in the .deb' "ok (${#units[@]})"

# Shown, and fatal only on an error: lintian exits 0 on warnings, and some of its
# checks follow the version of groff on the machine rather than the package.
if [ -n "${lint}" ] && command -v lintian >/dev/null; then
  echo
  echo '== lintian (informational) =='
  lintian --fail-on error "${deb}" || die 'lintian' 'reported an error'
fi
