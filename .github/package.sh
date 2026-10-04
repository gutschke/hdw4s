#!/bin/bash -e
# Build the .debs from the tree this is run in, and read back what they contain.
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
# Every binary package debian/control declares, each of which must have been
# built. Derived from the control file rather than listed: hdw4s-shared-sweep
# was added as a second one, and a list here would be right until the third.
debs=()
while read -r pkg; do
  [ -n "${pkg}" ] || continue
  deb="../${pkg}_${version}_all.deb"
  [ -f "${deb}" ] || die 'dpkg-buildpackage' "did not produce ${deb}"
  note 'built' "$(basename "${deb}")"
  debs+=("${deb}")
done < <(awk '/^Package:/ {print $2}' debian/control)
[ "${#debs[@]}" -gt 0 ] || die 'debian/control' 'declares no binary package'

# What the recipient actually receives. A glob in debian/install that matched
# nothing, a unit renamed in the tree but not in the file that copies it, a
# dh_install failure swallowed by the build -- none of those are visible from the
# source, and all of them end as a package that installs cleanly and is missing a
# unit. That is the shape once found on a live box: the file was absent, so
# "systemctl cat" did not answer, and nothing anywhere failed.
#
# EXACTLY ONE package, now that there are two: hdw4s's unit lines are globs, the
# shared tool's units match them, and debian/rules excludes them from hdw4s by
# a list it derives. If that derivation broke, a unit would be in BOTH packages
# and dpkg would refuse to install the second -- on the machine, not here.
units=()
for u in hdw4s*.service hdw4s*.socket hdw4s*.timer hdw4s*.slice hdw4s*.path; do
  [ -e "${u}" ] && units+=("${u}")
done
# An empty list would make the loop below a silent pass.
[ "${#units[@]}" -gt 0 ] || die 'package contents' 'no unit files in this tree; wrong working directory?'
contents=''
for deb in "${debs[@]}"; do
  c="$(dpkg-deb -c "${deb}" 2>/dev/null | awk '{print $NF}')"
  [ -n "${c}" ] || die 'package contents' "dpkg-deb -c ${deb} produced nothing"
  # Directories are shared by design (./usr/lib/hdw4s/ is in both); files are not.
  contents+="$(grep -v '/$' <<<"${c}" | sed "s|^|$(basename "${deb}" | cut -d_ -f1) |")"$'\n'
done
missing=0
for u in "${units[@]}"; do
  n="$(awk -v p="./usr/lib/systemd/system/${u}" '$2 == p' <<<"${contents}" | wc -l)"
  [ "${n}" = 1 ] ||
    { note "${u}" "FAIL: is in ${n} built packages, not exactly one"; missing=$((missing + 1)); }
done
[ "${missing}" = 0 ] || exit 1
note 'every unit is in one .deb' "ok (${#units[@]})"
dup="$(awk '{print $2}' <<<"${contents}" | grep . | sort | uniq -d)"
[ -z "${dup}" ] || { printf '%s\n' "${dup}"; die 'package contents' 'the files above are in more than one package'; }
note 'no file in two packages' 'ok'

# Shown, and fatal only on an error: lintian exits 0 on warnings, and some of its
# checks follow the version of groff on the machine rather than the package.
if [ -n "${lint}" ] && command -v lintian >/dev/null; then
  echo
  echo '== lintian (informational) =='
  lintian --fail-on error "${debs[@]}" || die 'lintian' 'reported an error'
fi
