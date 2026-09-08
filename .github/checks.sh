#!/bin/bash -e
export LC_ALL='C'
set -o nounset -o pipefail

# Every check CI runs, in the order CI runs them. Run this before pushing and
# there should be no surprises afterwards; that is the entire point of it being
# a script rather than a list of steps in a workflow file.
#
#   .github/checks.sh
#
# Needs: shellcheck, groff-base, systemd, and for --package also debhelper,
# dpkg-dev and fakeroot.

cd "$(dirname "$0")/.."

SCRIPTS=(hdw4s hdw4s-session hdw4s-run-session hdw4s-firewall hdw4s-update hdw4s-wait
         install.sh uninstall.sh wrappers/firefox wrappers/thunderbird
         debian/postinst debian/prerm debian/postrm .github/checks.sh)
UNITS=(hdw4s@.service hdw4s-proxy@.socket hdw4s-proxy@.service
       hdw4s-firewall.service hdw4s-firewall-check.service
       hdw4s-firewall.timer hdw4s-updater.service hdw4s-updater.timer
       hdw4s-reaper.service hdw4s-reaper.timer
       hdw4s.slice)

fail=0
note() { printf '%-28s %s\n' "$1" "$2"; }
bad()  { note "$1" "FAIL: $2"; fail=1; }

echo '== shell =='
for f in "${SCRIPTS[@]}"; do
  bash -n "$f" 2>/dev/null || bad "${f}" 'bash -n rejected it'
done
note 'bash -n' 'ok'
if out="$(shellcheck -f gcc "${SCRIPTS[@]}" 2>&1)" && [ -z "${out}" ]; then
  note 'shellcheck' 'ok'
else
  printf '%s\n' "${out}"
  bad 'shellcheck' 'findings above'
fi

# Every command a script dispatches must resolve to a function that exists.
# A "case" branch calling a name nobody defined parses cleanly, survives the
# linter, and fails only when somebody runs that one subcommand. When that
# subcommand is one a timer runs rather than a person, nothing surfaces it.
#
# (Note for the next person: a comment line may not begin with the linter's own
# name, because it then gets read as a directive and rejected as malformed.)
for f in hdw4s hdw4s-firewall; do
  while read -r fn; do
    [ -n "${fn}" ] || continue
    grep -qE "^${fn}\(\) \{" "${f}" ||
      bad "${f}" "dispatches ${fn}, which is not defined"
  done < <(grep -oE '\bcmd_[a-z_]+' "${f}" | sort -u)
done
note 'dispatch targets exist' 'ok'

echo
echo '== systemd units =='
for u in "${UNITS[@]}"; do
  # Unit files reference paths that only exist once installed, and reference
  # each other by name, so those two complaints are expected here and are not
  # what this check is looking for. Anything else -- an unknown directive, an
  # unparseable value -- is a real error that would only surface at runtime.
  out="$(systemd-analyze verify "./${u}" 2>&1 |
         grep -viE 'not executable|does not exist|man .* failed|command .* failed|Unit .* not found|ssh\.socket' || :)"
  [ -z "${out}" ] || { printf '%s\n' "${out}"; bad "${u}" 'verify reported the above'; }
done
note 'systemd-analyze verify' 'ok'

echo
echo '== documentation =='
# A converter that silently writes nothing is the failure mode worth guarding:
# ronn exits 0 after producing an empty file when it dislikes an argument.
if [ ! -s hdw4s.8 ]; then
  bad 'hdw4s.8' 'missing or empty'
else
  note 'hdw4s.8 non-empty' "$(wc -l < hdw4s.8) lines"
fi
if out="$(groff -man -Tutf8 -ww hdw4s.8 2>&1 >/dev/null)" && [ -z "${out}" ]; then
  note 'groff warnings' 'none'
else
  printf '%s\n' "${out}"
  bad 'groff' 'warnings above'
fi
for section in NAME SYNOPSIS DESCRIPTION COMMANDS CONFIGURATION \
               'SHARED HOME DIRECTORIES' 'REVERSE PROXY AND SECURITY' FILES; do
  grep -q "^\.SH \"\{0,1\}${section}" hdw4s.8 ||
    bad 'hdw4s.8' "section '${section}' is missing"
done
note 'required sections' 'present'

# The updater injects JavaScript into the streaming client's page. It is code
# we ship, and a syntax error in it would otherwise be found by a user looking
# at a blank browser tab, with nothing in any log to explain it.
if command -v node >/dev/null; then
  jstmp="$(mktemp --suffix=.js)"
  if python3 "$(dirname "$0")/extract-injected-js.py" > "${jstmp}" 2>/dev/null &&
     [ -s "${jstmp}" ]; then
    if node --check "${jstmp}" 2>/dev/null; then
      note 'injected javascript' 'parses'
    else
      node --check "${jstmp}" 2>&1 | head -5
      bad 'injected javascript' 'does not parse'
    fi
  else
    bad 'injected javascript' 'could not be extracted from hdw4s-update'
  fi
  rm -f "${jstmp}"
fi

echo
echo '== packaging =='
# The tag, the changelog and the built artifact have to agree, or a release
# ships a version nobody asked for.
version="$(dpkg-parsechangelog -S Version)"
note 'changelog version' "${version}"
if [ -n "${EXPECT_VERSION:-}" ] && [ "${version}" != "${EXPECT_VERSION}" ]; then
  bad 'version' "changelog says ${version}, tag says ${EXPECT_VERSION}"
fi
dpkg-parsechangelog >/dev/null || bad 'changelog' 'will not parse'

# The version is stated in the script rather than generated into it, so that
# the files in git are the files that ship down both distribution paths. That
# only works if something checks the two agree.
declared="$(sed -n "s/^HDW4S_VERSION='\(.*\)'\$/\1/p" hdw4s)"
if [ "${declared}" = "${version}" ]; then
  note 'hdw4s --version' "${declared}"
else
  bad 'hdw4s --version' "says ${declared}, changelog says ${version}"
fi

# Defaults are necessarily repeated between the scripts, the sample config and
# the man page. They drift silently, and only a user notices.
for setting in HDW4S_BASE_PORT:7300 HDW4S_BLOCK_SIZE:64; do
  key="${setting%%:*}"; want="${setting#*:}"
  for f in hdw4s hdw4s-firewall; do
    got="$(sed -n "s/^${key}=\([0-9]*\)\$/\1/p" "${f}" | head -n1)"
    [ "${got}" = "${want}" ] ||
      bad "${f}" "${key} is ${got}, expected ${want}"
  done
  grep -q "^#${key}=${want}\$" hdw4s.conf ||
    bad 'hdw4s.conf' "documents a different ${key}"
done
note 'defaults agree' 'ok'

# A package that builds but cannot be installed is not a working package. CI
# never installs this one -- pulling a whole desktop onto a runner is not worth
# it -- so at least check that every dependency names a package the archive
# actually has. This catches depending on something only one distribution
# ships, which is otherwise discovered by a person trying to install it.
if command -v apt-cache >/dev/null; then
  missing=''
  while read -r dep; do
    [ -n "${dep}" ] || continue
    cand="$(apt-cache policy "${dep}" 2>/dev/null | sed -n 's/  Candidate: //p')"
    [ -n "${cand}" ] && [ "${cand}" != '(none)' ] || missing="${missing} ${dep}"
  done < <(awk '/^Depends:/ { d = 1; sub(/^Depends:/, "") }
                /^[A-Z][A-Za-z-]*:/ && !/^Depends:/ { d = 0 }
                d { print }' debian/control |
           tr -d ' ' | tr ',' '\n' | grep -v '^[$]' | grep .)
  if [ -z "${missing}" ]; then
    note 'dependencies exist' 'ok'
  else
    bad 'dependencies' "not in the archive:${missing}"
  fi
fi

if [ "${1:-}" = '--package' ]; then
  echo
  echo '== build =='
  dpkg-buildpackage -us -uc -b >/dev/null
  deb="../hdw4s_${version}_all.deb"
  [ -f "${deb}" ] || bad 'dpkg-buildpackage' "did not produce ${deb}"
  note 'built' "$(basename "${deb}")"

  # Lintian's findings are shown but do not fail the run. It exits 0 on
  # warnings, and some of its checks are sensitive to the version of groff on
  # the machine rather than to anything in the package.
  if command -v lintian >/dev/null; then
    echo
    echo '== lintian (informational) =='
    lintian --fail-on error "${deb}" || bad 'lintian' 'reported an error'
  fi
fi

echo
if [ "${fail}" -eq 0 ]; then
  echo 'All checks passed.'
else
  echo 'Some checks failed.' >&2
fi
exit "${fail}"
