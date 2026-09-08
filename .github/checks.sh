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
         debian/postinst debian/prerm debian/postrm
         .github/checks.sh .github/tests.sh)
UNITS=(hdw4s@.service hdw4s-proxy@.socket hdw4s-proxy@.service
       hdw4s-firewall.service hdw4s-firewall-check.service
       hdw4s-firewall.timer hdw4s-updater.service hdw4s-updater.timer
       hdw4s-reaper.service hdw4s-reaper.timer
       hdw4s.slice)

fail=0
mark=0
note() { printf '%-28s %s\n' "$1" "$2"; }
bad()  { note "$1" "FAIL: $2"; fail=1; }
# A summary line after a loop must not claim success the loop did not have.
# These used to print "ok" unconditionally, so a run that had already reported
# a failure went on to say the same check passed two lines later. The exit
# status was right and the report was not, which is the worse half to get
# wrong: the report is the part a person reads.
begin() { mark="${fail}"; }
okif()  { if [ "${fail}" = "${mark}" ]; then note "$1" 'ok'; fi; }
# A check that cannot run has to say so. Silently skipping one means CI prints
# "All checks passed" for a check it never performed.
skip()  { note "$1" "skipped: $2"; }

echo '== shell =='
begin
for f in "${SCRIPTS[@]}"; do
  bash -n "$f" 2>/dev/null || bad "${f}" 'bash -n rejected it'
done
okif 'bash -n'
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
begin
for f in hdw4s hdw4s-firewall; do
  while read -r fn; do
    [ -n "${fn}" ] || continue
    grep -qE "^${fn}\(\) \{" "${f}" ||
      bad "${f}" "dispatches ${fn}, which is not defined"
  done < <(grep -oE '\bcmd_[a-z_]+' "${f}" | sort -u)
done
okif 'dispatch targets exist'

echo
echo '== systemd units =='
begin
for u in "${UNITS[@]}"; do
  # Unit files reference paths that only exist once installed, and reference
  # each other by name, so those two complaints are expected here and are not
  # what this check is looking for. Anything else -- an unknown directive, an
  # unparseable value -- is a real error that would only surface at runtime.
  out="$(systemd-analyze verify "./${u}" 2>&1 |
         grep -viE 'not executable|does not exist|man .* failed|command .* failed|Unit .* not found|ssh\.socket' || :)"
  [ -z "${out}" ] || { printf '%s\n' "${out}"; bad "${u}" 'verify reported the above'; }
done
okif 'systemd-analyze verify'

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
               'SHARED HOME DIRECTORIES' 'REVERSE PROXY AND SECURITY' FILES \
               DIAGNOSTICS UPDATES LIMITATIONS; do
  grep -q "^\.SH \"\{0,1\}${section}" hdw4s.8 ||
    bad 'hdw4s.8' "section '${section}' is missing"
done
note 'required sections' 'present'

# The roff page is generated from the markdown one and committed alongside it,
# so the two can drift: an edit to the source that nobody regenerates ships a
# manual describing the previous release. Naming sections cannot catch that --
# the whole LIMITATIONS section could vanish and every named section would
# still be present. Regenerating and comparing can.
if command -v ronn >/dev/null; then
  regen="$(mktemp)"
  # The .TH line carries the build date and the leading .\" lines name the
  # generator's version, so both differ between machines and neither says
  # anything about content. Everything else must match exactly.
  strip() { grep -v '^\.\\"' "$1" | grep -v '^\.TH '; }
  if ronn --roff --pipe --manual='hdw4s' --organization='hdw4s' \
          --date='2000-01-01' hdw4s.8.md > "${regen}" 2>/dev/null &&
     [ -s "${regen}" ]; then
    if diff -q <(strip "${regen}") <(strip hdw4s.8) >/dev/null; then
      note 'hdw4s.8 matches its source' 'yes'
    else
      bad 'hdw4s.8' 'differs from hdw4s.8.md -- regenerate it'
      diff <(strip hdw4s.8) <(strip "${regen}") | head -10
    fi
  else
    bad 'hdw4s.8' 'could not be regenerated for comparison'
  fi
  rm -f "${regen}"
else
  skip 'hdw4s.8 matches its source' 'ronn is not installed (ruby-ronn)'
fi

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
else
  skip 'injected javascript' 'node is not installed'
fi

echo
echo '== behaviour tests =='
if "$(dirname "$0")/tests.sh" > /tmp/hdw4s-tests.$$ 2>&1; then
  printf '%-28s %s\n' 'tests.sh' "$(tail -n1 /tmp/hdw4s-tests.$$)"
else
  bad 'tests.sh' 'behaviour tests failed'
  grep -E '^  FAIL|failed\.$' /tmp/hdw4s-tests.$$ | sed 's/^/  /'
fi
rm -f /tmp/hdw4s-tests.$$
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
begin
for setting in HDW4S_BASE_PORT:7300 HDW4S_BLOCK_SIZE:64; do
  key="${setting%%:*}"; want="${setting#*:}"
  # Every script that carries its own copy, in either form it is written in.
  # hdw4s-wait was missing here, and it is the one whose drift is invisible:
  # ExecStartPre would poll the wrong port and every session start would time
  # out with nothing to say why.
  for f in hdw4s hdw4s-firewall hdw4s-wait hdw4s-session; do
    got="$(sed -n "s/^${key}=\([0-9]*\)\$/\1/p;s/^ *: \"\${${key}:=\([0-9]*\)}\"\$/\1/p" \
           "${f}" | head -n1)"
    [ -n "${got}" ] ||
      bad "${f}" "does not set a default for ${key}"
    [ -z "${got}" ] || [ "${got}" = "${want}" ] ||
      bad "${f}" "${key} is ${got}, expected ${want}"
  done
  grep -q "^#${key}=${want}\$" hdw4s.conf ||
    bad 'hdw4s.conf' "documents a different ${key}"
done
okif 'defaults agree'

# "hdw4s show" carries its own table of the defaults a session falls back to,
# so that it can report an effective value for a setting nobody has written
# down. A table like that is drift waiting to happen, and the drift is
# invisible: show would confidently report a default the session does not use.
begin
while IFS=: read -r key def; do
  [ -n "${key}" ] || continue
  found=''
  for f in hdw4s-run-session hdw4s-session hdw4s; do
    got="$(sed -n "s/^ *: \"\${${key}:=\(.*\)}\"\$/\1/p" "${f}" | head -n1)"
    [ -n "${got}" ] || continue
    found='yes'
    [ "${got}" = "${def}" ] ||
      bad 'hdw4s show' "${key} defaults to ${def} here and ${got} in ${f}"
    break
  done
  # HDW4S_IDLE_DAYS is not defaulted with the ":=" form; the reaper passes it
  # to setting_of instead.
  if [ -z "${found}" ] && [ "${key}" = 'HDW4S_IDLE_DAYS' ]; then
    grep -q "setting_of \"\${inst}\" ${key} ${def}\b" hdw4s || found=''
    grep -q "setting_of \"\${inst}\" ${key} ${def}" hdw4s && found='yes'
  fi
  [ -n "${found}" ] ||
    bad 'hdw4s show' "${key} is in its table but nothing defaults it to ${def}"
done < <(sed -n '/^SESSION_SETTINGS=(/,/^)/p' hdw4s |
         sed -n "s/^  '\(.*\)'\$/\1/p")
okif 'show defaults match the session scripts'

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
else
  skip 'dependencies exist' 'apt-cache is not available'
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
