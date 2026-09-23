#!/bin/bash -e
# Which built-in defaults does the suite never actually exercise?
#
# Written after a release blocker that a green test was named for. The harness
# set HDW4S_GATE_MODE for every case, so the shipped default was never run --
# and a test called "default_gate_is_mint" passed throughout while measuring the
# EXPLICIT value. The router and the page then disagreed about that default and
# every arrival minted a second session.
#
# This checks a property of the SUITE, not of any test's name, which is the whole
# point: it does not depend on anyone having named anything honestly. A sweep for
# suspicious names finds only the cases that announce themselves.
#
# It reports, it does not judge. An uncovered default may be fine -- the question
# is whether anyone decided that.
#
# AND IT SEPARATES TWO KINDS, because the first version did not and produced
# twelve findings of which most were correct behaviour. A test MUST override
# HDW4S_ETCDIR and friends: their defaults point at the real machine, and a test
# exercising them would write to /etc. Those being uncovered is the harness
# working. What matters is a default that encodes BEHAVIOUR -- which arm, which
# mode, which policy -- because there the untested value is the one that ships.
#
# A tool that reports a dozen correct things alongside the real one gets ignored,
# which is how the first version of the litter checker failed too.
LC_ALL=C; PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd "$(dirname "$0")/../.."

# Every environment variable the product reads WITH a fallback.
defaults=$(
  { grep -rhoE 'os\.environ\.get\("[A-Z0-9_]+", *"[^"]*"\)' \
        hdw4s-demux 2>/dev/null | sed -E 's/.*get\("([A-Z0-9_]+)".*/\1/'
    grep -rhoE '\$\{(HDW4S_[A-Z0-9_]+):-' hdw4s hdw4s-run-session hdw4s-session \
        hdw4s-webroot hdw4s-ephemeral-slots 2>/dev/null | sed -E 's/.*\{([A-Z0-9_]+):-/\1/'
  } | sort -u)

printf '%-34s %-10s %s\n' 'VARIABLE' 'SET BY' 'VERDICT'
n_uncov=0
for v in ${defaults}; do
  # Where does a test set it? Counted separately from where the product reads it.
  in_suite=$(grep -rlE "(^|[^A-Z_])${v}=" .github/tests.sh .github/live/*.py .github/live/*.sh 2>/dev/null | wc -l)
  # NO second heuristic here, deliberately.
  #
  # The first version tried to detect "but some test leaves it unset" with a
  # keyword grep, and reported "both arms present" for a variable that had just
  # been re-pinned -- because the pattern matched the test's own prose rather
  # than the harness's behaviour. A tool written to find claims stronger than
  # their evidence had shipped with one. It is removed rather than tuned: the
  # question "does any code path leave this unset" is not answerable by grep, and
  # a weak answer dressed as a strong one is worse than no column at all.
  #
  # What remains IS decidable: whether the suite mentions the variable at all.
  # A behaviour default the suite touches deserves a human deciding whether the
  # shipped value is ever what runs. That judgement is not automated here.
  # Redirection knobs: a test must set these or it writes to the real machine.
  case "${v}" in
    *DIR|*ROOT|*PATH|*_PY|HDW4S_DEMUX_BIND|HDW4S_DEMUX_PORT|HDW4S_DEMUX_CRED|HDW4S_DEMUX_STATE)
      kind='path' ;;
    *) kind='behaviour' ;;
  esac
  if [ "${in_suite}" -eq 0 ]; then
    printf '%-34s %-10s %s\n' "${v}" 'nowhere' 'untouched -- the shipped value is what every test runs'
  elif [ "${kind}" = 'path' ]; then
    printf '%-34s %-10s %s\n' "${v}" "${in_suite} file(s)" 'redirection knob -- a test MUST set this'
  else
    printf '%-34s %-10s %s\n' "${v}" "${in_suite} file(s)" '*** BEHAVIOUR default, and the suite sets it -- CHECK BY HAND ***'
    n_uncov=$((n_uncov+1))
  fi
done
echo
echo "BEHAVIOUR defaults the suite touches -- read each one: ${n_uncov}"
echo "(redirection knobs are excluded -- a test must override those or it writes to the real machine)"
