#!/bin/bash
#----------------------------------------------------------------------
# Runs sipban against the simulated AMI (fake_ami.pl) for one scenario
# and leaves everything in test/work/.
#
# Usage: run.sh [contacts mode: ok|error|empty] [seconds before the console]
#
# Environment:
#   CONF       configuration file (default test/sipban.conf)
#   RULES      copies of the sipban INPUT rule that already exist at
#              startup, as after an unclean stop (default 0)
#   SIPBAN_PL  program to test (default ../sipban.pl)
#
# Nothing touches the real system: ipset and iptables are the fake
# commands in test/bin/, and the CPAN modules are the stubs in test/lib/.
# The AMI listens on 127.0.0.1:15038 and the console on 127.0.0.1:14451.
#----------------------------------------------------------------------
T="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-ok}"
SECONDS_BEFORE_CONSOLE="${2:-12}"
W="$T/work"
rm -rf "$W"
mkdir -p "$W"
export FAKE_STATE="$W"
[ -n "$RULES" ] && echo "$RULES" > "$W/rules"

sed "s|TESTDIR|$T|g" "${CONF:-$T/sipban.conf}" > "$W/sipban.conf"
printf '127.0.0.1\n192.0.2.0/24 # office\n' > "$W/sipban.wl"
# dump of a previous run: one whitelisted IP and one that is not
printf '%s\n' 'create sipban hash:net family inet hashsize 4096 maxelem 65536 timeout 604800' \
              'add sipban 192.0.2.99 timeout 500000' \
              'add sipban 198.51.100.200 timeout 500000' > "$W/sipban.dump"
# sipban reads /etc/sipban.conf; the copy under test reads the test one
sed "s|/etc/sipban.conf|$W/sipban.conf|" "${SIPBAN_PL:-$T/../sipban.pl}" > "$W/sipban.pl"

perl "$T/fake_ami.pl" 15038 "$MODE" 2> "$W/ami.err" &
AMI=$!
sleep 0.5
perl -I "$T/lib" "$W/sipban.pl" > "$W/stdout" 2> "$W/stderr" &
SIPBAN=$!
sleep "$SECONDS_BEFORE_CONSOLE"
perl "$T/console.pl" 14451 "block 192.0.2.5" "block 198.51.100.20" "trusted" \
     "unblock 198.51.100.20" "block" "quit" > "$W/console.out"
kill -TERM $SIPBAN
sleep 1
kill $AMI 2>/dev/null
wait 2>/dev/null
exit 0
