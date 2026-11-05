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
#   CONF_SED   sed expression applied to the configuration, e.g. to use a
#              wrong ipset path
#   IPSET_FAIL ipset commands that fail (see bin/ipset), e.g. "add save"
#   DUMP       dump file at startup: "previous" (default, two blocked IPs),
#              "empty" (0 bytes) or "none"
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

sed -e "${CONF_SED:-}" -e "s|TESTDIR|$T|g" "${CONF:-$T/sipban.conf}" > "$W/sipban.conf"
printf '127.0.0.1\n192.0.2.0/24 # office\n# 198.51.100.20 commented out\n' > "$W/sipban.wl"
case "${DUMP:-previous}" in
  previous)
    # dump of a previous run: one whitelisted IP and one that is not
    printf '%s\n' 'create sipban hash:net family inet hashsize 4096 maxelem 65536 timeout 604800' \
                  'add sipban 192.0.2.99 timeout 500000' \
                  'add sipban 198.51.100.200 timeout 500000' > "$W/sipban.dump" ;;
  empty) : > "$W/sipban.dump" ;;
esac
# sipban reads /etc/sipban.conf; the copy under test reads the test one
sed "s|/etc/sipban.conf|$W/sipban.conf|" "${SIPBAN_PL:-$T/../sipban.pl}" > "$W/sipban.pl"

perl "$T/fake_ami.pl" 15038 "$MODE" 2> "$W/ami.err" &
AMI=$!
sleep 0.5
perl -I "$T/lib" "$W/sipban.pl" > "$W/stdout" 2> "$W/stderr" &
SIPBAN=$!
sleep "$SECONDS_BEFORE_CONSOLE"
perl "$T/console.pl" 14451 "block 192.0.2.5" "block 198.51.100.20" "trusted" \
     "unblock 198.51.100.20" "block" "quit" > "$W/console.out" 2> "$W/console.err"
kill -TERM $SIPBAN 2>/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 $SIPBAN 2>/dev/null || break
    sleep 0.5
done
kill -KILL $SIPBAN 2>/dev/null
wait $SIPBAN 2>/dev/null
echo $? > "$W/exit_status"
kill $AMI 2>/dev/null
wait 2>/dev/null
exit 0
