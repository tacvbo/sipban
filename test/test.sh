#!/bin/bash
#----------------------------------------------------------------------
# Runs every scenario (see run.sh) and checks the results.
# Exit status: 0 if every check passes, 1 otherwise. It takes about a
# minute.
#----------------------------------------------------------------------
T="$(cd "$(dirname "$0")" && pwd)"
W="$T/work"
FAILURES=0

pass() { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; FAILURES=$((FAILURES + 1)); }

# check <description> <command...>
check() {
    local description="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}
has()   { grep -qF -- "$2" "$W/$1"; }
lacks() { ! grep -qF -- "$2" "$W/$1"; }
times() { [ "$(grep -cF -- "$3" "$W/$2")" -eq "$1" ]; }
log_has()     { check "log has: $1" has sipban.log "$1"; }
log_lacks()   { check "log lacks: $1" lacks sipban.log "$1"; }
console_has() { check "console shows: $1" has console.out "$1"; }
no_errors()   { check "no Perl errors or warnings" lacks_errors; }
lacks_errors() { ! grep -v 'The set does not exist' "$W/stderr" "$W/stdout" | grep -q .; }

echo "== contacts ok: trusted IPs, events, whitelist, console"
"$T/run.sh" ok 12
log_has   'UNBLOCK => 192.0.2.99 (White List)'
log_has   'IPTABLES => INPUT rule for set sipban created'
log_has   'CONTACTS => 3 IPs with registered PJSIP contacts'
check     'repeated failure of a registered IP is logged once' \
          times 1 sipban.log 'IGNORE => 203.0.113.10 (Invalid Account, AccountID 205) trusted IP'
log_lacks '] BLOCK => 203.0.113.10'
log_has   '] BLOCK => 198.51.100.20 (Invalid Account, AccountID admin)'
log_has   'TRUST => 198.51.100.30 (Successful Auth, AccountID 300)'
log_has   'IGNORE => 198.51.100.30 (Invalid Account, AccountID 999) trusted IP'
log_lacks '] BLOCK => 198.51.100.30'
log_has   '] BLOCK => 198.51.100.40 (No Auth Response, 3 unanswered challenges)'
log_lacks '] BLOCK => 198.51.100.50'
log_has   '] BLOCK => 198.51.100.60 (Challenge Response Failed, AccountID 101)'
log_has   '] BLOCK => 198.51.100.70 (Failed ACL, AccountID anonymous)'
log_lacks '192.0.2.55'
log_has   '] BLOCK => 203.0.113.11 (Challenge Response Failed, AccountID 102, 4 failures from a trusted IP)'
log_lacks '198.51.100.90'
log_lacks '2001:db8::1'
log_has   '] BLOCK => 198.51.100.95 (Invalid Account, AccountID evil??[31m)'
check     'no control characters in the log' lacks sipban.log $'\x1b'
log_has   '] BLOCK => 198.51.100.80 (Invalid Account, AccountID split)'
log_has   'UNBLOCK => 198.51.100.20 (Manual Unblock)'
log_has   'IPTABLES => INPUT rule for set sipban erased'
log_has   'SipBan Stop'
console_has '192.0.2.5 is whitelisted'
console_has '198.51.100.20 is already blocked'
console_has '203.0.113.10 (registered contact)'
console_has '198.51.100.30 (successful authentication)'
console_has '198.51.100.20 unblocked'
check     'dump keeps the earlier block' has sipban.dump 'add sipban 198.51.100.200 '
check     'dump lacks the whitelisted IP' lacks sipban.dump '192.0.2.99'
no_errors

echo "== PJSIPShowContacts fails: only SuccessfulAuth trusts IPs"
"$T/run.sh" error 8
check     'the failure is logged once' \
          times 1 sipban.log 'CONTACTS => PJSIPShowContacts failed (Permission denied)'
check     'no more PJSIPShowContacts requests' has ami.err 'PJSIPShowContacts requests: 1'
log_has   '] BLOCK => 203.0.113.10 (Invalid Account, AccountID 205)'
log_has   'TRUST => 198.51.100.30 (Successful Auth, AccountID 300)'
no_errors

echo "== no contacts: keeps asking, without errors"
"$T/run.sh" empty 8
log_lacks 'PJSIPShowContacts failed'
check     'more than one PJSIPShowContacts request' lacks ami.err 'PJSIPShowContacts requests: 1'
log_has   '] BLOCK => 203.0.113.10 (Invalid Account, AccountID 205)'
no_errors

echo "== configuration of version 1.0: the new parameters use their defaults"
CONF="$T/sipban-defaults.conf" "$T/run.sh" ok 10
log_lacks '] BLOCK => 198.51.100.40'
log_has   'IGNORE => 203.0.113.11 (Challenge Response Failed, AccountID 102) trusted IP'
log_lacks '] BLOCK => 203.0.113.11'
log_has   '] BLOCK => 198.51.100.60 (Challenge Response Failed, AccountID 101)'
no_errors

echo "== INPUT rule left by an unclean stop (2 copies)"
RULES=2 "$T/run.sh" ok 4
check     'the rule is not inserted again' lacks calls.log '-I INPUT'
check     'both copies are deleted on stop' times 2 calls.log '-D INPUT'
check     'no copies remain' has rules '0'
no_errors

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "All checks passed"
    exit 0
fi
echo "$FAILURES checks failed (the files of the last scenario are in test/work/)"
exit 1
