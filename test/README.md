# sipban tests

These tests run `sipban.pl` against a simulated Asterisk Manager Interface
(AMI). They do not need Asterisk, ipset, iptables, root or the CPAN modules,
and they do not touch the firewall of the machine.

## Run

```
test/test.sh
```

It runs every scenario, prints one line per check and ends with
`All checks passed` (exit status 0) or with the number of failed checks
(exit status 1). It takes about a minute.

To run a single scenario and look at the results:

```
test/run.sh ok 12
less test/work/sipban.log
```

Requirements: Perl 5 with its core modules, and the ports 15038 (AMI) and
14451 (console) free on 127.0.0.1.

## What is tested

| Scenario | Checks |
|---|---|
| contacts ok | Registered PJSIP contacts and SuccessfulAuth make an IP trusted; its failures are logged once as `IGNORE`. Unknown IPs are blocked with InvalidAccountID, ChallengeResponseFailed and FailedACL. Unanswered challenges block after `flood.count`. A brute force attack from a trusted IP is blocked after `trust.max_failures`. Whitelist classes and comments, services that are not processed, IPv6 addresses, control characters in the AccountID, an event split between two reads, the console commands and the dump file. |
| PJSIPShowContacts fails | The error is logged once, sipban stops asking, and SuccessfulAuth still trusts IPs. |
| no contacts | "No Contacts found" is not an error: sipban keeps asking. |
| configuration of version 1.0 | A configuration without `[trust]` and `flood.grace` works with the defaults. |
| INPUT rule left by an unclean stop | sipban deletes the leftover copies, inserts the rule once and deletes it on stop. |
| empty dump file | An empty or damaged dump file (older versions left it empty after a failed save) does not stop sipban: it starts with an empty set. |
| no dump file | sipban creates the set and saves it on stop. |
| wrong ipset path | sipban refuses to start with a clear error and exit status 78, inserts no rule and keeps the dump file. |
| ipset fails to block and to save | The failures are logged as `ERROR` instead of `BLOCK`, the console reports them, and the dump file is kept. |

To check that a change does not break anything, run `test/test.sh` before
and after it. To test another version of the program:

```
SIPBAN_PL=/path/to/sipban.pl test/test.sh
```

## Files

| File | Purpose |
|---|---|
| `test.sh` | Runs the scenarios and checks the results. |
| `run.sh` | Runs one scenario: starts the simulated AMI and sipban, sends console commands and stops sipban with SIGTERM. The results stay in `work/`. |
| `fake_ami.pl` | Simulated AMI: answers Login, Ping and PJSIPShowContacts, and sends the security events of the scenario with the format of Asterisk 16 (PJSIP). |
| `console.pl` | Sends commands to the sipban console and prints the answers. |
| `bin/ipset`, `bin/iptables` | Fake commands: they keep their state in files of `work/` and log every call to `work/calls.log`. `bin/ipset` can simulate failures (`IPSET_FAIL`). |
| `lib/` | Stubs of the CPAN modules (Config::Simple, Tie::Cache, Proc::PID::File, Net::Whois::IP). They take precedence over the installed modules. |
| `sipban.conf` | Configuration of the tests: small thresholds and a contact refresh every 2 seconds. |
| `sipban-defaults.conf` | Configuration in the format of version 1.0. |

`run.sh` uses a copy of `sipban.pl` that reads `work/sipban.conf` instead of
`/etc/sipban.conf`, and `sipban.conf` points the commands, the whitelist, the
dump file and the log to `test/`.

`run.sh` options (environment variables):

* `CONF`: configuration file (default `test/sipban.conf`).
* `RULES`: copies of the INPUT rule that exist at startup (default 0).
* `SIPBAN_PL`: program to test (default `sipban.pl` of the repository).
* `CONF_SED`: sed expression applied to the configuration, e.g. to use a
  wrong ipset path.
* `IPSET_FAIL`: ipset commands that fail, e.g. `IPSET_FAIL="add save"`.
* `DUMP`: dump file at startup: `previous` (default, two blocked IPs),
  `empty` (0 bytes) or `none`.

## Results in work/

| File | Content |
|---|---|
| `sipban.log` | Log of sipban. |
| `console.out` | Answers of the console commands. |
| `calls.log` | Every ipset and iptables call. |
| `sipban.dump` | Dump file saved on stop. |
| `rules` | Copies of the INPUT rule at the end. |
| `stderr`, `stdout` | Output of sipban (empty, unless sipban stops with an error). |
| `console.err` | Errors of the console client (e.g. when sipban did not start). |
| `ami.err` | Number of PJSIPShowContacts requests. |
| `exit_status` | Exit status of sipban: 0 after SIGTERM, 78 after an error at startup. |

## Limits

The simulated AMI follows the format of the events in the Asterisk 16.3.0
source code, but it is not Asterisk: before relying on a change, also check
it on a real server.
