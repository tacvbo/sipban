# SIPban

## Description

SIPban stops SIP scanning attacks. It monitors the security events of the
Asterisk Manager Interface (AMI) and blocks the IP addresses of the
attackers with ipset and iptables.

It connects to the AMI with a user that only reads the security events, and
it processes the events of the PJSIP and SIP channels (also IAX and AMI).

Upstream tested SIPban with Asterisk 16.3.0 to 22.1.0. The fork changes were
checked against the source code of Asterisk 16.3.0.

## Fork changes (version 1.1.0, 2026-11-04)

This fork (https://github.com/tacvbo/sipban) focuses on PJSIP and on not
blocking your own phones. Phones behind NAT share the same public IP, so with
the original rules a single phone with a wrong account blocked the whole
office, and normal traffic (Asterisk challenges every REGISTER, INVITE and
SUBSCRIBE with a 401) reached the ChallengeSent flood counter.

* **Trusted IPs**: an IP with a registered PJSIP contact (requested with the
  AMI action *PJSIPShowContacts* every `trust->refresh` seconds) or with a
  *SuccessfulAuth* event in the last `trust->ttl` seconds is not blocked by
  InvalidAccountID, InvalidPassword, ChallengeResponseFailed, FailedACL or
  unanswered challenges. Each failure is logged as `IGNORE`, at most once
  per hour. A brute force attack from a trusted IP is still blocked after
  `trust->max_failures` failures within `trust->interval` seconds.
* **Unanswered challenges** replace the ChallengeSent counter: after a
  challenge, sipban waits `flood->grace` seconds for the *SuccessfulAuth* of
  the same session. Phones answer their challenges and scanners usually do
  not; `flood->count` unanswered challenges within `flood->interval` seconds
  block the IP.
* **New events**: *ChallengeResponseFailed* (PJSIP reports a wrong password
  with it and never sends InvalidPassword) and *FailedACL*.
* The `BLOCK` log line includes the AccountID, which helps to find a phone
  with a wrong account.
* **Failures are visible**: if the ipset or iptables command is missing, the
  set cannot be created or the INPUT rule cannot be inserted, sipban stops at
  startup with an error (exit status 78) instead of logging blocks that do
  not happen. Other ipset and iptables failures are logged as `ERROR`.
* The set is saved to a temporary file first, so a failed save no longer
  empties the dump file, and an empty or damaged dump file starts an empty
  set.
* At startup, the copies of the INPUT rule left by an unclean stop are
  deleted before the rule is inserted, and every copy is deleted on stop.
* The whitelist accepts classes (`192.0.2.0/24`) and comments (`#`), and
  whitelisted addresses are removed from the set at startup and on
  `restore`.
* The console shows until when each IP is blocked or trusted; new command
  `trusted`.
* init.d: `reload` restarts sipban (it used to stop it) and `start` reports
  a failed start. systemd: the errors go to the journal, and a startup error
  does not cause a restart loop.
* Tests with a simulated AMI in `test/`.
* Removed: the legacy iptables version, the Docker files and the firewall
  sample.

Requirements for the trust by contact:

* The AMI user needs `write = system` (the sample *manager.conf* already has
  it). If *PJSIPShowContacts* fails, sipban logs it once and only uses the
  *SuccessfulAuth* events.
* For phones behind NAT, the PJSIP endpoints need `rewrite_contact=yes` (the
  FreePBX default), so the contact has the public IP of the phone.

Log examples:

```
[2026-11-04 17:13:52] CONTACTS => 3 IPs with registered PJSIP contacts
[2026-11-04 17:13:53] IGNORE => 203.0.113.10 (Invalid Account, AccountID 205) trusted IP
[2026-11-04 17:13:53] BLOCK => 198.51.100.20 (Invalid Account, AccountID admin)
[2026-11-04 17:13:53] TRUST => 198.51.100.30 (Successful Auth, AccountID 300)
[2026-11-04 17:13:54] BLOCK => 198.51.100.40 (No Auth Response, 5 unanswered challenges)
[2026-11-04 17:13:54] BLOCK => 203.0.113.11 (Challenge Response Failed, AccountID 102, 30 failures from a trusted IP)
```

## Upstream changes (2024-12-02)

* SIPban uses ipset ([ipset.netfilter.org](https://ipset.netfilter.org)):
  iptables checks a single rule against a hash of addresses instead of one
  rule per address, which is faster and changes the rules less often.
* The set removes each block when its timeout expires. sipban also keeps the
  expiration time of each block, to list the blocks and to block an IP
  address again after its block expires.
* Only one rule is inserted at the top of the iptables INPUT chain, instead of
  an additional chain.
* The set accepts whole classes (e.g. 192.0.2.0/24); you can block one from
  the console or with **sipban_admin.bash**.
* Upstream tested it on Ubuntu 22.04, Debian 12 and Fedora 41.
* **sipban_admin.bash** is a wrapper for common ipset commands on the sipban
  set.
* The systemd unit starts after "netfilter-persistent.service".

## Install

sipban changes the iptables rules, so it must run as **root**.

1. Download the files

    ```
    git clone https://github.com/tacvbo/sipban.git
    ```

2. Install the dependencies:

    a) Ubuntu/Debian

    ```
    sudo apt-get install iptables ipset libproc-pid-file-perl libconfig-simple-perl libnet-whois-ip-perl libtime-hires-perl libtie-cache-perl
    ```

    b) Red Hat/CentOS/Fedora

    ```
    sudo dnf install iptables-nft ipset perl-Proc-PID-File perl-Config-Simple perl-Net-Whois-IP perl-Time-HiRes perl-Tie-Cache
    ```

3. Copy the program and the configuration files

    ```
     cd sipban
     sudo cp sipban.pl /usr/local/bin/.
     sudo cp sipban_admin.bash /usr/local/bin/.
     sudo cp etc/sipban.conf /etc/.
     sudo cp etc/sipban.wl /etc/.
    ```

4. Add the sipban user to **/etc/asterisk/manager.conf**, as in the sample **etc/asterisk/manager.conf**, and reload the manager configuration with "**asterisk -rx 'manager reload'**".

5. Install the startup script

    a) init.d, for systems of the Red Hat family without systemd (e.g. CentOS 6)

    ```
    sudo cp etc/init.d/sipban /etc/init.d/.
    sudo chkconfig --level 345 sipban on
    sudo service sipban start
    ```

    "service sipban reload" restarts sipban: the blocked IPs are saved to the dump file and restored.

    b) systemd, for newer systems (e.g. Ubuntu, Debian, CentOS 7 and later)

    ```
    sudo cp etc/systemd/system/sipban.service /etc/systemd/system/.
    sudo systemctl daemon-reload
    sudo systemctl enable sipban
    sudo systemctl start sipban
    ```

    If sipban stops at startup (for example, because of a wrong path in **/etc/sipban.conf**), the reason is in **/var/log/sipban.log**, and also in **/var/log/sipban_daemon.log** (init.d) or in "systemctl status sipban" (systemd). systemd does not restart sipban after such an error.

6. Install the log rotation

    ```
    sudo cp etc/logrotate.d/sipban /etc/logrotate.d/.
    ```

    It rotates **/var/log/sipban.log** and **/var/log/sipban_daemon.log** every week and keeps 8 weeks. sipban cannot reopen its log, so the files are copied and truncated in place (copytruncate); the comments of the file explain it.

## Configure

1. **/etc/asterisk/manager.conf** needs this configuration:

    ```
    [general]
    enabled = yes

    port = 5038
    bindaddr = 127.0.0.1

    [sipban]
    secret = getout
    writetimeout = 100000
    read = security
    write = system,command
    ```

2. **/etc/sipban.conf** has the parameters of the service:

    ```
    # SIPban configuration file

    # Connection to the Asterisk Manager Interface (AMI)
    [ami]
    port = "5038"
    user = "sipban"
    pass = "getout"
    host = "127.0.0.1"
    # Seconds between pings that keep the connection alive
    ping = 60

    # Control console: connect with telnet to this address and port
    [control]
    port = "4451"
    address = "127.0.0.1"

    # iptables rule that applies the set of blocked IPs
    [iptables]
    # Directory of the iptables command ("which iptables" shows it)
    path       = "/sbin/"
    # DROP discards the packets of a blocked IP without answering (recommended).
    # REJECT answers every packet with an ICMP error, which tells the attacker
    # that the host exists and sends traffic back:
    #rule  = "REJECT --reject-with icmp-port-unreachable"
    rule       = "DROP"
    # File with the IP or IP/class addresses that are never blocked, one per line
    white_list = "/etc/sipban.wl"
    # Network interface where the attacks arrive
    interface  = "eno1"

    # ipset set with the blocked IPs
    [ipset]
    # Directory of the ipset command ("which ipset" shows it); if it is wrong,
    # sipban stops at startup with an error
    path     = "/sbin/"
    set_name = "sipban"
    # The set is saved to this file on stop and restored from it on start
    dump     = "/etc/sipban.dump"
    # Block time in seconds: 604800 = 1 week
    timeout  = 604800
    # 86400 = 1 day
    #timeout  = 86400

    [log]
    file = "/var/log/sipban.log"

    [flood]
    # Block an IP after "count" unanswered challenges (401/407) within
    # "interval" seconds. Phones always answer the challenge with their
    # credentials; scanners such as sipvicious don't. A challenge is
    # unanswered when no SuccessfulAuth arrives within "grace" seconds.
    count=5
    interval=60
    grace=5

    [trust]
    # Trusted IPs (with a registered PJSIP contact or a recent successful
    # authentication) are not blocked by InvalidAccountID, InvalidPassword,
    # ChallengeResponseFailed, FailedACL or unanswered challenges, so a phone
    # with a bad account does not block the other phones behind the same NAT.
    # Seconds an IP stays trusted after a successful authentication (0 = off)
    ttl=3600
    # Seconds between PJSIPShowContacts requests (0 = off)
    refresh=60
    # A trusted IP is still blocked (brute force) after "max_failures"
    # failures within "interval" seconds
    max_failures=30
    interval=60
    ```

    The "ipset->timeout" parameter is in seconds (604800 = 1 week).

    The "iptables->rule" option is what iptables does with the packets of a blocked IP: "DROP" (recommended) or "REJECT".

    The flood section blocks an IP after a number (count) of unanswered challenges within a period (interval) in seconds. With the default configuration, 5 unanswered challenges within 60 seconds block the IP. The trust section is explained in "Fork changes". The sections and parameters added by the fork are optional; their defaults are the values of the sample.

3. The whitelist is **/etc/sipban.wl**. It has the IP addresses that are never blocked, one IP address or class per line (e.g. 192.0.2.0/24); everything after "#" is a comment. You can change its location in the configuration file.

    You do not need to whitelist the phones: an IP with a registered PJSIP contact or a recent successful authentication is trusted automatically (see "Fork changes"). Whitelist what never registers or authenticates, such as SIP trunks identified by IP ("pjsip show identifies" lists their addresses), and the addresses you manage the server from: a blocked IP loses access to every port on the interface, not only SIP.

4. On stop, sipban saves the blocked IPs and their remaining time to **/etc/sipban.dump**, and it restores them on start.

5. The control console listens on port 4451 (the "control->port" parameter); connect to it with telnet.

## Operation

1. The service is fully automatic, but you can control it from the console on port 4451 (or the port set in **/etc/sipban.conf**) and with **sipban_admin.bash**, e.g.:

    ```
    [root@pbx ~]# telnet localhost 4451
    Trying ::1...
    telnet: connect to address ::1: Connection refused
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.

    SIPban  Copyright (C) 2019-2024 Fernando 'El Pop' Romo

    This program comes with ABSOLUTELY NO WARRANTY;
    for details https://www.gnu.org/licenses/gpl-3.0.en.html
    This is free software, and you are welcome to redistribute
    it under certain conditions.

    Type 'help' to list the commands
    sipban>help

    Commands:

    block                => list the blocked IP addresses
    block {ip address}   => block an IP address
    unblock {ip address} => unblock an IP address
    save                 => save the blocked IP addresses to the dump file
    restore              => restore the blocked IP addresses from the dump file
    uptime               => show how long sipban has been running
    whois {ip address}   => show the WHOIS information of an IP address
    wl                   => show the whitelist
    trusted              => show the trusted IP addresses (registered or authenticated)
    exit/quit            => close the console session

    sipban>
    ```

2. The log is **/var/log/sipban.log**

    ```
    [root@pbx ~]# tail -f /var/log/sipban.log
    [2026-11-04 10:40:25] SipBan Start
    [2026-11-04 10:40:25] WHITE LIST => 127.0.0.1
    [2026-11-04 10:40:25] WHITE LIST => 192.0.2.0/24
    [2026-11-04 10:40:25] IPSET => set sipban created
    [2026-11-04 10:40:25] IPTABLES => INPUT rule for set sipban created
    [2026-11-04 10:40:26] CONTACTS => 12 IPs with registered PJSIP contacts
    [2026-11-04 10:40:31] BLOCK => 198.51.100.81 (Invalid Account, AccountID 1000)
    [2026-11-04 10:53:46] BLOCK => 198.51.100.101 (Invalid Account, AccountID admin)
    [2026-11-04 10:56:42] BLOCK => 203.0.113.55 (Challenge Response Failed, AccountID 100)
    ...
    ```

3. You can check the iptables rule with "**iptables -vnL INPUT 1**"

    ```
    [root@pbx ~]# iptables -vnL INPUT 1
     4212  253K DROP all -- eno1 * 0.0.0.0/0 0.0.0.0/0 match-set sipban src
    ```

4. You can list the blocked IPs with "**sipban_admin.bash -l**"

    ```
    [root@pbx ~]# sipban_admin.bash -l

    Name: sipban
    Type: hash:net
    Revision: 7
    Header: family inet hashsize 4096 maxelem 65536 timeout 604800 bucketsize 12 initval 0x285783a9
    Size in memory: 3536
    References: 1
    Number of entries: 3
    Members:
    198.51.100.81 timeout 596479
    198.51.100.101 timeout 597278
    203.0.113.55 timeout 597454
    ```

## sipban_admin.bash

The script is a wrapper for common ipset commands. Use it with care: it does not check the whitelist.

```
# sipban_admin.bash
Usage: /usr/local/bin/sipban_admin.bash [options]
options:
    -c (create the sipban set)
    -f (delete all the members of the set)
    -k (destroy the sipban set)
    -i (show information about the set)

    -a [ip] or [ip/class] (add an IP address or class to the set)
    -d [ip] (delete an IP address from the set)
    -l {ip} (list the members, or test an IP address)

    -s (save the set to the dump file)
    -r (restore the set from the dump file)
    -u [file] (add the IP addresses listed in a file)
```

## Tests

`test/test.sh` runs sipban against a simulated AMI, with fake ipset and
iptables commands, and checks the results. It does not need Asterisk or root;
see [test/README.md](test/README.md).

## To-do

   - IPv6 support
   - ~~IP class blocking~~

## Author

   Fernando Romo (pop@cofradia.org)

   Fork changes: tacvbo (https://github.com/tacvbo/sipban)

## License

```
GNU GENERAL PUBLIC LICENSE Version 3
https://www.gnu.org/licenses/gpl-3.0.en.html
See LICENSE.txt
```

## Sponsor the original author

Fernando Romo accepts sponsorships at [github.com/sponsors/elpop](https://github.com/sponsors/elpop).
