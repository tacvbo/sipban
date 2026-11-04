# SIPban

## Description

Program to stop SIP scanning attacks using live monitoring of the Asterisk AMI security Events and use iptables and ipset to block remote ip address.

The program use AMI (Asterisk manager Interface, with the security profile, obtain events related to SIP authorization on PJSIP and SIP channels.

Tested with Asterisk version 16.3.0 - 22.1.0 (C) 1999 - 2024, Digium, Inc. and others.

## Fork changes (2026-11-04)

This fork (https://github.com/tacvbo/sipban) is focused on PJSIP and on
not blocking the own phones. Phones behind a NAT share the public ip, so
with the original rules one phone with a bad account blocked the whole
office, and the normal traffic (every REGISTER, INVITE or SUBSCRIBE is
challenged with a 401) reached the ChallengeSent flood counter.

* **Trusted ip's**: an ip with a registered PJSIP contact (asked with the AMI
  action *PJSIPShowContacts* every `trust->refresh` seconds) or with a
  *SuccessfulAuth* event in the last `trust->ttl` seconds is not blocked by
  InvalidAccountID, InvalidPassword, ChallengeResponseFailed, FailedACL or
  unanswered challenges. The failure is logged as `IGNORE` (once per hour).
  A brute force from a trusted ip is still blocked after
  `trust->max_failures` events in `trust->interval` seconds.
* **Unanswered challenges** replace the ChallengeSent counter: after a
  challenge, sipban waits `flood->grace` seconds the *SuccessfulAuth* of the
  same session. Phones answer, scanners don't. `flood->count` unanswered
  challenges in `flood->interval` seconds block the ip.
* **New events**: *ChallengeResponseFailed* (PJSIP reports a bad password
  with it, not with InvalidPassword) and *FailedACL*.
* The `BLOCK` log line includes the AccountID, useful to find a phone with a
  bad account.
* The white list accepts ip/class (`192.0.2.0/24`); ip's of the white list
  are removed from the set at startup and on `restore`.
* New console command `trusted`.

Requirements of the trust by contact:

* The AMI user needs `write = system` (the sample *manager.conf* already has
  it). If *PJSIPShowContacts* fails, sipban logs it once and uses only the
  *SuccessfulAuth* events.
* With phones behind NAT, the PJSIP endpoints need `rewrite_contact=yes`
  (FreePBX default), so the contact has the public ip of the phone.

Log examples:

```
[2026-11-04 17:13:52] CONTACTS => 3 ip's with registered PJSIP contacts
[2026-11-04 17:13:53] IGNORE => 203.0.113.10 (Invalid Account, AccountID 205) trusted ip
[2026-11-04 17:13:53] BLOCK => 198.51.100.20 (Invalid Account, AccountID admin)
[2026-11-04 17:13:53] TRUST => 198.51.100.30 (Successful Auth, AccountID 300)
[2026-11-04 17:13:54] BLOCK => 198.51.100.40 (No Auth Response, 5 unanswered challenges)
[2026-11-04 17:13:54] BLOCK => 203.0.113.11 (Challenge Response Failed, AccountID 102, 30 failures from trusted ip)
```

## Last Update (2024-12-02)

* SipBan use now IPSet ([ipset.netfilter.org](https://ipset.netfilter.org)) making the iptables check of attackers more faster, with less iptables rules changes.
* If you have version 7 or grather, the ipset "set" can handle the block timeout automatic. 
* I conserve the time keeping for support version older than 6. This will be depreciated in the next version.
* I only insert in the top of the iptables INPUT rules a single statement, in place of generate an adittional chain.
* Ipset can handle a complet ip/class ban. With **sipban_admin.bash** you can block entire ip/class.
* I keep the old version with his configuration file with the name "sipban_legacy.pl" and "sipban_legacy.conf"
* Is tested in Ubuntu 22.04, Debian 12 and Fedora 41. I don't have other Linux Distros to test, but if you have any comments about it, please let me know.
* As part of Sipban, i put a bash script called "sipban_admin.bash", is only a wrapper for common ipset commands for easy admin of the sipban ipset "set".
* The SystemD file wait for "netfilter-persistent.service" to start.
    
## Install
   
The service use iptables, you need the "**root**" user of your system

1. Download file
  
    ```
    git clone https://github.com/tacvbo/sipban.git
    ```  

2. Install dependecies:
         
    a) Ubuntu/Debian
         
    ```
    sudo apt-get install iptables ipset libproc-pid-file-perl libconfig-simple-perl libnet-whois-ip-perl libtime-hires-perl libtie-cache-perl
    ```
         
    b) Redhat/CentOS/Fedora
    
    ```     
    sudo dnf install iptables-nft ipset perl-Proc-PID-File perl-Config-Simple perl-Net-Whois-IP perl-Time-HiRes perl-Tie-Cache
    ```
         
3. Copy configuration files

    ```      
     cd sipban
     sudo cp sipban.pl /usr/local/bin/.
     sudo cp sipban_admin.bash /usr/local/bin/.
     sudo cp etc/sipban.conf /etc/.
     sudo cp etc/sipban.wl /etc/.
    ```
    
4. Edit and add **/etc/asterisk/manager.conf** acording our sample on **sipban/etc/asterisk/manager.conf**
         
    Use "**asterisk -rx'manager reload'**" after change the manager configuration file.
         
5. Install the launch scripts
      
    a) for init.d 
    
    ```     
    sudo cp etc/init.d/sipban /etc/init.d/.
    sudo chkconfig --level 345 sipban on
    sudo /etc/init.d/sipban start
    ```
                    
    b) for systemd
    
    ```     
    sudo cp etc/systemd/system/sipban.service /etc/systemd/system/.
    sudo systemctl enable sipban
    sudo service sipban start
    ```
    
## Configure

1. In the file **/etc/asterisk/manager.conf** we put this configuration:

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

2. The **/etc/sipban.conf** contains the parameters of the service:

    ```   
    # SipBan Configuration File
    
    # Parameters to connect to Asterisk AMI
    [ami]
    port = "5038"
    user = "sipban"
    pass = "getout"
    host = "127.0.0.1"
    ping = 60
    
    # Port to send commands
    [control]
    port = "4451"
    address = "127.0.0.1"
    
    #Iptables rules actions config
    [iptables]
    path       = "/sbin/"
    chain      = "sipban"
    # to block udp port 5060, you can block all but test
    # with caution to avoid lost total access to your system.
    #scope = "-p udp --dport 5060"
    scope      = ""
    #rule  = "REJECT --reject-with icmp-port-unreachable"
    rule       = "DROP"
    white_list = "/etc/sipban.wl"
    interface  = "eno1"
    
    [ipset]
    path     = "/sbin/"
    set_name = "sipban"
    dump     = "/etc/sipban.dump"
    # week
    timeout  = 604800
    # day
    #timeout  = 86400 
    
    [log]
    file = "/var/log/sipban.log"
    
    [flood]
    # Block an ip with "count" challenges (401/407) without answer in
    # "interval" seconds. Phones always answer the challenge with their
    # credentials, scanners like sipvicious don't.
    # A challenge is unanswered if no SuccessfulAuth comes in "grace" seconds.
    count=5
    interval=10
    grace=5

    [trust]
    # Trusted ip's (with a registered PJSIP contact or a recent successful
    # authentication) are not blocked by InvalidAccountID, InvalidPassword,
    # ChallengeResponseFailed, FailedACL or unanswered challenges, so a phone
    # with a bad account does not block the other phones behind the same NAT.
    # seconds an ip stays trusted after a successful authentication (0 = off)
    ttl=3600
    # seconds between PJSIPShowContacts requests (0 = off)
    refresh=60
    # a trusted ip is blocked anyway with "max_failures" in "interval" seconds
    max_failures=30
    interval=60
    ```
    
    The file is sefl explanatory. only take in count the "ipset->timeout" parameter are seconds (default 604800 = 1 week).
   
    The "iptables->rule" option is how iptables respond to the attack, you can choose "REJECT" or "DROP"

    The flood section will block an ip with a number (count) of challenges without answer in a period of (interval) seconds. In the default configuration 5 unanswered challenges in 10 seconds block the ip. The trust section is explained in "Fork changes". The sections and parameters added by the fork are optional, the defaults are the values of the sample.
   
3. The White List is on **/etc/sipban.wl**. This file contains the ip address you don't want to block (one ip or ip/class per line, v.g. 192.0.2.0/24). You can change the location modify the sipban configuration file.
   
4. The sipban.dump file is a temp one to save the ip's and ban timers in case of mantinance.
   
5. You can reach via Telnet with the port 4451 (you can change in the "control->port" pararmeter).
        
## Operation

1. The service are fully automatic, but you can control through the port 4451 (or another defined on **/etc/sipban.conf**) and using **sipban_admin.bash**, v.g.:
   
    ```   
    [root@pbx ~]# telnet localhost 4451
    Trying ::1...
    telnet: connect to address ::1: Connection refused
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
        
    Sipban
    use 'help' for more commands
    sipban>
     
    sipban>help
        
    Commands:
        
    block                => List blocked ip address
    block {ip address}   => block ip address
    unblock [ip address] => unblock ip address
    save                 => Dump the blocked IP's
    restore              => If exists a dump file restore the rules from it
    uptime               => show the program uptime
    whois                => show the WHOIS info of a given ip
    wl                   => show white list ip address
    trusted              => show trusted ip address (registered or authenticated)
    exit/quit            => exit console session
        
    sipban>
    ```
    
2. The log files reside on the file "**/var/log/sipban.log**"
   
    ```
    [root@pbx ~]# tail -f /var/log/sipban.log 
    [2024-12-02 10:40:25] SipBan Start
    [2024-12-02 10:40:25] WHITE LIST => 127.0.0.1
    [2024-12-02 10:40:25] WHITE LIST => 10.88.1.11
    [2024-12-02 10:40:25] WHITE LIST => 10.88.1.1
    [2024-12-02 10:40:25] WHITE LIST => 10.64.12.1
    [2024-12-02 10:40:25] WHITE LIST => 10.64.12.10
    [2024-12-02 10:40:25] IPSET => set sipban created
    [2024-12-02 10:40:25] CHAIN => sipban created
    [2024-12-02 10:40:31] BLOCK => 54.39.137.81 (Invalid Account)
    [2024-12-02 10:53:46] BLOCK => 87.98.251.101 (Invalid Account)
    [2024-12-02 10:56:42] BLOCK => 185.243.5.55 (Invalid Account)
    [2024-12-02 11:20:20] BLOCK => 206.168.34.198 (Invalid Account)
    [2024-12-02 12:25:48] BLOCK => 94.23.148.30 (Invalid Account)
    ...   
    ```

3. You can check the iptables rules with "**iptables -vnL INPUT 1**"
   
    ```
    [root@pbx ~]# # iptables -vnL INPUT 1 
     4212  253K DROP all -- eno1 * 0.0.0.0/0 0.0.0.0/0 match-set sipban src
    ```
    
4. You can list blocked ip's with "**sipban_admin.bash -l**"
   
    ```
    [root@pbx ~]# sipban_admin.bash -l

    Name: sipban
    Type: hash:ip
    Revision: 5
    Header: family inet hashsize 4096 maxelem 65536 timeout 604800 bucketsize 12 initval 0x285783a9
    Size in memory: 3536
    References: 1
    Number of entries: 6
    Members:
    23.95.39.90 timeout 596479
    94.23.145.155 timeout 596479
    84.32.32.134 timeout 596479
    154.212.141.253 timeout 596479
    209.141.54.234 timeout 596479
    172.168.40.246 timeout 596479
    ```
    
## sipban_admin.bash

The bash script is a wrapper of the common ipset commands. Use with caution, this don't take care of the "White List".

```
# sipban_admin.bash 
Usage: /usr/local/bin/sipban_admin.bash [options]
options:
    -c (create sipban set)
    -f (flush ipset members)
    -k (destroy sipban set)
    -i (info of sipban set)

    -a [ip] or [ip/class] (add ip or ip/class to sipban set)'
    -d [ip] (delete ip from sipban set)
    -l {ip} (list members or test a given ip)

    -s (save to sipban file)
    -r (restore from sipban file)
    -u [file] (upload from a given file)
```

## Docker

Our friend Federico Pereira (lord.basex@gmail.com), make the docker image of SipBan, the instructions are on the README.md on the docker directory.


## To-do

   - IPv6 support
   - ~~ip Class blocking~~

## Author

   Fernando Romo (pop@cofradia.org)

   Fork changes: tacvbo (https://github.com/tacvbo/sipban)

## License
     
```
GNU GENERAL PUBLIC LICENSE Version 3
https://www.gnu.org/licenses/gpl-3.0.en.html
See LICENSE.txt
```

## Sponsor the project

Please [sponsor this project](https://github.com/sponsors/elpop), to pay my high debt on credit cards :)
