#!/usr/bin/perl
#======================================================================#
# Program => sipban.pl (Perl 5)                          version 1.1.0 #
#======================================================================#
# Author => Fernando "El Pop" Romo                  (pop@cofradia.org) #
# Creation date => 07/jun/2019                                         #
# Modified => 04/nov/2026 by tacvbo (https://github.com/tacvbo/sipban) #
#             trusted IPs (PJSIP contacts and successful               #
#             authentication), new PJSIP events and detection of       #
#             unanswered challenges.                                   #
#----------------------------------------------------------------------#
# Info => Connects to the Asterisk Manager Interface (AMI), reads the  #
#         security events and blocks the IP addresses of SIP attackers #
#         with ipset and iptables.                                     #
#----------------------------------------------------------------------#
#        This code is released under the GPL 3.0 License.              #
#                                                                      #
#                  (c) 2019-2024 - Fernando Romo                       #
#                                                                      #
# This program is free software: you can redistribute it and/or modify #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 3 of the License, or    #
# (at your option) any later version.                                  #
#                                                                      #
# This program is distributed in the hope that it will be useful, but  #
# WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    #
# General Public License for more details.                             #
#                                                                      #
# You should have received a copy of the GNU General Public License    #
# along with this program. If not, see <https://www.gnu.org/licenses/> #
#======================================================================#
use strict;
use POSIX;
use IO::Socket;
use IO::Select;
use Socket;
use Fcntl;
use Net::Whois::IP qw(whoisip_query);
use Tie::RefHash;
use Time::HiRes qw(usleep);
use Proc::PID::File;
use File::Basename;
use Config::Simple;
use Tie::Cache;

my %cache = ();
tie %cache, 'Tie::Cache', 1000, { Debug => 0 };

if (defined($ARGV[0])) {
    if ($ARGV[0] eq "-d") {
        defined(my $pid = fork) or die "Can't fork: $!";
        exit if $pid;
        setsid or die "Can't start a new session: $!";
    }
}

# Only one instance can run (PID file in /tmp)
die "Already running" if Proc::PID::File->running( dir=>"/tmp/", name => basename("$0",".pl") );

my %Config;
Config::Simple->import_from('/etc/sipban.conf', \%Config) or die Config::Simple->error();

# Defaults for the parameters added in version 1.1.0, so older configuration
# files keep working
$Config{'flood.count'}        = 5    unless (defined($Config{'flood.count'}));
$Config{'flood.interval'}     = 60   unless (defined($Config{'flood.interval'}));
$Config{'flood.grace'}        = 5    unless (defined($Config{'flood.grace'}));
$Config{'trust.ttl'}          = 3600 unless (defined($Config{'trust.ttl'}));
$Config{'trust.refresh'}      = 60   unless (defined($Config{'trust.refresh'}));
$Config{'trust.max_failures'} = 30   unless (defined($Config{'trust.max_failures'}));
$Config{'trust.interval'}     = 60   unless (defined($Config{'trust.interval'}));

#--------------------#
# Global state       #
#--------------------#

# Timers
my $Start_Time = time();
my $Ping_Time  = $Start_Time + $Config{'ami.ping'};
# 9999-12-31 23:59:59 UTC, used when no block is waiting to expire
my $max_epoch = 253402300799;
my $min_epoch = $max_epoch;

# Sockets
my $asterisk_handler;
my $asterisk_select;
my $asterisk_client;

# Stop cleanly (see Terminate) on INT, TERM and HUP
$SIG{PIPE} = 'IGNORE';
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = 'Terminate';

my $ipt = "$Config{'iptables.path'}" . 'iptables'; # iptables command
my $ips = "$Config{'ipset.path'}" . 'ipset';       # ipset command

# INPUT rule that applies the set: -i eno1 -m set --match-set sipban src -j DROP
my $ipt_rule = "-i $Config{'iptables.interface'} -m set --match-set $Config{'ipset.set_name'} src -j $Config{'iptables.rule'}";

# Control console: listening socket for the telnet clients
my $server = IO::Socket::INET->new(LocalPort => "$Config{'control.port'}",
                             LocalAddr => "$Config{'control.address'}",
                             Listen    => 10,
                             ReuseAddr => 1,
                             Blocking  => 0,
) or die "Can't create the control socket: $@\n";

$server->blocking(0);

my $select = IO::Select->new($server);

# Input and output buffers of each socket
my %in_buffer     = ();
my %out_buffer    = ();

my %sessions     = ();
my %ban_ip       = ();
my %white_list   = ();
my %partial_in   = ();   # incomplete line of each socket, completed by the next read

# Trusted IPs are not blocked by the security events (see Security_Failure)
my %registered_ip = ();  # IPs with a registered PJSIP contact
my %contacts_next = ();  # contact list being received (PJSIPShowContacts)
my %trusted_ip    = ();  # ip => epoch until it is trusted (SuccessfulAuth)
my %pending_auth  = ();  # "ip|session" => [ip, epoch] of each challenge waiting for an answer
my %log_once      = ();  # key => epoch when that log line was last written
my $contacts_supported = 1;
my $Contacts_Time      = 0;
my $Housekeeping_Time  = $Start_Time + 60;

# Services whose security events are processed
my %Services = map { $_ => 1 } qw(PJSIP SIP IAX IAX2 AMI);

tie %in_buffer, 'Tie::RefHash';
my $event_str = "";

# AMI connection: while the flag is 1, the main loop tries to connect
my $manager_connect_time = 0;
my $manager_connect_flag = 1;

# Help
my $HELP = "\nCommands:\n\n";
$HELP .= "block                => list the blocked IP addresses\n";
$HELP .= "block {ip address}   => block an IP address\n";
$HELP .= "unblock {ip address} => unblock an IP address\n";
$HELP .= "save                 => save the blocked IP addresses to the dump file\n";
$HELP .= "restore              => restore the blocked IP addresses from the dump file\n";
$HELP .= "uptime               => show how long sipban has been running\n";
$HELP .= "whois {ip address}   => show the WHOIS information of an IP address\n";
$HELP .= "wl                   => show the whitelist\n";
$HELP .= "trusted              => show the trusted IP addresses (registered or authenticated)\n";
$HELP .= "exit/quit            => close the console session\n";

my $LICENSE  = "SIPban  Copyright (C) 2019-2024 Fernando 'El Pop' Romo\n\n";
$LICENSE .= "This program comes with ABSOLUTELY NO WARRANTY;\n";
$LICENSE .= "for details https://www.gnu.org/licenses/gpl-3.0.en.html\n";
$LICENSE .= "This is free software, and you are welcome to redistribute\n";
$LICENSE .= "it under certain conditions.";

# An IPv4 address with an optional class (CIDR prefix), e.g. 192.0.2.0/24
my $IPv4 ='^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]' .
           '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]' .
           '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]' .
           '(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))' .
           '(\/(3[0-2]|[1-2][0-9]|[0-9]))?$';

# Log file
open(LOG, ">> $Config{'log.file'}") or die;
LOG->autoflush(1);

print LOG Time_Stamp() . " SipBan Start\n";

#-----------------#
# Ipset functions #
#-----------------#

sub Ipset_Exists_Set {
    # /usr/sbin/ipset list -t sipban
    my ($ok, $output) = Run_Command("$ips list -t $Config{'ipset.set_name'} 2>&1");
    return ($ok && $output =~ /Name\:\s$Config{'ipset.set_name'}/) ? 1 : 0;
}

sub Ipset_Create_Set {
    # /usr/sbin/ipset create sipban hash:net hashsize 4096 timeout 604800
    my ($ok, $output) = Run_Command("$ips create $Config{'ipset.set_name'} hash:net hashsize 4096 timeout $Config{'ipset.timeout'} 2>&1");
    Fatal("ipset could not create the set $Config{'ipset.set_name'}: $output") unless ($ok);
    print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} created\n";
}

sub Ipset_Destroy_Set {
    # /usr/sbin/ipset destroy sipban
    my ($ok, $output) = Run_Command("$ips destroy $Config{'ipset.set_name'} 2>&1");
    if ($ok) {
        print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} destroyed\n";
    }
    else {
        print LOG Time_Stamp() . " ERROR => ipset could not destroy the set $Config{'ipset.set_name'}: $output\n";
    }
}

sub Ipset_Save {
    # /usr/sbin/ipset save sipban > /etc/sipban.dump
    # It writes a temporary file first: if ipset fails, the previous dump
    # file is kept instead of being left empty.
    my $temporary = "$Config{'ipset.dump'}.tmp";
    my ($ok, $output) = Run_Command("$ips save $Config{'ipset.set_name'} 2>&1 > $temporary");
    if ($ok && rename($temporary, $Config{'ipset.dump'})) {
        print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} saved\n";
    }
    else {
        unlink($temporary);
        print LOG Time_Stamp() . " ERROR => ipset could not save the set $Config{'ipset.set_name'}, $Config{'ipset.dump'} is unchanged: $output\n";
    }
}

sub Ipset_Restore_Set {
    if (-e $Config{'ipset.dump'}) {
        # /usr/sbin/ipset restore -! < /etc/sipban.dump
        my ($ok, $output) = Run_Command("$ips restore -! < $Config{'ipset.dump'} 2>&1");
        if ($ok) {
            print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} restored\n";
        }
        else {
            print LOG Time_Stamp() . " ERROR => ipset could not restore $Config{'ipset.dump'}: $output\n";
        }
    }
}

# Returns 1 if the address was added to the set
sub Ipset_Block {
    my ($ip, $msg) = @_;
    # /usr/sbin/ipset add sipban 192.0.2.10 -exist
    my ($ok, $output) = Run_Command("$ips add $Config{'ipset.set_name'} $ip -exist 2>&1");
    unless ($ok) {
        print LOG Time_Stamp() . " ERROR => ipset could not block $ip ($msg): $output\n";
        return 0;
    }
    if ($min_epoch > $ban_ip{$ip}) {
        $min_epoch = $ban_ip{$ip};
    }
    print LOG Time_Stamp() . " BLOCK => $ip ($msg)\n";
    return 1;
}

sub Ipset_Unblock {
    my ($ip, $msg) = @_;
    # /usr/sbin/ipset -q del sipban 192.0.2.10
    my $rv = qx($ips -q del $Config{'ipset.set_name'} $ip);
    print LOG Time_Stamp() . " UNBLOCK => $ip ($msg)\n";
}

# Block an IP address or class, unless it is already blocked or whitelisted
sub Ban_IP {
    my ($ip, $msg) = @_;
    return 0 unless ($ip =~ /$IPv4/);
    return 0 if (exists($ban_ip{$ip}) || In_White_List($ip));
    $ban_ip{$ip} = time() + $Config{'ipset.timeout'};
    unless (Ipset_Block($ip, $msg)) {
        # not blocked: the next event tries again
        delete $ban_ip{$ip};
        return 0;
    }
    return 1;
}

# Whitelisted addresses take precedence over earlier blocks (from the dump
# file, or from a set that was still loaded)
sub Ipset_Purge_White_List {
    foreach my $ip (sort keys %ban_ip) {
        if (In_White_List($ip)) {
            Ipset_Unblock($ip, 'White List');
            delete $ban_ip{$ip};
        }
    }
}

# Rebuild %ban_ip from the members of the set and their remaining time
sub Ipset_Load_Ban_IP {
    %ban_ip = ();
    # /usr/sbin/ipset list sipban (one "<ip> timeout <seconds>" line per member)
    my @rv = qx($ips list $Config{'ipset.set_name'});
    my $now = time();
    foreach my $line (@rv) {
        chomp($line);
        my ($ip, $timeout) = $line =~ /^(.*)\stimeout\s(.*)/;
        if ($ip =~ /$IPv4/) {
            $ban_ip{$ip} = $now + $timeout;
            if ($min_epoch > $ban_ip{$ip}) {
                $min_epoch = $ban_ip{$ip};
            }
        }
    }
}

# The set removes the expired members by itself; this keeps %ban_ip in sync
# and finds the next expiration
sub Ipset_Prune_Block {
    my $time = shift;
    foreach my $ip (sort keys %ban_ip) {
        if ($time >= $ban_ip{$ip}) {
            Ipset_Unblock($ip, 'Timeout Unblock');
            delete $ban_ip{$ip};
        }
        else {
            if ($ban_ip{$ip} < $min_epoch) {
                $min_epoch = $ban_ip{$ip};
            }
        }
    }
    my $hash_size = keys %ban_ip;
    if ($hash_size <= 0) {
        $min_epoch = $max_epoch;
    }
}

#--------------------#
# Iptables functions #
#--------------------#

sub Iptables_Create_Rule {
    # /sbin/iptables -t filter -I INPUT -i eno1 -m set --match-set sipban src -j DROP
    my ($ok, $output) = Run_Command("$ipt -t filter -I INPUT $ipt_rule 2>&1");
    Fatal("iptables could not insert the INPUT rule: $output") unless ($ok);
    print LOG Time_Stamp() . " IPTABLES => INPUT rule for set $Config{'ipset.set_name'} created\n";
}

# Delete every copy of the INPUT rule and return how many there were. An
# unclean stop leaves the rule in place, and the set cannot be destroyed while
# a rule still uses it. "iptables -D" fails when no copy is left.
sub Iptables_Erase_Rule {
    # /sbin/iptables -t filter -D INPUT -i eno1 -m set --match-set sipban src -j DROP
    my $copies = 0;
    while ($copies < 100) {
        my ($ok) = Run_Command("$ipt -t filter -D INPUT $ipt_rule 2>&1");
        last unless ($ok);
        $copies++;
    }
    return $copies;
}

#--------------------#
# Asterisk functions #
#--------------------#

# Returns the new value of $manager_connect_flag: 0 connected, 1 failed
sub Connect_To_Asterisk {
    my $host = shift;
    $asterisk_handler = new IO::Socket::INET->new( PeerAddr  => "$host",
                                                   PeerPort  => $Config{'ami.port'},
                                                   Proto     => "tcp",
                                                   ReuseAddr => 1,
                                                   Blocking  => 0,
                                                   Type      => SOCK_STREAM );
    if ($asterisk_handler) {
        $asterisk_handler->autoflush(1);
        $select->add($asterisk_handler);
        return 0;
    }
    else {
    	return 1;
    }
}

# Queue an AMI action; the main loop sends it when the socket is writable.
# Nothing is queued while disconnected.
sub Send_To_Asterisk {
    my $command_ref = shift;
    if ($$command_ref ne '' && $manager_connect_flag == 0) {
        $out_buffer{$asterisk_handler} .= $$command_ref;
    }
}

# "Events: on" receives every event allowed by the read permission of the AMI
# user (read = security in the sample manager.conf)
sub Manager_Login {
    my $command  = "Action: login\r\n";
    $command .= "Username: $Config{'ami.user'}\r\n";
    $command .= "Secret: $Config{'ami.pass'}\r\n";
    $command .= "Events: on\r\n\r\n";
    Send_To_Asterisk(\$command);
}

# Asterisk answers with one ContactList event per contact and a final
# ContactListComplete event (see %AMI_Handler)
sub Request_Contacts {
    %contacts_next = ();
    Send_To_Asterisk(\"Action: PJSIPShowContacts\r\nActionID: sipban-contacts\r\n\r\n");
}

#-----------------#
# Trust functions #
#-----------------#

# An IP is trusted if it has a registered PJSIP contact or a recent successful
# authentication. Phones behind the same NAT share the IP, so one phone with a
# wrong account or password must not block the others.
sub Is_Trusted {
    my $ip = shift;
    return 1 if (exists($registered_ip{$ip}));
    return 1 if (exists($trusted_ip{$ip}) && $trusted_ip{$ip} > time());
    return 0;
}

# Common fields of the security events
sub Parse_Security_Event {
    my $packet_content_ref = shift;
    my ($service)    = $$packet_content_ref =~ /\nService\:\s(.*?)\n/i;
    my ($account_id) = $$packet_content_ref =~ /\nAccountID\:\s(.*?)\n/i;
    my ($session_id) = $$packet_content_ref =~ /\nSessionID\:\s(.*?)\n/i;
    my ($remote_ip)  = $$packet_content_ref =~ /\nRemoteAddress\:\sIPV4\/[^\/]*\/([^\/]*)\//i;
    # AccountID comes from the SIP request, so the sender controls it: it is
    # only logged, with a length limit and without non-printable characters
    $account_id = substr($account_id, 0, 64);
    $account_id =~ s/[^[:print:]]/?/g;
    return ($service, $account_id, $session_id, $remote_ip);
}

#---------------------------------------------------------------------#
# InvalidAccountID, InvalidPassword, ChallengeResponseFailed and      #
# FailedACL block the remote IP unless it is trusted. A trusted IP is #
# only blocked after "trust.max_failures" failures within             #
# "trust.interval" seconds: a phone with a wrong account retries      #
# slowly, a brute force attack does not.                              #
#---------------------------------------------------------------------#
sub Security_Failure {
    my ($packet_content_ref, $reason) = @_;
    my ($service, $account_id, $session_id, $remote_ip) = Parse_Security_Event($packet_content_ref);
    return unless (exists($Services{$service}) && $remote_ip =~ /$IPv4/);
    delete $pending_auth{"$remote_ip|$session_id"};
    my $msg = "$reason, AccountID $account_id";
    if (Is_Trusted($remote_ip)) {
        my $count = Count_Event("failure $remote_ip", $Config{'trust.interval'});
        if ($count >= $Config{'trust.max_failures'}) {
            Ban_IP($remote_ip, "$msg, $count failures from a trusted IP");
        }
        else {
            Log_Once("$remote_ip $msg", "IGNORE => $remote_ip ($msg) trusted IP");
        }
        return;
    }
    Ban_IP($remote_ip, $msg);
}

#---------------------------------------------------------------------#
# A challenge (401/407) is unanswered if no SuccessfulAuth of the     #
# same session arrives within "flood.grace" seconds. Phones answer    #
# their challenges and scanners usually do not, so an IP is blocked   #
# after "flood.count" unanswered challenges within "flood.interval"   #
# seconds.                                                            #
#---------------------------------------------------------------------#
sub Check_Pending_Auth {
    my $now = shift;
    foreach my $key (keys %pending_auth) {
        my ($ip, $challenge_time) = @{$pending_auth{$key}};
        next if (($now - $challenge_time) < $Config{'flood.grace'});
        delete $pending_auth{$key};
        next if (Is_Trusted($ip));
        my $count = Count_Event("noauth $ip", $Config{'flood.interval'});
        if ($count >= $Config{'flood.count'}) {
            Ban_IP($ip, "No Auth Response, $count unanswered challenges");
        }
    }
}

# Forget the expired trusted IPs and the old Log_Once() keys
sub Housekeeping {
    my $now = shift;
    foreach my $ip (keys %trusted_ip) {
        delete $trusted_ip{$ip} if ($trusted_ip{$ip} <= $now);
    }
    foreach my $key (keys %log_once) {
        delete $log_once{$key} if (($now - $log_once{$key}) >= 3600);
    }
}

#-------------------#
# Utility functions #
#-------------------#

sub Trim {
    my @out = @_;

    for (@out) {
         s/^\s+//g;
         s/\s+$//g;
    }
    return wantarray ? @out : $out[0];
}

# Extract an IP address or class from a text; returns it and whether it is valid
sub Get_IP {
    my $address = shift;
    $address = Trim($address);
    my ($ip)  = $address =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
    my ($net) = $address =~ /\/(\d{1,2})/;
    if ($net ne ''){
        $ip .= "\/$net"
    };
    my $status = 0;
    if ($ip =~ /$IPv4/) {
        $status =1;
    }
    return $ip, $status;
}

sub IP_To_Int {
    my @octet = split(/\./, shift);
    return ($octet[0] << 24) + ($octet[1] << 16) + ($octet[2] << 8) + $octet[3];
}

# True if two IP addresses or classes share at least one address
sub CIDR_Overlap {
    my ($first, $second) = @_;
    my ($first_ip, $first_net)   = split(/\//, $first);
    my ($second_ip, $second_net) = split(/\//, $second);
    $first_net  = 32 unless (defined($first_net));
    $second_net = 32 unless (defined($second_net));
    my $net  = ($first_net < $second_net) ? $first_net : $second_net;
    my $mask = ($net == 0) ? 0 : (0xFFFFFFFF << (32 - $net)) & 0xFFFFFFFF;
    return ((IP_To_Int($first_ip) & $mask) == (IP_To_Int($second_ip) & $mask));
}

# True if the address overlaps any whitelist entry
sub In_White_List {
    my $ip = shift;
    foreach my $address (keys %white_list) {
        return 1 if (CIDR_Overlap($ip, $address));
    }
    return 0;
}

sub Time_Stamp {
    my $time = shift;
    $time = time() unless($time);
    my ($sec, $min, $hour, $day,$month,$year) = (localtime( $time ))[0,1,2,3,4,5];
    $year = $year + 1900;
    $month++;
    return sprintf("\[%04d-%02d-%02d %02d:%02d:%02d\]",$year,$month,$day,$hour,$min,$sec);
}

sub Convert_To_Time {
    my $time = shift;
    my $days = int($time / 86400);
    my $aux = $time % 86400;
    my $hours = int($aux / 3600);
       $aux = $aux % 3600;
    my $minutes = int($aux / 60);
    my $seconds = $time % 60;
    my $result = "";
    if ($days == 1) {
        $result = "$days day ";
    }
    elsif ($days > 1) {
        $result = "$days days ";
    }
    $result .= sprintf("%02d\:%02d\:%02d",$hours,$minutes,$seconds);
    return $result;
}

# Count the events of a key in a fixed window of $interval seconds that starts
# with the first event. The counters are kept in %cache (at most 1000 keys).
sub Count_Event {
    my ($key, $interval) = @_;
    my $now = time();
    my $entry = $cache{$key};
    if ($entry && ($now - $entry->[1]) <= $interval) {
        $cache{$key} = [ $entry->[0] + 1, $entry->[1] ];
        return $entry->[0] + 1;
    }
    $cache{$key} = [ 1, $now ];
    return 1;
}

# Run a shell command; returns whether it succeeded and its output. The
# caller adds "2>&1" to capture the error messages.
sub Run_Command {
    my $command = shift;
    my $output = qx($command);
    chomp($output);
    return ($? == 0, $output);
}

# Log the reason and stop: without the set and the INPUT rule, nothing would
# be blocked
sub Fatal {
    my $msg = shift;
    print LOG Time_Stamp() . " ERROR => $msg\n";
    die "sipban: $msg\n";
}

# Write a log line at most once per hour for the same key
sub Log_Once {
    my ($key, $line) = @_;
    my $now = time();
    return if (exists($log_once{$key}) && ($now - $log_once{$key}) < 3600);
    $log_once{$key} = $now;
    print LOG Time_Stamp() . " $line\n";
}

sub Terminate {
    Iptables_Erase_Rule();
    print LOG Time_Stamp() . " IPTABLES => INPUT rule for set $Config{'ipset.set_name'} erased\n";
    Ipset_Save();
    Ipset_Destroy_Set();

    my $client;
    # Close the console sessions
    foreach $client (keys %sessions) {
        $select->remove($client);
        close($client);
    }
    close($server);                   # close the control socket
    close($asterisk_handler);         # close the AMI connection
    print LOG Time_Stamp() . " SipBan Stop\n";
    close(LOG);
    exit(0);                          # Exit without error
}

#----------------------------------------------------------------------------------------------
# Console commands: %Client_Handler maps each command to the code that runs it.
#----------------------------------------------------------------------------------------------
my %Client_Handler = (
    "block" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip, $valid) = Get_IP($control->[1]);
            if ($valid) {
                if (exists($ban_ip{$ip})) {
                    $out_buffer{$client} .= "$ip is already blocked\n";
                }
                elsif (In_White_List($ip)) {
                    $out_buffer{$client} .= "$ip is whitelisted\n";
                }
                elsif (Ban_IP($ip, 'Manual block')) {
                    $out_buffer{$client} .= "$ip blocked\n";
                }
                else {
                    $out_buffer{$client} .= "$ip could not be blocked (see the log)\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip is not a valid IP address\n";
            }
        }
        else {
            foreach my $ip (sort { $ban_ip{$a} <=> $ban_ip{$b} } keys %ban_ip) {
                $out_buffer{$client} .= Time_Stamp($ban_ip{$ip}) . " $ip\n";
            }
        }
    },
    "unblock" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip, $valid) = Get_IP($control->[1]);
            if ($valid) {
                if (exists($ban_ip{$ip})) {
                    Ipset_Unblock($ip, 'Manual Unblock');
                    delete $ban_ip{$ip};
                    my $hash_size = keys %ban_ip;
                    if ($hash_size <= 0) {
                        $min_epoch = $max_epoch;
                    }
                    $out_buffer{$client} .= "$ip unblocked\n";
                }
                else {
                    $out_buffer{$client} .= "$ip is not blocked\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip is not a valid IP address\n";
            }
        }
        else {
            $out_buffer{$client} .= "Missing IP address\n";
        }
    },
    "save" => sub {
        my $client = shift;
        Ipset_Save();
        $out_buffer{$client} .= "ipset $Config{'ipset.set_name'} saved\n";
    },
    "restore" => sub {
        my $client = shift;
        Ipset_Restore_Set($client);
        Ipset_Load_Ban_IP();
        Ipset_Purge_White_List();
        $out_buffer{$client} .= "ipset $Config{'ipset.set_name'} restored\n";
    },
    "help" => sub {
        my $client = shift;
        $out_buffer{$client} .= $HELP;
    },
    "uptime" => sub {
        my $client = shift;
        $out_buffer{$client} .= 'Uptime ' . Convert_To_Time(time() - $Start_Time). "\n";
    },
    "whois" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip, $valid) = Get_IP($control->[1]);
            if ($valid) {
                $out_buffer{$client} .= "WHOIS information: $ip\n\n";
                my $response = ();
                my $status = eval { $response = whoisip_query($ip) } ;
                if ($response) {
                    foreach my $resp(sort keys(%{$response}) ) {
                        $out_buffer{$client} .= "$resp $response->{$resp} \n";
                    }
                }
                else {
                    $out_buffer{$client} .=  "No response from the WHOIS servers\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip is not a valid IP address\n";
            }
        }
        else {
            $out_buffer{$client} .= "Missing IP address\n";
        }
    },
    "wl" => sub {
        my $client = shift;
        $out_buffer{$client} .= '';
        foreach my $ip (sort keys %white_list) {
            $out_buffer{$client} .= "$ip\n";
        }
    },
    "trusted" => sub {
        my $client = shift;
        my $now = time();
        $out_buffer{$client} .= '';
        foreach my $ip (sort keys %registered_ip) {
            $out_buffer{$client} .= "$ip (registered contact)\n";
        }
        foreach my $ip (sort { $trusted_ip{$a} <=> $trusted_ip{$b} } keys %trusted_ip) {
            next if ($trusted_ip{$ip} <= $now);
            $out_buffer{$client} .= Time_Stamp($trusted_ip{$ip}) . " $ip (successful authentication)\n";
        }
    },
    "quit" => sub {
        my $client = shift;
        delete $in_buffer{$client};
        delete $out_buffer{$client};
        delete $partial_in{$client};
        delete $sessions{$client};
        $select->remove($client);
        close($client);
    },
);
#----------------------------------------------------------------
# "exit" is an alias of "quit". It is added after the declaration
# because a "my" variable is not visible inside its own
# initialization, so the code there cannot use %Client_Handler.
#----------------------------------------------------------------
$Client_Handler{exit} = (sub {
    my $client = shift;
    $Client_Handler{quit}->($client);
});

#--------------------------------------------------------------------------------------
# AMI packets: %AMI_Handler maps the packet type (Event, Response) and its name to the
# code that processes it.
#--------------------------------------------------------------------------------------
my %AMI_Handler = (
    "Event" => {
        #-----------------------------
        # Event: InvalidAccountID
        # Privilege: security,all
        # EventTV: 2019-06-07T21:25:59.559+0000
        # Severity: Error
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: 55001
        # SessionID: 99260YTExOWI2Y2NjZTVhODQ4NTVmMmZjMDc1MWUwMzY3MTM
        # LocalAddress: IPV4/UDP/10.211.55.8/5060
        # RemoteAddress: IPV4/UDP/10.211.55.2/59977
        #-----------------------------
        "InvalidAccountID" => sub {
            Security_Failure(shift, 'Invalid Account');
        },
        #-----------------------------
        # Event: InvalidPassword
        # Privilege: security,all
        # EventTV: 2019-06-07T21:17:59.819+0000
        # Severity: Error
        # Service: SIP
        # EventVersion: 2
        # AccountID: 5500
        # SessionID: 0x7f8db400d860
        # LocalAddress: IPV4/UDP/10.211.55.8/5060
        # RemoteAddress: IPV4/UDP/10.211.55.2/52551
        # Challenge: 79cca43d
        # ReceivedChallenge: 79cca43d
        # ReceivedHash: 91801011d87fe17fca4aca4893f9920d
        #-----------------------------
        "InvalidPassword" => sub {
            Security_Failure(shift, 'Invalid Password');
        },
        #-----------------------------
        # PJSIP reports a wrong password with this event; it never sends InvalidPassword
        #
        # Event: ChallengeResponseFailed
        # Privilege: security,all
        # Severity: Error
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: 101
        # SessionID: 9f3c2e1a5b7d4c6e8a0b@192.168.1.50
        # LocalAddress: IPV4/UDP/203.0.113.1/5060
        # RemoteAddress: IPV4/UDP/198.51.100.7/5060
        # Challenge: 1782379082/60573f75eacde01c393d1172933792fb
        # Response: 6d6f486145c747e30a74b20bd70abd2b
        # ExpectedResponse:
        #-----------------------------
        "ChallengeResponseFailed" => sub {
            Security_Failure(shift, 'Challenge Response Failed');
        },
        #-----------------------------
        # Event: FailedACL
        # Privilege: security,all
        # Severity: Error
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: anonymous
        # SessionID: 1969512380@127.0.1.1
        # LocalAddress: IPV4/UDP/203.0.113.1/5060
        # RemoteAddress: IPV4/UDP/198.51.100.7/45682
        # ACLName: registrar_attempt_without_configured_aors
        #-----------------------------
        "FailedACL" => sub {
            Security_Failure(shift, 'Failed ACL');
        },
        #-----------------------------
        # Event: ChallengeSent
        # Privilege: security,all
        # EventTV: 2022-01-27T18:47:34.606-0300
        # Severity: Informational
        # Service: SIP
        # EventVersion: 1
        # AccountID: sip:127.0.0.1:9
        # SessionID: 0x7fe8480d4100
        # LocalAddress: IPV4/UDP/149.28.237.109/5060
        # RemoteAddress: IPV4/UDP/127.0.0.1/9
        # Challenge: 43ccaa48
        #-----------------------------
        "ChallengeSent" => sub {
            my ($service, $account_id, $session_id, $remote_ip) = Parse_Security_Event(shift);
            return unless (exists($Services{$service}) && $remote_ip =~ /$IPv4/);
            return if (Is_Trusted($remote_ip) || exists($ban_ip{$remote_ip}));
            # wait for the SuccessfulAuth of the same session (see Check_Pending_Auth)
            my $key = "$remote_ip|$session_id";
            $pending_auth{$key} = [ $remote_ip, time() ] unless (exists($pending_auth{$key}));
        },
        #-----------------------------
        # Event: SuccessfulAuth
        # Privilege: security,all
        # Severity: Informational
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: 101
        # SessionID: 0_122972204@192.168.1.50
        # LocalAddress: IPV4/UDP/203.0.113.1/5060
        # RemoteAddress: IPV4/UDP/198.51.100.7/5060
        # UsingPassword: 1
        #-----------------------------
        "SuccessfulAuth" => sub {
            my $packet_content_ref = shift;
            my ($service, $account_id, $session_id, $remote_ip) = Parse_Security_Event($packet_content_ref);
            my ($using_password) = $$packet_content_ref =~ /\nUsingPassword\:\s(.*?)\n/i;
            return unless (exists($Services{$service}) && $remote_ip =~ /$IPv4/);
            delete $pending_auth{"$remote_ip|$session_id"};
            return unless ($using_password eq '1' && $Config{'trust.ttl'} > 0);
            unless (Is_Trusted($remote_ip)) {
                print LOG Time_Stamp() . " TRUST => $remote_ip (Successful Auth, AccountID $account_id)\n";
            }
            $trusted_ip{$remote_ip} = time() + $Config{'trust.ttl'};
        },
        #-----------------------------
        # Response to PJSIPShowContacts, one event per contact
        #
        # Event: ContactList
        # ActionID: sipban-contacts
        # ObjectType: contact
        # ObjectName: 101;@a1b2c3d4e5f60718293a4b5c6d7e8f90
        # ViaAddr: 192.168.1.50
        # Uri: sip:101@198.51.100.7:5060;ob
        # Endpoint: 101
        # Status: Reachable
        #-----------------------------
        "ContactList" => sub {
            my $packet_content_ref = shift;
            my ($uri) = $$packet_content_ref =~ /\nUri\:\s(.*?)\n/i;
            my ($via) = $$packet_content_ref =~ /\nViaAddr\:\s(.*?)\n/i;
            # Behind NAT, the URI has the public IP of the phone only if the
            # endpoint has rewrite_contact=yes. ViaAddr is the sent-by address
            # of the Via header that the phone added to its REGISTER.
            my ($host) = $uri =~ /^sips?\:(?:[^\@]*\@)?([^\:\;\>]+)/i;
            foreach my $ip ($host, $via) {
                $contacts_next{$ip} = 1 if (defined($ip) && $ip =~ /$IPv4/);
            }
        },
        # End of the list: it replaces the previous one
        "ContactListComplete" => sub {
            my $before = keys %registered_ip;
            %registered_ip = %contacts_next;
            %contacts_next = ();
            my $after = keys %registered_ip;
            if ($before != $after) {
                print LOG Time_Stamp() . " CONTACTS => $after IPs with registered PJSIP contacts\n";
            }
        },
    }, # Event
    "Response" => {
        "Success" => sub {
            my $packet_content_ref = shift;
            if ($$packet_content_ref =~ /Ping\:\sPong/) {
               # print LOG Time_Stamp() . " Pong\n";
            }

        },
        "Error" => sub {
            my $packet_content_ref = shift;
            my ($action_id) = $$packet_content_ref =~ /\nActionID\:\s(.*?)\n/i;
            my ($message)   = $$packet_content_ref =~ /\nMessage\:\s(.*?)\n/i;
            if ($action_id eq 'sipban-contacts') {
                if ($message =~ /No Contacts found/i) {
                    %registered_ip = ();
                    %contacts_next = ();
                }
                else {
                    # e.g. the AMI user lacks the "system" write permission
                    $contacts_supported = 0;
                    print LOG Time_Stamp() . " CONTACTS => PJSIPShowContacts failed ($message); only SuccessfulAuth events will trust IPs\n";
                }
            }
            else {
                Log_Once("AMI $message", "AMI => Error ($message)");
            }
        },
    } # Response
);

#---------------------------------------------------------#
#  Function: Handle_Clients([Client TCP handler])         #
#---------------------------------------------------------#
# Objective: Run the console commands received from a     #
#            client                                       #
#   Params: [client TCP handler]                          #
#    Usage:                                               #
#          Handle_Clients($client);                       #
#---------------------------------------------------------#
sub Handle_Clients {
    # the commands are in $in_buffer{$client}, the answers go to
    # $out_buffer{$client}
    my $client = shift;
    my $request;

    foreach $request (@{$in_buffer{$client}}) {
       $request =~ s/\r|\n//g;
       if ($request) {
           my @control = split (/\s+/, Trim($request));
           if (exists($Client_Handler{$control[0]})) {
               $Client_Handler{$control[0]}->($client,\@control);
           }
           else {
               $out_buffer{$client} .= "Invalid command";
           }
       }
       if ($out_buffer{$client}) {
            $out_buffer{$client} .= "\nsipban>";
       } else {
            $out_buffer{$client} = 'sipban>';
       }
    }
    delete $in_buffer{$client};
}

#---------------------------------------------------------#
#  Function: Handle_AMI([Asterisk TCP handler])           #
#---------------------------------------------------------#
# Objective: Split the data received from the AMI into    #
#            packets and run the handler of each one      #
#   Params: [Asterisk TCP handler]                        #
#    Usage:                                               #
#          Handle_AMI($asterisk_handler);                 #
#---------------------------------------------------------#
sub Handle_AMI {
    # the received lines are in $in_buffer{$client}
    my $client = shift;
    my $request;
    my @packet = ();

    foreach $request (@{$in_buffer{$client}}) {
        $event_str .= $request if ($request);
    }
    if ($event_str =~ /\r\n\r\n/) {
       # a packet ends with an empty line
       @packet = $event_str =~ /(?:Action|Event|Message|Response).*?\r\n\r\n/isxg;
       # process each individual packet
       foreach my $packet_content (@packet) {
           $packet_content =~ s/\r//g;
           # the first line has the type and the name, e.g. "Event: ChallengeSent"
           my ($ami_action, $event) = $packet_content =~ /^(.*?):\s(.*?)\n/isx;
           # $event = lc($event);
           if (exists($AMI_Handler{$ami_action}{$event})) {
               $AMI_Handler{$ami_action}{$event}->(\$packet_content);
	       #    print "----- AMI -----\n$packet_content\n";
           }
       }
       # keep an incomplete packet for the next read
       my $last_pos = rindex($event_str,"\r\n\r\n");
       $last_pos = $last_pos + 4;
       my $len = length($event_str);
       if ($len > $last_pos) {
           $event_str = substr($event_str,$last_pos);
       }
       else {
           $event_str = '';
       }
    }
    delete $in_buffer{$client};
}

sub Clean_Connection {
    my $client = shift;

    # Delete the buffers of the connection
    delete $in_buffer{$client};
    delete $out_buffer{$client};
    delete $partial_in{$client};
    delete $sessions{$client};

    # If the AMI connection was lost, the main loop connects again
    if ($client eq $asterisk_handler) {
    	$manager_connect_flag =1;
        $event_str = '';
        %contacts_next = ();
    }
    $select->remove($client);
    close($client);
}

#======================#
#      Main block      #
#======================#

# The ipset and iptables commands must exist, otherwise nothing is blocked
foreach my $command ($ips, $ipt) {
    Fatal("$command not found, check ipset.path and iptables.path in /etc/sipban.conf") unless (-x $command);
}

# Load the whitelist
if (-e $Config{'iptables.white_list'}) {
    open WL, "< $Config{'iptables.white_list'}" || die "Can\'t open the whitelist\n";
    while(<WL>) { # one address per line
        chomp;
        my ($ip, $valid) = Get_IP($_);
        if ($valid) {
            $white_list{$ip} = 1;
            print LOG Time_Stamp() . " WHITE LIST => $ip\n";
        }
    }
    close (WL);
}

# Load the blocked IPs. If the set still exists (unclean stop), the dump file
# is merged into it; otherwise the set is restored from the dump file, or
# created empty.
if ( Ipset_Exists_Set() ) {
    Ipset_Restore_Set();
    Ipset_Load_Ban_IP();
}
else {
    if (-e $Config{'ipset.dump'}) {
        Ipset_Restore_Set();
        Ipset_Load_Ban_IP();
    }
    else {
        Ipset_Create_Set();
    }
}
Fatal("the ipset set $Config{'ipset.set_name'} does not exist (see the previous errors)") unless (Ipset_Exists_Set());
Ipset_Purge_White_List();

# Insert the INPUT rule; the copies left by an unclean stop are deleted first
my $leftover_rules = Iptables_Erase_Rule();
if ($leftover_rules > 0) {
    print LOG Time_Stamp() . " IPTABLES => $leftover_rules INPUT rules left by an unclean stop deleted\n";
}
Iptables_Create_Rule();

# Main loop

while (1) { # Main loop #
    my $client;
    my $rv;
    my $data;
    if ($manager_connect_flag) {
        $manager_connect_flag = Connect_To_Asterisk("$Config{'ami.host'}");
        unless ($manager_connect_flag) {
            Manager_Login();
            $Contacts_Time = 0;   # request the contacts right after login
        }
    }

    # Read the sockets that have data and accept new console clients
    foreach $client ($select->can_read(1)) {
        if ($client == $server) {
            # accept a new connection
            $client = $server->accept();
            $client->blocking(0);
            $select->add($client);
            $sessions{$client} = 1;
            $out_buffer{$client} = "\n$LICENSE\n\nType 'help' to list the commands\nsipban>";
        }
        else {
            # read data
            $data = '';
            eval { $rv   = $client->recv($data, POSIX::BUFSIZ, 0) };
            unless (defined($rv) && length $data) {
                # no data: the other side closed the connection
                Clean_Connection($client);
                next;
            }
            $data =~ s/\0/\r\n/g;
            # a read can end in the middle of a line: prepend the rest of the
            # previous read
            $data = $partial_in{$client} . $data if (exists($partial_in{$client}));
            # move the complete lines to $in_buffer{$client}
            while ($data =~ s/(.*\r\n)//) {
                push( @{$in_buffer{$client}}, $1 );
            }
            # keep the incomplete line for the next read (at most 64 KB)
            $partial_in{$client} = (length($data) < 65536) ? $data : '';
        }
    }

    # Process the complete lines
    foreach $client (keys %in_buffer) {
        if ($client eq $asterisk_handler) {
            Handle_AMI($client);
        }
        else {
            Handle_Clients($client);
        }
    }

    # Timers
    my $current_time = time();
    # keep the AMI connection alive
    if ($current_time >= $Ping_Time) {
        $Ping_Time += $Config{'ami.ping'};
        # print LOG Time_Stamp() . " Ping\n";
        Send_To_Asterisk(\"Action: Ping\r\n\r\n");
    }
    # expired blocks
    if ($current_time >= $min_epoch) {
        Ipset_Prune_Block($current_time);
    }
    # unanswered challenges
    Check_Pending_Auth($current_time);
    # refresh the IPs with registered PJSIP contacts
    if ($contacts_supported && $Config{'trust.refresh'} > 0 && $current_time >= $Contacts_Time) {
        $Contacts_Time = $current_time + $Config{'trust.refresh'};
        Request_Contacts();
    }
    # once a minute
    if ($current_time >= $Housekeeping_Time) {
        $Housekeeping_Time = $current_time + 60;
        Housekeeping($current_time);
    }

    # Send the pending output
    foreach $client ($select->can_write(1)) {
        # nothing to send to this socket
        next unless exists $out_buffer{$client};
        # defensive check: can_write() only returns socket objects
        ## if (defined(getpeername($client))) {
        unless($client eq "") {
            # eval: a failed send must not stop the main loop
            eval { $rv = $client->send($out_buffer{$client}, 0) };
            unless (defined $rv) {
                # Whine, but move on.
                warn "I was told I could write, but I can't.\n";
                next;
            }
            if ($rv == length $out_buffer{$client} ||
                $! == POSIX::EWOULDBLOCK) {
                substr($out_buffer{$client}, 0, $rv) = '';
                delete $out_buffer{$client} unless length $out_buffer{$client};
            } else {
                Clean_Connection($client);
                next;
            }
        } else {
            Clean_Connection($client);
            next;
	    }
    }

    # Out-of-band data is not used
    foreach $client ($select->has_exception(0)) {  # the argument is the timeout
    }
} # End of main loop

#------------- End of main block ----------
