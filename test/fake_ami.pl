#!/usr/bin/perl
#----------------------------------------------------------------------
# Simulated Asterisk Manager Interface (AMI) for the sipban tests.
#
# Usage: fake_ami.pl <port> <contacts mode>
#
# It accepts one connection, answers the actions that sipban sends
# (Login, Ping and PJSIPShowContacts) and plays the scenario below: a
# list of security events with the format of Asterisk 16 (PJSIP).
#
# Contacts mode, how PJSIPShowContacts is answered:
#   ok    two registered contacts (203.0.113.10 and 203.0.113.11)
#   error "Response: Error" (as when the AMI user lacks permissions)
#   empty "No Contacts found" (as Asterisk answers when there are none)
#
# The number of PJSIPShowContacts requests is written to stderr.
#----------------------------------------------------------------------
use strict;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(sleep time);

my ($port, $mode) = @ARGV;
my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
                                   LocalPort => $port,
                                   Listen    => 1,
                                   ReuseAddr => 1) or die "fake_ami: $!\n";
my $client = $server->accept();
$client->autoflush(1);
print $client "Asterisk Call Manager/7.0.3\r\n";

my $in = '';
my $logged_in = 0;
my $contacts_requests = 0;
my $select = IO::Select->new($client);

# A security event; the fields that sipban reads are parameters
sub Event {
    my ($name, %field) = @_;
    my $event = "Event: $name\r\nPrivilege: security,all\r\nSeverity: Error\r\n";
    $event .= "Service: " . ($field{service} // 'PJSIP') . "\r\nEventVersion: 1\r\n";
    $event .= "AccountID: $field{account}\r\nSessionID: $field{session}\r\n";
    $event .= "LocalAddress: IPV4/UDP/203.0.113.1/5060\r\n";
    $event .= "RemoteAddress: " . ($field{address} // "IPV4/UDP/$field{ip}/5060") . "\r\n";
    $event .= "UsingPassword: $field{password}\r\n" if (defined($field{password}));
    return "$event\r\n";
}

sub Answer_Contacts {
    my $action_id = shift;
    $contacts_requests++;
    if ($mode eq 'error') {
        print $client "Response: Error\r\nActionID: $action_id\r\nMessage: Permission denied\r\n\r\n";
    }
    elsif ($mode eq 'empty') {
        print $client "Response: Error\r\nActionID: $action_id\r\nMessage: No Contacts found\r\n\r\n";
    }
    else {
        print $client "Response: Success\r\nActionID: $action_id\r\nEventList: start\r\n"
                    . "Message: A listing of Contacts follows, presented as ContactList events\r\n\r\n";
        # phone behind NAT: public IP in the URI (rewrite_contact=yes), private IP in ViaAddr
        print $client "Event: ContactList\r\nActionID: $action_id\r\nObjectType: contact\r\n"
                    . "ObjectName: 101;\@abc\r\nViaAddr: 192.168.1.50\r\n"
                    . "Uri: sip:101\@203.0.113.10:5060;ob\r\nEndpoint: 101\r\nStatus: Reachable\r\n\r\n";
        print $client "Event: ContactList\r\nActionID: $action_id\r\nObjectType: contact\r\n"
                    . "ObjectName: 102;\@def\r\nViaAddr: 203.0.113.11\r\n"
                    . "Uri: sip:102\@203.0.113.11:5062\r\nEndpoint: 102\r\nStatus: Reachable\r\n\r\n";
        print $client "Event: ContactListComplete\r\nActionID: $action_id\r\nEventList: Complete\r\nListItems: 2\r\n\r\n";
    }
}

# Read and answer the actions of sipban for $seconds seconds
sub Serve {
    my $seconds = shift;
    my $end = time() + $seconds;
    while (time() < $end) {
        next unless ($select->can_read(0.05));
        my $data;
        exit(0) unless (sysread($client, $data, 65536));
        $in .= $data;
        while ($in =~ s/^(.*?)\r\n\r\n//s) {
            my $action = $1;
            my ($action_id) = $action =~ /ActionID: ([^\r\n]*)/;
            if ($action =~ /Action: login/i) {
                print $client "Response: Success\r\nMessage: Authentication accepted\r\n\r\n";
                $logged_in = 1;
            }
            elsif ($action =~ /Action: Ping/i) {
                print $client "Response: Success\r\nPing: Pong\r\n\r\n";
            }
            elsif ($action =~ /Action: PJSIPShowContacts/i) {
                Answer_Contacts($action_id);
            }
        }
    }
}

Serve(0.05) until ($logged_in);
Serve(1.5);    # sipban requests the contacts right after the login

my @scenario = (
    # registered contact: ignored, and logged only once
    Event('InvalidAccountID', ip => '203.0.113.10', account => '205', session => 'r1'),
    Event('InvalidAccountID', ip => '203.0.113.10', account => '205', session => 'r2'),
    # unknown IP: blocked at the first failure
    Event('InvalidAccountID', ip => '198.51.100.20', account => 'admin', session => 'u1'),
    # answered challenge: not blocked, and the IP becomes trusted
    Event('ChallengeSent', ip => '198.51.100.30', account => '300', session => 'S1'),
    Event('SuccessfulAuth', ip => '198.51.100.30', account => '300', session => 'S1', password => 1),
    Event('InvalidAccountID', ip => '198.51.100.30', account => '999', session => 'S2'),
    # 3 unanswered challenges: blocked after flood.grace seconds
    (map { Event('ChallengeSent', ip => '198.51.100.40', account => '100', session => "A$_") } 1..3),
    # 2 unanswered challenges: fewer than flood.count
    (map { Event('ChallengeSent', ip => '198.51.100.50', account => '100', session => "B$_") } 1..2),
    Event('ChallengeResponseFailed', ip => '198.51.100.60', account => '101', session => 'c1'),
    Event('FailedACL', ip => '198.51.100.70', account => 'anonymous', session => 'f1'),
    # inside the whitelisted class 192.0.2.0/24
    Event('InvalidAccountID', ip => '192.0.2.55', account => '205', session => 'w1'),
    # brute force from a registered IP: blocked after trust.max_failures
    (map { Event('ChallengeResponseFailed', ip => '203.0.113.11', account => '102', session => "bf$_") } 1..4),
    # a service that sipban does not process, and an IPv6 address
    Event('InvalidAccountID', ip => '198.51.100.90', account => 'x', session => 'n1', service => 'FOO'),
    Event('InvalidAccountID', address => 'IPV6/UDP/2001:db8::1/5060', account => 'x', session => 'n2'),
    # control characters in the account: they must not reach the log
    Event('InvalidAccountID', ip => '198.51.100.95', account => "evil\x01\x1b[31m", session => 'e1'),
);
foreach my $event (@scenario) {
    print $client $event;
    Serve(0.05);
}

# An event split in the middle of a line, in two writes. Nothing is
# answered in between: Asterisk never writes inside a packet.
my $split = Event('InvalidAccountID', ip => '198.51.100.80', account => 'split', session => 'p1');
my $cut = index($split, 'RemoteAdd') + 9;
print $client substr($split, 0, $cut);
sleep(1.5);
print $client substr($split, $cut);

Serve(3);
print STDERR "PJSIPShowContacts requests: $contacts_requests\n";
Serve(60);
