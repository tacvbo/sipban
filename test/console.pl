#!/usr/bin/perl
# Sends commands to the sipban control console and prints the answers.
# Usage: console.pl <port> <command>...
use strict;
use IO::Socket::INET;
use Time::HiRes qw(sleep);

my ($port, @commands) = @ARGV;
my $console = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port") or die "console: $!\n";
sleep(0.5);
foreach my $command (@commands) {
    print $console "$command\r\n";
    sleep(0.8);
}
$console->blocking(0);
my $output = '';
while (sysread($console, my $data, 65536)) {
    $output .= $data;
}
$output =~ s/\r//g;
print $output;
