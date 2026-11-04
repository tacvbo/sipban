package Tie::Cache;
# Test stub of Tie::Cache: a plain hash, without the size limit
require Tie::Hash;
our @ISA = ('Tie::StdHash');
sub TIEHASH { my $class = shift; return bless {}, $class }
1;
