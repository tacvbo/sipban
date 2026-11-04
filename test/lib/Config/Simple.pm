package Config::Simple;
# Test stub of Config::Simple: only import_from() for INI files
sub import_from {
    my ($class, $file, $hash) = @_;
    open(my $fh, '<', $file) or return 0;
    my $block = 'default';
    while (<$fh>) {
        chomp;
        next if /^\s*(#|$)/;
        if (/^\s*\[(.+?)\]/) { $block = $1; next }
        if (/^\s*([^=]+?)\s*=\s*(.*?)\s*$/) {
            my ($key, $value) = ($1, $2);
            $value =~ s/^"(.*)"$/$1/;
            $hash->{"$block.$key"} = $value;
        }
    }
    return 1;
}
sub error { 'Config::Simple stub error' }
1;
