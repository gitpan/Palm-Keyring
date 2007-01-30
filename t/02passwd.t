#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 3;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing", 0.90);
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

my $d = $k->getDecryptor("secret");
ok($d, "Decryptor / Password check");
