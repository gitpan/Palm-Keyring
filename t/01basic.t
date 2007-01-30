#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing", 0.91);
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

is($k->getRecords, 4, "Four records");

my @a = sort($k->getNames);
is(join("|",@a), "Bank|Bank|MyComputer|Paypal", "Four names");
