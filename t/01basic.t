#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing");
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

is($k->getRecords, 3, "Three records");

my @a = sort($k->getNames);
is(join("|",@a), "Bank|MyComputer|Paypal", "Three names");
