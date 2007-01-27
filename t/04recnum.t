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

my $d = $k->getDecoder("secret");
ok($d, "Decoder / Password check");

my @a = $d->decode($k->getRecord(2));
is(join("|",@a), "MyComputer|root|M15mz1Za|", "Record 2");
