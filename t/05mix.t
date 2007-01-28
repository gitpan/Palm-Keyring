#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 6;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing");
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

my $d = $k->getDecoder("secret");
ok($d, "Decoder / Password check");

my @a = $d->decode($k->getRecordByName("Paypal"));
is(join("|",@a), "Paypal|Web|friend|vy7rouaD|", "Record \"Paypal\"");

@a = $d->decode($k->getRecord(2));
is(join("|",@a), "MyComputer|Computer|root|M15mz1Za|", "Record 2");

@a = $d->decode($k->getRecordByName("Bank"));
is(join("|",@a), "Bank|Banking|123456|KCCHDE3z|", "Record \"Bank\"");
