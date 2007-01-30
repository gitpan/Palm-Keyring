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

my $d = $k->getDecryptor("secret");
ok($d, "Decryptor / Password check");

my @a = $d->decrypt($k->getRecordsByName("Paypal")->[0]);
pop(@a);
is(join("|",@a), "Paypal|Web|friend|vy7rouaD|", "Record \"Paypal\"");

