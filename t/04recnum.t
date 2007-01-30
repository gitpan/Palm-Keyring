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

my $d = $k->getDecryptor("secret");
ok($d, "Decryptor / Password check");

my @a = $d->decrypt($k->getRecord(3));
pop(@a);
is(join("|",@a), "MyComputer|Computer|root|M15mz1Za|", "Record 2");
