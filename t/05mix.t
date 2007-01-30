#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing");
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

my $d = $k->getDecryptor("secret");
ok($d, "Decryptor / Password check");

my @a = $d->decrypt($k->getRecordsByName("Paypal")->[0]);
pop(@a);
is(join("|",@a), "Paypal|Web|friend|vy7rouaD|", "Record \"Paypal\"");

@a = $d->decrypt($k->getRecord(3));
pop(@a);
is(join("|",@a), "MyComputer|Computer|root|M15mz1Za|", "Record 2");

@a = $d->decrypt($k->getRecordsByName("Bank")->[0]);
pop(@a);
is(join("|",@a), "Bank|Phone|55-555-557|vlZGQO72|", "Record \"Bank\"");

@a = $d->decrypt($k->getRecordsByName("Bank")->[1]);
pop(@a);
is(join("|",@a), "Bank|Banking|123456|KCCHDE3z|", "Record \"Bank\"");
