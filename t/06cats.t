#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 13;

chdir("t") if -d "t";

BEGIN {
    use_ok("Palm::KeyRing");
}

my $k = Palm::KeyRing->new("Keys-Gtkr.pdb");
ok($k, "New Palm::KeyRing");

my @a = $k->getCategories;
is(join("|",@a), "Unfiled|Banking|Computer|Phone|Web|||||||||||");

is($k->getCategoryByName("Computer"), 2, "Computer = 2");

my $recs = $k->getRecordsByName("Bank");
is(scalar(@$recs),2, "Two Bank records");

my $m_phone = 1 << $k->getCategoryByName("Phone");
my $m_banking = 1 << $k->getCategoryByName("Banking");

$recs = $k->getRecordsByName("Bank", $m_phone|$m_banking);
is(scalar(@$recs),2, "Two Bank records");

$recs = $k->getRecordsByName("Bank", ~0);
is(scalar(@$recs),2, "Two Bank records");

$recs = $k->getRecordsByName("Bank", 0);
is(scalar(@$recs),0, "No Bank records in 0");

$recs = $k->getRecordsByName("Bank", $m_phone);
is(scalar(@$recs),1, "One Bank record in Phone");

my $d = $k->getDecryptor("secret");
ok($d, "Decryptor / Password check");

@a = $d->decrypt($recs->[0]);
pop(@a);
is(join("|",@a), "Bank|Phone|55-555-557|vlZGQO72|", "Record \"Bank\"");

$recs = $k->getRecordsByName("Bank", $m_banking);
is(scalar(@$recs),1, "One Bank record in Banking");

@a = $d->decrypt($recs->[0]);
pop(@a);
is(join("|",@a), "Bank|Banking|123456|KCCHDE3z|", "Record \"Bank\"");


