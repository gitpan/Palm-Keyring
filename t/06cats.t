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

my @a = $k->getCategories;
is(join("|",@a), "Unfiled|Banking|Computer|Phone|Web|||||||||||");

is($k->getCategoryByName("Computer"), 2, "Computer = 2");

