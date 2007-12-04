#!/usr/bin/perl
# $RedRiver: example2.pl,v 1.4 2007/08/10 04:13:31 andrew Exp $
use strict;
use warnings;

use Palm::PDB;
use Palm::Keyring;

my $pdb = new Palm::PDB;

$pdb->Load("Keys-Gtkr-example.PDB"); 
$pdb->Password('12345');

foreach my $rec (@{ $pdb->{records} }) {
    my $acct = $pdb->Decrypt($rec);

    my $d = $acct->{3}->{data};
    my $date = ($d->{year} + 1900) . '/' . ($d->{month} + 1) . '/' . $d->{day};
    print join ":", $acct->{0}->{data} , $acct->{1}->{data},
        $acct->{2}->{data}, $date, $acct->{255}->{data};
    print "\n";
}
