#!/usr/bin/perl
# $RedRiver: example1.pl,v 1.11 2007/09/12 03:59:37 andrew Exp $
use strict;
use warnings;

use Palm::Keyring;

my $pdb = new Palm::Keyring('12345');

my $rec = $pdb->append_Record();

$rec->{plaintext} = {
	0 => { data => 'Test3' },
	1 => { data => 'anothertestaccount' },
	2 => { data => 'adifferentmypass' },
	255 => { data => 'now that really roxorZ!' },
};

$pdb->Encrypt($rec);
 
$pdb->Write("Keys-Gtkr-example.PDB");
