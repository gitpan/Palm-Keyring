#!/usr/bin/perl -T
# $RedRiver: keyring5-samples.t,v 1.6 2007/09/13 15:44:39 andrew Exp $
use strict;
use warnings;

use Test::More tests => 30;

BEGIN { use_ok( 'Palm::PDB' ); }
BEGIN { use_ok( 'Palm::Keyring' ); }

my $password = 'abc';
my $orig_recs = [
    {
        0 => {
            'label_id' => 0,
            'data' => '',
            'label' => 'name',
            'font' => 0,
        },
        2 => {
            'label_id' => 2,
            'data' => 'only password is set',
            'label' => 'password',
            'font' => 0
        },
        3 => {
            'label_id' => 3,
            'data' => {
                'month' => 1,
                'day' => 1,
                'year' => 107
            },
            'label' => 'lastchange',
            'font' => 0
        }
    },
    {
        0 => {
            'label_id' => 0,
            'data' => 'hoenicke',
            'label' => 'name',
            'font' => 0,
        },
        1 => {
            'label_id' => 1,
            'data' => 'test',
            'label' => 'account',
            'font' => 0
        },
        2 => {
            'label_id' => 2,
            'data' => 'abcd1234',
            'label' => 'password',
            'font' => 0
        },
        3 => {
            'label_id' => 3,
            'data' => {
                'month' => 1,
                'day' => 11,
                'year' => 107
            },
            'label' => 'lastchange',
            'font' => 0
        },
        255 => {
            'label_id' => 255,
            'data' => 'This is a short note.',
            'label' => 'notes',
            'font' => 0
        }
    },
    {
        0 => {
            'label_id' => 0,
            'data' => 'name',
            'label' => 'name',
            'font' => 0,
        },
        2 => {
            'label_id' => 2,
            'data' => 'password (date is 2/2/07)',
            'label' => 'password',
            'font' => 0
        },
        3 => {
            'label_id' => 3,
            'data' => {
                'month' => 1,
                'day' => 2,
                'year' => 107
            },
            'label' => 'lastchange',
            'font' => 0
        }
    }
];

foreach my $file ('Keys-None.pdb', 'Keys-3DES.pdb', 'Keys-AES.pdb', 'Keys-AES256.pdb') {
    my $pdb;
    ok( $pdb = new Palm::PDB, 'new Palm::PDB' );
    ok( $pdb->Load('t/' . $file), "Loading '$file'" );
    my $Num_Tests_Left = 5;
    SKIP: {
        skip 'Digest::HMAC_SHA1 not installed', $Num_Tests_Left
            unless eval "require Digest::HMAC_SHA1";

        if ($pdb->{appinfo}->{cipher} > 0) {
            my $crypt = Palm::Keyring::crypts($pdb->{appinfo}->{cipher});
            skip 'Crypt::CBC not installed', $Num_Tests_Left
                unless eval "require Crypt::CBC";
            skip 'Crypt::' . $crypt->{name} . ' not installed', $Num_Tests_Left
                unless eval "require Crypt::$crypt->{name}";
        }

        $password = 'abc';
        ok( $pdb->Password($password), 'Passing Password' );
        my @recs = ();
        foreach my $rec (@{ $pdb->{records}}) {
            my $acct;
            ok( $acct = $pdb->Decrypt( $rec ), 'Decrypting record ' . scalar @recs );
            push @recs, $acct;
        }
        is_deeply(\@recs, $orig_recs, "Matching records in '$file'" );
    }
}
