#!/usr/bin/perl -T
# $RedRiver: keyring5.t,v 1.8 2007/09/12 02:44:36 andrew Exp $
use strict;
use warnings;

use Test::More tests => 138;

BEGIN { 
    use_ok( 'Palm::PDB' ); 
    use_ok( 'Palm::Keyring' ); 
}

my $file = 'Keys-test.pdb';
my $password = '12345';
my $new_password = '54321';

foreach my $cipher (0..3) {
#next unless $cipher == 0;
    my $pdb;
    my @recs;
    my $record;
    my $decrypted;

    my $crypt = Palm::Keyring::crypts($cipher);

    my $options = {
        version  => 5,
        password => $password,
        cipher   => $cipher,
    };

    my $original_accts = [
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
        'font' => 0,
    },
    3 => {
        'label_id' => 3,
        'data' => {
            'month' => 1,
            'day' => 1,
            'year' => 107
        },
        'label' => 'lastchange',
        'font' => 0,
    }
    },
    {
    0 => {
        'label_id' => 0,
        'data' => 'test',
        'label' => 'name',
        'font' => 0,
    },
    2 => {
        'label_id' => 2,
        'data' => 'abcd1234',
        'label' => 'password',
        'font' => 0,
    },
    3 => {
        'label_id' => 3,
        'data' => {
            'month' => 1,
            'day' => 11,
            'year' => 107
        },
        'label' => 'lastchange',
        'font' => 0,
    },
    255 => {
        'label_id' => 255,
        'data' => 'This is a short note.',
        'label' => 'notes',
        'font' => 0,
    }
    },
    {
    0 => {
        'label_id' => 0,
        'data' => '',
        'label' => 'name',
        'font' => 0,
    },
    2 => {
        'label_id' => 2,
        'data' => 'password (date is 2/2/07)',
        'label' => 'password',
        'font' => 0,
    },
    3 => {
        'label_id' => 3,
        'data' => {
            'month' => 1,
            'day' => 2,
            'year' => 107
        },
        'label' => 'lastchange',
        'font' => 0,
    }
    }
    ];

    SKIP: {
        if ($cipher > 0) {
            skip 'Crypt::CBC not installed', 34 unless 
                eval "require Crypt::CBC";
            skip 'Crypt::' . $crypt->{name} . ' not installed', 34 unless 
                eval "require Crypt::$crypt->{name}";
        }
        skip 'Digest::HMAC_SHA1 not installed', 34 unless 
            eval " require Digest::HMAC_SHA1 ";

        ok( $pdb = new Palm::Keyring($options), 'New Palm::Keyring v' 
            . $options->{version} 
            . ' Cipher ' 
            . $options->{cipher}
        );

        foreach my $acct (@{ $original_accts} ) {
            ok( $record = $pdb->append_Record(), 'Append Record' );
            ok( $pdb->Encrypt($record, $password, $acct), 
                'Encrypt account into record' );
        }

        ok( $pdb->Write($file), 'Write file' );

        $pdb = undef;

        ok( $pdb = new Palm::PDB(), 'New Palm::PDB' );

        ok( $pdb->Load($file), 'Load File' );

        ok( $pdb->Password($password), 'Verify Password' );

        my $rec_id = 0;
        foreach my $rec (@{ $pdb->{records} }) {
            ok( $decrypted = $pdb->Decrypt($rec), 'Decrypt record' );
            if ($rec_id == 1) {
                is( $decrypted->{0}->{data}, $original_accts->[1]->{0}->{data}, 
                    'Checking record name' );
            }
            push @recs, $decrypted;
            $rec_id++;
        }

        is_deeply( \@recs, $original_accts, 'Account Matches' );

        @recs = ();
        my $rec_num = 1;

        ok( $pdb->Password($password, $new_password), 'Change PDB Password' );

        foreach my $rec (@{ $pdb->{records} }) {
        ok( $decrypted = $pdb->Decrypt($rec), 'Decrypt record' );
        push @recs, $decrypted;
        }

        is_deeply( \@recs, $original_accts, 'Account Matches' );

        my $acct;
        ok( $acct = $pdb->Decrypt( $pdb->{records}->[$rec_num]), 'decrypt record ' . $rec_num);

        ok($acct->{2}->{data} = $new_password, 'Change password');

        $pdb->{records}->[$rec_num]->{plaintext} = $acct;
        $recs[$rec_num] = $acct;

        ok(  $pdb->Encrypt($pdb->{'records'}->[$rec_num]), 'Change record');

        ok( $decrypted = $pdb->Decrypt($pdb->{'records'}->[$rec_num]), 
            'Decrypt changed record' );

        is_deeply($acct, $decrypted, 'Compare changed record');

        my $last_decrypted = $decrypted;
        $decrypted = {};
        ok( $pdb->Password(), 'Forget password' );

        eval{ $decrypted = $pdb->Decrypt($pdb->{'records'}->[$rec_num]) };
        ok($@, 'Don\'t decrypt');

        my $got_password = 'Got nothing';
        if ($decrypted) {
            $got_password = $decrypted->{2}->{data};
        }

        isnt( $got_password, $new_password, 'Didn\'t get new password' );

        ok( $pdb->Unlock($new_password), 'Unlock' );

        my @plaintext = map { $_->{plaintext} } @{ $pdb->{records} };

        is_deeply( \@plaintext, \@recs, 'Account Matches' );

        ok( $pdb->Lock(), 'Lock' );

        my @cleared = map { { 0 => $_->{0} } } @recs;
        @plaintext  = map { $_->{plaintext} } @{ $pdb->{records} };

        is_deeply( \@plaintext, \@cleared, 'Cleared records' );

        ok( unlink($file), 'Remove test pdb v' . $options->{version} );
        }
}

1;
