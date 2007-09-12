#!/usr/bin/perl -T
# $RedRiver: keyring.t,v 1.15 2007/09/12 02:44:36 andrew Exp $
use strict;
use warnings;

use Test::More tests => 52;
use Data::Dumper;

BEGIN { 
    use_ok( 'Palm::PDB' ); 
    use_ok( 'Palm::Keyring' ); 
}

my $file = 'Keys-test.pdb';
my $password = '12345';
my $new_password = '54321';

my @o = (
    {
        version  => 4,
        password => $password,
    },
    {
        version      => 5,
        password     => $password,
        cipher       => 1,
    },
);

foreach my $options (@o) {
    my $pdb;
    my $record;
    my $decrypted;

    my $acct = {
        0 => {
            label => 'name',
            label_id => 0,
            data  => 'test3',
            font  => 0,
        },
        1 => {
            label => 'account',
            label_id => 1,
            data  => 'atestaccount',
            font  => 0,
        },
        2 => {
            label    => 'password',
            label_id => 2,
            data     => $password,
            font  => 0,
        },
        3 => {
            label => 'lastchange',
            label_id => 3,
            data => {
                day   =>  2,
                month =>  2,
                year  => 99,
            },
            font  => 0,
        },
        255 => {
            label => 'notes',
            label_id => 255,
            data  => 'now that really roxorZ!',
            font  => 0,
        },
    };

    SKIP: {
        if (defined $options->{cipher} && $options->{cipher} > 0) {
            my $crypt = Palm::Keyring::crypts($options->{cipher});
            skip 'Crypt::CBC not installed', 21 unless 
                eval "require Crypt::CBC";
            skip 'Crypt::' . $crypt->{name} . ' not installed', 21 unless 
                eval "require Crypt::$crypt->{name}";
        }

        if ($options->{version} == 4) {
            skip 'Crypt::DES not installed', 21 unless 
                eval " require Crypt::DES ";
            skip 'Digest::MD5 not installed', 21 unless 
                eval " require Digest::MD5 ";
        } elsif ($options->{version} == 5) {
            skip 'Digest::HMAC_SHA1 not installed', 21 unless 
                eval " require Digest::HMAC_SHA1 ";
        }

        ok( $pdb = new Palm::Keyring($options), 
            'new Palm::Keyring v' . $options->{version});

        ok( $record = $pdb->append_Record(), 'Append Record' );

        ok( $pdb->Encrypt($record, $password, $acct), 
            'Encrypt account into record' );

        ok( $pdb->Write($file), 'Write file' );

        $pdb = undef;

        ok( $pdb = new Palm::PDB(), 'new Palm::Keyring' );

        ok( $pdb->Load($file), 'Load File' );

        ok( $pdb->Password($password), 'Verify Password' );

        my $rec_num = 0;
        ok( $decrypted = $pdb->Decrypt($pdb->{records}->[$rec_num]), 
            'Decrypt record' );

        is( $decrypted->{2}->{data}, $password, 'Got password' );

        is_deeply( $decrypted, $acct, 'Account Matches' );

        my $old_date = $decrypted->{3}->{data};

        ok( $pdb->Password($password, $new_password), 'Change PDB Password' );

        ok( $decrypted = $pdb->Decrypt($pdb->{'records'}->[$rec_num]), 
            'Decrypt with new password' );

        my $new_date = $decrypted->{3}->{data};

        is_deeply( $old_date, $new_date, 'Date didn\'t change' );

        $acct->{2}->{data} = $new_password;

        $pdb->{records}->[$rec_num]->{plaintext} = $acct;

        ok(  $pdb->Encrypt($pdb->{'records'}->[$rec_num]), 'Change record' );

        ok( $decrypted = $pdb->Decrypt($pdb->{'records'}->[$rec_num]), 
            'Decrypt new record' );

        $new_date = $decrypted->{3}->{data};

        my $od = join '/', map { $old_date->{$_} } sort keys %{ $old_date };
        my $nd = join '/', map { $new_date->{$_} } sort keys %{ $new_date };

        isnt( $od, $nd, 'Date changed');

        is( $decrypted->{2}->{data}, $new_password, 'Got new password' ); 

        my $last_decrypted = $decrypted;

        $decrypted = {};
        ok( $pdb->Password(), 'Forget password' );

        eval{ $decrypted = $pdb->Decrypt($pdb->{'records'}->[$rec_num]) };
        ok( $@, 'Don\'t decrypt' );

        isnt( $decrypted->{password}, $new_password, 'Didn\'t get new password' );

        ok( $pdb->Unlock($new_password), 'Unlock' );

        my @plaintext = map { $_->{plaintext} } @{ $pdb->{records} };

        is_deeply( $plaintext[0], $last_decrypted, 'Account Matches' );

        ok( $pdb->Lock(), 'Lock' );

        my $cleared_decrypted = {};
        $cleared_decrypted->{0}= $last_decrypted->{0};
        @plaintext = map { $_->{plaintext} } @{ $pdb->{records} };

        is_deeply( $plaintext[0], $cleared_decrypted, 'Cleared records' );

        ok( unlink($file), 'Remove test pdb v' . $options->{version} );

    }
}

1;
