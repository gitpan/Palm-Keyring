package Palm::Keyring;

# $RedRiver: Keyring.pm,v 1.25 2007/02/03 01:12:21 andrew Exp $
#
# Perl class for dealing with Keyring for Palm OS databases.
#
#   This started as Memo.pm, I just made it work for Keyring.

use strict;
use warnings;
use Carp;

use base qw/ Palm::StdAppInfo /;

use Digest::MD5 qw(md5);
use Crypt::DES;

my $ENCRYPT    = 1;
my $DECRYPT    = 0;
my $MD5_CBLOCK = 64;
my $kSalt_Size = 4;
my $EMPTY      = q{};
my $SPACE      = q{ };
my $NULL       = chr 0;

our $VERSION = 0.94;

sub new {
    my $classname = shift;
    my $pass      = shift;

    # Create a generic PDB. No need to rebless it, though.
    my $self = $classname->SUPER::new(@_);

    $self->{'name'}    = 'Keys-Gtkr';    # Default
    $self->{'creator'} = 'Gtkr';
    $self->{'type'}    = 'Gkyr';

    # The PDB is not a resource database by
    # default, but it's worth emphasizing,
    # since MemoDB is explicitly not a PRC.
    $self->{'attributes'}{'resource'} = 0;

    # Initialize the AppInfo block
    $self->{'appinfo'} = {};

    # Add the standard AppInfo block stuff
    Palm::StdAppInfo::seed_StdAppInfo( $self->{'appinfo'} );

    # Set the version
    $self->{'version'} = 4;

    if ( defined $pass ) {
        $self->Password($pass);
    }

    return $self;
}

sub import {
    Palm::PDB::RegisterPDBHandlers( __PACKAGE__, [ 'Gtkr', 'Gkyr' ], );
    return 1;
}

sub ParseRecord {
    my $self     = shift;

    my $rec = $self->SUPER::ParseRecord(@_);

    # skip the 0 record that holds the password
    return $rec if ! exists $self->{'records'}; 
    return $rec if ! exists $rec->{'data'};

    my ( $name, $encrypted ) = split /$NULL/xm, $rec->{'data'}, 2;

    return $rec if ! $encrypted;
    delete $rec->{'data'};
    $rec->{'name'} = $name;
    $rec->{'encrypted'} = $encrypted;

    return $rec;
}

sub PackRecord {
    my $self = shift;
    my $rec  = shift;

    if ($rec->{'encrypted'}) {
        if (! defined $rec->{'name'}) {
            $rec->{'name'} = $EMPTY;
        }
        $rec->{'data'} = join $NULL, $rec->{'name'}, $rec->{'encrypted'};
        delete $rec->{'name'};
        delete $rec->{'encrypted'};
    }

    return $self->SUPER::PackRecord($rec, @_);
}

sub Encrypt {
    my $self = shift;
    my $rec  = shift;
    my $data = shift;
    my $pass = shift || $self->{'password'};

    if ( ! $pass) {
        croak("'password' not set!\n");
    }

    if ( ! $rec) {
        croak("Needed parameter 'record' not passed!\n");
    }

    if ( ! $data) {
        croak("Needed parameter 'data' not passed!\n");
    }

    if ( ! $self->Password($pass)) {
        croak("Incorrect Password!\n");
    }

    $self->{'digest'}   ||= _calc_keys( $pass );

    $data->{'account'}  ||= $EMPTY;
    $data->{'password'} ||= $EMPTY;
    $data->{'notes'}    ||= $EMPTY;

    my $changed      = 0;
    my $need_newdate = 0;
    my $acct = {};
    if ($rec->{'encrypted'}) {
        $acct = $self->Decrypt($rec, $pass);
        foreach my $key (keys %{ $data }) {
            next if $key eq 'lastchange';
            if ($data->{$key} ne $acct->{$key}) {
                $changed = 1;
                last;
            }
        }
        if ( exists $data->{'lastchange'} && exists $acct->{'lastchange'} && (
            $data->{'lastchange'}->{day}   != $acct->{'lastchange'}->{day}   ||
            $data->{'lastchange'}->{month} != $acct->{'lastchange'}->{month} ||
            $data->{'lastchange'}->{year}  != $acct->{'lastchange'}->{year}
        )) {
            $changed = 1;
            $need_newdate = 0;
        } else {
            $need_newdate = 1;
        }

    } else {
        $changed = 1;
    }

    # no need to re-encrypt if it has not changed.
    return 1 if ! $changed;

    my ($day, $month, $year);

    if ($data->{'lastchange'} && ! $need_newdate ) {
        $day   = $data->{'lastchange'}->{'day'}   || 1;
        $month = $data->{'lastchange'}->{'month'} || 0;
        $year  = $data->{'lastchange'}->{'year'}  || 0;

        # XXX Need to actually validate the above information somehow
        if ($year >= 1900) {
            $year -= 1900;
        }
    } else {
        $need_newdate = 1;
    }

    if ($need_newdate) {
        ($day, $month, $year) = (localtime)[3,4,5];
    }
    $year -= 4;
    $month++;


    my $p = $day | ($month << 5) | ($year << 9);
    my $packeddate = pack 'n', $p;

    my $plaintext = join $NULL, 
        $data->{'account'}, $data->{'password'}, $data->{'notes'}, $packeddate;

    my $encrypted = _crypt3des( $plaintext, $self->{'digest'}, $ENCRYPT );

    return if ! $encrypted;

    $rec->{'attributes'}{'Dirty'} = 1;
    $rec->{'attributes'}{'dirty'} = 1;
    $rec->{'name'}    ||= $data->{'name'};
    $rec->{'encrypted'} = $encrypted;

    return 1;
}

sub Decrypt {
    my $self = shift;
    my $rec  = shift;
    my $pass = shift || $self->{'password'};

    if ( ! $pass) {
        croak("'password' not set!\n");
    }

    if ( ! $rec) {
        croak("Needed parameter 'record' not passed!\n");
    }

    if ( ! $self->Password($pass)) {
        croak("Invalid Password!\n");
    }

    if ( ! $rec->{'encrypted'} ) {
        croak("No encrypted content!");
    }

    $self->{'digest'} ||= _calc_keys( $pass );

    my $decrypted = 
        _crypt3des( $rec->{'encrypted'}, $self->{'digest'}, $DECRYPT );
    my ( $account, $password, $notes, $packeddate ) = split /$NULL/xm,
          $decrypted, 4;

    my %Modified;
    if ($packeddate) {
        my $u = unpack 'n', $packeddate;
        my $year  = (($u & 0xFE00) >> 9) + 4; # since 1900
        my $month = (($u & 0x01E0) >> 5) - 1; # 0-11
        my $day   = (($u & 0x001F) >> 0);     # 1-31

        %Modified = (
            year   => $year,
            month  => $month || 0,
            day    => $day   || 1,
        );
    }

    return {
        name       => $rec->{'name'},
        account    => $account,
        password   => $password,
        notes      => $notes,
        lastchange => \%Modified,
    };
}

sub Password {
    my $self = shift;
    my $pass = shift;
    my $new_pass = shift;

    if (! $pass) {
        delete $self->{password};
	return 1;
    }

    if (! exists $self->{'records'}) {
        # Give the PDB the first record that will hold the encrypted password
        $self->{'records'} = [ $self->new_Record ];

        return $self->_password_update($pass);
    }

    if ($new_pass) {
        my @accts = ();
        foreach my $i (0..$#{ $self->{'records'} }) {
            if ($i == 0) {
                push @accts, undef;
                next;
            }
            my $acct = $self->Decrypt($self->{'records'}->[$i], $pass);
            if ( ! $acct ) {
                croak("Couldn't decrypt $self->{'records'}->[$i]->{'name'}");
            }
            push @accts, $acct;
        }

        if ( ! $self->_password_update($new_pass)) {
            croak("Couldn't set new password!");
        }
        $pass = $new_pass;

        foreach my $i (0..$#accts) {
            next if $i == 0;
            delete $self->{'records'}->[$i]->{'encrypted'};
            $self->Encrypt($self->{'records'}->[$i], $accts[$i], $pass);
        }
    }

    return $self->_password_verify($pass);
}

sub _calc_keys {
    my $pass = shift;
    if (! defined $pass) { croak('No password defined!'); };

    my $digest = md5($pass);

    my ( $key1, $key2 ) = unpack 'a8a8', $digest;

    #--------------------------------------------------
    # print "key1: $key1: ", length $key1, "\n";
    # print "key2: $key2: ", length $key2, "\n";
    #--------------------------------------------------

    $digest = unpack 'H*', $key1 . $key2 . $key1;

    #--------------------------------------------------
    # print "Digest: ", $digest, "\n";
    # print length $digest, "\n";
    #--------------------------------------------------

    return $digest;
}

sub _password_verify {
    my $self = shift;
    my $pass = shift;

    if (! $pass) { croak('No password specified!'); };

    if (defined $self->{'password'} && $pass eq $self->{'password'}) {
        # already verified this password
        return 1;
    }

    # AFAIK the thing we use to test the password is
    #     always in the first entry
    my $data = $self->{'records'}->[0]->{'data'};

    #die "No encrypted password in file!" unless defined $data;
    if ( ! defined $data) { return; };

    $data =~ s/$NULL$//xm;

    my $salt = substr $data, 0, $kSalt_Size;

    my $msg = $salt . $pass;

    $msg .= "\0" x ( $MD5_CBLOCK - length $msg );

    my $digest = md5($msg);

    if ( $data eq $salt . $digest ) {

# May as well generate the keys we need now, since we know the password is right
        $self->{'digest'} = _calc_keys($pass);
        if ( $self->{'digest'} ) {
            $self->{'password'} = $pass;
            return 1;
        }
    }
    return;
}

sub _password_update {

    # It is very important to Encrypt after calling this
    #     (Although it is generally only called by Encrypt)
    # because otherwise the data will be out of sync with the
    # password, and that would suck!
    my $self = shift;
    my $pass = shift;

    if (! defined $pass) { croak('No password specified!'); };

    my $salt;
    for ( 1 .. $kSalt_Size ) {
        $salt .= chr int rand 255;
    }

    my $msg = $salt . $pass;

    $msg .= "\0" x ( $MD5_CBLOCK - length $msg );

    my $digest = md5($msg);

    my $data = $salt . $digest;    # . "\0";

    # AFAIK the thing we use to test the password is
    #     always in the first entry
    $self->{'records'}->[0]->{'data'} = $data;

    $self->{'password'} = $pass;
    $self->{'digest'}   = _calc_keys( $self->{'password'} );

    return 1;
}

sub _crypt3des {
    my ( $plaintext, $passphrase, $flag ) = @_;

    $passphrase   .= $SPACE x ( 16 * 3 );
    my $cyphertext = $EMPTY;

    my $size = length $plaintext;

    #print "STRING: '$plaintext' - Length: " . (length $plaintext) . "\n";

    my @C;
    for ( 0 .. 2 ) {
        $C[$_] =
          new Crypt::DES( pack 'H*', ( substr $passphrase, 16 * $_, 16 ));
    }

    for ( 0 .. ( ($size) / 8 ) ) {
        my $pt = substr $plaintext, $_ * 8, 8;

        #print "PT: '$pt' - Length: " . length($pt) . "\n";
        if (! length $pt) { next; };
        if ( (length $pt) < 8 ) {
            if ($flag == $DECRYPT) { croak('record not 8 byte padded'); };
            my $len = 8 - (length $pt);

            #print "LENGTH: $len\n";
            #print "Binary:    '" . unpack("b*", $pt) . "'\n";
            $pt .= ($NULL x $len);

            #print "PT: '$pt' - Length: " . length($pt) . "\n";
            #print "Binary:    '" . unpack("b*", $pt) . "'\n";
        }
        if ( $flag == $ENCRYPT ) {
            $pt = $C[0]->encrypt($pt);
            $pt = $C[1]->decrypt($pt);
            $pt = $C[2]->encrypt($pt);
        }
        else {
            $pt = $C[0]->decrypt($pt);
            $pt = $C[1]->encrypt($pt);
            $pt = $C[2]->decrypt($pt);
        }

        #print "PT: '$pt' - Length: " . length($pt) . "\n";
        $cyphertext .= $pt;
    }

    $cyphertext =~ s/$NULL+$//xm;

    #print "CT: '$cyphertext' - Length: " . length($cyphertext) . "\n";

    return $cyphertext;
}

1;
__END__

=head1 NAME

Palm::Keyring - Handler for Palm Keyring databases.

=head1 DESCRIPTION

The Keyring PDB handler is a helper class for the Palm::PDB package. It
parses Keyring for Palm OS databases.  See
L<http://gnukeyring.sourceforge.net/>.

It has the standard Palm::PDB methods with 2 additional public methods.  
Decrypt and Encrypt.

It currently supports the v4 Keyring databases.  The v5 databases from 
the pre-release keyring-2.0 are not supported.

This module doesn't store the decrypted content.  It only keeps it until it 
returns it to you or encrypts it.

=head1 SYNOPSIS

    use Palm::PDB;
    use Palm::Keyring;
    
    my $pass = 'password';
    my $file = 'Keys-Gtkr.pdb';
    my $pdb  = new Palm::PDB;
    $pdb->Load($file);
    
    foreach (0..$#{ $pdb->{'records'} }) {
        next if $_ = 0; # skip the password record
        my $rec  = $pdb->{'records'}->[$_];
        my $acct = $pdb->Decrypt($rec, $pass);
        print $rec->{'name'}, ' - ', $acct->{'account'}, "\n";
    }

=head1 SUBROUTINES/METHODS

=head2 new

    $pdb = new Palm::Keyring([$password]);

Create a new PDB, initialized with the various Palm::Keyring fields
and an empty record list.

Use this method if you're creating a Keyring PDB from scratch otherwise you 
can just use Palm::PDB::new() before calling Load().

If you pass in a password, it will initalize the first record with the encrypted 
password.

=head2 Encrypt

    $pdb->Encrypt($rec, $acct[, $password]);

Encrypts an account into a record, either with the password previously 
used, or with a password that is passed.

$rec is a record from $pdb->{'records'} or a new_Record().
$acct is a hashref in the format below.

    my $acct = {
        name       => $rec->{'name'},
        account    => $account,
        password   => $password,
        notes      => $notes,
        lastchange => {
            year  => 107, # years since 1900
            month =>   0, # 0-11, 0 = January, 11 = December
            day   =>  30, # 1-31, same as localtime
        },
    };

If you have changed anything other than the lastchange, or don't pass in a 
lastchange key, Encrypt() will generate a new lastchange date for you.

If you pass in a lastchange field that is different than the one in the
record, it will honor what you passed in.

Encrypt() only uses the $acct->{'name'} if there is not already a $rec->{'name'}.

=head2 Decrypt

    my $acct = $pdb->Decrypt($rec[, $password]);

Decrypts the record and returns a hashref for the account as described 
under Encrypt().  

    foreach (0..$#{ $pdb->{'records'}) {
        next if $_ == 0;
        my $rec = $pdb->{'records'}->[$_];
        my $acct = $pdb->Decrypt($rec[, $password]);
        # do something with $acct
    }

=head2 Password

    $pdb->Password([$password[, $new_password]]);

Either sets the password to be used to crypt, or if you pass $new_password, 
changes the password on the database.

If you have created a new $pdb, and you didn't set a password when you 
called new(), you only need to pass one password and it will set that as 
the password. 

If nothing is passed, it forgets the password that it was remembering.

=head1 DEPENDENCIES

Palm::StdAppInfo

Digest::MD5

Crypt::DES

Readonly

=head1 THANKS

I would like to thank the helpful Perlmonk shigetsu who gave me some great advice
and helped me get my first module posted.  L<http://perlmonks.org/?node_id=596998>

I would also like to thank 
Johan Vromans
E<lt>jvromans@squirrel.nlE<gt> -- 
L<http://www.squirrel.nl/people/jvromans>.
He had his own Palm::KeyRing module that he posted a couple of days before 
mine was ready and he was kind enough to let me have the namespace as well 
as giving me some very helpful hints about doing a few things that I was 
unsure of.  He is really great.

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to
C<bug-palm-keyring at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.  I will be notified, and then you'll automatically be
notified of progress on your bug as I make changes.

=head1 AUTHOR

Andrew Fresh E<lt>andrew@mad-techies.orgE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright 2004, 2005, 2006, 2007 Andrew Fresh, All Rights Reserved.

This program is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

=head1 SEE ALSO

Palm::PDB(3)

Palm::StdAppInfo(3)

The Keyring for Palm OS website: 
L<http://gnukeyring.sourceforge.net/>

Johan Vromans also has a wxkeyring app that now uses this module, available 
from his website at L<http://www.vromans.org/johan/software/>
