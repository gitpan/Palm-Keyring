#!/usr/bin/perl

package Palm::KeyRing;

$VERSION = "0.92";

use strict;
use warnings;

use Carp;
use Palm::PDB;
use Palm::Raw;

=head1 NAME

Palm::KeyRing - Interface to GNU KeyRing databases

=head1 SYNOPSIS

  use Palm::KeyRing;

  # Open the database.
  my $db = Palm::KeyRing->new("Keys-Gtkr.pdb");

  # Fetch a decryptor (verifies the password).
  my $decryptor = $db->getDecryptor("Secret PassPhrase");
  die("Incorrect password") unless $decryptor;

  # Fetch record by number (first = 1).
  my $rec = $db->getRecord(1);
  # Or fetch record by name.
  # Note that there can be several records with the same name.
  $rec = $db->getRecordsByName("BankAccount")->[0];
  # $rec->{name} the name.
  # $rec->{category} the category index.
  # $rec->{data} contains the encrypteddata.

  # Decrypt record.
  my ($name, $category, $account, $password, $note, $lastmod) =
    $decryptor->decrypt($rec);

=head1 DESCRIPTION

Palm::KeyRing provides a (currently read-only) interface to the
keyring files as used by the GNU KeyRing tool on Palm handhelds.

Records in the keyring file have 5 fields: name, account, password,
note, and lastmod. All fields except name are encrypted.

The lastmod field, if present, will be returned by the decryptor as an
array reference [ year, month, day ], compatible with the first three
elements returned by localtime.

=head1 METHODS

The following are methods of Palm::KeyRing.

=over 4

=item new

Constructor. Takes one argument: the name of the keyring file. 

=item getRecords

Returns the number of records read. Note that the contents will not be
decrypted.

=item getNames

Returns a list (in scalar context: array reference) of all names used
in the keyring file.

=item getRecord

Takes one integer argument, a record number, and returns the record.
This is a hash ref with at least keys "name, "data" and "category".
Note that "category" is the category index.

If no such record exists, returns undef.

=item getRecordsByName

Takes two arguments, a record name, and a category mask. Returns an
list (or arry ref in scalar context) of the corresponding records. See
getRecord above for the return values.

If no such record exists, returns an empty list (or reference).

The category mask is a bit pattern, where bit 0 = category 0
(Unfiled), bit 1 = category 1, and so on. When the category mask is
omitted, returns the results for all categories.

=item getCategory

Takes one argument, a category index. Returns the category as a string.

=item getCategories

In list context, returns a list of categories. In scalar context
returns an array reference.

=item getDecryptor

Takes one argument, the keyring password. If the password is correct,
it returns a decryptor for this keyring. Otherwise, it returns undef.

The decryptor provides one method: decrypt. This method takes one
argument, the record (as a hash ref). It returns a list (in scalar
context: array reference) of the record name, category_name, account,
password, note, and lastmod; all decrypted.

=head1 REQUIREMENTS

PDA::Pilot

Crypt::DES

=head1 DEMO PROGRAM

Palm::KeyRing comes with a nice GUI based demo program wxkeyring. This
program requires WxPerl 0.15 or later.

=head1 BUGS AND LIMITATIONS

Installs Palm::Raw as the default handler for Palm::PDB. This could
have side effects if the rest of the program also uses Palm::PDB.

Please report any bugs or feature requests to bug-palm-keyring at
rt.cpan.org, or through the web interface at http://rt.cpan.org.

=head1 SEE ALSO

Palm::PDB

The Keyring for Palm OS website: http://gnukeyring.sourceforge.net

=head1 AUTHOR

Johan Vromans E<lt>jv@cpan.orgE<gt>.

=head1 LICENCE AND COPYRIGHT

Copyright 2007 Johan Vromans, All Rights Reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

sub new {
    my ($pkg, $file, %args) = @_;
    $pkg = ref($pkg) || $pkg;
    my $self = {};

    croak("$file: $!\n") unless -f $file && -r $file;
    $self->{db} = Palm::PDB->new;
    $self->{db}->Load($file);
    $self->{filename} = $file;

    # Load the records.
    my $recno = 0;
    foreach ( @{$self->{db}->{records}} ) {
	if ( $recno == 0 ) {
	    $recno++;
	    next;
	}
	my $r = $_->{data};
	$r =~ /^(.+?)\000/s;
	my $name = $1;
	push(@{$self->{recs}->{$name}}, $recno, $_->{category});
	push(@{$self->{names}}, $name);
	$recno++;
    }

    # Load the categories.
    $self->{categories} =
      [ unpack("xx".("A16"x16), $self->{db}->{appinfo}) ];

    # Return the object.
    bless($self, $pkg);
}

sub getDecryptor {
    my ($self, $passwd) = @_;
    Palm::KeyRing::Decryptor->_new
	($self, $self->{db}->{records}->[0]->{data}, $passwd);
}

sub getRecord {
    my ($self, $recno) = @_;
    return undef if $recno >= scalar(@{$self->{db}->{records}});
    $self->{db}->{records}->[$recno];
}

sub getRecordsByName {
    my ($self, $name, $catmask) = @_;
    $catmask = ~0 unless defined $catmask;
    my @ret = ();
    if ( exists $self->{recs}->{$name} ) {
	my @a = @{$self->{recs}->{$name}};
	while ( @a ) {
	    my $rnr = shift(@a);
	    my $cat = shift(@a);
	    next unless $catmask & (1 << $cat);
	    push(@ret, $self->getRecord($rnr));
	}
    }
    wantarray ? @ret : \@ret;
}

sub getRecords {
    my ($self) = @_;
    scalar(@{$self->{db}->{records}})-1;
}

sub getNames {
    my ($self) = @_;
    my @names = @{$self->{names}};
    wantarray ? @names : \@names;
}

sub getCategory {
    my ($self, $cat) = @_;
    return undef unless $self->{categories}->[$cat];
    return $self->{categories}->[$cat];
}

sub getCategoryByName {
    my ($self, $name) = @_;

    unless ( exists($self->{catmap}) ) {
	# Build reverse mapping.
	for ( my $i = 0; $i < 15; $i++ ) {
	    next unless $self->{categories}->[$i];
	    $self->{catmap}->{$self->{categories}->[$i]} = $i;
	}
    }

    $self->{catmap}->{$name};
}

sub getCategories {
    my ($self) = @_;
    wantarray ? @{$self->{categories}} : $self->{categories};
}

package Palm::KeyRing::Decryptor;

use Crypt::DES;
use Digest::MD5 qw(md5);
use Carp;

sub _new {
    my ($pkg, $super, $keyring0, $passwd) = @_;
    $pkg = ref($pkg) || $pkg;

    my $msg = substr($keyring0,0,4).$passwd."\000" x 64;
    $msg = substr($msg,0,64);	# cut to 64 bytes
    my $digest = md5($msg);
    if ( substr($keyring0,4,length($digest)) eq $digest ) {
	my $key = md5($passwd);
	return bless([$super,
		      Crypt::DES->new(substr($key,0,8)),
		      Crypt::DES->new(substr($key,8,8))], $pkg);
    }
    undef;
}

sub decrypt {
    my ($self, $rec) = @_;

    croak("decrypt requires a hash ref as argument")
      unless UNIVERSAL::isa($rec, 'HASH');
    my $data = $rec->{data};
    my $cat = $self->[0]->getCategory($rec->{category});
    my ($name, $raw) = split(/\000/, $data, 2);
    my $out = "";
    for ( my $j=0; $j<int(length($raw) / 8); $j++) {
	my $to = $self->[1]->decrypt( substr($raw,$j*8,8) );
	my $other = $self->[2]->encrypt($to);
	$to = $self->[1]->decrypt($other);
	$out .= $to;
    }
    my ($acc,$pass,$note,$x) = split(/\000/,$out,4);
    $note =~ s/\n+$// if $note;

    if ( $x && (my $packed_date = unpack("n", $x)) ) {
	my @tm = ((($packed_date & 0xFE00) >> 9) + 4,
		  (($packed_date & 0x01E0) >> 5) - 1,
		  ($packed_date & 0x001F),
		  0, 0, 0);
	$x = \@tm;
    }
    else {
	undef $x;
    }

    wantarray ? ($name,$cat,$acc,$pass,$note,$x) : [$name,$cat,$acc,$pass,$note,$x];
}

# Self-test. This requires the Keys-Gtkr.pdb that is in the tests
# directory.

unless ( caller ) {

    # Open the database.
    my $db = Palm::KeyRing->new("Keys-Gtkr.pdb");

    warn("Number of records = ", $db->getRecords, "\n");

    # Verify the password.
    my $decryptor = $db->getDecryptor("secret");
    die("Incorrect password") unless $decryptor;

    # Fetch first record:
    my $rec = $db->getRecord(1);
    # Or fetch a record by its name:
    $rec = $db->getRecordsByName("Bank",
				 1 << $db->getCategoryByName("Banking")
				)->[0];

    # Decrypt record.
    my ($name, $cat, $account, $password, $note, $x) =
      $decryptor->decode($rec);

    print("Name:     $name\n",
	  "Category: $cat\n",
	  "Account:  $account\n",
	  "Password: $password\n",
	  "Note:     $note\n",
	  "Modified: ", $x ? sprintf("%d-%02d-%02d",
				     1900 + $x->[0],
				     1 + $x->[1],
				     $x->[2]) : "", "\n",
	 );


}

1;
