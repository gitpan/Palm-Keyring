#!/usr/bin/perl

package Palm::KeyRing;

$VERSION = "0.90";

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

  # Fetch a decoder (verifies the password).
  my $decoder = $db->getDecoder("Secret PassPhrase");
  die("Incorrect password") unless $decoder;

  # Fetch record by number (first = 1).
  my $rec = $db->getRecord(1);
  # Or fetch record by name.
  $rec = $db->getRecordByName("BankAccount");
  # $rec->{data} contains the raw data.
  # $rec->{category} the category index.
  # $rec->{name} the name.
  # Decode record.
  my ($name, $category, $account, $password, $note) = $decoder->decode($rec);

=head1 DESCRIPTION

Palm::KeyRing provides a (currently read-only) interface to the
keyring files as used by the GNU KeyRing tool on Palm handhelds.

Records in the keyring file have 4 fields: name, account, password,
and note. All fields except name are encrypted.

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

=item getRecordByName

Takes one argument, a record name, and returns the corresponding
record. See getRecord above for the return values.

If no such record exists, returns undef.

=item getCategory

Takes one argument, a category index. Returns the category as a string.

=item getCategories

In list context, returns a list of categories. In scalar context
returns an array reference.

=item getDecoder

Takes one argument, the keyring password. If the password is correct,
it returns a decoder for this keyring. Otherwise, it returns undef.

The decoder provides one method: decode. This method takes one
argument, the record (as a hash ref). It returns a list (in scalar
context: array reference) of the record name, category_name, account,
password and note, all decrypted.

=head1 REQUIREMENTS

PDA::Pilot

Crypt::DES

=head1 DEMO PROGRAM

Palm::KeyRing comes with a nice GUI based demo program wxkeyring. This
program requires WxPerl 0.15 or later.

=head1 BUGS

Installs Palm::Raw as the default handler for Palm::PDB. This could
have side effects if the rest of the program also uses Palm::PDB.

=head1 AUTHOR

Johan Vromans E<lt>jv@cpan.orgE<gt>.

=head1 LICENCE

Artistic or GPL, whichever you prefer.

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
	$self->{recs}->{$name} = [$recno, $_->{category}];
	$recno++;
    }

    # Load the categories.
    $self->{categories} =
      [ unpack("xx".("A16"x16), $self->{db}->{appinfo}) ];

    # Return the object.
    bless($self, $pkg);
}

sub getDecoder {
    my ($self, $passwd) = @_;
    Palm::KeyRing::Decoder->_new
	($self, $self->{db}->{records}->[0]->{data}, $passwd);
}

sub getRecord {
    my ($self, $recno) = @_;
    return undef if $recno >= scalar(@{$self->{db}->{records}});
    $self->{db}->{records}->[$recno];
}

sub getRecordByName {
    my ($self, $name) = @_;
    return undef unless exists $self->{recs}->{$name};
    $self->getRecord($self->{recs}->{$name}->[0]);
}

sub getRecords {
    my ($self) = @_;
    scalar(@{$self->{db}->{records}})-1;
}

sub getNames {
    my ($self) = @_;
    my @names = keys(%{$self->{recs}});
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

package Palm::KeyRing::Decoder;

use Crypt::DES;
use Digest::MD5 qw(md5);

sub _new {
    my ($pkg, $super, $keyring0, $passwd) = @_;
    $pkg = ref($pkg) || $pkg;

    my $key = md5($passwd);
    my $c1 = new Crypt::DES substr($key,0,8);
    my $c2 = new Crypt::DES substr($key,8,8);

    my $msg = substr($keyring0,0,4).$passwd."\000" x 64;
    $msg = substr($msg,0,64);	# cut to 64 bytes
    my $digest = md5($msg);
    if ( substr($keyring0,4,length($digest)) eq $digest ) {
	return bless([$super, $c1, $c2], $pkg);
    }
    undef;
}

sub decode {
    my ($self, $rec) = @_;

    croak("decode requires a hash ref as argument")
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
    my ($acc,$pass,$note,undef) = split(/\000/,$out,4);
    $note =~ s/\n+$// if $note;

    wantarray ? ($name,$cat,$acc,$pass,$note) : [$name,$cat,$acc,$pass,$note];
}

# Self-test. This requires the Keys-Gtkr.pdb that is in the tests
# directory.

unless ( caller ) {

    # Open the database.
    my $db = Palm::KeyRing->new("Keys-Gtkr.pdb");

    warn("Number of records = ", $db->getRecords, "\n");

    # Verify the password.
    my $decoder = $db->getDecoder("secret");
    die("Incorrect password") unless $decoder;

    # Fetch first record:
    my $rec = $db->getRecord(1);
    # Or fetch a record by its name:
    $rec = $db->getRecordByName("Paypal");

    # Decode record.
    my ($name, $cat, $account, $password, $note) = $decoder->decode($rec);

    print("Name:     $name\n",
	  "Category: $cat\n",
	  "Account:  $account\n",
	  "Password: $password\n",
	  "Note:     $note\n");

}

1;
