#!/usr/bin/perl

package Palm::KeyRing;

$VERSION = "0.01";

use strict;
use warnings;

use Carp;
use PDA::Pilot;

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

  # Decode record.
  my ($name, $account, $password, $note) = $decoder->decode($rec);

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

Loads all the records from the file in an internal cache (if
necessary), and returns the number of records read. Note that the
contents will not be decrypted.

=item getNames

Loads all the records from the file in an internal cache (if
neccessary), and returns a list (in scalar context: array reference)
of all names used in the keyring file.

=item getRecord

Takes one integer argument, a record number, and returns the record
data. The first data record is numbered 1.

If no such record exists, returns undef.

=item getRecordByName

Takes one argument, a record name, and returns the corresponding
record.

If no such record exists, returns undef.

=item getDecoder

Takes one argument, the keyring password. If the password is correct,
it returns a decoder for this keyring. Otherwise, it returns undef.

The decoder provides one method: decode. This method takes one
argument, the record data. It returns a list (in scalar context: array
reference) of the record name, account, password and note, all
decrypted.

=head1 REQUIREMENTS

PDA::Pilot

Crypt::DES

=head1 DEMO PROGRAM

Palm::KeyRing comes with a nice GUI based demo program wxkeyring. This
program requires WxPerl 0.15 or later.

=head1 BUGS

Currently does not handle categories.

=head1 AUTHOR

Johan Vromans E<lt>jv@cpan.orgE<gt>.

=cut

sub new {
    my ($pkg, $file, %args) = @_;
    $pkg = ref($pkg) || $pkg;
    my $self = {};

    croak("$file: $!\n") unless -f $file && -r $file;
    $self->{db} = PDA::Pilot::File::open($file);
    $self->{rec0} = $self->{db}->getRecord(0)->{raw};
    $self->{cacheptr} = 1;
    $self->{eof} = 0;
    $self->{filename} = $file;
    bless($self, $pkg);
}

sub getDecoder {
    my ($self, $passwd) = @_;
    Palm::KeyRing::Decoder->_new($self->{rec0}, $passwd);
}

sub getRecord {
    my ($self, $recno) = @_;
    my $r = $self->{db}->getRecord($recno);
    if ( defined $r ) {
	$r = $r->{raw};
	$r =~ /^(.+?)\000/s;
	my $name = $1;
	$self->{recs}->{$name} = $r if defined($name);
	# warn("Record: $recno => \"$name\"\n");
    }
    $r;
}

sub getRecordByName {
    my ($self, $name) = @_;
    return $self->{recs}->{$name} if exists $self->{recs}->{$name};
    return undef if $self->{eof};
    while ( defined($self->getRecord($self->{cacheptr}++)) ) {
	return $self->{recs}->{$name} if exists $self->{recs}->{$name};
    }
    $self->{eof} = 1;
    undef;
}

sub getRecords {
    my ($self) = @_;
    scalar(@{$self->getNames});
}

sub getNames {
    my ($self) = @_;
    while ( !$self->{eof}
	    && defined($self->getRecord($self->{cacheptr}++)) ) { }
    my @names = keys(%{$self->{recs}});
    wantarray ? @names : \@names;
}

package Palm::KeyRing::Decoder;

use Crypt::DES;
use Digest::MD5 qw(md5);

sub _new {
    my ($pkg, $keyring0, $passwd) = @_;
    $pkg = ref($pkg) || $pkg;

    my $key = md5($passwd);
    my $c1 = new Crypt::DES substr($key,0,8);
    my $c2 = new Crypt::DES substr($key,8,8);

    my $msg = substr($keyring0,0,4).$passwd."\000" x 64;
    $msg = substr($msg,0,64);	# cut to 64 bytes
    my $digest = md5($msg);
    if ( substr($keyring0,4,length($digest)) eq $digest ) {
	return bless([$c1, $c2], $pkg);
    }
    undef;
}

sub decode {
    my ($self, $data) = @_;

    my ($name, $raw) = split(/\000/, $data, 2);
    my $out = "";
    for ( my $j=0; $j<int(length($raw) / 8); $j++) {
	my $to = $self->[0]->decrypt( substr($raw,$j*8,8) );
	my $other = $self->[1]->encrypt($to);
	$to = $self->[0]->decrypt($other);
	$out .= $to;
    }
    my ($acc,$pass,$note,undef) = split(/\000/,$out,4);
    $note =~ s/\n+$// if $note;

    wantarray ? ($name,$acc,$pass,$note) : [$name,$acc,$pass,$note];
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
    my ($name, $account, $password, $note) = $decoder->decode($rec);

    print("Name:     $name\n",
	  "Account:  $account\n",
	  "Password: $password\n",
	  "Note:     $note\n");

}

1;
