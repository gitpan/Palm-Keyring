# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

my $test = 1;
BEGIN { $| = 1; print "1..20\n"; }
END {print "not ok $test\n" unless $loaded;}
use Palm::PDB;
use Palm::Keyring;
$loaded = 1;
print "ok $test\n";
$test++;

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $file = 'Keys-GTKR-test.pdb';
my $password = '12345';
my $new_password = '54321';
my $acct = {
    name        => 'test3',
	account     => 'atestaccount',
	password    => $password,
	notes       => 'now that really roxorZ!',
    lastchange  => {
        day   =>  2,
        month =>  2,
        year  => 99,
    },
};

my $pdb;
my $record;

eval { $pdb = new Palm::Keyring($password) };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $record = $pdb->append_Record() };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $pdb->Encrypt($record, $acct, $password) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $pdb->Write($file) };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

$pdb = new Palm::PDB;
$acct = {};

eval { $pdb->Load($file) };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $pdb->Password($password) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $acct = $pdb->Decrypt($pdb->{'records'}->[1]) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

if ($acct->{'password'} eq $password) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

my $old_date = $acct->{'lastchange'};

eval { $pdb->Password($password, $new_password) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

$acct = {};
eval { $acct = $pdb->Decrypt($pdb->{'records'}->[1]) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

if ($acct->{'password'} eq $password) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

my $new_date = $acct->{'lastchange'};

if (
    $old_date->{'day'}   == $new_date->{'day'}   &&
    $old_date->{'month'} == $new_date->{'month'} &&
    $old_date->{'year'}  == $new_date->{'year'}
) {
    print "ok $test\n";
} else {
    print "not ok $test\n";
}
$test++;

$acct->{'password'} = $new_password;

eval { $acct = $pdb->Encrypt($pdb->{'records'}->[1], $acct) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

$old_date = $new_date;
$new_date = $acct->{'lastchange'};

eval { $acct = $pdb->Decrypt($pdb->{'records'}->[1]) || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

if (
    $old_date->{'day'}   != $new_date->{'day'}   ||
    $old_date->{'month'} != $new_date->{'month'} ||
    $old_date->{'year'}  != $new_date->{'year'}
) {
    print "ok $test\n";
} else {
    print "not ok $test\n";
}
$test++;

if ($acct->{'password'} eq $new_password) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $pdb->Password() || die };
unless( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

eval { $acct = $pdb->Decrypt($pdb->{'records'}->[1]) || die };
if ( $@ ) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;

unless ($acct->{'password'} eq $password) {
	print "ok $test\n";
} else {
	print "not ok $test\n";
}
$test++;


unlink($file);

1;

