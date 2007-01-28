# Makefile.PL for Palm::KeyRing.

use ExtUtils::MakeMaker;

my @scripts = qw (wxkeyring);
my $usrbin = "/usr/bin";
my $installscript = $Config{installscript};

print STDERR <<EOD unless $installscript eq $usrbin;

WARNING: This Makefile will install user accessible scripts.
The location for these scripts is $installscript.
You may consider to pass INSTALLSCRIPT=$usrbin (or some other
convenient location) to "make install".
EOD

print STDERR <<EOD;

IMPORTANT: The wxkeyring program requires WxPerl version 0.15 or later.

EOD


my %ctl = (
    NAME		=> 'Palm::KeyRing',
    VERSION_FROM	=> 'lib/Palm/KeyRing.pm',
    EXE_FILES           => [ map { "script/$_" } @scripts ],
    PREREQ_PM		=> {
	'Palm::PDB' => 0,
	'Palm::Raw' => 0,
        'Crypt::DES' => 0,
    },
);

if ( $] >= 5.005 ) {
    $ctl{ABSTRACT_FROM} = 'lib/Palm/KeyRing.pm';
    $ctl{AUTHOR}        = 'JV';
}

WriteMakefile(%ctl);
