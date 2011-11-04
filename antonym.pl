#!/usr/bin/perl -w

# $Id: antonym,v 1.4 2002/07/18 01:21:15 kirk Exp $

use strict;
use Getopt::Long;
use Digest::MD5;

######################################################################
#### Configuration                                                ####
######################################################################

# Command-line arguments, their types, and their defaults
my %opt_def = (
	       'alias=s'     => '',
	       'blockfile=s' => 'rb.asc',
	       'config=s'    => 'replyblocks.dat',
	       'ctype=s'     => 'pgp',
	       'dict=s'      => '/usr/share/dict/american-english',
	       'words=i'     => 5,
               'help!'       => 0,
               'showopts!'   => 0
	      );

my %opt;


## Global variables
my $block;
my $command;
my $file;
my @hops;
my %evblock;
my %nym;


######################################################################
#### Argument parsing                                             ####
######################################################################

#### Option handling

# Create the option hash
foreach my $key (keys %opt_def)
  {
    my $keyname = $key;
    $keyname =~ s/[!=].*$//;
    $opt{$keyname} = $opt_def{$key};
  }

my $optsuccess = GetOptions(\%opt, keys %opt_def);

if ($opt{'showopts'} or not $optsuccess or $opt{'help'})
  {
    print "Command line options:\n";
    foreach my $key (keys %opt)
      {
	print "    $key: $opt{$key}\n";
      }
    print "\n";
  }

exit if $opt{'help'};

unless ($optsuccess)
{
    showUsageAndExit();
    exit -1;
}


#### Command handling

if (@ARGV < 1)
{
    showUsageAndExit();
}

$command = shift @ARGV;

if ($command eq 'decrypt')
{
    $file = shift @ARGV;
}

# If there are any arguments left, then there was a usage error
if (@ARGV)
{
    showUsageAndExit();
}


######################################################################
#### Parse the configuration blocks                               ####
######################################################################

open INFILE, $opt{'config'} or die "Couldn't open the alias block file: $!";
$block = '';
while (defined ($_ = <INFILE>))
{
    $block .= $_;
}
close INFILE;
%evblock = eval '(' . $block . ');';


# The 'decrypt', 'create', and 'modify' commands all use the same configuration
# information, so calculate it once.

if ($command eq 'decrypt' or
    $command eq 'create' or
    $command eq 'modify')
{

# The 'decrypt' operation is slightly different from 'create' or
# 'modify' in that the appropriate alias is determined from the
# contents of the file to be decrypted rather than from the command
# line.  This way, incoming messages can be decrypted without
# additional user intervention.

    if ($command eq 'decrypt' and $opt{'alias'} eq '')
    {
	open INFILE, $file or die "Unable to read the input file: $!";
	my $fileSubject;
	while (defined ($_ = <INFILE>))
	{
	    next unless /^Subject:\s/;
	    chomp;
	    s/^Subject:\s*//;
	    s/\s*$//;
	    $fileSubject = $_;
	    last;
	}
	close INFILE;
	unless (defined $fileSubject)
	{
	    exitWithError("No Subject: line was found in the input file.");
	}

	foreach my $testAlias (keys %evblock)
	{
	    my @hops = @{$evblock{$testAlias}{'hops'}};
	    my $last = $hops[-1];
	    next unless (defined $$last{'subj'});
	    if ($$last{'subj'} eq $fileSubject)
	    {
		$opt{'alias'} = $testAlias;
		last;
	    }
	}
	if ($opt{'alias'} eq '')
	{
	    exitWithError("No reply block matches the message subject.");
	}
    }


    unless (defined ($evblock{$opt{'alias'}}))
    {
	exitWithError("Alias \"$opt{'alias'}\" is not configured.");
    }

    %nym  = %{$evblock{$opt{'alias'}}{'user'}};
    @hops = @{$evblock{$opt{'alias'}}{'hops'}};
}


######################################################################
#### Main processing                                              ####
######################################################################


########################################
#### Decrypt                        ####
########################################

if ($command eq 'decrypt')
{
    $ENV{'PGPPASSFD'} = 0;

    my $oldfile = $file;
    my $newfile = "$oldfile.strip";

    # Remove the email headers from the file before decryption
    open INFILE, $oldfile or die "Unable to read $oldfile: $!";
    open OUTFILE, "> $newfile" or die "Unable to write $newfile: $!";

    # Skip all of the headers
    while (defined ($_ = <INFILE>))
    {
	chomp;
	last if $_ eq '**';
    }

    # Now copy the remaining lines
    while (defined ($_ = <INFILE>))
    {
	print OUTFILE;
    }
    close OUTFILE;
    close INFILE;
    $oldfile = $newfile;

    while (defined (my $current = pop @hops))
    {
	$newfile = "$file-$$current{'addr'}.tmp";
	print "$$current{'addr'}\n";
	system "echo $$current{'pass'} | pgp +verbose=0 $oldfile -o $newfile";
	if ($oldfile ne $file)
	{
	    unlink $oldfile or die "Unable to unlink $oldfile: $!";
	}
	$oldfile = $newfile;
    }

    delete $ENV{'PGPPASSFD'};

    print "Oldfile: $oldfile\n";

    system "pgp +verbose=0 $oldfile -o $file.txt";
    unlink $oldfile or die "Unable to unlink $oldfile: $!";
    exit;
}


########################################
#### Create and modify              ####
########################################

if ($command eq 'create' or $command eq 'modify')
{
    my $public_key = getPubKey($nym{'fprint'});

    # Initialize the block-building algorithm
    my $next = pop @hops;
    my $message = mkheader($next);

    # Encrypt each of the reply blocks in turn
    while (defined (my $current = pop @hops))
    {
	print "Building the block $$current{'addr'} -> $$next{'addr'}\n";
	print "Encrypting to $$current{'addr'}...\n";
	$message = pgpDoAction($opt{'ctype'}, $message, 'encrypt_to', $$current{'addr'});
	$message = <<__EOHEADER__ . $message;
::
Encrypted: PGP

__EOHEADER__

        $message = mkheader($current) . $message;
	$next = $current;
    }

    foreach $_ ($command)
    {
	/^create$/ and do {
	    # Build a creation request
	    $message = <<__EOCREATEREQ__;
Config:
From: $nym{'id'}
Nym-Commands: create +acksend +fingerkey name="$nym{'full'}"
Public-Key:
$public_key
Reply-Block:
$message
**
__EOCREATEREQ__
            last;
	};
	/^modify$/ and do {
	    # Build a change request
	    $message = <<__EOCREATEREQ__;
Config:
From: $nym{'id'}
Reply-Block:
$message
**
__EOCREATEREQ__
            last;
	};
    }

    # Dump the penultimate message buffer to the screen for examination
    print "FINAL ==================\n";
    print $message;
    print "FINAL ==================\n";

    # Given the final message, encrypt it to the appropriate remailer.
    # Now the creation request is all ready for mailing!
    print "Signing and encrypting the creation request...\n";
    $message = pgpDoAction($opt{'ctype'}, $message, 'encrypt_sign_to', $nym{'mailer'});

    open OUTFILE, ">$opt{'blockfile'}" or die "Unable to write the reply block to a file: $!";
    print OUTFILE $message;
    close OUTFILE;
    exit;
}


########################################
#### Random password                ####
########################################

if ($command eq 'password')
{
    my $digest = Digest::MD5->new;
    for (my $i = 0; $i < 1024; $i++)
    {
	$digest->add(rand);
    }
    print $digest->hexdigest . "\n";
    exit;
}


########################################
#### Random phrase                  ####
########################################

if ($command eq 'phrase')
{
    # This algorithm courtesy of the Perl Cookbook
    open INFILE, $opt{'dict'} or die "Unable to read the dictionary file: $!";
    1 while <INFILE>;
    my $count = $.;
    close INFILE;

    my %list;
    for (my $i = 0; $i < $opt{'words'}; $i++)
    {
	$list{$i}{'number'} = int (rand $count);
    }

    open INFILE, $opt{'dict'} or die "Unable to read the dictionary file: $!";
    foreach my $index (sort { $list{$a}{'number'} <=> $list{$b}{'number'} } (keys %list))
    {
	while ($. < $list{$index}{'number'})
	{
	    $_ = <INFILE>;
	}
	chomp;
	$list{$index}{'word'} = $_;
    }
    close INFILE;

    foreach my $index (sort {$a <=> $b} (keys %list))
    {
	print "$list{$index}{'word'} ";
    }
    print "\n";
    exit;
}

exitWithError("The command \"$command\" is not valid.");




######################################################################
#### Support functions                                            ####
######################################################################

## Get the public key of the specified account
sub getPubKey
{
    my $fingerprint = shift;
    my $pk;

    # Extract the public key for later use
    if ($opt{'ctype'} eq 'gpg')
    {
	open INPIPE, "gpg -at --export '$fingerprint' |" or die "Unable to open the key export pipe: $!";
    }
    elsif ($opt{'ctype'} eq 'pgp')
    {
	open INPIPE, "pgp -fkxa '$fingerprint' |" or die "Unable to open the key export pipe: $!";
    }
    else
    {
	exitWithError("Unknown encryption type: $opt{'ctype'}");
    }

    while (defined ($_ = <INPIPE>))
    {
	$pk .= $_;
    }
    close INPIPE;
    chomp $pk;
    return $pk;
}


## Make a header for the specified hop
sub mkheader
{
    my $dest = shift;
    my $message = <<__EOHEADER__;
::
Anon-To: $$dest{'addr'}
__EOHEADER__

    $message .= "Latent-Time: $$dest{'ltnt'}\n" if $$dest{'ltnt'};

    $message .= <<__EOHEADER__;
Encrypt-Key: $$dest{'pass'}

__EOHEADER__

    if (defined $$dest{'subj'})	# Is this a Usenet gateway?
    {
	$message .= <<__EOUSENET__;
##
Subject: $$dest{'subj'}
Newsgroups: $$dest{'ngrp'}

__EOUSENET__
    }

    return $message;
}

## GPG version of _do_action
sub gpgDoAction
{
    my $message = shift;
    my $target = shift;
    my $action = shift || '--batch --encrypt';
    my $rnd_filename = '/tmp/antonym-temp-file';
    my $retval = '';

    # Write out the message buffer to a gpg encryption pipe
    #    my $gpg_syscmd = "gpg -at -r $target -u $nym{'fprint'} --output $rnd_filename --openpgp --comment '' $action";
    my $gpg_syscmd = "gpg -at -r $target -u $nym{'fprint'} --output $rnd_filename --comment '' $action";
    print "\$gpg_syscmd: $gpg_syscmd\n";
    open OUTPIPE, "| $gpg_syscmd" or die "Unable to open the output pipe: $!";
    print OUTPIPE $message;
    close OUTPIPE;

    # Slurp the output of the gpg command
    open INFILE, $rnd_filename or die "Unable to open the input file: $!";
    while (defined ($_ = <INFILE>))
    {
	$retval .= $_;
    }
    close INFILE;

    # Unlink the temp file or complain loudly!
    unlink $rnd_filename or die "Unable to remove the temporary file: $!\n";

    return $retval;
}

## PGP version of _do_action
sub pgpDoAction
{
    my $type = shift;
    my $message = shift;
    my $action = shift;
    my $target = shift;
    my $rnd_filename = '/tmp/mkreplyblock.pl-temp-file';
    my $retval = '';
    my $args = "-u '$nym{'fprint'}'";

    if ($action eq 'encrypt_to')
    {
	$args .= ' +batchmode -eat';
    }
    elsif ($action eq 'encrypt_sign_to')
    {
	$args .= ' -seat';
    }
    else
    {
	exitWithError("Unknown pgp action: $action");
    }

    # Write out the message buffer to a temp file
    open OUTFILE, ">$rnd_filename" or die "Unable to open the output file: $!";
    print OUTFILE $message;
    close OUTFILE;

    my $pgp_syscmd = "pgp $args $rnd_filename $target";
    print "----> $pgp_syscmd <----\n";
    system $pgp_syscmd;	     # or die "Unable to open syscmd pgp: $!";

    # Slurp the output of the gpg command
    open INFILE, "$rnd_filename.asc" or die "Unable to open the input file: $!";
    while (defined ($_ = <INFILE>))
    {
	$retval .= $_;
    }
    close INFILE;

    # Unlink the temp files or complain loudly!
    unlink $rnd_filename or die "Unable to remove the temporary file: $!\n";
    unlink "$rnd_filename.asc" or die "Unable to remove the temporary file: $!\n";

    return $retval;
}

## A quick help for users
sub showUsageAndExit
{
    print <<__EOHELP__;
Usage: $0 command [arguments]

Where alias is the name of the nym you wish to process, and command is one
of

    create    Create a new reply block.

    modify    Create a modification request block.

    decrypt filename
              Decrypt the contents of filename with the appropriate sequence.

    password  Generate a reasonably random password.

    phrase    Generate a string of random words.

Options:

    --alias   Identity of the alias to operate on.  For the "create" and
              "modify" commands, this is the alias to create a
              replyblock for.  The "decrypt" command will attempt to
              determine this value automatically, but may fail under
              some circumstances.

    --blockfile
              Name of the file to write for "create" and "modify" commands.
              (Default: $opt_def{'blockfile=s'})

    --config  Name of the file to read configuration information from.
	      (Default: $opt_def{'config=s'})

    --ctype   Encryptiong program to use.  Only 'pgp' is currently supported.
              (Default: $opt_def{'ctype=s'})

    --dict    Name of the dictionary file from with to pull random words
              for the "phrase" command. (Default: $opt_def{'dict=s'})

    --words   Length (in words) of the string generated with the "phrase" command.
              (Default: $opt_def{'words=i'})

__EOHELP__
    exit;
}

## Print a message then quit
sub exitWithError
{
    $_ = shift;
    print "Error: $_\n";
    exit;
}
