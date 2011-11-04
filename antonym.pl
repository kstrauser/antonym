#!/usr/bin/perl -w

# Antonym - a Perl pseudonym management tool
# Copyright (C) 2002  Kirk Strauser

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# Also add information on how to contact you by electronic and paper
# mail.

# $Id: antonym,v 1.8 2002/08/06 16:35:04 kirk Exp $

# TODO:
#
#   Add support for:
#      Generating random reply blocks
#      Editing encrypted files (i.e. with a pipe to vi)

use strict;
use Getopt::Long;
use Digest::MD5;
use FileHandle;
use IPC::Open2;

######################################################################
#### Configuration                                                ####
######################################################################

# Command-line arguments, their types, and their defaults
my %opt_def = (
	       'alias=s'         => '',
	       'config=s'        => 'replyblocks.dat',
	       'ctype=s'         => 'pgp',
	       'dict=s'          => '/usr/share/dict/american-english',
	       'remailers=s'     => "$ENV{'HOME'}/.remailers",
	       'words=i'         => 5,
	       'rlist=s'         => 'finger:rlist@mixmaster.shinn.net',
	       'maxrlistage=i'   => 2,
	       'mailinformat=s'  => 'mbox',
	       'mailoutformat=s' => 'mbox',
	       'tmp=s'           => '/tmp',
	       'debug!'          => 0,
               'help!'           => 0,
               'showopts!'       => 0
	      );

# The filehandles that each command needs
my %handles = (
	       'nymcrypt' => { 'input'  => 'either',
			       'output' => 'either' },
	       'decrypt'  => { 'input'  => 'either',
			       'output' => 'either' },
	       'create'   => { 'output' => 'either' },
	       'modify'   => { 'output' => 'either' },
	       'remcrypt' => { 'input'  => 'stdin',
			       'output' => 'stdout' }
);

my %opt;

## Global variables
my $block;
my $command;
my $inputfile;
my $outputfile;
my @hops;
my %evblock;
my %nym;
my %remailer;
my %newsgate;
my %nymserver;

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

if ($opt{'showopts'} or not $optsuccess)
  {
    print "Command line options:\n";
    foreach my $key (sort (keys %opt))
      {
	print "    $key: $opt{$key}\n";
      }
    print "\n";
  }

if ($opt{'help'})
{
    showUsageAndExit();
    exit;
}

unless ($optsuccess)
{
    showUsageAndExit("Invalid options were specified");
}


#### Command handling

if (@ARGV < 1)
{
    showUsageAndExit("No command was specified");
}

$command = shift @ARGV;

# Get arguments for other commands
if ($command eq 'chainstat' or
    $command eq 'remcrypt')
{
    showUsageAndExit("No remailers were specified") if @ARGV < 1;
    @hops = @ARGV;
    @ARGV = ();
}

if ($command eq 'create' or
    $command eq 'modify' or
    $command eq 'validate')
{
    showUsageAndExit("No alias was specified") if @ARGV < 1;
    $opt{'alias'} = shift @ARGV;
}

# Bind the filehandles needed by each command
if (defined ($handles{$command}{'input'}))
{
    if ($handles{$command}{'input'} eq 'either' and @ARGV)
    {
	my $infilename = shift @ARGV;
	$inputfile = new FileHandle $infilename or exitWithError("Couldn't read the input file: $!");
    }
    else
    {
	$inputfile = *STDIN;
    }
}

if (defined ($handles{$command}{'output'}))
{
    if ($handles{$command}{'output'} eq 'either' and @ARGV)
    {
	my $outfilename = shift @ARGV;
	$outputfile = new FileHandle "> $outfilename" or
	    exitWithError("Couldn't write the output file: $!");
    }
    else
    {
	$outputfile = *STDOUT;
    }
}

# If there are any arguments left, then there was a usage error
if (@ARGV)
{
    showUsageAndExit("Too many arguments");
}

parseRemailers();


######################################################################
#### Parse the configuration blocks                               ####
######################################################################

open INFILE, $opt{'config'} or exitWithError("Couldn't open the alias block file: $!");
$block = '';
while (defined ($_ = <INFILE>))
{
    $block .= $_;
}
close INFILE;

if ($opt{'config'} =~ /\.pgp$/)
{
    $block = pgpDoAction('action'  => 'decrypt',
			 'message' => $block);
}

eval ($block) or exitWithError("Unable to evaluate the configuration file.");

# These commands all use the same configuration information, so
# calculate it once.

if ($command eq 'create' or
    $command eq 'decrypt' or
    $command eq 'modify')
{
    # The 'decrypt' operation is slightly different from 'create' or
    # 'modify' in that the appropriate alias is determined from the
    # contents of the file to be decrypted rather than from the
    # command line.  This way, incoming messages can be decrypted
    # without additional user intervention.

    if ($command eq 'decrypt' and $opt{'alias'} eq '')
    {
	# open INFILE, $inputfile or exitWithError("Unable to read the input file: $!");
	my $fileSubject;
	while (defined ($_ = <$inputfile>))
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

	# Find the name of the alias to use by examining each of the
	# configured reply blocks
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


############################################################
#### Calculate a chain's stats                          ####
############################################################

if ($command eq 'chainstat')
{
    my $prob = 1.0;
    my $latency = 0;
    my $count = 0;

    print <<__EOHD__;
                    this hop           cumulative
##  remailer    latency     prob    latency     prob
--  --------   --------  -------   --------  -------
__EOHD__

    foreach my $hop (@hops)
    {
	unless (defined ($remailer{$hop}))
	{
	    exitWithError("Unknown remailer \"$hop\"");
	}
	$count++;
	my $hopprob = $remailer{$hop}{'uptime'};
	$hopprob =~ s/\%$//;
	$prob = $prob * $hopprob / 100.0;
	my $hoplatency = $remailer{$hop}{'latency'};
	my ($hours, $minutes, $seconds) = (split /:/, $hoplatency);
	$latency += $hours * 3600 + $minutes * 60 + $seconds;

	printf "%2d  %-8s  %9s  %6.2f%%  %9s  %6.2f%%\n",
	    $count,
	    $hop,
            $hoplatency,
            $hopprob,
            formatTime($latency),
            $prob * 100;
    }

    print "\n";
    printf "Probability of success: %2.2f%%\n", $prob * 100;
    printf "Expected latency      : %s\n", formatTime($latency);

    exit;
}


############################################################
#### Decrypt                                            ####
############################################################

if ($command eq 'decrypt')
{
    my $message = '';
    $message .= $_ while defined ($_ = <$inputfile>);
    close $inputfile;

    while (defined (my $current = pop @hops))
    {
	$message = pgpDoAction('action'  => 'decrypt',
			       'pass'    => $$current{'pass'},
			       'message' => $message);
    }

    delete $ENV{'PGPPASSFD'};

    $message = pgpDoAction('action'  => 'decrypt',
			   'message' => $message);

    select $outputfile;
    print $message;
    close INPIPE;
    close $outputfile;

    exit;
}


############################################################
#### Create and modify                                  ####
############################################################


if ($command eq 'create' or $command eq 'modify')
{
    my $public_key = getPubKey($nym{'fprint'});

    # Initialize the block-building algorithm
    my $next = pop @hops;
    my $message = mkHeader($next);

    debug(<<__EOHD__);

######################################################################
######################################################################
$message
######################################################################
######################################################################

__EOHD__

    # Encrypt each of the reply blocks in turn
    while (defined (my $current = pop @hops))
    {
	my $destination;
	unless (defined ($destination = resolveAddr($$current{'addr'})))
	{
	    exitWithError("Unknown remailer: $$current{'addr'}");
	}
	debug("Building the block $$current{'addr'} -> $$next{'addr'}");
	debug("Encrypting to $$current{'addr'}...");
	$message = pgpDoAction('message' => $message,
			       'action'  => 'encrypt_to',
			       'to'      => $destination);
	$message = <<__EOHEADER__;
::
Encrypted: PGP

$message
**
__EOHEADER__

        $message = mkHeader($current) . $message;
	$next = $current;

    debug(<<__EOHD__);

######################################################################
######################################################################
$message
######################################################################
######################################################################

__EOHD__

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
__EOCREATEREQ__
            last;
	};
    }

    # Dump the penultimate message buffer to the screen for examination
    debug("FINAL ==================");
    debug($message);
    debug("FINAL ==================");

    # Given the final message, encrypt it to the appropriate remailer.
    # Now the creation request is all ready for mailing!
    debug("Signing and encrypting the creation request...");
    $message = pgpDoAction('message' => $message,
			   'action'  => 'encrypt_sign_to',
			   'to'      => $nymserver{$nym{'nymserver'}}{'config'},
			   'from'    => $nym{'fprint'});

    select $outputfile;
    print writeMailFile('recipient' => $nymserver{$nym{'nymserver'}}{'config'},
			'message'   => $message,
			'format'    => $opt{'mailoutformat'});
    exit;
}


############################################################
#### Random password                                    ####
############################################################

if ($command eq 'password')
{
    print mkRandString() . "\n";
    exit;
}


############################################################
#### Random phrase                                      ####
############################################################

if ($command eq 'phrase')
{
    # This algorithm courtesy of the Perl Cookbook
    open INFILE, $opt{'dict'} or exitWithError("Unable to read the dictionary file: $!");
    1 while <INFILE>;
    my $count = $.;
    close INFILE;

    my %list;
    for (my $i = 0; $i < $opt{'words'}; $i++)
    {
	$list{$i}{'number'} = int (rand $count);
    }

    open INFILE, $opt{'dict'} or exitWithError("Unable to read the dictionary file: $!");
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

    $list{0}{'word'} = capitalize($list{0}{'word'});

    foreach my $index (sort {$a <=> $b} (keys %list))
    {
	print "$list{$index}{'word'} ";
    }
    print "\n";
    exit;
}


############################################################
#### Encrypt a file for sending                         ####
############################################################

if ($command eq 'nymcrypt')
{
    my %maildata = readMailFile($inputfile, $opt{'mailinformat'});

    #### Verify that all required parts are present

    # Check the sender
    if ($opt{'alias'} eq '')
    {
	if ($maildata{'from'} eq '')
	{
	    exitWithError("No alias was specified or found.");
	}
	else
	{
	    $opt{'alias'} = $maildata{'from'};
	}
    }
    unless (defined ($evblock{$opt{'alias'}}))
    {
	exitWithError("Unknown alias \"$opt{'alias'}\"");
    }

    # Check that at least one recipient is defined
    unless ($maildata{'recipient'} ne '' or $maildata{'newsgroups'} ne '')
    {
	exitWithError("No recipient address or newsgroups were specified.");
    }

    # Check that no more than one recipient is defined
    if ($maildata{'recipient'} ne '' and $maildata{'newsgroups'} ne '')
    {
	exitWithError("Only an email address *or* a list of newsgroups may be specified.");
    }

    # See if the message has any content.  This may not actually be an
    # error, but we should warn the user anyway.
    if ($maildata{'message'} eq '')
    {
	warnButContinue("No message body was found.");
    }


    #### Generate the body of the message to be encrypted
    %nym  = %{$evblock{$opt{'alias'}}{'user'}};

    my $buffer = "From: $opt{'alias'}\n";

    if ($maildata{'recipient'} ne '')
    {
	$buffer .= "To: $maildata{'recipient'}\n";
	if ($maildata{'cc'} ne '')
	{
	    $buffer .= "Cc: $maildata{'cc'}\n";
	}
    }
    elsif ($maildata{'newsgroups'} ne '')
    {
	$buffer .= "To: " . resolveAddr($nym{'newsgate'}) . "\n";
	$buffer .= "Newsgroups: $maildata{'newsgroups'}\n";
    }

    if ($maildata{'refs'} ne '')
    {
	$buffer .= "References: $maildata{'refs'}\n";
    }

    $buffer .= "Subject: $maildata{'subject'}\n";
    $buffer .= "\n$maildata{'message'}";

    debug("####################\n$buffer\n####################");

    ## Encrypt the message
    $maildata{'message'} = pgpDoAction('message' => $buffer,
				       'action'  => 'encrypt_sign_to',
				       'to'      => $nymserver{$nym{'nymserver'}}{'send'},
				       'from'    => $nym{'fprint'});

    my $subject = mkRandString();

    select $outputfile;
    print writeMailFile('recipient' => $nymserver{$nym{'nymserver'}}{'send'},
			'subject'   => $subject,
			'message'   => $maildata{'message'},
			'format'    => $opt{'mailoutformat'});
    exit;
}


############################################################
#### List remailing services                            ####
############################################################

if ($command eq 'list')
{
    print "Remailers\n";
    print "############################################################\n";
    print "\n";

    foreach my $name (sort { $remailer{$a}{'index'} <=> $remailer{$b}{'index'} } (keys %remailer))
    {
	print <<__EOHD__;
$name:
    Address: $remailer{$name}{'address'}
    Index  : $remailer{$name}{'index'}
    Uptime : $remailer{$name}{'uptime'}
    Latency: $remailer{$name}{'latency'}
__EOHD__

	print "    Caps   : " . join (', ', (keys %{$remailer{$name}{'caps'}})) . "\n";
	print "\n";
    }

    print "\n";
    print "mail2news gateways\n";
    print "############################################################\n";
    print "\n";

    foreach my $name (sort (keys %newsgate))
    {
	print "$name\n";
	print "    $newsgate{$name}\n";
	print "\n";
    }

    print "\n";
    print "Nymservers\n";
    print "############################################################\n";
    print "\n";

    foreach my $name (sort (keys %nymserver))
    {
	print "$name\n";
    }

    exit;
}


############################################################
#### Encrypt to a chain of remailers                    ####
############################################################

if ($command eq 'remcrypt')
{
    my %parsedinfo = readMailFile($inputfile, $opt{'mailinformat'});
    my %maildata = (
		    'format'    => 'mbox',
		    'message'   => $parsedinfo{'message'},
		    'recipient' => resolveAddr($parsedinfo{'recipient'})
		   );

    foreach my $key ('message', 'recipient')
    {
	$maildata{$key} = $parsedinfo{$key};
	if ($maildata{$key} eq '')
	{
	    exitWithError("Mandatory field \"$key\" is not defined.");
	}
    }

    unless (defined ($maildata{'recipient'} = resolveAddr($parsedinfo{'recipient'})))
    {
	exitWithError("Unknown recipient: $parsedinfo{'recipient'}");
    }

    # Copy *only* the parameters we want from %parsedinfo to %maildata
    foreach my $key ('newsgroups', 'subject', 'cc', 'refs')
    {
	if ($parsedinfo{$key} ne '')
	{
	    $maildata{'headers'}{$key} = $parsedinfo{$key};
	}
    }

    # Now, remove the ability to output sensitive information
    undef %parsedinfo;

    my $message = <<__EOHD__;
::
Anon-To: $maildata{'recipient'}

__EOHD__

    # Copy additional headers from the original message
    if (keys %{$maildata{'headers'}})
    {
	$message .= "##\n";
	foreach my $key (keys %{$maildata{'headers'}})
	{
	    $message .= capitalize($key) . ": $maildata{'headers'}{$key}\n";
	}
	$message .= "\n";
    }

    $message .= $maildata{'message'};

    while (defined (my $hop = shift @hops))
    {
	my $destination;
	unless (defined ($destination = resolveAddr($hop)))
	{
	    exitWithError("Unknown remailer: $hop");
	}
	$message = pgpDoAction('message' => $message,
			       'action'  => 'encrypt_to',
			       'to'      => $destination);

	if (@hops)
	{
	    $message = <<__EOHD__;
::
Anon-To: $destination

::
Encrypted: PGP

$message
__EOHD__
	}
	else
	{
	    $message = <<__EOHD__;
To: $destination

::
Encrypted: PGP

$message
__EOHD__
	}
    }

    print $message;

    exit;
}


############################################################
#### Update the remailers file                          ####
############################################################

if ($command eq 'update')
{
    updateRemailers();
    exit;
}


############################################################
#### Validate the hops in a reply block                 ####
############################################################

if ($command eq 'validate')
{
    my @aliases;
    my $alias;
    my $pass = 0;

    if ($opt{'alias'} eq 'all')
    {
	foreach my $alias (keys %evblock)
	{
	    push @aliases, $alias;
	}
    }
    else
    {
	push @aliases, $opt{'alias'};
    }

    foreach $alias (@aliases)
    {
	my @hops = @{$evblock{$alias}{'hops'}};
	my $fatal = 0;
	my $warn = 0;

	print "\nAlias: $alias\n";
	print "----------------------------------------\n";

	foreach my $hop (@hops)
	{
	    print "Hop: $$hop{'addr'}\n";
	    if (defined (my $addr = resolveAddr($$hop{'addr'})))
	    {
		print "    Address: $addr\n";
	    }
	    else
	    {
		print "    FATAL: The address is not resolvable!\n";
		$fatal++;
	    }
	    if (defined ($$hop{'pass'}))
	    {
		print "    A password is set.\n";
	    }
	    else
	    {
		print "    WARNING: No password is set!\n";
		$warn++;
	    }
	    print "\n";
	}

	if ($fatal or $warn)
	{
	    print "There were $fatal fatal errors and $warn warnings.\n";
	}
	else
	{
	    print "This replyblock seems valid.\n";
	    $pass++;
	}
	print "\n";
    }

    print "Passed: $pass\n";
    print "Failed: " . (@aliases - $pass) . "\n";

    exit;
}


exitWithError("The command \"$command\" is not valid.");




######################################################################
#### Support functions                                            ####
######################################################################

########################################
# Encryption management                #
########################################

## Get the public key of the specified account
sub getPubKey
{
    my $fingerprint = shift;
    my $pk;

    debug("Getting pubkey for $fingerprint");

    # Extract the public key for later use
    if ($opt{'ctype'} eq 'gpg')
    {
	open INPIPE, "gpg -at --export '$fingerprint' |" or exitWithError("Unable to open the key export pipe: $!");
    }
    elsif ($opt{'ctype'} eq 'pgp')
    {
	open INPIPE, "pgp -fkxa '$fingerprint' |" or exitWithError("Unable to open the key export pipe: $!");
    }
    elsif ($opt{'ctype'} eq 'pgp6')
    {
	my $fname = "$opt{'tmp'}/" . mkRandString() . '.asc';
	system "pgp -kxa '$fingerprint' $fname";
	open INFILE, $fname or exitWithError("Unable to open the key export file: $!");
	$pk .= $_ while defined ($_ = <INFILE>);
	close INFILE;
	unlink $fname or exitWithError("Unable to delete the key export file: $!");
	chomp $pk;
	return $pk;
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

## GPG version of _do_action
sub gpgDoAction
{
    my $message = shift;
    my $target = shift;
    my $action = shift || '--batch --encrypt';
    my $rnd_filename = "$opt{'temp'}/antonym-temp-file";
    my $retval = '';

    # Write out the message buffer to a gpg encryption pipe
    #    my $gpg_syscmd = "gpg -at -r $target -u $nym{'fprint'} --output $rnd_filename --openpgp --comment '' $action";
    my $gpg_syscmd = "gpg -at -r $target -u $nym{'fprint'} --output $rnd_filename --comment '' $action";
    debug("\$gpg_syscmd: $gpg_syscmd");
    open OUTPIPE, "| $gpg_syscmd" or exitWithError("Unable to open the output pipe: $!");
    print OUTPIPE $message;
    close OUTPIPE;

    # Slurp the output of the gpg command
    open INFILE, $rnd_filename or exitWithError("Unable to open the input file: $!");
    while (defined ($_ = <INFILE>))
    {
	$retval .= $_;
    }
    close INFILE;

    # Unlink the temp file or complain loudly!
    unlink $rnd_filename or exitWithError("Unable to remove the temporary file: $!\n");

    return $retval;
}

## PGP version of _do_action
sub pgpDoAction
{
    my %params = @_;
    my $retval = '';
    my $pgp_syscmd;

    if ($params{'action'} eq 'encrypt_to')
    {
	$pgp_syscmd = "pgp -feat '$params{'to'}'";
    }
    elsif ($params{'action'} eq 'encrypt_sign_to')
    {
	$pgp_syscmd = "pgp -u '$params{'from'}' -seatf '$params{'to'}'";
    }
    elsif ($params{'action'} eq 'decrypt')
    {
	$pgp_syscmd = "pgp -f";
    }
    else
    {
	exitWithError("Unknown pgp action: $params{'action'}");
    }

    # Tell pgp to accept the password from STDIN if one is given
    if (defined ($params{'pass'}))
    {
	$ENV{'PGPPASSFD'} = 0;
    }

    if ($opt{'debug'})
    {
	my $out = "\n########################################\npgpDoAction:\n";
	foreach my $key (keys %params)
	{
	    next if $key eq 'message';
	    $out .= "    $key: $params{$key}\n";
	}
	$out .= "    Command line: $pgp_syscmd\n";
	$out .= "Message:\nvvvvvvvvvvvvvvvvvvvv\n$params{'message'}^^^^^^^^^^^^^^^^^^^^\n";
	$out .= "########################################\n";
	debug($out);
    }

    my $pid = open2( \*INPIPE, \*OUTPIPE, $pgp_syscmd);
    if (defined ($params{'pass'}))
    {
	print OUTPIPE "$params{'pass'}\n";
    }
    if (defined ($params{'message'}))
    {
	print OUTPIPE $params{'message'};
    }
    # Closing this handle will force PGP to process the data
    close OUTPIPE;
    $retval .= $_ while (defined ($_ = <INPIPE>));
    close INPIPE;

    if (defined ($params{'pass'}))
    {
	# This can have nasty side effects, such as swallowing the
	# first line of an input buffer, if left set
	delete $ENV{'PGPPASSFD'};
    }

    debug("Leaving pgpDoAction");

    return $retval;
}


## Generate a somewhat random string
sub mkRandString
{
    my $digest = Digest::MD5->new;
    for (my $i = 0; $i < 1024; $i++)
    {
	$digest->add(rand);
    }
    return $digest->hexdigest;
}


########################################
# Misc. message processing             #
########################################

## Make a header for the specified hop
sub mkHeader
{
    my $dest = shift;
    my $destinationAddr;

    unless (defined ($destinationAddr = resolveAddr($$dest{'addr'})))
    {
	exitWithError("Tried to encrypt to an unknown address: \"$$dest{'addr'}\"");
    }

    my $message = <<__EOHEADER__;
::
Anon-To: $destinationAddr
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

sub capitalize
{
    my $string = shift;
    my $option = shift || 'one';

    if ($option eq 'one')
    {
	$string =~ s/(\w+)/\u\L$1/;
    }
    else
    {
	$string =~ s/(\w+)/\u\L$1/g;
    }
    return $string;
}

## Format a time in seconds as HH:MM:SS
sub formatTime
{
    my $time = shift;

    my ($hours, $minutes, $seconds);

    $seconds = $time % 60;
    $time = ($time - $seconds) / 60;
    $minutes = $time % 60;
    $hours = ($time - $minutes) / 60;

    return sprintf ("%d:%02d:%02d", $hours, $minutes, $seconds);
}

########################################
# Configuration assistants             #
########################################

## Read a .remailers file for interesting information
sub parseRemailers
{
    my $inline;
    my $index = 0;

    # Fetch the user's remailers file if necessary
    if (not -e $opt{'remailers'} or
	 time - (stat $opt{'remailers'})[9] > $opt{'maxrlistage'} * 86400)
    {
	updateRemailers();
    }

    open INFILE, $opt{'remailers'} or exitWithError("Unable to read $opt{'remailers'}: $!");
    while (defined ($inline = <INFILE>))
    {
	chomp $inline;
	next if $inline eq '';

	# Handle remailer capability lines
	if ($inline =~ /^\$remailer/)
	{
	    my ($name, $info) = (split /\s=\s/, $inline)[0,1];
	    $name =~ s/^\$remailer{"(.*)"}/$1/;
	    $info =~ s/^"(.*)";/$1/;
	    my ($address, $caps) = (split /\s+/, $info, 2)[0,1];
	    $address =~ s/^\<(.*)\>$/$1/;
	    $remailer{$name}{'address'} = $address;
	    foreach $_ (split /\s+/, $caps)
	    {
		$remailer{$name}{'caps'}{$_} = 1;
	    }
	    next;
	}

	my ($name) = (split /\s+/, $inline)[0];
	next unless defined $remailer{$name};

	$index++;
	my ($address, $latency, $uptime);
	($name, $address, $latency, $uptime) = (split /\s+/, $inline)[0,1,-2,-1];

	# Validate email addresses.  Use a regexp match instead of a
	# string comparison because the value in the reliability table
	# may be truncated.
	unless ($remailer{$name}{'address'} =~ /^$address/)
	{
	    warnButContinue("Conflicting addresses in $name: \"$remailer{$name}{'address'}\" and \"$address\"");
	}
	$remailer{$name}{'latency'} = $latency;
	$remailer{$name}{'uptime'} = $uptime;
	$remailer{$name}{'index'} = $index;
    }

    # Finally, remove all remailers that don't offer cpunk services.
    foreach my $name (keys %remailer)
    {
	delete $remailer{$name} unless defined $remailer{$name}{'caps'}{'cpunk'};
    }
}

## Convert an address name into an email address, a remailer, or a
## newsgate
sub resolveAddr
{
    my $addr = shift;

    # Get the destination email address.  If addr contains an '@'
    # symbol, then use its value for the address.
    if ($addr =~ /\@/)
    {
	return $addr;
    }
    # Otherwise, if addr is the name of a defined remailer, then use
    # that remailer's address.
    elsif (defined ($remailer{$addr}))
    {
	return $remailer{$addr}{'address'};
    }
    # Finally, if addr is the name of a mail2news gateway, then use
    # the gateway's addrses.
    elsif (defined ($newsgate{$addr}))
    {
	return $newsgate{$addr};
    }
    return undef;
}

## A quick help for users
sub showUsageAndExit
{
    my $error;

    if (defined ($error = shift))
    {
	print "Error: $error\n\n";
    }

    print <<__EOHELP__;
Usage: $0 command [arguments]

Where alias is the name of the nym you wish to process, and command is one
of

    chainstat hop1 [hop2]...
              Calculate the probably latency and reliability of a chain of
              named remailers.

    create alias [filename]
              Create a new reply block.

    modify alias [filename]
             Create a modification request block.

    decrypt [input file] [output file]
              Decrypt the input data with the appropriate sequence.

    list      Get a list of defined remailers, mail2news gateways, and
              nymservers.

    nymcrypt [input file] [output file]
              Encrypt a file (in email format) for delivery to the
              appropriate nymserver.

    password  Generate a reasonably random password.

    phrase    Generate a string of random words.

    remcrypt hop1 [hop2]...
              Accept an email message on STDIN and encrypt it for delivery for
              each of the listed hops in turn.  Output is to STDOUT.

    update    Force an update of the remailers file

    validate alias|"all"
              Verify the that all of the hops in an alias' reply block are
              defined.

Options:

    --alias   Identity of the alias to operate on.  This is mainly
              needed for the "decrypt" and "nymcrypt" commands, which
              will attempt to determine this value automatically but
              may fail under some circumstances.

    --config  Name of the file to read configuration information from.
	      (Default: $opt_def{'config=s'})

    --ctype   Encryptiong program to use.  Current options are 'pgp' and 'pgp6'.
              (Default: $opt_def{'ctype=s'})

    --dict    Name of the dictionary file from with to pull random words
              for the "phrase" command. (Default: $opt_def{'dict=s'})

    --debug   Toggle the printing of debugging information (Default: $opt_def{'debug!'})

    --mailinformat
              Specify the expected file format for reading in mail data.
              'gnus' and 'mbox' are currently supported.  (Default: $opt_def{'mailinformat=s'})

    --mailoutformat
              Specify the format for writing mail messages.  'gnus' and 'mbox' are
              currently supported.  (Default: $opt_def{'mailinformat=s'})

    --maxrlistage
              The maximum acceptable age (in days) of the local remailer information file.
              If the file is older than this value, then antonym will attempt to fetch
              a more recent version.  (Default: $opt_def{'maxrlistage=i'})

    --remailers
              The name of the file that contains current (see --maxrlistage) information
              about anonymous remailers.  (Default: $opt_def{'remailers=s'})

    --rlist   The location (presumably on the Internet) of a remailer information
              file, and the method used to fetch it.  The only method currently
              supported is 'finger'.  (Default: $opt_def{'rlist=s'})

    --tmp     The path of a directory to use for writing temporary files (Default: $opt_def{'tmp=s'})

    --words   Length (in words) of the string generated with the "phrase" command.
              (Default: $opt_def{'words=i'})

__EOHELP__
    exit;
}


########################################
# Error handling                       #
########################################

## These functions are pretty trivial.  However, by defining this
## functionality in one place in the program, it would be easy to swap
## in a different reporting backend.  For example, these messages
## could be send to syslog, email, MySQL, a carrier pigeon, or
## whatever else.

## Print a debugging message if debugging is turned on
sub debug
{
    $_ = shift;
    return unless $opt{'debug'};
    print STDERR "DEBUG: $_\n";
}

## Print a message then quit
sub exitWithError
{
    $_ = shift;
    print STDERR "ERROR: $_\n";
    exit;
}

## Print a warning, but continue
sub warnButContinue
{
    $_ = shift;
    print STDERR "WARNING: $_\n";
}


## File I/O
sub readMailFile
{
    my $fh = shift;
    my $format = shift;

    my %header = (
		  recipient => '',
		  cc        => '',
		  subject   => '',
		  refs      => '',
		  message   => '',
		  from      => '',
		  groups    => ''
		 );

    if ($format eq 'gnus' or $format eq 'mbox')
    {
	my $sep;
	if ($format eq 'gnus')
	{
	    $sep = '--text follows this line--';
	}
	elsif ($format eq 'mbox')
	{
	    $sep = '';
	}

	# open INFILE, $inputfile or exitWithError("Unable to read the input file: $!");
	my $state = 0;

	# Deconstruct the message to get the information we're
	# interested in and throw away the rest.
	while (defined ($_ = <$fh>))
	{
	    chomp;

	    # State 0: Inside the main part of the header
	    if ($state == 0)
	    {
		if (/^To:\s/)
		{
		    s/^To:\s//;
		    $header{'recipient'} = $_;
		}
		elsif (/^Subject:\s/)
		{
		    s/^Subject:\s//;
		    $header{'subject'} = $_;
		}
		elsif (/^From:\s/)
		{
		    s/^From:\s//;
		    $header{'from'} = $_;
		}
		elsif (/^Newsgroups:\s/)
		{
		    s/^Newsgroups:\s//;
		    $header{'newsgroups'} = $_;
		}
		elsif (/^References:\s/)
		{
		    s/^References:\s//;
		    $header{'refs'} = $_;
		    $state = 1;
		}
		elsif (/^Cc:\s/)
		{
		    s/^Cc:\s//;
		    $header{'cc'} = $_;
		    $state = 2;
		}
		elsif ($_ eq $sep)
		{
		    $state = 3;
		}
		next;
	    }

	    # State 1: Inside the references section
	    if ($state == 1)
	    {
		if (/^\s+/)
		{
		    $header{'refs'} .= "\n$_";
		}
		elsif ($_ eq $sep)
		{
		    $state = 3;
		}
		else
		{
		    $state = 0;
		    redo;
		}
		next;
	    }

	    # State 2: Inside the cc section
	    if ($state == 2)
	    {
		if (/^\s+/)
		{
		    $header{'cc'} .= "\n$_";
		}
		elsif ($_ eq $sep)
		{
		    $state = 3;
		}
		else
		{
		    $header{'state'} = 0;
		    redo;
		}
		next;
	    }

	    # State 3: Inside the message
	    if ($state == 3)
	    {
		$header{'message'} .= "$_\n";
		next;
	    }
	}

	chomp $header{'message'};

	# close INFILE;
    }
    # End gnus-specific code

    return %header;
}

sub updateRemailers
{
    debug("Fetching remailer keys");
    my ($method, $source) = (split /\:/, $opt{'rlist'})[0, 1];
    if ($method eq 'finger')
    {
	system "finger $source > $opt{'remailers'}";
    }
}

sub writeMailFile
{
    my %maildata = @_;

    my $message = '';

    if (defined ($maildata{'recipient'}))
    {
	$message .= "To: $maildata{'recipient'}\n";
    }
    elsif (defined ($maildata{'anon-to'}))
    {
	$message .= "Anon-To: $maildata{'anon-to'}\n";
    }

    foreach my $key ('from', 'subject', 'cc', 'refs')
    {
	if (defined ($maildata{$key}))
	{
	    $message .= capitalize($key) . ": $maildata{$key}\n";
	}
    }

    if ($maildata{'format'} eq 'gnus')
    {
	$message .= "--text follows this line--\n";
    }
    elsif ($maildata{'format'} eq 'mbox')
    {
	$message .= "\n";
    }
    else
    {
	exitWithError("Unknown output format: $maildata{'format'}");
    }

    $message .= $maildata{'message'};

    return $message;
}
