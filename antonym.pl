#!/usr/bin/perl -w

# $Id: antonym 79 2004-05-03 18:20:33Z kirk $

# Antonym - a Perl pseudonym management tool
# Copyright (C) 2004  Kirk Strauser

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

# The author may be contacted by email at kirk@strauser.com

# TODO:
#
#   Add support for:
#      Editing encrypted files (i.e. with a pipe to vi)

use strict;
use Digest::MD5;
use FileHandle;
use Getopt::Long;
use IPC::Open2;
use UNIVERSAL;

######################################################################
#### Configuration                                                ####
######################################################################

# Command-line arguments, their types, and their defaults
my %opt_def = (
	       'alias=s'         => '',
	       'config=s'        => 'replyblocks.dat',
	       'ctype=s'         => 'pgp',
	       'dict=s'          => '/usr/share/dict/american-english-large',
	       'remailers=s'     => "$ENV{'HOME'}/.remailers",
	       'words=i'         => 5,
	       'rlist=s'         => 'http://mixmaster.shinn.net/stats/rlist',
	       'maxrlistage=i'   => 1,
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
	       'delete'   => { 'output' => 'either' },
	       'remcrypt' => { 'input'  => 'stdin',
			       'output' => 'stdout' }
);

my %opt;

## Global variables
my $block;
my $command;
my $doAction;
my $inputfile;
my $outputfile;
my $inputfilename;
my @hops;
my %evblock;
my %geninfo;
my %nym;
my %remailer;
my %broken;
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

$doAction = (($opt{'ctype'} eq 'gpg') ? \&gpgDoAction : \&pgpDoAction);

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

if ($command eq 'makenym')
{
    showUsageAndExit("Too few creation parameters were specified") if @ARGV < 5;

    %geninfo = ('id' => shift @ARGV,
		'userid' => shift @ARGV,
		'nymserver' => shift @ARGV,
		'ngate'     => shift @ARGV);

    @hops = @ARGV;
    @ARGV = ();
}

if ($command eq 'create' or
    $command eq 'modify' or
    $command eq 'delete' or
    $command eq 'validate')
{
    showUsageAndExit("No alias was specified") if @ARGV < 1;
    $opt{'alias'} = shift @ARGV;
}

if ($command eq 'edit')
{
    showUsageAndExit("No filename was specified") if @ARGV < 1;
    $inputfilename = shift @ARGV;
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

open INFILE, $opt{'config'} or exitWithError("Couldn't open the configuration file $opt{'config'}: $!");
$block = '';
while (defined ($_ = <INFILE>))
{
    $block .= $_;
}
close INFILE;

if ($opt{'config'} =~ /\.pgp$/)
{
    $block = &$doAction('action'  => 'decrypt',
			'message' => $block);
}

eval $block;
exitWithError("Unable to evaluate the configuration file $opt{'config'}:\n$@") if $@;

# Expand random-chain clauses
my @temp = @hops;
@hops = ();
foreach my $hop (@temp)
{
    # Random chain?
    if ($hop =~ /^\d+(\[\d*\.?\d*\])?$/)
    {
	my $threshold = 100;
	my $length = $hop;
	if ($hop =~ /\[/)
	{
	    $hop =~ /(\d+)\[(.*)\]/;
	    $length = $1;
	    $threshold = $2;
	}
	push @hops, mkRandChain($length, $threshold);
    }
    # Hop name
    else
    {
	push @hops, $hop;
    }
}
@temp = ();

# These commands all use the same configuration information, so
# calculate it once.

if ($command eq 'create' or
    $command eq 'decrypt' or
    $command eq 'modify' or
    $command eq 'delete')
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
    my $lasthop = '';

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
	$hopprob = 0 if ($broken{"$lasthop:$hop"} || $broken{"*:$hop"});
	$prob = $prob * $hopprob / 100.0;
	my $hoplatency = $remailer{$hop}{'latency'};
	$hoplatency = "0:$hoplatency" if ($hoplatency =~ /^\d+:\d+$/);
	my ($hours, $minutes, $seconds) = (split /:/, $hoplatency);
	$latency += $hours * 3600 + $minutes * 60 + $seconds;

	if ($hopprob > 0) {
	    $hopprob = sprintf('%6.2f%%', $hopprob);
	} else {
	    $hopprob = 'BROKEN!';
	}

	printf "%2d  %-8s  %9s  %s  %9s  %6.2f%%\n",
	    $count,
	    $hop,
            $hoplatency,
            $hopprob,
            formatTime($latency),
            $prob * 100;

	$lasthop = $hop;
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
	my $pass = $$current{'pass'};

	$message = &$doAction('action'  => 'decrypt',
			      'pass'    => $pass,
			      'message' => $message) if defined $pass;
    }

    $message = &$doAction('action'  => 'decrypt',
			  'message' => $message);

    select $outputfile;
    print $message;
    close INPIPE;
    close $outputfile;

    exit;
}


############################################################
#### Edit an encrypted file                             ####
############################################################

## This doesn't work correctly.  It's not a documented feature for
## good reason.

if ($command eq 'edit')
{
    my $tempname = "$opt{'tmp'}/" . mkRandString();
    my $message;

    if (system "mknod -m 700 $tempname p" and
	system "mkfifo -m 700 $tempname")
    {
	exitWithError("Unable to create a named pipe \"$tempname\"");
    }

    unless (open INFILE, $inputfilename)
    {
	my $error = $!;
	unlink $tempname;
	exitWithError("Unable to read the input file: $error");
    }

    $message .= $_ while defined ($_ = <INFILE>);
    close INFILE;

    $message = &$doAction('action'  => 'decrypt',
			  'message' => $message);

#     my $pid;
#     unless (defined ($pid = fork()))
#     {
# 	unlink $tempname;
# 	exitWithError("Unable to fork");
#     }

#     if ($pid)
#     {
    if (fork())
    {
	print "Opening the pipe\n";
	unless (open OUTPIPE, "> $tempname")
	{
	    my $error = $_;
	    unlink $tempname;
	    exitWithError("Unable to write to the named pipe: $error");
	}
	print "Writing to the pipe\n";
	print OUTPIPE "$message\n\n";
	close OUTPIPE;
	# $pid = waitpid $pid, 0;
	my $pid = wait;
	if ($pid == -1)
	{
	    unlink $tempname;
	    exitWithError("Something strange happened to our child");
	}
    }
    else
    {
	print "Editing $tempname\n";
	exec "vi $tempname" or die "Unable to exec: $!";
    }

    unless (open INPIPE, $tempname)
    {
	my $error = $_;
	unlink $tempname;
	exitWithError("Unable to read the named pipe: $!");
    }
    $message = '';
    $message .= $_ while defined ($_ = <INPIPE>);
    close INPIPE;
    print "Final output: $message\n";

    unlink $tempname or exitWithError("Couldn't delete the named pipe: $!");

    exit;
}


############################################################
#### Create and modify                                  ####
############################################################

if ($command eq 'create' or $command eq 'modify')
{
    my $public_key = getPubKey($nym{'userid'});

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
	$message = &$doAction('message' => $message,
			      'action'  => 'encrypt_to',
			      'to'      => $destination);

        $message = mkHeader($current) . "::\nEncrypted: PGP\n\n$message\n";
	$message .= "**\n" if defined $$current{'pass'};

	$next = $current;

    debug(<<__EOHD__);

######################################################################
######################################################################
$message
######################################################################
######################################################################

__EOHD__

    }

    # Build a conditional creation request ("create?" works as modify if signed)
    $message = <<__EOCREATEREQ__;
Config:
From: $nym{'id'}
Nym-Commands: create? +acksend +fingerkey name="$nym{'full'}"
Public-Key:
$public_key
Reply-Block:
$message
__EOCREATEREQ__

    # Dump the penultimate message buffer to the screen for examination
    debug("FINAL ==================");
    debug($message);
    debug("FINAL ==================");

    # Given the final message, encrypt it to the appropriate remailer.
    # Now the creation request is all ready for mailing!
    debug("Signing and encrypting the creation request...");
    $message = &$doAction('message' => $message,
			  'action'  => 'encrypt_sign_to',
			  'to'      => $nymserver{$nym{'nymserver'}}{'config'},
			  'from'    => $nym{'userid'});

    select $outputfile;
    print writeMailFile('recipient' => $nymserver{$nym{'nymserver'}}{'config'},
			'message'   => $message,
			'format'    => $opt{'mailoutformat'});
    exit;
}


############################################################
#### Delete                                             ####
############################################################

if ($command eq 'delete')
{
    # Build a delete request
    my $message = <<__EOCREATEREQ__;
Config:
From: $nym{'id'}
Nym-Commands: delete
__EOCREATEREQ__

    # Dump the penultimate message buffer to the screen for examination
    debug("FINAL ==================");
    debug($message);
    debug("FINAL ==================");

    # Given the final message, encrypt it to the appropriate remailer.
    # Now the creation request is all ready for mailing!
    debug("Signing and encrypting the creation request...");
    $message = &$doAction('message' => $message,
			  'action'  => 'encrypt_sign_to',
			  'to'      => $nymserver{$nym{'nymserver'}}{'config'},
			  'from'    => $nym{'userid'});

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
    print mkRandPhrase($opt{'words'}) . "\n";
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

	print "    Caps   : " . join (', ', (sort keys %{$remailer{$name}{'caps'}})) . "\n";
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
#### Generate a new nym                                 ####
############################################################

if ($command eq 'makenym')
{
    # Get the nym's "full" component from the PGP key
    foreach $_ (split "\n", &$doAction('action' => 'getkeyinfo',
				       'userid' => $geninfo{'userid'}))
    {
	next unless /^pub/;
	$geninfo{'fullname'} = (split /\s+/, $_, 4)[3];
	$geninfo{'fullname'} =~ s/\s+\<.*$//;
	last;
    }

    my $lasthop = $geninfo{'ngate'};

    unless (defined $newsgate{$lasthop})
    {
	# Maybe it's a remailer or direct e-mail address.
	exitWithError("$geninfo{'ngate'} is not a known newsgate or remailer, or e-mail address.")
	    unless ($lasthop = resolveAddr($lasthop));
    }

    push @hops, $lasthop;
    my @varhops;

    foreach my $name (@hops)
    {
	my %this;

	# Split newsgate:newsgroup hops
	my $group = 'alt.anonymous.messages';
	if ($name =~ /:/)
	{
	    ($name, $group) = (split /:/, $name);
	}

	# Verify the existence of the named hop
	unless (resolveAddr($name))
	{
	    exitWithError("Unknown recipient: $name");
	}

	$this{'addr'} = $name;
	$this{'pass'} = mkRandString();

	# Define newsgroups and subject if this hop is a newsgate
	if (defined $newsgate{$name})
	{
	    $this{'subj'} = mkRandPhrase($opt{'words'});
	    $this{'ngrp'} = $group;
	}

	push(@varhops, \%this);
    }

    require Data::Dumper;

    my $dumper = new Data::Dumper([
	{
	    'user' =>
	    {
		'id'		=> $geninfo{'id'},
	  	'full'		=> $geninfo{'fullname'},
		'userid'	=> $geninfo{'userid'},
		'nymserver'	=> $geninfo{'nymserver'},
	    },
	    'hops' => [ @varhops ]
	}
    ], [ "\$evblock{$geninfo{'id'}}" ]);

    $dumper->Indent(1);
    $dumper->Sortkeys(1) if UNIVERSAL::can($dumper, 'Sortkeys');

    print $dumper->Dump;
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
    if (defined $maildata{'recipient'} and $maildata{'recipient'} ne '' and
	defined $maildata{'newsgroups'} and $maildata{'newsgroups'} ne '')
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
    $maildata{'message'} = &$doAction('message' => $buffer,
				      'action'  => 'encrypt_sign_to',
				      'to'      => $nymserver{$nym{'nymserver'}}{'send'},
				      'from'    => $nym{'userid'});

    my $subject = mkRandString();

    select $outputfile;
    print writeMailFile('recipient' => $nymserver{$nym{'nymserver'}}{'send'},
			'subject'   => $subject,
			'message'   => $maildata{'message'},
			'format'    => $opt{'mailoutformat'});
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
	if (defined $parsedinfo{$key} and $parsedinfo{$key} ne '')
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
	$message = &$doAction('message' => $message,
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
	unless (defined $evblock{$alias})
	{
	    print "Alias \"$alias\" does not exist.\n\n";
	    next;
	}

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
	open INPIPE, "gpg -at --openpgp --export '$fingerprint' |" or exitWithError("Unable to open the key export pipe: $!");
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

## GPG version of $doAction
sub gpgDoAction
{
    my %params = @_;
    my $retval = '';
    my $gpg_opts;
    my $use_tmpfile = 0;

    if ($params{'action'} eq 'encrypt_to')
    {
	$gpg_opts = "--pgp2 -r '$params{'to'}' -eat";
	$use_tmpfile = 1;
    }
    elsif ($params{'action'} eq 'encrypt_sign_to')
    {
	$gpg_opts = "--openpgp -u '$params{'from'}' -r '$params{'to'}' -seat";
    }
    elsif ($params{'action'} eq 'decrypt')
    {
	$gpg_opts = "-d";
    }
    elsif ($params{'action'} eq 'getkeyinfo')
    {
	$gpg_opts = "--list-keys '$params{'userid'}'";
    }
    else
    {
	exitWithError("Unknown pgp action: $params{'action'}");
    }

    # Tell gpg to accept the password from STDIN if one is given
    if (defined ($params{'pass'}))
    {
	$gpg_opts = "--passphrase-fd 0 $gpg_opts";
    }

    $gpg_opts = "-q --always-trust $gpg_opts";

    if ($opt{'debug'})
    {
	my $out = "\n########################################\ngpgDoAction:\n";
	foreach my $key (keys %params)
	{
	    next if $key eq 'message';
	    $out .= "    $key: $params{$key}\n";
	}
	$out .= "    Command line: gpg $gpg_opts\n";
	$out .= "Message:\nvvvvvvvvvvvvvvvvvvvv\n$params{'message'}^^^^^^^^^^^^^^^^^^^^\n";
	$out .= "########################################\n";
	debug($out);
    }

    my $tmpfile_in;
    my $tmpfile_out;

    eval {
	my $pid;

	if ($use_tmpfile) {
	    # By design or flagrant bug?  You make the call.
	    # In --pgp2 mode, gnupg doesn't write the output data
	    # correctly if a pipe is used.  Probably because of lack
	    # of ability to *seek() the file, but that's no reason to
	    # be boneheaded about it....

	    $tmpfile_in = "/tmp/gpg.in.".rand;
	    $tmpfile_out = "/tmp/gpg.out.".rand;

	    open(O, ">$tmpfile_in") || die "$tmpfile_in: $!";
	    print O $params{'message'};
	    close(O);

	    (system("gpg $gpg_opts -o $tmpfile_out $tmpfile_in") / 256)
		&& die "gpg exec failed; aborting\n";

	    open(I, "<$tmpfile_out") || die "$tmpfile_out: $!";
	    $retval .= $_ while (defined ($_ = <I>));
	    close I;
	} else {
	    $pid = open2(\*INPIPE, \*OUTPIPE, "gpg $gpg_opts");

	    if (defined ($params{'pass'})) {
		print OUTPIPE "$params{'pass'}\n";
	    }
	    if (defined ($params{'message'})) {
		print OUTPIPE $params{'message'};
	    }

	    # Closing this handle will force GPG to process the data
	    close OUTPIPE;

	    $retval .= $_ while (defined ($_ = <INPIPE>));
	    close INPIPE;

	    die "gpg exec failed; aborting\n" unless (waitpid($pid, 0));
	}
    };

    unlink $tmpfile_in if defined $tmpfile_in;
    unlink $tmpfile_out if defined $tmpfile_out;
    die $@ if $@;
    debug("Leaving gpgDoAction");

    return $retval;
}

## PGP version of $doAction
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
    elsif ($params{'action'} eq 'getkeyinfo')
    {
	$pgp_syscmd = "pgp -kv '$params{'userid'}'";
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

    die "pgp exec failed; aborting\n" unless (waitpid($pid, 0) == $pid && !$?);
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
    return $digest->b64digest;
}

## Generate a somewhat random phrase
sub mkRandPhrase
{
    my $length = shift;
    my $retval;

    # This algorithm courtesy of the Perl Cookbook
    open INFILE, $opt{'dict'} or exitWithError("Unable to read the dictionary file $opt{'dict'}: $!");
    1 while <INFILE>;
    my $count = $.;
    close INFILE;

    my %list;
    for (my $i = 0; $i < $length; $i++)
    {
	$list{$i}{'number'} = int (rand $count);
    }

    open INFILE, $opt{'dict'} or exitWithError("Unable to read the dictionary file $opt{'dict'}: $!");
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
	if (defined $retval)
	{
	    $retval .= ' ';
	}
	$retval .= $list{$index}{'word'};
    }
    return $retval;
}

sub mkRandChain
{
    my $length = shift;
    my $threshold = shift || 100;
    my @chain;
    my %candidate;

    foreach my $name (keys %remailer)
    {
	my $uptime = $remailer{$name}{'uptime'};
	$uptime =~ s/\%$//;
	if ($uptime >= $threshold)
	{
	    $candidate{$name} = rand;
	}
    }
    if ($length > scalar(keys %candidate))
    {
	exitWithError(sprintf "The specified chain length, %d, was greater than the number of candidates, %d.",
		      $length,
		      scalar (keys %candidate));
    }
    my $i = 1;
    foreach my $name (sort { $candidate{$a} <=> $candidate{$b} } keys %candidate)
    {
	push @chain, $name;
	$i++;
	last if $i > $length;
    }
    return @chain;
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

    my $algo = $$dest{'algo'};
    $algo = 'Key' if (!defined $algo || $algo eq 'IDEA');
    $message .= "Encrypt-$algo: $$dest{'pass'}\n" if $$dest{'pass'};

    $message .= "\n";

    my $headers = '';
    $headers .= "Newsgroups: $$dest{'ngrp'}\n" if (defined $$dest{'ngrp'});
    $headers .= "Subject: $$dest{'subj'}\n" if (defined $$dest{'subj'});

    $message .= "##\n$headers\n" if length($headers) > 0;

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
	print STDERR "$0: warning: $opt{'remailers'} missing or too old; re-fetching\n";
	updateRemailers();
    }

    open INFILE, $opt{'remailers'} or exitWithError("Unable to read $opt{'remailers'}: $!");
    while (defined ($inline = <INFILE>))
    {
	chomp $inline;
	next if $inline eq '';

	if ($inline =~ /^Broken type-I remailer chains:/) {
	    # Cache the broken links for "chainstat" command.

	    while (defined ($inline = <INFILE>)) {
		chomp $inline;
		last if $inline eq '';

		if ($inline =~ /^\(([^ ]+) ([^ ]+)\)$/) {
		    $broken{"$1:$2"} = 1;
		}
	    }

	    next;
	}

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
	next unless (defined $name && defined $remailer{$name});

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

    # Finally, remove all remailers that don't offer cpunk services or are missing information
    foreach my $name (keys %remailer)
    {
	delete $remailer{$name} unless (defined $remailer{$name}{'caps'}{'cpunk'}
					and defined $remailer{$name}{'latency'});
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
Usage: $0 COMMAND [arguments]

COMMANDS

    chainstat CHAIN
              Calculate the probably latency and reliability of a chain of
              named remailers.

    create alias [filename]
              Create a new reply block.

    modify alias [filename]
             Create a modification request block.

    delete alias [filename]
             Create a deletion request block.

    decrypt [input file] [output file]
              Decrypt the input data with the appropriate sequence.

    list      Get a list of defined remailers, mail2news gateways, and
              nymservers.

    makenym alias userid nymserver newsgate CHAIN
    makenym alias userid nymserver email CHAIN

    nymcrypt [input file] [output file]
              Encrypt a file (in email format) for delivery to the
              appropriate nymserver.

    password  Generate a reasonably random password.

    phrase    Generate a string of random words.

    remcrypt CHAIN
              Accept an email message on STDIN and encrypt it for delivery for
              each of the listed hops in turn.  Output is to STDOUT.

    update    Force an update of the remailers file

    validate alias|"all"
              Verify the that all of the hops in an alias' reply block are
              defined.


OPTIONS

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


CHAINS

    hop1 hop2 n[m]

__EOHELP__
    exit 1;
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
    exit 1;
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
    my ($method, $source) = (split /\:\/\//, $opt{'rlist'})[0, 1];
    if ($method eq 'finger')
    {
	system "finger $source > $opt{'remailers'}";
    }
    if ($method eq 'http' || $method eq 'ftp')
    {
	my $ok = 0;
	# Find a fetch command
	foreach my $path (split /:/, $ENV{'PATH'})
	{
	    if (-e "$path/wget")
	    {
		system "$path/wget -q $opt{'rlist'} -O $opt{'remailers'}";
		$ok = 1;
		last;
	    }
	    if (-e "$path/curl")
	    {
		system "$path/curl $opt{'rlist'} > $opt{'remailers'}";
		$ok = 1;
		last;
	    }
	}
	unless ($ok)
	{
	    print "Unable to find wget or curl anywhere in the search path.\n";
	    exit -1;
	}

	# update timestamp
	system("touch $opt{'remailers'}");
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
