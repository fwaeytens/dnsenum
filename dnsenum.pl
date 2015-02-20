#!/usr/bin/perl
#
#
#	dnsenum.pl VERSION 1.2.4
#	This version:	- changed version number to the correct one		
#		
#	dnsenum.pl: multithread script to enumerate information on
#		a domain and to discover non-contiguous ip blocks.
#	
#	1) Get the host's addresse.
#	2) Get the nameservers (threaded).
#	3) get the MX record (threaded).
#	4) Perform axfr queries on nameservers (threaded).
#	5) Get extra names via google scraping.
#	6) Brute force subdomains from file (threaded).
#	7) Calculate C class domain network ranges and perform whois 
#		queries on them (threaded).
#	8) Perform reverse lookups on C class or/and whois
#		network ranges (threaded).
#	9) Write to domain_ips.txt file non-contiguous ip-blocks results.
#
#	run perldoc on this script for help.
#
#	To install needed modules:
#	sudo perl -MCPAN -e shell
#	and then e.g.: cpan[1]> install XML::Writer
#
#	Copyright (C) 2014 - Filip Waeytens, tixxDZ
#
#       This program is free software; you can redistribute it and/or
#       modify it under the terms of the GNU General Public License as
#       published by the Free Software Foundation; either version 2 of
#       the License, or (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful, but
#       WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#       General Public License for more details.
#
#       You should have received a copy of the GNU General Public License along
#       with this program; if not, write to the Free Software Foundation,
#       Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
#	Special thanks to all perl developers.
#
#	please see perldoc dnsenum.pl for options and arguments

use strict;
use warnings;#it complains about uninitialized values when it doesn't find address in RR; need to fix later
use Config;
use Term::ANSIColor;
use Getopt::Long;
use IO::File;
use Net::IP;
use Net::DNS;
use Net::Netmask;
use XML::Writer;
use Socket;
use String::Random;

my ($ithreads_support, $whois_support, $mech_support, $html_support,$xml_support);

my (%nameservers, %allsubs, %googlesubs);
my (%filesubs, %netranges, %recursubs);
my (@mxservers, @results, @ipblocks, @privateips);
my ($enum, $exp, $help, $noreverse, $nocolor, $update, $whois, $dnsserver);
my ($private, $recursion, $scrap, $threads, $verbose);
my ($dnsfile, $subfile, $dns_tmp, $sub_tmp, $fileips);
my ($domain, $recur, $table, $extend_b, $extend_r);
my ($timeout, $delay, $pages, $ipcount, $ipvalid) = (10, 3, 5, 0, 0);
my ($output);
my $writer;
my $program = 'dnsenum.pl';
my $string_gen = String::Random->new;
my $wildcards = $string_gen->randpattern("cccccccccccc");
my @wildcardaddress;
my @wildcardcname;
my $VERSION = '1.2.4';

#load threads modules (perl must be compiled with ithreads support)
BEGIN {
	if ($Config{useithreads}){
		eval("	use threads;
			use threads::shared;
			use Thread::Queue;
		");		
		$ithreads_support = 1 unless $@;
	}
}

eval("use Net::Whois::IP qw(whoisip_query);");
$whois_support = 1 unless $@;

eval("use WWW::Mechanize;");
$mech_support = 1 unless $@;

eval("use HTML::Parser;");
$html_support = 1 unless $@;

eval("use XML::Writer;");
$xml_support = 1 unless $@;


print STDOUT $program, " VERSION:", $VERSION, "\n";

GetOptions (	'dnsserver=s'	=>	\$dnsserver,
		'enum'		=>	\$enum,
		'd|delay=i'	=>	\$delay,
		'e|exclude=s'	=>	\$exp,
		'f|file=s'	=>	\$dnsfile,
		'h|help' 	=>	\$help,
		'noreverse'	=>	\$noreverse,
		'nocolor'	=>	\$nocolor,
		'p|pages=i'	=>	\$pages,
		'private'	=>	\$private,
		'r|recursion'	=>	\$recursion,
		's|scrap=i'	=>	\$scrap,
		'subfile=s'	=>	\$subfile,
		'threads=i'	=>	\$threads,
		't|timeout=i'	=>	\$timeout,
		'u|update=s'	=>	\$update,
		'v|verbose'	=>	\$verbose,
		'w|whois'	=>	\$whois,
		'o|out=s'	=>	\$output);

usage() if $help || @ARGV == 0;

$domain = lc $ARGV[0];
$fileips = $domain.'_ips.txt';

#DEFAULT options --threads 5 -s 15 -w 
if ($enum) {
	$threads = 5;
	$scrap = 15;# Google scraping default to 15 to avoid Google Blocking us with captcha's
	$whois = 1;
}

#module support
if ($threads) {

	if ((!defined $ithreads_support and
	warn "Warning: can't use threads, check ithreads support, and ".
		"(threads, threads::shared, Thread::Queue) modules.\n") ||
		$threads <= 0) {
		$threads = undef;
	}
	else {
		#to handle different ips that belongs to the domain
		share(@results);
		
		#number of ips that will be queried in reverse lookup
		share($ipcount);

		#number of valid ips (taken from reverse lookup responses)
		share($ipvalid); 

		#will contain all valid subdomains 
		share(%allsubs);

		if ($recursion) {
			share(%recursubs);
			share(%nameservers);
		}

		#to save whois netblocks
		share($table);

		#whois and reverse lookup results
		share(%netranges);
	}
}

if ($whois && !defined $whois_support) {
	warn "Warning: can't load Net::Whois::IP module, ".
		"whois queries disabled.\n";
	$whois = undef;
}
if ($whois && !defined $whois_support) {
	warn "Warning: can't load Net::Whois::IP module, ".
		"whois queries disabled.\n";
	$whois = undef;
}
if ($output && !defined $xml_support) {
	warn "Warning: can't load XML::Writer module, ".
		"xml output disabled.\n";
	$output = undef;
}
if(defined($output)) {
    my $out = new IO::File(">$output");
    $writer = new XML::Writer(OUTPUT=>$out);
    $writer->xmlDecl("UTF-8");
    $writer->startTag("magictree", "class"=>"MtBranchObject");
    $writer->startTag("testdata", "class"=>"MtBranchObject");
}

$scrap = undef
	if $scrap && ((not defined $mech_support and
	warn "Warning: can't load WWW::Mechanize module".
			", Google scraping desabled.\n") ||
	(not defined $html_support and
	warn "Warning: can't load HTML::Parser module".
			", Google scraping desabled.\n") ||
	$scrap <= 0 || $pages <= 0);

$timeout = 10 if $timeout < 0 || $timeout > 128;
$delay = 3 if $delay < 0;

$update = undef if $update && !$dnsfile;
unless ($nocolor) {
	print color 'bold blue';
}
print STDOUT "\n-----   ", $domain ,"   -----\n";
unless ($nocolor) {
	print color 'reset';
}
################START#####################

# (1) get the host's addresses
printheader ("Host's addresses:\n");
my $res = Net::DNS::Resolver->new(	tcp_timeout => $timeout,
					udp_timeout => $timeout,
					defnames => 0);

$res->nameservers($dnsserver) if $dnsserver;

my $packet = $res->query($domain);
if ($packet) {
	foreach my $rr (grep { $_->type eq 'A' } $packet->answer) {
		printrr($rr->string);
		xml_host($rr);
		push @results, $rr->address
			if $rr->name =~ /$domain$/;
	}
}
elsif ($verbose) {
	warn " ", $domain ," A query failed: ", $res->errorstring, "\n";
}

# wildcards test - I guess it can be cleaner, but it seems to be working
# tested with opendns servers and ubuntu.org domain

print STDOUT "\n"."-" x 16 ."\nWildcards test:\n"."-" x 16 ."\n"
	if $verbose;
my $wildcardpacket=$res->query($wildcards.".".$domain);
# if we get a response resolving our random hostname, it can be a A or a CNAME
if ($wildcardpacket) {
	printheader ("Wildcard detection using: ".$wildcards."\n");
	foreach my $rr ($wildcardpacket->answer) {
		
		if ($rr->type eq 'A')
		{
		printrr($rr->string);
		#wildcardaddress will hold the IP that's used as a string
		my @wcheck= split('\s+',$rr->string); 
		push @wildcardaddress, $wcheck[4];
			
		}
		if ($rr->type eq 'CNAME')
		{
		printrr($rr->string);
		#wildcardcname will hold CNAME that's used as a string
		my @wcheck= split('\s+',$rr->string); 
		push @wildcardcname, $wcheck[4];
		
		}
	}
	
	unless ($nocolor) {
		print color 'bold red';
	}
	print "\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n";
	print STDOUT " Wildcards detected, all subdomains will point to the same IP address\n";
	print STDOUT " Omitting results containing ".join(', ', @wildcardaddress).".\n Maybe you are using OpenDNS servers.\n";
	print "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
	
	unless ($nocolor) {
		print color 'reset';
	}
	
	#exit(1);#we don't exit when wildcards are detected, because we will miss existing hosts
}

elsif ($verbose) {
	print STDOUT " good\n";
}

# (2) get the namservers for the domain
printheader ("Name Servers:\n");
$packet = $res->query($domain, 'NS');
if ($packet) {

	foreach my $rr (grep { $_->type eq 'NS' } $packet->answer) {
		$nameservers{$rr->nsdname} = 1;
	}

	die " Error: can't continue no NS record for " , $domain ,"\n" 
		unless %nameservers;

	#read the A record from the additional section
	if ($packet->header->arcount) {
		my @remain = additionalrecord($packet, keys %nameservers);
		#do nslookup on nameservers that are not present in the 
		#additional section
		launchqueries(\&nslookup, @remain)
			if scalar @remain;
	}
	#perform the nslookup on the nameservers
	else {
		launchqueries(\&nslookup, keys %nameservers);
	}
}
#exit if there is no NS record.
else {
	die " ", $domain ," NS record query failed: ",
		$res->errorstring , "\n";
}

# (3) get the MX record
printheader ("Mail (MX) Servers:\n");
$packet = $res->query($domain, 'MX');
if ($packet) {

	foreach my $rr (grep { $_->type eq 'MX' } $packet->answer) {
		push @mxservers, $rr->exchange;
	}
	if (scalar @mxservers) {
		if ($packet->header->arcount) {
			my @remain = additionalrecord($packet, @mxservers);
			launchqueries(\&nslookup, @remain)
				if scalar @remain;
		}
		else {
			launchqueries(\&nslookup, @mxservers);	
		}
	}
} 
elsif ($verbose) {
	warn " ", $domain ," MX record query failed: ",
		$res->errorstring, "\n";
}

# (4) perform zonetransfers on nameservers 
printheader ("Trying Zone Transfers and getting Bind Versions:\n");
launchqueries(\&zonetransfer, keys %nameservers);


# (5) scrap additional names from google search and do nslookup on them
if ($scrap) {
	printheader ("Scraping ".$domain." subdomains from Google:\n");
	my @tmp = googlescraping();
	if (scalar @tmp) {
		#print STDOUT "\n Performing nslookups:\n";
		launchqueries(\&nslookup, map { $_ .= '.'.$domain } @tmp);
	}
}

#exit if the brute force file is not specified
unless ($dnsfile) {
	print STDOUT "\nbrute force file not specified, bay.\n";
    if(defined($output)) {
        $writer->endTag('testdata');
        $writer->endTag('magictree');
    }
	exit(0);
}

$extend_b = 1 if ($update && $update eq 'a') || $subfile || $recursion;

# (6) brute force subdomains from a file

printheader ("Brute forcing with ".$dnsfile.":\n");
bruteforce('f');

#updating dnsfile with zonetransfer or googlescraping subdomains results
if ($update) {

	if ($dns_tmp = IO::File->new_tmpfile()) {
		if ($update eq 'z') {	
			print $dns_tmp $_, "\n"
				for uniq_hosts(grep {
					$allsubs{$_} eq $update 
					} keys %allsubs);
		}
		elsif ($update eq 'g') {
			print $dns_tmp $_, "\n"
				for uniq_hosts(keys %googlesubs);
		}
	}
	else {
		die "Error can't create a temporary file: $!, ". 
			"to update ", $dnsfile ," file\n";
	}
}

undef %googlesubs if %googlesubs;

#launch recursion
if ($recursion) {
	if (%allsubs) {
		printheader("Performing recursion:\n");
		
		print STDOUT "\n ---- Checking subdomains NS records ----\n";

		#select subdomains that are able to recursion
		launchqueries(\&selectsubdomains,
			map { $_ .= '.'.$domain } sort keys %allsubs);

		if (%recursubs) {
			my @tmp = keys %recursubs;
			undef %recursubs;

			#brute force from a list using recursion
			bruteforce('l', \@tmp);
		}
		else {
			print STDERR "\n  Can't perform recursion ".
					"no NS records.\n";
		}
	}
	else {
		print STDERR "\n Can't perform recursion no subdomains.\n";
	}
	undef %filesubs;
}

#updating the brute force file (-u a switch)
if ($update && ($update eq 'a' || $update eq 'all')) {

	#save ns and mx servers
	my @tmp = keys %nameservers;
	push @tmp, @mxservers if scalar @mxservers;
	
	print $dns_tmp $_, "\n" 
		for uniq_hosts(grep { s/\.$domain// } @tmp);
	print $dns_tmp $_, "\n" for uniq_hosts(keys %allsubs);
}

#write subdomains to the subfile
if ($subfile) {
	if ($sub_tmp = IO::File->new_tmpfile()) {
		my %uniq;
		@uniq{keys %nameservers} = ();
		@uniq{@mxservers} = () if scalar @mxservers;

		print $sub_tmp $_, "\n"
			for grep { s/\.$domain// } keys %uniq;
		
		print $sub_tmp $_, "\n" for keys %allsubs;
	}
	else {
		die "Error can't create a temporary file: $!, ".
			" to save results to ", $subfile ," file\n"; 
	}	
}

undef @mxservers;
undef %allsubs;

# (7) get domain network ranges from brute force results and whois queries
@results = networkranges(@results);
undef %netranges;

# (8) perform reverse lookups on netranges (class C or whois netranges)
unless ($noreverse) {

	#to save all valid subdomains discovred in
	#the reverse lookup process
	$extend_r = 1 
		if ($update && ($update eq 'r' || $update eq 'a' ||
			$update eq 'all')) || $subfile;
	printheader("Performing reverse lookup on ".$ipcount." ip addresses:\n");
	launchqueries(\&reverselookup, @results);

	print STDOUT "\n", $ipvalid ," results out of ",
			$ipcount ," IP addresses.\n";
}
else {
	#calculate ip blocks
	@ipblocks = finalvalidips(sort_by_ip_address(@results));
}

#save final IP blocks to the domain_ips.txt file
writetofile($fileips, "w", @ipblocks);

#show private ips
if ($private && scalar @privateips) {

	print STDOUT "\n"."-" x 26 ."\n",
			$domain ," private ips:\n".
			"-" x 26 ."\n";
	print STDOUT " ", $_ , "\n" for @privateips;

	#save private ips to domain_ips.txt file
	writetofile($fileips, "a+", @privateips);
}

# (9) show non-contiguous IP blocks
printheader($domain." ip blocks:\n");
print STDOUT " ", $_ , "\n" for @ipblocks;

#clean the brute force file
cleanfile($dnsfile, $dns_tmp) if $update;

#clean the subfile
cleanfile($subfile, $sub_tmp) if $subfile;

if(defined($output)) {
    $writer->endTag('testdata');
    $writer->endTag('magictree');
}


print STDOUT "\ndone.\n";

exit(0);

#--------------------------------------------------

#subroutine that will launch different queries
#(nslookup, zonetransfer, whoisip, reverselookup)
sub launchqueries {

	my $querytype = shift;

	if ($querytype != \&reverselookup) {

		if ($threads) {
			my $stream = new Thread::Queue;
			$stream->enqueue(@_);
			my $thrs = $threads;  #don't create unused threads
			$thrs = scalar @_ if $threads > scalar @_;
		
			for (1 .. $thrs) {
				threads->new($querytype, \$stream);	
			}
			#wait all threads
			foreach (threads->list) {
				$_->join
				if ($_->tid &&
				!threads::equal($_, threads->self));
			}
		}
		else {
			foreach (@_) {
				&$querytype($_);
			}
		}
	}
	else {
		foreach (@_) {
			my $block = new2 Net::Netmask($_);
			unless ($block) {
				print STDERR " Can't perform reverse lookup: "
						, $Net::Netmask::error ,"\n";
				next;
			}

			if ($threads) {
				my $stream = new Thread::Queue;
				$stream->enqueue($block->enumerate);

				for (1 .. $threads) {
					threads->new($querytype, \$stream);
				}
				#wait all threads
				foreach (threads->list) {
					$_->join
					if ($_->tid &&
					!threads::equal($_, threads->self));
				}
			}
			else {
				&$querytype($block->enumerate);
			}

			#calculate IP blocks results
			if (%netranges) {
				my @tmp = finalvalidips(
					sort_by_ip_address(keys %netranges));
				undef %netranges;

				#get final valid ip blocks
				push @ipblocks, @tmp;
			}

			#write reverse lookup hostnames results to files
			if ($extend_r && %allsubs) {

				if ($update && ($update eq 'r' ||
				$update eq 'a' || $update eq 'all')) {
					print $dns_tmp $_, "\n"
					for uniq_hosts(keys %allsubs);
				}
				if ($subfile) {
					print $sub_tmp $_, "\n"
					for keys %allsubs;
				}
				undef %allsubs;
			}	
		}
	}
}

#subroutine to perform reverse lookups
sub reverselookup {

	my $stream = shift if $threads;

	my $res = Net::DNS::Resolver->new(	
					tcp_timeout => $timeout,
					udp_timeout => $timeout,
					persistent_udp => 1);
	
	$res->nameservers(keys %nameservers);

	while (defined(my $ip = $threads ? $$stream->dequeue_nb : shift)) { 
		
		my $query = $res->query($ip);
		if ($query) {
			foreach my $rr ( grep { $_->type eq 'PTR' } 
				$query->answer) {
				
				#exclude non PTR types answers or unwanted hostnames
				next if $exp && $rr->ptrdname =~ /$exp/;
				 
				if ($rr->ptrdname =~ /(.*)(\.$domain$)/i) {

					$allsubs{$1} = 1 
					if $extend_r && !$allsubs{$1};

					#to calculate last valid ip blocks
					unless ($netranges{$ip}) {
						$netranges{$ip} = 1;
						$ipvalid++;
					}
					printrr($rr->string);
					xml_host($rr);
				}
				#show all answers even if the hostname don't match the domain
				elsif ($verbose) {
					printrr($rr->string);
					xml_host($rr);
				}	
			}
		}
		#this part is just to check progress
		elsif ($verbose) {
		      print STDOUT "  ", $ip ,"    ...\n";
		}
	}
}

sub xml_host {
    if(defined $output) {
        my $rr = shift; 
        my $ip;
        if($rr->type eq 'A') {
            $ip = $rr->address;
        } else {
            my $packed_ip = gethostbyname($rr->name);
            if (defined $packed_ip) {
                $ip = inet_ntoa($packed_ip);
            }
        }
        if(defined($ip)) {
            $writer->startTag("host");
            $writer->characters($ip);
            $writer->startTag("hostname");
            $writer->characters($rr->name);
            $writer->endTag("hostname");
            $writer->endTag("host");
        }
        $writer->startTag("fqdn");
        $writer->characters($rr->name . '.');
        $writer->endTag("fqdn");
    }
}

#subroutine for nslookups (A record)
sub nslookup {

	my $stream = shift if $threads;

	my $res = Net::DNS::Resolver->new(	tcp_timeout => $timeout,
						udp_timeout => $timeout,
						persistent_udp => 1,
						dnsrch => 0);
	$res->nameservers($dnsserver) if $dnsserver;
	
	while (defined(my $host = $threads ? $$stream->dequeue_nb : shift)) {

		my $query = $res->search($host);
		
		if ($query) {
			foreach my $rr ($query->answer) {
				##we only print / add the result if it doesn't match the wildcardaddress
				if (!($rr->can('address') && $rr->address ~~ @wildcardaddress) && !($rr->name ~~ @wildcardcname))
				{
				printrr($rr->string);
				xml_host($rr);

				#check if it match the domain
				if ($rr->name =~ /(.*)(\.$domain$)/i) {
	
					#save valid subdomains
					if ($extend_b) {
						$allsubs{$1} = 1
						unless $allsubs{$1};

						#recursion results
						$recursubs{$1} = 1
						if $recur &&
						!$recursubs{$1};
					}
					#save ip address 
					push @results, $rr->address
						if $rr->type eq 'A';
				}
				}
				
 			}
		}
		
		elsif ($verbose) {
			warn "  ", $host ," A record query failed: ",
				$res->errorstring, "\n";
		}
	}
}

#subroutine to select subdomains that have NS records
sub selectsubdomains {

	my $stream = shift if $threads;

	my $res = Net::DNS::Resolver->new(	tcp_timeout => $timeout,
						udp_timeout => $timeout,
						persistent_udp => 1);

	$res->nameservers($dnsserver) if $dnsserver;

	while (defined(my $host = $threads ? $$stream->dequeue_nb : shift)) {
		my $packet = $res->query($host, 'NS');

		if ($packet) {

			foreach my $rr (grep { $_->type eq 'NS' }
				$packet->answer) {

				#show all results
				#print STDOUT "  ", $rr->string ,"\n";
				printrr($rr->string);
				xml_host($rr);
					
				if ($rr->name =~ /(.*)(\.$domain$)/i) {

					if (!$allsubs{$1} ||
					$allsubs{$1} ne 'r') {

						#bookmark this hostname to
						#perform recursion on it and
						#to avoid repetition, because
						#some domains will use CNAME
						#types that point to subs
						#that we have already
						#processed in a previous
						#recursion levels
						$allsubs{$1} = 'r';
						
						#select this subdomain
						#for recursion
						$recursubs{$rr->name} = 1;
					}

					#perhaps for future additions we save
					#ns servers for each domain or
					#subdomain, this will be very
					#useful in reverse lookup
					
					# --- begin --- 
					#check if we already have this
					#NS server
					#next if $nameservers{$rr->nsdname};

					#$nameservers{$rr->nsdname} = 1;
					#push @tmp, $rr->nsdname;
					# --- end ---
				}	
			}

			#perhaps for future additions to perform an extrem
			#recursion to get the IP addresse of the NS servers

			# --- begin ---
			#next unless scalar @tmp;

			#get the NS servers A record
			#if ($packet->header->arcount) {
			#	@tmp = additionalrecord($packet,@tmp);
			#	next unless scalar @tmp;
			#}	
			
			#foreach my $nshost (@tmp) {
			#	$packet = $res->query($nshost);
			#	if ($packet) {
			#		foreach my $rr \
			#		(grep { $_->type eq 'A' }
			#			$packet->answer) {
			#			print STDOUT "  ",
			#			$rr->string , "\n";
			#			push @results, $rr->address
			#			if ($rr->name =~ /$domain$/);
			#		}
			#	}
			#	elsif ($verbose) {
			#		warn "  ", $nshost ,
			#		" A record query failed: ",
			#		$res->errorstring , "\n";
			#	}
			#}
			# --- end ---
		}
		elsif ($verbose) {
			warn "  ", $host ," NS record query failed: ",
				$res->errorstring , "\n";
		}
	}
}

#subroutine for zonetransfers
#I got rid of the Bind Versions search...doesn't really add anything and clutters output
sub zonetransfer {

	my $stream = shift if $threads;

	my $res = Net::DNS::Resolver->new(	tcp_timeout => $timeout,
						udp_timeout => $timeout);

	while (defined(my $ns = $threads ? $$stream->dequeue_nb : shift)) {
	  	$res->nameservers($ns);
		
		my @zone = $res->axfr($domain);
		#my $version_query = $res->search("version.bind","TXT","CH");
		print STDOUT "\nTrying Zone Transfer for ", $domain ,
				" on ", $ns ," ... \n";
		
		if (@zone) {
			foreach my $rr (@zone) {
				#print all results
				printrr($rr->string);
				xml_host($rr);

				#save data if the record's domain name
				#match the domain
				if ($rr->name =~ /(.*)(\.$domain$)/i) {
					
					#save hostname
					$allsubs{$1} = 'z'
						unless $allsubs{$1};

					#save the IP address
					push @results, $rr->address
						if $rr->type eq 'A';

					#save new mx servers hostnames
					push @mxservers, $rr->exchange
						if $rr->type eq 'MX';

					#perhaps for future additions
					#save NS servers for reverse lookups
					# --- begin ---
					#$nameservers{$rr->nsdname} = 1
					#	if ($rr->type eq 'NS' &&
					#	!$nameservers{$rr->nsdname});
					# --- end ---
				}
			}
		}	
		else	{
			warn "AXFR record query failed: ",
				$res->errorstring, "\n";
		}
	}
}

#subroutine for scraping domains from google 
sub googlescraping {

	my ($response, $browser, $form, $parser, $nextpage);
	my ($count, $mypage) = (0,1);
	my $query = qq[allinurl: -www site:$domain];
	my $nexturl = qq[/search?.*q=.*$domain.*start];
	
	#on errors the mech object will call die
	$browser = WWW::Mechanize->new(	autocheck	=> 1,
					stack_depth	=> 1,
					cookie_jar	=> undef);
        #uncomment for debugging with BURP
        #$browser->proxy(['http'], 'http://127.0.0.1:8080');
	#setup the browser config
	my @agents = $browser->known_agent_aliases();
	my $agent = $agents[rand(scalar @agents)];
	$browser->agent_alias($agent);
	$browser->timeout($timeout);

	#get the first page
	$response = $browser->get("http://www.google.com/ncr");
	
	$form = $browser->form_number(1)
		or return;

	$form->find_input('q')->value($query);
	$response = $browser->submit_form(	form_number	=> 1,
						form_name	=> 'f');
	do {
		$nextpage = undef;
		print STDOUT "\n ----   Google search page: ",
			$mypage ,"   ---- \n\n";

		$parser = HTML::Parser->new(
			api_version => 3,
			start_h	=> [sub {
					my $attr = shift;

					#end of parsing
					#(we have enough subdomains)
					$parser->eof 
						unless $count < $scrap;

					return unless $attr->{href};
							
					#subdomains checks - if shit goes wrong with googlescraping it's prolly the regex
					if ($attr->{href} =~    
					/(\/url\?q\=http:\/\/)([\w\.-]+)(\.$domain\/)/) {

						$allsubs{$2} = 'g'
						unless $allsubs{$2};

						$googlesubs{$2} = 1
						unless $googlesubs{$2};

						print STDOUT "  ", $2 ,"\n";
						$count++;
					}
					#the next page
					elsif ($attr->{href} =~
					/^$nexturl=$mypage\d.*/ && 
					!defined $nextpage) {
						$nextpage = $attr->{href};
					}
				},'attr'] 
			);

		$parser->parse($response->decoded_content);

		if ($nextpage) {
			$response = $browser->get($nextpage);
			$mypage++;
		}

	} while ($count < $scrap && $mypage <= $pages && $nextpage);

	#print STDOUT "\n Google results: ", $count ,"\n";
	printheader("Google Results:\n");
	if ($count) {
		return grep { $allsubs{$_} eq 'g' } keys %allsubs;
	}
	else {
		print STDERR "  perhaps Google is blocking our queries.\n Check manually.\n";
		return;
	}
}

#subroutine to query a whois server for an IP address to get the correct netrange
sub whoisip {

	my $stream = shift if $threads;

	while (defined(my $ip = $threads ? $$stream->dequeue_nb : shift)) {
		my ($inetnum, $block);

		#search in the network blocks table to find
		#if any of them contains the IP address
		next if (findAllNetblock($ip, $table));
		
		#this is very useful on whois servers
		#that limit the number of connections
		sleep rand $delay;
	
		#catch different exceptions
		#(on exceptions netrange will be a class C /24)
		eval {
			my $response = whoisip_query($ip);
			foreach (keys %{$response}) {

				next if ($_ !~ /^(inetnum|netrange)$/i);

				$inetnum = $response->{$_};

				#handle all whois netrange format
				if ($inetnum =~ /([\d.\.]+)\/(\d{1,2})/) {
					#whois.lacnic.net format
					$block = new2 Net::Netmask (qq[$1/$2]);
				}
				else {
					$inetnum =~ s/\s//g;
					$block = new2 Net::Netmask ($inetnum);
				}	

				if ($block) {

					# this is useful when threads are enabled to eliminate
					# the processing of same netranges 
					next if $threads &&
					$netranges{$block->desc};

					$block->storeNetblock($table);

					#this is a simple workaround to
					#save netblocks in a hash
					#because we will lost all data
					#in $table after threads exit
					#(see Net::Netmask and
					#threads::shared and threads safe)
					#i am soure that there is a beter
					#solution please excuse my ignorance
					$netranges{$block->desc} = 1;

					$ipcount += $block->size();
					printf STDOUT " whois ip result:".
						"   %-15s    ->      %s\n",
						$ip, $block->desc;
				}
				else {
					print STDERR " Netmask error: ",
						$Net::Netmask::error ,"\n"
							if $verbose;
					$inetnum = undef;
				}
			}
		};
		if ($@) {
			#catch any invalid results 
			#assume that the network range is a class C
			print STDERR " Error: ", $@
				if $verbose;
			$inetnum = undef;
		}

		#can't get the netrange form the whois server
		#so we assume that is a class C range (/24)
		unless (defined $inetnum) {
			$block = new Net::Netmask (qq[$ip/24]);
			next if $threads && $netranges{$block->desc};
				
			$block->storeNetblock($table);
			$netranges{$block->desc} = 1;
			$ipcount += 256;	
			printf STDOUT " c class default:   ".
				"%-15s    ->      %s  ".
				"    (whois netrange operation failed)\n",
				$ip, $block->desc;
		}
	}	
}

#subroutine to brute force subdomains
sub bruteforce {

	#recursion on valid subdomains brute force from a list
	if (shift eq 'l') {
		my ($level, $hosts, @tmp) = 1;
		my $res = Net::DNS::Resolver->new(
						tcp_timeout => $timeout,
						udp_timeout => $timeout,
						persistent_udp => 1,
						dnsrch => 0);

		$res->nameservers($dnsserver) if $dnsserver;

		#signal to nslookup to save all recursive subdomains
		$recur = 1;

		RECURSION:
		$hosts = shift;	

		print STDOUT "\n ----   Recursion level ",
				$level ,"   ---- \n";
		foreach my $host (@$hosts) {
			my (@words, %uniq);
			print STDOUT "\n Recursion on ", $host ," ...\n";

			#wildcards test
			if ($res->search($wildcards.$host)) {
				print STDERR "  ", $host ,
					": Wildcards detected.\n";
				next;
			}

			#perform brute force using all hostnames and include the new one
			#(discovered from previous brute forces)
			foreach (sort keys %allsubs,
				grep { not $allsubs{$_} } keys %filesubs) {
				push @words, $_.'.'.$host;

				#split hostnames that contain dots
				foreach (split /\./) {
					unless ($allsubs{$_} ||
					$filesubs{$_} || $uniq{$_}) {
						$uniq{$_} = 1;
						push @words, $_.'.'.$host;
					}
				}
			}
			launchqueries(\&nslookup, @words);
		}

		#can't find new hostnames
		return
		unless @tmp = grep { $allsubs{$_} ne 'r' } keys %recursubs;
		undef %recursubs;

		#select subdomains
		printheader("Checking subdomains NS records:\n" );
		
		launchqueries(\&selectsubdomains,
				map { $_ .= '.'.$domain } sort @tmp);

		unless (%recursubs) {
			print STDOUT "\n  Can't perform recursion, ".
				"no new NS records.\n" if $verbose;
			return;
		}

		@tmp = keys %recursubs;
		undef %recursubs;
		
		$level++;
		@_ = \@tmp; 
		goto RECURSION;
	}
	#brute force subdomains from dnsfile
	else {
		my @words;
		die "Error: make sure that the file ", $dnsfile ,
			" exists and has a size greater than zero.\n"
			unless -s $dnsfile;

		my $input = new IO::File $dnsfile, "r" 
			or die "Could not open ", $dnsfile ," file: $!\n";
		while (<$input>) {
			chomp;
			
			#save subdomains found in the file to use them
			#in the recursion process
			$filesubs{$_} = 1 if $recursion;

			#select all subdomains that have not been listed
			push @words, $_.'.'.$domain
				unless $allsubs{$_};	
		}	
		$input->close;
	
		scalar @words ? launchqueries(\&nslookup, @words) :
				print STDOUT " Can't find new subdomains.\n";
		#the names have already been found by zonetransfer, ...
	}
}

#subroutine to get the domain's network ranges
sub networkranges {
	my (@cnets, %ips, %seen);
	
	#uniq IP's
	@ips{@_} = ();

	foreach my $ip (sort_by_ip_address(keys %ips)) {
		my @octets = split /\./, $ip;

		#private IP's
		if ($octets[0] == 10 
			|| $octets[0] == 127
			|| ($octets[0] == 169 && $octets[1] == 254)
			|| ($octets[0] == 172 && ($octets[1] > 15 &&
				$octets[1] < 32 ))
			|| ($octets[0] == 192 && $octets[1] == 168 )) {

			#save private ips
			push @privateips, $ip if $private;

			delete $ips{$ip};
			next;
		}

		#to get unique class C netranges
		my $net = join("\.",$octets[0],$octets[1],$octets[2]);
		unless ($seen{$net}) {
			$seen{$net} = 1;
			push @cnets, $net.".0";
		}
	}	

	#launch whois queries on IP's to get the correct netranges
	if ($whois) {
		printheader("Launching Whois Queries:\n");
		#shutdown warns the whois ip will catch exceptions with eval
		$SIG{__WARN__} = sub {} ;
		launchqueries(\&whoisip, @cnets);
		$SIG{__WARN__} = 'DEFAULT';
		
		printheader($domain ," whois netranges:\n");			
		print STDOUT " ", $_ , "\n" for keys %netranges; 
	}
	#default class C netrange
	else {
		
		printheader($domain." class C netranges:\n");
		grep { $_ .= "/24"; print STDOUT " ",$_,"\n"; } @cnets;
		$ipcount = scalar @cnets * 256;
	}

	defined $noreverse ? return keys %ips :
		(defined $whois ? return keys %netranges :
				return @cnets);
}

#subroutine that calculate and return non-contiguous IP blocks
sub finalvalidips {

	my $firstip = shift;
	
	#one single IP address
	return $firstip."/32" unless scalar @_;

	my ($lastip, @tmp);
	my $broadcast = $_[$#_];
	my $tmpip = new Net::IP(qq[$firstip - $broadcast]);
	foreach my $thisip (@_) {
		# increment the previous tmp IP address to compare it with the current 
		# IP address taken from the array 
		++$tmpip;

		if ($broadcast ne $thisip) {
			#this IP belongs to the current netrange
			if ($tmpip->ip() eq $thisip) {
				$lastip = $thisip;
			}
			#new netrange
			else {
				defined $lastip ?
				push @tmp, range2cidrlist($firstip, $lastip):
				push @tmp, $firstip."/32";
				
				#update data
				$firstip = $thisip;
				$lastip = undef;
				$tmpip = new Net::IP(qq[$firstip - $broadcast]);
			}
		}
		#we have reached the last valid IP address in the network range
		else {
			#this IP belongs to the current range
			if ($tmpip->ip() eq $broadcast) {
				push @tmp,
				range2cidrlist($firstip, $broadcast);
			}
			#this IP is the start of a new range 
			else {
				defined $lastip ?
				push @tmp, range2cidrlist($firstip, $lastip):
				push @tmp, $firstip."/32";

				#save the current new ip
				push @tmp, $broadcast."/32";
			}	
		}
	}
	return @tmp;
}


#subroutine that reads the A record from the additional section
sub additionalrecord {

	my ($packet, @servers, %seen) = @_;
	
	foreach my $rr (grep { $_->type eq 'A' } $packet->additional) {
		foreach (grep {$_ eq $rr->name} @servers) {

			$seen{$rr->name} = 1;
			printrr($rr->string);
			xml_host($rr);
			push @results, $rr->address
				if $rr->name =~ /$domain$/;

		} 
	}

	#get the nameservers that have not been found in the additional section
	keys %seen == @servers ? return :
	return grep { not $seen{$_} } @servers;
}

#subroutine to get uniq splited subdomains
sub uniq_hosts {
	my %uniq;	
	grep { !$uniq{$_} && $uniq{$_}++ for split /\./ } @_;
	return keys %uniq;
}

#subroutine to write valid subdomains to files
sub writetofile {
	my $file = shift;
	my $output = new IO::File $file, shift
		or die "Could not open ", $file ," file: $!\n";
	print $output $_, "\n" for @_;	
	$output->close;
}

#subroutine to update and clean files
sub cleanfile {

	my ($file,$tmpfile,%uniq) = @_;
	
	seek($tmpfile,0,0)
		or die "Error: seek failed on the temporary file: $!\n".
			"can't update ", $file ,"\n";

	@uniq{<$tmpfile>} = ();

	if (-s $file) {
		my $input = new IO::File $file, "r"
			or die "Unable to update ", $file ," file: $!\n";
		@uniq{<$input>} = ();
		$input->close;
	}

	writetofile($file,"w",
		sort {uc($a) cmp uc($b)} grep {chomp} keys %uniq);
}

#broken

sub printrr {
	
	my $output = shift;
	my @outputA = split('\s+',$output);
	printf("%-40s %-8s %-5s %-8s %10s\n", $outputA[0], $outputA[1], $outputA[2], $outputA[3], $outputA[4]);
	
}
sub printheader{
	my ($header) = @_;
	unless ($nocolor) {
		print color 'bold red';
	}
	print STDOUT "\n\n".$header."_" x length($header) ."\n\n";
	unless ($nocolor) {
		print color 'reset';
	}
}

#the usage subroutine
sub usage {
	print STDOUT 
qq{Usage: $program [Options] <domain> 
[Options]:
Note: the brute force -f switch is obligatory.
GENERAL OPTIONS:
  --dnsserver 	<server>
			Use this DNS server for A, NS and MX queries.
  --enum		Shortcut option equivalent to --threads 5 -s 15 -w.
  -h, --help		Print this help message.
  --noreverse		Skip the reverse lookup operations.
  --nocolor		Disable ANSIColor output.
  --private		Show and save private ips at the end of the file domain_ips.txt.
  --subfile <file>	Write all valid subdomains to this file.
  -t, --timeout <value>	The tcp and udp timeout values in seconds (default: 10s).
  --threads <value>	The number of threads that will perform different queries.
  -v, --verbose		Be verbose: show all the progress and all the error messages.
GOOGLE SCRAPING OPTIONS:
  -p, --pages <value>	The number of google search pages to process when scraping names, 
			the default is 5 pages, the -s switch must be specified.
  -s, --scrap <value>	The maximum number of subdomains that will be scraped from Google (default 15).
BRUTE FORCE OPTIONS:
  -f, --file <file>	Read subdomains from this file to perform brute force.
  -u, --update	<a|g|r|z>
			Update the file specified with the -f switch with valid subdomains.
	a (all)		Update using all results.
	g		Update using only google scraping results.
	r		Update using only reverse lookup results.
	z		Update using only zonetransfer results.
  -r, --recursion	Recursion on subdomains, brute force all discovred subdomains that have an NS record.
WHOIS NETRANGE OPTIONS:
  -d, --delay <value>	The maximum value of seconds to wait between whois queries, the value is defined randomly, default: 3s.
  -w, --whois		Perform the whois queries on c class network ranges.
			 **Warning**: this can generate very large netranges and it will take lot of time to performe reverse lookups.
REVERSE LOOKUP OPTIONS:
  -e, --exclude	<regexp>
			Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames.
OUTPUT OPTIONS:
  -o --output <file>	Output in XML format. Can be imported in MagicTree (www.gremwell.com)
};
        exit(1);
}

__END__


=head1 NAME

dnsenum.pl: multithread script to enumerate information on a domain and to discover non-contiguous IP blocks.

=head1 VERSION

dnsenum.pl version 1.2.4

=head1 SYNOPSIS

dnsenum.pl [options] <domain> -f dns.txt

=head1 DESCRIPTION

Supported operations:
nslookup, zonetransfer, google scraping, domain brute force
(support also recursion), whois ip and reverse lookups.


Operations:

=over 5

=item

1) Get the host's addresse (A record).

=item

2) Get the nameservers (threaded).

=item

3) Get the MX record (threaded).

=item

4) Perform AXFR queries on nameservers (threaded).

=item

5) Get extra names and subdomains via google scraping
(google query = "allinurl: -www site:domain").

=item

6) Brute force subdomains from  (REQUIRED), can also perform recursion on
subdomain that have NS records (all threaded).

=item

7) Calculate Class C IP network ranges from the results and perform whois queries on them (threaded).

=item

8) Perform reverse lookups on netranges (class C or/and whois netranges)(threaded).

=item

9) Write to domain_ips.txt file non-contiguous ip-blocks results.

=back

=head1 OPTIONS

The brute force -f switch is obligatory.

=head2 GENERAL OPTIONS:

=over

=over 30

=item B<--dnsserver> B<<server>>

Use this DNS server to perform all A, NS and MX queries,
 the AXFR and PTR queries are sent to the domain's NS servers.

=item B<--enum>

Shortcut option equivalent to --threads 5 -s 20 -w.

=item B<-h>,  B<--help>

Print the help message.

=item B<--noreverse>

Skip the reverse lookup operations.
 Reverse lookups can take long time on big netranges.

=item B<--nocolor>

Disable ANSIColor output.
 This option is only intended to be used on consoles that do not support
 color output.

=item B<--private>

Show and save private ips at the end of the file domain_ips.txt.

=item B<--subfile> B<<file>>

Write all valid subdomains to this file.
 Subdomains are taken from NS and MX records, zonetransfer,
 google scraping, brute force and reverse lookup hostnames.

=item B<-t>,  B<--timeout> B<<value>>

The tcp and udp timeout values in seconds (default: 10s).

=item B<--threads> B<<va


The number of threads that will perform different queries.

=item B<-v>,  B<--verbose>

Be verbose (show all the progress and all the error messages).

=back

=back

=over 3

B<Notes:>
neither the default domain nor the resolver search list are
appended to domains that don't contain any dots.

=back

=head2 GOOGLE SCRAPING OPTIONS:

=over 3

This function will scrap subdomains from google search,
using query: allinurl: -www site:domain.

=back

=over

=over 30

=item B<-p>,  B<--pages> B<<value>>

The number of google search pages to process when scraping names,
 the -s switch must be specified, (default: 20 pages).

=item B<-s>,  B<--scrap> B<<value>>

The maximum number of subdomains that will be scraped from google.

=back

=back

=over 3

B<NOTES:>
Google can block our queries with the malware detection.
Http proxy options for google scraping are automatically loaded from
the environment if the vars http_proxy or HTTP_PROXY are present.
"http_proxy=http://127.0.0.1:8118/" or "HTTP_PROXY=http://127.0.0.1:8118/".
On IO errors the mechanize browser object will automatically call die.

=back

=head2 BRUTE FORCE OPTIONS:

=over

=over 30

=item B<-f>,  B<--file> B<<file>>

Read subdomains from this file to perform brute force.

=item B<-u>,  B<--update> B<<a|g|r|z>>

Update the file specified with the -f switch with vaild subdomains.

=back

=back

=over 35

B<-u> a		Update using all results.

B<-u> g		Update using only google scraping results.

B<-u> r		Update using only reverse lookup results.

B<-u> z		Update using only zonetransfer results.

=back

=over

=over 30

=item B<-r>,  B<--recursion>

Recursion on subdomains, brute force all discovred subdomains
 that have an NS record.

=back

=back

=over 3

B<NOTES:>
To perform recursion first we must check previous subdomains results (zonetransfer, google scraping and brute force) for NS
records after that we perform brute force on valid subdomains that have NS records and so on. NS, MX and reverse lookup results are
not concerned.

=back

=head2 WHOIS IP OPTIONS:

Perform whois ip queries on c class netanges discovred from
previous operations.

=over

=over 30

=item B<-d>,  B<--delay> B<<value>>

The maximum value of seconds to wait between whois queries,
 the value is defined randomly, (default: 3s).

=back

=back

=over 3

B<NOTES:>
whois servers will limit the number of connections.

=back

=over

=over 30

=item B<-w>,  B<--whois>

Perform the whois queries on c class network ranges.
 B<Warning>: this can generate very large netranges and it
 will take lot of time to performe reverse lookups.

=back

=back

=over 3

B<NOTES:>
The whois query should recursively query the various whois
providers untile it gets the more detailed information including
either TechPhone or OrgTechPhone by default. See: perldoc Net::Whois::IP.
On errors the netrange will be a default c class /24.

=back

=head2 REVERSE LOOKUP OPTIONS:

=over

=over 30

=item B<-e>,  B<--exclude> B<<regexp>>

Exclude PTR records that match the regexp expression from reverse
 lookup results, useful on invalid hostnames.

=back

=back

=over 3

B<NOTES:>
PTR records that not match the domain are also excluded.
Verbose mode will show all results.

=back

=head1 OUTPUT FILES

Final non-contiguous ip blocks are writen to domain_ips.txt file.

B<NOTES:>
Final non-contiguous ip blocks are calculated :

=over 5

=item

1) From reverse lookups that were performed on netranges
( c class network ranges or whois netranges ).

=item

2) If the noreverse switch is used then they are calculated from
previous operations results (nslookups, zonetransfers,
google scraping and brute forcing).

=back

=head1 README

dnsenum.pl: multithread script to enumerate information on a domain
and to discover non-contiguous ip blocks.

=head1 PREREQUISITES

Modules that are included in perl 5.10.0:
  Getopt::Long, IO::File, Thread::Queue.

Other Necessary modules:
  Must have: Net::DNS, Net::IP, Net::Netmask.
  Optional: Net::Whois::IP, HTML::Parser, WWW::Mechanize.

Perl ithreads modules (perl must be compiled with ithreads support):
  threads, threads::shared.

=head1 AUTHORS

Filip Waeytens	<filip.waeytens[at]gmail.com>

tix tixxDZ	<tixxdz[at]gmail.com>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of
the License, or (at your option) any later version.

=head1 SCRIPT CATEGORIES

Networking 
DNS

=cut
