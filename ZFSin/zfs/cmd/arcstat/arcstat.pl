#!/usr/bin/perl 
#
# $Id: arcstat.pl,v 389:6a4ad672a88a 2011-08-14 03:40:05Z jhell $
#
# Print out ZFS ARC Statistics exported via kstat(1)
# For a definition of fields, or usage, use arctstat.pl -v
#
# Author: Neelakanth Nadgir http://blogs.sun.com/realneel
# Comments/Questions/Feedback to neel_sun.com or neel_gnu.org
#
# CDDL HEADER START
# 
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
# 
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
# 
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
# 
# CDDL HEADER END
#
#
# Fields have a fixed width. Every interval, we fill the "v"
# hash with its corresponding value (v[field]=value) using calculate(). 
# @hdr is the array of fields that needs to be printed, so we
# just iterate over this array and print the values using our pretty printer.

use strict;
use POSIX qw(strftime);
use Getopt::Long;
use IO::Handle;

my %cols = (# HDR => [Size, Description]
	"Time"	=>[8, "Time"],
	"hits"	=>[5, "Arc reads per second"],
	"miss"	=>[5, "Arc misses per second"],
	"read"	=>[5, "Total Arc accesses per second"],
	"Hit%"	=>[4, "Arc Hit percentage"],
	"miss%"	=>[5, "Arc miss percentage"],
	"dhit"	=>[5, "Demand Data hits per second"],
	"dmis"	=>[5, "Demand Data misses per second"],
	"dh%"	=>[3, "Demand Data hit percentage"],
	"dm%"	=>[3, "Demand Data miss percentage"],
	"phit"	=>[4, "Prefetch hits per second"],
	"pmis"	=>[4, "Prefetch misses per second"],
	"ph%"	=>[3, "Prefetch hits percentage"],
	"pm%"	=>[3, "Prefetch miss percentage"],
	"mhit"	=>[5, "Metadata hits per second"],
	"mmis"	=>[5, "Metadata misses per second"],
	"mread"	=>[5, "Metadata accesses per second"],
	"mh%"	=>[3, "Metadata hit percentage"],
	"mm%"	=>[3, "Metadata miss percentage"],
	"size"	=>[5, "Arc Size"],
	"tsize"	=>[5, "Arc Target Size"],
	"mfu" 	=>[5, "MFU List hits per second"],
	"mru" 	=>[5, "MRU List hits per second"],
	"mfug" 	=>[5, "MFU Ghost List hits per second"],
	"mrug" 	=>[5, "MRU Ghost List hits per second"],
	"eskip"	=>[5, "evict_skip per second"],
	"mtxmis"=>[6, "mutex_miss per second"],
	"rmis"	=>[5, "recycle_miss per second"],
	"dread"	=>[5, "Demand data accesses per second"],
	    "pread"	=>[5, "Prefetch accesses per second"],
	    "l2read" =>[5, "L2ARC reads per second"],
	    "l2write" =>[5, "L2ARC writes per second"],
	    "l2hits" =>[5, "L2ARC hits per second"],
	    "l2miss" =>[5, "L2ARC misses per second"],
	    "l2Hit%" =>[4, "L2ARC Hit%"],
	    "l2miss%" =>[4, "L2ARC miss%"],
	    "comprs" =>[5, "bytes of cache consumed by compressed blocks"],
	    "uncomp" =>[5, "bytes required to cache compress if the same data decompressed"],
	    "ovrhd" =>[5, "amount of uncompressed data cache is currently using"],
	    "cap%" =>[4, "capacity of arc"],
	    "rat%" =>[4, "ratio between uncompressed and compressed size"],
	    "redirt" =>[6, "number of calls to dbuf_redirty()"],
);
my %v=();
my @hdr = qw(Time read miss miss% dmis dm% pmis pm% mmis mm% size tsize);
my @xhdr = qw(Time mfu mru mfug mrug eskip mtxmis rmis dread pread read);
my $int = 1;		# Print stats every 1 second by default
my $count = 0;		# Print stats forever
my $hdr_intr = 20;	# Print header every 20 lines of output
my $opfile = "";
my $sep = "  ";		# Default seperator is 2 spaces
my $rflag = 0;		# Do not display pretty print by default
my $version = "0.1";
my $cmd = "Usage: arcstat.pl [-hvx] [-f fields] [-o file] [interval [count]]\n";
my %cur;
my %d;
my $out;
my $kstat; # = Sun::Solaris::Kstat->new();
STDOUT->autoflush;

sub kstat_update {
	$/ = "\r\n";  # Handle Unix \r\n input
	my @k = `./kstat.exe 'zfs:0:arcstats'`;
	if (!@k) { exit 1 };

	undef $kstat;

	foreach my $k (@k) {
		chomp $k;
		$k =~ m/^\s*(\S+)\s*(.*)\s*/;
		${kstat}->{zfs}->{0}->{arcstats}->{$1} = $2;
	}
}

sub detailed_usage {
	print STDERR "Arcstat version $version\n$cmd";
	print STDERR "Field definitions are as follows\n";
	foreach my $hdr (keys %cols) {
		print STDERR sprintf("%6s : %s\n", $hdr, $cols{$hdr}[1]);
	}
	print STDERR "\nNote: K=10^3 M=10^6 G=10^9 and so on\n";
	exit(1);

}

sub usage {
	print STDERR "Arcstat version $version\n$cmd";
	print STDERR "\t -x : Print extended stats\n";
	print STDERR "\t -f : Specify specific fields to print (see -v)\n";
	print STDERR "\t -o : Print stats to file\n";
	print STDERR "\t -r : Raw output\n";
	print STDERR "\t -s : Specify a seperator\n\nExamples:\n";
	print STDERR "\tarcstat -o /tmp/a.log 2 10\n";
	print STDERR "\tarcstat -s , -o /tmp/a.log 2 10\n";
	print STDERR "\tarcstat -v\n";
	print STDERR "\tarcstat -f Time,Hit%,dh%,ph%,mh%\n";
	exit(1);
}

sub init {
	my $desired_cols;
	my $xflag = '';
	my $hflag = '';
	my $vflag;
	my $res = GetOptions('x' => \$xflag,
		'o=s' => \$opfile,
		'help|h|?' => \$hflag,
		'v' => \$vflag,
		'r' => \$rflag,
		's=s' => \$sep,
		'f=s' => \$desired_cols);
	$int = $ARGV[0] || $int;
	$count = $ARGV[1] || $count;
	usage() if !$res or $hflag or ($xflag and $desired_cols);
	detailed_usage() if $vflag;
	@hdr = @xhdr if $xflag;		#reset headers to xhdr

	# we want to capture the stats here, so that we can use them to check
	# if an L2ARC device exists; but more importantly, so that we print
	# the stats since boot as the first line of output from main().
	snap_stats();

	if ($desired_cols) {
		@hdr = split(/[ ,]+/, $desired_cols);
		# Now check if they are valid fields
		my @invalid = ();
		foreach my $ele (@hdr) {
			push(@invalid, $ele) if not exists($cols{$ele});
		}
		if (scalar @invalid > 0) {
			print STDERR "Invalid column definition! -- "
				. "@invalid\n\n";
			usage();
		}
	}
	if ($opfile) {
		open($out, ">$opfile") ||die "Cannot open $opfile for writing";
		$out->autoflush;
		select $out;
	}
}

# Capture kstat statistics. We maintain 3 hashes, prev, cur, and
# d (delta). As their names imply they maintain the previous, current,
# and delta (cur - prev) statistics.
sub snap_stats {
	my %prev = %cur;
	kstat_update();

	my $hashref_cur = $kstat->{"zfs"}{0}{"arcstats"};
	%cur = %$hashref_cur;
	foreach my $key (keys %cur) {
		next if $key =~ /class/;
		if (defined $prev{$key}) {
			$d{$key} = $cur{$key} - $prev{$key};
		} else {
			$d{$key} = $cur{$key};
		}
	}
}

# Pretty print num. Arguments are width and num
sub prettynum {
	my @suffix=(' ','K', 'M', 'G', 'T', 'P', 'E', 'Z');
	my $num = $_[1] || 0;
	my $sz = $_[0];
	my $index = 0;
	return sprintf("%*s", $sz, $num) if ($rflag or not $num =~ /^[0-9\.]+$/);
	while ($num >= 10000 and $index < 8) {
		$num = $num/1000;
		$index++;
	}
	if ($index == 0) {
		if ((($num - int($num)) == 0)) {
			return sprintf("%*d", $sz, $num);
		} else {
			return sprintf("%*.1f", $sz, $num);
		}
	} else {
		return sprintf("%*d%s", $sz - 1, $num,$suffix[$index]);
	}
}

#1		1
#10		10
#100		100
#1000		1000
#10000		10K
#100000		100K
#1000000	1000K
#10000000	10M
#100000000	100M
#1000000000	1000M

sub print_values {
	foreach my $col (@hdr) {
		printf("%s%s", prettynum($cols{$col}[0], $v{$col}), $sep);
	}
	printf("\n");
}

sub print_header {
	foreach my $col (@hdr) {
		printf("%*s%s", $cols{$col}[0], $col, $sep);
	}
	printf("\n");
}

sub calculate {
	%v=();
	$v{"Time"} = strftime("%H:%M:%S", localtime);
	$v{"hits"} = $d{"hits"}/$int;
	$v{"l2hits"} = $d{"l2_hits"}/$int;
	$v{"l2miss"} = $d{"l2_misses"}/$int;
	$v{"miss"} = $d{"misses"}/$int;
	$v{"read"} = $v{"hits"} + $v{"miss"};
	$v{"l2read"} = $d{"l2_read_bytes"}/$int;
	$v{"l2write"} = $d{"l2_write_bytes"}/$int;
	$v{"l2Hit%"} = 100*$v{"l2hits"}/$v{"l2miss"} if $v{"l2miss"} > 0;
	$v{"l2miss%"} = 100 - $v{"l2Hit%"} if $v{"l2miss"} > 0;
	$v{"Hit%"} = 100*$v{"hits"}/$v{"read"} if $v{"read"} > 0;
	$v{"miss%"} = 100 - $v{"Hit%"} if $v{"read"} > 0;

	$v{"dhit"} = ($d{"demand_data_hits"} + $d{"demand_metadata_hits"})/$int;
	$v{"dmis"} = ($d{"demand_data_misses"}+$d{"demand_metadata_misses"})/$int;
	$v{"dread"} = $v{"dhit"} + $v{"dmis"};
	$v{"dh%"} = 100*$v{"dhit"}/$v{"dread"} if $v{"dread"} > 0;
	$v{"dm%"} = 100 - $v{"dh%"} if $v{"dread"} > 0;

	$v{"phit"}=($d{"prefetch_data_hits"} + $d{"prefetch_metadata_hits"})/$int;
	$v{"pmis"}=($d{"prefetch_data_misses"}
		+$d{"prefetch_metadata_misses"})/$int;
	$v{"pread"} = $v{"phit"} + $v{"pmis"};
	$v{"ph%"} = 100*$v{"phit"}/$v{"pread"} if $v{"pread"} > 0;
	$v{"pm%"} = 100 - $v{"ph%"} if $v{"pread"} > 0;

	$v{"mhit"}=($d{"prefetch_metadata_hits"}+$d{"demand_metadata_hits"})/$int;
	$v{"mmis"}=($d{"prefetch_metadata_misses"}
		+$d{"demand_metadata_misses"})/$int;
	$v{"mread"} = $v{"mhit"} + $v{"mmis"};
	$v{"mh%"} = 100*$v{"mhit"}/$v{"mread"} if $v{"mread"} > 0;
	$v{"mm%"} = 100 - $v{"mh%"} if $v{"mread"} > 0;

	$v{"size"} = $cur{"size"};
	$v{"tsize"} = $cur{"c"};
	$v{"mfu"} = $d{"hits"}/$int;
	$v{"mru"} = $d{"mru_hits"}/$int;
	$v{"mrug"} = $d{"mru_ghost_hits"}/$int;
	$v{"mfug"} = $d{"mru_ghost_hits"}/$int;
	$v{"eskip"} = $d{"evict_skip"}/$int;
	$v{"rmiss"} = $d{"recycle_miss"}/$int;
	$v{"mtxmis"} = $d{"mutex_miss"}/$int;

	$v{"comprs"} = $cur{"compressed_size"};
	$v{"uncomp"} = $cur{"uncompressed_size"};
	$v{"ovrhd"} = $cur{"overhead_size"};

	$v{"rat%"} = 100*$v{"uncomp"}/$v{"comprs"} if $v{"comprs"} > 0;

	$v{"redirt"} = $d{"dbuf_redirtied"}/$int;

}

sub main {
	my $i = 0;
	my $count_flag = 0;

	init();
	if ($count > 0) { $count_flag = 1; }
	while (1) {
		print_header() if ($i == 0);
		calculate();
		print_values();
		last if ($count_flag == 1 && $count-- <= 1);
		$i = ($i == $hdr_intr) ? 0 : $i+1;
		sleep($int);
		snap_stats();
	}
	close($out) if defined $out;
}

&main;
