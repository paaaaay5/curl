#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
# Verify the HAProxy PROXY protocol version 2 header at the start of a
# protocol dump. The version 2 header is binary and carries a random source
# port, so it cannot be compared verbatim in a <protocol> section.
#
# Usage:
#
#   test3234.pl FILE FAMILY [KEY=VALUE ...]
#
# FILE    the protocol dump to read, normally %LOGDIR/server.input
# FAMILY  the expected address family and transport: tcp4, tcp6 or unix
#
# Recognized KEY=VALUE pairs, all optional:
#
#   src=ADDR      expected source address, or socket path for "unix"
#   dst=ADDR      expected destination address, or socket path for "unix"
#   sport=N       expected source port, or "nonzero" to only require it set
#   dport=N       expected destination port, or "nonzero"
#   req=NUM       the header must be directly followed by the HTTP request
#                 line "GET /NUM HTTP/1.1"
#
# Note that no argument may contain a "<" or a ">" since the test files that
# invoke this script are checked by xmllint.

use strict;
use warnings;

my $sig = pack("C*", 0x0D, 0x0A, 0x0D, 0x0A, 0x00,
                     0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A);

# family name => [ fam byte, address block length, address size ]
my %families = (
    "tcp4" => [ 0x11,  12,   4 ],
    "tcp6" => [ 0x21,  36,  16 ],
    "unix" => [ 0x31, 216, 108 ],
);

my $errors = 0;

sub fail {
    print STDERR "test3234.pl: @_\n";
    $errors++;
}

sub check {
    my ($what, $got, $want) = @_;
    fail("$what is $got, expected $want") if $got ne $want;
}

# Convert a printable address into its network representation, so that
# comparisons do not depend on how the address is formatted.
sub addr_to_bytes {
    my ($family, $text) = @_;
    if($family eq "tcp4") {
        my @o = split(/\./, $text, -1);
        return undef if scalar(@o) != 4;
        for my $o (@o) {
            return undef if $o !~ /^[0-9]+$/ || $o > 255;
        }
        return pack("C4", @o);
    }
    # tcp6
    my $packed;
    my $ok = eval {
        require Socket;
        $packed = Socket::inet_pton(Socket::AF_INET6(), $text);
        1;
    };
    if(!$ok) {
        fail("cannot convert IPv6 address $text: this perl has no working " .
             "Socket::inet_pton()");
        return undef;
    }
    return $packed;
}

my $file = shift @ARGV;
my $family = shift @ARGV;

if(!defined $file || !defined $family || !$families{$family}) {
    print STDERR "usage: test3234.pl FILE tcp4|tcp6|unix [KEY=VALUE ...]\n";
    exit 1;
}

my %want;
for my $arg (@ARGV) {
    if($arg =~ /^([a-z]+)=(.*)$/) {
        $want{$1} = $2;
    }
    else {
        print STDERR "test3234.pl: cannot parse argument '$arg'\n";
        exit 1;
    }
}

my ($wantfam, $blocklen, $addrsize) = @{$families{$family}};
my $hdrlen = 16 + $blocklen;

open(my $fh, "<", $file) or die "test3234.pl: cannot open $file: $!";
binmode $fh;
my $dump = do { local $/; readline($fh) };
close $fh;
$dump = "" if !defined $dump;

if(length($dump) < $hdrlen) {
    fail(sprintf("dump is %d bytes, need at least %d for a %s header",
                 length($dump), $hdrlen, $family));
    exit 1;
}

fail("signature mismatch: " . unpack("H*", substr($dump, 0, 12)))
    if substr($dump, 0, 12) ne $sig;

my ($vercmd, $fam, $len) = unpack("CCn", substr($dump, 12, 4));

# protocol version 2 (0x20) with the PROXY command (0x01)
check("version/command byte", sprintf("0x%02x", $vercmd), "0x21");
check("family/transport byte", sprintf("0x%02x", $fam),
      sprintf("0x%02x", $wantfam));
check("address block length", $len, $blocklen);

# The source and destination addresses both sit at the start of the address
# block and are of the same size.
my %offset = (
    "src" => 16,
    "dst" => 16 + $addrsize,
);

for my $which ("src", "dst") {
    next if !defined $want{$which};
    my $got = substr($dump, $offset{$which}, $addrsize);
    my $expected = $want{$which};

    if($family eq "unix") {
        # a path occupies a fixed size, NUL padded field
        if(length($expected) > $addrsize) {
            fail("$which path is longer than $addrsize bytes");
            next;
        }
        check("$which path", unpack("Z*", $got), $expected);
        my $padding = substr($got, length($expected));
        fail("$which path is not NUL padded: " . unpack("H*", $padding))
            if $padding ne ("\0" x length($padding));
    }
    else {
        my $bytes = addr_to_bytes($family, $expected);
        next if !defined $bytes;
        check("$which address", unpack("H*", $got), unpack("H*", $bytes));
    }
}

# AF_UNIX carries no ports at all
if($family eq "unix") {
    for my $which ("sport", "dport") {
        fail("$which cannot be checked for the unix family")
            if defined $want{$which};
    }
}
else {
    my @ports = unpack("nn", substr($dump, 16 + 2 * $addrsize, 4));
    my %got = ("sport" => $ports[0], "dport" => $ports[1]);
    for my $which ("sport", "dport") {
        next if !defined $want{$which};
        if($want{$which} eq "nonzero") {
            fail("$which is zero, expected it to be set") if !$got{$which};
        }
        else {
            check($which, $got{$which}, $want{$which});
        }
    }
}

# The request must start immediately after the header, with nothing in
# between and nothing consumed from it.
if(defined $want{"req"}) {
    my $rest = substr($dump, $hdrlen);
    my $expected = "GET /$want{'req'} HTTP/1.1";
    if(substr($rest, 0, length($expected)) ne $expected) {
        fail("header is not followed by '$expected' but by '" .
             substr($rest, 0, length($expected)) . "'");
    }
}

if($errors) {
    print STDERR "test3234.pl: first 48 bytes: " .
        unpack("H*", substr($dump, 0, 48)) . "\n";
    exit 1;
}

exit 0;
