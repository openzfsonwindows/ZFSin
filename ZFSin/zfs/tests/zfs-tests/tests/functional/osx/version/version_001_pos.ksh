#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright (C) 2016 Brendon Humphrey (brendon.humphrey@mac.com). All rights reserved.
#
# Use is subject to license terms.
#
. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
# Fetch and output the ZFS and SPL version log strings
#

verify_runnable "both"

typeset spl_version=`sysctl -a | grep "spl.kext_version" | cut -d" " -f2`
typeset zfs_version=`sysctl -a | grep "zfs.kext_version" | cut -d" " -f2`

if [[ -z "$spl_version" ]]; then
	log_fail "Unable to determine SPL version string"
elif [[ -z "$zfs_version" ]]; then
	log_fail "Unable to determine ZFS version string"
else
	log_pass "Tests run against ZFS->$zfs_version, SPL->$spl_version."
fi

