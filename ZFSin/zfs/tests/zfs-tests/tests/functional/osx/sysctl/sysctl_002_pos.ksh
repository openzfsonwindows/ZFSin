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

. $STF_SUITE/tests/functional/osx/sysctl/sysctl.kshlib

#
# DESCRIPTION:
# Check that all dataset related kstats are published via OSX sysctl.
#
# STRATEGY:
#
#

log_assert "Per dataset kstats are created and destroyed as dataset is imported and exported"

log_onexit cleanup

DISK=${DISKS%% *}
default_setup $DISK

#log_must $ZPOOL create $TESTPOOL $DISK

#
# Check the POOL sysctls
#
while (( i < ${#POOL_SYSCTLS[@]} )); do
	typeset OID=${${POOL_SYSCTLS[i]}/POOL/$TESTPOOL}
	log_must sysctl_exists $OID
	(( i += 1 ))
done

#
# Export pool and change that they have gone
#

log_must $ZPOOL export $TESTPOOL

while (( i < ${#POOL_SYSCTLS[@]} )); do
	typeset OID=${${POOL_SYSCTLS[i]}/POOL/$TESTPOOL}
	log_mustnot sysctl_exists $OID
	(( i += 1 ))
done

log_pass