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
# Check that all "base" kstats are published via OSX sysctl.
#
# STRATEGY:
#
#

log_assert "kstats are published as sysctls."
log_onexit cleanup

typeset -i i=0

#
# Check the SPL sysctls
#
while (( i < ${#SPL_SYSCTLS[@]} )); do
	log_must sysctl_exists ${SPL_SYSCTLS[i]}
	(( i += 1 ))
done

#
# Check the ZFS sysctls
#
while (( i < ${#ZFS_SYSCTLS[@]} )); do
	log_must sysctl_exists ${ZFS_SYSCTLS[i]}
	(( i += 1 ))
done

#
# Check the ZFS sysctls
#
while (( i < ${#ZFS_TUNEABLE_SYSCTLS[@]} )); do
	log_must sysctl_exists ${ZFS_TUNEABLE_SYSCTLS[i]}
	(( i += 1 ))
done



log_pass
