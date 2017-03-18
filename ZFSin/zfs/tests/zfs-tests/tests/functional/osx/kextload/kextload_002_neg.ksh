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

. $STF_SUITE/tests/functional/osx/kextload/kexts.kshlib

#
# DESCRIPTION:
# Verify that the kexts can NOT be unloaded when ZFS pools are in use.
#
# STRATEGY:
# 1. Initial state will be kexts loaded, prove it
# 2. Create a pool.
# 3. Attempt to unload kexts.
#


verify_runnable "both"

DISK=${DISKS%% *}
default_setup $DISK

log_onexit cleanup

#
# Attempt to unload the kexts
#
unload_kexts

#
# Prove that they didnt unload
#
log_must verify_kexts_loaded

log_pass