#!/usr/bin/env ksh -p
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2015 by Brendon Humphrey (brendon.humphrey@mac.com). All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_upgrade/zpool_upgrade.cfg

#
# DESCRIPTION:
# Replication of OpenZFS bug 6183 (https://www.illumos.org/issues/6183)
#
# STRATEGY:
# 1. create a pool with specific version
# 2. incrementally upgrade pool and dataset until completion or failure.
#

verify_runnable "global"

function cleanup {
    destroy_pool $TESTPOOL
    destroy_pool $FILE_POOL
    if [[ -f $VDEV ]]; then
        log_must $RM -f $VDEV
    fi
}


log_assert "Executing specific zpool and zfs upgrade command succeeds (success = no panic)"

typeset VDEV=$TESTDIR/filepool.bin
typeset FILE_POOL=fp

if [[ -n "$OSX" ]]; then
    log_must $MKFILE $MKFILE_SPARSE 256m $VDEV
else
    log_must $MKFILE -s 256m $VDEV
fi

log_must $ZPOOL create -o version=1 -O version=1 $FILE_POOL $VDEV
$ZFS upgrade -V 2 $FILE_POOL
$ZFS upgrade -V 3 $FILE_POOL
$ZPOOL upgrade -V 9 $FILE_POOL
$ZFS upgrade -V 3 $FILE_POOL
$ZFS upgrade -V 4 $FILE_POOL
$ZPOOL upgrade -V 15 $FILE_POOL
$ZFS upgrade -V 4 $FILE_POOL

log_pass "Executing specific zpool and zfs upgrade command succeeds (success - no panic)"
