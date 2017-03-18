#!/bin/ksh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_rename/zfs_rename.kshlib

#
# DESCRIPTION:
#       'zfs rename' can successfully rename a volume snapshot.
#
# STRATEGY:
#       1. Create a snapshot of volume.
#       2. Rename volume snapshot to a new one.
#	3. Rename volume to a new one.
#       5. Verify that the rename operations are successful and zfs list can
#	   list them.
#
###############################################################################

verify_runnable "global"

#
# cleanup defined in zfs_rename.kshlib
#
log_onexit cleanup

log_assert "'zfs rename' can successfully rename a volume snapshot."

vol=$TESTPOOL/$TESTVOL
snap=$TESTSNAP

typeset vol_dev
if [[ -n "$OSX" ]]; then
	vol_dev=$(find_zvol_rpath $vol)
else
	vol_dev=${VOL_R_PATH}
fi

log_must eval "$DD if=$DATA of=$vol_dev bs=$BS count=$CNT >/dev/null 2>&1"
if ! snapexists $vol@$snap; then
	log_must $ZFS snapshot $vol@$snap
fi

rename_dataset $vol@$snap $vol@${snap}-new
rename_dataset $vol ${vol}-new
rename_dataset ${vol}-new@${snap}-new ${vol}-new@$snap
rename_dataset ${vol}-new $vol

if [[ -n "$OSX" ]]; then
	vol_dev=$(find_zvol_rpath $vol)
	vol_snap_dev=$(find_zvol_rpath $vol@$snap)
else
	vol_dev=${VOL_R_PATH}
	vol_snap_dev=$vol_dev@$snap
fi

#verify data integrity
for input in $vol_dev $vol_snap_dev; do
	log_must eval "$DD if=$input of=$VOLDATA bs=$BS count=$CNT >/dev/null 2>&1"
	if ! cmp_data $VOLDATA $DATA ; then
		log_fail "$input gets corrupted after rename operation."
	fi
done

destroy_dataset $vol@$snap

log_pass "'zfs rename' can rename volume snapshot as expected."
