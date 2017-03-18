/*
 * This file is part of the 'Automated ZFS Test Suite'
 *
 * Copyright (c) 2014 Turbo Fredriksson <turbo@bayour.com>
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

AC_INIT([zfs-test], [0.9])
AC_LANG(C)
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_CANONICAL_SYSTEM
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AS

PREFIX=`/bin/pwd`
AC_SUBST(PREFIX)

m4_include(config/system.m4)
m4_include(config/commands-common.m4)
m4_include(config/commands-linux.m4)
m4_include(config/commands-bsd.m4)

ZFS_AC_SYSTEM

AC_CONFIG_FILES([ 
	Makefile
	zfs-tests/cmd/largest_file/Makefile
	zfs-tests/cmd/mkbusy/Makefile
	zfs-tests/cmd/file_trunc/Makefile
	zfs-tests/cmd/readmmap/Makefile
	zfs-tests/cmd/file_write/Makefile
	zfs-tests/cmd/randfree_file/Makefile
	zfs-tests/cmd/mktree/Makefile
	zfs-tests/cmd/file_check/Makefile
	zfs-tests/cmd/rm_lnkcnt_zero_file/Makefile
	zfs-tests/cmd/chg_usr_exec/Makefile
	zfs-tests/cmd/mmapwrite/Makefile
	zfs-tests/tests/functional/exec/Makefile
	zfs-tests/tests/functional/ctime/Makefile
	zfs-tests/include/commands.cfg
	zfs-tests/runfiles/osx.run
	zfs-tests/include/default.cfg
])

AC_OUTPUT
