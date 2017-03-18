dnl # We have some wrappers to empulate BSD commands here
export PATH=$PATH:`pwd`/scripts

dnl # Give a pretty explanation if a command is missing
MISSING_CMD="MISSING_CMD=`pwd`/scripts/missing_cmd \$missingcmd"
AC_SUBST(MISSING_CMD)
# AC_PATH_TOOL(CLRI, clri, "eval\ missingcmd=clri\;\ \$MISSING_CMD")

AC_PATH_TOOL(COMPRESS, gzip, "")
AC_PATH_TOOL(FORMAT, parted, "")
AC_PATH_TOOL(LOCKFS, lsof, "")
AC_PATH_TOOL(MODUNLOAD, rmmod, "")
AC_PATH_TOOL(NEWFS, mke2fs, "")
AC_PATH_TOOL(PACK, jar, "")
AC_PATH_TOOL(SHARE, exportfs, "")
AC_PATH_TOOL(SWAP, swapon, "")
AC_PATH_TOOL(TUNEFS, tune2fs, "")
AC_PATH_TOOL(UFSDUMP, dump, "")
AC_PATH_TOOL(UFSRESTORE, restore, "")
AC_PATH_TOOL(UNCOMPRESS, gunzip, "")
AC_PATH_TOOL(UNPACK, jar, "")
AC_PATH_TOOL(UNSHARE, exportfs, "")
AC_PATH_TOOL(GETENT, getent, "")
AC_PATH_TOOL(KPARTX, kpartx, "")
AC_PATH_TOOL(GETFACL, getfacl, "")
AC_PATH_TOOL(SETFACL, setfacl, "")
AC_PATH_TOOL(CHACL, chacl, "")

AC_CHECK_FILE([/etc/mtab], [MNTTAB=/etc/mtab], [])
