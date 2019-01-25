dnl #
dnl # Detect Darwin (or not)
dnl #
AC_DEFUN([ZFS_AC_SYSTEM], [
	AC_MSG_CHECKING([if OS is Windows])
	_uname=$(uname -s)
	AS_IF([test "${_uname}" = "CYGWIN*"], [
			WINDOWS="yes"

			ZONENAME="echo global"
			AC_SUBST(ZONENAME)
		])
	AC_MSG_RESULT([$WINDOWS])

	AC_SUBST(WINDOWS)
])
