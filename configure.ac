#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([clusternetd], [0.1], [fdinitto@redhat.com])
AM_INIT_AUTOMAKE([-Wno-portability])
LT_PREREQ([2.2.6])
LT_INIT

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
AC_PROG_LIBTOOL

AC_LANG([C])

if test "$prefix" = "NONE"; then
	prefix="/usr"
	if test "$localstatedir" = "\${prefix}/var"; then
		localstatedir="/var"
	fi
	if test "$sysconfdir" = "\${prefix}/etc"; then
		sysconfdir="/etc"
	fi
fi

# Checks for programs.
if ! ${MAKE-make} --version /cannot/make/this >/dev/null 2>&1; then
	AC_MSG_ERROR([you don't seem to have GNU make; it is required])
fi
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_CXX
AC_PROG_RANLIB
AC_CHECK_PROGS([PKGCONFIG], [pkg-config])

## local helper functions
# this function checks if CC support options passed as
# args. Global CFLAGS are ignored during this test.
cc_supports_flag() {
	local CFLAGS="$@"
	AC_MSG_CHECKING([whether $CC supports "$@"])
	AC_COMPILE_IFELSE([int main(){return 0;}] ,
			  [RC=0; AC_MSG_RESULT([yes])],
			  [RC=1; AC_MSG_RESULT([no])])
	return $RC
}

# helper macro to check libs without adding them to LIBS
check_lib_no_libs() {
	lib_no_libs_arg1=$1
	shift
	lib_no_libs_arg2=$1
	shift
	lib_no_libs_args=$@
	AC_CHECK_LIB([$lib_no_libs_arg1],
		     [$lib_no_libs_arg2],,,
		     [$lib_no_libs_args])
        LIBS=$ac_check_lib_save_LIBS
}

# Checks for libraries.
PKG_CHECK_MODULES([logt],[liblogthread])
PKG_CHECK_MODULES([confdb],[libconfdb])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h netinet/in.h arpa/inet.h netdb.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit ftruncate memset strdup strtol setenv strcasecmp strchr strerror])

# local options
AC_ARG_ENABLE([debug],
	[  --enable-debug          enable debug build. ],
	[ default="no" ])

AC_ARG_WITH([syslogfacility],
	[  --syslogfacility=FACILITY
			  default syslog facility. ],
	[ SYSLOGFACILITY="$withval" ],
	[ SYSLOGFACILITY="LOG_LOCAL4" ])

AC_ARG_WITH([sysloglevel],
	[  --sysloglevel=LEVEL
			  default syslog level. ],
	[ SYSLOGLEVEL="$withval" ],
	[ SYSLOGLEVEL="LOG_INFO" ])

## random vars
LOGDIR=${localstatedir}/log/
RUNDIR=${localstatedir}/run/

## do subst

AC_DEFINE_UNQUOTED([CONFFILE], "$(eval echo ${sysconfdir}/clusternetd.conf)",
		   [Default config file])

AC_DEFINE_UNQUOTED([LOGDIR], "$(eval echo ${LOGDIR})",
		   [Default logging directory])

AC_DEFINE_UNQUOTED([RUNDIR], "$(eval echo ${RUNDIR})",
		   [Default run directory])

AC_DEFINE_UNQUOTED([SYSLOGFACILITY], $(eval echo ${SYSLOGFACILITY}),
		   [Default syslog facility])

AC_DEFINE_UNQUOTED([SYSLOGLEVEL], $(eval echo ${SYSLOGLEVEL}),
		   [Default syslog level])

## *FLAGS handling
ENV_CFLAGS="$CFLAGS"
ENV_CPPFLAGS="$CPPFLAGS"
ENV_LDFLAGS="$LDFLAGS"

# debug build stuff
if test "x${enable_debug}" = xyes; then
	AC_DEFINE_UNQUOTED([DEBUG], [1], [Compiling Debugging code])
	OPT_CFLAGS="-O0"
else
	OPT_CFLAGS="-O3"
fi

# gdb flags
if test "x${GCC}" = xyes; then
	GDB_FLAGS="-ggdb3"
else
	GDB_FLAGS="-g"
fi

# extra warnings
EXTRA_WARNINGS=""

WARNLIST="
	all
	shadow
	missing-prototypes
	missing-declarations
	strict-prototypes
	declaration-after-statement
	pointer-arith
	write-strings
	cast-align
	bad-function-cast
	missing-format-attribute
	format=2
	format-security
	format-nonliteral
	no-long-long
	unsigned-char
	gnu89-inline
	no-strict-aliasing
	error
	"

for j in $WARNLIST; do
	if cc_supports_flag -W$j; then
		EXTRA_WARNINGS="$EXTRA_WARNINGS -W$j";
	fi
done

CFLAGS="$ENV_CFLAGS $OPT_CFLAGS $GDB_FLAGS \
	$EXTRA_WARNINGS $WERROR_CFLAGS"
CPPFLAGS="$ENV_CPPFLAGS"
LDFLAGS="$ENV_LDFLAGS"

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
