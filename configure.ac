#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.63])
AC_INIT([kronosnet],
	m4_esyscmd([build-aux/git-version-gen .tarball-version]),
	[devel@lists.kronosnet.org])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([1.11.1 dist-bzip2 dist-xz color-tests -Wno-portability])
# Usage of subdir-objects breaks make maintainer-clean targets.
# Not using it spits out some warnings at ./autogen time and we can live with those for now
# AM_INIT_AUTOMAKE([1.11.1 dist-bzip2 dist-xz color-tests -Wno-portability subdir-objects])
LT_PREREQ([2.2.6])
LT_INIT

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([kronosnetd/main.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
AC_PROG_LIBTOOL

AC_LANG([C])

systemddir=${prefix}/lib/systemd/system

if test "$prefix" = "NONE"; then
	prefix="/usr"
	if test "$localstatedir" = "\${prefix}/var"; then
		localstatedir="/var"
	fi
	if test "$sysconfdir" = "\${prefix}/etc"; then
		sysconfdir="/etc"
	fi
	if test "$systemddir" = "NONE/lib/systemd/system"; then
		systemddir=/lib/systemd/system
	fi
	if test "$libdir" = "\${exec_prefix}/lib"; then
		if test -e /usr/lib64; then
			libdir="/usr/lib64"
		else
			libdir="/usr/lib"
		fi
	fi
fi

# Checks for programs.
if ! ${MAKE-make} --version /cannot/make/this >/dev/null 2>&1; then
	AC_MSG_ERROR(["you don't seem to have GNU make; it is required"])
fi

AC_PROG_AWK
AC_PROG_GREP
AC_PROG_SED
AC_PROG_CPP
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_CXX
AC_PROG_RANLIB
AC_CHECK_PROGS([PUBLICAN], [publican], [:])
AC_CHECK_PROGS([PKGCONFIG], [pkg-config])

AC_ARG_ENABLE([kronosnetd],
        [  --enable-kronosnetd               : Kronosnetd support ],,
        [ enable_kronosnetd="no" ])
AM_CONDITIONAL([BUILD_KRONOSNETD], test x$enable_kronosnetd = xyes)

AC_ARG_ENABLE([libtap],
        [  --enable-libtap                   : libtap support ],,
        [ enable_libtap="no" ])

if test "x$enable_kronosnetd" = xyes; then
   enable_libtap=yes
fi
AM_CONDITIONAL([BUILD_LIBTAP], test x$enable_libtap = xyes)

## local helper functions
# this function checks if CC support options passed as
# args. Global CFLAGS are ignored during this test.
cc_supports_flag() {
	saveCPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$@"
	if echo $CC | grep -q clang; then
		CPPFLAGS="-Werror $CPPFLAGS"
	fi
	AC_MSG_CHECKING([whether $CC supports "$@"])
	AC_PREPROC_IFELSE([AC_LANG_PROGRAM([])],
			  [RC=0; AC_MSG_RESULT([yes])],
			  [RC=1; AC_MSG_RESULT([no])])
	CPPFLAGS="$saveCPPFLAGS"
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

# Checks for C features
AC_C_INLINE

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([m], [ceil])
AC_CHECK_LIB([rt], [clock_gettime])

PKG_CHECK_MODULES([nss],[nss])
PKG_CHECK_MODULES([libqb], [libqb])

AC_CHECK_LIB([qb], [qb_log_thread_priority_set],
	     [have_qb_log_thread_priority_set="yes"],
             [have_qb_log_thread_priority_set="no"])

if test "x${have_qb_log_thread_priority_set}" = xyes; then
	AC_DEFINE_UNQUOTED([HAVE_QB_LOG_THREAD_PRIORITY_SET], 1, [have qb_log_thread_priority_set])
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT32_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([atexit])
AC_CHECK_FUNCS([ftruncate])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([clock_gettime])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([sendmmsg])
AC_CHECK_FUNCS([recvmmsg])

# Check entries in specific structs
AC_CHECK_MEMBER([struct mmsghdr.msg_hdr],
                [AC_DEFINE_UNQUOTED([HAVE_MMSGHDR], [1], [struct mmsghdr exists])],
                [], [[#include <sys/socket.h>]])

# PAM check (for kronosnetd)
if test "x$enable_kronosnetd" = xyes; then
AC_CHECK_HEADERS([security/pam_appl.h],
		 [AC_CHECK_LIB([pam], [pam_start])],
		 [AC_MSG_ERROR([Unable to find LinuxPAM devel files])])


AC_CHECK_HEADERS([security/pam_misc.h],
	        [AC_CHECK_LIB([pam_misc], [misc_conv])],
                [AC_MSG_ERROR([Unable to find LinuxPAM MISC devel files])])

fi

# local options
AC_ARG_ENABLE([debug],
	[  --enable-debug          enable debug build. ],
	[ default="no" ])

AC_ARG_ENABLE([publicandocs],
	[  --enable-publicandocs   enable docs build. ],
	[ default="no" ])

AC_ARG_WITH([initdefaultdir],
	[  --with-initdefaultdir   : path to /etc/sysconfig/.. or /etc/default dir. ],
	[ INITDEFAULTDIR="$withval" ],
	[ INITDEFAULTDIR="$sysconfdir/default" ])

AC_ARG_WITH([initddir],
	[  --with-initddir=DIR     : path to init script directory. ],
	[ INITDDIR="$withval" ],
	[ INITDDIR="$sysconfdir/init.d" ])

AC_ARG_WITH([systemddir],
	[  --with-systemddir=DIR   : path to systemd unit files directory. ],
	[ SYSTEMDDIR="$withval" ],
	[ SYSTEMDDIR="$systemddir" ])

AC_ARG_WITH([syslogfacility],
	[  --with-syslogfacility=FACILITY
			  default syslog facility. ],
	[ SYSLOGFACILITY="$withval" ],
	[ SYSLOGFACILITY="LOG_DAEMON" ])

AC_ARG_WITH([sysloglevel],
	[  --with-sysloglevel=LEVEL
			  default syslog level. ],
	[ SYSLOGLEVEL="$withval" ],
	[ SYSLOGLEVEL="LOG_INFO" ])

AC_ARG_WITH([defaultadmgroup],
	[  --with-defaultadmgroup=GROUP
			  define PAM group. Users part of this group will be
			  allowed to configure kronosnet. Others will only
			  receive read-only rights. ],
	[ DEFAULTADMGROUP="$withval" ],
	[ DEFAULTADMGROUP="kronosnetadm" ])

## random vars
LOGDIR=${localstatedir}/log/
RUNDIR=${localstatedir}/run/
DEFAULT_CONFIG_DIR=${sysconfdir}/kronosnet

## do subst

AM_CONDITIONAL([BUILD_DOCS], [test "x${enable_publicandocs}" = xyes])

AC_SUBST([DEFAULT_CONFIG_DIR])
AC_SUBST([INITDEFAULTDIR])
AC_SUBST([INITDDIR])
AC_SUBST([SYSTEMDDIR])
AC_SUBST([LOGDIR])
AC_SUBST([DEFAULTADMGROUP])

AC_DEFINE_UNQUOTED([DEFAULT_CONFIG_DIR],
		   ["$(eval echo ${DEFAULT_CONFIG_DIR})"],
		   [Default config directory])

AC_DEFINE_UNQUOTED([DEFAULT_CONFIG_FILE],
		   ["$(eval echo ${DEFAULT_CONFIG_DIR}/kronosnetd.conf)"],
		   [Default config file])

AC_DEFINE_UNQUOTED([LOGDIR],
		   ["$(eval echo ${LOGDIR})"],
		   [Default logging directory])

AC_DEFINE_UNQUOTED([DEFAULT_LOG_FILE],
		   ["$(eval echo ${LOGDIR}/kronosnetd.log)"],
		   [Default log file])

AC_DEFINE_UNQUOTED([RUNDIR],
		   ["$(eval echo ${RUNDIR})"],
		   [Default run directory])

AC_DEFINE_UNQUOTED([SYSLOGFACILITY],
		   [$(eval echo ${SYSLOGFACILITY})],
		   [Default syslog facility])

AC_DEFINE_UNQUOTED([SYSLOGLEVEL],
		   [$(eval echo ${SYSLOGLEVEL})],
		   [Default syslog level])

AC_DEFINE_UNQUOTED([DEFAULTADMGROUP],
		   ["$(eval echo ${DEFAULTADMGROUP})"],
		   [Default admin group])

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
	address
	cpp
	overflow
	parentheses
	sequence-point
	switch
	uninitialized
	unused-but-set-variable
	unused-function
	unused-result
	unused-value
	unused-variable
	"

for j in $WARNLIST; do
	if cc_supports_flag -W$j; then
		EXTRA_WARNINGS="$EXTRA_WARNINGS -W$j";
	fi
done

CFLAGS="$ENV_CFLAGS $lt_prog_compiler_pic $OPT_CFLAGS $GDB_FLAGS \
	$EXTRA_WARNINGS $WERROR_CFLAGS"
CPPFLAGS="$ENV_CPPFLAGS"
LDFLAGS="$ENV_LDFLAGS $lt_prog_compiler_pic -Wl,--as-needed"

AC_CONFIG_FILES([
		Makefile
		common/Makefile
		init/Makefile
		libtap/Makefile
		libtap/libtap.pc
		kronosnetd/Makefile
		kronosnetd/kronosnetd.logrotate
		libknet/Makefile
		libknet/libknet.pc
		libknet/tests/Makefile
		docs/Makefile
		])

AC_OUTPUT
