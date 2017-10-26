#
# Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
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
AM_INIT_AUTOMAKE([1.13 dist-bzip2 dist-xz color-tests -Wno-portability subdir-objects])
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

AC_PROG_AWK
AC_PROG_GREP
AC_PROG_SED
AC_PROG_CPP
AC_PROG_CC
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno"; then
	AC_MSG_ERROR(["C99 support is required"])
fi
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG
AC_CHECK_PROGS([PUBLICAN], [publican], [:])
AC_CHECK_PROGS([VALGRIND_EXEC], [valgrind])
AM_CONDITIONAL([HAS_VALGRIND], [test x$VALGRIND_EXEC != "x"])

AC_ARG_ENABLE([libknet-sctp],
	[  --disable-libknet-sctp            : disable libknet SCTP support ],,
	[ enable_libknet_sctp="yes" ])
AM_CONDITIONAL([BUILDSCTP], [test x$enable_libknet_sctp = xyes])

AC_ARG_ENABLE([crypto-all],
	[  --disable-crypto-all              : disable libknet all crypto modules support ],,
	[ enable_crypto_all="yes" ])

AC_ARG_ENABLE([crypto-nss],
	[  --disable-crypto-nss              : disable libknet nss support ],,
	[ enable_crypto_nss="$enable_crypto_all" ])
AM_CONDITIONAL([BUILDCRYPTONSS], [test x$enable_crypto_nss = xyes])

AC_ARG_ENABLE([crypto-openssl],
	[  --disable-crypto-openssl          : disable libknet openssl support ],,
	[ enable_crypto_openssl="$enable_crypto_all" ])
AM_CONDITIONAL([BUILDCRYPTOOPENSSL], [test x$enable_crypto_openssl = xyes])

AC_ARG_ENABLE([compress-all],
	[  --disable-compress-all            : disable libknet all compress modules support ],,
	[ enable_compress_all="yes" ])

AC_ARG_ENABLE([compress-zlib],
	[  --disable-compress-zlib           : disable libknet zlib support ],,
	[ enable_compress_zlib="$enable_compress_all" ])
AM_CONDITIONAL([BUILDCOMPZLIB], [test x$enable_compress_zlib = xyes])

AC_ARG_ENABLE([compress-lz4],
	[  --disable-compress-lz4            : disable libknet lz4 support ],,
	[ enable_compress_lz4="$enable_compress_all" ])
AM_CONDITIONAL([BUILDCOMPLZ4], [test x$enable_compress_lz4 = xyes])

AC_ARG_ENABLE([compress-lzo2],
	[  --disable-compress-lzo2           : disable libknet lzo2 support ],,
	[ enable_compress_lzo2="$enable_compress_all" ])
AM_CONDITIONAL([BUILDCOMPLZO2], [test x$enable_compress_lzo2 = xyes])

AC_ARG_ENABLE([compress-lzma],
	[  --disable-compress-lzma           : disable libknet lzma support ],,
	[ enable_compress_lzma="$enable_compress_all" ])
AM_CONDITIONAL([BUILDCOMPLZMA], [test x$enable_compress_lzma = xyes])

AC_ARG_ENABLE([compress-bzip2],
	[  --disable-compress-bzip2          : disable libknet bzip2 support ],,
	[ enable_compress_bzip2="$enable_compress_all" ])
AM_CONDITIONAL([BUILDCOMPBZIP2], [test x$enable_compress_bzip2 = xyes])

AC_ARG_ENABLE([poc],
	[  --enable-poc                      : enable building poc code ],,
	[ enable_poc="no" ])
AM_CONDITIONAL([BUILD_POC], [test x$enable_poc = xyes])

AC_ARG_ENABLE([kronosnetd],
	[  --enable-kronosnetd               : Kronosnetd support ],,
	[ enable_kronosnetd="no" ])
AM_CONDITIONAL([BUILD_KRONOSNETD], [test x$enable_kronosnetd = xyes])

AC_ARG_ENABLE([runautogen],
	[  --enable-runautogen               : run autogen.sh ],,
	[ enable_runautogen="no" ])
AM_CONDITIONAL([BUILD_RUNAUTOGEN], [test x$enable_runautogen = xyes])

AC_ARG_ENABLE([libtap],
	[  --enable-libtap                   : libtap support ],,
	[ enable_libtap="no" ])

if test "x$enable_kronosnetd" = xyes; then
	enable_libtap=yes
fi
AM_CONDITIONAL([BUILD_LIBTAP], [test x$enable_libtap = xyes])

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
AC_CHECK_LIB([pthread], [pthread_create], [AC_SUBST([pthread_LIBS], [-lpthread])], [AC_MSG_ERROR([kronosnet requires pthread library])])
AC_CHECK_LIB([m], [ceil], [AC_SUBST([m_LIBS], [-lm])], [AC_MSG_ERROR([kronosnet requires m library])])
AC_CHECK_LIB([rt], [clock_gettime], [AC_SUBST([rt_LIBS], [-lrt])], [AC_MSG_ERROR([kronosnet requires rt library])])

AC_SEARCH_LIBS([dlopen], [dl dld], [dllibs=$ac_res], [AC_MSG_ERROR([kronosnet requires dl library])])

if test "x$dllibs" != "xnone required"; then
	AC_SUBST([dl_LIBS], [$dllibs])
fi

# crypto libraries checks
if test "x$enable_crypto_nss" = xyes; then
	PKG_CHECK_MODULES([nss],[nss])
	AC_DEFINE_UNQUOTED([BUILDCRYPTONSS], [1], [Enable nss crypto])
fi

if test "x$enable_crypto_openssl" = xyes; then
	PKG_CHECK_MODULES([openssl],[openssl < 1.1],
			  [AC_DEFINE_UNQUOTED([BUILDCRYPTOOPENSSL10], [1], [openssl 1.0 crypto])],
			  [PKG_CHECK_MODULES([openssl],[openssl >= 1.1],
					     [AC_DEFINE_UNQUOTED([BUILDCRYPTOOPENSSL11], [1], [openssl 1.1 crypto])])])
	AC_DEFINE_UNQUOTED([BUILDCRYPTOOPENSSL], [1], [Enable openssl crypto])
fi

# compress libraries checks
if test "x$enable_compress_zlib" = xyes; then
	PKG_CHECK_MODULES([zlib], [zlib])
	AC_DEFINE_UNQUOTED([BUILDCOMPZLIB], [1], [Enable zlib compression])
fi
if test "x$enable_compress_lz4" = xyes; then
	PKG_CHECK_MODULES([liblz4], [liblz4])
	AC_DEFINE_UNQUOTED([BUILDCOMPLZ4], [1], [Enable lz4 compress])
fi
if test "x$enable_compress_lzo2" = xyes; then
	PKG_CHECK_MODULES([lzo2], [lzo2],,
		[AC_CHECK_HEADERS([lzo/lzo1x.h],
			[AC_CHECK_LIB([lzo2], [lzo1x_decompress_safe],
				[AC_SUBST([lzo2_LIBS], [-llzo2])])],
				[AC_MSG_ERROR(["missing required lzo/lzo1x.h header"])])])
	AC_DEFINE_UNQUOTED([BUILDCOMPLZO2], [1], [Enable lzo2 compress])
fi
if test "x$enable_compress_lzma" = xyes; then
	PKG_CHECK_MODULES([liblzma], [liblzma])
	AC_DEFINE_UNQUOTED([BUILDCOMPLZMA], [1], [Enable lzma compress])
fi
if test "x$enable_compress_bzip2" = xyes; then
	PKG_CHECK_MODULES([bzip2], [bzip2],,
		[AC_CHECK_HEADERS([bzlib.h],
			[AC_CHECK_LIB([bz2], [BZ2_bzBuffToBuffCompress],
				[AC_SUBST([bzip2_LIBS], [-lbz2])])],
				[AC_MSG_ERROR(["missing required bzlib.h"])])])
	AC_DEFINE_UNQUOTED([BUILDCOMPBZIP2], [1], [Enable bzip2 compress])
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
AC_CHECK_HEADERS([sys/epoll.h])

if test "x$enable_libknet_sctp" = xyes; then
	AC_CHECK_HEADERS([netinet/sctp.h],, [AC_MSG_ERROR(["missing required SCTP headers"])])
fi

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
AC_CHECK_FUNCS([kevent])
# if neither sys/epoll.h nor kevent are present, we should fail.

if test "x$ac_cv_header_sys_epoll_h" = xno && test "x$ac_cv_func_kevent" = xno; then
	AC_MSG_ERROR([Both epoll and kevent unavailable on this OS])
fi

if test "x$ac_cv_header_sys_epoll_h" = xyes && test "x$ac_cv_func_kevent" = xyes; then
	AC_MSG_ERROR([Both epoll and kevent available on this OS, please contact the maintainers to fix the code])
fi

# checks (for kronosnetd)
if test "x$enable_kronosnetd" = xyes; then
	AC_CHECK_HEADERS([security/pam_appl.h],
			 [AC_CHECK_LIB([pam], [pam_start])],
			 [AC_MSG_ERROR([Unable to find LinuxPAM devel files])])

	AC_CHECK_HEADERS([security/pam_misc.h],
			 [AC_CHECK_LIB([pam_misc], [misc_conv])],
			 [AC_MSG_ERROR([Unable to find LinuxPAM MISC devel files])])

	PKG_CHECK_MODULES([libqb], [libqb])

	AC_CHECK_LIB([qb], [qb_log_thread_priority_set],
		     [have_qb_log_thread_priority_set="yes"],
		     [have_qb_log_thread_priority_set="no"])
	if test "x${have_qb_log_thread_priority_set}" = xyes; then
		AC_DEFINE_UNQUOTED([HAVE_QB_LOG_THREAD_PRIORITY_SET], [1], [have qb_log_thread_priority_set])
	fi
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
AM_CONDITIONAL([DEBUG], [test "x${enable_debug}" = xyes])

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
	extra
	unused
	shadow
	missing-prototypes
	missing-declarations
	suggest-attribute=noreturn
	suggest-attribute=format
	strict-prototypes
	declaration-after-statement
	pointer-arith
	write-strings
	cast-align
	bad-function-cast
	missing-format-attribute
	float-equal
	format=2
	format-signedness
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
	shift-overflow=2
	overlength-strings
	retundent-decls
	init-self
	uninitialized
	unused-but-set-variable
	unused-function
	unused-result
	unused-value
	unused-variable
	unknown-pragmas
	no-unused-parameter
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
		init/Makefile
		libtap/Makefile
		libtap/libtap.pc
		kronosnetd/Makefile
		kronosnetd/kronosnetd.logrotate
		libknet/Makefile
		libknet/libknet.pc
		libknet/tests/Makefile
		docs/Makefile
		poc-code/Makefile
		poc-code/iov-hash/Makefile
		poc-code/access-list/Makefile
		])

AC_OUTPUT
