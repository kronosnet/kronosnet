#
# Copyright (C) 2010-2020 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.63])
AC_INIT([kronosnet],
	m4_esyscmd([build-aux/git-version-gen .tarball-version .gitarchivever]),
	[devel@lists.kronosnet.org])
# Don't let AC_PROC_CC (invoked by AC_USE_SYSTEM_EXTENSIONS) replace
# undefined CFLAGS with -g -O2, overriding our special OPT_CFLAGS.
: ${CFLAGS=""}
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([1.13 dist-bzip2 dist-xz color-tests -Wno-portability subdir-objects])

LT_PREREQ([2.2.6])
# --enable-new-dtags: Use RUNPATH instead of RPATH.
# It is necessary to have this done before libtool does linker detection.
# See also: https://github.com/kronosnet/kronosnet/issues/107
# --as-needed: Modern systems have builtin ceil() making -lm superfluous but
# AC_SEARCH_LIBS can't detect this because it tests with a false prototype
AX_CHECK_LINK_FLAG([-Wl,--enable-new-dtags],
		   [AM_LDFLAGS=-Wl,--enable-new-dtags],
		   [AC_MSG_ERROR(["Linker support for --enable-new-dtags is required"])])
AX_CHECK_LINK_FLAG([-Wl,--as-needed], [AM_LDFLAGS="$AM_LDFLAGS -Wl,--as-needed"])

AC_SUBST([AM_LDFLAGS])
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
LT_INIT
LDFLAGS="$saved_LDFLAGS"

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([kronosnetd/main.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

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

AC_CHECK_PROGS([VALGRIND_EXEC], [valgrind])
AM_CONDITIONAL([HAS_VALGRIND], [test x$VALGRIND_EXEC != "x"])

AC_CHECK_PROGS([COVBUILD_EXEC], [cov-build])
AM_CONDITIONAL([HAS_COVBUILD], [test x$COVBUILD_EXEC != "x"])

AC_CHECK_PROGS([COVANALYZE_EXEC], [cov-analyze])
AM_CONDITIONAL([HAS_COVANALYZE], [test x$COVANALYZE_EXEC != "x"])

AC_CHECK_PROGS([COVFORMATERRORS_EXEC], [cov-format-errors])
AM_CONDITIONAL([HAS_COVFORMATERRORS], [test x$COVFORMATERRORS_EXEC != "x"])

# KNET_OPTION_DEFINES(stem,type,detection code)
# stem: enters name of option, Automake conditional and preprocessor define
# type: compress or crypto, determines where the default comes from
AC_DEFUN([KNET_OPTION_DEFINES],[
AC_ARG_ENABLE([$2-$1],[AS_HELP_STRING([--disable-$2-$1],[disable libknet $1 support])],,
	[enable_$2_$1="$enable_$2_all"])
AM_CONDITIONAL([BUILD_]m4_toupper([$2_$1]),[test "x$enable_$2_$1" = xyes])
if test "x$enable_$2_$1" = xyes; then
	$3
fi
AC_DEFINE_UNQUOTED([WITH_]m4_toupper([$2_$1]), [`test "x$enable_$2_$1" != xyes; echo $?`], $1 $2 [built in])
])

AC_ARG_ENABLE([man],
	[AS_HELP_STRING([--disable-man],[disable man page creation])],,
	[ enable_man="yes" ])
AM_CONDITIONAL([BUILD_MAN], [test x$enable_man = xyes])

AC_ARG_ENABLE([libknet-sctp],
	[AS_HELP_STRING([--disable-libknet-sctp],[disable libknet SCTP support])],,
	[ enable_libknet_sctp="yes" ])
AM_CONDITIONAL([BUILD_SCTP], [test x$enable_libknet_sctp = xyes])

AC_ARG_ENABLE([crypto-all],
	[AS_HELP_STRING([--disable-crypto-all],[disable libknet all crypto modules support])],,
	[ enable_crypto_all="yes" ])

KNET_OPTION_DEFINES([nss],[crypto],[PKG_CHECK_MODULES([nss], [nss])])
KNET_OPTION_DEFINES([openssl],[crypto],[PKG_CHECK_MODULES([openssl],[libcrypto])])

AC_ARG_ENABLE([compress-all],
	[AS_HELP_STRING([--disable-compress-all],[disable libknet all compress modules support])],,
	[ enable_compress_all="yes" ])

KNET_OPTION_DEFINES([zstd],[compress],[PKG_CHECK_MODULES([libzstd], [libzstd])])
KNET_OPTION_DEFINES([zlib],[compress],[PKG_CHECK_MODULES([zlib], [zlib])])
KNET_OPTION_DEFINES([lz4],[compress],[PKG_CHECK_MODULES([liblz4], [liblz4])])
KNET_OPTION_DEFINES([lzo2],[compress],[
	PKG_CHECK_MODULES([lzo2], [lzo2],
		[# work around broken pkg-config file in v2.10
		 AC_SUBST([lzo2_CFLAGS],[`echo $lzo2_CFLAGS | sed 's,/lzo *, ,'`])],
		[AC_CHECK_HEADERS([lzo/lzo1x.h],
			[AC_CHECK_LIB([lzo2], [lzo1x_decompress_safe],
				[AC_SUBST([lzo2_LIBS], [-llzo2])])],
				[AC_MSG_ERROR(["missing required lzo/lzo1x.h header"])])])
])
KNET_OPTION_DEFINES([lzma],[compress],[PKG_CHECK_MODULES([liblzma], [liblzma])])
KNET_OPTION_DEFINES([bzip2],[compress],[
	PKG_CHECK_MODULES([bzip2], [bzip2],,
		[AC_CHECK_HEADERS([bzlib.h],
			[AC_CHECK_LIB([bz2], [BZ2_bzBuffToBuffCompress],
				[AC_SUBST([bzip2_LIBS], [-lbz2])])],
				[AC_MSG_ERROR(["missing required bzlib.h"])])])
])

AC_ARG_ENABLE([install-tests],
	[AS_HELP_STRING([--enable-install-tests],[install tests])],,
	[ enable_install_tests="no" ])
AM_CONDITIONAL([INSTALL_TESTS], [test x$enable_install_tests = xyes])

AC_ARG_ENABLE([poc],
	[AS_HELP_STRING([--enable-poc],[enable building poc code])],,
	[ enable_poc="no" ])
AM_CONDITIONAL([BUILD_POC], [test x$enable_poc = xyes])

AC_ARG_ENABLE([kronosnetd],
	[AS_HELP_STRING([--enable-kronosnetd],[Kronosnetd support])],,
	[ enable_kronosnetd="no" ])
AM_CONDITIONAL([BUILD_KRONOSNETD], [test x$enable_kronosnetd = xyes])

AC_ARG_ENABLE([runautogen],
	[AS_HELP_STRING([--enable-runautogen],[run autogen.sh])],,
	[ enable_runautogen="no" ])
AM_CONDITIONAL([BUILD_RUNAUTOGEN], [test x$enable_runautogen = xyes])

override_rpm_debuginfo_option="yes"
AC_ARG_ENABLE([rpm-debuginfo],
	[AS_HELP_STRING([--enable-rpm-debuginfo],[build debuginfo packages])],,
	[ enable_rpm_debuginfo="no", override_rpm_debuginfo_option="no" ])
AM_CONDITIONAL([BUILD_RPM_DEBUGINFO], [test x$enable_rpm_debuginfo = xyes])
AM_CONDITIONAL([OVERRIDE_RPM_DEBUGINFO], [test x$override_rpm_debuginfo_option = xyes])

AC_ARG_ENABLE([libnozzle],
	[AS_HELP_STRING([--enable-libnozzle],[libnozzle support])],,
	[ enable_libnozzle="yes" ])

if test "x$enable_kronosnetd" = xyes; then
	enable_libnozzle=yes
fi
AM_CONDITIONAL([BUILD_LIBNOZZLE], [test x$enable_libnozzle = xyes])

# Checks for libraries.
AX_PTHREAD(,[AC_MSG_ERROR([POSIX threads support is required])])
saved_LIBS="$LIBS"
LIBS=
AC_SEARCH_LIBS([ceil], [m], , [AC_MSG_ERROR([ceil not found])])
AC_SUBST([m_LIBS], [$LIBS])
LIBS=
AC_SEARCH_LIBS([clock_gettime], [rt], , [AC_MSG_ERROR([clock_gettime not found])])
AC_SUBST([rt_LIBS], [$LIBS])
LIBS=
AC_SEARCH_LIBS([dlopen], [dl dld], , [AC_MSG_ERROR([dlopen not found])])
AC_SUBST([dl_LIBS], [$LIBS])
LIBS="$saved_LIBS"

# Check RTLD_DI_ORIGIN (not decalred by musl. glibc has it as an enum so cannot use ifdef)
AC_CHECK_DECL([RTLD_DI_ORIGIN], [AC_DEFINE([HAVE_RTLD_DI_ORIGIN], 1,
    [define when RTLD_DI_ORIGIN is declared])], ,[[#include <dlfcn.h>]])

# OS detection

AC_MSG_CHECKING([for os in ${host_os}])
case "$host_os" in
	*linux*)
		AC_DEFINE_UNQUOTED([KNET_LINUX], [1], [Compiling for Linux platform])
		AC_MSG_RESULT([Linux])
		;;
	*bsd*)
		AC_DEFINE_UNQUOTED([KNET_BSD], [1], [Compiling for BSD platform])
		AC_MSG_RESULT([BSD])
		;;
	*)
		AC_MSG_ERROR([Unsupported OS? hmmmm])
		;;
esac

# Checks for header files.
AC_CHECK_HEADERS([sys/epoll.h])
AC_CHECK_FUNCS([kevent])
# if neither sys/epoll.h nor kevent are present, we should fail.

if test "x$ac_cv_header_sys_epoll_h" = xno && test "x$ac_cv_func_kevent" = xno; then
	AC_MSG_ERROR([Both epoll and kevent unavailable on this OS])
fi

if test "x$ac_cv_header_sys_epoll_h" = xyes && test "x$ac_cv_func_kevent" = xyes; then
	AC_MSG_ERROR([Both epoll and kevent available on this OS, please contact the maintainers to fix the code])
fi

if test "x$enable_libknet_sctp" = xyes; then
	AC_CHECK_HEADERS([netinet/sctp.h],, [AC_MSG_ERROR(["missing required SCTP headers"])])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T

if test "x$enable_man" = "xyes"; then
	AC_ARG_VAR([DOXYGEN], [override doxygen executable])
	AC_CHECK_PROGS([DOXYGEN], [doxygen], [no])
	if test "x$DOXYGEN" = xno; then
		AC_MSG_ERROR(["Doxygen command not found"])
	fi
	# required by doxyxml to build man pages dynamically
	# Don't let AC_PROC_CC (invoked by AX_PROG_CC_FOR_BUILD) replace
	# undefined CFLAGS_FOR_BUILD with -g -O2, overriding our special OPT_CFLAGS.
	: ${CFLAGS_FOR_BUILD=""}
	AX_PROG_CC_FOR_BUILD
	saved_PKG_CONFIG="$PKG_CONFIG"
	saved_ac_cv_path_PKG_CONFIG="$ac_cv_path_PKG_CONFIG"
	unset PKG_CONFIG ac_cv_path_PKG_CONFIG
	AC_PATH_PROG([PKG_CONFIG], [pkg-config])
	PKG_CHECK_MODULES([libqb_BUILD], [libqb])
	PKG_CHECK_MODULES([libxml_BUILD], [libxml-2.0])
	PKG_CONFIG="$saved_PKG_CONFIG"
	ac_cv_path_PKG_CONFIG="$saved_ac_cv_path_PKG_CONFIG"
fi

# checks for libnozzle
if test "x$enable_libnozzle" = xyes; then
	if `echo $host_os | grep -q linux`; then
		PKG_CHECK_MODULES([libnl], [libnl-3.0])
		PKG_CHECK_MODULES([libnlroute], [libnl-route-3.0 >= 3.3], [],
			[PKG_CHECK_MODULES([libnlroute], [libnl-route-3.0 < 3.3],
					   [AC_DEFINE_UNQUOTED([LIBNL3_WORKAROUND], [1], [Enable libnl < 3.3 build workaround])], [])])
	fi
fi

# checks for kronosnetd
if test "x$enable_kronosnetd" = xyes; then
	AC_CHECK_HEADERS([security/pam_appl.h],
			 [AC_CHECK_LIB([pam], [pam_start],
				       [AC_SUBST([pam_LIBS], [-lpam])],
				       [AC_MSG_ERROR([Unable to find LinuxPAM devel files])])])

	AC_CHECK_HEADERS([security/pam_misc.h],
			 [AC_CHECK_LIB([pam_misc], [misc_conv],
				       [AC_SUBST([pam_misc_LIBS], [-lpam_misc])],
				       [AC_MSG_ERROR([Unable to find LinuxPAM MISC devel files])])])

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
	[AS_HELP_STRING([--enable-debug],[enable debug build])])

AC_ARG_WITH([sanitizers],
	[AS_HELP_STRING([--with-sanitizers=...,...],
			[enable SANitizer build, do *NOT* use for production. Only ASAN/UBSAN/TSAN are currently supported])],
	[ SANITIZERS="$withval" ],
	[ SANITIZERS="" ])

AC_ARG_WITH([testdir],
	[AS_HELP_STRING([--with-testdir=DIR],[path to /usr/lib../kronosnet/tests/ dir where to install the test suite])],
	[ TESTDIR="$withval" ],
	[ TESTDIR="$libdir/kronosnet/tests" ])

AC_ARG_WITH([initdefaultdir],
	[AS_HELP_STRING([--with-initdefaultdir=DIR],[path to /etc/sysconfig or /etc/default dir])],
	[ INITDEFAULTDIR="$withval" ],
	[ INITDEFAULTDIR="$sysconfdir/default" ])

AC_ARG_WITH([initddir],
	[AS_HELP_STRING([--with-initddir=DIR],[path to init script directory])],
	[ INITDDIR="$withval" ],
	[ INITDDIR="$sysconfdir/init.d" ])

AC_ARG_WITH([systemddir],
	[AS_HELP_STRING([--with-systemddir=DIR],[path to systemd unit files directory])],
	[ SYSTEMDDIR="$withval" ],
	[ SYSTEMDDIR="$systemddir" ])

AC_ARG_WITH([syslogfacility],
	[AS_HELP_STRING([--with-syslogfacility=FACILITY],[default syslog facility])],
	[ SYSLOGFACILITY="$withval" ],
	[ SYSLOGFACILITY="LOG_DAEMON" ])

AC_ARG_WITH([sysloglevel],
	[AS_HELP_STRING([--with-sysloglevel=LEVEL],[default syslog level])],
	[ SYSLOGLEVEL="$withval" ],
	[ SYSLOGLEVEL="LOG_INFO" ])

AC_ARG_WITH([defaultadmgroup],
	[AS_HELP_STRING([--with-defaultadmgroup=GROUP],
		[define PAM group. Users part of this group will be allowed to configure
		 kronosnet. Others will only receive read-only rights.])],
	[ DEFAULTADMGROUP="$withval" ],
	[ DEFAULTADMGROUP="kronosnetadm" ])

## random vars
LOGDIR=${localstatedir}/log/
RUNDIR=${localstatedir}/run/
DEFAULT_CONFIG_DIR=${sysconfdir}/kronosnet

## do subst

AC_SUBST([TESTDIR])
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

# --- ASAN/UBSAN/TSAN (see man gcc) ---
# when using SANitizers, we need to pass the -fsanitize..
# to both CFLAGS and LDFLAGS. The CFLAGS/LDFLAGS must be
# specified as first in the list or there will be runtime
# issues (for example user has to LD_PRELOAD asan for it to work
# properly).

if test -n "${SANITIZERS}"; then
	SANITIZERS=$(echo $SANITIZERS | sed -e 's/,/ /g')
	for SANITIZER in $SANITIZERS; do
		case $SANITIZER in
			asan|ASAN)
				SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=address"
				SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=address -lasan"
				AC_CHECK_LIB([asan],[main],,AC_MSG_ERROR([Unable to find libasan]))
				;;
			ubsan|UBSAN)
				SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=undefined"
				SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=undefined -lubsan"
				AC_CHECK_LIB([ubsan],[main],,AC_MSG_ERROR([Unable to find libubsan]))
				;;
			tsan|TSAN)
				SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=thread"
				SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=thread -ltsan"
				AC_CHECK_LIB([tsan],[main],,AC_MSG_ERROR([Unable to find libtsan]))
				;;
		esac
	done
fi

DEFAULT_CFLAGS="-Werror -Wall -Wextra"

# manual overrides
# generates too much noise for stub APIs
UNWANTED_CFLAGS="-Wno-unused-parameter"

AC_SUBST([AM_CFLAGS],["$SANITIZERS_CFLAGS $OPT_CFLAGS $GDB_FLAGS $DEFAULT_CFLAGS $UNWANTED_CFLAGS"])
LDFLAGS="$SANITIZERS_LDFLAGS $LDFLAGS"

AX_PROG_DATE
AS_IF([test "$ax_cv_prog_date_gnu_date:$ax_cv_prog_date_gnu_utc" = yes:yes],
	[UTC_DATE_AT="date -u -d@"],
	[AS_IF([test "x$ax_cv_prog_date_bsd_date" = xyes],
		[UTC_DATE_AT="date -u -r"],
		[AC_MSG_ERROR([date utility unable to convert epoch to UTC])])])
AC_SUBST([UTC_DATE_AT])

AC_ARG_VAR([SOURCE_EPOCH],[last modification date of the source])
AC_MSG_NOTICE([trying to determine source epoch])
AC_MSG_CHECKING([for source epoch in \$SOURCE_EPOCH])
AS_IF([test -n "$SOURCE_EPOCH"],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	 AC_MSG_CHECKING([for source epoch in source_epoch file])
	 AS_IF([test -e "$srcdir/source_epoch"],
		[read SOURCE_EPOCH <"$srcdir/source_epoch"
		 AC_MSG_RESULT([yes])],
		[AC_MSG_RESULT([no])
		 AC_MSG_CHECKING([for source epoch baked in by gitattributes export-subst])
		 SOURCE_EPOCH='$Format:%at$' # template for rewriting by git-archive
		 AS_CASE([$SOURCE_EPOCH],
			[?Format:*], # was not rewritten
				[AC_MSG_RESULT([no])
				 AC_MSG_CHECKING([for source epoch in \$SOURCE_DATE_EPOCH])
				 AS_IF([test "x$SOURCE_DATE_EPOCH" != x],
					[SOURCE_EPOCH="$SOURCE_DATE_EPOCH"
					 AC_MSG_RESULT([yes])],
					[AC_MSG_RESULT([no])
					 AC_MSG_CHECKING([whether git log can provide a source epoch])
					 SOURCE_EPOCH=f${SOURCE_EPOCH#\$F} # convert into git log --pretty format
					 SOURCE_EPOCH=$(cd "$srcdir" && git log -1 --pretty=${SOURCE_EPOCH%$} 2>/dev/null)
					 AS_IF([test -n "$SOURCE_EPOCH"],
						[AC_MSG_RESULT([yes])],
						[AC_MSG_RESULT([no, using current time and breaking reproducibility])
						 SOURCE_EPOCH=$(date +%s)])])],
			[AC_MSG_RESULT([yes])]
		 )])
	])
AC_MSG_NOTICE([using source epoch $($UTC_DATE_AT$SOURCE_EPOCH +'%F %T %Z')])

AC_CONFIG_FILES([
		Makefile
		init/Makefile
		libnozzle/Makefile
		libnozzle/libnozzle.pc
		libnozzle/tests/Makefile
		kronosnetd/Makefile
		kronosnetd/kronosnetd.logrotate
		libknet/Makefile
		libknet/libknet.pc
		libknet/tests/Makefile
		man/Makefile
		man/Doxyfile-knet
		man/Doxyfile-nozzle
		poc-code/Makefile
		poc-code/iov-hash/Makefile
		])

if test "x$VERSION" = "xUNKNOWN"; then
	AC_MSG_ERROR([m4_text_wrap([
  configure was unable to determine the source tree's current version. This
  generally happens when using git archive (or the github download button)
  generated tarball/zip file. In order to workaround this issue, either use git
  clone https://github.com/kronosnet/kronosnet.git or use an official release
  tarball, available at https://kronosnet.org/releases/.  Alternatively you
  can add a compatible version in a .tarball-version file at the top of the
  source tree, wipe your autom4te.cache dir and generated configure, and rerun
  autogen.sh.
  ], [  ], [   ], [76])])
fi

AC_OUTPUT
