#
# Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
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

AC_CANONICAL_HOST
# --enable-new-dtags: Use RUNPATH instead of RPATH.
# It is necessary to have this done before libtool does linker detection.
# See also: https://github.com/kronosnet/kronosnet/issues/107
# --as-needed: Modern systems have builtin ceil() making -lm superfluous but
# AC_SEARCH_LIBS can't detect this because it tests with a false prototype
case "$host_os" in
	solaris*)
		AC_MSG_NOTICE([Skipping --enable-new-dtags check, Solaris' RPATH logic is like RUNPATH on other platforms])
		;;
	*)
		AX_CHECK_LINK_FLAG([-Wl,--enable-new-dtags],
				   [AM_LDFLAGS=-Wl,--enable-new-dtags],
				   [AC_MSG_ERROR(["Linker support for --enable-new-dtags is required"])])
		;;
esac
AX_CHECK_LINK_FLAG([-Wl,--as-needed], [AM_LDFLAGS="$AM_LDFLAGS -Wl,--as-needed"])

saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
LT_INIT
LDFLAGS="$saved_LDFLAGS"

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([libknet/handle.c])
AC_CONFIG_HEADERS([config.h])

AC_LANG([C])

if test "$prefix" = "NONE"; then
	prefix="/usr"
	if test "$localstatedir" = "\${prefix}/var"; then
		localstatedir="/var"
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
m4_version_prereq([2.70], [:], [AC_PROG_CC_C99])
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

AC_ARG_ENABLE([functional-tests],
	[AS_HELP_STRING([--disable-functional-tests],[disable execution of functional tests, useful for old and slow arches])],,
	[ enable_functional_tests="yes" ])
AM_CONDITIONAL([RUN_FUN_TESTS], [test x$enable_functional_tests = xyes])

AC_ARG_ENABLE([crypto-all],
	[AS_HELP_STRING([--disable-crypto-all],[disable libknet all crypto modules support])],,
	[ enable_crypto_all="yes" ])

KNET_OPTION_DEFINES([nss],[crypto],[PKG_CHECK_MODULES([nss], [nss])])
KNET_OPTION_DEFINES([openssl],[crypto],[PKG_CHECK_MODULES([openssl], [libcrypto])])

# use gcry_mac_open to detect if libgcrypt is new enough
KNET_OPTION_DEFINES([gcrypt],[crypto],[
	PKG_CHECK_MODULES([gcrypt], [libgcrypt >= 1.8.0],,
		[AC_CHECK_HEADERS([gcrypt.h],
			[AC_CHECK_LIB([gcrypt], [gcry_mac_open],
				[AC_SUBST([gcrypt_LIBS], ["-lgcrypt -ldl -lgpg-error"])])],
				[AC_MSG_ERROR(["missing required gcrypt.h"])])])
])

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
AM_CONDITIONAL([BUILD_LIBNOZZLE], [test x$enable_libnozzle = xyes])

AC_ARG_ENABLE([rust-bindings],
	[AS_HELP_STRING([--enable-rust-bindings],[rust bindings support])],,
	[ enable_rust_bindings="no" ])
AM_CONDITIONAL([BUILD_RUST_BINDINGS], [test x$enable_rust_bindings = xyes])

## local helper functions
# this function checks if CC support options passed as
# args. Global CPPFLAGS are ignored during this test.
cc_supports_flag() {
	saveCPPFLAGS="$CPPFLAGS"
	CPPFLAGS="-Werror $@"
	AC_MSG_CHECKING([whether $CC supports "$@"])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <stdio.h>], [
			   #ifdef __USE_FORTIFY_LEVEL
			   printf("%d\n", __USE_FORTIFY_LEVEL)
			   #else
			   printf("hello world\n")
			   #endif
			  ])],
			  [RC=0; AC_MSG_RESULT([yes])],
			  [RC=1; AC_MSG_RESULT([no])])
	CPPFLAGS="$saveCPPFLAGS"
	return $RC
}

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

AC_CHECK_DECLS([MSG_NOSIGNAL], [], [CFLAGS="$CFLAGS -DMSG_NOSIGNAL=0"], [#include <sys/socket.h>])

AC_CHECK_LIB([socket], [socket],
	     [AC_SUBST([socket_LIBS], [-lsocket])])

# OS detection

build_for_solaris=no
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
	solaris*)
		AC_DEFINE_UNQUOTED([KNET_SOLARIS], [1], [Compiling for Solaris platform])
		AC_MSG_RESULT([Solaris])
		build_for_solaris=yes
		;;
	*)
		AC_MSG_ERROR([Unsupported OS? hmmmm])
		;;
esac

AM_CONDITIONAL([BUILD_FOR_SOLARIS], [test "x$build_for_solaris" = "xyes"])

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

PKG_CHECK_MODULES([libqb], [libqb])

if test "x$enable_man" = "xyes"; then
	AC_ARG_VAR([DOXYGEN], [override doxygen executable])
	AC_CHECK_PROGS([DOXYGEN], [doxygen], [no])
	if test "x$DOXYGEN" = xno; then
		AC_MSG_ERROR(["Doxygen command not found"])
	fi

	AC_ARG_VAR([DOXYGEN2MAN], [override doxygen2man executable])

	# required to detect doxygen2man when libqb is installed
	# in non standard paths
	saved_PKG_CONFIG="$PKG_CONFIG"
	saved_ac_cv_path_PKG_CONFIG="$ac_cv_path_PKG_CONFIG"
	unset PKG_CONFIG ac_cv_path_PKG_CONFIG
	AC_PATH_PROG([PKG_CONFIG], [pkg-config])
	PKG_CHECK_MODULES([libqb_BUILD], [libqb])
	PKG_CHECK_VAR([libqb_BUILD_PREFIX], [libqb], [prefix])
	AC_PATH_PROG([DOXYGEN2MAN], [doxygen2man], [no], [$libqb_BUILD_PREFIX/bin$PATH_SEPARATOR$PATH])
	PKG_CONFIG="$saved_PKG_CONFIG"
	ac_cv_path_PKG_CONFIG="$saved_ac_cv_path_PKG_CONFIG"

	if test "x$DOXYGEN2MAN" = "xno"; then
		AC_MSG_ERROR(["doxygen2man command not found"])
	fi
	AC_SUBST([DOXYGEN2MAN])
fi

# check for rust tools to build bindings
if test "x$enable_rust_bindings" = "xyes"; then
	AC_PATH_PROG([CARGO], [cargo], [no])
	if test "x$CARGO" = xno; then
		AC_MSG_ERROR(["cargo command not found"])
	fi

	AC_PATH_PROG([RUSTC], [rustc], [no])
	if test "x$RUSTC" = xno; then
		AC_MSG_ERROR(["rustc command not found"])
	fi

	AC_PATH_PROG([RUSTDOC], [rustdoc], [no])
	if test "x$RUSTDOC" = xno; then
		AC_MSG_ERROR(["rustdoc command not found"])
	fi

	AC_PATH_PROG([BINDGEN], [bindgen], [no])
	if test "x$BINDGEN" = xno; then
		AC_MSG_ERROR(["bindgen command not found"])
	fi

	AC_PATH_PROG([CLIPPY], [clippy-driver], [no])
	if test "x$CLIPPY" = xno; then
		AC_MSG_ERROR(["clippy-driver command not found"])
	fi

	AC_PATH_PROG([RUSTFMT], [rustfmt], [no])
	if test "x$RUSTFMT" = xno; then
		AC_MSG_ERROR(["rustfmt command not found (optional)"])
	fi
fi

# checks for libnozzle
if test "x$enable_libnozzle" = xyes; then
	case $host_os in
		*linux*)
			PKG_CHECK_MODULES([libnl], [libnl-3.0])
			PKG_CHECK_MODULES([libnlroute], [libnl-route-3.0 >= 3.3], [],
				[PKG_CHECK_MODULES([libnlroute], [libnl-route-3.0 < 3.3],
						   [AC_DEFINE_UNQUOTED([LIBNL3_WORKAROUND], [1], [Enable libnl < 3.3 build workaround])], [])])
			;;
		*solaris*)
			saved_LIBS="$LIBS"
			AC_SEARCH_LIBS([dlpi_open], [dlpi], , [AC_MSG_ERROR([dlpi_open not found])])
			AC_SUBST([dlpi_LIBS], [$LIBS])
			LIBS="$saved_LIBS"
			AC_CHECK_HEADERS([net/if_tun.h],, [AC_MSG_ERROR([net/if_tun.h not found])])
			;;
		*)
			;;
	esac
fi

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
knetcurrent="2"
knetrevision="0"
knetage="0"
# c:r:a
libknetversion="$knetcurrent:$knetrevision:$knetage"
# soname derived from c:r:a
# use $VERSION as build info https://semver.org/. build info are incremental automatically
knetalpha="-alpha1"
libknetrustver="$(($knetcurrent - $knetage)).$knetage.$knetrevision$knetalpha+$VERSION"

nozzlecurrent="1"
nozzlerevision="0"
nozzleage="0"
libnozzleversion="$nozzlecurrent:$nozzlerevision:$nozzleage"
# nozzle is stable for now
nozzlealpha=""
libnozzlerustver="$(($nozzlecurrent - $nozzleage)).$nozzleage.$nozzlerevision$nozzlealpha+$VERSION"

AC_SUBST([libknetversion])
AC_SUBST([libknetrustver])
AC_SUBST([libnozzleversion])
AC_SUBST([libnozzlerustver])

# local options
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[enable debug build])])

AC_ARG_ENABLE([onwire-v1-extra-debug],
	[AS_HELP_STRING([--enable-onwire-v1-extra-debug],[enable onwire protocol v1 extra debug. WARNING: IT BREAKS ONWIRE COMPATIBILITY! DO NOT USE IN PRODUCTION!])])

if test "x${enable_onwire_v1_extra_debug}" = xyes; then
	AC_DEFINE_UNQUOTED([ONWIRE_V1_EXTRA_DEBUG], [1], [Enable crc32 checksum for data and packets])
fi

# for standard crc32 function (used in test suite)
PKG_CHECK_MODULES([zlib], [zlib])

AC_ARG_ENABLE([hardening],
	[AS_HELP_STRING([--disable-hardening],[disable hardening build flags])],,
	[ enable_hardening="yes" ])

AC_ARG_WITH([sanitizers],
	[AS_HELP_STRING([--with-sanitizers=...,...],
			[enable SANitizer build, do *NOT* use for production. Only ASAN/UBSAN/TSAN are currently supported])],
	[ SANITIZERS="$withval" ],
	[ SANITIZERS="" ])

AC_ARG_WITH([testdir],
	[AS_HELP_STRING([--with-testdir=DIR],[path to /usr/lib../kronosnet/tests/ dir where to install the test suite])],
	[ TESTDIR="$withval" ],
	[ TESTDIR="$libdir/kronosnet/tests" ])

## do subst

AC_SUBST([TESTDIR])

# debug build stuff
if test "x${enable_debug}" = xyes; then
	AC_DEFINE_UNQUOTED([DEBUG], [1], [Compiling Debugging code])
	OPT_CFLAGS="-O0"
	RUST_FLAGS=""
	RUST_TARGET_DIR="debug"
else
	OPT_CFLAGS="-O3"
	RUST_FLAGS="--release"
	RUST_TARGET_DIR="release"
fi

# check flags for CMSG_SPACE()
AC_CACHE_CHECK([for CMSG_SPACE() requiring _XOPEN_SOURCE], [ac_cv_macro_xopen_source], [
	ac_cv_macro_xopen_source=yes
	saveCPPFLAGS="$CPPFLAGS"
	CPPFLAGS="-Werror $CPPFLAGS"
	# First, try to link with strdup() using standard flags
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/socket.h>
	], [
	        unsigned char c = CMSG_SPACE(1);
	])], [ac_cv_macro_xopen_source=no], [
		# Failure, try again with -D_XOPEN_SOURCE
		XOPEN_CPPFLAGS="-D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED=1"
		CPPFLAGS="$CPPFLAGS $XOPEN_CPPFLAGS"
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
			#include <sys/socket.h>
		], [
		        unsigned char c = CMSG_SPACE(1);
		],
		[ac_cv_macro_xopen_source=yes],
		[AC_MSG_ERROR([no CMSG_SPACE() found])])])
	])
	CPPFLAGS="$saveCPPFLAGS"
])

AC_SUBST([XOPEN_CPPFLAGS])

# Check for availablility of hardening options

annocheck=no

if test "x${enable_hardening}" = xyes; then
	# support only gcc for now
	if echo $CC | grep -q gcc; then
		ANNOPLUGIN="-fplugin=annobin"
		annocheck=yes
	fi

	FORTIFY_CFLAGS=""
	if test "x${enable_debug}" != xyes; then
		for j in 3 2; do
			FORTIFY_CFLAGS_TEMP="-D_FORTIFY_SOURCE=$j"
			if cc_supports_flag "$OPT_CFLAGS $FORTIFY_CFLAGS_TEMP"; then
				FORTIFY_CFLAGS="$FORTIFY_CFLAGS_TEMP"
				break
			fi
		done
	fi

	HARDENING_CFLAGS_ANNOCHECK="$ANNOPLUGIN -fPIC -DPIC"
	case "$host_os" in
		solaris*)
			# no support for -pie when linking, but supported during compile
			;;
		*)
			HARDENING_CFLAGS_ANNOCHECK="$HARDENING_CFLAGS_ANNOCHECK -pie"
			;;
	esac
	HARDENING_CFLAGS_ANNOCHECK="$HARDENING_CFLAGS_ANNOCHECK -fstack-protector-strong -fexceptions -D_GLIBCXX_ASSERTIONS -Wl,-z,now"
	HARDENING_CFLAGS="-fstack-clash-protection -fcf-protection=full -mcet -mstackrealign"
	EXTRA_HARDENING_CFLAGS=""

	# check for annobin required cflags/ldflags
	for j in $HARDENING_CFLAGS_ANNOCHECK; do
		if cc_supports_flag $j; then
			EXTRA_HARDENING_CFLAGS="$EXTRA_HARDENING_CFLAGS $j"
		else
			annocheck=no
		fi
	done

	# check for other hardening cflags/ldflags
	for j in $HARDENING_CFLAGS; do
		if cc_supports_flag $j; then
			EXTRA_HARDENING_CFLAGS="$EXTRA_HARDENING_CFLAGS $j"
		fi
	done

	EXTRA_HARDENING_CFLAGS="$EXTRA_HARDENING_CFLAGS $FORTIFY_CFLAGS"

	# check if annocheck binary is available
	if test "x${annocheck}" = xyes; then
		AC_CHECK_PROGS([ANNOCHECK_EXEC], [annocheck])
		if test "x${ANNOCHECK_EXEC}" = x; then
			annocheck=no
		fi
	fi

	AM_LDFLAGS="$AM_LDFLAGS $EXTRA_HARDENING_CFLAGS"
fi

if test "x${enable_debug}" = xyes; then
	annocheck=no
fi

AM_CONDITIONAL([HAS_ANNOCHECK], [test "x$annocheck" = "xyes"])

# gdb flags
if test "x${GCC}" = xyes; then
	GDB_CFLAGS="-ggdb3"
else
	GDB_CFLAGS="-g"
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
UNWANTED_CFLAGS="-Wno-unused-parameter -Wno-gnu-folding-constant"

# check for character index warning
AC_CACHE_CHECK([if -Wchar-subscripts warns for int8_t], [ac_cv_int8_t_warn], [
	saveCFLAGS="$CFLAGS"
	CFLAGS="-Werror -Wchar-subscripts"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <stdint.h>], [
			   char arr[256];
			   uint8_t i = 200;
			   arr[i] = 'J';
			   return 0;
			  ])],
			  [ac_cv_int8_t_warn=no],
			  [ac_cv_int8_t_warn=yes])
	CFLAGS="$saveCFLAGS"
])
if test "x$ac_cv_int8_t_warn" = xyes; then
	UNWANTED_CFLAGS="$UNWANTED_CFLAGS -Wno-char-subscripts"
fi

AC_SUBST([AM_CFLAGS],["$SANITIZERS_CFLAGS $OPT_CFLAGS $GDB_CFLAGS $DEFAULT_CFLAGS $EXTRA_HARDENING_CFLAGS $UNWANTED_CFLAGS"])
LDFLAGS="$SANITIZERS_LDFLAGS $LDFLAGS"
AC_SUBST([AM_LDFLAGS])
AC_SUBST([RUST_FLAGS])
AC_SUBST([RUST_TARGET_DIR])

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
		libnozzle/Makefile
		libnozzle/libnozzle.pc
		libnozzle/tests/Makefile
		libnozzle/bindings/Makefile
		libnozzle/bindings/rust/Makefile
		libnozzle/bindings/rust/Cargo.toml
		libnozzle/bindings/rust/tests/Makefile
		libnozzle/bindings/rust/tests/Cargo.toml
		libknet/Makefile
		libknet/libknet.pc
		libknet/tests/Makefile
		libknet/bindings/Makefile
		libknet/bindings/rust/Makefile
		libknet/bindings/rust/Cargo.toml
		libknet/bindings/rust/tests/Makefile
		libknet/bindings/rust/tests/Cargo.toml
		man/Makefile
		man/Doxyfile-knet
		man/Doxyfile-nozzle
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
