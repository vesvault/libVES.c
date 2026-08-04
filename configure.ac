#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ([2.69])
# Version is read from LIBVES_VERSION_CODE in lib/libVES.h (single source of
# truth) so the release/tarball/.pc version never drifts from the library.
# VESUTIL_VERSION_CODE in src/ves-util.h tracks the ves(1) CLI separately.
AC_INIT([libVES],
    m4_esyscmd_s([awk '$2=="LIBVES_VERSION_CODE"{gsub(/"/,"",$3);print $3}' lib/libVES.h]),
    [bugs@vesvault.com])
AC_CONFIG_SRCDIR([src/ves-util.c])
AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign 1.0 subdir-objects])

AM_MAINTAINER_MODE([disable])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for libraries.
# Post-quantum support via liboqs (ML-KEM / FIPS 203) is REQUIRED by default:
# configure fails if liboqs is not found. Pass --without-oqs to build a
# classical-only library (not recommended; loses harvest-now-decrypt-later
# protection for newly generated keys).
AC_ARG_WITH([oqs],
    [AS_HELP_STRING([--without-oqs],
          [build without post-quantum support (liboqs); not recommended])],
    [],
    [with_oqs=yes])
LIBOQS=
AC_SUBST([LIBOQS])
    AS_IF([test "x$with_oqs" != xno],
        [AC_CHECK_LIB([oqs], [OQS_KEM_new],
            [AC_SUBST([LIBOQS], ["-loqs"])
                AC_DEFINE([HAVE_LIBOQS], [1],
                    [Define if you have liboqs])
		AM_CONDITIONAL([HAVE_LIBOQS], [test 1])
            ],
            [AC_MSG_FAILURE([
liboqs was not found, but post-quantum support is enabled by default.
Install liboqs from https://github.com/open-quantum-safe/liboqs -- it is also
packaged by Homebrew, MSYS2, Fedora and Arch -- then re-run configure.
To build a classical-only library instead, re-run with --without-oqs.])],
            [-lcrypto]
        )],
	[AM_CONDITIONAL([HAVE_LIBOQS], [test])]
    )

# The KEM used for newly generated OQS vault keys. It has to be an algorithm
# the linked liboqs actually compiled in: liboqs before 0.10 has no ML-KEM at
# all (it spells these sets "Kyber*"), and a trimmed liboqs can omit whole
# families. Neither shows up until key generation fails at runtime, so fail
# here instead -- lib/libVES/KeyAlgo_OQS.c repeats the check at compile time.
# Existing keys carry their own algorithm in the stored method string, so this
# only affects newly generated ones.
AC_ARG_WITH([oqs-algo],
    [AS_HELP_STRING([--with-oqs-algo=ALGO],
	  [liboqs KEM for newly generated vault keys @<:@default=ML-KEM-768@:>@])],
    [],
    [with_oqs_algo=ML-KEM-768])
    AS_IF([test "x$with_oqs" != xno],
	[
	    # liboqs pairs each algorithm's identifier macro OQS_KEM_alg_<token>
	    # with an OQS_ENABLE_KEM_<token>, where <token> is the identifier
	    # lowercased with '-' turned into '_' ("ML-KEM-768" -> ml_kem_768).
	    oqs_algo_token=`echo "$with_oqs_algo" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ-' 'abcdefghijklmnopqrstuvwxyz_'`
	    AC_MSG_CHECKING([whether liboqs provides $with_oqs_algo])
	    AC_COMPILE_IFELSE(
		[AC_LANG_SOURCE([[
#include <oqs/oqs.h>
#if !defined(OQS_ENABLE_KEM_]$oqs_algo_token[)
#error algorithm not enabled in this liboqs build
#endif
/* Also proves the token names an algorithm this liboqs knows. */
const char *libves_oqs_algo_check = OQS_KEM_alg_]$oqs_algo_token[;
		]])],
		[AC_MSG_RESULT([yes])
		    AC_DEFINE_UNQUOTED([LIBVES_KEYALGO_OQS_DEFAULT], ["$with_oqs_algo"],
			[liboqs KEM for newly generated vault keys])
		    AC_DEFINE_UNQUOTED([LIBVES_KEYALGO_OQS_DEFAULT_ENABLE], [OQS_ENABLE_KEM_$oqs_algo_token],
			[liboqs enable macro for LIBVES_KEYALGO_OQS_DEFAULT, rechecked at compile time])
		],
		[AC_MSG_RESULT([no])
		    AC_MSG_FAILURE([
The installed liboqs does not provide $with_oqs_algo -- OQS_ENABLE_KEM_$oqs_algo_token
is not set in <oqs/oqsconfig.h>.

Most often this means liboqs is too old: ML-KEM (FIPS 203) arrived in liboqs
0.10, and libVES additionally wants 0.13 or newer for seed-based key import.
It can also mean liboqs was built with this algorithm family switched off.

Upgrade or rebuild liboqs, or pick a different set with --with-oqs-algo=ALGO,
naming it exactly as liboqs does (see the OQS_KEM_alg_* macros in
<oqs/kem.h>). Note that ALGO is mapped to the enable macro by lowercasing and
turning '-' into '_', which holds for ML-KEM but not for every family.

To build a classical-only library instead, re-run with --without-oqs.])]
	    )
	]
    )

AC_ARG_WITH([keystore],
    [AS_HELP_STRING([--with-keystore],
          [build with a keystore module from lib/KeyStore])],
    [],
    [with_keystore=cli])
LIBVES_KEYSTORE=
    AS_IF([test "x$with_keystore" != xno],
	[AC_SUBST([LIBVES_KEYSTORE], [$with_keystore])
	    AC_DEFINE_UNQUOTED([LIBVES_KEYSTORE], [$with_keystore],
                    [Define the keystore module from lib/KeyStore])
	    AM_CONDITIONAL([LIBVES_KEYSTORE], [test 1])
        ],
	[AM_CONDITIONAL([LIBVES_KEYSTORE], [test])]
    )

# The keystore static archive is folded whole into the shared library so its
# symbols (libVES_KeyStore_cli etc.) get exported. GNU ld spells this
# --whole-archive/--no-whole-archive; the macOS (ld64/cctools) linker does not
# understand those options and uses -force_load <archive> instead.
AC_CANONICAL_HOST
case "$host_os" in
    darwin*)
	WHOLE_ARCHIVE_BEGIN="-Wl,-force_load,"
	WHOLE_ARCHIVE_END=""
	;;
    *)
	WHOLE_ARCHIVE_BEGIN="-Wl,--whole-archive,"
	WHOLE_ARCHIVE_END=",--no-whole-archive"
	;;
esac
AC_SUBST([WHOLE_ARCHIVE_BEGIN])
AC_SUBST([WHOLE_ARCHIVE_END])



# Checks for header files.
AC_CHECK_HEADERS([malloc.h string.h stddef.h fcntl.h unistd.h sys/ioctl.h openssl/evp.h curl/curl.h termios.h windows.h oqs/oqs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_OFF_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strdup strndup memmove memset strerror])

AC_PREFIX_DEFAULT(/usr)

AC_CONFIG_FILES([Makefile lib/Makefile src/Makefile libVES.pc])
AC_OUTPUT

