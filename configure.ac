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

