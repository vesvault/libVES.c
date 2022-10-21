#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ([2.69])
AC_INIT([VES], [1.08], [bugs@vesvault.com])
AC_CONFIG_SRCDIR([src/ves-util.c])
AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.0 subdir-objects])

AM_MAINTAINER_MODE([disable])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for libraries.
AC_ARG_WITH([oqs],
    [AS_HELP_STRING([--with-oqs],
          [enable experimental support for liboqs])],
    [],
    [])
LIBOQS=
    AS_IF([test "x$with_oqs" != xno],
        [AC_CHECK_LIB([oqs], [OQS_KEM_new],
            [AC_SUBST([LIBOQS], ["-loqs"])
                AC_DEFINE([HAVE_LIBOQS], [1],
                    [Define if you have liboqs])
		AM_CONDITIONAL([HAVE_LIBOQS], [test 1])
            ],
            [AC_MSG_FAILURE(
                [--with-oqs was given, but test for liboqs failed])],
            [-lcrypto]
        )],
	[AM_CONDITIONAL([HAVE_LIBOQS], [test])]
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

AC_CONFIG_FILES([Makefile lib/Makefile src/Makefile])
AC_OUTPUT

