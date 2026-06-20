VESUTIL_CFILES = ves-util.c \
ves-util/put.c \
ves-util/get.c \
ves-util/set.c \
ves-util/out.c \
ves-util/ci.c \
ves-util/help.c \
ves-util/hook.c \
ves-util/tty.c \
ves-util/keystore_flags.c

VESUTIL_HFILES = ves-util.h \
ves-util/put.h \
ves-util/get.h \
ves-util/set.h \
ves-util/out.h \
ves-util/ci.h \
ves-util/help.h \
ves-util/hook.h \
ves-util/tty.h \
ves-util/keystore_flags.h

bin_PROGRAMS = ves

dist_man_MANS = ves.1

AM_CPPFLAGS = -I $(top_builddir)/lib

ves_SOURCES = $(VESUTIL_CFILES) $(VESUTIL_HFILES)
ves_LDADD = -lcrypto -lcurl $(top_builddir)/lib/libVES.la

# Platform tty source fragments: #included by ves-util/tty.c (not compiled
# directly), so ship them in the tarball but don't add them to the build.
EXTRA_DIST = ves-util/tty_u.c ves-util/tty_w.c
