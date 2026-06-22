SUBDIRS = KeyStore/cli

LIBVES_CFILES = libVES.c \
libVES/Util.c \
libVES/List.c \
libVES/Cipher.c \
libVES/CiAlgo_AES.c \
libVES/VaultKey.c \
libVES/KeyAlgo_EVP.c \
libVES/VaultItem.c \
libVES/Ref.c \
libVES/User.c \
libVES/File.c \
libVES/Event.c \
libVES/Session.c \
libVES/REST.c \
libVES/KeyStore.c \
libVES/Watch.c \
libVES/Flow.c

LIBVES_HFILES = libVES.h \
libVES/List.h \
libVES/Cipher.h \
libVES/CiAlgo_AES.h \
libVES/VaultKey.h \
libVES/KeyAlgo_EVP.h \
libVES/VaultItem.h \
libVES/Ref.h \
libVES/User.h \
libVES/File.h \
libVES/Event.h \
libVES/Session.h \
libVES/REST.h \
libVES/KeyStore.h \
libVES/Watch.h \
libVES/Flow.h

if HAVE_LIBOQS
LIBVES_CFILES += libVES/KeyAlgo_OQS.c
LIBVES_HFILES += libVES/KeyAlgo_OQS.h
endif

JVAR_CFILES = jVar.c

JVAR_HFILES = jVar.h

VL_CFILES = VESlocker.c

VL_HFILES = VESlocker.h

VF_CFILES = VESflow.c

VF_HFILES = VESflow.h

lib_LTLIBRARIES = libVES.la
nobase_include_HEADERS = $(LIBVES_HFILES) $(JVAR_HFILES) $(VL_HFILES)
# Internal headers: shipped in the source tarball so the library builds, but
# NOT installed to includedir (libVES.Util etc. are private to libVES).
noinst_HEADERS = libVES/Util.h

libVES_la_SOURCES = $(LIBVES_CFILES) $(JVAR_CFILES) $(VL_CFILES) $(VF_CFILES) $(LIBVES_HFILES) $(JVAR_HFILES) $(VL_HFILES) $(VF_HFILES)
libVES_la_LIBADD = -lcrypto -lcurl $(LIBOQS)
# -no-undefined is required for libtool to build a shared library (DLL) on
# Windows/PE, where shared objects may not contain unresolved symbols. Without
# it libtool silently builds static-only, and the --whole-archive keystore fold
# below (a shared-link step) never runs -> libVES_KeyStore_cli stays undefined.
libVES_la_LDFLAGS = -version-info 1:0:0 -no-undefined
if LIBVES_KEYSTORE
# WHOLE_ARCHIVE_BEGIN/END are set by configure per host: GNU ld uses
# --whole-archive/--no-whole-archive, the macOS ld64 linker uses -force_load.
libVES_la_LDFLAGS += $(WHOLE_ARCHIVE_BEGIN)KeyStore/$(LIBVES_KEYSTORE)/libVES_KeyStore_$(LIBVES_KEYSTORE).a$(WHOLE_ARCHIVE_END)
EXTRA_libVES_la_DEPENDENCIES = KeyStore/$(LIBVES_KEYSTORE)/libVES_KeyStore_$(LIBVES_KEYSTORE).a
endif

# KeyStore/cli has its own cross-platform Makefile (not automake); ship the
# shared keydir sources here so `make dist` produces a buildable tarball.
# (KeyStore/cli/* are shipped by that subdir's own distdir target.)
EXTRA_DIST = KeyStore/keydir.c KeyStore/keydir.h
