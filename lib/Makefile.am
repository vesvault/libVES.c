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
libVES/REST.c

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
libVES/REST.h

if HAVE_LIBOQS
LIBVES_CFILES += libVES/KeyAlgo_OQS.c
LIBVES_HFILES += libVES/KeyAlgo_OQS.h
endif

JVAR_CFILES = jVar.c

JVAR_HFILES = jVar.h

lib_LTLIBRARIES = libVES.la
nobase_include_HEADERS = $(LIBVES_HFILES) $(JVAR_HFILES)

libVES_la_SOURCES = $(LIBVES_CFILES) $(JVAR_CFILES) $(LIBVES_HFILES) $(JVAR_HFILES)
libVES_la_LIBADD = $(LIBOQS)
libVES_la_LDFLAGS = -version-info 1:0:0
