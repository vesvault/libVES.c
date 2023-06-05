CLI_OBJS = KeyStore_cli.o KeyStore_cli_locale.o ../keydir.o
CLI_LIB=libVES_KeyStore_cli.a

CPPFLAGS = -fPIC

CLI_OBJS_WIN = KeyStore_cli.obj KeyStore_cli_locale.obj ../keydir.obj
CLI_LIB_WIN=libVES_KeyStore_cli.lib
AR_WIN=lib

$(CLI_LIB): $(CLI_OBJS)
	$(AR) cru $(CLI_LIB) $(CLI_OBJS)

.c.obj:
	$(CC) $(CFLAGS) -Fo:$@ -c $<

$(CLI_LIB_WIN): $(CLI_OBJS_WIN)
	$(AR_WIN) /OUT:$(CLI_LIB_WIN) $(CLI_OBJS_WIN) shell32.lib

all: $(CLI_LIB)

install:
	true

clean:
	rm -f $(CLI_LIB) $(CLI_OBJS)

