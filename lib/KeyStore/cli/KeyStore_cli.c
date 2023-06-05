/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //            VES Utility:   A command line interface to libVES
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2023 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * KeyStore_cli.c                   libVES: CLI key store module
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#endif


#include "../keydir.h"
#include "../../libVES/KeyStore.h"
#include "KeyStore_cli_locale.h"

const char **libVES_KeyStore_cli_path(libVES_KeyStore *ks);
void *libVES_KeyStore_cli_dialog(libVES_KeyStore_dialog *dlg);

struct libVES_KeyStore_keydir libVES_KeyStore_cli_keydir = {
    .pathfn = &libVES_KeyStore_cli_path,
    .chain = {
	.getfn = NULL,
	.putfn = NULL,
	.deletefn = NULL
    }
};

struct libVES_KeyStore libVES_KeyStore_cli = {
    .getfn = &libVES_KeyStore_keydir_get,
    .putfn = &libVES_KeyStore_keydir_put,
    .deletefn = &libVES_KeyStore_keydir_delete,
    .dialogfn = &libVES_KeyStore_cli_dialog,
    .store = &libVES_KeyStore_cli_keydir
};

struct cli_ctl {
#ifdef _WIN32
    HANDLE tty_in;
    HANDLE tty_out;
#else
    int fd;
#endif
    int flags;
    const struct libVES_KeyStore_cli_locale *locale;
    const char *path[8];
    char home[0];
};

#define	CLI_HEADING	0x0001
#define	CLI_SYNCODE	0x0002
#define	CLI_ANSI	0x0010
#define	CLI_ERR		0x0100

const char *libVES_KeyStore_cli_globaldir = "/usr/share/ves/";

static struct cli_ctl *libVES_KeyStore_cli_ctl(libVES_KeyStore *ks) {
    if (!ks->ctl) {
	struct cli_ctl *ctl;
	const char **ppath;
	const char *dir = getenv("VES_KEYSTORE");
	if (dir) {
	    ctl = malloc(sizeof(struct cli_ctl) + strlen(dir) + 1);
	    strcpy(ctl->home, dir);
	    char *s = ctl->home;
	    ppath = ctl->path;
	    while (s && ppath < ctl->path + sizeof(ctl->path) - sizeof(*ctl->path)) {
		*ppath++ = s;
		s = strchr(s, ':');
		if (s) *s++ = 0;
	    }
	} else {
#ifdef _WIN32
	    ctl = malloc(sizeof(struct cli_ctl) + MAX_PATH);
	    ppath = ctl->path;
	    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, ctl->home))) {
		ctl = realloc(ctl, sizeof(struct cli_ctl) + strlen(ctl->home) + 8);
		strcat(ctl->home, "\\.ves\\");
		*ppath++ = ctl->home;
	    }
#else
	    dir = getenv("HOME");
	    ctl = malloc(sizeof(struct cli_ctl) + (dir ? strlen(dir) + 8 : 0));
	    ppath = ctl->path;
	    if (dir) {
		sprintf(ctl->home, "%s/.ves/", dir);
		*ppath++ = ctl->home;
	    }
#endif
	    *ppath++ = libVES_KeyStore_cli_globaldir;
	}
	ctl->locale = &libVES_KeyStore_cli_locale_default;
#ifdef _WIN32
	ctl->tty_in = ctl->tty_out = INVALID_HANDLE_VALUE;
#else
	ctl->fd = -1;
#endif
	ctl->flags = 0;
	*ppath = NULL;
	ks->ctl = ctl;
    }
    return ks->ctl;
}

const char **libVES_KeyStore_cli_path(libVES_KeyStore *ks) {
    return libVES_KeyStore_cli_ctl(ks)->path;
}


#ifdef _WIN32

#define sleep(sec)	_sleep(sec)

void libVES_KeyStore_cli_close(struct cli_ctl *ctl) {
    if (ctl->tty_in != INVALID_HANDLE_VALUE) CloseHandle(ctl->tty_in);
    if (ctl->tty_out != INVALID_HANDLE_VALUE) CloseHandle(ctl->tty_out);
    ctl->tty_in = ctl->tty_out = INVALID_HANDLE_VALUE;
}

int libVES_KeyStore_cli_open(struct cli_ctl *ctl) {
    if (ctl->tty_in == INVALID_HANDLE_VALUE) ctl->tty_in = CreateFile( "CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
    if (ctl->tty_out == INVALID_HANDLE_VALUE) ctl->tty_out = CreateFile( "CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0 );
    if (ctl->tty_in == INVALID_HANDLE_VALUE || ctl->tty_out == INVALID_HANDLE_VALUE) return libVES_KeyStore_cli_close(ctl), 0;
    int mode;
    if (GetConsoleMode(ctl->tty_out, &mode) && (mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING) && SetConsoleMode(ctl->tty_out, mode)) ctl->flags |= CLI_ANSI;
    return 1;
}

static char *libVES_KeyStore_cli_in(struct cli_ctl *ctl, char *buf, int len) {
    int mode;
    if (!GetConsoleMode(ctl->tty_in, &mode)) return NULL;
    mode &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(ctl->tty_in, mode)) return NULL;
    char *bufp = buf;
    char *tail = buf + len - 1;
    int r = -1;
    while (bufp < tail && (ReadConsole(ctl->tty_in, bufp, 1, &r, 0))) {
	if (*bufp == 0x0d || *bufp == 0x0a) break;
	bufp++;
    }
    *bufp = 0;
    mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(ctl->tty_in, mode);
    return buf;
}

static void libVES_KeyStore_cli_write(struct cli_ctl *ctl, const char *s, int len) {
    if (!WriteConsole(ctl->tty_out, s, len, NULL, 0)) ctl->flags |= CLI_ERR;
}

#else // UNIX

void libVES_KeyStore_cli_close(struct cli_ctl *ctl) {
    if (ctl->fd >= 0) {
	close(ctl->fd);
	ctl->fd = -1;
    }
}

int libVES_KeyStore_cli_open(struct cli_ctl *ctl) {
    if (ctl->fd >= 0) return 1;
    if ((ctl->fd = open("/dev/tty", O_RDWR)) < 0) return 0;
    if (getpgrp() != tcgetpgrp(ctl->fd)) return libVES_KeyStore_cli_close(ctl), 0;
    struct winsize wsize;
    if (ioctl(ctl->fd, TIOCGWINSZ, &wsize) >= 0) ctl->flags |= CLI_ANSI;
    return 1;
}

static char *libVES_KeyStore_cli_in(struct cli_ctl *ctl, char *buf, int len) {
    if (ctl->flags & CLI_ERR) return NULL;
    struct termios t;
    if (tcgetattr(ctl->fd, &t) < 0) return NULL;
    t.c_lflag &= ~ECHO;
    if (tcsetattr(ctl->fd, TCSANOW, &t) < 0) return NULL;
    char *bufp = buf;
    char *tail = buf + len - 1;
    int r = -1;
    while ((r = read(ctl->fd, bufp, 1)) > 0 && bufp < tail) {
	if (*bufp == 0x0a) break;
	bufp++;
    }
    *bufp = 0;
    if (tcgetattr(ctl->fd, &t) < 0) r = -1;
    t.c_lflag |= ECHO;
    if (tcsetattr(ctl->fd, TCSANOW, &t) < 0) r = -1;
    if (r >= 0) return buf;
    return NULL;
}

static void libVES_KeyStore_cli_write(struct cli_ctl *ctl, const char *s, int len) {
    if (!(ctl->flags & CLI_ERR) && write(ctl->fd, s, len) < 0) ctl->flags |= CLI_ERR;
}

#endif // UNIX / _WIN32

static void libVES_KeyStore_cli_outv(struct cli_ctl *ctl, const char *s) {
    const char *h = s;
    char c;
    do {
	c = *h;
	if (!(c & 0xe0)) {
	    if (h > s) libVES_KeyStore_cli_write(ctl, s, h - s);
	    s = h + 1;
	}
	h++;
    } while (c);
}

static void libVES_KeyStore_cli_outs(struct cli_ctl *ctl, const char *s) {
    switch (*s) {
	case 0x1b:
	    if (!(ctl->flags & CLI_ANSI)) return;
	    break;
	case 0x0d:
	default:
	    break;
    }
    libVES_KeyStore_cli_write(ctl, s, strlen(s));
}

static void libVES_KeyStore_cli_out(struct cli_ctl *ctl, const char **s) {
    while (*s) libVES_KeyStore_cli_outs(ctl, *s++);
}

void *libVES_KeyStore_cli_dialog(libVES_KeyStore_dialog *dlg) {
    struct cli_ctl *ctl = libVES_KeyStore_cli_ctl(dlg->ks);

    switch (dlg->state) {
	case LIBVES_KSD_CLOSE:
	case LIBVES_KSD_EXPIRE:
	case LIBVES_KSD_ERROR:
	case LIBVES_KSD_DONE:
	    libVES_KeyStore_cli_close(ctl);
	    dlg->state = LIBVES_KSD_DONE;
	    return NULL;
	default:
	    break;
    }
    if (!libVES_KeyStore_cli_open(ctl)) {
	dlg->state = LIBVES_KSD_ERROR;
	return NULL;
    }
    if (!(ctl->flags & CLI_HEADING)) {
	ctl->flags |= CLI_HEADING;
	libVES_KeyStore_cli_out(ctl, ctl->locale->head);
	if (dlg->domain) {
	    libVES_KeyStore_cli_out(ctl, ctl->locale->domain);
	    libVES_KeyStore_cli_outv(ctl, dlg->domain);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->domain2);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->keyname);
	    libVES_KeyStore_cli_outv(ctl, dlg->extid);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->keyname2);
	} else {
	    libVES_KeyStore_cli_out(ctl, ctl->locale->keyname);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->primary);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->keyname2);
	}
	if (dlg->email) {
	    libVES_KeyStore_cli_out(ctl, ctl->locale->user);
	    libVES_KeyStore_cli_outv(ctl, dlg->email);
	    libVES_KeyStore_cli_out(ctl, ctl->locale->user2);
	}
    }
    if (dlg->syncode && !(ctl->flags & CLI_SYNCODE)) {
	ctl->flags |= CLI_SYNCODE;
	libVES_KeyStore_cli_out(ctl, ctl->locale->syncode);
	libVES_KeyStore_cli_outv(ctl, dlg->syncode);
	libVES_KeyStore_cli_out(ctl, ctl->locale->syncode2);
    }
    if (dlg->state == LIBVES_KSD_NOUSER) {
	libVES_KeyStore_cli_out(ctl, ctl->locale->nouser);
	dlg->state = LIBVES_KSD_DONE;
    }
    if (dlg->state == LIBVES_KSD_PINRETRY && dlg->retry) {
	char buf[16];
	sprintf(buf, "%d", dlg->retry);
	libVES_KeyStore_cli_out(ctl, ctl->locale->retry);
	libVES_KeyStore_cli_outv(ctl, buf);
	libVES_KeyStore_cli_out(ctl, ctl->locale->retry2);
	sleep(dlg->retry);
	dlg->state = LIBVES_KSD_INIT;
    }
    else if (dlg->pin) {
	libVES_KeyStore_cli_out(ctl, ctl->locale->pin);
	dlg->state = libVES_KeyStore_cli_in(ctl, dlg->pin, dlg->pinmax) ? LIBVES_KSD_PIN : LIBVES_KSD_ERROR;
	libVES_KeyStore_cli_out(ctl, ctl->locale->pin2);
    }
    if (ctl->flags & CLI_ERR) dlg->state = LIBVES_KSD_ERROR;
    return ctl;
}

