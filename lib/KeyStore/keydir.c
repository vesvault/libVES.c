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
 * keydir.c                       libVES: Local directory key storage
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <errno.h>
#include "../libVES/KeyStore.h"
#include "keydir.h"


static int libVES_KeyStore_keydir_badchrs(char *s) {
    char c;
    int ct = 0;
    if (s) while ((c = *s++)) if (c < 0x20 || strchr("\"\'`:;,[](){}<>|^/\\*?\x7f", c)) {
	ct++;
	s[-1] = '.';
    }
    return ct;
}

static char *libVES_KeyStore_keydir_filepath(libVES_KeyStore *ks, const char *path, const char *domain, const char *extid, int flags) {
    if (!path) return NULL;
    int pl = strlen(path);
    int dl = domain ? strlen(domain) : 0;
    char *fname = malloc(pl + dl + strlen(extid) + 16);
    memcpy(fname, path, pl);
    if (domain) {
	strcpy(fname + pl, domain);
	libVES_KeyStore_keydir_badchrs(fname + pl);
	pl += dl;
	fname[pl++] = '^';
    }
    strcpy(fname + pl, extid);
    libVES_KeyStore_keydir_badchrs(fname + pl);
    strcat(fname + pl, ((flags & LIBVES_KS_SESS) ? ".ses" : ((flags & LIBVES_KS_NOPIN) ? ".key" : ".lkr")));
    return fname;
}

int libVES_KeyStore_keydir_get(libVES_KeyStore *ks, const char *domain, const char *extid, char *val, int maxlen, int flags) {
    struct libVES_KeyStore_keydir *kd = ks->store;
    const char **ppath = kd->pathfn(ks);
    const char *path;
    int len = -1;
    while ((path = *ppath++)) {
	char *fpath = libVES_KeyStore_keydir_filepath(ks, path, domain, extid, flags);
	if (!fpath) break;
	int fd = open(fpath, O_RDONLY);
	free(fpath);
	if (fd < 0) continue;
	len = read(fd, val, maxlen);
	close(fd);
	if (len > 0) break;
    }
    if (len < 0 && kd->chain.getfn) len = kd->chain.getfn(ks, domain, extid, val, maxlen, flags);
    return len;
}

int libVES_KeyStore_keydir_put(libVES_KeyStore *ks, const char *domain, const char *extid, const char *val, int len, int flags) {
    struct libVES_KeyStore_keydir *kd = ks->store;
    const char *path = *(kd->pathfn(ks));
    char *fpath = libVES_KeyStore_keydir_filepath(ks, path, domain, extid, flags);
    if (!fpath) return -1;
    int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
	mkdir(path, 0700);
	fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    free(fpath);
    int r = -1;
    if (fd >= 0) {
	r = write(fd, val, len);
	close(fd);
    }
    if (r > 0 && kd->chain.putfn) r = kd->chain.putfn(ks, domain, extid, val, len, flags);
    return r;
}

int libVES_KeyStore_keydir_delete(libVES_KeyStore *ks, const char *domain, const char *extid, int flags) {
    struct libVES_KeyStore_keydir *kd = ks->store;
    char *fpath = libVES_KeyStore_keydir_filepath(ks, *(kd->pathfn(ks)), domain, extid, flags);
    if (!fpath) return -1;
    int r = unlink(fpath);
    free(fpath);
    if (r > 0 && kd->chain.deletefn) r = kd->chain.deletefn(ks, domain, extid, flags);
    return r;
}

