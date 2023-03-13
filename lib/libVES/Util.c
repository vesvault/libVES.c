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
 * (c) 2018 VESvault Corp
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
 * libVES/Util.c              libVES: Internal utilities
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <assert.h>
#include "Util.h"
#include "List.h"
#include "../libVES.h"


size_t libVES_b64decode(const char *b64, char **dec) {
    static const unsigned char map[0x60] = {
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3e,0xff,0x3e,0xff,0x3f,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
	0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xff,0xff,0xff,0xff,0x3f,
	0xff,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0xff,0xff,0xff,0xff,0xff
    };
    const char *p = b64;
    unsigned char c;
    if (!*dec) *dec = malloc(libVES_b64decsize(strlen(b64)));
    char *d = *dec;
    assert(d);
    int sh = 16;
    int a = 0;
    while ((c = *p++)) if (c >= 0x20 && c < 0x80) {
	unsigned char m = map[c - 0x20];
	if (m == 0xff) continue;
	sh -= 6;
	a |= m << sh;
	if (sh <= 8) {
	    *d++ = a >> 8;
	    a <<= 8;
	    sh += 8;
	}
    }
    return d - *dec;
}

char *libVES_b64encode(const char *data, size_t len, char *b64) {
    static const char map[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    if (!b64) b64 = malloc(libVES_b64encsize(len));
    const unsigned char *s = (const unsigned char *) data;
    size_t l = len;
    char *d = b64;
    assert(d);
    unsigned char c, cc;
    while (l > 0) {
	*d++ = map[(c = *s++) >> 2];
	*d++ = map[((c & 0x03) << 4) | (--l > 0 ? (cc = *s++) >> 4 : 0)];
	*d++ = map[l > 0 ? (((cc & 0x0f) << 2) | (--l > 0 ? (c = *s++) : 0) >> 6) : 0x40];
	*d++ = map[l > 0 ? (l--, c & 0x3f) : 0x40];
    }
    *d = 0;
    return b64;
}

int libVES_enumStrl(const char *str, size_t len, const char **list) {
    int i;
    for (i = 0; i < len; i++) if (!strcmp(str, list[i])) return i;
    return -1;
}

void libVES_initEVP() {
    static char init = 0;
    if (init) return;
    OpenSSL_add_all_algorithms();
    init = 1;
}

void libVES_setError(libVES *ves, int err, const char *msg) {
    if (!ves) return;
    ves->error = err;
    ves->errorMsg = msg;
    free(ves->errorBuf);
    ves->errorBuf = NULL;
}

void libVES_setError0(libVES *ves, int err, char *msg) {
    libVES_setError(ves, err, msg);
    if (ves) ves->errorBuf = msg;
}

void libVES_setErrorEVP(libVES *ves, int err, const char *scope) {
    static char err_loaded = 0;
    if (!err_loaded) ERR_load_crypto_strings();
    err_loaded = 1;
    unsigned long int e = ERR_get_error();
    int bufl = 512;
    char *buf = malloc(bufl);
    if (buf) {
	sprintf(buf, "[%s]", scope);
	while (e) {
	    int l = strlen(buf);
	    if (l < bufl - 8) {
		buf[l++] = ' ';
		buf[l] = 0;
		ERR_error_string_n(e, buf + l, bufl - l - 1);
	    }
	    e = ERR_get_error();
	}
    }
    libVES_setError0(ves, err, buf);
}

void *libVES_lookupAlgo(const char *str, struct libVES_List *lst) {
    char sbuf[24];
    if (!str) return NULL;
    const char *p = strchr(str, ':');
    if (p) {
	if (p - str >= sizeof(sbuf)) return NULL;
	memcpy(sbuf, str, p - str);
	sbuf[p - str] = 0;
	str = sbuf;
    }
    return libVES_List_find(lst, &str);
}

int libVES_cmpAlgoLST(void *a, void *b) {
    return strcmp(*((char **) a), *((char **) b));
}

const libVES_ListCtl libVES_algoListCtl = { .cmpfn = &libVES_cmpAlgoLST, .freefn = NULL };

char *libVES_buildURI(int argc, ...) {
    static const char hex[] = "0123456789ABCDEF";
    va_list ar;
    va_start(ar, argc);
    char buf[1024] = "ves:/";
    char *p = buf + strlen(buf);
    char *tail = buf + sizeof(buf) - 4;
    int i;
    for (i = 0; i < argc; i++) {
	const char *s = va_arg(ar, const char *);
	*p++ = '/';
	if (p >= tail) break;
	if (s) {
	    unsigned char c;
	    while ((c = *s++)) {
		if (p >= tail) break;
		if ((c >= ',' && c <= '.') || (c >= '0' && c <= ';') || (c >= '@' && c <= 'Z') || (c >= '^' && c <= '~') || c >= 0x80) *p++ = c;
		else {
		    *p++ = '%';
		    *p++ = hex[c >> 4];
		    *p++ = hex[c & 0x0f];
		}
	    }
	}
    }
    *p = 0;
    va_end(ar);
    return strdup(buf);
}
