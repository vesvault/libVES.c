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
 * ves-util/out.c             VES Utility: Output handlers
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <libVES.h>
#include <libVES/List.h>
#include <libVES/VaultItem.h>
#include <libVES/Cipher.h>
#include <libVES/Ref.h>
#include <libVES/VaultKey.h>
#include <libVES/User.h>
#include <jVar.h>
#include "../ves-util.h"
#include "out.h"
#include "keystore_flags.h"
#include "tty.h"

int out_list(int fdi, struct ctx_st *ctx) {
    FILE *fd = fdopen(fdi, "a");
    libVES_List *lst = libVES_VaultItem_list(ctx->vkey);
    if (!lst) return_VESerror2("[libVES_VaultItem_list]", ctx->ves);
    size_t i;
    for (i = 0; i < lst->len; i++) {
	char *s;
	libVES_VaultItem *vi = (libVES_VaultItem *) lst->list[i];
	fprintf(fd, "%s\t%s%s\t", (s = libVES_VaultItem_toURIi(vi)), (libVES_VaultItem_isDeleted(vi) ? "!" : ""), libVES_VaultItem_typeStr(vi->type));
	free(s);
	switch (vi->objectType) {
	    case LIBVES_O_FILE:
		if ((s = libVES_VaultItem_toURI(vi))) fprintf(fd, "%s", s);
		free(s);
		break;
	    case LIBVES_O_VKEY:
		if (vi->vaultKey) {
		    if ((s = libVES_VaultKey_toURI(vi->vaultKey))) fprintf(fd, "%s", s);
		    free(s);
		    fprintf(fd, "\t");
		    fprintf(fd, "%s", (s = libVES_VaultKey_toURIi(vi->vaultKey)));
		    free(s);
		}
		break;
	    default:
		break;
	}
	fprintf(fd, "\n");
    }
    libVES_List_free(lst);
    return 0;
}

void out_strings(int fdi, libVES_List *lst) {
    FILE *fd = fdopen(fdi, "a");
    int i;
    for (i = 0; i < lst->len; i++) fprintf(fd, "%s\n", *((char **)(lst->list[i])));
}

int out_keyAlgos(int fdi, struct ctx_st *ctx) {
    FILE *fd = fdopen(fdi, "a");
    int i;
    for (i = 0; i < libVES_VaultKey_algos.len; i++) {
	char method[160];
	libVES_KeyAlgo *a = libVES_VaultKey_algos.list[i];
	fprintf(fd, "%s\n", a->str);
	int j, l;
	for (j = 0; (l = libVES_KeyAlgo_methodstr(a, method, sizeof(method), j)) >= 0; j++) {
	    if (!l) continue;
	    fprintf(fd, "\t%s:%s\n", a->str, method);
	}
    }
    return 0;
}

int out_ciAlgos(int fdi, struct ctx_st *ctx) {
    return out_strings(fdi, &libVES_Cipher_algos), 0;
}

void hex_dump(FILE *fd, size_t len, const char *value) {
    if (params.dump.detect) {
	int wd = tty_get_width(fileno(fd));
	if (wd > 0) {
	    int w0 = 8;
	    int xc = params.dump.col > 0 ? (w0 - 1) / params.dump.col + 1 : 0;
	    int c = (wd - 9) / (w0 * 4 + xc);
	    params.dump.width = c > 0 ? c * w0 : (w0 - 1) / 2 + 1;
	    params.dump.detect = 0;
	}
    }
    const char *v = value;
    const char *vtail = v + len;
    int i;
    for (; v < vtail; ) {
	fprintf(fd, "  %04x:", (int)(v - value));
	const char *vc = v;
	for (i = 0; i < params.dump.width; i++) {
	    if (!(params.dump.col ? i % params.dump.col : i)) fprintf(fd, " ");
	    if (v < vtail) fprintf(fd, " %02x", (unsigned char) *v++);
	    else fprintf(fd, "   ");
	}
	fprintf(fd, "  ");
	while (vc < v) {
	    unsigned char c = *vc;
	    char cw = (c >= 0x20 && c < 0x7f) ? 1 : ((c >= 0xc0 && c < 0xe0) ? 2 : (c >= 0xe0 && c < 0xf0) ? 3 : 0);
	    if (vc + cw > vtail) cw = 0;
	    for (i = 1; i < cw; i++) if ((vc[i] & 0xc0) != 0x80) cw = 0;
	    if (cw) for (i = 0; i < cw; i++) fprintf(fd, "%c", vc[i]);
	    else fprintf(fd, ".");
	    vc++;
	}
	fprintf(fd, "\n");
    }
}

int out_vkey_line(FILE *fd, libVES_VaultKey *vkey) {
    char *uri;
    fprintf(fd, "%s [%s] ", (uri = libVES_VaultKey_toURIi(vkey)), libVES_VaultKey_typeStr(vkey->type));
    free(uri);
    uri = libVES_VaultKey_toURI(vkey);
    if (uri) fprintf(fd, "\"%s\" ", uri);
    free(uri);
    if (vkey->user) fprintf(fd, "(user #%lld)", vkey->user->id);
    fprintf(fd, "\n");
    return 0;
}

int out_explore(int fdi, struct ctx_st *ctx) {
    FILE *fd = fdopen(fdi, "a");
    libVES_VaultItem *vitem;
    libVES_VaultKey *vkey;
    if ((vitem = ctx->vitem)) {
	char *uri;
	fprintf(fd, "Vault Item (%s)", (uri = libVES_VaultItem_toURIi(vitem)));
	free(uri);
	if ((uri = libVES_VaultItem_toURI(vitem))) {
	    fprintf(fd, " \"%s\"", uri);
	    free(uri);
	}
	libVES_VaultKey *vkey = libVES_VaultItem_getVaultKey(vitem);
	if (vkey) {
	    fprintf(fd, " <internal==> ");
	    out_vkey_line(fd, vkey);
	} else fprintf(fd, "\n");
	fprintf(fd, " Type: [%s]%s\n", libVES_VaultItem_typeStr(vitem->type), (libVES_VaultItem_isDeleted(vitem) ? " *deleted" : ""));
	if (vitem->value) {
	    fprintf(fd, " Value: (length = %d)\n", (int) vitem->len);
	    hex_dump(fd, vitem->len, vitem->value);
	} else {
	    fprintf(fd, " Value: (not available)\n");
	}
	fprintf(fd, " Metadata: ");
	if (vitem->meta) {
	    char *m = jVar_toJSON(vitem->meta);
	    fprintf(fd, "%s\n", m);
	    free(m);
	} else fprintf(fd, "(not available)\n");
	fprintf(fd, " Shared with Vault Keys:\n");
	if (vitem->sharelen > 0) {
	    int i;
	    for (i = 0; i < vitem->sharelen; i++) {
		fprintf(fd, "  ");
		out_vkey_line(fd, vitem->share[i]);
	    }
	} else {
	    fprintf(fd, "  (no data)\n");
	}
    } else if ((vkey = ctx->vkey)) {
	fprintf(fd, "Vault Key #%lld:\n", vkey->id);
	fprintf(fd, " Type: [%s] %s\n", libVES_VaultKey_typeStr(vkey->type), libVES_VaultKey_algoStr(vkey->algo));
	fprintf(fd, " Status:");
	if (libVES_VaultKey_unlock(vkey, NULL)) {
	    fprintf(fd, " unlocked");
	    if (vkey->vitem) fprintf(fd, " (indirect)");
	} else fprintf(fd, " locked");
	fprintf(fd, "\n User:");
	if (vkey->user) {
	    fprintf(fd, " #%lld", vkey->user->id);
	    if (vkey->user->firstName || vkey->user->lastName) fprintf(fd, " \"%s %s\"", vkey->user->firstName, vkey->user->lastName);
	    if (vkey->user->email) fprintf(fd, " <%s>", vkey->user->email);
	} else fprintf(fd, " (no data)");
	fprintf(fd, "\n");
	fprintf(fd, " Key Info:\n");
	fflush(fd);
	libVES_VaultKey_dump(vkey, fdi, 0);
    }
    return 0;
}

int out_value(int fd, struct ctx_st *ctx) {
    if (!ctx->vitem || !ctx->vitem->value) VES_throw("[out_value]", params.object, "Value is not available", E_PARAM);
    OUT_IO_assert("[out_value]", write(fd, ctx->vitem->value, ctx->vitem->len));
    return 0;
}

int out_meta(int fd, struct ctx_st *ctx) {
    if (!ctx->vitem) VES_throw("[out_meta]", params.object, "Vault Item is not available", E_PARAM);
    char *json = jVar_toJSON(ctx->vitem->meta);
    int e = json ? write(fd, json, strlen(json)) : 0;
    free(json);
    OUT_IO_assert("[out_meta]", e);
    return 0;
}

int out_cimeta(int fd, struct ctx_st *ctx) {
    libVES_Cipher *ci = libVES_VaultItem_getCipher(ctx->vitem, ctx->ves);
    if (!ci) VES_throw("[out_meta]", params.object, "Cipher is not accessible", E_PARAM);
    int e;
    if (ci->meta) {
	char *s = jVar_toJSON(ci->meta);
	e = write(fd, s, strlen(s));
	free(s);
    } else e = 0;
    libVES_Cipher_free(ci);
    OUT_IO_assert("[out_cimeta]", e);
    return 0;
}

int out_cipher(int fd, struct ctx_st *ctx) {
    libVES_Cipher *ci = libVES_VaultItem_getCipher(ctx->vitem, ctx->ves);
    int e = 0;
    if (ci) {
	const char *s = libVES_Cipher_algoStr(ci->algo);
	if (s) e = write(fd, s, strlen(s));
    } else {
	jVar *a = jVar_get(ctx->vitem->meta, "a");
	if (jVar_isString(a)) e = write(fd, a->vString, a->len);
	else VES_throw("[out_cimeta]", params.object, "Cipher is not accessible", E_PARAM);
    }
    libVES_Cipher_free(ci);
    OUT_IO_assert("[out_cipher]", e);
    return 0;
}

int out_token(int fd, struct ctx_st *ctx) {
    if (!ctx->ves->sessionToken) VES_throw("[out_token]", "", "Session token is not set", E_PARAM);
    OUT_IO_assert("[out_assert]", write(fd, ctx->ves->sessionToken, strlen(ctx->ves->sessionToken)));
    return 0;
}

int out_pub(int fd, struct ctx_st *ctx) {
    if (!ctx->vkey->publicKey) VES_throw("[out_pub]", "", "Public key is not available", E_PARAM);
    OUT_IO_assert("[out_pub]", write(fd, ctx->vkey->publicKey, strlen(ctx->vkey->publicKey)));
    return 0;
}

int out_priv(int fd, struct ctx_st *ctx) {
    char *pk = libVES_VaultKey_getPrivateKey1(ctx->vkey);
    if (!pk) VES_throw("[out_priv]", "", "Private key is not available", E_PARAM);
    int e = write(fd, pk, strlen(pk));
    free(pk);
    OUT_IO_assert("[out_priv]", e);
    return 0;
}

int out_email(int fd, struct ctx_st *ctx) {
    libVES_User *u = libVES_me(ctx->ves);
    if (!u || !u->email) VES_throw("[out_email]", "", "User info is not available", E_PARAM);
    OUT_IO_assert("[out_email]", write(fd, u->email, strlen(u->email)));
    return 0;
}

int out_veskey(int fd, struct ctx_st *ctx) {
    libVES_veskey *veskey = libVES_VaultKey_getVESkey(ctx->vkey);
    if (!veskey) return_VESerror2("[out_veskey]", ctx->ves);
    int e = write(fd, veskey->veskey, veskey->keylen);
    libVES_veskey_free(veskey);
    OUT_IO_assert("[out_veskey]", e);
    return 0;
}

void out_ansi_str(int fdi, const char *str) {
    if (tty_is_ansi(fdi)) {
	write(fdi, str, strlen(str));
	return;
    }
    const char *s = str;
    const char *s0 = s;
    char c;
    char esc = 0;
    do {
	c = *s++;
	if (esc) {
	    if (c == 'm') {
		esc = 0;
		s0 = s;
	    }
	} else {
	    if (c == 0x1b || c == 0) {
		esc = 1;
		int l = s - s0 - 1;
		if (l > 0) write(fdi, s0, l);
	    }
	}
    } while (c);
}

int out_keystore_flags(int fd, struct ctx_st *ctx) {
    struct keystore_flag *f;
    char buf[256];
    for (f = keystore_flags; f->tag; f++) {
	sprintf(buf, "%-8s  %.160s\r\n", f->tag, f->info);
	(void)write(fd, buf, strlen(buf));
    }
    return 0;
}
