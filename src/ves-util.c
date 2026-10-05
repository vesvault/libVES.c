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
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * ves-util.c                 VES Utility Main File
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <libVES.h>
#include <jVar.h>
#include <libVES/List.h>
#include <libVES/VaultKey.h>
#include <libVES/VaultItem.h>
#include <libVES/Ref.h>
#include <libVES/Cipher.h>
#include <libVES/User.h>
#include <libVES/KeyStore.h>
#include <libVES/KeyAlgo_EVP.h>
#include <openssl/crypto.h>
#include "ves-util.h"
#include "ves-util/put.h"
#include "ves-util/get.h"
#include "ves-util/set.h"
#include "ves-util/out.h"
#include "ves-util/ci.h"
#include "ves-util/help.h"
#include "ves-util/hook.h"

#define set_out(fn) { \
    MEM_chk_list(params.out, out); \
    size_t len = params.out->len; \
    params.out->out[len].outfn = fn; \
    params.out->out[len].set.mode = SF_WR; \
    params.out->out[len].set.setfn = NULL; \
    in.setptr = &params.out->out[params.out->len++].set; \
}

struct param_st params = {
    .user = NULL,
    .object = NULL,
    .key = NULL,
    .token = NULL,
    .uveskey = NULL,
    .veskey = NULL,
    .share = NULL,
    .value = NULL,
    .debug = 0,
    .dump = {.width = 16, .col = 4, .detect = 1},
    .apiUrl = NULL,
    .wwwUrl = NULL,
    .pollUrl = NULL,
    .itemType = -1,
    .keyAlgo = NULL,
    .watch = {.startId = 0, .count = -1, .follow = 0, .timeout = 0},
    .ptext = {.setfn = NULL},
    .ctext = {.setfn = NULL},
    .out = NULL,
    .cifn = NULL,
    .cipher = NULL,
    .meta = NULL,
    .cimeta = NULL,
    .priv = NULL,
    .pub = NULL,
    .ictext = NULL,
};

/* Item values and VESkeys go out as raw bytes, the rest as text */
static int out_binary(int (*outfn)(int, struct ctx_st *)) {
    return outfn == &out_value || outfn == &out_veskey;
}

static void offline_out(int (*outfn)(int, struct ctx_st *)) {
    MEM_chk_list(params.out, out);
    params.out->out[params.out->len].outfn = outfn;
    params.out->out[params.out->len].set.mode = SF_WR;
    params.out->out[params.out->len++].set.setfn = NULL;
}

static int offline_has_out(int (*outfn)(int, struct ctx_st *)) {
    int i;
    if (params.out) for (i = 0; i < params.out->len; i++) if (params.out->out[i].outfn == outfn) return 1;
    return 0;
}

static int offline_main() {
    static int (*const outfns[])(int, struct ctx_st *) = {
	&out_value, &out_ictext, &out_meta, &out_cipher, &out_cimeta, &out_pub, &out_priv, &out_veskey, &out_keyalgo, &out_keyAlgos, &out_ciAlgos
    };
    int gen = params.flags & PF_VK_CR;
    const char *opt = NULL;
    int i, j;
    if (params.user) opt = "-a";
    else if (params.primary) opt = "-A";
    else if (params.key) opt = "-k";
    else if (params.token) opt = "-T";
    else if (params.uveskey) opt = "-u";
    else if (params.share) opt = "-s | -r | -S";
    else if (params.flags & PF_KEYSTORE) opt = "-E";
    else if (params.flags & PF_NEW) opt = "-n";
    else if (params.flags & PF_VK_PROP) opt = "-K";
    else if (params.flags & PF_VK_REKEY) opt = "-R";
    else if (params.flags & PF_DEL) opt = "--delete";
    else if (params.flags & PF_FRC) opt = "-U";
    else if (params.flags & PF_LCK) opt = "-L";
    else if (params.flags & PF_WATCH) opt = "-W";
    else if (params.flags & PF_EXPLORE) opt = "-X";
    if (opt) {
	fprintf(stderr, "'%s' cannot be used in offline mode (stream or item crypto without '-o')\n", opt);
	return E_PARAM;
    }
    for (i = 0; params.out && i < params.out->len; i++) {
	for (j = 0; j < sizeof(outfns) / sizeof(*outfns); j++) if (params.out->out[i].outfn == outfns[j]) break;
	if (j >= sizeof(outfns) / sizeof(*outfns)) {
	    fprintf(stderr, "Only -ip, -Ip, -mp, -cp, -zp, -yp, -Yp, -vp, -Gp, -cl, -Gl can print in offline mode\n");
	    return E_PARAM;
	}
    }
    if (!!params.priv + !!params.pub + !!gen > 1) {
	fprintf(stderr, "Use only one of '-g', '-y' and '-Y' in offline mode\n");
	return E_PARAM;
    }
    if (gen && !offline_has_out(&out_priv)) {
	fprintf(stderr, "Save the new private key with '-ypf FILE'\n");
	return E_PARAM;
    }
    if (offline_has_out(&out_veskey) && !params.priv && !gen) {
	fprintf(stderr, "'-vp' needs a private key, '-y' or '-g'\n");
	return E_PARAM;
    }
    /* -yp is encrypted when a VESkey is asked for with -vp (-v, or a generated
     * one), or given with -v for a new key; otherwise it is a plain PEM */
    if (offline_has_out(&out_veskey) || (gen && params.veskey)) {
	for (i = 0; i < params.out->len; i++) if (params.out->out[i].outfn == &out_priv) params.out->out[i].outfn = &out_privenc;
    }
    if (params.value && params.ictext) {
	fprintf(stderr, "Use either '-i' or '-I', not both\n");
	return E_PARAM;
    }
    if (params.ictext && !params.priv) {
	fprintf(stderr, "A private key '-y' is required to decrypt '-I'\n");
	return E_PARAM;
    }
    /* -e with keys to wrap the cipher key for, and no detached -Ip, puts it in
     * the stream header; -d with no -i | -I reads it from there */
    int hdrout = params.cifn == &ci_encrypt && (params.priv || params.pub || gen) && !offline_has_out(&out_ictext);
    int hdrin = params.cifn == &ci_decrypt && !params.value && !params.ictext;
    if (params.pub && params.pub->len > 1 && !hdrout) {
	fprintf(stderr, "Several '-Y' keys go in a stream header: use '-e', without '-Ip'\n");
	return E_PARAM;
    }
    if (hdrin && !params.priv) {
	fprintf(stderr, "Use '-y' to decrypt the stream header, or '-I' with '-y' | '-i' for a detached cipher key\n");
	return E_PARAM;
    }
    if (hdrin && (params.cipher || params.meta)) {
	fprintf(stderr, "The stream header names the cipher, '-c' and '-m' don't apply\n");
	return E_PARAM;
    }

    struct ctx_st ctx = {
	.ves = NULL,
	.vitem = NULL,
	.ci = NULL,
	.vkey = NULL,
	.domain = NULL
    };
    libVES_init(VESUTIL_VERSION_SHORT);
    ctx.ves = libVES_new(NULL);
    if (!ctx.ves) return E_PARAM;
    if (params.debug > 0) ctx.ves->debug = params.debug;
    /* VaultKey getPub() and getPrivateKey() fetch missing key material from the
     * API; nothing here leaves it missing, and an unroutable endpoint makes sure */
    libVES_setOption(ctx.ves, LIBVES_O_APIURL, VESUTIL_OFFLINE_URL);
    libVES_setOption(ctx.ves, LIBVES_O_POLLURL, VESUTIL_OFFLINE_URL);

    /*****************************************
     * The key: -y [-v] private, -Y public (one or more), or -g generated
     */
    const libVES_KeyAlgo *algo = params.keyAlgo ? libVES_VaultKey_algoFromStr(params.keyAlgo) : NULL;
    libVES_VaultKey **rcpt = &ctx.vkey;
    int nrcpt = 0;
    if (params.priv) {
	void *pkey = params.priv;
	if (algo) {
	    libVES_VaultKey stub = {.ves = ctx.ves, .algo = algo};
	    if (!(pkey = algo->str2privfn(&stub, params.priv, params.veskey))) {
		if (!params.veskey && params.debug >= 0) fprintf(stderr, "Use '-v VESKEY' if the private key is encrypted\n");
		return_VESerror("[str2priv]");
	    }
	}
	ctx.vkey = libVES_VaultKey_new(LIBVES_VK_CURRENT, (algo ? algo : &libVES_KeyAlgo_autoPEM), pkey, params.veskey, ctx.ves);
	if (!ctx.vkey) {
	    if (algo) libVES_KeyAlgo_pkeyfree(algo, pkey);
	    if (!params.veskey && params.debug >= 0) fprintf(stderr, "Use '-v VESKEY' if the private key is encrypted\n");
	    return_VESerror("[libVES_VaultKey_new]");
	}
	nrcpt = 1;
    } else if (gen) {
	if (!algo && !(algo = libVES_VaultKey_algoFromStr("OQS"))) {
	    if (params.debug >= 0) fprintf(stderr, "Use '-G ALGO' to specify the key algorithm\n");
	    return E_PARAM;
	}
	void *pkey = libVES_KeyAlgo_pkeygen(algo, params.keyAlgo);
	if (!pkey) return_VESerror("[libVES_KeyAlgo_pkeygen]");
	ctx.vkey = libVES_VaultKey_new(LIBVES_VK_CURRENT, algo, pkey, params.veskey, ctx.ves);
	if (!ctx.vkey) {
	    libVES_KeyAlgo_pkeyfree(algo, pkey);
	    return_VESerror("[libVES_VaultKey_new]");
	}
	nrcpt = 1;
    } else if (params.pub) {
	if (!algo && !(algo = libVES_VaultKey_algoFromStr("OQS"))) {
	    if (params.debug >= 0) fprintf(stderr, "Use '-G ALGO' to specify the public key algorithm\n");
	    return E_PARAM;
	}
	if (!(rcpt = malloc(params.pub->len * sizeof(*rcpt)))) return E_PARAM;
	for (nrcpt = 0; nrcpt < params.pub->len; nrcpt++) {
	    jVar *jvkey = jVar_put(jVar_put(jVar_object(), "algo", jVar_string(algo->str)), "publicKey", jVar_string(params.pub->pem[nrcpt]));
	    rcpt[nrcpt] = libVES_VaultKey_fromJVar(jvkey, ctx.ves);
	    jVar_free(jvkey);
	    if (!rcpt[nrcpt]) return_VESerror("[libVES_VaultKey_fromJVar]");
	}
	ctx.vkey = rcpt[0];
    }

    /*****************************************
     * The dummy item: -i plaintext, or -I decrypted with -y
     */
    ctx.vitem = libVES_VaultItem_new();
    if (!ctx.vitem) return E_PARAM;
    if (params.meta) libVES_VaultItem_setMeta(ctx.vitem, params.meta);
    if (params.value) {
	char *v = malloc(params.value->len + 1);
	if (!v) return E_PARAM;
	memcpy(v, params.value->vString, params.value->len);
	libVES_VaultItem_setValue0(ctx.vitem, params.value->len, v, -1);
    } else if (params.ictext) {
	char *v = NULL;
	int l = libVES_VaultKey_decrypt(ctx.vkey, params.ictext, &v);
	if (l < 0) return_VESerror("[libVES_VaultKey_decrypt]");
	libVES_VaultItem_setValue0(ctx.vitem, l, v, -1);
    }

    /*****************************************
     * -d: the stream header, read off the ciphertext before the stream
     */
    char *hdr = NULL;
    size_t hdrlen = 0;
    int ctfd = -1;
    if (hdrin) {
	char *v;
	size_t vl;
	jVar *meta;
	int e;
	if ((ctfd = ci_get_fd(&params.ctext, 0)) < 0) return E_PARAM;
	if ((e = ci_read_header(ctfd, &hdr, &hdrlen))) return e;
	e = ci_header_open(hdr, hdrlen, ctx.vkey, &v, &vl, &meta);
	free(hdr);
	hdr = NULL;
	if (e) return e;
	libVES_VaultItem_setMeta(ctx.vitem, meta);
	libVES_VaultItem_setValue0(ctx.vitem, vl, v, -1);
    }

    if (params.cifn) {
	/*****************************************
	 * Stream cipher: -c, else -m {"a":...}, else the default algo
	 */
	const char *cistr = params.cipher ? params.cipher : jVar_getStringP(jVar_get(ctx.vitem->meta, "a"));
	const libVES_CiAlgo *cialgo = cistr ? libVES_Cipher_algoFromStr(cistr) : ctx.ves->cipherAlgo;
	if (!cialgo) {
	    if (params.debug >= 0) fprintf(stderr, "Unknown cipher algorithm: %s\n", cistr);
	    return E_PARAM;
	}
	if (!ctx.vitem->value && !hdrout && !offline_has_out(&out_ictext) && !offline_has_out(&out_value)) {
	    if (params.debug >= 0) fprintf(stderr, "Save the new cipher key: '-Y' | '-y' put it in the stream header, '-ipf FILE' saves it raw\n");
	    return E_PARAM;
	}
	ctx.ci = libVES_Cipher_new(cialgo, ctx.ves, (ctx.vitem->value ? ctx.vitem->len : 0), ctx.vitem->value);
	if (!ctx.ci) return_VESerror("[libVES_Cipher_new]");
	if (params.cimeta) libVES_Cipher_setMeta(ctx.ci, params.cimeta);
	if (!libVES_VaultItem_setCipher(ctx.vitem, ctx.ci)) return_VESerror("[libVES_VaultItem_setCipher]");
	if (hdrout) {
	    int e = ci_header(ctx.vitem->value, ctx.vitem->len, ctx.vitem->meta, rcpt, nrcpt, &hdr, &hdrlen);
	    if (e) return e;
	}
    } else if (!params.out) {
	if (params.ictext) offline_out(&out_value);
	else if (params.value && ctx.vkey) offline_out(&out_ictext);
	else {
	    if (params.debug >= 0) fprintf(stderr, "Use '-i' with '-Y' to encrypt, '-I' with '-y' to decrypt, or '-e' | '-d' for a stream\n");
	    return E_PARAM;
	}
    }

    /************************************
     * Output before the stream, so the cipher key is saved
     * before any ciphertext is written
     */
    for (i = 0; params.out && i < params.out->len; i++) {
	int fd;
	if (params.out->out[i].set.setfn) {
	    if ((fd = params.out->out[i].set.setfn(params.out->out[i].set.data, params.out->out[i].set.mode)) < 0) {
		if (params.debug >= 0) fprintf(stderr, "Invalid output option\n");
		return E_PARAM;
	    }
	} else fd = 1;
	set_binary(fd, out_binary(params.out->out[i].outfn));
	int er = params.out->out[i].outfn(fd, &ctx);
	if (er) return er;
    }

    if (params.cifn) {
	int r = hdrin ? ci_decrypt_fd(ctx.ci, ctfd)
	    : (params.cifn == &ci_encrypt ? ci_encrypt_hdr(ctx.ci, hdr, hdrlen) : params.cifn(ctx.ci));
	free(hdr);
	if (r < 0) {
	    int e = libVES_getError(ctx.ves);
	    return e ? e : E_IO;
	}
    }

    if (rcpt != &ctx.vkey) {
	for (i = 1; i < nrcpt; i++) libVES_VaultKey_free(rcpt[i]);
	free(rcpt);
    }
    libVES_Cipher_free(ctx.ci);
    libVES_VaultItem_free(ctx.vitem);
    libVES_VaultKey_free(ctx.vkey);
    libVES_free(ctx.ves);
    return 0;
}

int main(int argc, char **argv) {
    if (argc) hook_progPath = *argv;
    char **argend = argv + argc;
    char **argp = argv + 1;
    char *arg = NULL;
    enum { o_null, o_error, o_data, o_help, o_ver, o_a, o_o, o_x, o_explore, o_v, o_q, o_s, o_r, o_setshare, o_apiurl, o_l, o_i,
	o_delete, o_f, o_fd, o_ptext, o_ctext, o_p, o_e, o_d, o_c, o_m, o_z, o_k, o_force, o_token, o_priv, o_pub, o_u, o_g,
	o_keyalgo, o_lock, o_pri, o_new, o_rekey, o_propagate, o_manual, o_keystore, o_wwwurl, o_pollurl, o_watch, o_ictext } op = o_null;
    const struct { char op; char *argw; } argwords[] = {
	{o_a, "account"}, {o_o, "vault-item"}, {o_o, "object"}, {o_x, "debug"}, {o_help, "help"}, {o_p, "print"}, {o_v, "veskey"},
	{o_v, "VESkey"}, {o_q, "quiet"}, {o_s, "share"}, {o_r, "unshare"}, {o_setshare, "set-share"}, {o_apiurl, "api-url"}, {o_wwwurl, "www-url"}, {o_pollurl, "poll-url"}, {o_l, "list"}, {o_ictext, "item-ciphertext"}, {o_i, "item"}, {o_m, "meta"},
	{o_delete, "delete"}, {o_f, "file"}, {o_fd, "fd"}, {o_ptext, "plaintext"}, {o_ctext, "ciphertext"}, {o_explore, "explore"},
	{o_e, "encrypt"}, {o_d, "decrypt"}, {o_c, "cipher"}, {o_z, "cipher-meta"}, {o_k, "vault-key"}, {o_u, "unlock"},
	{o_force, "force"}, {o_token, "token"}, {o_priv, "private-key"}, {o_pub, "public-key"}, {o_g, "generate"},
	{o_keyalgo, "key-algo"}, {o_lock, "lock"}, {o_pri, "primary-account"}, {o_new, "new"}, {o_ver, "version"},
	{o_rekey, "rekey"}, {o_propagate, "propagate"}, {o_manual, "manual"}, {o_keystore, "keystore"},
	{o_watch, "events"}, {o_watch, "watch"}
    };
    struct {
	void **ptr;
	void *(*putfn)(const char *, size_t, void **);
	void *(*getfn)(const char *, size_t *, void **);
	struct setfn_st *setptr;
	int (*outfn)(int, struct ctx_st *);
	int flags;
	int delflags;
    } in = {.ptr = NULL, .putfn = NULL, .getfn = NULL, .setptr = NULL, .outfn = NULL, .flags = 0, .delflags = 0};

    /**************************************
     * Collect the command line arguments
     */
    while (arg || argp < argend) {
	op = o_null;
	if (!arg) {
	    arg = *argp++;
	    if (*arg == '-') {
		arg++;
		if (*arg == '-') {
		    int i;
		    for (i = 0; i < sizeof(argwords) / sizeof(*argwords); i++) {
			char *s = argwords[i].argw;
			char *d = arg + 1;
			while (*s && *s++ == *d++);
			if (*s) continue;
			switch (*d) {
			    case '=': case '-': case 0:
				op = argwords[i].op;
				arg = d;
			    default: break;
			}
			if (op != o_null) break;
		    }
		    if (op == o_null) {
			fprintf(stderr, "Unrecognized option: %s\nUse --help' for option list\n", arg - 1);
			op = o_error;
		    }
		}
	    } else op = o_data;
	}
	if (op == o_null) switch (*arg++) {
	    case 0: arg = NULL; break;
	    case 'a': op = o_a; break;
	    case 'c': op = o_c; break;
	    case 'd': op = o_d; break;
	    case 'e': op = o_e; break;
	    case 'f': op = o_f; break;
	    case 'g': op = o_g; break;
	    case 'h': op = o_help; break;
	    case 'i': op = o_i; break;
	    case 'k': op = o_k; break;
	    case 'l': op = o_l; break;
	    case 'm': op = o_m; break;
	    case 'n': op = o_new; break;
	    case 'o': op = o_o; break;
	    case 'p': op = o_p; break;
	    case 'q': op = o_q; break;
	    case 'r': op = o_r; break;
	    case 's': op = o_s; break;
	    case 'u': op = o_u; break;
	    case 'v': op = o_v; break;
	    case 'w': op = o_p; break;
	    case 'x': op = o_x; break;
	    case 'y': op = o_priv; break;
	    case 'z': op = o_z; break;
	    case 'A': op = o_pri; break;
	    case 'C': op = o_ctext; break;
	    case 'E': op = o_keystore; break;
	    case 'F': op = o_fd; break;
	    case 'G': op = o_keyalgo; break;
	    case 'I': op = o_ictext; break;
	    case 'K': op = o_propagate; break;
	    case 'L': op = o_lock; break;
	    case 'O': op = o_o; break;
	    case 'P': op = o_ptext; break;
	    case 'R': op = o_rekey; break;
	    case 'S': op = o_setshare; break;
	    case 'T': op = o_token; break;
	    case 'U': op = o_force; break;
	    case 'V': op = o_ver; break;
	    case 'W': op = o_watch; break;
	    case 'X': op = o_explore; break;
	    case 'Y': op = o_pub; break;
	    case '-': break;
	    case '=': op = o_data; break;
	    default:
		fprintf(stderr, "Unrecognized option: '-%c' (%s)\nUse '--help' for option list\n", *(arg - 1), *(argp - 1));
		op = o_error;
		break;
	}
	switch (op) {
	    case o_null:
	    case o_error:
		break;
	    case o_help:
		out_ansi_str(1, VEShelp);
		return 0;
	    case o_p:
		if (!in.outfn) {
		    fprintf(stderr, "'-p' modifier cannot be used in this context\n");
		    op = o_error;
		} else {
		    in.ptr = NULL;
		    in.putfn = NULL;
		    in.getfn = NULL;
		    in.setptr = NULL;
		    set_out(in.outfn);
		    in.outfn = NULL;
		    params.flags |= (in.flags >> 1);
		    in.flags = 0;
		}
		break;
	    case o_f:
		if (in.setptr) {
		    in.setptr->setfn = &set_file;
		    in.ptr = &in.setptr->data;
		} else if (in.ptr) {
		    in.getfn = &get_file;
		} else {
		    fprintf(stderr, "The modifier cannot be used in this context: %s\n", *(argp - 1));
		    op = o_error;
		}
		break;
	    case o_fd:
		if (in.setptr) {
		    in.setptr->setfn = &set_fd;
		    in.ptr = &in.setptr->data;
		} else if (in.ptr) {
		    in.getfn = &get_fd;
		} else {
		    fprintf(stderr, "The modifier cannot be used in this context: %s\n", *(argp - 1));
		    op = o_error;
		}
		break;
	    default:
		if (in.ptr == (void *)&params.ks_flags || in.ptr == (void *)&params.watch) switch (op) {
		    case o_data:
		    case o_l:
			break;
		    default:
			in.ptr = NULL;
			in.putfn = NULL;
			break;
		}
		/* A new option ends a preceding -p, so a later f | F is not its file */
		if (!in.ptr) in.setptr = NULL;
		if (in.ptr) switch (op) {
		    case o_data: {
			size_t len;
			char *val;
			if (in.getfn) val = in.getfn(arg, &len, in.ptr);
			else len = strlen(val = strdup(arg));
			if (!val) return E_PARAM;
			if (in.putfn) {
			    if (!in.putfn(val, len, in.ptr)) {
				fprintf(stderr, "Bad parameter value: %s\n", val);
				return free(val), E_PARAM;
			    } else free(val);
			} else *((char **) in.ptr) = val;
			in.ptr = NULL;
			in.putfn = NULL;
			in.getfn = NULL;
			in.outfn = NULL;
			in.setptr = NULL;
			arg = NULL;
			params.flags |= in.flags;
			in.flags = in.delflags = 0;
			break;
		    }
		    case o_delete:
			if (in.delflags) params.flags |= in.delflags;
			else {
			    fprintf(stderr, "'--delete' cannot be used in this context\n");
			    op = o_error;
			}
			break;
		    case o_l:
			if (in.ptr == (void *) &params.keyAlgo) {
			    set_out(out_keyAlgos);
			} else if (in.ptr == (void *) &params.cipher) {
			    set_out(out_ciAlgos);
			} else if (in.ptr == (void *)&params.ks_flags) {
			    set_out(out_keystore_flags);
			    params.flags &= ~PF_KEYSTORE;
			} else {
			    fprintf(stderr, "'-l' cannot be used in this context\n");
			    op = o_error;
			    break;
			}
			in.ptr = NULL;
			in.putfn = NULL;
			in.getfn = NULL;
			in.outfn = NULL;
			in.setptr = NULL;
			break;
		    default:
			fprintf(stderr, "expected: value or action modifier, see '--help'\n");
			op = o_error;
			break;
		} else switch(op) {
		    case o_a:
			in.ptr = (void *) &params.user;
			break;
		    case o_o:
			in.ptr = (void *) &params.object;
			break;
		    case o_u:
			in.ptr = (void *) &params.uveskey;
			in.putfn = &put_veskey;
			in.outfn = &out_veskey;
			break;
		    case o_v:
			in.ptr = (void *) &params.veskey;
			in.putfn = &put_veskey;
			in.outfn = &out_veskey;
			break;
		    case o_x:
			if (params.debug < 0) params.debug = 1;
			else params.debug++;
			break;
		    case o_explore:
			params.flags |= PF_RD | PF_EXPLORE;
			break;
		    case o_watch:
			params.flags |= PF_RD | PF_WATCH;
			in.ptr = (void **) &params.watch;
			in.putfn = &put_watch;
			break;
		    case o_l:
			params.flags |= PF_RD;
			set_out(&out_list);
			break;
		    case o_q:
			params.debug = -1;
			break;
		    case o_s:
			in.ptr = (void *) &params.share;
			in.flags |= PF_VI_WR;
			in.putfn = &put_share;
			in.outfn = &out_share;
			break;
		    case o_r:
			in.ptr = (void **) &params.share;
			in.flags |= PF_VI_WR;
			in.putfn = &put_unshare;
			break;
		    case o_setshare:
			in.ptr = (void *) &params.share;
			in.flags |= PF_VI_WR;
			in.putfn = &put_setshare;
			in.outfn = &out_share;
			break;
		    case o_apiurl:
			in.ptr = (void **) &params.apiUrl;
			break;
		    case o_wwwurl:
			in.ptr = (void **) &params.wwwUrl;
			break;
		    case o_pollurl:
			in.ptr = (void **) &params.pollUrl;
			break;
		    case o_i:
			in.ptr = (void **) &params.value;
			in.flags |= PF_VI_WR;
			in.putfn = &put_jvar;
			in.outfn = &out_value;
			break;
		    case o_e:
			params.flags |= PF_CI_RD | PF_CI_EN;
			params.cifn = &ci_encrypt;
			params.ctext.mode |= SF_WR;
			params.ptext.mode &= ~SF_WR;
			break;
		    case o_d:
			params.flags |= PF_CI_RD;
			params.cifn = &ci_decrypt;
			params.ptext.mode |= SF_WR;
			params.ctext.mode &= ~SF_WR;
			break;
		    case o_ptext:
			in.setptr = &params.ptext;
			params.ptext.setfn = &set_file;
			params.ptext.mode &= SF_WR;
			/* The file name can follow directly, f | F are optional */
			in.ptr = &in.setptr->data;
			break;
		    case o_ctext:
			in.setptr = &params.ctext;
			params.ctext.setfn = &set_file;
			params.ctext.mode &= SF_WR;
			in.ptr = &in.setptr->data;
			break;
		    case o_c:
			in.ptr = (void **) &params.cipher;
			in.flags |= PF_CI_WR;
			in.outfn = &out_cipher;
			break;
		    case o_m:
			in.ptr = (void **) &params.meta;
			in.flags |= PF_VI_WR;
			in.outfn = &out_meta;
			in.putfn = &put_jvarobj;
			break;
		    case o_z:
			in.ptr = (void **) &params.cimeta;
			in.flags |= PF_CI_WR;
			in.outfn = &out_cimeta;
			in.putfn = &put_jvarobj;
			break;
		    case o_k:
			in.ptr = (void **) &params.key;
			break;
		    case o_token:
			in.ptr = (void **) &params.token;
			in.outfn = &out_token;
			break;
		    case o_lock:
			params.flags |= PF_LCK;
			break;
		    case o_priv:
			in.ptr = (void **) &params.priv;
			in.flags |= PF_VK_WR;
			in.outfn = &out_priv;
			break;
		    case o_pub:
			in.ptr = (void **) &params.pub;
			in.putfn = &put_pub;
			in.flags |= PF_VK_WR;
			in.outfn = &out_pub;
			break;
		    case o_ictext:
			in.ptr = (void **) &params.ictext;
			in.outfn = &out_ictext;
			params.flags |= PF_ICT;
			break;
		    case o_keyalgo:
			in.ptr = (void **) &params.keyAlgo;
			in.putfn = &put_keyalgo;
			in.outfn = &out_keyalgo;
			break;
		    case o_new:
			params.flags |= PF_NEW | PF_VK_WR;
			break;
		    case o_g:
			params.flags |= PF_VK_CR | PF_VK_WR;
			break;
		    case o_pri:
			in.ptr = (void **) &params.primary;
			in.outfn = &out_email;
			break;
		    case o_propagate:
			params.flags |= PF_VK_PROP;
			break;
		    case o_rekey:
			params.flags |= PF_VK_REKEY;
			break;
		    case o_force:
			params.flags |= PF_FRC;
			break;
		    case o_delete:
			params.flags |= PF_DEL;
			break;
		    case o_keystore:
			params.flags |= PF_KEYSTORE;
			in.ptr = (void **) &params.ks_flags;
			in.putfn = &put_keystore;
			break;
		    case o_ver:
			printf("%s\n", VESUTIL_VERSION_STR);
			return 0;
		    case o_null:
			break;
		    default:
			fprintf(stderr, "Unexpected argument in this context: %s\n", *(argp - 1));
			op = o_error;
			break;
		}
		break;
	}
	if (op == o_error) break;
    }
    if (op == o_error) return E_PARAM;
    if (in.ptr && in.ptr != (void *)&params.ks_flags && in.ptr != (void *)&params.watch) {
	fprintf(stderr, "Unexpeted end of argument list\n");
	return E_PARAM;
    }

    /****************************************
     * Stream and item crypto without -o run offline,
     * with an explicit key and no Vault
     */
    if (!params.object && (params.cifn || params.pub || (params.flags & PF_ICT)
	|| ((params.priv || (params.flags & PF_VK_CR)) && !params.user && !params.primary && !params.key))) return offline_main();
    if (params.pub || (params.flags & PF_ICT)) {
	fprintf(stderr, "'-I' and '-Y KEY' are used in offline mode only, without '-o'\n");
	return E_PARAM;
    }

    /****************************************
     * Validate the action
     */
    if (!params.object) {
	if (params.flags & (PF_VI_RD | PF_VI_WR | PF_CI_RD | PF_CI_WR)) {
	    fprintf(stderr, "An object reference is required for this action, use '-o REF'\n");
	    return E_PARAM;
	}
	if (!params.out && !params.key && !params.user && !params.primary) {
	    out_ansi_str(1, VESbanner);
	    return E_PARAM;
	}
    }
    
    /*****************************************
     * Initialize the context
     */
    struct ctx_st ctx = {
	.ves = NULL,
	.vitem = NULL,
	.ci = NULL,
	.vkey = NULL,
	.domain = NULL
    };
    libVES_init(VESUTIL_VERSION_SHORT);
    ctx.ves = libVES_new(params.user);
    if (!ctx.ves) {
	if (params.debug >= 0) fprintf(stderr, "Invalid app key reference: %s\n", params.user);
	return E_PARAM;
    }
    if (ctx.ves->external && !ctx.ves->external->externalId[0]) ctx.domain = ctx.ves->external->domain;
    ctx.ves->httpInitFn = &hook_httpInitFn;
    if (params.debug > 0) ctx.ves->debug = params.debug;
    if (params.apiUrl) libVES_setOption(ctx.ves, LIBVES_O_APIURL, params.apiUrl);
    if (params.wwwUrl) libVES_setOption(ctx.ves, LIBVES_O_WWWURL, params.wwwUrl);
    if (params.pollUrl) libVES_setOption(ctx.ves, LIBVES_O_POLLURL, params.pollUrl);
    ctx.ves->genVaultKeyFn = &hook_genVaultKey;
    if (params.token) libVES_setSessionToken(ctx.ves, params.token);
    if (params.primary) {
	const char *p = params.primary;
	libVES_Ref *ref = libVES_Ref_fromURI(&p, NULL);
	if (ref) {
	    libVES_Ref_free(ref);
	    if (*p == '/') p++;
	}
	if (!*p) p = params.primary;
	libVES_User *u = libVES_User_fromPath(&p);
	libVES_setUser(ctx.ves, u);
	libVES_User_free(u);
	if (!u) return_VESerror("[primary]");
	if (!libVES_KeyStore_unlock(NULL, ctx.ves, params.ks_flags)) return_VESerror("[libVES_KeyStore_unlock]");
	if (!params.user && !params.key && ctx.ves->me) ctx.vkey = ctx.ves->me->primary;
    } else if ((params.flags & PF_KEYSTORE) && params.user && (params.key || !(params.flags & PF_NEW)) && !params.uveskey) {
	if (!libVES_KeyStore_unlock(NULL, ctx.ves, params.ks_flags)) return_VESerror("[libVES_KeyStore_unlock]");
    }
    if (params.uveskey || (params.flags & PF_NEW)) {
	libVES_veskey *v = params.uveskey;
	libVES_veskey *newv = NULL;
	if ((params.flags & PF_NEW) && !params.key) {
	    libVES_VaultKey *vk = libVES_createVaultKey(ctx.ves);
	    if (!vk) return_VESerror("[libVES_createVaultKey]");
	    if (!v) v = params.veskey;
	    if (!v) v = newv = libVES_VaultKey_getVESkey(vk);
	} else if (v) {
	    if (!libVES_unlock(ctx.ves, v->keylen, v->veskey)) return_VESerror("[libVES_unlock]");
	}
//	if (v && (params.ks_flags & LIBVES_KS_SAVE) && !libVES_KeyStore_savekey(NULL, ctx.ves->external, v->keylen, v->veskey)) return_VESerror("[libVES_KeyStore_savekey]");
	if (newv) libVES_veskey_free(newv);
    }
    if (params.flags & PF_LCK) libVES_lock(ctx.ves);

    if (params.debug >= 0 && !params.out) {
	if (params.flags & PF_WATCH) {
	    set_out(&out_events);
	} else if ((params.flags & PF_EXPLORE) || !(params.flags & (PF_VK_RD | PF_VK_WR | PF_VI_RD | PF_VI_WR | PF_CI_RD | PF_CI_WR | PF_DEL))) {
	    set_out(&out_explore);
	}
	if (params.out) params.flags |= PF_RD;
    }
    
    if (params.object) {
	const char *objpath = params.object;
	ctx.vitem = (params.flags & (PF_VI_WR | PF_CI_WR | PF_CI_EN)) ? libVES_VaultItem_fromURI(&objpath, ctx.ves) : libVES_VaultItem_loadFromURI(&objpath, ctx.ves);
	if (!ctx.vitem) return_VESerror("[libVES_VaultItem_fromURI]");
    }

    if (params.key) {
	const char *s = params.key;
        ctx.vkey = libVES_objectFromURI(&s, ctx.ves, LIBVES_O_VKEY | LIBVES_O_GET | (params.flags & PF_NEW ? LIBVES_O_NEW | LIBVES_O_FORCE : 0), NULL);
	if (!ctx.vkey) return_VESerror("[libVES_VaultKey_fromURI]");
	if (!libVES_VaultKey_unlock(ctx.vkey, NULL)) libVES_getError(ctx.ves);
	if (libVES_VaultKey_isNew(ctx.vkey)) params.flags |= PF_VK_WR;
	params.flags |= PF_VK_FR;
    } else if (!ctx.vkey && !ctx.domain && ((params.flags & (PF_VK_RD | PF_VK_WR)) || params.user || params.primary) && !(ctx.vkey = libVES_getVaultKey(ctx.ves))) return_VESerror("[libVES_getVaultKey]");
    
    /****************************
     * Perform update actions
     */
    if (params.flags & PF_DEL) {
	if (ctx.vitem) {
	    if (!libVES_VaultItem_delete(ctx.vitem, ctx.ves)) return_VESerror("[libVES_VaultItem_delete]");
	} else if (ctx.vkey) {
	    if (!libVES_VaultKey_delete(ctx.vkey)) return_VESerror("[libVES_VaultKey_delete]");
	}
    }
    if ((params.value || params.meta) && ctx.vitem->type == LIBVES_VI_FILE && !(params.flags & PF_FRC)) {
	if (params.debug >= 0) fprintf(stderr, "Use '-U' to force overwrite raw cipher data\n");
	return LIBVES_E_PARAM;
    }
    if (params.value && !(params.flags & (PF_CI_RD | PF_CI_WR))) libVES_VaultItem_setValue0(ctx.vitem, params.value->len, params.value->vString, params.itemType);
    if (params.meta) libVES_VaultItem_setMeta(ctx.vitem, params.meta);
    if (params.flags & (PF_CI_RD | PF_CI_WR)) {
	char new_ci = 0;
	if (!libVES_VaultItem_isNew(ctx.vitem)) {
	    ctx.ci = libVES_VaultItem_getCipher(ctx.vitem, ctx.ves);
	    if (!ctx.ci) {
		if (params.flags & PF_CI_WR) {
		    libVES_getError(ctx.ves);
		    new_ci = 1;
		} else return_VESerror("[libVES_VaultItem_getCipher]");
	    }
	    if (params.cipher) new_ci = 1;
	    if (new_ci && !(params.flags & PF_FRC)) {
		if (params.debug >= 0) fprintf(stderr, "Use '-U' to force creating a new cipher on an existing vault item\n");
		return E_PARAM;
	    }
	} else if (params.cifn == &ci_decrypt && !params.value) {
	    if (params.debug >= 0) fprintf(stderr, "Use '-e' to generate a new cipher, or '-i' to supply an externally created cipher key\n");
	    return E_PARAM;
	} else new_ci = 1;
	if (new_ci) {
	    libVES_Cipher_free(ctx.ci);
	    const libVES_CiAlgo *algo = params.cipher ? libVES_Cipher_algoFromStr(params.cipher) : ctx.ves->cipherAlgo;
	    if (!algo) {
		if (params.debug >= 0) fprintf(stderr, "Unknown cipher algorithm\n");
		return E_PARAM;
	    }
	    ctx.ci = libVES_Cipher_new(algo, ctx.ves, (params.value ? params.value->len : 0), (params.value ? params.value->vString : NULL));
	    if (!ctx.ci) return_VESerror("[libVES_Cipher_new]");
	    params.flags |= PF_CI_WR;
	}
	if (params.cimeta) libVES_Cipher_setMeta(ctx.ci, params.cimeta);
	if ((params.flags & PF_CI_WR) && !libVES_VaultItem_setCipher(ctx.vitem, ctx.ci)) return_VESerror("[libVES_VaultItem_setCipher]");
    }
    if (params.share) {
	int i;
	for (i = 0; i < params.share->len; i++) {
	    libVES_List *share = libVES_List_new(&libVES_VaultKey_ListCtl);
	    char *shpath = params.share->share[i].path;
	    while (*shpath) {
		switch (*shpath) {
		    case ' ': case 9: case 10: case 13: case ',': case ';':
			shpath++;
		    case 0:
			break;
		    default: {
			char *s = shpath;
			char *next = NULL;
			char q = 0;
			do switch (*s++) {
			    case 0:
				next = s - 1;
				break;
			    case '\\':
				if (*s) s++;
				break;
			    case '"':
				q = !q;
				break;
			    case ',': case ';':
				if (!q) {
				    *(s - 1) = 0;
				    next = s;
				}
				break;
			} while (!next);
			if (!libVES_VaultKey_listFromURI((const char **) &shpath, ctx.ves, share)) return_VESerror("[libVES_VaultKey_listFromURI]");
			shpath = next;
		    }
		}
	    }
	    if (!libVES_VaultItem_entries(ctx.vitem, share, params.share->share[i].flags)) return_VESerror("[libVES_VaultItem_entries]");
	    libVES_List_free(share);
	}
    }
    if (params.flags & PF_FRC) {
	if (ctx.vitem) {
	    libVES_VaultItem_force(ctx.vitem);
	    params.flags |= PF_VI_WR;
	}
    }
    if ((params.flags & PF_VK_CR) && !libVES_VaultKey_isNew(ctx.vkey)) {
	libVES_VaultKey *vkey = libVES_VaultKey_createFrom(ctx.vkey);
	if (!vkey) return_VESerror("[libVES_VaultKey_createFrom]");
	if (!libVES_VaultKey_rekeyFrom(vkey, ctx.vkey, 0)) return_VESerror("[libVES_VaultKey_rekeyFrom]");
	if (params.flags & PF_VK_FR) libVES_VaultKey_free(ctx.vkey);
	ctx.vkey = vkey;
    }
    if (params.flags & PF_VK_PROP) {
	if (!libVES_VaultItem_post(libVES_VaultKey_propagate(ctx.vkey), ctx.ves)) return_VESerror("[libVES_VaultKey_propagate]");
    }
    if (params.flags & PF_VK_REKEY) {
	if (!libVES_VaultKey_rekey(ctx.vkey)) return_VESerror("[libVES_VaultKey_rekey]");
    }
    
    
    /***************************************
     * Perform stream cipher encrypt/decrypt action
     */
    if (params.cifn) {
	if (params.cifn(ctx.ci) < 0) {
	    int e = libVES_getError(ctx.ves);
	    return e ? e : E_IO;
	}
    }
    
    /*********************************
     * Commit updates
     */
    if (params.flags & (PF_VI_WR | PF_CI_WR)) {
	if (!libVES_VaultItem_post(ctx.vitem, ctx.ves)) return_VESerror("[libVES_VaultItem_post]");
	libVES_VaultItem_free(ctx.vitem);
	if (params.flags & (PF_VK_RD | PF_CI_RD)) {
	    const char *objpath = params.object;
	    if (!(ctx.vitem = libVES_VaultItem_loadFromURI(&objpath, ctx.ves))) return_VESerror("[libVES_VaultItem_fromURI]");
	} else ctx.vitem = NULL;
    }
    if (params.flags & PF_VK_WR) {
	if (libVES_VaultKey_isNew(ctx.vkey)) {
	    if (!libVES_VaultKey_post(ctx.vkey)) return_VESerror("[libVES_VaultKey_post]");
            if ((params.ks_flags & LIBVES_KS_SAVE) && (ctx.vkey->type == LIBVES_VK_SECONDARY)) {
                libVES_veskey *v = libVES_VaultKey_getVESkey(ctx.vkey);
                int ok = v && libVES_KeyStore_savekey(NULL, ctx.vkey->external, v->keylen, v->veskey);
                libVES_veskey_free(v);
                if (!ok) return_VESerror("[libVES_KeyStore_savekey]");
            }
	}
    }
    
    /************************************
     * Output
     */
    if (params.debug >= 0 && !params.out && !(params.flags & (PF_VK_RD | PF_VK_WR | PF_VI_RD | PF_VI_WR | PF_CI_RD | PF_CI_WR | PF_DEL))) set_out(&out_explore);
    if (params.out) {
	int i;
	for (i = 0; i < params.out->len; i++) {
	    int fd;
	    if (params.out->out[i].set.setfn) {
		if ((fd = params.out->out[i].set.setfn(params.out->out[i].set.data, params.out->out[i].set.mode)) < 0) {
		    if (params.debug >= 0) fprintf(stderr, "Invalid output option\n");
		    return E_PARAM;
		}
	    } else fd = 1;
	    set_binary(fd, out_binary(params.out->out[i].outfn));
	    int er = params.out->out[i].outfn(fd, &ctx);
	    if (er) return er;
	}
    }

//    if (pvkey != ctx.vkey) libVES_VaultKey_free(pvkey);
    libVES_VaultKey_free(ctx.vkey);
    libVES_VaultItem_free(ctx.vitem);
    libVES_free(ctx.ves);
    return 0;
}
