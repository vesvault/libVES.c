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
 * ves-util/ci.c              VES Utility: Stream cipher handlers
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
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
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <libVES.h>
#include <jVar.h>
#include <libVES/Cipher.h>
#include <libVES/VaultKey.h>
#include "../ves-util.h"
#include "set.h"
#include "ci.h"

/***************************************************************************
 * Offline stream header, ahead of the ciphertext:
 *   ves/1 LF
 *   {"meta":{"a":ALGO,...},"entries":[encData,...]} LF
 *   "--- " base64(HMAC-SHA256) LF
 * One encData per recipient: the cipher key, as a Vault Item stores it.
 * The MAC covers the first two lines, keyed by HKDF-SHA256 of the cipher key.
 */
#define CI_HDR_MAGIC	"ves/1\n"
#define CI_HDR_MACPFX	"--- "
#define CI_HDR_MACLEN	44
#define CI_HDR_TAILLEN	(sizeof(CI_HDR_MACPFX) - 1 + CI_HDR_MACLEN + 1)
#define CI_HDR_MAX	(1 << 20)

int ci_process(int in, int out, libVES_Cipher *ci, int (*fn)(libVES_Cipher *, int, const char *, size_t, char **)) {
    char buf[16384];
    char *outbuf = NULL;
    int outlen = -1;
    int r, cl;
    int w = 0;
    int tl = 0;
    while ((r = read(in, buf, sizeof(buf))) >= 0) {
	/* The output length can depend on the cipher state (LIBVES_CF_EXACT),
	 * so it is queried for every chunk. outbuf is never NULL when fn writes
	 * to it, else libVES_Cipher_proceed() would allocate one of its own */
	cl = fn(ci, r == 0, buf, r, NULL);
	if (cl > outlen) {
	    char *p = realloc(outbuf, (cl > 0 ? cl : 1));
	    if (!p) {
		free(outbuf);
		VES_throw("[ci_process]", "", "Out of memory", -1);
	    }
	    outbuf = p;
	    outlen = cl;
	}
	if (cl >= 0) cl = fn(ci, r == 0, buf, r, &outbuf);
	if (cl >= 0) {
	    int wp = 0;
	    while (wp < cl) {
		w = write(out, outbuf + wp, cl - wp);
		if (w >= 0) {
		    wp += w;
		    tl += w;
		} else break;
	    }
	}
	if (r <= 0 || w < 0 || cl < 0) break;
    }
    free(outbuf);
    if (cl < 0) {
	const char *err, *msg;
	libVES_getErrorInfo(ci->ves, &err, &msg);
	VES_throw("[ci_process]", err, msg, -1);
    }
    if (r < 0) { IO_throw("[read]", "(in)", -1); }
    else if (w < 0) { IO_throw("[write]", "(out)", -1); }
    else return tl;
}

int ci_get_fd(struct setfn_st *st, int dflt) {
    int fd = st->setfn ? st->setfn(st->data, st->mode) : dflt;
    if (fd >= 0) set_binary(fd, 1);
    return fd;
}

int ci_encrypt_hdr(libVES_Cipher *ci, const char *hdr, size_t hdrlen) {
    int ptext = ci_get_fd(&params.ptext, 0);
    if (ptext < 0) return -1;
    int ctext = ci_get_fd(&params.ctext, 1);
    if (ctext < 0) return -1;
    size_t wp = 0;
    while (wp < hdrlen) {
	int w = write(ctext, hdr + wp, hdrlen - wp);
	if (w < 0) IO_throw("[write]", "(out)", -1);
	wp += w;
    }
    return ci_process(ptext, ctext, ci, &libVES_Cipher_encrypt);
}

int ci_encrypt(libVES_Cipher *ci) {
    return ci_encrypt_hdr(ci, NULL, 0);
}

int ci_decrypt_fd(libVES_Cipher *ci, int ctext) {
    int ptext = ci_get_fd(&params.ptext, 1);
    if (ptext < 0) return -1;
    return ci_process(ctext, ptext, ci, &libVES_Cipher_decrypt);
}

int ci_decrypt(libVES_Cipher *ci) {
    int ctext = ci_get_fd(&params.ctext, 0);
    if (ctext < 0) return -1;
    return ci_decrypt_fd(ci, ctext);
}

static int ci_hdr_mac(const char *key, size_t keylen, const char *hdr, size_t hdrlen, char *b64) {
    static const unsigned char salt[32] = {0};
    static const char info[] = "ves/1 header mac\x01";
    unsigned char prk[32], mk[32], mac[32];
    unsigned int l;
    int ok = HMAC(EVP_sha256(), salt, sizeof(salt), (const unsigned char *) key, keylen, prk, &l)
	&& HMAC(EVP_sha256(), prk, sizeof(prk), (const unsigned char *) info, sizeof(info) - 1, mk, &l)
	&& HMAC(EVP_sha256(), mk, sizeof(mk), (const unsigned char *) hdr, hdrlen, mac, &l);
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(mk, sizeof(mk));
    return ok ? EVP_EncodeBlock((unsigned char *) b64, mac, sizeof(mac)) : -1;
}

int ci_header(const char *key, size_t keylen, jVar *meta, libVES_VaultKey **rcpt, int n, char **hdr, size_t *hdrlen) {
    jVar *jhdr = jVar_object();
    jVar *entries = jVar_array();
    int i;
    jVar_put(jhdr, "meta", (meta ? jVar_clone(meta) : jVar_object()));
    jVar_put(jhdr, "entries", entries);
    for (i = 0; i < n; i++) {
	char *ct = libVES_VaultKey_encrypt(rcpt[i], key, keylen);
	if (!ct) {
	    const char *err, *msg;
	    int e = libVES_getErrorInfo(rcpt[i]->ves, &err, &msg);
	    jVar_free(jhdr);
	    VES_throw("[ci_header]", (err ? err : ""), (msg ? msg : "Encryption failed"), (e ? e : E_VALUE));
	}
	jVar_push(entries, jVar_string0(ct));
    }
    char *json = jVar_toJSON(jhdr);
    jVar_free(jhdr);
    if (!json) VES_throw("[ci_header]", "", "Cannot render the header JSON", E_VALUE);
    size_t ml = sizeof(CI_HDR_MAGIC) - 1;
    size_t jl = strlen(json);
    size_t hl = ml + jl + 1;
    char *buf = malloc(hl + CI_HDR_TAILLEN + 1);
    if (!buf) return free(json), E_VALUE;
    memcpy(buf, CI_HDR_MAGIC, ml);
    memcpy(buf + ml, json, jl);
    buf[hl - 1] = '\n';
    free(json);
    memcpy(buf + hl, CI_HDR_MACPFX, sizeof(CI_HDR_MACPFX) - 1);
    if (ci_hdr_mac(key, keylen, buf, hl, buf + hl + sizeof(CI_HDR_MACPFX) - 1) != CI_HDR_MACLEN) {
	free(buf);
	VES_throw("[ci_header]", "", "Header MAC failed", LIBVES_E_CRYPTO);
    }
    buf[hl + CI_HDR_TAILLEN - 1] = '\n';
    *hdr = buf;
    *hdrlen = hl + CI_HDR_TAILLEN;
    return 0;
}

static size_t ci_read_full(int fd, char *buf, size_t len) {
    size_t l = 0;
    int r;
    while (l < len && (r = read(fd, buf + l, len - l)) > 0) l += r;
    return l;
}

int ci_read_header(int fd, char **hdr, size_t *hdrlen) {
    size_t ml = sizeof(CI_HDR_MAGIC) - 1;
    size_t bufl = 4096;
    size_t l = ml;
    char *buf = malloc(bufl);
    if (!buf) return E_VALUE;
    if (ci_read_full(fd, buf, ml) != ml || memcmp(buf, CI_HDR_MAGIC, ml)) {
	free(buf);
	VES_throw("[ci_read_header]", "", "Not a VES stream header, use '-If' | '-i' for a detached cipher key", E_PARAM);
    }
    /* The JSON line a byte at a time, so no ciphertext past the header is consumed */
    do {
	if (l + CI_HDR_TAILLEN >= bufl) {
	    if (bufl >= CI_HDR_MAX) {
		free(buf);
		VES_throw("[ci_read_header]", "", "The stream header is too long", LIBVES_E_PARSE);
	    }
	    char *b = realloc(buf, bufl *= 2);
	    if (!b) return free(buf), E_VALUE;
	    buf = b;
	}
	if (read(fd, buf + l, 1) != 1) {
	    free(buf);
	    VES_throw("[ci_read_header]", "", "Unexpected end of the stream header", LIBVES_E_PARSE);
	}
    } while (buf[l++] != '\n');
    if (ci_read_full(fd, buf + l, CI_HDR_TAILLEN) != CI_HDR_TAILLEN
	|| memcmp(buf + l, CI_HDR_MACPFX, sizeof(CI_HDR_MACPFX) - 1) || buf[l + CI_HDR_TAILLEN - 1] != '\n') {
	free(buf);
	VES_throw("[ci_read_header]", "", "Malformed stream header MAC", LIBVES_E_PARSE);
    }
    *hdr = buf;
    *hdrlen = l + CI_HDR_TAILLEN;
    return 0;
}

int ci_header_open(const char *hdr, size_t hdrlen, libVES_VaultKey *vkey, char **key, size_t *keylen, jVar **meta) {
    size_t ml = sizeof(CI_HDR_MAGIC) - 1;
    size_t hl = hdrlen - CI_HDR_TAILLEN;
    jVar *jhdr = jVar_parse(hdr + ml, hl - ml - 1);
    jVar *entries = jVar_get(jhdr, "entries");
    if (!jVar_isObject(jhdr) || !jVar_isArray(entries) || !jVar_count(entries)) {
	jVar_free(jhdr);
	VES_throw("[ci_header_open]", "", "Malformed stream header", LIBVES_E_PARSE);
    }
    int i, macbad = 0;
    for (i = 0; i < jVar_count(entries); i++) {
	const char *ct = jVar_getStringP(jVar_index(entries, i));
	char *v = NULL;
	char mac[CI_HDR_MACLEN + 1];
	int l = ct ? libVES_VaultKey_decrypt(vkey, ct, &v) : -1;
	if (l < 0) {
	    libVES_getError(vkey->ves);
	    continue;
	}
	if (ci_hdr_mac(v, l, hdr, hl, mac) == CI_HDR_MACLEN && !CRYPTO_memcmp(mac, hdr + hl + sizeof(CI_HDR_MACPFX) - 1, CI_HDR_MACLEN)) {
	    *key = v;
	    *keylen = l;
	    *meta = jVar_clone(jVar_get(jhdr, "meta"));
	    jVar_free(jhdr);
	    return 0;
	}
	OPENSSL_cleanse(v, l);
	free(v);
	macbad = 1;
    }
    jVar_free(jhdr);
    if (macbad) VES_throw("[ci_header_open]", "", "Stream header MAC mismatch, the header was modified", LIBVES_E_CRYPTO);
    VES_throw("[ci_header_open]", "", "No stream header entry decrypts with this key", LIBVES_E_CRYPTO);
}
