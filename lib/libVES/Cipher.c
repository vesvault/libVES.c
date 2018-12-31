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
 * libVES/Cipher.c            libVES: Stream cipher
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include "Cipher.h"
#include "CiAlgo_AES.h"
#include "Util.h"
#include "List.h"
#include "../libVES.h"
#include "../jVar.h"

libVES_List_STATIC(libVES_Cipher_algos, &libVES_algoListCtl, 4, &libVES_CiAlgo_NULL, &libVES_CiAlgo_AES256GCMp, &libVES_CiAlgo_AES256GCM1K, &libVES_CiAlgo_AES256CFB);

libVES_Cipher *libVES_Cipher_new(const libVES_CiAlgo *algo, libVES *ves, size_t keylen, const char *key) {
    if (!algo) libVES_throw(ves, LIBVES_E_PARAM, "libVES_CiAlgo is not supplied", NULL);
    if (!algo->newfn) libVES_throw(ves, LIBVES_E_UNSUPPORTED, "Operation is not supported", NULL);
    libVES_Cipher *ci = algo->newfn(algo, ves, keylen, key);
    if (!ci) return NULL;
    ci->ves = ves;
    ci->algo = algo;
    ci->flags = 0;
    ci->ctx = NULL;
    if (algo->keylenfn) {
	const char *extra = key + algo->keylenfn(ci);
	ci->meta = (extra < key + keylen) ? jVar_parse(extra, key + keylen - extra) : NULL;
    } else ci->meta = NULL;
    return ci;
}

libVES_Cipher *libVES_Cipher_forVEntry(size_t keylen, const char *key, libVES *ves) {
    if (!key || keylen >= libVES_Cipher_KEYLENforVEntry) return libVES_Cipher_new(&libVES_CiAlgo_AES256GCMp, ves, libVES_Cipher_KEYLENforVEntry, key);
    libVES_throw(ves, LIBVES_E_CRYPTO, "Cipher key is too short", NULL);
}

char *libVES_Cipher_toStringl(libVES_Cipher *ci, size_t *len, char *buf) {
    if (!ci) return NULL;
    if (!ci->algo->keylenfn) libVES_throw(ci->ves, LIBVES_E_UNSUPPORTED, "Key length is not available", NULL);
    size_t kl = ci->algo->keylenfn(ci);
    char *extra = ci->meta ? jVar_toJSON(ci->meta) : NULL;
    size_t xl = extra ? strlen(extra) : 0;
    if (buf) {
	if (*len < kl + xl) buf = NULL;
	else {
	    memcpy(buf + kl, extra, xl);
	    *len = kl + xl;
	}
	free(extra);
	if (!buf) libVES_throw(ci->ves, LIBVES_E_PARAM, "Buffer is too short", NULL);
    } else {
	buf = realloc(extra, *len = kl + xl);
	memmove(buf + kl, buf, xl);
    }
    memcpy(buf, ci->key, kl);
    return buf;
}



int libVES_Cipher_proceed(libVES_Cipher *ci, int final, const char *srctext, size_t srclen, char **dsttext, int func(libVES_Cipher *ci, int final, const char *src, size_t srclen, char *dst)) {
    if (!ci) return -1;
    if (!((void *) func)) libVES_throw(ci->ves, LIBVES_E_UNSUPPORTED, "Cipher operation is not supported by algo", -1);
    if (!dsttext || !*dsttext) {
	int len = func(ci, final, srctext, srclen, NULL);
	if (len < 0) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "Cannot determine the cipher buffer size", -1);
	if (!dsttext) return len;
	*dsttext = malloc(len);
    }
    int res = func(ci, final, srctext, srclen, *dsttext);
    if (res < 0) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "Cipher error", -1);
    return res;
}

int libVES_Cipher_decrypt(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char **plaintext) {
    return ci ? libVES_Cipher_proceed(ci, final, ciphertext, ctlen, plaintext, ci->algo->decfn) : -1;
}

int libVES_Cipher_encrypt(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char **ciphertext) {
    return ci ? libVES_Cipher_proceed(ci, final, plaintext, ptlen, ciphertext, ci->algo->encfn) : -1;
}

libVES_Seek *libVES_Cipher_seek(libVES_Cipher *ci, libVES_Seek *sk) {
    if (!sk) {
	sk = malloc(sizeof(*sk));
	sk->plainPos = sk->cipherPos = sk->cipherFbPos = -1;
	sk->cipherFbLen = 0;
	sk->cipherFb = NULL;
	sk->flags = LIBVES_SK_NEW;
	return sk;
    }
    if (!ci) return NULL;
    sk->flags &= ~(LIBVES_SK_ERR | LIBVES_SK_RDY | LIBVES_SK_FBK);
    if (sk->plainPos < 0 && sk->cipherPos < 0) {
	sk->flags |= LIBVES_SK_ERR;
	libVES_throw(ci->ves, LIBVES_E_PARAM, "Uninitialized libVES_Seek", NULL);
    }
    if (!ci->algo->seekfn) {
	sk->flags |= LIBVES_SK_ERR;
	libVES_throw(ci->ves, LIBVES_E_UNSUPPORTED, "Operation is not supported", NULL);
    }
    return ci->algo->seekfn(ci, sk);
}

struct jVar *libVES_Cipher_getMeta(libVES_Cipher *ci) {
    return ci ? ci->meta : NULL;
}

int libVES_Cipher_setMeta(libVES_Cipher *ci, struct jVar *meta) {
    if (!ci) return 0;
    jVar_free(ci->meta);
    ci->meta = meta;
    return 1;
}

const libVES_CiAlgo *libVES_Cipher_algoFromStr(const char *str) {
    return (const libVES_CiAlgo *) libVES_lookupAlgo(str, &libVES_Cipher_algos);
}

void libVES_Cipher_reset(libVES_Cipher *ci) {
    if (!ci) return;
    if (ci->algo->resetfn) ci->algo->resetfn(ci);
    ci->flags = 0;
}

void libVES_Cipher_free(libVES_Cipher *ci) {
    if (!ci) return;
    libVES_Cipher_reset(ci);
    jVar_free(ci->meta);
    if (ci->algo->freefn) ci->algo->freefn(ci);
    free(ci);
}

void libVES_Cipher_registerAlgo(const libVES_CiAlgo *algo) {
    libVES_registerAlgo((void *) algo, &libVES_Cipher_algos);
}



libVES_Cipher *libVES_CiAlgo_n_NULL(const libVES_CiAlgo *algo, libVES *ves, size_t keylen, const char *key) {
    return (libVES_Cipher *) malloc(offsetof(libVES_Cipher, key));
}

int libVES_CiAlgo_l_NULL(libVES_Cipher *ci) {
    return 0;
}

const libVES_CiAlgo libVES_CiAlgo_NULL = {
    .str = "NULL",
    .name = "NULL cipher, secret metadata only",
    .newfn = &libVES_CiAlgo_n_NULL,
    .keylenfn = &libVES_CiAlgo_l_NULL,
    .encfn = NULL,
    .decfn = NULL,
    .resetfn = NULL,
    .seekfn = NULL,
    .freefn = NULL
};
