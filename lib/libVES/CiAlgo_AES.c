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
 * libVES/CiAlgo_AES.c        libVES: Stream cipher algorithms: AES256GCM1K,
 *                                    AES256CFB, AES256GCMp
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
#include <openssl/crypto.h>
#include <assert.h>
#include "Cipher.h"
#include "CiAlgo_AES.h"
#include "Util.h"
#include "../libVES.h"
#include "../jVar.h"

#define libVES_CiAlgo_AESSETKEY(alg, algname) \
	    if (key && keylen < sizeof(ci->alg.key)) libVES_throw(ves, LIBVES_E_PARAM, algname " cipher key is too short", NULL); \
	    ci = malloc(offsetof(libVES_Cipher, alg.end)); \
	    assert(ci); \
	    if (key) { \
		memcpy(ci->alg.key, key, sizeof(ci->alg.key)); \
		memcpy(ci->alg.seed, key + (keylen <= sizeof(ci->alg.key) + sizeof(ci->alg.seed) ? keylen - sizeof(ci->alg.seed) : sizeof(ci->alg.key)), sizeof(ci->alg.seed)); \
	    } else { \
		if (RAND_bytes(ci->alg.key, sizeof(ci->alg.key) + sizeof(ci->alg.seed)) <= 0) libVES_throwEVP(ves, LIBVES_E_CRYPTO, "RAND_bytes", NULL); \
	    }

#define libVES_CiAlgo_LEN_1K	1024
#define libVES_CiAlgo_LEN_GCMP	32


libVES_Cipher *libVES_CiAlgo_n_AES256GCMp(const libVES_CiAlgo *algo, libVES *ves, size_t keylen, const char *key) {
    libVES_Cipher *ci;
    libVES_CiAlgo_AESSETKEY(gcm, "AES 256 GCM");
    memcpy(ci->gcm.iv, ci->gcm.seed, sizeof(ci->gcm.iv));
    ci->gcm.pbuf = NULL;
    ci->gcm.offs = 0;
    return ci;
}

libVES_Cipher *libVES_CiAlgo_n_AES256GCM1K(const libVES_CiAlgo *algo, libVES *ves, size_t keylen, const char *key) {
    libVES_Cipher *ci;
    libVES_CiAlgo_AESSETKEY(gcm, "AES 256 GCM");
    ci->gcm.mdctx = NULL;
    ci->gcm.offs = 0;
    return ci;
}

libVES_Cipher *libVES_CiAlgo_n_AES256CFB(const libVES_CiAlgo *algo, libVES *ves, size_t keylen, const char *key) {
    libVES_Cipher *ci;
    libVES_CiAlgo_AESSETKEY(cfb, "AES 256 CFB");
    memcpy(ci->cfb.iv, ci->cfb.seed, sizeof(ci->cfb.iv));
    return ci;
}



int libVES_CiAlgo_d_AES256GCM(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char *plaintext) {
    if (!plaintext) return ctlen;
    if (!ci->ctx) {
	ci->ctx = EVP_CIPHER_CTX_new();
    }
    if (ci->flags & LIBVES_CF_ENC) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec conflict", -1);
    else if (!(ci->flags & LIBVES_CF_DEC)) {
	if (EVP_DecryptInit_ex(ci->ctx, EVP_aes_256_gcm(), NULL, ci->gcm.key, ci->gcm.iv) > 0) ci->flags |= LIBVES_CF_DEC;
	else libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec init", -1);
    }
    if (final) {
	if (ctlen < sizeof(ci->gcm.gbuf)) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec: Unexpected end of stream", -1);
	ctlen -= sizeof(ci->gcm.gbuf);
    }
    int ptlen = ctlen;
    if (EVP_DecryptUpdate(ci->ctx, (unsigned char *) plaintext, &ptlen, (unsigned char *) ciphertext, ctlen) <= 0) {
	libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec update", -1);
    }
    if (final) {
	if (EVP_CIPHER_CTX_ctrl(ci->ctx, EVP_CTRL_GCM_SET_TAG, sizeof(ci->gcm.gbuf), (void *)(ciphertext + ctlen)) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec gcm", -1);
	}
	int ptlenf = ctlen - ptlen;
	if (EVP_DecryptFinal_ex(ci->ctx, (unsigned char *) plaintext + ptlen, &ptlenf) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM dec final", -1);
	}
	ci->flags &= !LIBVES_CF_DEC;
	ptlen += ptlenf;
    }
    return ptlen;
}

int libVES_CiAlgo_e_AES256GCM(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char *ciphertext) {
    if (!ciphertext) return ptlen + sizeof(ci->gcm.gbuf);
    if (!ci->ctx) {
	ci->ctx = EVP_CIPHER_CTX_new();
    }
    if (ci->flags & LIBVES_CF_DEC) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256GCM enc conflict", -1);
    else if (!(ci->flags & LIBVES_CF_ENC)) {
	if (EVP_EncryptInit_ex(ci->ctx, EVP_aes_256_gcm(), NULL, ci->gcm.key, ci->gcm.iv) > 0) ci->flags |= LIBVES_CF_ENC;
	else libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM enc init", -1);
    }
    int ctlen = ptlen + sizeof(ci->gcm.gbuf);
    if (EVP_EncryptUpdate(ci->ctx, (unsigned char *) ciphertext, &ctlen, (unsigned char *) plaintext, ptlen) <= 0) {
	libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM enc update", -1);
    }
    if (final) {
	int ctlenf = ptlen - ctlen;
	if (EVP_EncryptFinal_ex(ci->ctx, (unsigned char *) ciphertext + ctlen, &ctlenf) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM enc final", -1);
	}
	ctlen += ctlenf;
	if (EVP_CIPHER_CTX_ctrl(ci->ctx, EVP_CTRL_GCM_GET_TAG, sizeof(ci->gcm.gbuf), (void *)(ciphertext + ctlen)) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM enc gcm", -1);
	}
	ci->flags &= !LIBVES_CF_ENC;
	ctlen += sizeof(ci->gcm.gbuf);
    }
    return ctlen;
}

int libVES_CiAlgo_d_AES256CFB(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char *plaintext) {
    if (!plaintext) return (ci->flags |= LIBVES_CF_EXACT), ctlen;
    if (!ci->ctx) {
	ci->ctx = EVP_CIPHER_CTX_new();
    }
    if (ci->flags & LIBVES_CF_ENC) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256CFB dec conflict", -1);
    else if (!(ci->flags & LIBVES_CF_DEC)) {
	if (EVP_DecryptInit_ex(ci->ctx, EVP_aes_256_cfb(), NULL, ci->cfb.key, ci->cfb.iv) > 0) ci->flags |= LIBVES_CF_DEC;
	else libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB dec init", -1);
    }
    int ptlen = ctlen;
    if (EVP_DecryptUpdate(ci->ctx, (unsigned char *) plaintext, &ptlen, (unsigned char *) ciphertext, ctlen) <= 0) {
	libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB dec update", -1);
    }
    if (final) {
	int ptlenf = ctlen - ptlen;
	if (EVP_DecryptFinal_ex(ci->ctx, (unsigned char *) plaintext + ptlen, &ptlenf) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB dec final", -1);
	}
	ci->flags &= !LIBVES_CF_DEC;
	ptlen += ptlenf;
    }
    return ptlen;
}

int libVES_CiAlgo_e_AES256CFB(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char *ciphertext) {
    if (!ciphertext) return (ci->flags |= LIBVES_CF_EXACT), ptlen;
    if (!ci->ctx) {
	ci->ctx = EVP_CIPHER_CTX_new();
    }
    if (ci->flags & LIBVES_CF_DEC) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256CFB enc conflict", -1);
    else if (!(ci->flags & LIBVES_CF_ENC)) {
	if (EVP_EncryptInit_ex(ci->ctx, EVP_aes_256_cfb(), NULL, ci->cfb.key, ci->cfb.iv) > 0) ci->flags |= LIBVES_CF_ENC;
	else libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB enc init", -1);
    }
    int ctlen = ptlen;
    if (EVP_EncryptUpdate(ci->ctx, (unsigned char *) ciphertext, &ctlen, (unsigned char *) plaintext, ptlen) <= 0) {
	libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB enc update", -1);
    }
    if (final) {
	int ctlenf = ptlen - ctlen;
	if (EVP_EncryptFinal_ex(ci->ctx, (unsigned char *) ciphertext + ctlen, &ctlenf) <= 0) {
	    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256CFB enc final", -1);
	}
	ci->flags &= !LIBVES_CF_ENC;
	ctlen += ctlenf;
    }
    return ctlen;
}

int libVES_CiAlgo_d_AES256GCMp(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char *plaintext) {
    size_t len = ci->gcm.offs + ctlen;
    if (!plaintext) return len;
    if (!final || ctlen < sizeof(ci->gcm.gbuf)) {
	ci->gcm.pbuf = realloc(ci->gcm.pbuf, len);
	memcpy(ci->gcm.pbuf + ci->gcm.offs, ciphertext, ctlen);
	ci->gcm.offs = len;
	ctlen = 0;
    }
    if (final) {
	int l;
	char *ptext = plaintext;
	if (ci->gcm.offs) {
	    l = libVES_CiAlgo_d_AES256GCM(ci, !ctlen, ci->gcm.pbuf, ci->gcm.offs, ptext);
	    if (l < 0) return -1;
	    ptext += l;
	}
	if (ctlen) {
	    l = libVES_CiAlgo_d_AES256GCM(ci, 1, ciphertext, ctlen, ptext);
	    if (l < 0) return -1;
	    ptext += l;
	}
	ci->gcm.offs = 0;
	unsigned char padl = plaintext[0];
	ptext -= padl + 1;
	memmove(plaintext, plaintext + 1, ptext - plaintext);
	return ptext - plaintext;
    } else return 0;
}

int libVES_CiAlgo_e_AES256GCMp(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char *ciphertext) {
    size_t len = ci->gcm.offs + ptlen;
    if (!ciphertext) return (ci->flags |= LIBVES_CF_EXACT), (len / libVES_CiAlgo_LEN_GCMP + 1) * libVES_CiAlgo_LEN_GCMP + sizeof(ci->gcm.gbuf);
    if (final) {
	char padl = libVES_CiAlgo_LEN_GCMP - 1 - len % libVES_CiAlgo_LEN_GCMP;
	char pad[libVES_CiAlgo_LEN_GCMP - 1];
	memset(pad, 0, padl);
	char *ctext = ciphertext;
	int l = libVES_CiAlgo_e_AES256GCM(ci, 0, &padl, 1, ctext);
	if (l < 0) return -1;
	ctext += l;
	if (ci->gcm.offs) {
	    l = libVES_CiAlgo_e_AES256GCM(ci, 0, ci->gcm.pbuf, ci->gcm.offs, ctext);
	    if (l < 0) return -1;
	    OPENSSL_cleanse(ci->gcm.pbuf, ci->gcm.offs);
	    ctext += l;
	}
	l = libVES_CiAlgo_e_AES256GCM(ci, 0, plaintext, ptlen, ctext);
	if (l < 0) return -1;
	ctext += l;
	l = libVES_CiAlgo_e_AES256GCM(ci, 1, pad, padl, ctext);
	if (l < 0) return -1;
	ci->gcm.offs = 0;
	return ctext + l - ciphertext;
    } else {
	ci->gcm.pbuf = realloc(ci->gcm.pbuf, len);
	memcpy(ci->gcm.pbuf + ci->gcm.offs, plaintext, ptlen);
	ci->gcm.offs = len;
	return 0;
    }
}

int libVES_CiAlgo_setiv_AES256GCM1K(libVES_Cipher *ci, const char *gbuf) {
    char md[32];
    if (!ci->gcm.mdctx) ci->gcm.mdctx = EVP_MD_CTX_create();
    unsigned int shalen = sizeof(md);
    if (EVP_DigestInit_ex(ci->gcm.mdctx, EVP_sha256(), NULL) > 0
	&& EVP_DigestUpdate(ci->gcm.mdctx, ci->gcm.seed, sizeof(ci->gcm.seed)) > 0
	&& EVP_DigestUpdate(ci->gcm.mdctx, gbuf, sizeof(ci->gcm.gbuf)) > 0
	&& EVP_DigestFinal_ex(ci->gcm.mdctx, (unsigned char *) md, &shalen) > 0) {
	memcpy(ci->gcm.iv, md, sizeof(ci->gcm.iv));
	return 1;
    }
    libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "AES256GCM1K setiv", 0);
}

int libVES_CiAlgo_d_AES256GCM1K(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char *plaintext) {
    if (!plaintext) {
	ci->flags |= LIBVES_CF_EXACT;
	size_t al = ctlen + ci->gcm.offs;
	if (al > sizeof(ci->gcm.gbuf)) al -= sizeof(ci->gcm.gbuf);
	else al = 0;
	size_t ad = al / (libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf));
	size_t am = al % (libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf));
	size_t dl = (ci->gcm.offs < 2 * sizeof(ci->gcm.gbuf)) ? 2 * sizeof(ci->gcm.gbuf) - ci->gcm.offs : 0;
	dl += ad * sizeof(ci->gcm.gbuf);
	if (am < sizeof(ci->gcm.gbuf) && ad) dl -= sizeof(ci->gcm.gbuf) - am;
	return ctlen > dl ? ctlen - dl : 0;
    }
    const char *ctext = ciphertext;
    const char *ctail = ctext + ctlen;
    char *ptext = plaintext;
    int force = final;
    while (ctext < ctail || force) {
	size_t len = ctail - ctext;
	if (ci->gcm.offs < sizeof(ci->gcm.gbuf)) {
	    if (final && !len) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256GCM1K dec: Unexpected end of stream", -1);
	    int l = sizeof(ci->gcm.gbuf) - ci->gcm.offs;
	    if (l > len) l = len;
	    memcpy(ci->gcm.gbuf + ci->gcm.offs, ctext, l);
	    ci->gcm.offs += l;
	    ctext += l;
	    if (ci->gcm.offs >= sizeof(ci->gcm.gbuf)) {
		if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, ci->gcm.gbuf)) return -1;
	    }
	} else {
	    int bl = libVES_CiAlgo_LEN_1K + 2 * sizeof(ci->gcm.gbuf);
	    if (final && bl > len + ci->gcm.offs) {
		bl = len + ci->gcm.offs;
		if (bl < sizeof(ci->gcm.gbuf)) libVES_throw(ci->ves, LIBVES_E_CRYPTO, "AES256GCM1K dec: Framing error", -1);
		force = 0;
	    }
	    int bl2 = bl - ci->gcm.offs;
	    if (len > bl2) len = bl2;

	    int gp0 = sizeof(ci->gcm.gbuf) + sizeof(ci->gcm.gbuf) - ci->gcm.offs;
	    if (gp0 < 0) gp0 = 0;
	    int gp1 = len;
	    if (gp1 > sizeof(ci->gcm.gbuf)) gp1 = sizeof(ci->gcm.gbuf);
	    int gl2 = (bl2 <= len && len >= sizeof(ci->gcm.gbuf)) ? 0 : len;
	    if (gl2 > sizeof(ci->gcm.gbuf)) gl2 = sizeof(ci->gcm.gbuf);
	    int gp2 = sizeof(ci->gcm.gbuf) - gl2;
	    int l;
	    
	    if (gp1 > gp0) {
		l = libVES_CiAlgo_d_AES256GCM(ci, 0, ci->gcm.gbuf + gp0, gp1 - gp0, ptext);
		if (l < 0) return -1;
		ptext += l;
	    }
	    int ff = len && !gl2;
	    l = libVES_CiAlgo_d_AES256GCM(ci, ff, ctext, len - gl2, ptext);
	    if (l < 0) return -1;
	    ptext += l;
	    ctext += len - gl2;
	    if (ff) {
		if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, ctext - sizeof(ci->gcm.gbuf))) return -1;
	    }
	    if (gl2 > 0) {
		if (gp2 > 0) memmove(ci->gcm.gbuf, ci->gcm.gbuf + gl2, gp2);
		memcpy(ci->gcm.gbuf + gp2, ctext, gl2);
		ctext += gl2;
	    }
	    if (len >= bl2) {
		if (!ff) {
		    l = libVES_CiAlgo_d_AES256GCM(ci, 1, ci->gcm.gbuf, sizeof(ci->gcm.gbuf), ptext);
		    if (l < 0) return -1;
		    ptext += l;
		    if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, ci->gcm.gbuf)) return -1;
		}
		ci->gcm.offs = sizeof(ci->gcm.gbuf);
	    } else ci->gcm.offs += len;
	}
    }
    return ptext - plaintext;
}

int libVES_CiAlgo_e_AES256GCM1K(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char *ciphertext) {
    if (!ciphertext) return (ci->flags |= LIBVES_CF_EXACT), ptlen + ((ptlen
	+ (ci->gcm.offs > sizeof(ci->gcm.gbuf) ? ci->gcm.offs - sizeof(ci->gcm.gbuf) : 0)
	) / libVES_CiAlgo_LEN_1K + (final ? 1 : 0) + (ci->gcm.offs ? 0 : 1)) * sizeof(ci->gcm.gbuf);
    char *ctext = ciphertext;
    const char *ptext = plaintext;
    const char *ptail = ptext + ptlen;
    int ff = final;
    if (!ci->gcm.offs) {
	if (RAND_bytes((unsigned char *) ctext, sizeof(ci->gcm.gbuf)) <= 0) libVES_throwEVP(ci->ves, LIBVES_E_CRYPTO, "RAND_bytes", -1);
	if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, ctext)) return -1;
	ctext += sizeof(ci->gcm.gbuf);
	ci->gcm.offs = sizeof(ci->gcm.gbuf);
    }
    while (ptext < ptail || ff) {
	int len = ptail - ptext;
	int bl2 = libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf) - ci->gcm.offs;
	if (final && len < bl2) {
	    bl2 = len;
	    ff = 0;
	}
	if (len > bl2) len = bl2;
	int l = libVES_CiAlgo_e_AES256GCM(ci, len >= bl2, ptext, len, ctext);
	if (l < 0) return -1;
	ctext += l;
	ptext += len;
	if (len >= bl2) {
	    ci->gcm.offs = sizeof(ci->gcm.gbuf);
	    if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, ctext - sizeof(ci->gcm.gbuf))) return -1;
	} else ci->gcm.offs += l;
    }
    return ctext - ciphertext;
}



void libVES_CiAlgo_r_AES256GCMp(libVES_Cipher *ci) {
    if (ci->gcm.pbuf) {
	OPENSSL_cleanse(ci->gcm.pbuf, ci->gcm.offs);
	free(ci->gcm.pbuf);
	ci->gcm.pbuf = NULL;
    }
    ci->gcm.offs = 0;
    if (ci->ctx) EVP_CIPHER_CTX_free(ci->ctx);
    ci->ctx = NULL;
}

void libVES_CiAlgo_r_AES256GCM1K(libVES_Cipher *ci) {
    if (ci->gcm.mdctx) EVP_MD_CTX_destroy(ci->gcm.mdctx);
    ci->gcm.mdctx = NULL;
    ci->gcm.offs = 0;
    if (ci->ctx) EVP_CIPHER_CTX_free(ci->ctx);
    ci->ctx = NULL;
}

void libVES_CiAlgo_r_AES256CFB(libVES_Cipher *ci) {
    if (ci->ctx) EVP_CIPHER_CTX_free(ci->ctx);
    ci->ctx = NULL;
}

libVES_Seek *libVES_CiAlgo_s_AES256GCMp(libVES_Cipher *ci, libVES_Seek *sk) {
    sk->plainPos = 0;
    sk->cipherPos = 0;
    sk->cipherFbPos = -1;
    sk->flags |= LIBVES_SK_RDY;
    return sk;
}

libVES_Seek *libVES_CiAlgo_s_AES256GCM1K(libVES_Cipher *ci, libVES_Seek *sk) {
    if (sk->cipherFb) {
	if (!libVES_CiAlgo_setiv_AES256GCM1K(ci, sk->cipherFb)) {
	    sk->flags |= LIBVES_SK_ERR;
	    return NULL;
	}
	sk->flags |= LIBVES_SK_RDY;
	ci->gcm.offs = sizeof(ci->gcm.gbuf);
    } else {
	if (sk->plainPos >= 0) {
	    sk->plainPos -= sk->plainPos % libVES_CiAlgo_LEN_1K;
	    sk->cipherFbPos = (sk->plainPos / libVES_CiAlgo_LEN_1K) * (libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf));
	    sk->cipherPos = sk->cipherFbPos + sizeof(ci->gcm.gbuf);
	    sk->cipherFbLen = sizeof(ci->gcm.gbuf);
	    sk->flags |= LIBVES_SK_FBK;
	} else if (sk->cipherPos == 0) {
	    sk->plainPos = 0;
	    sk->cipherFbPos = -1;
	    ci->gcm.offs = 0;
	    sk->flags |= LIBVES_SK_RDY;
	} else if (sk->cipherPos > 0) {
	    sk->cipherPos -= sk->cipherPos % (libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf));
	    sk->cipherFbPos = sk->cipherPos;
	    sk->cipherPos += sizeof(ci->gcm.gbuf);
	    sk->cipherFbLen = sizeof(ci->gcm.gbuf);
	    sk->plainPos = sk->cipherFbPos / (libVES_CiAlgo_LEN_1K + sizeof(ci->gcm.gbuf)) * libVES_CiAlgo_LEN_1K;
	    sk->flags |= LIBVES_SK_FBK;
	}
    }
    return sk;
}

libVES_Seek *libVES_CiAlgo_s_AES256CFB(libVES_Cipher *ci, libVES_Seek *sk) {
    if (sk->cipherFb) {
	if (sk->cipherFbLen < sizeof(ci->cfb.iv)) memcpy(ci->cfb.iv, ci->cfb.seed + sk->cipherFbLen, sizeof(ci->cfb.iv) - sk->cipherFbLen);
	memcpy(ci->cfb.iv + sizeof(ci->cfb.iv) - sk->cipherFbLen, sk->cipherFb, sk->cipherFbLen);
	sk->flags |= LIBVES_SK_RDY;
    } else {
	if (sk->plainPos >= 0) {
	    int fbl = sk->cipherFbLen = sk->plainPos;
	    if (fbl > sizeof(ci->cfb.iv)) fbl = sizeof(ci->cfb.iv);
	    sk->cipherPos = sk->plainPos - fbl;
	    if (fbl) sk->flags |= LIBVES_SK_FBK;
	    else {
		memcpy(ci->cfb.iv, ci->cfb.seed, sizeof(ci->cfb.iv));
		sk->flags |= LIBVES_SK_RDY;
	    }
	} else if (sk->cipherPos == 0) {
	    sk->plainPos = 0;
	    sk->cipherFbPos = -1;
	    sk->flags |= LIBVES_SK_RDY;
	} else {
	    sk->cipherFbPos = sk->cipherPos;
	    sk->cipherFbLen = sizeof(ci->cfb.iv);
	    sk->plainPos = sk->cipherPos = sk->cipherPos + sizeof(ci->cfb.iv);
	    sk->flags |= LIBVES_SK_FBK;
	}
    }
    return sk;
}

int libVES_CiAlgo_l_AES256GCM(libVES_Cipher *ci) {
    return sizeof(ci->gcm.key) + sizeof(ci->gcm.seed);
}

int libVES_CiAlgo_l_AES256CFB(libVES_Cipher *ci) {
    return sizeof(ci->cfb.key) + sizeof(ci->cfb.seed);
}

void libVES_CiAlgo_f_AES256(libVES_Cipher *ci) {
    OPENSSL_cleanse(ci->gcm.key, sizeof(ci->gcm.key));
}


const libVES_CiAlgo libVES_CiAlgo_AES256GCMp = {
    .str = "AES256GCMp",
    .name = "AES-256 GCM with plaintext padding",
    .newfn = &libVES_CiAlgo_n_AES256GCMp,
    .keylenfn = &libVES_CiAlgo_l_AES256GCM,
    .encfn = &libVES_CiAlgo_e_AES256GCMp,
    .decfn = &libVES_CiAlgo_d_AES256GCMp,
    .resetfn = &libVES_CiAlgo_r_AES256GCMp,
    .seekfn = &libVES_CiAlgo_s_AES256GCMp,
    .freefn = &libVES_CiAlgo_f_AES256
};
const libVES_CiAlgo libVES_CiAlgo_AES256GCM1K = {
    .str = "AES256GCM1K",
    .name = "AES-256 GCM chunked seekable",
    .newfn = &libVES_CiAlgo_n_AES256GCM1K,
    .keylenfn = &libVES_CiAlgo_l_AES256GCM,
    .encfn = &libVES_CiAlgo_e_AES256GCM1K,
    .decfn = &libVES_CiAlgo_d_AES256GCM1K,
    .resetfn = &libVES_CiAlgo_r_AES256GCM1K,
    .seekfn = &libVES_CiAlgo_s_AES256GCM1K,
    .freefn = &libVES_CiAlgo_f_AES256
};
const libVES_CiAlgo libVES_CiAlgo_AES256CFB = {
    .str = "AES256CFB",
    .name = "AES-256 CFB",
    .newfn = &libVES_CiAlgo_n_AES256CFB,
    .keylenfn = &libVES_CiAlgo_l_AES256CFB,
    .encfn = &libVES_CiAlgo_e_AES256CFB,
    .decfn = &libVES_CiAlgo_d_AES256CFB,
    .resetfn = &libVES_CiAlgo_r_AES256CFB,
    .seekfn = &libVES_CiAlgo_s_AES256CFB,
    .freefn = &libVES_CiAlgo_f_AES256
};
