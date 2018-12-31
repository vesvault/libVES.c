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
 * libVES/KeyAlgo_EVP.c       libVES: Vault Key algorithms: ECDH, RSA,
 *                                    via OpenSSL EVP
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
#include "../jVar.h"
#include "../libVES.h"
#include "VaultKey.h"
#include "Util.h"
#include "KeyAlgo_EVP.h"


libVES_VaultKey *libVES_KeyAlgo_autoEVP_new(const libVES_KeyAlgo *algo, void *pkey, libVES_veskey *veskey, libVES *ves) {
    if (!pkey) libVES_throw(ves, LIBVES_E_PARAM, "EVP private key is not available", NULL);
    switch (EVP_PKEY_base_id((EVP_PKEY *) pkey)) {
	case EVP_PKEY_RSA: algo = &libVES_KeyAlgo_RSA; break;
	case EVP_PKEY_EC: algo = &libVES_KeyAlgo_ECDH; break;
	default: libVES_throw(ves, LIBVES_E_UNSUPPORTED, "Unsupported algorithm in the supplied private key", NULL);
    }
    return algo->newfn(algo, pkey, veskey, ves);
}

libVES_VaultKey *libVES_KeyAlgo_autoPEM_new(const libVES_KeyAlgo *algo, void *pkey, libVES_veskey *veskey, libVES *ves) {
    if (!pkey) libVES_throw(ves, LIBVES_E_PARAM, "PEM private key expected", NULL);
    EVP_PKEY *p = libVES_KeyAlgo_EVP_fromPEM(veskey, pkey);
    libVES_VaultKey *vkey = libVES_KeyAlgo_autoEVP_new(algo, p, veskey, ves);
    if (!vkey) EVP_PKEY_free(p);
    return vkey;
}

void *libVES_KeyAlgo_EVP_str2pub(libVES_VaultKey *vkey, const char *pub) {
    BIO *bio = BIO_new_mem_buf((void *) pub, strlen(pub));
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "[str2pub]");
    BIO_free(bio);
    return pkey;
}

char *libVES_KeyAlgo_EVP_pub2str(libVES_VaultKey *vkey, void *pkey) {
    char *buf, *str;
    int len;
    BIO *mem = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(mem, (EVP_PKEY *) pkey) > 0) {
	len = BIO_get_mem_data(mem, &buf);
	str = malloc(len + 1);
	memcpy(str, buf, len);
	str[len] = 0;
    } else str = NULL;
    BIO_free(mem);
    return str;
}

void *libVES_KeyAlgo_EVP_str2priv(libVES_VaultKey *vkey, const char *priv, libVES_veskey *veskey) {
    EVP_PKEY *pkey = libVES_KeyAlgo_EVP_fromPEM(veskey, priv);
    if (!pkey) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "Incorrect VESkey?", NULL);
    return pkey;
}

char *libVES_KeyAlgo_EVP_priv2str(libVES_VaultKey *vkey, void *pkey, libVES_veskey *veskey) {
    char *priv = libVES_KeyAlgo_EVP_toPEM(veskey, pkey);
    if (!priv) libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "[priv2str]");
    return priv;
}

void libVES_KeyAlgo_EVP_lock(libVES_VaultKey *vkey) {
    if (vkey->pPub && vkey->pPub != vkey->pPriv) EVP_PKEY_free(vkey->pPub);
    if (vkey->pPriv) EVP_PKEY_free(vkey->pPriv);
    vkey->pPriv = vkey->pPub = NULL;
}

int libVES_KeyAlgo_EVP_dump(libVES_VaultKey *vkey, int fd, int flags) {
    BIO *out = BIO_new_fd(fd, BIO_NOCLOSE);
    int res = 0;
    if (vkey->pPub) {
	res = EVP_PKEY_print_public(out, vkey->pPub, 8, NULL) > 0;
	EVP_PKEY_print_params(out, vkey->pPub, 8, NULL);
    }
    if (vkey->pPriv) {
	EVP_PKEY_print_private(out, vkey->pPriv, 8, NULL);
	EVP_PKEY_print_params(out, vkey->pPriv, 8, NULL);
    }
    return res;
}

int libVES_KeyAlgo_EVP_veskey_cb(char *buf, int size, int rwflag, void *u) {
    libVES_veskey *vk = (libVES_veskey *) u;
    if (!vk || size < vk->keylen) return -1;
    memcpy(buf, vk->veskey, vk->keylen);
    return vk->keylen;
}

struct evp_pkey_st *libVES_KeyAlgo_EVP_fromPEM(libVES_veskey *veskey, const char *pem) {
    if (!veskey || !pem) return NULL;
    BIO *bio = BIO_new_mem_buf((void *) pem, strlen(pem));
    struct evp_pkey_st *pkey = PEM_read_bio_PrivateKey(bio, NULL, &libVES_KeyAlgo_EVP_veskey_cb, veskey);
    BIO_free(bio);
    return pkey;
}

char *libVES_KeyAlgo_EVP_toPEM(libVES_veskey *veskey, struct evp_pkey_st *pkey) {
    BIO *mem = BIO_new(BIO_s_mem());
    char *res;
    if (PEM_write_bio_PKCS8PrivateKey(mem, pkey, (veskey ? EVP_aes_256_cbc() : NULL), (veskey ? veskey->veskey : NULL), (veskey ? veskey->keylen : 0), NULL, NULL) > 0) {
	char *buf;
	int len = BIO_get_mem_data(mem, &buf);
	res = malloc(len + 1);
	memcpy(res, buf, len);
	res[len] = 0;
    } else res = NULL;
    BIO_free(mem);
    return res;
}


libVES_VaultKey *libVES_KeyAlgo_RSA_new(const libVES_KeyAlgo *algo, void *pkey, libVES_veskey *veskey, libVES *ves) {
    if (pkey) {
	if (EVP_PKEY_base_id((EVP_PKEY *) pkey) != EVP_PKEY_RSA) libVES_throw(ves, LIBVES_E_PARAM, "Invalid pkey type, expected RSA", NULL);
    } else {
	BIGNUM *e = BN_new();
	BN_set_word(e, 0x10001);
	RSA *rsa = RSA_new();
	if (RSA_generate_key_ex(rsa, 2048, e, NULL)) {
	    pkey = EVP_PKEY_new();
	    EVP_PKEY_assign_RSA((EVP_PKEY *) pkey, rsa);
	} else RSA_free(rsa);
	BN_free(e);
    }
    if (!pkey) {
	libVES_setErrorEVP(ves, LIBVES_E_CRYPTO, "[generate RSA]");
	return NULL;
    }
    libVES_VaultKey *vkey = malloc(sizeof(libVES_VaultKey));
    vkey->algo = algo;
    vkey->pPriv = pkey;
    vkey->pPub = NULL;
    vkey->ves = ves;
    return vkey;
}

int libVES_KeyAlgo_RSA_decrypt(libVES_VaultKey *vkey, const char *ciphertext, size_t *ctlen, char *plaintext, char *key, size_t *keylen) {
    int len = EVP_PKEY_size(vkey->pPriv);
    unsigned char *keybuf = NULL;
    unsigned char *d;
    if (*ctlen > len) {
	*ctlen = len;
	d = keybuf = malloc(len);
    } else {
	if (!plaintext) return len;
	d = (unsigned char *) plaintext;
    }
    int res = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(vkey->pPriv, ENGINE_get_default_RSA());
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
	libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "RSA decrypt init");
    } else {
	size_t dlen;
	if (EVP_PKEY_decrypt(ctx, d, &dlen, (unsigned char *) ciphertext, *ctlen) <= 0) {
	    libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "RSA decrypt");
	} else if (keybuf) {
	    if (dlen > *keylen) dlen = *keylen;
	    else *keylen = dlen;
	    memcpy(key, keybuf, dlen);
	    res = 0;
	} else res = dlen;
    }
    if (keybuf) memset(keybuf, 0, len);
    free(keybuf);
    EVP_PKEY_CTX_free(ctx);
    return res;
}

#define libVES_KeyAlgo_RSA_LENpad	42

int libVES_KeyAlgo_RSA_encrypt(libVES_VaultKey *vkey, const char *plaintext, size_t *ptlen, char *ciphertext, char *key, size_t *keylen) {
    int len = EVP_PKEY_size(vkey->pPub);
    const char *s;
    int sl;
    if (*ptlen + libVES_KeyAlgo_RSA_LENpad > len && *ptlen > *keylen) {
	*ptlen = 0;
	if (!ciphertext) return len;
	RAND_bytes((unsigned char *) key, *keylen);
	s = key;
	sl = *keylen;
    } else {
	if (!ciphertext) return len;
	s = plaintext;
	sl = *ptlen;
    }
    int res = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(vkey->pPub, ENGINE_get_default_RSA());
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
	libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "RSA encrypt init");
    } else {
	size_t elen = len;
	if (EVP_PKEY_encrypt(ctx, (unsigned char *) ciphertext, &elen, (unsigned char *) s, sl) > 0) {
	    res = elen;
	} else {
	    libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "RSA encrypt");
	}
    }
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return res;
}


libVES_VaultKey *libVES_KeyAlgo_ECDH_new(const libVES_KeyAlgo *algo, void *pkey, libVES_veskey *veskey, libVES *ves) {
    if (pkey) {
	if (EVP_PKEY_base_id((EVP_PKEY *) pkey) != EVP_PKEY_EC) libVES_throw(ves, LIBVES_E_PARAM, "Invalid pkey type, expected EC", NULL);
    } else {
	EC_KEY *ec_priv = EC_KEY_new();
	EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
	EC_KEY_set_group(ec_priv, grp);
	EC_GROUP_free(grp);
	EC_KEY_set_asn1_flag(ec_priv, OPENSSL_EC_NAMED_CURVE);
	if (EC_KEY_generate_key(ec_priv)) {
	    pkey = EVP_PKEY_new();
	    EVP_PKEY_assign_EC_KEY((EVP_PKEY *) pkey, ec_priv);
	} else EC_KEY_free(ec_priv);
    }
    if (!pkey) {
	libVES_setErrorEVP(ves, LIBVES_E_CRYPTO, "[generate EC]");
	return NULL;
    }
    libVES_VaultKey *vkey = malloc(sizeof(libVES_VaultKey));
    vkey->algo = algo;
    vkey->pPriv = pkey;
    vkey->pPub = NULL;
    vkey->ves = ves;
    return vkey;
}

int libVES_KeyAlgo_ECDH_derive(EVP_PKEY *pub, EVP_PKEY *priv, char *buf, size_t len) {
    if (!priv || !pub) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return -1;
    unsigned char dh[256];
    size_t dhlen = sizeof(dh);
    int res = -1;
    if (EVP_PKEY_derive_init(ctx) > 0
	&& EVP_PKEY_derive_set_peer(ctx, pub) > 0
	&& EVP_PKEY_derive(ctx, dh, &dhlen) > 0) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	unsigned int shalen = sizeof(dh);
	if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) > 0
	    && EVP_DigestUpdate(mdctx, dh, dhlen) > 0
	    && EVP_DigestFinal_ex(mdctx, dh, &shalen) > 0) {
	    res = shalen;
	    if (len < res) res = len;
	    memcpy(buf, dh, res);
	}
	if (mdctx) EVP_MD_CTX_destroy(mdctx);
    }
    memset(dh, 0, sizeof(dh));
    EVP_PKEY_CTX_free(ctx);
    return res;
}

int libVES_KeyAlgo_ECDH_decrypt(libVES_VaultKey *vkey, const char *ciphertext, size_t *ctlen, char *plaintext, char *key, size_t *keylen) {
    const char *ctext = ciphertext;
    EVP_PKEY* epub = d2i_PUBKEY(NULL, (const unsigned char **) &ctext, *ctlen);
    if (!epub) libVES_throwEVP(vkey->ves, LIBVES_E_CRYPTO, "read ePub", -1);
    *ctlen = ctext - ciphertext;
    int l = libVES_KeyAlgo_ECDH_derive(epub, vkey->pPriv, key, *keylen);
    if (l < 0) libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "ECDH derive");
    else *keylen = l;
    EVP_PKEY_free(epub);
    return l < 0 ? -1 : 0;
}

int libVES_KeyAlgo_ECDH_encrypt(libVES_VaultKey *vkey, const char *plaintext, size_t *ptlen, char *ciphertext, char *key, size_t *keylen) {
    EC_KEY *ec_vkey = EVP_PKEY_get1_EC_KEY(vkey->pPub);
    if (!ec_vkey) libVES_throwEVP(vkey->ves, LIBVES_E_CRYPTO, "EC pub", -1);
    EC_KEY *ec_epriv = EC_KEY_new();
    EC_KEY_set_group(ec_epriv, EC_KEY_get0_group(ec_vkey));
    EC_KEY_free(ec_vkey);
    EC_KEY_generate_key(ec_epriv);
    EVP_PKEY *epriv = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(epriv, ec_epriv);
    int res = -1;
    int l = libVES_KeyAlgo_ECDH_derive(vkey->pPub, epriv, key, *keylen);
    if (l < 0) libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "ECDH derive");
    else {
	*keylen = l;
	res = i2d_PUBKEY(epriv, (unsigned char **) &ciphertext);
	if (res < 0) libVES_setErrorEVP(vkey->ves, LIBVES_E_CRYPTO, "write ePub");
	else *ptlen = 0;
    }
    EVP_PKEY_free(epriv);
    return res;
}





void *libVES_KeyAlgo_autoEVPfn = (void *) &libVES_KeyAlgo_autoEVP_new;
void *libVES_KeyAlgo_autoPEMfn = (void *) &libVES_KeyAlgo_autoPEM_new;

const libVES_KeyAlgo libVES_KeyAlgo_RSA = {
    .str = "RSA",
    .name = "RSA with OAEP padding",
    .newfn = &libVES_KeyAlgo_RSA_new,
    .str2pubfn = &libVES_KeyAlgo_EVP_str2pub,
    .pub2strfn = &libVES_KeyAlgo_EVP_pub2str,
    .str2privfn = &libVES_KeyAlgo_EVP_str2priv,
    .priv2strfn = &libVES_KeyAlgo_EVP_priv2str,
    .encfn = &libVES_KeyAlgo_RSA_encrypt,
    .decfn = &libVES_KeyAlgo_RSA_decrypt,
    .lockfn = &libVES_KeyAlgo_EVP_lock,
    .dumpfn = &libVES_KeyAlgo_EVP_dump,
    .freefn = NULL
};

const libVES_KeyAlgo libVES_KeyAlgo_ECDH = {
    .str = "ECDH",
    .name = "ECDH ECIES",
    .newfn = &libVES_KeyAlgo_ECDH_new,
    .str2pubfn = &libVES_KeyAlgo_EVP_str2pub,
    .pub2strfn = &libVES_KeyAlgo_EVP_pub2str,
    .str2privfn = &libVES_KeyAlgo_EVP_str2priv,
    .priv2strfn = &libVES_KeyAlgo_EVP_priv2str,
    .encfn = &libVES_KeyAlgo_ECDH_encrypt,
    .decfn = &libVES_KeyAlgo_ECDH_decrypt,
    .lockfn = &libVES_KeyAlgo_EVP_lock,
    .dumpfn = &libVES_KeyAlgo_EVP_dump,
    .freefn = NULL
};
