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
 * (c) 2022 VESvault Corp
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
 * libVES/KeyAlgo_OQS.c       libVES: Vault Key algorithms via libOQS
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
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <oqs/kem.h>

#include "../jVar.h"
#include "../libVES.h"
#include "VaultKey.h"
#include "Util.h"
#include "KeyAlgo_EVP.h"
#include "KeyAlgo_OQS.h"


typedef struct libVES_KeyAlgo_OQS_PRIVATEKEY_st {
    int32_t version;
    ASN1_OCTET_STRING *privateKey;
    ASN1_BIT_STRING *publicKey;
} libVES_KeyAlgo_OQS_PRIVATEKEY;

ASN1_SEQUENCE(libVES_KeyAlgo_OQS_PRIVATEKEY) = {
    ASN1_EMBED(libVES_KeyAlgo_OQS_PRIVATEKEY, version, INT32),
    ASN1_SIMPLE(libVES_KeyAlgo_OQS_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
    ASN1_EXP_OPT(libVES_KeyAlgo_OQS_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
} static_ASN1_SEQUENCE_END(libVES_KeyAlgo_OQS_PRIVATEKEY)

#if OPENSSL_VERSION_NUMBER >= 0x30000000
DECLARE_ASN1_FUNCTIONS(libVES_KeyAlgo_OQS_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(libVES_KeyAlgo_OQS_PRIVATEKEY, libVES_KeyAlgo_OQS_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS(libVES_KeyAlgo_OQS_PRIVATEKEY)
#else
DECLARE_ASN1_FUNCTIONS_const(libVES_KeyAlgo_OQS_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(libVES_KeyAlgo_OQS_PRIVATEKEY, libVES_KeyAlgo_OQS_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS_const(libVES_KeyAlgo_OQS_PRIVATEKEY)
#endif

#define libVES_KeyAlgo_OQS_chklimits(kem)	((kem)->length_ciphertext <= LIBVES_MAXLEN_ENCDATA - 256 && (kem)->length_secret_key + (kem)->length_public_key <= LIBVES_MAXLEN_KEY * 3 / 4 - 256)

void *libVES_KeyAlgo_OQS_pkeygen(const libVES_KeyAlgo *algo, const char *algostr) {
    libVES_KeyAlgo_OQS_Key *oqs = malloc(sizeof(*oqs));
    if (!oqs) return NULL;
    const char *s = algostr ? strchr(algostr, ':') : NULL;
    oqs->kem = OQS_KEM_new(s ? s + 1 : libVES_KeyAlgo_OQS_defaultAlgo);
    if (!libVES_KeyAlgo_OQS_chklimits(oqs->kem)) return OQS_KEM_free(oqs->kem), free(oqs), NULL;
    oqs->pub = NULL;
    oqs->priv = NULL;
    return oqs;
}

libVES_VaultKey *libVES_KeyAlgo_OQS_new(const libVES_KeyAlgo *algo, void *pkey, const libVES_veskey *veskey, libVES *ves) {
    libVES_KeyAlgo_OQS_Key *oqs = pkey;
    if (!oqs) oqs = libVES_KeyAlgo_OQS_pkeygen(algo, NULL);
    if (!oqs || !oqs->kem) {
	libVES_setError(ves, LIBVES_E_CRYPTO, "Error allocating OQS");
	if (!pkey) free(oqs);
	return NULL;
    }
    if (!oqs->pub) {
	oqs->pub = malloc(oqs->kem->length_public_key);
	oqs->priv = malloc(oqs->kem->length_secret_key);
	if (!oqs->pub || !oqs->priv || OQS_KEM_keypair(oqs->kem, oqs->pub, oqs->priv) != OQS_SUCCESS) {
	    libVES_setError(ves, LIBVES_E_CRYPTO, "Error generating OQS keypair");
	    if (!pkey) {
		free(oqs->pub);
		free(oqs->priv);
		OQS_KEM_free(oqs->kem);
		free(oqs);
	    }
	    return NULL;
	}
    }
    libVES_VaultKey *vkey = malloc(sizeof(libVES_VaultKey));
    if (!vkey) return NULL;
    vkey->algo = algo;
    vkey->pPriv = oqs;
    vkey->pPub = NULL;
    vkey->ves = ves;
    return vkey;
}

void *libVES_KeyAlgo_OQS_str2pub(libVES_VaultKey *vkey, const char *pub) {
    libVES_KeyAlgo_OQS_Key *oqs = NULL;
    BIO *bio = BIO_new_mem_buf((void *) pub, strlen(pub));
    unsigned char *asn = NULL;
    long asnl;
    if (PEM_bytes_read_bio(&asn, &asnl, NULL, "PUBLIC KEY", bio, NULL, NULL)) {
	X509_PUBKEY *pubkey = NULL;
	const unsigned char *asn1 = asn;
	if (d2i_X509_PUBKEY(&pubkey, &asn1, asnl)) {
	    int len;
	    X509_ALGOR *algor;
	    const unsigned char *asn2;
	    if (X509_PUBKEY_get0_param(NULL, &asn2, &len, &algor, pubkey) > 0) {
		const ASN1_OBJECT *obj;
		const ASN1_STRING *pval;
		int ptype;
		char oid[24];
		X509_ALGOR_get0(&obj, &ptype, (const void **)&pval, algor);
		if (OBJ_obj2txt(oid, sizeof(oid), obj, 1) > 0) {
		    char algo[48];
		    OQS_KEM *kem;
		    if (!strcmp(oid, libVES_KeyAlgo_OQS_OID) && ptype == V_ASN1_OCTET_STRING && pval && pval->length < sizeof(algo)) {
			memcpy(algo, pval->data, pval->length);
			algo[pval->length] = 0;
			kem = OQS_KEM_new(algo);
			if (kem) {
			    if (kem->length_public_key == len) {
				oqs = malloc(sizeof(*oqs));
				if (oqs && ((oqs->pub = malloc(len)))) {
				    oqs->kem = kem;
				    oqs->priv = NULL;
				    memcpy(oqs->pub, asn2, len);
				} else {
				    free(oqs);
				    oqs = NULL;
				}
			    } else {
				libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect public key length");
				OQS_KEM_free(kem);
			    }
			} else {
			    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "OQS KEM error (unsupported algorithm?)");
			}
		    } else {
			libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect public key type");
		    }
		}
	    }
	    X509_PUBKEY_free(pubkey);
	} else {
	    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Malformed public key");
	}
	free(asn);
    } else {
	libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Expected: Public Key");
    }
    BIO_free(bio);
    return oqs;
}

char *libVES_KeyAlgo_OQS_pub2str(libVES_VaultKey *vkey, void *pkey) {
    libVES_KeyAlgo_OQS_Key *oqs = pkey;
    ASN1_OBJECT *obj;
    ASN1_STRING *algo;
    char *str = NULL;
    if (!oqs || !oqs->kem || !oqs->pub) return NULL;
    if ((obj = OBJ_txt2obj(libVES_KeyAlgo_OQS_OID, 1))) {
	if ((algo = ASN1_STRING_new())) {
	    X509_PUBKEY *pub = X509_PUBKEY_new();
	    if (pub) {
		if (ASN1_STRING_set(algo, oqs->kem->method_name, strlen(oqs->kem->method_name))) {
		    unsigned char *penc = malloc(oqs->kem->length_public_key);
		    if (penc && (memcpy(penc, oqs->pub, oqs->kem->length_public_key)
		    , X509_PUBKEY_set0_param(pub, obj, V_ASN1_OCTET_STRING, algo, penc, oqs->kem->length_public_key)) > 0) {
			unsigned char *asn = NULL;
			int len = i2d_X509_PUBKEY(pub, &asn);
			if (len > 0) {
			    BIO *mem = BIO_new(BIO_s_mem());
			    char *pem;
			    if (PEM_write_bio(mem, "PUBLIC KEY", "", asn, len) > 0) {
				int l = BIO_get_mem_data(mem, &pem);
				if ((str = malloc(l + 1))) {
				    memcpy(str, pem, l);
				    str[l] = 0;
				}
			    }
			    BIO_free(mem);
			}
			free(asn);
		    } else free(penc);
		    algo = NULL;
		    obj = NULL;
		}
		X509_PUBKEY_free(pub);
	    }
	    ASN1_STRING_free(algo);
	}
	ASN1_OBJECT_free(obj);
    }
    return str;
}



void *libVES_KeyAlgo_OQS_str2priv(libVES_VaultKey *vkey, const char *priv, const libVES_veskey *veskey) {
    libVES_KeyAlgo_OQS_Key *oqs = NULL;
    BIO *bio = BIO_new_mem_buf((void *) priv, strlen(priv));
    unsigned char *asn = NULL;
    long asnl;
    if (PEM_bytes_read_bio(&asn, &asnl, NULL, PEM_STRING_EVP_PKEY, bio, (veskey ? &libVES_KeyAlgo_EVP_veskey_cb : NULL), (void *)veskey)) {
	PKCS8_PRIV_KEY_INFO *privkey = NULL;
	X509_SIG *sig = NULL;
	const unsigned char *asn1 = asn;
	if (veskey && d2i_X509_SIG(&sig, &asn1, asnl)) {
	    privkey = PKCS8_decrypt(sig, veskey->veskey, veskey->keylen);
	    X509_SIG_free(sig);
	    if (!privkey) libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Error decrypting private key (bad VESkey?)");
	} else if (!d2i_PKCS8_PRIV_KEY_INFO(&privkey, &asn1, asnl)) {
	    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Malformed private key");
	}
	if (privkey) {
	    int len;
	    const X509_ALGOR *algor;
	    const unsigned char *asn2;
	    if (PKCS8_pkey_get0(NULL, &asn2, &len, &algor, privkey) > 0) {
		const ASN1_OBJECT *obj;
		const ASN1_STRING *pval;
		int ptype;
		char oid[24];
		X509_ALGOR_get0(&obj, &ptype, (const void **)&pval, algor);
		if (OBJ_obj2txt(oid, sizeof(oid), obj, 1) > 0) {
		    char algo[48];
		    OQS_KEM *kem;
		    if (!strcmp(oid, libVES_KeyAlgo_OQS_OID) && ptype == V_ASN1_OCTET_STRING && pval && pval->length < sizeof(algo)) {
			memcpy(algo, pval->data, pval->length);
			algo[pval->length] = 0;
			kem = OQS_KEM_new(algo);
			if (kem) {
			    libVES_KeyAlgo_OQS_PRIVATEKEY *priv = NULL;
			    if (d2i_libVES_KeyAlgo_OQS_PRIVATEKEY(&priv, &asn2, len)) {
				if (!priv->publicKey) {
				    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "No public key is OQS bundle");
				} else if (priv->privateKey->length != kem->length_secret_key) {
				    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect OQS private key length");
				} else if (priv->publicKey->length != kem->length_public_key) {
				    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect OQS public key length");
				} else {
				    oqs = malloc(sizeof(*oqs));
				    if (oqs) {
					oqs->priv = malloc(kem->length_secret_key);
					oqs->pub = malloc(kem->length_public_key);
					if (oqs->priv && oqs->pub) {
					    oqs->kem = kem;
					    memcpy(oqs->priv, priv->privateKey->data, kem->length_secret_key);
					    memcpy(oqs->pub, priv->publicKey->data, kem->length_public_key);
					} else {
					    free(oqs->priv);
					    free(oqs->pub);
					    OQS_KEM_free(kem);
					    free(oqs);
					    oqs = NULL;
					}
				    }
				}
				libVES_KeyAlgo_OQS_PRIVATEKEY_free(priv);
			    } else {
				libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect public key length");
				OQS_KEM_free(kem);
			    }
			} else {
			    libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "OQS KEM error (unsupported algorithm?)");
			}
		    } else {
			libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Incorrect public key type");
		    }
		}
	    }
	    PKCS8_PRIV_KEY_INFO_free(privkey);
	}
	free(asn);
    } else {
	libVES_setError(vkey->ves, LIBVES_E_CRYPTO, "Missing private key or bad VESkey");
    }
    BIO_free(bio);
    return oqs;
}



char *libVES_KeyAlgo_OQS_priv2str(libVES_VaultKey *vkey, void *pkey, const libVES_veskey *veskey) {
    libVES_KeyAlgo_OQS_Key *oqs = pkey;
    ASN1_OBJECT *obj;
    ASN1_STRING *algo;
    char *str = NULL;
    if (!oqs || !oqs->kem || !oqs->pub || !oqs->priv) return NULL;
    if ((obj = OBJ_txt2obj(libVES_KeyAlgo_OQS_OID, 1))) {
	if ((algo = ASN1_STRING_new()) && ASN1_STRING_set(algo, oqs->kem->method_name, strlen(oqs->kem->method_name))) {
	    PKCS8_PRIV_KEY_INFO *privkey = PKCS8_PRIV_KEY_INFO_new();
	    if (privkey) {
		libVES_KeyAlgo_OQS_PRIVATEKEY *priv = libVES_KeyAlgo_OQS_PRIVATEKEY_new();
		if (priv) {
		    priv->publicKey = ASN1_STRING_type_new(V_ASN1_BIT_STRING);
		    if (priv->publicKey
		    && ASN1_STRING_set(priv->privateKey, oqs->priv, oqs->kem->length_secret_key)
		    && ASN1_STRING_set(priv->publicKey, oqs->pub, oqs->kem->length_public_key)) {
			unsigned char *asn = NULL;
			int len = i2d_libVES_KeyAlgo_OQS_PRIVATEKEY(priv, &asn);
			if (len > 0 && PKCS8_pkey_set0(privkey, obj, 0, V_ASN1_OCTET_STRING, algo, asn, len)) {
			    BIO *mem = BIO_new(BIO_s_mem());
			    int w;
			    unsigned char *pem;
			    if (veskey) {
				X509_SIG *sig = PKCS8_encrypt(-1, EVP_aes_256_cbc(), veskey->veskey, veskey->keylen, NULL, 0, 0, privkey);
				w = sig ? PEM_write_bio_PKCS8(mem, sig) : -1;
				X509_SIG_free(sig);
			    } else {
				w = PEM_write_bio_PKCS8_PRIV_KEY_INFO(mem, privkey);
			    }
			    if (w > 0) {
				int l = BIO_get_mem_data(mem, &pem);
				if ((str = malloc(l + 1))) {
				    memcpy(str, pem, l);
				    str[l] = 0;
				}
			    }
			    BIO_free(mem);
			    obj = NULL;
			    algo = NULL;
			} else free(asn);
		    }
		    libVES_KeyAlgo_OQS_PRIVATEKEY_free(priv);
		}
	    }
	    PKCS8_PRIV_KEY_INFO_free(privkey);
	}
	ASN1_STRING_free(algo);
	ASN1_OBJECT_free(obj);
    }
    return str;
}

void libVES_KeyAlgo_OQS_keyfree(libVES_KeyAlgo_OQS_Key *oqs) {
    if (!oqs) return;
    OQS_KEM_free(oqs->kem);
    free(oqs->pub);
    if (oqs->priv) OPENSSL_cleanse(oqs->priv, oqs->kem->length_secret_key);
    free(oqs->priv);
    free(oqs);
}

void libVES_KeyAlgo_OQS_lock(libVES_VaultKey *vkey) {
    if (vkey->pPub && vkey->pPub != vkey->pPriv) libVES_KeyAlgo_OQS_keyfree(vkey->pPub);
    if (vkey->pPriv) libVES_KeyAlgo_OQS_keyfree(vkey->pPriv);
    vkey->pPriv = vkey->pPub = NULL;
}

int libVES_KeyAlgo_OQS_dump(libVES_VaultKey *vkey, int fd, int flags) {
    libVES_KeyAlgo_OQS_Key *oqs = vkey->pPriv;
    if (!oqs) oqs = vkey->pPub;
    BIO *out;
    if (!oqs || !oqs->kem) return -1;
    out = BIO_new_fd(fd, BIO_NOCLOSE);
    int w = BIO_printf(out, "\tOQS: %s (%s)\n\tNIST level: %d\n\tIND-%s\n", oqs->kem->method_name, oqs->kem->alg_version, oqs->kem->claimed_nist_level, (oqs->kem->ind_cca ? "CCA" : "CPA"));
    BIO_free(out);
    return w;
}

int libVES_KeyAlgo_OQS_derive(unsigned char *secret, size_t slen, char *buf, size_t len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    unsigned char sha[48];
    int res;
    unsigned int shalen = sizeof(sha);
    if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) > 0
    && EVP_DigestUpdate(mdctx, secret, slen) > 0
    && EVP_DigestFinal_ex(mdctx, sha, &shalen) > 0) {
	res = shalen;
	if (len < res) res = len;
	memcpy(buf, sha, res);
    } else res = -1;
    EVP_MD_CTX_destroy(mdctx);
    OPENSSL_cleanse(secret, slen);
    return res;
}

int libVES_KeyAlgo_OQS_decrypt(libVES_VaultKey *vkey, const char *ciphertext, size_t *ctlen, char *plaintext, char *key, size_t *keylen) {
    libVES_KeyAlgo_OQS_Key *oqs = vkey->pPriv;
    unsigned char secret[128];
    int len;
    if (!oqs || !oqs->kem || !oqs->priv) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "Missing OQS private key", -1);
    if (oqs->kem->length_shared_secret > sizeof(secret)) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS secret is too long", -1);
    if (*ctlen < oqs->kem->length_ciphertext) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS ciphertext is too short", -1);
    if (OQS_KEM_decaps(oqs->kem, secret, (const unsigned char *)ciphertext, oqs->priv) != OQS_SUCCESS) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS decaps failed", -1);
    len = libVES_KeyAlgo_OQS_derive(secret, oqs->kem->length_shared_secret, key, *keylen);
    if (len < 0) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS key derivation failed", -1);
    *keylen = len;
    *ctlen = oqs->kem->length_ciphertext;
    return 0;
}

int libVES_KeyAlgo_OQS_encrypt(libVES_VaultKey *vkey, const char *plaintext, size_t *ptlen, char *ciphertext, char *key, size_t *keylen) {
    libVES_KeyAlgo_OQS_Key *oqs = vkey->pPub;
    unsigned char secret[128];
    int len;
    if (!oqs || !oqs->kem || !oqs->pub) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "Missing OQS public key", -1);
    if (oqs->kem->length_shared_secret > sizeof(secret)) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS secret is too long", -1);
    if (ciphertext) {
	if (OQS_KEM_encaps(oqs->kem, (unsigned char *)ciphertext, secret, oqs->pub) != OQS_SUCCESS) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS encaps failed", -1);
	len = libVES_KeyAlgo_OQS_derive(secret, oqs->kem->length_shared_secret, key, *keylen);
	if (len <= 0) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "OQS key derivation failed", -1);
	*keylen = len;
    }
    *ptlen = 0;
    return oqs->kem->length_ciphertext;
}

void libVES_KeyAlgo_OQS_pkeyfree(const libVES_KeyAlgo *algo, void *pkey) {
    libVES_KeyAlgo_OQS_keyfree(pkey);
}

int libVES_KeyAlgo_OQS_methodstr(const libVES_KeyAlgo *algo, char *buf, size_t buflen, int idx) {
    const char *a = idx >= 0 ? OQS_KEM_alg_identifier(idx) : NULL;
    if (!a) return -1;
    int l = strlen(a);
    if (l >= buflen || !OQS_KEM_alg_is_enabled(a)) return 0;
    OQS_KEM *kem = OQS_KEM_new(a);
    if (!kem) return 0;
    if (!libVES_KeyAlgo_OQS_chklimits(kem)) l = 0;
    OQS_KEM_free(kem);
    if (l) strcpy(buf, a);
    return l;
}


const libVES_KeyAlgo libVES_KeyAlgo_OQS = {
    .str = "OQS",
    .name = "libOQS Post-Quantum Suite",
    .newfn = &libVES_KeyAlgo_OQS_new,
    .str2pubfn = &libVES_KeyAlgo_OQS_str2pub,
    .pub2strfn = &libVES_KeyAlgo_OQS_pub2str,
    .str2privfn = &libVES_KeyAlgo_OQS_str2priv,
    .priv2strfn = &libVES_KeyAlgo_OQS_priv2str,
    .priv2pubfn = NULL,
    .encfn = &libVES_KeyAlgo_OQS_encrypt,
    .decfn = &libVES_KeyAlgo_OQS_decrypt,
    .lockfn = &libVES_KeyAlgo_OQS_lock,
    .dumpfn = &libVES_KeyAlgo_OQS_dump,
    .freefn = NULL,
    .pkeygenfn = &libVES_KeyAlgo_OQS_pkeygen,
    .pkeyfreefn = &libVES_KeyAlgo_OQS_pkeyfree,
    .methodstrfn = &libVES_KeyAlgo_OQS_methodstr,
    .len = sizeof(libVES_KeyAlgo)
};
