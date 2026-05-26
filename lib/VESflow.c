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
 * (c) 2026 VESvault Corp
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
 * VESflow.c                   libVES: URL-based e2ee messaging flow
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>

#include "libVES.h"
#include "jVar.h"
#include "libVES/KeyStore.h"
#include "VESflow.h"

static const char VESflow_prefix[8] = "VESflow.";

static const unsigned char VESflow_escapemap[32] = {
    0xff, 0xff, 0xff, 0xff, 0x79, 0x98, 0x00, 0xfc,
    0x01, 0x00, 0x00, 0x78, 0x01, 0x00, 0x00, 0xb8,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static jVar *VESflow_bn2jvar(const BIGNUM *bn) {
    if (!bn) return NULL;
    int len = BN_num_bytes(bn);
    int bufl = len * 7 / 3 + 3;
    char *buf = malloc(bufl);
    BN_bn2bin(bn, buf);
    jVar *jv = jVar_string(libVES_b64encode_web(buf, len, buf + len));
    OPENSSL_cleanse(buf, bufl);
    free(buf);
    return jv;
}

static BIGNUM *VESflow_jvar2bn(jVar *jv) {
    const char *b64 = jVar_getStringP(jv);
    if (!b64) return NULL;
    char *val = NULL;
    int len = libVES_b64decode(b64, &val);
    BIGNUM *bn = BN_bin2bn(val, len, NULL);
    OPENSSL_cleanse(val, len);
    free(val);
    return bn;
}

static jVar *VESflow_jvar2pub(jVar *jpriv, ...) {
    va_list va;
    jVar *jpub = jVar_object();
    va_start(va, jpriv);
    const char *k;
    while ((k = va_arg(va, const char *))) {
        jVar *v = jVar_get(jpriv, k);
        if (v) jVar_put(jpub, k, jVar_clone(v));
    }
    va_end(va);
    return jpub;
}

static int VESflow_KeyAlgo_EC_nid(const char *algo) {
    if (algo && algo[0] == 'P' && algo[1] == '-') {
        if (!strcmp(algo + 2, "256")) return NID_X9_62_prime256v1;
        else if (!strcmp(algo + 2, "384")) return NID_secp384r1;
        else if (!strcmp(algo + 2, "521")) return NID_secp521r1;
    }
    return -1;
}

static EC_KEY *VESflow_KeyAlgo_EC_jvar2ec(jVar *jkey) {
    int nid = VESflow_KeyAlgo_EC_nid(jVar_getStringP(jVar_get(jkey, "crv")));
    if (nid < 0) return NULL;
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid);
    if (!grp) return NULL;
    EC_KEY *ec = EC_KEY_new();
    EC_KEY_set_group(ec, grp);
    EC_GROUP_free(grp);
    BIGNUM *d = VESflow_jvar2bn(jVar_get(jkey, "d"));
    BIGNUM *x = VESflow_jvar2bn(jVar_get(jkey, "x"));
    BIGNUM *y = VESflow_jvar2bn(jVar_get(jkey, "y"));
    int ok = x && y
        && EC_KEY_set_public_key_affine_coordinates(ec, x, y) > 0
        && (!d || EC_KEY_set_private_key(ec, d) > 0);
    BN_free(y);
    BN_free(x);
    BN_free(d);
    if (!ok) return EC_KEY_free(ec), NULL;
    return ec;
}

static const char *VESflow_KeyAlgo_EC_algo(jVar *jkey) {
    const char *kty = jVar_getStringP(jVar_get(jkey, "kty"));
    if (strcmp(kty, "EC")) return NULL;
    return jVar_getStringP(jVar_get(jkey, "crv"));
}

static jVar *VESflow_KeyAlgo_EC_keygen(const char *ref) {
    int nid = VESflow_KeyAlgo_EC_nid(ref);
    if (nid < 0) return NULL;
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid);
    if (!grp) return NULL;
    EC_KEY *ec_priv = EC_KEY_new();
    EC_KEY_set_group(ec_priv, grp);
    EC_GROUP_free(grp);
    EC_KEY_set_asn1_flag(ec_priv, OPENSSL_EC_NAMED_CURVE);
    if (!EC_KEY_generate_key(ec_priv)) {
        EC_KEY_free(ec_priv);
        return NULL;
    }
    jVar *jkey = jVar_object();
    jVar_put(jkey, "kty", jVar_string("EC"));
    jVar_put(jkey, "crv", jVar_string(ref));
    jVar_put(jkey, "d", VESflow_bn2jvar(EC_KEY_get0_private_key(ec_priv)));
    const EC_POINT *pub = EC_KEY_get0_public_key(ec_priv);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec_priv), pub, x, y, NULL);
    jVar_put(jkey, "x", VESflow_bn2jvar(x));
    jVar_put(jkey, "y", VESflow_bn2jvar(y));
    BN_free(y);
    BN_free(x);
    EC_KEY_free(ec_priv);
    return jkey;
}

static jVar *VESflow_KeyAlgo_EC_priv2pub(jVar *jpriv) {
    return VESflow_jvar2pub(jpriv, "kty", "crv", "x", "y", NULL);
}

static int VESflow_KeyAlgo_EC_derive(jVar *jpub, jVar *jpriv, char **psh, int *pshlen, char **pkc, int *pkclen) {
    EC_KEY *pub = VESflow_KeyAlgo_EC_jvar2ec(jpub);
    if (!pub) return 0;
    EC_KEY *priv = VESflow_KeyAlgo_EC_jvar2ec(jpriv);
    if (!priv) return EC_KEY_free(pub), 0;
    EVP_PKEY *ppub = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(ppub, pub);
    EVP_PKEY *ppriv = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(ppriv, priv);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ppriv, NULL);
    size_t dhlen = 256;
    int ok = ctx && EVP_PKEY_derive_init(ctx) > 0
        && EVP_PKEY_derive_set_peer(ctx, ppub) > 0
        && (*psh || (EVP_PKEY_derive(ctx, NULL, &dhlen) > 0 && (*psh = malloc(dhlen))))
        && EVP_PKEY_derive(ctx, (unsigned char *)*psh, &dhlen) > 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ppriv);
    EVP_PKEY_free(ppub);
    return ok ? *pshlen = dhlen : 0;
}


static VESflow_KeyAlgo VESflow_KeyAlgo_EC = {
    .algo = &VESflow_KeyAlgo_EC_algo,
    .keygen = &VESflow_KeyAlgo_EC_keygen,
    .priv2pub = &VESflow_KeyAlgo_EC_priv2pub,
    .derive = &VESflow_KeyAlgo_EC_derive
};

static VESflow_KeyAlgo *VESflow_algos[] = { &VESflow_KeyAlgo_EC, NULL };

VESflow *VESflow_new(const char *name, const char *url) {
    if (!name) name = VESFLOW_DEFAULTNAME;
    VESflow *flow = malloc(sizeof(VESflow) + strlen(name) + (url ? strlen(url) + 1 : 0));
    strcpy(flow->name, name);
    flow->ks = NULL;
    flow->keys = NULL;
    flow->defaultAlgo = VESFLOW_DEFAULTALGO;
    flow->escapemap = VESflow_escapemap;
    if (url) {
        char *d = flow->name + strlen(flow->name) + 1;
        strcpy(d, url);
        flow->url = d;
    } else flow->url = NULL;
    return flow;
}

static char *VESflow_origin(char *buf, const char *url) {
    if (!url) return NULL;
    const char *s = strchr(url, '/');
    if (!s || *++s != '/') return NULL;
    s++;
    char c;
    char *d = buf;
    char *dmax = buf + 255;
    int fsym = 1;
    while ((c = *s++)) {
        if (d >= dmax) return NULL;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) *d++ = c;
        else if (c >= 'A' && c <= 'Z') *d++ = c | 0x20;
        else if (c == '.' || c == '-' || c == ':') {
            if (fsym++) return NULL;
            *d++ = c;
            continue;
        } else break;
        fsym = 0;
    }
    switch (c) {
        case 0: case '/': case '?': case '#':
            *d = 0;
            return buf;
        default:
            return NULL;
    }
}

static jVar *VESflow_keygen(const char *ref) {
    VESflow_KeyAlgo **a;
    jVar *jkey = NULL;
    for (a = VESflow_algos; *a; a++) {
        jkey = (*a)->keygen(ref);
        if (jkey) break;
    }
    return jkey;
}

static jVar *VESflow_priv2pub(jVar *jpriv) {
    VESflow_KeyAlgo **a;
    jVar *jkey = NULL;
    for (a = VESflow_algos; *a; a++) {
        jkey = (*a)->priv2pub(jpriv);
        if (jkey) break;
    }
    return jkey;
}

static jVar *VESflow_appendKey(VESflow *flow, const char *ref, int type, jVar *jkey) {
    struct VESflow_KeyEntry *k = malloc(sizeof(struct VESflow_KeyEntry) + strlen(ref) + 1);
    strcpy(k->ref, ref);
    k->key = jkey;
    k->type = type;
    k->chain = flow->keys;
    flow->keys = k;
    return jkey;
}

static jVar *VESflow_replaceKey(VESflow *flow, const char *ref, int type, jVar *jkey) {
    struct VESflow_KeyEntry *k;
    if (flow->ks) flow->ks->putfn(flow->ksref, ref, type, jkey);
    for (k = flow->keys; k; k = k->chain) {
        if (!strcmp(ref, k->ref) && k->type == type) {
            jVar_free(k->key);
            return k->key = jkey;
        }
    }
    return VESflow_appendKey(flow, ref, type, jkey);
}

static jVar *VESflow_getKey(VESflow *flow, const char *ref, int type) {
    struct VESflow_KeyEntry *k;
    jVar *skey = NULL;
    int stype = type == VESFLOW_K_LPUB ? VESFLOW_K_LPRIV : type;
    for (k = flow->keys; k; k = k->chain) {
        if (!strcmp(ref, k->ref)) {
            if (k->type == type) return k->key;
            else if (k->type == stype) skey = k->key;
        }
    }
    if (!skey) {
        if (flow->ks) skey = flow->ks->getfn(flow->ksref, ref, stype);
        if (!skey && stype == VESFLOW_K_LPRIV) {
            skey = VESflow_keygen(ref);
            if (skey && flow->ks) flow->ks->putfn(flow->ksref, ref, stype, skey);
        }
        if (skey) VESflow_appendKey(flow, ref, stype, skey);
    }
    if (type != VESFLOW_K_LPUB || !skey) return skey;
    return VESflow_appendKey(flow, ref, type, VESflow_priv2pub(skey));
}

int VESflow_urlencode(VESflow *flow, const char *src, int len, char *dst) {
    const char *s = src;
    char *d = dst;
    unsigned char c;
    static const char hex[16] = "0123456789ABCDEF";
    while ((c = *s++)) {
        if (flow->escapemap[c >> 3] & (1 << (c & 7))) {
            *d++ = '%';
            *d++ = hex[c >> 4];
            *d++ = hex [c & 0x0f];
        } else *d++ = c;
    }
    return d - dst;
}

int VESflow_urldecode(VESflow *flow, const char *src, int len, char *dst) {
    char *d = dst;
    const char *s = src;
    const char *e = s + len;
    while (s < e) {
        char c = *s++;
        if (c == '%' && s + 2 <= e) {
            char h1 = s[0];
            char h2 = s[1];
            if ((h1 >= 'A' && h1 <= 'F') || (h1 >= 'a' && h1 <= 'f')) h1 += 9;
            else if (h1 < '0' || h1 > '9') h1 = 0;
            if ((h2 >= 'A' && h2 <= 'F') || (h2 >= 'a' && h2 <= 'f')) h2 += 9;
            else if (h2 < '0' || h2 > '9') h2 = 0;
            if (h1 && h2) {
                c = ((h1 & 0x0f) << 4) | (h2 & 0x0f);
                s += 2;
            }
        }
        *d++ = c;
    }
    return d - dst;
}

static int VESflow_derive(VESflow *flow, jVar *jpub, char *buf, char **pkc, int *pkclen) {
    VESflow_KeyAlgo **a;
    const char *algo = NULL;
    for (a = VESflow_algos; *a; a++) {
        algo = (*a)->algo(jpub);
        if (algo) break;
    }
    if (!algo) return 0;
    jVar *jpriv = VESflow_getKey(flow, algo, VESFLOW_K_LPRIV);
    if (!jpriv) return 0;
    char sh[256];
    char *psh = sh;
    int shlen = sizeof(sh);
    int r = (*a)->derive(jpub, jpriv, &psh, &shlen, pkc, pkclen);
    if (r <= 0) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    int shalen = 32;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) > 0
        && EVP_DigestUpdate(ctx, sh, shlen) > 0
        && EVP_DigestFinal_ex(ctx, buf, &shalen) > 0;
    EVP_MD_CTX_free(ctx);
    return ok ? shalen : 0;
}

int VESflow_send(VESflow *flow, const char *url, char **rwurl, jVar *data) {
    if (!flow || !url || !rwurl) return VESFLOW_E_ARG;
    const char *algo = NULL;
    char *ctext = NULL;
    if (data) {
        char org[256];
        if (!VESflow_origin(org, url)) return VESFLOW_E_ARG;
        jVar *jpub = VESflow_getKey(flow, org, VESFLOW_K_RPUB);
        if (jpub) {
            char *json = jVar_toJSON(data);
            int jsonl = strlen(json);
            char ckey[32];
            char *kc = NULL;
            int kclen = 0;
            int rs = VESFLOW_E_OK;
            if (VESflow_derive(flow, jpub, ckey, &kc, &kclen)) {
                char iv[12];
                RAND_bytes(iv, sizeof(iv));
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                int ctlen = jsonl + 16;
                int ctlenf;
                char *ctbuf = malloc(ctlen);
                (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ckey, iv) > 0
                    && EVP_EncryptUpdate(ctx, (unsigned char *) ctbuf, &ctlen, (unsigned char *) json, jsonl) > 0
                    && (ctlenf = jsonl - ctlen + 16)
                    && EVP_EncryptFinal_ex(ctx, (unsigned char *) ctbuf + ctlen, &ctlenf) > 0
                    && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (void *)(ctbuf + ctlen + ctlenf)) > 0
                    && (ctlen += ctlenf + 16)
                ) || (free(ctbuf), ctbuf = NULL, rs = VESFLOW_E_ENC);
                EVP_CIPHER_CTX_free(ctx);
                if (ctbuf) {
                    ctext = malloc((ctlen + kclen) * 4 / 3 + 32);
                    char *d = ctext;
                    d += strlen(libVES_b64encode_web(iv, sizeof(iv), d));
                    *d++ = '.';
                    libVES_b64encode_web(ctbuf, ctlen, d);
                    if (kclen > 0) {
                        d += strlen(d);
                        *d++ = '.';
                        libVES_b64encode_web(kc, kclen, d);
                    }
                    free(ctbuf);
                }
                free(kc);
            } else rs = VESFLOW_E_KEY;
            OPENSSL_cleanse(json, jsonl);
            free(json);
            OPENSSL_cleanse(ckey, sizeof(ckey));
            if (rs != VESFLOW_E_OK) return rs;
        }
    }
    if (!algo) algo = flow->defaultAlgo;
    jVar *jkey = VESflow_getKey(flow, algo, VESFLOW_K_LPUB);
    if (!jkey) return free(ctext), VESFLOW_E_KEY;
    jVar *msg = jVar_object();
    jVar_put(msg, "key", jVar_clone(jkey));
    if (ctext) jVar_put(msg, "enc", jVar_string(ctext));
    free(ctext);
    if (flow->url) jVar_put(msg, "url", jVar_string(flow->url));
    char *json = jVar_toJSON(msg);
    jVar_free(msg);
    int urll = strlen(url);
    int jsonl = strlen(json);
    if (!*rwurl) *rwurl = malloc(3 * jsonl + urll + strlen(flow->name) + 16);
    char *d = *rwurl;
    strcpy(d, url);
    d += urll;
    *d++ = strchr(url, '#') ? '&' : '#';
    memcpy(d, VESflow_prefix, sizeof(VESflow_prefix));
    d += sizeof(VESflow_prefix);
    d += strlen(strcpy(d, flow->name));
    *d++ = '=';
    d += VESflow_urlencode(flow, json, jsonl, d);
    *d = 0;
    free(json);
    return data && !ctext ? VESFLOW_E_XCHG : VESFLOW_E_OK;
}

int VESflow_recv(VESflow *flow, const char *url, char **rwurl, jVar **pdata, const char *srcurl) {
    const char *s, *e;
    for (s = strchr(url, '#'); s; s = e) {
        const char *s0 = s;
        if (!*s++) break;
        e = strchr(s, '#');
        const char *a = strchr(s, '&');
        if (!e || (a && a < e)) e = a;
        if (!e) e = s + strlen(s);
        if (strncmp(s, VESflow_prefix, sizeof(VESflow_prefix))) continue;
        s += sizeof(VESflow_prefix);
        int l = strlen(flow->name);
        if (strncmp(s, flow->name, l)) continue;
        s += l;
        if (*s++ != '=') continue;
        char *fval = malloc(e - s + 1);
        char *d = fval + VESflow_urldecode(flow, s, e - s, fval);
        *d = 0;
        jVarParser *jvp = jVarParser_new(NULL);
        jVarParser_parse(jvp, fval, d - fval);
        free(fval);
        jVar *msg = jVarParser_isComplete(jvp) ? jVarParser_done(jvp) : (jVarParser_free(jvp), NULL);
        if (rwurl) {
            if (!*rwurl) *rwurl = malloc(strlen(url) - (e - s0) + 1);
            d = *rwurl;
            memcpy(d, url, s0 - url);
            d += (s0 - url);
            if (*e) {
                *d++ = *s0;
                strcpy(d, e + 1);
            } else *d = 0;
        }
        jVar *jpub = jVar_get(msg, "key");
        jVar *jurl = jVar_get(msg, "url");
        if (jurl) srcurl = jVar_getStringP(jurl);
        if (srcurl) {
            char org[256];
            if (VESflow_origin(org, srcurl)) {
                if (jpub) VESflow_replaceKey(flow, org, VESFLOW_K_RPUB, jVar_clone(jpub));
                else jpub = VESflow_getKey(flow, org, VESFLOW_K_RPUB);
            }
        }
        if (!jpub) return jVar_free(msg), VESFLOW_E_KEY;
        const char *ctext = jVar_getStringP(jVar_get(msg, "enc"));
        int rs = VESFLOW_E_OK;
        if (ctext && pdata) {
            char *buf = malloc(strlen(ctext));
            char *pbuf[4];
            int pblen[3];
            char *d = buf;
            int cl;
            const char *s = ctext;
            for (cl = 0; cl < sizeof(pbuf) / sizeof(pbuf[0]); cl++) {
                pbuf[cl] = d;
                if (cl > 0) pblen[cl - 1] = d - pbuf[cl - 1];
                if (!s) continue;
                const char *e = strchr(s, '.');
                d += libVES_b64decodel(s, (e ? e - s : strlen(s)), &pbuf[cl]);
                s = e ? e + 1 : NULL;
            }
            char ckey[32];
            if (VESflow_derive(flow, jpub, ckey, &pbuf[2], &pblen[2])) {
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                int ptlen0 = pblen[1];
                int ptlen = ptlen0;
                int ptlenf;
                char *ptext = malloc(ptlen0);
                (pblen[0] >= 12 && pblen[1] >= 16
                    && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ckey, pbuf[0]) > 0
                    && EVP_DecryptUpdate(ctx, (unsigned char *) ptext, &ptlen, (unsigned char *) pbuf[1], pblen[1] - 16) > 0
                    && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(pbuf[2] - 16)) > 0
                    && (ptlenf = ptlen0 - ptlen)
                    && EVP_DecryptFinal_ex(ctx, (unsigned char *) ptext + ptlen, &ptlenf) > 0
                ) || (OPENSSL_cleanse(ptext, ptlen0), free(ptext), ptext = NULL, rs = VESFLOW_E_ENC);
                EVP_CIPHER_CTX_free(ctx);
                if (ptext) {
                    jvp = jVarParser_new(NULL);
                    jVarParser_parse(jvp, ptext, ptlen + ptlenf);
                    *pdata = jVarParser_isComplete(jvp) ? jVarParser_done(jvp) : (jVarParser_free(jvp), NULL);
                    if (!*pdata) rs = VESFLOW_E_MSG;
                    OPENSSL_cleanse(ptext, ptlen0);
                }
                free(ptext);
            } else rs = VESFLOW_E_KEY;
            free(buf);
        }
        jVar_free(msg);
        return rs;
    }
    return VESFLOW_E_DATA;
}

void VESflow_setKeyStore(VESflow *flow, VESflow_KeyStore *ks, void *ksref) {
    if (!flow) return;
    flow->ks = ks;
    flow->ksref = ksref;
}

void VESflow_free(VESflow *flow) {
    struct VESflow_KeyEntry *k;
    if (flow) while ((k = flow->keys)) {
        flow->keys = k->chain;
        if (k->type == VESFLOW_K_LPRIV) libVES_cleanseJVar(k->key);
        jVar_free(k->key);
        free(k);
    }
    free(flow);
}

