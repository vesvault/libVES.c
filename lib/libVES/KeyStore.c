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
 * KeyStore.c                    libVES: Local key storage
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "../src/config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <time.h>
#include <jVar.h>
#include "../libVES.h"
#include "VaultKey.h"
#include "Ref.h"
#include "User.h"
#include "List.h"
#include "REST.h"
#include "Util.h"
#include "KeyStore.h"

#ifdef NO_VESLOCKER
#define libVES_KeyStore_dialog_decrypt(...)	(0)
#define libVES_KeyStore_dialog_import(...)	(0)
#else

#include "../VESlocker.h"

struct libVES_KeyStore_api libVES_KeyStore_api_default = {
    .locker = "https://www.vesvault.com/api/VESlocker",
    .msg = "https://www.vesvault.com/api/msg",
    .exportkey = "https://www.vesvault.com/vv/exportkey",
    .importdone = "https://www.vesvault.com/vv/import_done/"
};

static void libVES_KeyStore_VLhttpInitFn(VESlocker *vl) {
    libVES *ves = vl->ref;
    if (ves->httpInitFn) {
	void *tmpcurl = ves->curl;
	ves->curl = vl->curl;
	ves->httpInitFn(ves);
	vl->curl = ves->curl;
	ves->curl = tmpcurl;
	if (ves->debug) curl_easy_setopt(vl->curl, CURLOPT_VERBOSE, 1);
    }
}

static jVar *libVES_KeyStore_wwwPost0(libVES *ves, const char *url, char *body, int len, long *pcode) {
    jVar *post = jVar_stringl0(body, len, 0);
    post->type = JVAR_JSON;
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");
    jVar *msg = libVES_REST_req(ves, url, post, hdrs, pcode);
    jVar_free(post);
    return msg;
}

static VESlocker_entry *libVES_KeyStore_entryfn(void *arg, const char *vlentry, char *pin) {
    return VESlocker_entry_parse(vlentry);
}

struct libVES_KeyStore_import {
    libVES_KeyStore_dialog *dlg;
    char *sess;
    char ch[VESlocker_chsize];
    char idenc[libVES_b64encsize(VESlocker_idsize)];
};

static VESlocker_entry *libVES_KeyStore_importfn(void *arg, const char *vlentry, char *pin) {
    struct libVES_KeyStore_import *im = arg;
    VESlocker_entry *e = VESlocker_entry_parse(vlentry);
    if (!e || !e->entryid || !e->seed || libVES_b64decsize(VESlocker_idsize) > VESlocker_seedsize) return VESlocker_entry_free(e), NULL;
    char entryid[VESlocker_idsize];
    char seed[VESlocker_seedsize];
    int seedoffs = e->entryid - e->data;
    int seedvallen = e->seed - e->entryid + strlen(e->seed) + 1;
    char *pseed = seed;
    int l = libVES_b64decode(e->entryid, &pseed);
    if (l < VESlocker_seedsize) memset(seed + l, 0, VESlocker_seedsize - l);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    unsigned int shalen = VESlocker_idsize;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0
	|| EVP_DigestUpdate(mdctx, seed, VESlocker_seedsize) <= 0
	|| EVP_DigestFinal_ex(mdctx, (unsigned char *)entryid, &shalen) <= 0) return VESlocker_entry_free(e), NULL;
    shalen = VESlocker_chsize;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0
	|| EVP_DigestUpdate(mdctx, pin, strlen(pin)) <= 0
	|| EVP_DigestUpdate(mdctx, seed, VESlocker_seedsize) <= 0
	|| EVP_DigestFinal_ex(mdctx, (unsigned char *)im->ch, &shalen) <= 0) return VESlocker_entry_free(e), NULL;
    EVP_MD_CTX_free(mdctx);
    char *xbuf = malloc(128);
    strcpy(xbuf, "ch=");
    char *d = xbuf + 3;
    d += strlen(libVES_b64encode_web(im->ch, sizeof(im->ch), d));
    strcpy(d, "&id=");
    d += 4;
    d += strlen(strcpy(im->idenc, libVES_b64encode_web(entryid, sizeof(entryid), d)));
    jVar *xrsp = libVES_KeyStore_wwwPost0(im->dlg->ves, im->dlg->api->exportkey, xbuf, d - xbuf, NULL);
    jVar *xpin = jVar_get(xrsp, "xpin");
    if (jVar_getBool(jVar_get(xrsp, "expire"))) {
	im->dlg->state = LIBVES_KSD_EXPIRE;
	xpin = NULL;
	im->dlg->pin = NULL;
    }
    if (xpin && xpin->len <= 255) {
	memcpy(pin, xpin->vString, xpin->len);
	pin[xpin->len] = 0;
    } else xpin = NULL;
    jVar_free(xrsp);
    if (!xpin) return VESlocker_entry_free(e), NULL;
    int diff = libVES_b64encsize(VESlocker_idsize) - seedoffs;
    if (diff > 0) e = realloc(e, sizeof(*e) + seedoffs + seedvallen + diff);
    diff += e->data - e->url;
    e->value = e->seed + diff;
    e->seed = e->entryid + diff;
    e->url = NULL;
    memmove(e->seed, e->data + seedoffs, seedvallen);
    e->entryid = libVES_b64encode_web(entryid, sizeof(entryid), e->data);
    return e;
}

int libVES_KeyStore_dialog_decrypt(struct libVES_KeyStore_dialog *dlg, const char *vlentry, libVES_veskey *veskey, int maxlen, char *newentry, void *arg, VESlocker_entry *(* entryfn)(void *arg, const char *vlentry, char *pin)) {
    char pin[256];
    char decpin[256];
    int rs = 0;
    dlg->pinmax = sizeof(pin);
    dlg->pin = pin;
    while (dlg->state != LIBVES_KSD_DONE) {
	dlg->ks->dialogfn(dlg);
	if (dlg->state != LIBVES_KSD_PIN || !pin[0]) continue;
	VESlocker *vl = VESlocker_new(dlg->api->locker);
	vl->httpInitFn = &libVES_KeyStore_VLhttpInitFn;
	vl->ref = dlg->ves;
	strcpy(decpin, pin);
	VESlocker_entry *e = entryfn(arg, vlentry, decpin);
	int l;
	char *dec = veskey->veskey;
	if (e && e->value && VESlocker_decsize(e) <= maxlen && ((l = VESlocker_decrypt(vl, e, decpin, &dec))) > 0) {
	    veskey->keylen = l;
	    if (newentry) {
		if (VESlocker_encrypt(vl, veskey->veskey, l, pin, newentry) <= 0) *newentry = 0;
	    }
	    dlg->pin = NULL;
	    dlg->state = LIBVES_KSD_CLOSE;
	    rs = 1;
	} else {
	    dlg->retry = vl->retry;
	    switch (vl->error) {
		case VESLOCKER_E_CRYPTO:
		    dlg->retry = 0;
		case VESLOCKER_E_RETRY:
		    dlg->state = LIBVES_KSD_PINRETRY;
		    break;
		default:
		    if (dlg->state == LIBVES_KSD_PIN) dlg->state = LIBVES_KSD_ERROR;
		    break;
	    }
	}
	VESlocker_entry_free(e);
	VESlocker_free(vl);
	OPENSSL_cleanse(pin, sizeof(pin));
	OPENSSL_cleanse(decpin, sizeof(decpin));
    }
    return rs;
}

static int libVES_KeyStore_dialog_urlencode(const char *src, char *dst) {
    static const char hex[16] = "0123456789ABCDEF";
    const char *s = src;
    char *d = dst;;
    char c;
    while ((c = *s++)) {
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-') *d++ = c;
	else {
	    *d++ = '%';
	    *d++ = hex[(c >> 4) & 0x0f];
	    *d++ = hex[c & 0x0f];
	}
    }
    *d = 0;
    return d - dst;
}

int libVES_KeyStore_dialog_import(libVES_KeyStore_dialog *dlg, long long key_id, char *sess, libVES_veskey *veskey, int maxlen, char *newentry) {
    if (!dlg->ks->dialogfn || !dlg->ks->dialogfn(dlg)) return 0;
    libVES_VaultKey *ekey = dlg->ves->genVaultKeyFn(dlg->ves, LIBVES_VK_TEMP, NULL, NULL);
    if (!ekey) return 0;
    char *pub = libVES_VaultKey_getPublicKey(ekey);
    if (!pub) return libVES_VaultKey_free(ekey), 0;
    char *buf = malloc(strlen(pub) * 2 + 64);
    sprintf(buf, "vaultKeyId=%lld&publicKey=", key_id);
    char *d = buf + strlen(buf);
    d += libVES_KeyStore_dialog_urlencode(pub, d);
    jVar *msg = libVES_KeyStore_wwwPost0(dlg->ves, dlg->api->msg, buf, d - buf, NULL);
    char *code = jVar_getString0(jVar_get(msg, "code"));
    jVar_free(msg);
    int rs = 0;
    if ((dlg->syncode = code)) {
	char post[128];
	dlg->ks->dialogfn(dlg);
	sprintf(post, "vaultKeyId=%lld&code=%.64s", key_id, code);
	char *encdata = NULL;
	while (!encdata) {
	    long code;
	    msg = libVES_KeyStore_wwwPost0(dlg->ves, dlg->api->msg, strdup(post), strlen(post), &code);
	    if (!msg && code != 304) break;
	    encdata = jVar_getString0(jVar_get(msg, "encData"));
	    jVar_free(msg);
	}
	char *sync = NULL;
	int l;
	if ((l = libVES_VaultKey_decrypt(ekey, encdata, &sync)) > 0) {
	    sync = realloc(sync, l + 1);
	    sync[l] = 0;
	    struct libVES_KeyStore_import im = {
		.dlg = dlg,
		.sess = sess
	    };
	    if (libVES_KeyStore_dialog_decrypt(dlg, sync, veskey, maxlen, newentry, &im, &libVES_KeyStore_importfn)) {
		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
		unsigned int shalen = 64;
		if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) > 0
		    && EVP_DigestUpdate(mdctx, veskey->veskey, veskey->keylen) > 0
		    && EVP_DigestUpdate(mdctx, im.ch, sizeof(im.ch)) > 0
		    && EVP_DigestFinal_ex(mdctx, (unsigned char *)sess + 16, &shalen) > 0) {
		    libVES_b64encode_web(sess + 16, 33, sess);
		    char buf[256];
		    sprintf(buf, "Cookie: KDsessId=%s", sess);
		    struct curl_slist *hdrs = curl_slist_append(NULL, buf);
		    long code;
		    sprintf(buf, "%.192s%s", dlg->api->importdone, im.idenc);
		    jVar *rsp = libVES_REST_req(dlg->ves, buf, NULL, hdrs, &code);
		    jVar_free(rsp);
		    if (code == 302 || code == 200) rs = 1;
		}
		EVP_MD_CTX_free(mdctx);
	    }
	}
	free(sync);
	free(encdata);
    }
    free(code);
    libVES_VaultKey_free(ekey);
    return rs;
}

#endif

void libVES_KeyStore_dialog_close(struct libVES_KeyStore_dialog *dlg) {
    while (dlg->state != LIBVES_KSD_DONE) dlg->ks->dialogfn(dlg);
}

int libVES_KeyStore_savekey(libVES_KeyStore *ks, const libVES_Ref *ref, size_t keylen, const char *key) {
    if (!ref || !ref->domain || !key) return 0;
#ifdef libVES_KeyStore_default
    if (!ks) ks = libVES_KeyStore_default;
#endif
    if (!ks) return 0;
    return ks->putfn(ks, ref->domain, ref->externalId, key, keylen, LIBVES_KS_SAVE | LIBVES_KS_NOPIN) >= 0 ? 1 : 0;
}

libVES *libVES_KeyStore_unlock(libVES_KeyStore *ks, libVES *ves, int flags) {
    if (!ves) return NULL;
#ifdef libVES_KeyStore_default
    if (!ks) ks = libVES_KeyStore_default;
#endif
    if (!ks) return NULL;
    if (!(flags & (LIBVES_KS_RESYNC | LIBVES_KS_PRIMARY))) {
	if ((flags & LIBVES_KS_SESS) ? !!libVES_getSessionToken(ves) : libVES_getVaultKey(ves) && libVES_unlocked(ves)) return ves;
	else libVES_getError(ves);
    }
    libVES_lock(ves);
    struct {
	union {
	    libVES_veskey veskey;
	    char _ms_vs_c2229;
	};
	char buf[256];
	char entry[768];
	char sess[256];
    } buf;
    libVES_Ref *ext = ves->external;
    libVES_User *me = libVES_me(ves);
    if (!me) {
	if (!ext) return NULL;
	const char *email = ext->externalId;
	const char *at = strchr(email, '@');
	const char *end = strchr(email, '!');
	if (at && (!end || at < end)) {
	    char *tmp = NULL;
	    if (end) {
		int l = end - email;
		memcpy((tmp = malloc(l + 1)), email, l);
		tmp[l] = 0;
		email = tmp;
	    }
	    me = libVES_User_fromPath(&email);
	    free(tmp);
	    libVES_setUser(ves, me);
	}
    }
    libVES_KeyStore_dialog dlg = {
	.len = sizeof(libVES_KeyStore_dialog),
	.state = LIBVES_KSD_INIT,
	.ks = ks,
	.ves = ves,
	.api = (ks->api ? ks->api : &libVES_KeyStore_api_default),
	.ref = NULL,
	.domain = (ext ? ext->domain : NULL),
	.extid = (ext ? ext->externalId : NULL),
	.email = libVES_User_getEmail(me),
	.pin = NULL,
	.flags = flags
    };
    if (!ext && !dlg.email) return NULL;
    if (flags & LIBVES_KS_FORGET) {
	if (dlg.domain) {
	    ks->deletefn(ks, dlg.domain, dlg.extid, flags);
	    if (!(flags & LIBVES_KS_NOPIN)) ks->deletefn(ks, dlg.domain, dlg.extid, flags | LIBVES_KS_NOPIN);
	}
	if (!(flags & LIBVES_KS_SESS) && dlg.email) {
	    ks->deletefn(ks, NULL, dlg.email, flags);
	    if (!(flags & LIBVES_KS_NOPIN)) {
		ks->deletefn(ks, NULL, dlg.email, flags | LIBVES_KS_NOPIN);
		ks->deletefn(ks, NULL, dlg.email, flags | LIBVES_KS_SESS);
	    }
	}
	return ves;
    }
    int l;
    if (dlg.domain) {
	if ((flags & (LIBVES_KS_SESS | LIBVES_KS_RESYNC | LIBVES_KS_PRIMARY)) == LIBVES_KS_SESS) {
	    l = ks->getfn(ks, dlg.domain, dlg.extid, buf.sess, sizeof(buf.sess) - 1, flags | LIBVES_KS_NOPIN);
	    if (l > 0) {
		buf.sess[l] = 0;
		return libVES_setSessionToken(ves, buf.sess), OPENSSL_cleanse(&buf, sizeof(buf)), ves;
	    }
	}
	if ((~flags & (LIBVES_KS_SESS | LIBVES_KS_SAVE)) && !(flags & (LIBVES_KS_RESYNC | LIBVES_KS_PRIMARY))) {
	    l = ks->getfn(ks, dlg.domain, dlg.extid, buf.veskey.veskey, sizeof(buf.buf), (flags & ~LIBVES_KS_SESS) | LIBVES_KS_NOPIN);
	    if (l > 0) {
		buf.veskey.keylen = l;
		void *un = libVES_unlock(ves, buf.veskey.keylen, buf.veskey.veskey);
		OPENSSL_cleanse(&buf, sizeof(buf));
		if (un) return ves;
	    }
	}
    }
    buf.veskey.keylen = 0;
    if (!(flags & (LIBVES_KS_RESYNC)) && dlg.email && ((l = ks->getfn(ks, NULL, dlg.email, buf.sess, sizeof(buf.sess) - 1, flags | (LIBVES_KS_SESS | LIBVES_KS_NOPIN)))) > 0) {
	buf.sess[l] = 0;
	l = ks->getfn(ks, NULL, dlg.email, buf.veskey.veskey, sizeof(buf.buf), (flags & ~LIBVES_KS_SESS) | LIBVES_KS_NOPIN);
	if (l > 0) {
	    buf.veskey.keylen = l;
	} else if (!(flags & LIBVES_KS_NOPIN)) {
	    int l = ks->getfn(ks, NULL, dlg.email, buf.entry, sizeof(buf.entry) - 1, (flags & ~LIBVES_KS_SESS & ~LIBVES_KS_NOPIN));
	    if (l > 0) {
		buf.entry[l] = 0;
		if (!libVES_KeyStore_dialog_decrypt(&dlg, buf.entry, &buf.veskey, sizeof(buf.buf), buf.entry, NULL, &libVES_KeyStore_entryfn)) {
		    libVES_setError(dlg.ves, LIBVES_E_DIALOG, "KeyStore PIN dialog failed");
		    return NULL;
		}
	    }
	}
    }
    libVES_VaultKey *cur;
    char impd = 0;
    if (!me || !(cur = libVES_User_primary(me, NULL, NULL, ves))) {
	if (me) {
	    dlg.state = LIBVES_KSD_NOUSER;
	    libVES_KeyStore_dialog_close(&dlg);
	}
    } else if (!buf.veskey.keylen && !(flags & LIBVES_KS_NOSYNC)) {
	impd = !!libVES_KeyStore_dialog_import(&dlg, cur->id, buf.sess, &buf.veskey, sizeof(buf.buf), (flags & LIBVES_KS_NOPIN) ? NULL : buf.entry);
	if (!impd) {
	    libVES_setError(dlg.ves, LIBVES_E_DIALOG, "KeyStore Import dialog failed");
	    buf.veskey.keylen = 0;
	}
	if (flags & LIBVES_KS_NOPIN) buf.entry[0] = impd = 0;
    }
    void *rs = NULL;
    if (buf.veskey.keylen) {
	char *sess = libVES_getSessionToken(ves);
	if (sess) sess = strdup(sess);
	libVES_setSessionToken(ves, buf.sess);
	if (libVES_VaultKey_unlock(cur, &buf.veskey)) {
	    rs = ves;
	    char fdom = dlg.extid && !dlg.extid[0];
	    if (buf.entry[0]) ks->putfn(ks, NULL, dlg.email, buf.entry, strlen(buf.entry), (flags & ~LIBVES_KS_SESS & ~LIBVES_KS_NOPIN));
	    if (impd) ks->putfn(ks, NULL, dlg.email, buf.sess, strlen(buf.sess), (flags | LIBVES_KS_SESS) & ~LIBVES_KS_NOPIN);
	    if (ves->external && (fdom || libVES_unlock(ves, 0, NULL)) && !(flags & LIBVES_KS_PRIMARY)) {
		if (!sess && (flags & LIBVES_KS_SESS) && ((flags & (LIBVES_KS_SAVE | LIBVES_KS_PERSIST)) || fdom)) {
		    char uri[80];
		    const char *fld = (flags & (LIBVES_KS_SAVE | LIBVES_KS_PERSIST)) ? "encPersistentSessionToken" : "encSessionToken";
		    if (fdom) sprintf(uri, "domains/%.48s?fields=%s", dlg.domain, fld);
		    else sprintf(uri, "vaultKeys/%lld?fields=%s", ves->vaultKey->id, fld);
		    jVar *rsp = libVES_REST(ves, uri, NULL);
		    const char *esess = jVar_getStringP(jVar_get(rsp, fld));
		    if (esess && ((l = libVES_VaultKey_decrypt(cur, esess, &sess))) > 0) sess = realloc(sess, l + 1), sess[l] = 0;
		    jVar_free(rsp);
		    if (sess) {
			if (dlg.domain && (flags & LIBVES_KS_SAVE)) ks->putfn(ks, dlg.domain, dlg.extid, sess, strlen(sess), (flags | LIBVES_KS_SESS | LIBVES_KS_NOPIN));
			libVES_setSessionToken(ves, sess);
		    }
		}
		if (!sess) {
		    char *esess = NULL;
		    libVES_setSessionToken(ves, NULL);
		    libVES_VaultKey_free(libVES_VaultKey_get2(ves->external, ves, NULL, &esess, LIBVES_O_GET));
		    if (esess && ((l = libVES_VaultKey_decrypt(ves->vaultKey, esess, &sess))) > 0) sess = realloc(sess, l + 1), sess[l] = 0;
		    free(esess);
		    if (sess) libVES_setSessionToken(ves, sess);
		}
		if (dlg.domain && (flags & (LIBVES_KS_SAVE | LIBVES_KS_SESS)) == LIBVES_KS_SAVE) {
		    libVES_veskey *vk = libVES_VaultKey_getVESkey(ves->vaultKey);
		    if (vk) ks->putfn(ks, dlg.domain, dlg.extid, vk->veskey, vk->keylen, (flags & ~LIBVES_KS_SESS) | LIBVES_KS_NOPIN);
		    libVES_veskey_free(vk);
		}
	    }
	    if (!(flags & LIBVES_KS_PRIMARY)) libVES_VaultKey_lock(cur);
	}
	free(sess);
    }
    if (!rs && !ves->error) libVES_setError(ves, LIBVES_E_INCORRECT, "Key not found in the Key Store");
    return rs;
}

