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
 * libVES/VaultKey.c          libVES: Vault Key object
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include "../jVar.h"
#include "../libVES.h"
#include "VaultKey.h"
#include "Cipher.h"
#include "CiAlgo_AES.h"
#include "Util.h"
#include "List.h"
#include "Ref.h"
#include "User.h"
#include "VaultItem.h"
#include "REST.h"
#include "KeyAlgo_EVP.h"
#include "KeyAlgo_OQS.h"

const char *libVES_VaultKey_types[9] = {"current", "shadow", "temp", "lost", "secondary", "recovery", "pending", "deleted", NULL};
#ifdef HAVE_LIBOQS
libVES_List_STATIC(libVES_VaultKey_algos, &libVES_algoListCtl, 3, &libVES_KeyAlgo_RSA, &libVES_KeyAlgo_ECDH, &libVES_KeyAlgo_OQS);
#else
libVES_List_STATIC(libVES_VaultKey_algos, &libVES_algoListCtl, 2, &libVES_KeyAlgo_RSA, &libVES_KeyAlgo_ECDH);
#endif

libVES_VaultKey *libVES_VaultKey_new(int type, const libVES_KeyAlgo *algo, void *pkey, libVES_veskey *veskey, libVES *ves) {
    if (!ves) return NULL;
    if (!algo || !algo->newfn) libVES_throw(ves, LIBVES_E_PARAM, "Invalid key algo", NULL);
    libVES_veskey *vknew = veskey ? NULL : (veskey = libVES_veskey_generate(ves->veskeyLen));
    if (!veskey) return NULL;
    char *vkcpy = malloc(veskey->keylen);
    libVES_VaultKey *vkey = vkcpy ? algo->newfn(algo, pkey, veskey, ves) : NULL;
    if (!vkey) {
	libVES_veskey_free(vknew);
	free(vkcpy);
	return NULL;
    }
    memcpy(vkcpy, veskey->veskey, veskey->keylen);
    vkey->id = 0;
    vkey->type = type;
    vkey->ves = ves;
    vkey->user = NULL;
    vkey->external = NULL;
    vkey->vitem = libVES_VaultItem_new();
    vkey->vitem->type = LIBVES_VI_PASSWORD;
    vkey->vitem->value = vkcpy;
    vkey->vitem->len = veskey->keylen;
    (void)libVES_REFUP(VaultItem, vkey->vitem);
    vkey->entries = NULL;
    vkey->appUrl = NULL;
    if (!vkey->algo || !vkey->pPriv) {
	libVES_setError(ves, LIBVES_E_PARAM, "Key algo and pPriv must be set by newfn");
	libVES_VaultKey_free(vkey);
	vkey = NULL;
    } else {
	if (!vkey->pPub && vkey->algo->priv2pubfn) vkey->pPub = vkey->algo->priv2pubfn(vkey, vkey->pPriv);
	if (vkey->algo->pub2strfn) vkey->publicKey = vkey->algo->pub2strfn(vkey, vkey->pPub ? vkey->pPub : vkey->pPriv);
	if (vkey->algo->priv2strfn) vkey->privateKey = vkey->algo->priv2strfn(vkey, vkey->pPriv, veskey);
    }
    libVES_veskey_free(vknew);
    return libVES_REFINIT(vkey);
}

libVES_VaultKey *libVES_VaultKey_fromJVar(jVar *j_vkey, libVES *ves) {
    if (!j_vkey) return NULL;
    libVES_VaultKey *vkey = malloc(sizeof(libVES_VaultKey));
    if (!vkey) return NULL;
    vkey->id = jVar_getInt(jVar_get(j_vkey, "id"));
    vkey->type = jVar_getEnum(jVar_get(j_vkey, "type"), libVES_VaultKey_types);
    vkey->algo = libVES_VaultKey_algoFromStr(jVar_getStringP(jVar_get(j_vkey, "algo")));
    vkey->ves = ves;
    vkey->publicKey = jVar_getString0(jVar_get(j_vkey, "publicKey"));
    vkey->privateKey = jVar_getString0(jVar_get(j_vkey, "privateKey"));
    vkey->user = libVES_User_fromJVar(jVar_get(j_vkey, "user"));
    (void)libVES_REFUP(User, vkey->user);
    vkey->external = libVES_External_fromJVar(jVar_get(j_vkey, "externals"));
    (void)libVES_REFUP(Ref, vkey->external);
    vkey->vitem = libVES_VaultItem_fromJVar(jVar_index(jVar_get(j_vkey, "items"), 0), ves);
    (void)libVES_REFUP(VaultItem, vkey->vitem);
    vkey->pPriv = vkey->pPub = NULL;
    vkey->entries = NULL;
    vkey->appUrl = NULL;
    return libVES_REFINIT(vkey);
}

libVES_List *libVES_VaultKey_listFromURI(const char **path, struct libVES *ves, struct libVES_List *lst) {
    const char *p = *path;
    libVES_Ref *ref = libVES_Ref_fromURI(&p, ves);
    libVES_List *res;
    if (*p == '/') {
	p++;
	libVES_User *user = libVES_User_fromPath(&p);
	libVES_VaultKey *vkey;
	if (ref) {
	    vkey = libVES_VaultKey_get(ref, ves, user);
	    if (!vkey) {
		res = NULL;
	    }
	} else {
	    res = libVES_User_activeVaultKeys(user, lst, ves);
	    if (!res && libVES_checkError(ves, LIBVES_E_NOTFOUND)) {
		vkey = libVES_VaultKey_create(ref, ves, user);
	    } else {
		vkey = NULL;
	    }
	}
	if (vkey) {
	    if (!lst) lst = libVES_List_new(&libVES_VaultKey_ListCtl);
	    libVES_List_push(lst, vkey);
	    res = lst;
	}
	libVES_User_free(user);
    } else {
	libVES_setError(ves, LIBVES_E_PARAM, "Vault URI expected (missing a trailing '/'?)");
	res = NULL;
    }
    if (res) *path = p;
    libVES_Ref_free(ref);
    return res;
}

jVar *libVES_VaultKey_toJVar(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    jVar *res = jVar_object();
    if (vkey->id) jVar_put(res, "id", jVar_int(vkey->id));
    else {
	jVar_put(res, "type", jVar_string(libVES_VaultKey_typeStr(vkey->type)));
	jVar_put(res, "algo", jVar_string(libVES_VaultKey_algoStr(vkey->algo)));
	jVar_put(res, "publicKey", jVar_string(vkey->publicKey));
	jVar_put(res, "privateKey", jVar_string(vkey->privateKey));
	if (vkey->user) jVar_put(res, "user", libVES_User_toJVar(vkey->user));
	if (vkey->vitem && vkey->vitem->entries) jVar_put(res, "vaultItems", jVar_push(jVar_array(), libVES_VaultItem_toJVar(vkey->vitem)));
	if (vkey->type == LIBVES_VK_TEMP) {
	    jVar_put(res, "creator", libVES_User_toJVar(libVES_VaultKey_getUser(vkey->ves->vaultKey)));
	    if (vkey->appUrl) jVar_put(res, "appUrl", jVar_string(vkey->appUrl));
	}
	if (vkey->external) libVES_Ref_toJVar(vkey->external, res);
    }
    if (vkey->entries) {
	jVar_put(res, "vaultEntries", vkey->entries);
	vkey->entries = NULL;
    }
    return res;
}

char *libVES_VaultKey_toURI(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    return vkey->external ? libVES_buildURI(3, vkey->external->domain, vkey->external->externalId, NULL) : (vkey->user && vkey->user->email ? libVES_buildURI(3, NULL, NULL, vkey->user->email) : NULL);
}

char *libVES_VaultKey_toURIi(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    char buf[48];
    sprintf(buf, "ves:///%lld/", vkey->id);
    return strdup(buf);
}

int libVES_VaultKey_setAppUrl(libVES_VaultKey *vkey, const char *url) {
    if (!vkey) return 0;
    free(vkey->appUrl);
    vkey->appUrl = url ? strdup(url) : NULL;
    return 1;
}

libVES_VaultKey *libVES_VaultKey_get2(libVES_Ref *ref, libVES *ves, libVES_User *user, char **sesstkn, int flags) {
    if (!ves) return NULL;
    if (!ref) libVES_throw(ves, LIBVES_E_PARAM, user ? "Primary vault URI cannot be used here" : "Vault key reference is missing", NULL);
    libVES_VaultKey *vkey;
    if (flags & LIBVES_O_GET) {
	jVar *vkey_req = jVar_object();
	libVES_Ref_toJVar(ref, vkey_req);
	if (ves->vaultKey) {
	    libVES_User *u = libVES_VaultKey_getUser(ves->vaultKey);
	    if (u) jVar_put(vkey_req, "creator", libVES_User_toJVar(u));
	}
	if (user) jVar_put(vkey_req, "user", jVar_put(libVES_User_toJVar(user), "$op", jVar_string("fetch")));
	jVar_put(vkey_req, "$op", jVar_string("fetch"));
	jVar *vkey_res = libVES_REST(ves, (sesstkn ? "vaultKeys?fields=id,algo,type,publicKey,privateKey,user(id,email,firstName,lastName),encSessionToken" : "vaultKeys?fields=id,type,algo,publicKey,externals"), vkey_req);
	jVar_free(vkey_req);
	if (vkey_res) {
	    vkey = libVES_VaultKey_fromJVar(vkey_res, ves);
	    if (sesstkn) *sesstkn = jVar_getString(jVar_get(vkey_res, "encSessionToken"));
	    if (!vkey->external && ref->domain) vkey->external = libVES_REFUP(Ref, ref);
	    if (!vkey->user) vkey->user = libVES_REFUP(User, user);
	} else {
	    if (!(flags & LIBVES_O_NEW) || !user || sesstkn) return NULL;
	    if (!libVES_checkError(ves, LIBVES_E_NOTFOUND)) return NULL;
	    vkey = libVES_VaultKey_create(ref, ves, user);
	}
	jVar_free(vkey_res);
    } else if (flags & LIBVES_O_NEW) {
	if (!user || sesstkn) libVES_throw(ves, LIBVES_E_PARAM, "Inconsistent arguments for a new vault key", NULL);
	vkey = libVES_VaultKey_create(ref, ves, user);
    } else libVES_throw(ves, LIBVES_E_PARAM, "No action requested", NULL);
    return vkey;
}

libVES_VaultKey *libVES_VaultKey_free_ref_user(libVES_VaultKey *vkey, libVES_Ref *ref, libVES_User *user) {
    libVES_Ref_free(ref);
    libVES_User_free(user);
    return vkey;
}

libVES_VaultKey *libVES_VaultKey_create(libVES_Ref *ref, libVES *ves, libVES_User *user) {
    if (!ves) return NULL;
    int type;
    if (ves->external) type = (ref && (ref->domain && ref->domain == ves->external->domain && !strcmp(ref->externalId, ves->external->externalId))) ? LIBVES_VK_SECONDARY : LIBVES_VK_TEMP;
    else {
	if (!user) libVES_throw(ves, LIBVES_E_PARAM, "Cannot generate a vault key for an unspecified user", NULL);
	libVES_User *me = libVES_me(ves);
	if (me && me->id == user->id) type = ref ? LIBVES_VK_SECONDARY : LIBVES_VK_CURRENT;
	else type = LIBVES_VK_TEMP;
    }
    libVES_VaultKey *vkey = ves->genVaultKeyFn(ves, type, ref, user);
    if (!vkey) return NULL;
    vkey->user = libVES_REFUP(User, user);
    vkey->external = libVES_REFUP(Ref, ref);
    if (user && !libVES_VaultKey_propagate(vkey)) {
	(void)libVES_REFRM(vkey->user);
	(void)libVES_REFRM(vkey->external);
	libVES_VaultKey_free(vkey);
	vkey = NULL;
    }
    return libVES_REFINIT(vkey);
}

libVES_VaultKey *libVES_VaultKey_createFrom(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (libVES_VaultKey_isNew(vkey)) libVES_throw(vkey->ves, LIBVES_E_PARAM, "The key is already pending update", NULL);
    libVES_Ref *ref = libVES_VaultKey_getExternal(vkey);
    libVES_User *user = libVES_VaultKey_getUser(vkey);
    libVES_VaultKey *res = libVES_VaultKey_create(ref, vkey->ves, user);
    return res;
}

libVES_VaultItem *libVES_VaultKey_propagate(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (!vkey->user) libVES_throw(vkey->ves, LIBVES_E_PARAM, "Cannot propagate a vault key to an unspecified user", NULL);
    if (!vkey->vitem) {
	free(vkey->privateKey);
	vkey->privateKey = NULL;
	if (!libVES_VaultKey_getPrivateKey(vkey)) libVES_getError(vkey->ves);
    }
    if (!vkey->vitem) libVES_throw(vkey->ves, LIBVES_E_PARAM, "Cannot propagate a vault key without a password VaultItem", NULL);
    libVES_List *share = libVES_List_new(&libVES_VaultKey_ListCtl);
    if (vkey->type == LIBVES_VK_TEMP) libVES_List_push(share, vkey->ves->vaultKey);
    char ok = libVES_User_activeVaultKeys(vkey->user, share, vkey->ves) || libVES_checkError(vkey->ves, LIBVES_E_NOTFOUND) ? 1 : 0;
    libVES_VaultKey *u_vkey = vkey->ves->vaultKey;
    if (ok && u_vkey && vkey->user->id != u_vkey->user->id) ok = libVES_User_activeVaultKeys(u_vkey->user, share, vkey->ves) ? 1 : 0;
    if (ok && vkey->id && vkey->external && vkey->type == LIBVES_VK_TEMP) {
	jVar *req = jVar_put(jVar_put(jVar_object(), "type", jVar_string(libVES_VaultKey_types[LIBVES_VK_SECONDARY])), "$op", jVar_string("fetch"));
	libVES_Ref_toJVar(vkey->external, req);
	jVar *rsp = libVES_REST(vkey->ves, "vaultKeys?fields=id,type,algo,publicKey", req);
	jVar_free(req);
	if (rsp) {
	    if (!libVES_List_push(share, libVES_VaultKey_fromJVar(rsp, vkey->ves))) ok = 0;
	    jVar_free(rsp);
	} else if (!libVES_checkError(vkey->ves, LIBVES_E_NOTFOUND)) ok = 0;
    }
    if (ok && !libVES_VaultItem_entries(vkey->vitem, share, LIBVES_SH_ADD)) ok = 0;
    libVES_List_free(share);
    return ok ? vkey->vitem : NULL;
}

void libVES_VaultKey_parseJVar(libVES_VaultKey *vkey, jVar *jvar) {
    jVar *jv = jVar_get(jvar, "privateKey");
    int i;
    if (jv) {
	free(vkey->privateKey);
	vkey->privateKey = jVar_getString0(jv);
    }
    jv = jVar_get(jvar, "algo");
    if (jv) vkey->algo = libVES_VaultKey_algoFromStr(jVar_getStringP(jv));
    jv = jVar_get(jvar, "vaultItems");
    if (jv && !vkey->vitem) {
	for (i = 0; i < jVar_count(jv); i++) {
	    libVES_VaultItem *vitem = libVES_VaultItem_fromJVar(jVar_index(jv, i), vkey->ves);
	    if (vitem && vitem->type == LIBVES_VI_PASSWORD) {
		libVES_REFDN(VaultItem, vkey->vitem);
		vkey->vitem = libVES_REFUP(VaultItem, vitem);
		break;
	    }
	    libVES_VaultItem_free(vitem);
	}
    }
    if (!vkey->user) vkey->user = libVES_User_fromJVar(jVar_get(jvar, "user"));
}

char *libVES_VaultKey_getPrivateKey(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (!vkey->privateKey) {
	if (!vkey->id) return NULL;
	char uri[160];
	sprintf(uri, "vaultKeys/%lld?fields=privateKey,vaultItems(id,type,vaultEntries(vaultKey(id),encData)),user(id,email,firstName,lastName)", vkey->id);
	jVar *rsp = libVES_REST(vkey->ves, uri, NULL);
	if (!rsp) return NULL;
	libVES_VaultKey_parseJVar(vkey, rsp);
	jVar_free(rsp);
	if (!vkey->privateKey) libVES_throw(vkey->ves, LIBVES_E_DENIED, "Cannot load encrypted private key", NULL);
    }
    return vkey->privateKey;
}

libVES_User *libVES_VaultKey_getUser(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (!vkey->user && !vkey->privateKey) {
	if (!vkey->id) return NULL;
	char uri[160];
	sprintf(uri, "vaultKeys/%lld?fields=user(id,email,firstName,lastName)", vkey->id);
	jVar *rsp = libVES_REST(vkey->ves, uri, NULL);
	if (!rsp) return NULL;
	vkey->user = libVES_User_fromJVar(jVar_get(rsp, "user"));
	(void)libVES_REFUP(User, vkey->user);
	jVar_free(rsp);
	if (!vkey->user) libVES_throw(vkey->ves, LIBVES_E_DENIED, "Cannot load vault key user info", NULL);
    }
    libVES_User_loadFields(vkey->user, vkey->ves);
    return vkey->user;
}

void *libVES_VaultKey_unlock(libVES_VaultKey *vkey, const libVES_veskey *veskey) {
    if (!vkey) return NULL;
    if (!vkey->pPriv) {
	libVES_veskey *vk = NULL;
	if (!libVES_VaultKey_getPrivateKey(vkey)) return NULL;
	if (!vkey->algo || !vkey->algo->str2privfn) libVES_throw(vkey->ves, LIBVES_E_UNSUPPORTED, "Key algo cannot unlock the private key", NULL);
	if (!veskey && !(veskey = vk = libVES_VaultKey_getVESkey(vkey))) libVES_throw(vkey->ves, LIBVES_E_PARAM, "VESkey is needed to unlock the private key", NULL);
	vkey->pPriv = vkey->algo->str2privfn(vkey, vkey->privateKey, veskey);
	libVES_veskey_free(vk);
	if (vkey->pPriv) libVES_addUnlocked(vkey->ves, vkey);
    }
    return vkey->pPriv;
}

void libVES_VaultKey_lock(libVES_VaultKey *vkey) {
    if (!vkey) return;
    (void)libVES_REFDN(VaultItem, vkey->vitem);
    vkey->vitem = NULL;
    if (vkey->pPriv) libVES_removeUnlocked(vkey->ves, vkey);
    if (vkey->algo && vkey->algo->lockfn) vkey->algo->lockfn(vkey);
}

libVES_veskey *libVES_VaultKey_getVESkey(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (!vkey->vitem) {
	free(vkey->privateKey);
	vkey->privateKey = NULL;
	if (!libVES_VaultKey_getPrivateKey(vkey) || !vkey->vitem) return NULL;
    }
    if (!vkey->vitem->value || vkey->vitem->type != LIBVES_VI_PASSWORD) return NULL;
    return libVES_veskey_new(vkey->vitem->len, vkey->vitem->value);
}

char *libVES_VaultKey_getPrivateKey1(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (vkey->pPriv && vkey->algo && vkey->algo->priv2strfn) return vkey->algo->priv2strfn(vkey, vkey->pPriv, NULL);
    char *res = libVES_VaultKey_getPrivateKey(vkey);
    return res ? strdup(res) : NULL;
}

void *libVES_VaultKey_getPub(libVES_VaultKey *vkey) {
    if (!vkey->pPub) {
	if (vkey->pPriv && vkey->algo) {
	    if (vkey->algo->priv2pubfn) vkey->pPub = vkey->algo->priv2pubfn(vkey, vkey->pPriv);
	    else vkey->pPub = vkey->pPriv;
	}
	if (!vkey->pPub) {
	    if (!vkey->publicKey) {
		char buf[160];
		sprintf(buf, "vaultKeys/%lld?fields=algo,publicKey", vkey->id);
		jVar *rsp = libVES_REST(vkey->ves, buf, NULL);
		vkey->publicKey = jVar_getString0(jVar_get(rsp, "publicKey"));
		if (!vkey->algo) vkey->algo = libVES_VaultKey_algoFromStr(jVar_getStringP(jVar_get(rsp, "algo")));
		jVar_free(rsp);
	    }
	    if (vkey->publicKey) {
		if (vkey->algo && vkey->algo->str2pubfn) vkey->pPub = vkey->algo->str2pubfn(vkey, vkey->publicKey);
		else libVES_throw(vkey->ves, LIBVES_E_UNSUPPORTED, "Key algo cannot read the public key", NULL);
	    }
	}
    }
    return vkey->pPub;
}

int libVES_VaultKey_decrypt(libVES_VaultKey *vkey, const char *ciphertext, char **plaintext) {
    if (!vkey) return -1;
    if (!ciphertext) libVES_throw(vkey->ves, LIBVES_E_PARAM, "No ciphertext to decrypt", -1);
    if (!libVES_VaultKey_unlock(vkey, NULL)) libVES_throw(vkey->ves, LIBVES_E_UNLOCK, "Decrypt is called on a locked Vault Key", -1);
    if (!vkey->algo || !vkey->algo->decfn) libVES_throw(vkey->ves, LIBVES_E_UNSUPPORTED, "Key algo doesn't support decryption", -1);
    char cikey[libVES_Cipher_KEYLENforVEntry];
    size_t keylen = libVES_Cipher_KEYLENforVEntry;
    char *ctext = NULL;
    size_t ctlen;
    if (plaintext) {
	ctlen = libVES_b64decode(ciphertext, &ctext);
	if (!ctext) libVES_throw(vkey->ves, LIBVES_E_CRYPTO, "Base64 decoding failed - Invalid ciphertext?", -1);
    } else ctlen = libVES_b64decsize(strlen(ciphertext));
    size_t cl = ctlen;
    int pl = 1;
    size_t ptlen;
    if (!plaintext || !*plaintext) {
	pl = vkey->algo->decfn(vkey, ctext, &cl, NULL, cikey, &keylen);
	if (pl >= 0) {
	    ptlen = pl;
	    if (cl < ctlen) ptlen += ctlen - cl;
	    if (!plaintext) return ptlen;
	    libVES_assert(vkey->ves, (*plaintext = malloc(ptlen)), -1);
	}
    }
    if (pl > 0) {
	cl = ctlen;
	pl = vkey->algo->decfn(vkey, ctext, &cl, *plaintext, cikey, &keylen);
    }
    if (pl >= 0 && ctlen > cl) {
	libVES_Cipher *ci = libVES_Cipher_forVEntry(keylen, cikey, vkey->ves);
	char *ptptr = *plaintext + pl;
	int l = libVES_Cipher_decrypt(ci, 1, ctext + cl, ctlen - cl, &ptptr);
	libVES_Cipher_free(ci);
	if (l >= 0) pl += l;
	else pl = -1;
    }
    free(ctext);
    OPENSSL_cleanse(cikey, sizeof(cikey));
    return pl;
}

char *libVES_VaultKey_encrypt(libVES_VaultKey *vkey, const char *plaintext, size_t ptlen) {
    if (!vkey || !libVES_VaultKey_getPub(vkey)) return NULL;
    if (!plaintext) libVES_throw(vkey->ves, LIBVES_E_PARAM, "No plaintext to encrypt", NULL);
    if (!vkey->algo || !vkey->algo->encfn) libVES_throw(vkey->ves, LIBVES_E_UNSUPPORTED, "Key algo doesn't support encryption", NULL);
    size_t pl = ptlen;
    char cikey[libVES_Cipher_KEYLENforVEntry];
    size_t keylen = libVES_Cipher_KEYLENforVEntry;
    int cl = vkey->algo->encfn(vkey, plaintext, &pl, NULL, cikey, &keylen);
    if (cl < 0) return NULL;
    size_t ctlen = cl;
    if (ptlen > pl) ctlen += ptlen - pl + libVES_Cipher_PADLENforVEntry;
    size_t buflen = libVES_b64encsize(ctlen) + 1;
    char *ctbuf = malloc(buflen);
    libVES_assert(vkey->ves, ctbuf, NULL);
    char *ctext = ctbuf + buflen - ctlen;
    pl = ptlen;
    cl = vkey->algo->encfn(vkey, plaintext, &pl, ctext, cikey, &keylen);
    if (cl >= 0 && ptlen > pl) {
	libVES_Cipher *ci = libVES_Cipher_forVEntry(keylen, cikey, vkey->ves);
	char *ctptr = ctext + cl;
	int l = libVES_Cipher_encrypt(ci, 1, plaintext + pl, ptlen - pl, &ctptr);
	libVES_Cipher_free(ci);
	if (l >= 0) cl += l;
	else cl = -1;
    }
    OPENSSL_cleanse(cikey, sizeof(cikey));
    if (cl >= 0) return libVES_b64encode(ctext, cl, ctbuf);
    free(ctbuf);
    return NULL;
}

jVar *libVES_VaultKey_rekeyFrom(libVES_VaultKey *vkey, libVES_VaultKey *from, int flags) {
    if (!vkey || !from) return NULL;
    char uri[160];
    sprintf(uri, "vaultKeys/%lld?fields=vaultEntries(encData,vaultItem(id))", from->id);
    jVar *rsp = libVES_REST(vkey->ves, uri, NULL);
    if (!rsp) return NULL;
    jVar *jvents = jVar_get(rsp, "vaultEntries");
    size_t len = jVar_count(jvents);
    if (len && !libVES_VaultKey_unlock(from, NULL)) libVES_throw(vkey->ves, LIBVES_E_UNLOCK, "Cannot rekey from a locked vault key", NULL);
    jVar *entries = vkey->entries;
    if (!jVar_isArray(entries)) entries = jVar_array();
    int i;
    int ptlen = 0;
    for (i = 0; i < len; i++) {
	jVar *jvent = jVar_detach(jVar_index(jvents, i));
	jVar_put(jvent, "id", NULL);
	jVar *jenc = jVar_get(jvent, "encData");
	char *enc = jVar_getString0(jenc);
	char *ptext = NULL;
	ptlen = libVES_VaultKey_decrypt(from, enc, &ptext);
	free(enc);
	if (ptlen >= 0) {
	    enc = libVES_VaultKey_encrypt(vkey, ptext, ptlen);
	    if (enc) jVar_setString0(jenc, enc);
	    else ptlen = -1;
	} else if ((flags & LIBVES_SH_IGN) && libVES_checkError(vkey->ves, LIBVES_E_CRYPTO)) {
	    jVar_put(jvent, "encData", NULL);
	    jVar_put(jvent, "$op", jVar_string("ignore"));
	    ptlen = 0;
	}
	jVar_push(entries, jvent);
	free(ptext);
	if (ptlen < 0) break;
    }
    if (ptlen < 0) {
	jVar_free(entries);
	entries = NULL;
    }
    jVar_free(rsp);
    if (vkey->entries != entries) jVar_free(vkey->entries);
    return vkey->entries = entries;
}

int libVES_VaultKey_rekey(libVES_VaultKey *vkey) {
    if (!vkey) return 0;
    if (vkey->external) {
	libVES_VaultKey *activekey = libVES_VaultKey_get(vkey->external, vkey->ves, NULL);
	if (!activekey) return 0;
	int ok = vkey->id == activekey->id || (libVES_VaultKey_rekeyFrom(activekey, vkey, 0) && libVES_VaultKey_post(activekey));
	libVES_VaultKey_free(activekey);
	return ok;
    } else {
	libVES_List *activekeys = libVES_User_activeVaultKeys(vkey->user, NULL, vkey->ves);
	jVar *req = NULL;
	int ok;
	if (activekeys) {
	    jVar *jvkeys = jVar_array();
	    req = jVar_put(jVar_put(jVar_object(), "vaultKeys", jvkeys), "id", jVar_int(vkey->user->id));
	    int i;
	    ok = 1;
	    for (i = 0; i < activekeys->len; i++) {
		libVES_VaultKey *vk = activekeys->list[i];
		if (libVES_VaultKey_rekeyFrom(vk, vkey, 0)) jVar_push(jvkeys, libVES_VaultKey_toJVar(vk));
		else {
		    ok = 0;
		    break;
		}
	    }
	    if (ok) {
		jVar *rsp = libVES_REST(vkey->ves, "users", req);
		if (rsp) jVar_free(rsp);
		else ok = 0;
	    }
	} else ok = 0;
	jVar_free(req);
	libVES_List_free(activekeys);
	return ok;
    }
}

int libVES_VaultKey_apply(libVES_VaultKey *vkey) {
    if (!vkey) return 0;
    libVES_VaultKey_rekey(vkey);
    if (libVES_getVaultKey(vkey->ves) || !vkey->pPriv) return 0;
    vkey->ves->vaultKey = vkey;
    return 1;
}


int libVES_VaultKey_post(libVES_VaultKey *vkey) {
    if (!vkey) return 0;
    jVar *req = libVES_VaultKey_toJVar(vkey);
    jVar *rsp = libVES_REST(vkey->ves, "vaultKeys", req);
    jVar_free(req);
    if (!rsp) return 0;
    if (!vkey->id) {
	vkey->id = jVar_getInt(jVar_get(rsp, "id"));
	if (vkey->id && vkey->pPriv) libVES_addUnlocked(vkey->ves, vkey);
    }
    jVar_free(rsp);
    return 1;
}

const libVES_KeyAlgo *libVES_VaultKey_algoFromStr(const char *str) {
    return (const libVES_KeyAlgo *) libVES_lookupAlgo(str, &libVES_VaultKey_algos);
}

const char *libVES_VaultKey_typeStr(int type) {
    return libVES_lookupStr(type, libVES_VaultKey_types);
}

int libVES_VaultKey_dump(libVES_VaultKey *vkey, int fd, int flags) {
    if (!vkey || !vkey->algo) return 0;
    if (!vkey->algo->dumpfn) return 0;
    if (!libVES_VaultKey_unlock(vkey, NULL)) {
	libVES_getError(vkey->ves);
	libVES_VaultKey_getPub(vkey);
    }
    return vkey->algo->dumpfn(vkey, fd, flags);
}

void libVES_VaultKey_free(libVES_VaultKey *vkey) {
    if (libVES_REFBUSY(vkey)) return;
    libVES_VaultKey_lock(vkey);
    libVES_REFDN(User, vkey->user);
    libVES_REFDN(VaultItem, vkey->vitem);
    libVES_REFDN(Ref, vkey->external);
    free(vkey->privateKey);
    free(vkey->publicKey);
    jVar_free(vkey->entries);
    free(vkey->appUrl);
    if (vkey->algo && vkey->algo->freefn) vkey->algo->freefn(vkey);
    free(vkey);
}

void libVES_VaultKey_registerAlgo(const libVES_KeyAlgo *algo) {
    libVES_registerAlgo((void *) algo, &libVES_VaultKey_algos);
}



int libVES_VaultKey_cmpLST(void *entry, void *match) {
    return ((libVES_VaultKey *) entry)->id < ((libVES_VaultKey *) match)->id ? -1
	: (((libVES_VaultKey *) entry)->id == ((libVES_VaultKey *) match)->id && ((libVES_VaultKey *) entry)->id ? 0 : 1);
}

void libVES_VaultKey_freeLST(void *entry) {
    libVES_VaultKey_free(entry);
}

const libVES_ListCtl libVES_VaultKey_ListCtl = { .cmpfn = &libVES_VaultKey_cmpLST, .freefn = &libVES_VaultKey_freeLST };
const libVES_ListCtl libVES_VaultKey_ListCtlU = { .cmpfn = &libVES_VaultKey_cmpLST, .freefn = NULL };

libVES_veskey *libVES_veskey_new(size_t keylen, const char *veskey) {
    libVES_veskey *vk = malloc(offsetof(libVES_veskey, veskey) + keylen);
    if (!vk) return NULL;
    if (veskey) memcpy(vk->veskey, veskey, keylen);
    else {
	if (RAND_bytes((unsigned char *) vk->veskey, keylen) <= 0) return NULL;
	char *p;
	for (p = vk->veskey; p < vk->veskey + keylen; p++) {
	    unsigned char c = *p;
	    *p = c < 26 * 3 ? c % 26 + 'A' : (c < 26 * 7 ? c % 26 + 'a' : (c < 26 * 7 + 10 * 4 ? (c - 26 * 7) % 10 + '0' : "!#$%&()+-_=[]{}:;@<>,./?*^~|-+_=:;"[c - 26 * 7 - 10 * 4]));
	}
    }
    vk->keylen = keylen;
    return vk;
}

void libVES_veskey_free(libVES_veskey *veskey) {
    if (!veskey) return;
    OPENSSL_cleanse(veskey, veskey->keylen + sizeof(veskey->keylen));
    free(veskey);
}
