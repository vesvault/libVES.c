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
 * libVES.c                   libVES: Main file
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "jVar.h"
#include "libVES/Util.h"
#include "libVES/List.h"
#include "libVES/REST.h"
#include "libVES/Ref.h"
#include "libVES/User.h"
#include "libVES/VaultKey.h"
#include "libVES/VaultItem.h"
#include "libVES/Cipher.h"
#include "libVES/CiAlgo_AES.h"
#include "libVES/KeyAlgo_EVP.h"
#include "libVES.h"

libVES_List_STATIC0(libVES_unlockedKeys, &libVES_VaultKey_ListCtlU);

const char *libVES_errorMsgs[12] = {
    NULL,
    "Bad parameters",
    "Communication with the API server failed",
    "Error parsing response from the API server",
    "Cryptographic error",
    "Vault Key is locked",
    "Access denied",
    "Object not found",
    "API server error",
    "Unsupported algorithm",
    "Incorrect operation",
    "Internal assertion failed",
};

const char *libVES_appName = "(unspecified app)";

void libVES_init(const char *appName) {
    if (appName) libVES_appName = appName;
    libVES_initEVP();
}

libVES *libVES_new(const char *vaultURI) {
    if (!vaultURI) return libVES_fromRef(NULL);
    libVES_Ref *ref = libVES_Ref_fromURI(&vaultURI, NULL);
    return ref ? libVES_fromRef(ref) : NULL;
}

libVES *libVES_fromRef(libVES_Ref *ref) {
    libVES_init(NULL);
    libVES *ves = malloc(sizeof(libVES));
    if (!ves) return NULL;
    ves->external = ref;
    ves->apiUrl = LIBVES_API_URL;
    ves->appName = libVES_appName;
    ves->vaultKey = NULL;
    ves->sessionToken = NULL;
    ves->me = NULL;
    ves->error = LIBVES_E_OK;
    ves->errorMsg = ves->errorBuf = NULL;
    ves->debug = 0;
    ves->curl = NULL;
    ves->httpInitFn = NULL;
    ves->cipherAlgo = &libVES_CiAlgo_AES256GCM1K;
    ves->keyAlgo = &libVES_KeyAlgo_ECDH;
    ves->veskeyLen = 32;
    ves->genVaultKeyFn = &libVES_defaultGenVaultKey;
    ves->attnFn = &libVES_defaultAttn;
    ves->unlockedKeys = &libVES_unlockedKeys;
    return ves;
}

int libVES_getError(libVES *ves) {
    int e = LIBVES_E_PARAM;
    if (ves) {
	e = ves->error;
	ves->error = LIBVES_E_OK;
    }
    return e;
}

int libVES_checkError(libVES *ves, int err) {
    return (ves && ves->error == err) ? libVES_getError(ves) : LIBVES_E_OK;
}

const char *libVES_errorStr(int error) {
    return libVES_lookupStr(error, libVES_errorMsgs);
}

int libVES_getErrorInfo(libVES *ves, const char **str, const char **msg) {
    int e = libVES_getError(ves);
    if (str) *str = libVES_errorStr(e);
    if (msg) *msg = ves ? ves->errorMsg : NULL;
    return e;
}

void *libVES_objectFromURI(const char **uri, libVES *ves, int flags, int *type) {
    const char *p = *uri;
    libVES_Ref *ref = libVES_Ref_fromURI(&p, ves);
    void *res = NULL;
    if (*p == '/') {
	if (!(flags & LIBVES_O_VKEY)) libVES_setError(ves, LIBVES_E_PARAM, "Vault key URI cannot be used here");
	else {
	    p++;
	    libVES_User *usr = libVES_User_fromPath(&p);
	    if ((res = libVES_VaultKey_get2(ref, ves, usr, NULL, flags))) {
		if (type) *type = LIBVES_O_VKEY;
		*uri = p;
	    }
	}
    } else {
	if (!(flags & LIBVES_O_VITEM)) libVES_setError(ves, LIBVES_E_PARAM, "Vault item URI cannot be used here");
	else {
	    if ((!(flags & LIBVES_O_GET) && (flags & LIBVES_O_NEW))
	    || (!(res = libVES_VaultItem_get(ref, ves)) && (flags & LIBVES_O_NEW) && libVES_checkError(ves, LIBVES_E_NOTFOUND))) {
		res = libVES_VaultItem_create(ref);
	    }
	    if (res) {
		if (type) *type = LIBVES_O_VITEM;
		*uri = p;
	    }
	}
    }
    if (!res || (ref && !ref->domain)) libVES_Ref_free(ref);
    return res;
}

libVES_VaultKey *libVES_defaultGenVaultKey(libVES *ves, int type, struct libVES_Ref *ref, struct libVES_User *user) {
    libVES_veskey *veskey = libVES_veskey_generate(ves->veskeyLen);
    libVES_VaultKey *vkey = libVES_VaultKey_new(type, ves->keyAlgo, NULL, veskey, ves);
    libVES_veskey_free(veskey);
    return vkey;
}

void libVES_defaultAttn(libVES *ves, jVar *attn) {
    if (!ves || !attn) return;
    jVar *vks = jVar_get(attn, "vaultKeys");
    if (!vks) return;
    libVES_User *me = libVES_me(ves);
    if (!me) return;
    int i;
    for (i = 0; i < jVar_count(vks); i++) {
	libVES_VaultKey *vk = libVES_VaultKey_fromJVar(jVar_index(vks, i), ves);
	libVES_User *u = libVES_VaultKey_getUser(vk);
	if (u) {
	    if (u->id == me->id) libVES_VaultKey_rekey(vk);
	    else libVES_VaultKey_propagate(vk);
	}
	libVES_VaultKey_free(vk);
	libVES_getError(ves);
    }
}

int libVES_fileExists(libVES *ves, const char *uri) {
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    if (!vitem) return libVES_checkError(ves, LIBVES_E_NOTFOUND) ? 0 : -1;
    libVES_VaultItem_free(vitem);
    return 1;
}

char *libVES_getValue(libVES *ves, const char *uri, size_t *len, char *buf) {
    libVES_VaultItem *vitem = libVES_VaultItem_loadFromURI(&uri, ves);
    if (!vitem) return NULL;
    char *res = libVES_VaultItem_toStringl(vitem, len, buf);
    libVES_VaultItem_free(vitem);
    return res;
}

int libVES_putValue(libVES *ves, const char *uri, size_t len, const char *value, size_t sharelen, const char **shareURI) {
    libVES_VaultItem *vitem = libVES_VaultItem_fromURI(&uri, ves);
    if (!vitem) return 0;
    if (value) libVES_VaultItem_setValue(vitem, len, value, -1);
    int ok;
    if (shareURI) {
	libVES_List *share = libVES_List_new(&libVES_VaultKey_ListCtl);
	const char *s;
	int i;
	for (i = 0; i < sharelen; i++) {
	    s = shareURI[i];
	    if (!libVES_List_push(share, libVES_VaultKey_fromURI(&s, ves))) break;
	}
	ok = (share->len >= sharelen) && libVES_VaultItem_entries(vitem, share, LIBVES_SH_ADD | LIBVES_SH_CLN | (value ? LIBVES_SH_UPD : 0));
	libVES_List_free(share);
    }
    if (ok && !libVES_VaultItem_post(vitem, ves)) ok = 0;
    libVES_VaultItem_free(vitem);
    return ok;
}

int libVES_shareFile(libVES *ves, const char *uri, size_t sharelen, const char **shareURI) {
    return libVES_putValue(ves, uri, 0, NULL, sharelen, shareURI);
}

libVES_VaultKey *libVES_getVaultKey(libVES *ves) {
    if (!ves) return NULL;
    if (!ves->vaultKey) ves->vaultKey = libVES_VaultKey_get2(ves->external, ves, NULL, NULL, LIBVES_O_GET);
    return ves->vaultKey;
}

libVES_VaultKey *libVES_createVaultKey(libVES *ves) {
    if (!ves) return NULL;
    if (ves->vaultKey) libVES_throw(ves, LIBVES_E_DENIED, "Vault key is already loaded", NULL);
    if (!ves->me) libVES_throw(ves, LIBVES_E_DENIED, "Login to the primary account to proceed", NULL);
    ves->vaultKey = libVES_VaultKey_create(ves->external, ves, ves->me);
    return ves->vaultKey;
}

libVES_VaultKey *libVES_unlock(libVES *ves, size_t keylen, const char *key) {
    if (!ves) return NULL;
    char *sesstkn = NULL;
    if (!ves->sessionToken) {
	libVES_VaultKey *vkey = libVES_VaultKey_get2(ves->external, ves, NULL, &sesstkn, LIBVES_O_GET);
	if (vkey) {
	    if (ves->vaultKey) {
		if (!ves->vaultKey->privateKey) {
		    ves->vaultKey->privateKey = vkey->privateKey;
		    vkey->privateKey = NULL;
		}
		if (!ves->vaultKey->vitem) {
		    ves->vaultKey->vitem = vkey->vitem;
		    vkey->vitem = NULL;
		}
		libVES_VaultKey_free(vkey);
	    } else ves->vaultKey = vkey;
	}
	if (!sesstkn) return NULL;
    }
    if (!libVES_getVaultKey(ves)) return NULL;
    libVES_veskey *veskey = key ? libVES_veskey_new(keylen, key) : NULL;
    void *res = libVES_VaultKey_unlock(ves->vaultKey, veskey);
    if (sesstkn) {
	if (res) {
	    int l = libVES_VaultKey_decrypt(ves->vaultKey, sesstkn, &ves->sessionToken);
	    if (l > 0) ves->sessionToken[l] = 0;
	    else {
		free(ves->sessionToken);
		ves->sessionToken = NULL;
		res = NULL;
	    }
	}
	free(sesstkn);
    }
    libVES_veskey_free(veskey);
    return res ? ves->vaultKey : NULL;
}

void libVES_setSessionToken(libVES *ves, const char *token) {
    if (!ves) return;
    if (token) {
	ves->sessionToken = realloc(ves->sessionToken, strlen(token) + 1);
	strcpy(ves->sessionToken, token);
    } else {
	free(ves->sessionToken);
	ves->sessionToken = NULL;
    }
}

void libVES_lock(libVES *ves) {
    if (!ves) return;
    int i = 0;
    libVES_List *unl = ves->unlockedKeys;
    while (i < unl->len) {
	libVES_VaultKey *vkey = unl->list[i];
	libVES_VaultKey_lock(vkey);
	if (!unl->list) break;
	if (unl->list[i] == vkey) i++;
    }
}

libVES_VaultKey *libVES_primary(libVES *ves, const char *email, const char *passwd) {
    libVES_VaultKey *pvkey = libVES_User_primary((libVES_User *) (((char *) &email) - offsetof(libVES_User, email)), passwd, (ves->sessionToken ? NULL : &ves->sessionToken), ves);
    if (pvkey && ves && !ves->me) ves->me = libVES_User_copy(libVES_VaultKey_getUser(pvkey));
    return pvkey;
}

libVES_User *libVES_me(libVES *ves) {
    if (!ves) return NULL;
    if (!ves->me) ves->me = libVES_VaultKey_getUser(libVES_getVaultKey(ves));
    libVES_User_loadFields(ves->me, ves);
    return ves->me;
}

void libVES_free(libVES *ves) {
    if (!ves) return;
    libVES_REST_done(ves);
    free(ves->sessionToken);
    free(ves->errorBuf);
    if (ves->vaultKey) libVES_VaultKey_free(ves->vaultKey);
    else libVES_User_free(ves->me);
    free(ves);
}
