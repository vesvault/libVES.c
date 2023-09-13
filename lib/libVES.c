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
#include <openssl/crypto.h>
#include <time.h>
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


const char *libVES_errorMsgs[14] = {
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
    "Dialog failed",
    "Quota exceeded"
};

const char *libVES_appName = "(unspecified app)";
const char *libVES_version = LIBVES_VERSION_CODE;

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
    ves->external = libVES_REFUP(Ref, ref);
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
    ves->veskeyLen = LIBVES_VESKEY_LEN;
    ves->genVaultKeyFn = &libVES_defaultGenVaultKey;
    ves->attnFn = NULL;
    ves->unlockedKeys = libVES_List_new(&libVES_VaultKey_ListCtlU);
    (void)libVES_REFUP(List, ves->unlockedKeys);
    ves->sessionTimeout = LIBVES_SESS_TMOUT;
    ves->pollUrl = LIBVES_POLL_URL;
    return ves;
}

libVES *libVES_child(libVES *pves) {
    if (!pves) return NULL;
    libVES *ves = malloc(sizeof(libVES));
    if (!ves) return NULL;
    memcpy(ves, pves, sizeof(libVES));
    ves->curl = NULL;
    (void)libVES_REFUP(Ref, ves->external);
    (void)libVES_REFUP(VaultKey, ves->vaultKey);
    (void)libVES_REFUP(User, ves->me);
    ves->error = LIBVES_E_OK;
    ves->errorMsg = ves->errorBuf = NULL;
    if (ves->sessionToken) ves->sessionToken = strdup(ves->sessionToken);
    ves->unlockedKeys = libVES_List_new(&libVES_VaultKey_ListCtlU);
    (void)libVES_REFUP(List, ves->unlockedKeys);
    libVES_VaultKey **pvk = NULL;
    while ((pvk = libVES_List_next(pves->unlockedKeys, pvk, libVES_VaultKey))) {
	libVES_List_push(ves->unlockedKeys, *pvk);
    }
    return ves;
}

static void **libVES_optionPtr(libVES *ves, int optn) {
    switch (optn) {
	case LIBVES_O_APIURL: return (void **)&ves->apiUrl;
	case LIBVES_O_POLLURL: return (void **)&ves->pollUrl;
	case LIBVES_O_APPNAME: return (void **)&ves->appName;
	case LIBVES_O_ATTNFN: return (void **)&ves->attnFn;
	case LIBVES_O_HTTPINITFN: return (void **)&ves->httpInitFn;
	case LIBVES_O_GENFN: return (void **)&ves->genVaultKeyFn;
	case LIBVES_O_CURL: return (void **)&ves->curl;
	case LIBVES_O_CIPHERALGO: return (void **)&ves->cipherAlgo;
	case LIBVES_O_KEYALGO: return (void **)&ves->keyAlgo;
	case LIBVES_O_REF: return &ves->ref;
	default: return NULL;
    }
}

void *libVES_getOption(libVES *ves, int optn) {
    if (!ves) return NULL;
    switch (optn) {
	case LIBVES_O_DEBUG: return (void *)(long long)ves->debug;
	case LIBVES_O_SESSTMOUT: return (void *)(long long)ves->sessionTimeout;
	case LIBVES_O_VESKEYLEN: return (void *)(long long)ves->veskeyLen;
	default: break;
    }
    void **ptr = libVES_optionPtr(ves, optn);
    return ptr ? *ptr : NULL;
}

int libVES_setOption(libVES *ves, int optn, void *val) {
    if (!ves) return 0;
    switch (optn) {
	case LIBVES_O_DEBUG: return ves->debug = (long long)val, 1;
	case LIBVES_O_SESSTMOUT: return ves->sessionTimeout = (long long)val, 1;
	case LIBVES_O_VESKEYLEN: return ves->veskeyLen = (long long)val, 1;
	default: break;
    }
    void **ptr = libVES_optionPtr(ves, optn);
    return ptr ? (*ptr = val, 1) : 0;
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
		libVES_VaultKey_free_ref_user(res, ref, usr);
	    }
	}
    } else {
	if (!(flags & LIBVES_O_VITEM)) libVES_setError(ves, LIBVES_E_PARAM, "Vault item URI cannot be used here");
	else {
	    if ((!(flags & LIBVES_O_GET) && (flags & LIBVES_O_NEW))
	    || (!(res = libVES_VaultItem_get(ref, ves)) && (flags & LIBVES_O_NEW) && libVES_checkError(ves, LIBVES_E_NOTFOUND))) {
		res = libVES_VaultItem_create(ref);
	    } else if (res) {
		libVES_Ref_free(ref);
	    }
	    if (res) {
		if (type) *type = LIBVES_O_VITEM;
		*uri = p;
	    }
	}
    }
    if (!res) libVES_Ref_free(ref);
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
	    else libVES_VaultItem_post(libVES_VaultKey_propagate(vk), ves);
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
    if (!ves->vaultKey) {
	ves->vaultKey = libVES_VaultKey_get2(ves->external, ves, NULL, NULL, LIBVES_O_GET);
	(void)libVES_REFUP(VaultKey, ves->vaultKey);
    }
    return ves->vaultKey;
}

libVES_VaultKey *libVES_createVaultKey(libVES *ves) {
    if (!ves) return NULL;
    if (ves->vaultKey) libVES_throw(ves, LIBVES_E_DENIED, "Vault key is already loaded", NULL);
    ves->vaultKey = libVES_VaultKey_create(ves->external, ves, ves->me);
    (void)libVES_REFUP(VaultKey, ves->vaultKey);
    return ves->vaultKey;
}

void libVES_setSessionExpire(libVES *ves) {
    ves->sessionExpire = ves->sessionTimeout ? time(NULL) + ves->sessionTimeout : 0;
}

libVES_VaultKey *libVES_unlock(libVES *ves, size_t keylen, const char *key) {
    libVES_veskey *veskey = key ? libVES_veskey_new(keylen, key) : NULL;
    libVES_VaultKey *vkey = libVES_unlock_veskey(ves, veskey);
    libVES_veskey_free(veskey);
    return vkey;
}

libVES_VaultKey *libVES_unlock_veskey(libVES *ves, const libVES_veskey *veskey) {
    if (!ves) return NULL;
    void *res;
    if (libVES_getVaultKey(ves)) {
	res = libVES_VaultKey_unlock(ves->vaultKey, veskey);
    } else if (!ves->external) {
	libVES_User *me = libVES_me(ves);
	res = NULL;
	if (me) {
	    libVES_List *lst = libVES_List_new(&libVES_VaultKey_ListCtl);
	    if (libVES_User_vaultKeys(me, lst, ves)) {
		libVES_VaultKey **pvk = NULL;
		while ((pvk = libVES_List_next(lst, pvk, libVES_VaultKey))) {
		    if (!res) {
			res = libVES_VaultKey_unlock(*pvk, veskey);
			if (res) {
			    ves->vaultKey = libVES_REFUP(VaultKey, *pvk);
			    break;
			}
		    }
		}
	    }
	    libVES_List_free(lst);
	}
    }
    if (res && !ves->sessionToken) {
	char *sesstkn = NULL;
	libVES_VaultKey *vkey = libVES_VaultKey_get2(ves->external, ves, NULL, &sesstkn, LIBVES_O_GET);
	if (vkey) {
	    if (ves->vaultKey) {
		if (!ves->vaultKey->privateKey) {
		    ves->vaultKey->privateKey = vkey->privateKey;
		    vkey->privateKey = NULL;
		}
		if (!ves->vaultKey->vitem) {
		    ves->vaultKey->vitem = libVES_REFUP(VaultItem, vkey->vitem);
		}
		libVES_VaultKey_free(vkey);
	    } else ves->vaultKey = libVES_REFUP(VaultKey, vkey);
	}
	if (sesstkn) {
	    int l = libVES_VaultKey_decrypt(ves->vaultKey, sesstkn, &ves->sessionToken);
	    if (l > 0) {
		ves->sessionToken[l] = 0;
		libVES_setSessionExpire(ves);
		if (!ves->attnFn) ves->attnFn = &libVES_defaultAttn;
	    } else {
		free(ves->sessionToken);
		ves->sessionToken = NULL;
		res = NULL;
	    }
	    free(sesstkn);
	} else res = NULL;
    }
    return res ? ves->vaultKey : NULL;
}

int libVES_refreshSession(libVES *ves) {
    if (!ves || !ves->vaultKey) return 0;
    char uri[128];
    sprintf(uri, "vaultKeys/%lld?fields=encSessionToken", ves->vaultKey->id);
    jVar *vkey_res = libVES_REST_hdrs(ves, uri, NULL, NULL);
    const char *sesstkn = jVar_getStringP(jVar_get(vkey_res, "encSessionToken"));
    int ok = 0;
    if (sesstkn) {
	char *token = NULL;
	int l = libVES_VaultKey_decrypt(ves->vaultKey, sesstkn, &token);
	if (l > 0) {
	    token[l] = 0;
	    free(ves->sessionToken);
	    ves->sessionToken = token;
	    libVES_setSessionExpire(ves);
	    ok = 1;
	} else {
	    free(token);
	}
    }
    jVar_free(vkey_res);
    return ok;
}

int libVES_checkSession(libVES *ves) {
    if (!ves || !ves->sessionToken) return 0;
    if (!ves->sessionExpire || ves->sessionExpire > time(NULL)) return 1;
    return libVES_refreshSession(ves);
}

void libVES_setSessionToken(libVES *ves, const char *token) {
    if (!ves) return;
    ves->sessionExpire = 0;
    if (token) {
	ves->sessionToken = realloc(ves->sessionToken, strlen(token) + 1);
	strcpy(ves->sessionToken, token);
    } else {
	free(ves->sessionToken);
	ves->sessionToken = NULL;
    }
}

void (*libVES_chkAttn(libVES *ves))(libVES *ves, jVar *attn) {
    if (!ves->attnFn) return NULL;
    void (* attnFn)(libVES *, jVar *) = ves->attnFn;
    ves->attnFn = NULL;
    jVar *attn = libVES_REST(ves, "attn", NULL);
    if (attn) attnFn(ves, attn);
    jVar_free(attn);
    return attnFn;
}

void libVES_attn(libVES *ves) {
    if (!ves->attnFn) ves->attnFn = &libVES_defaultAttn;
    ves->attnFn = libVES_chkAttn(ves);
}

void libVES_lock(libVES *ves) {
    if (!ves) return;
    libVES_chkAttn(ves);
    libVES_VaultKey *vk = NULL;
    libVES_VaultKey **pvk;
    while ((pvk = libVES_List_next(ves->unlockedKeys, NULL, libVES_VaultKey)) && *pvk != vk) {
	vk = *pvk;
	if (vk->ves == ves) libVES_VaultKey_lock(vk);
    }
    if (ves->vaultKey && ves->vaultKey->ves == ves) libVES_VaultKey_lock(ves->vaultKey);
}

libVES_VaultKey *libVES_primary(libVES *ves, const char *email, const char *passwd) {
    libVES_VaultKey *pvkey = libVES_User_primary((libVES_User *) (((char *) &email) - offsetof(libVES_User, email)), passwd, (ves->sessionToken ? NULL : &ves->sessionToken), ves);
    if (pvkey && ves && !ves->me) ves->me = libVES_REFUP(User, libVES_VaultKey_getUser(pvkey));
    return pvkey;
}

void libVES_setUser(libVES *ves, libVES_User *user) {
    if (!ves->me) ves->me = libVES_REFUP(User, user);
}

libVES_User *libVES_me(libVES *ves) {
    if (!ves) return NULL;
    if (!ves->me) {
	libVES_setUser(ves, libVES_VaultKey_getUser(libVES_getVaultKey(ves)));
    }
    if (!ves->me) {
	jVar *rsp = libVES_REST(ves, "me", NULL);
	libVES_setUser(ves, libVES_User_fromJVar(rsp));
	jVar_free(rsp);
    }
    libVES_User_loadFields(ves->me, ves);
    return ves->me;
}

char *libVES_fetchVerifyToken(const char *objuri, long long int objid, libVES *ves) {
    if (!objuri || !objid) return NULL;
    char uri[64];
    sprintf(uri, "%s/%lld?fields=verifyToken", objuri, objid);
    jVar *rsp = libVES_REST(ves, uri, NULL);
    char *token = jVar_getString0(jVar_get(rsp, "verifyToken"));
    jVar_free(rsp);
    return token;
}

void libVES_free(libVES *ves) {
    if (!ves) return;
    libVES_lock(ves);
    libVES_REST_done(ves);
    free(ves->sessionToken);
    free(ves->errorBuf);
    libVES_REFDN(User, ves->me);
    libVES_REFDN(Ref, ves->external);
    libVES_REFDN(VaultKey, ves->vaultKey);
    libVES_REFDN(List, ves->unlockedKeys);
    free(ves);
}


void libVES_cleanseJVar(jVar *jvar) {
    if (!jvar) return;
    int i;
    switch (jvar->type) {
	case JVAR_STRING:
	case JVAR_JSON:
	    if (jvar->vString) {
		OPENSSL_cleanse(jvar->vString, jvar->len);
		free(jvar->vString);
		jvar->vString = NULL;
	    }
	    jvar->len = 0;
	    break;
	case JVAR_OBJECT:
	    if (jvar->vObject) {
		for (i = 0; i < jvar->len; i++) {
		    libVES_cleanseJVar(jvar->vObject[i].key);
		    free(jvar->vObject[i].key);
		    libVES_cleanseJVar(jvar->vObject[i].val);
		    free(jvar->vObject[i].val);
		}
		OPENSSL_cleanse(jvar->vObject, jvar->len * sizeof(*(jvar->vObject)));
		free(jvar->vObject);
		jvar->vObject = NULL;
	    }
	    jvar->len = 0;
	    break;
	case JVAR_ARRAY:
	    if (jvar->vArray) {
		for (i = 0; i < jvar->len; i++) libVES_cleanseJVar(jvar->vArray[i]), jVar_free(jvar->vArray[i]);
		OPENSSL_cleanse(jvar->vArray, jvar->len * sizeof(*(jvar->vArray)));
		free(jvar->vArray);
	    }
	    jvar->vArray = NULL;
	    jvar->len = 0;
	    break;
	case JVAR_INT:
	    jvar->vInt = 0;
	    break;
	case JVAR_FLOAT:
	    jvar->vFloat = 0.0;
	    break;
	case JVAR_BOOL:
	    jvar->vBool = 0;
	    break;
	default:
	    return;
    }
    jvar->type = JVAR_NULL;
}
