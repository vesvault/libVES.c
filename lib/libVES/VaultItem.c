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
 * libVES/VaultItem.c         libVES: Vault Item object
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include "../jVar.h"
#include "../libVES.h"
#include "VaultItem.h"
#include "VaultKey.h"
#include "Ref.h"
#include "File.h"
#include "Util.h"
#include "List.h"
#include "Cipher.h"
#include "User.h"
#include "REST.h"
#include "CiAlgo_AES.h"

const char *libVES_VaultItem_types[5] = { "string", "file", "password", "secret", NULL };

libVES_VaultItem *libVES_VaultItem_new() {
    libVES_VaultItem *vitem = malloc(offsetof(libVES_VaultItem, share));
    if (!vitem) return NULL;
    vitem->id = 0;
    vitem->flags = LIBVES_SH_ADD | LIBVES_SH_UPD;
    vitem->sharelen = 0;
    vitem->type = LIBVES_VI_STRING;
    vitem->objectType = -1;
    vitem->object = NULL;
    vitem->value = NULL;
    vitem->meta = vitem->entries = NULL;
    return vitem;
}

jVar *libVES_VaultItem_Ref_toJVar(libVES_Ref *ref) {
    if (!ref) return NULL;
    jVar *obj = jVar_object();
    if (libVES_Ref_toJVar(ref, obj)) return ref->domain ? jVar_put(jVar_object(), "file", obj) : obj;
    jVar_free(obj);
    return NULL;
}

jVar *libVES_VaultItem_toJVar(libVES_VaultItem *vitem) {
    if (!vitem) return NULL;
    jVar *data = jVar_object();
    if (vitem->id && (!vitem->object || !(vitem->flags & LIBVES_SH_CLN))) jVar_put(data, "id", jVar_int(vitem->id));
    jVar_put(data, "type", jVar_string(libVES_VaultItem_typeStr(vitem->type)));
    switch (vitem->objectType) {
	case LIBVES_O_FILE: if (vitem->file) jVar_put(data, "file", libVES_File_toJVar(vitem->file)); break;
	case LIBVES_O_VKEY: if (vitem->vaultKey) jVar_put(data, "vaultKey", libVES_VaultKey_toJVar(vitem->vaultKey)); break;
    }
    if (vitem->meta && (vitem->flags & LIBVES_SH_META)) {
	jVar_put(data, "meta", jVar_clone(vitem->meta));
    }
    if (vitem->entries && jVar_count(vitem->entries)) {
	jVar_put(data, "vaultEntries", vitem->entries);
	vitem->entries = NULL;
	if (!vitem->id) jVar_put(data, "$op", jVar_string("create"));
    }
    return data;
}

libVES_VaultItem *libVES_VaultItem_fromJVar(jVar *data, libVES *ves) {
    if (!jVar_isObject(data)) return NULL;
    jVar *entries = jVar_get(data, "vaultEntries");
    size_t entct = jVar_count(entries);
    libVES_VaultItem *vitem = malloc(offsetof(libVES_VaultItem,share) + sizeof(vitem->share[0]) * entct);
    if (!vitem) return NULL;
    vitem->flags = jVar_getBool(jVar_get(data, "deleted")) ? LIBVES_SH_DEL : 0;
    vitem->id = jVar_getInt(jVar_get(data, "id"));
    vitem->type = jVar_getEnum(jVar_get(data, "type"), libVES_VaultItem_types);
    vitem->sharelen = entct;
    vitem->meta = jVar_detach(jVar_get(data, "meta"));
    vitem->value = NULL;
    vitem->len = 0;
    vitem->entries = NULL;
    jVar *obj;
    if ((obj = jVar_get(data, "file"))) {
	vitem->objectType = LIBVES_O_FILE;
	vitem->file = libVES_File_fromJVar(obj);
    } else if ((obj = jVar_get(data, "vaultKey"))) {
	vitem->objectType = LIBVES_O_VKEY;
	vitem->vaultKey = libVES_VaultKey_fromJVar(obj, NULL);
    } else {
	vitem->objectType = -1;
	vitem->object = NULL;
    }
    if (ves) {
	int i;
	if (ves->debug > 1) {
	    fprintf(stderr, "(unlocking Vault Item %lld) unlocked keys:", vitem->id);
	    for (i = 0; i < ves->unlockedKeys->len; i++) fprintf(stderr, " %lld", ((libVES_VaultKey *) ves->unlockedKeys->list[i])->id);
	    fprintf(stderr, "\n");
	}
	libVES_VaultKey *ukey;
	for (i = 0; i < entct; i++) {
	    jVar *entry = jVar_index(entries, i);
	    char *encdata = jVar_getString0(jVar_get(entry, "encData"));
	    libVES_VaultKey *vkey = vitem->share[i] = libVES_VaultKey_fromJVar(jVar_get(entry, "vaultKey"), ves);
	    if ((ukey = libVES_List_find(ves->unlockedKeys, vkey))) {
		int len = libVES_VaultKey_decrypt(ukey, encdata, &vitem->value);
		if (len >= 0) vitem->len = len;
		else if (vitem->value) {
		    free(vitem->value);
		    vitem->value = NULL;
		}
	    }
	    free(encdata);
	}
    }
    return vitem;
}

char *libVES_VaultItem_toURI(libVES_VaultItem *vitem) {
    if (!vitem) return NULL;
    switch (vitem->objectType) {
	case LIBVES_O_FILE: return libVES_File_toURI(vitem->file);
	default: return NULL;
    }
}

char *libVES_VaultItem_toURIi(libVES_VaultItem *vitem) {
    if (!vitem) return NULL;
    char buf[48];
    sprintf(buf, "ves:///%lld", vitem->id);
    return strdup(buf);
}

libVES_VaultItem *libVES_VaultItem_create(libVES_Ref *ref) {
    libVES_VaultItem *vitem = libVES_VaultItem_new();
    vitem->objectType = LIBVES_O_FILE;
    vitem->file = libVES_File_new(ref);
    return vitem;
}

#define libVES_VaultItem_CI_DEFAULT	&libVES_CiAlgo_AES256CFB

libVES_Cipher *libVES_VaultItem_getCipher(libVES_VaultItem *vitem, libVES *ves) {
    if (!vitem) libVES_throw(ves, LIBVES_E_PARAM, "VaultItem is not supplied", NULL);
    if (!vitem->value) libVES_throw(ves, LIBVES_E_UNLOCK, "Value is not decrypted", NULL);
    if (vitem->type != LIBVES_VI_FILE) libVES_throw(ves, LIBVES_E_INCORRECT, "Incorrect Vault Item type", NULL);
    jVar *algo_fld = jVar_get(vitem->meta, "a");
    const struct libVES_CiAlgo *algo;
    if (algo_fld) {
	char buf[64];
	if (algo_fld->len < sizeof(buf)) {
	    jVar_cpString(algo_fld, buf, algo_fld->len);
	    buf[algo_fld->len] = 0;
	    algo = libVES_Cipher_algoFromStr(buf);
	} else algo = NULL;
    } else algo = libVES_VaultItem_CI_DEFAULT;
    if (!algo) libVES_throw(ves, LIBVES_E_UNSUPPORTED, "Unknown cipher algorithm", NULL);
    return libVES_Cipher_new(algo, ves, vitem->len, vitem->value);
}

jVar *libVES_VaultItem_getObject(libVES_VaultItem *vitem) {
    if (!vitem || !vitem->value) return NULL;
    return jVar_parse(vitem->value, vitem->len);
}

int libVES_VaultItem_setValue(libVES_VaultItem *vitem, size_t len, const char *value, int type) {
    if (!vitem) return 0;
    free(vitem->value);
    vitem->value = (char *) value;
    vitem->len = len;
    if (type >= 0) vitem->type = type;
    libVES_VaultItem_force(vitem);
    return 1;
}

int libVES_VaultItem_setCipher(libVES_VaultItem *vitem, libVES_Cipher *ci) {
    if (!vitem || !ci) return 0;
    size_t len;
    char *value = libVES_Cipher_toStringl(ci, &len, NULL);
    int res = libVES_VaultItem_setValue(vitem, len, value, LIBVES_VI_FILE);
    if (!res) free(value);
    else {
	if (!jVar_isObject(vitem->meta)) {
	    jVar_free(vitem->meta);
	    vitem->meta = jVar_object();
	}
	libVES_VaultItem_setMeta(vitem, jVar_put(vitem->meta, "a", jVar_string(libVES_Cipher_algoStr(ci->algo))));
    }
    return res;
}

int libVES_VaultItem_setObject(libVES_VaultItem *vitem, jVar *obj) {
    if (!vitem || !obj) return 0;
    char *json = jVar_toJSON(obj);
    if (!json) return 0;
    int res = libVES_VaultItem_setValue(vitem, strlen(json), json, LIBVES_VI_STRING);
    if (!res) free(json);
    return res;
}

jVar *libVES_VaultItem_entries(libVES_VaultItem *vitem, libVES_List *share, int flags) {
    if (!vitem) return NULL;
    flags |= (vitem->flags & LIBVES_SH_UPD);
    jVar *entries;
    if (jVar_isArray(vitem->entries)) {
	entries = vitem->entries;
	vitem->entries = NULL;
    } else entries = jVar_array();
    int i, j;
    char *shflags;
    if (vitem->sharelen) {
	shflags = malloc(vitem->sharelen);
	if (!shflags) return jVar_free(entries), NULL;
	memset(shflags, 0, vitem->sharelen);
    } else {
	shflags = NULL;
    }
    if (share) for (i = 0; i < share->len; i++) {
	libVES_VaultKey *vkey = share->list[i];
	char exists = 0;
	if (vkey->id) {
	    if (flags & LIBVES_SH_DEL) {
		jVar_push(entries, jVar_put(jVar_put(jVar_object(), "vaultKey", jVar_put(jVar_object(), "id", jVar_int(vkey->id))), "$op", jVar_string("delete")));
		continue;
	    }
	    for (j = 0; j < vitem->sharelen; j++) {
		if (vkey->id == vitem->share[j]->id) exists = shflags[j] |= LIBVES_SH_CLN;
		else if (!vitem->share[j]->external && vkey->user && vitem->share[j]->user && vitem->share[j]->user->id == vkey->user->id) shflags[j] |= LIBVES_SH_PRI;
	    }
	}
	if (!(flags & (exists ? LIBVES_SH_UPD : LIBVES_SH_ADD))) continue;
	char *enc = libVES_VaultKey_encrypt(vkey, vitem->value, vitem->len);
	if (enc) {
	    jVar_push(entries, jVar_put(jVar_put(jVar_object(), "vaultKey", libVES_VaultKey_toJVar(vkey)), "encData", jVar_string0(enc)));
	} else {
	    if (!vitem->value) libVES_setError(vkey->ves, LIBVES_E_UNLOCK, "The value of the vault item has not been decrypted");
	    jVar_free(entries);
	    entries = NULL;
	    break;
	}
    }
    if (!entries) return free(shflags), NULL;
    if (flags & (LIBVES_SH_CLN | LIBVES_SH_UPD)) for (j = 0; j < vitem->sharelen; j++) {
	if ((flags & LIBVES_SH_CLN) && !(~(flags & LIBVES_SH_PRI) & shflags[j])) {
	    jVar_push(entries, jVar_put(jVar_put(jVar_object(), "vaultKey", jVar_put(jVar_object(), "id", jVar_int(vitem->share[j]->id))), "$op", jVar_string("delete")));
	} else if ((flags & LIBVES_SH_UPD) && !(shflags[j] & LIBVES_SH_CLN)) {
	    char *enc = libVES_VaultKey_encrypt(vitem->share[j], vitem->value, vitem->len);
	    if (enc) {
		jVar_push(entries, jVar_put(jVar_put(jVar_object(), "vaultKey", libVES_VaultKey_toJVar(vitem->share[j])), "encData", jVar_string0(enc)));
	    } else {
		if (!vitem->value) libVES_setError(vitem->share[j]->ves, LIBVES_E_UNLOCK, "The value of the vault item has not been decrypted");
		jVar_free(entries);
		entries = NULL;
		break;
	    }
	}
    }
    if (vitem->flags & LIBVES_SH_UPD) {
	vitem->flags &= ~LIBVES_SH_UPD;
	vitem->flags |= LIBVES_SH_CLN;
    }
    jVar_free(vitem->entries);
    free(shflags);
    return vitem->entries = entries;
}

libVES_VaultItem *libVES_VaultItem_get(libVES_Ref *ref, libVES *ves) {
    jVar *req = libVES_VaultItem_Ref_toJVar(ref);
    if (!req) libVES_throw(ves, LIBVES_E_PARAM, "Vault reference is not valid", NULL);
    jVar_put(req, "$op", jVar_string("fetch"));
    jVar *res = libVES_REST(ves, "vaultItems?fields=id,type,meta,file(externals,creator(id,email,firstName,lastName)),vaultKey(id,type,algo,user,externals),vaultEntries(encData,vaultKey(id,type,user(id),externals))", req);
    jVar_free(req);
    if (!res) return NULL;
    libVES_VaultItem *vitem = libVES_VaultItem_fromJVar(res, ves);
    jVar_free(res);
    return vitem;
}

int libVES_VaultItem_post(libVES_VaultItem *vitem, libVES *ves) {
    if (!vitem || !ves) return 0;
    if ((vitem->flags & LIBVES_SH_UPD) && !vitem->entries) {
	libVES_List_STATIC(lst, NULL, 1, ves->vaultKey);
	if (!libVES_VaultItem_entries(vitem, &lst, LIBVES_SH_ADD)) return 0;
    }
    jVar *req = libVES_VaultItem_toJVar(vitem);
    if (!req) return 0;
    jVar *res = libVES_REST(ves, "vaultItems", req);
    jVar_free(req);
    if (!res) return 0;
    jVar_free(res);
    return 1;
}

int libVES_VaultItem_delete(libVES_VaultItem *vitem, libVES *ves) {
    if (!vitem) return 0;
    jVar *req = jVar_put(jVar_put(jVar_object(), "id", jVar_int(vitem->id)), "$op", jVar_string("delete"));
    jVar *rsp = libVES_REST(ves, "vaultItems", req);
    jVar_free(req);
    if (!rsp) return 0;
    jVar_free(rsp);
    return 1;
}

libVES_List *libVES_VaultItem_list(libVES_VaultKey *vkey) {
    if (!vkey) return NULL;
    if (!vkey->id) libVES_throw(vkey->ves, LIBVES_E_PARAM, "VaultKey id is not set", NULL);
    char uri[160];
    sprintf(uri, "vaultKeys/%lld?fields=vaultEntries(vaultItem(id,type,deleted,file(externals,creator),vaultKey(externals,user),meta))", vkey->id);
    jVar *rsp = libVES_REST(vkey->ves, uri, NULL);
    if (!rsp) return NULL;
    jVar *entries = jVar_get(rsp, "vaultEntries");
    libVES_List *lst = NULL;
    if (jVar_isArray(entries)) {
	lst = libVES_List_new(&libVES_VaultItem_ListCtl);
	int len = jVar_count(entries);
	int idx;
	for (idx = 0; idx < len; idx++) {
	    libVES_List_push(lst, libVES_VaultItem_fromJVar(jVar_get(jVar_index(entries, idx), "vaultItem"), vkey->ves));
	}
    } else libVES_setError(vkey->ves, LIBVES_E_DENIED, "Vault Entries are not accessible");
    jVar_free(rsp);
    return lst;
}

char *libVES_VaultItem_toStringl(libVES_VaultItem *vitem, size_t *len, char *buf) {
    if (!vitem || !vitem->value) return NULL;
    if (!buf) buf = malloc(vitem->len + (len ? 0 : 1));
    else if (len && vitem->len > *len) return NULL;
    if (!buf) return NULL;
    memcpy(buf, vitem->value, vitem->len);
    if (len) *len = vitem->len;
    else buf[vitem->len] = 0;
    return buf;
}

struct jVar *libVES_VaultItem_getMeta(libVES_VaultItem *vitem) {
    return vitem ? vitem->meta : NULL;
}

int libVES_VaultItem_setMeta(libVES_VaultItem *vitem, struct jVar *meta) {
    if (!vitem) return 0;
    if (vitem->meta != meta) jVar_free(vitem->meta);
    vitem->meta = meta;
    vitem->flags |= LIBVES_SH_META;
    return 1;
}
const char *libVES_VaultItem_typeStr(int type) {
    return libVES_lookupStr(type, libVES_VaultItem_types);
}

int libVES_VaultItem_typeFromStr(const char *str) {
    return libVES_enumStr(str, libVES_VaultItem_types);
}

jVar *libVES_VaultItem_VESauthGET(libVES_VaultItem *vitem, libVES *ves, const char *url, long *pcode) {
    if (!vitem || !ves || !url) return NULL;
    char *vrfy = libVES_VaultItem_fetchVerifyToken(vitem, ves);
    if (!vrfy) libVES_throw(ves, LIBVES_E_PARAM, "Verify Token is NULL", NULL);
    jVar *rs = libVES_REST_VESauthGET(ves, url, pcode, "vaultItem.%lld.%s", vitem->id, vrfy);
    free(vrfy);
    return rs;
}


void libVES_VaultItem_free(libVES_VaultItem *vitem) {
    if (!vitem) return;
    jVar_free(vitem->meta);
    jVar_free(vitem->entries);
    if (vitem->value) {
	OPENSSL_cleanse(vitem->value, vitem->len);
	free(vitem->value);
	vitem->len = 0;
    }
    switch (vitem->objectType) {
	case LIBVES_O_FILE: libVES_File_free(vitem->file); break;
	case LIBVES_O_VKEY: libVES_VaultKey_free(vitem->vaultKey); break;
    }
    int i;
    for (i = 0; i < vitem->sharelen; i++) libVES_VaultKey_free(vitem->share[i]);
    free(vitem);
}


int libVES_VaultItem_cmpLST(void *entry, void *match) {
    return ((libVES_VaultItem *) entry)->id < ((libVES_VaultItem *) match)->id ? -1
	: (((libVES_VaultItem *) entry)->id == ((libVES_VaultItem *) match)->id && ((libVES_VaultItem *) entry)->id ? 0 : 1);
}

void libVES_VaultItem_freeLST(void *vitem) {
    libVES_VaultItem_free(vitem);
}

const libVES_ListCtl libVES_VaultItem_ListCtl = { .cmpfn = &libVES_VaultItem_cmpLST, .freefn = &libVES_VaultItem_freeLST };
