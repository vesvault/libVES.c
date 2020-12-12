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
 * libVES/Ref.c               libVES: Object reference
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../jVar.h"
#include "../libVES.h"
#include "Ref.h"
#include "User.h"
#include "VaultKey.h"
#include "VaultItem.h"
#include "List.h"

libVES_Ref *libVES_Ref_new(long long int intId) {
    if (!intId) return NULL;
    libVES_Ref *ref = malloc(offsetof(libVES_Ref, internalId) + sizeof(ref->internalId));
    if (!ref) return NULL;
    ref->domain = NULL;
    ref->internalId = intId;
    return ref;
}

// * Domain list control callbacks *******
int libVES_External_cmpDomLST(void *a, void *b) {
    return strcmp((char *) a, (char *) b);
}

void libVES_External_freeDomLST(void *a) {
    free(a);
}
// ***************************************

libVES_Ref *libVES_External_new(const char *domain, const char *extId) {
    static libVES_ListCtl domListCtl = {.cmpfn = &libVES_External_cmpDomLST, .freefn = &libVES_External_freeDomLST};
    static libVES_List_STATIC0(domlist, &domListCtl);
    static char lck = 0;
    if (!domain || !extId) return NULL;
    int l = strlen(extId);
    libVES_Ref *ext = malloc(offsetof(libVES_Ref, externalId) + l + 1);
    if (!ext) return NULL;
    ext->domain = libVES_List_find(&domlist, (void *) domain);
    if (!ext->domain) {
	if (lck || (++lck > 1 && lck--)) {
	    free(ext);
	    return NULL;
	}
	if (!(ext->domain = libVES_List_find(&domlist, (void *) domain))) {
	    char *d = strdup(domain);
	    if (!(ext->domain = libVES_List_push(&domlist, d))) {
		lck--;
		free(d);
		free(ext);
		return NULL;
	    }
	}
	lck--;
    }
    strcpy(ext->externalId, extId);
    return ext;
}

libVES_Ref *libVES_External_fromJVar(jVar *data) {
    if (jVar_isArray(data)) data = jVar_index(data, 0);
    if (!jVar_isObject(data)) return NULL;
    libVES_Ref *ext = libVES_External_new(jVar_getStringP(jVar_get(data, "domain")), jVar_getStringP(jVar_get(data, "externalId")));
    return ext;
}

libVES_Ref *libVES_Ref_fromURI(const char **path, libVES *ves) {
    if (!path) return NULL;
    const char *p = *path;
    if (!p) return NULL;
    enum {s_init, s_dom, s_ext, s_first, s_next, s_done} st = s_init;
    char buf[1024];
    char *d = buf;
    char *dom = NULL;
    char *ext = NULL;
    char *sch = NULL;
    char *tail = buf + sizeof(buf) - 4;
    int c;
    for (; st != s_done && d < tail; *d++ = c) switch (c = *p++) {
	case '/': case '#': case '?': case 0: {
	    switch (st) {
		case s_init:
		case s_next:
		    if (c != '/') return NULL;
		    if (*p != '/') {
			*path = p - 1;
			return NULL;
		    }
		    st = s_dom;
		    dom = d + 1;
		    p++;
		    break;
		case s_dom:
		    if (c != '/') return NULL;
		    st = s_ext;
		    ext = d + 1;
		    break;
		case s_first:
		case s_ext:
		    st = s_done;
		    *path = p - 1;
		    break;
		default: return NULL;
	    }
	    c = 0;
	    break;
	}
	case '%': {
	    char c1 = *p;
	    if (c1 >= '0' && c1 <= '9') c = c1 - '0';
	    else if (c1 >= 'A' && c1 <= 'F') c = c1 - ('A' - 10);
	    else if (c1 >= 'a' && c1 <= 'f') c = c1 - ('a' - 10);
	    else return NULL;
	    c <<= 4;
	    c1 = *(p + 1);
	    if (c1 >= '0' && c1 <= '9') c += c1 - '0';
	    else if (c1 >= 'A' && c1 <= 'F') c += c1 - ('A' - 10);
	    else if (c1 >= 'a' && c1 <= 'f') c += c1 - ('a' - 10);
	    else return NULL;
	    p += 2;
	}
	default: {
	    switch (st) {
		case s_first:
		    if (c == ':') {
			sch = ext;
			ext = NULL;
			c = 0;
			st = s_next;
		    }
		    break;
		case s_init:
		    st = s_first;
		    ext = d;
		    break;
		case s_next:
		    st = s_ext;
		    ext = d;
		    break;
		default:
		    break;
	    }
	    break;
	}
    }
    if (st != s_done) return NULL;
    if (sch && strcmp(sch, "ves")) return NULL;
    if (dom) {
	if (*dom) return libVES_External_new(dom, ext);
	else {
	    long long int id;
	    if (sscanf(ext, "%lld", &id) < 1 || id <= 0) return NULL;
	    return libVES_Ref_new(id);
	}
    } else return ves && ves->external ? libVES_External_new(ves->external->domain, ext) : NULL;
}

jVar *libVES_Ref_toJVar(libVES_Ref *ref, jVar *dst) {
    if (!ref) return NULL;
    jVar *jref;
    if (ref->domain) {
	jref = jVar_push(jVar_array(), jVar_put(jVar_put(jVar_object(), "domain", jVar_string(ref->domain)), "externalId", jVar_string(ref->externalId)));
	jVar_put(dst, "externals", jref);
    } else {
	jref = jVar_int(ref->internalId);
	jVar_put(dst, "id", jref);
    }
    return jref;
}

libVES_Ref *libVES_Ref_copy(libVES_Ref *ref) {
    if (!ref) return NULL;
    size_t len = ref->domain ? offsetof(libVES_Ref, externalId) + strlen(ref->externalId) + 1 : offsetof(libVES_Ref, internalId) + sizeof(ref->internalId);
    libVES_Ref *res = malloc(len);
    if (res) memcpy(res, ref, len);
    return res;
}
