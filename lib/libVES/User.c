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
 * libVES/User.c              libVES: User object
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../libVES.h"
#include "../jVar.h"
#include "User.h"
#include "VaultKey.h"
#include "REST.h"
#include "Util.h"
#include "List.h"


libVES_User *libVES_User_fromPath(const char **path) {
    const char *s = *path;
    char buf[1024];
    char *email = NULL;
    char *lastw = NULL;
    char *d = buf;
    char quote = 0;
    char ang = 0;
    char sp = 0;
    char at = 0;
    while (s) {
	char c = *s++;
	switch (c) {
	    case ',': case ';':
		if (quote) break;
	    case 0:
		*path = s - 1;
		s = NULL;
		c = 0;
		break;
	    case '"':
		quote ^= 1;
		c = 0;
		break;
	    case '\\':
		if ((c = *s)) s++;
		break;
	    case '%': {
		char cc;
		char c1 = *s;
		if (c1 >= '0' && c1 <= '9') cc = c1 - '0';
		else if (c1 >= 'A' && c1 <= 'F') cc = c1 - ('A' - 10);
		else if (c1 >= 'a' && c1 <= 'a') cc = c1 - ('a' - 10);
		else break;
		cc <<= 4;
		c1 = *(s + 1);
		if (c1 >= '0' && c1 <= '9') cc += c1 - '0';
		else if (c1 >= 'A' && c1 <= 'F') cc += c1 - ('A' - 10);
		else if (c1 >= 'a' && c1 <= 'a') cc += c1 - ('a' - 10);
		else break;
		c = cc;
		s += 2;
		break;
	    }
	}
	switch (c) {
	    case '"':
		c = 0;
		break;
	    case '<':
		if (!quote) {
		    ang = 1;
		    sp = 0;
		    c = 0;
		    if (d) {
			*d++ = 0;
			email = d;
			at = 0;
		    }
		}
		break;
	    case '>':
		if (!quote) {
		    ang = 0;
		    c = 0;
		    if (email && d) {
			if (email == d || !at) return NULL;
			*d = 0;
			d = NULL;
		    }
		}
		break;
	    case '@':
		at = 1;
		break;
	    case ' ': case 9: case 10: case 13:
		c = 0;
		if (!ang && sp > 1) sp = 1;
		break;
	    default:
		break;
	}
	if (c && d) {
	    if (d - buf >= sizeof(buf) - 4) return NULL;
	    if (sp == 1) {
		*d++ = ' ';
		lastw = d;
	    }
	    sp = 2;
	    *d++ = c;
	}
    }
    if (!email) {
	if (at && !lastw) email = buf;
	else return NULL;
    }
    if (d) *d = 0;
    if (lastw) *(lastw - 1) = 0;
    libVES_User *user = malloc(sizeof(libVES_User));
    user->id = 0;
    user->email = strdup(email);
    user->firstName = buf == email || !*buf ? NULL : strdup(buf);
    user->lastName = lastw ? strdup(lastw) : NULL;
    return user;
}

void libVES_User_parseJVar(libVES_User *user, jVar *data) {
    user->email = jVar_getString0(jVar_get(data, "email"));
    user->firstName = jVar_getString0(jVar_get(data, "firstName"));
    user->lastName = jVar_getString0(jVar_get(data, "lastName"));
}

libVES_User *libVES_User_fromJVar(jVar *data) {
    if (!data) return NULL;
    libVES_User *user = malloc(sizeof(libVES_User));
    user->id = jVar_getInt(jVar_get(data, "id"));
    libVES_User_parseJVar(user, data);
    return user;
}

jVar *libVES_User_toJVar(libVES_User *user) {
    if (!user) return NULL;
    if (user->id) return jVar_put(jVar_object(), "id", jVar_int(user->id));
    else if (user->email) {
	jVar *data = jVar_put(jVar_object(), "email", jVar_string(user->email));
	if (user->firstName) jVar_put(data, "firstName", jVar_string(user->firstName));
	if (user->lastName) jVar_put(data, "lastName", jVar_string(user->lastName));
	return data;
    } else return NULL;
}

libVES_List *libVES_User_activeVaultKeys(libVES_User *user, libVES_List *lst, libVES *ves) {
    if (!user || !ves) return NULL;
    jVar *req = libVES_User_toJVar(user);
    if (!req) libVES_throw(ves, LIBVES_E_PARAM, "Bad user data", NULL);
    jVar_put(req, "$op", jVar_string("fetch"));
    jVar *rsp = libVES_REST(ves, "users?fields=activeVaultKeys(id,type,algo,publicKey)", req);
    jVar_free(req);
    if (!rsp) return NULL;
    jVar *jvks = jVar_get(rsp, "activeVaultKeys");
    libVES_VaultKey *vkey;
    int len = jVar_count(jvks);
    if (len) {
	libVES_List *newlst = NULL;
	if (!lst) lst = newlst = libVES_List_new(&libVES_VaultKey_ListCtl);
	int i;
	for (i = 0; i < len; i++) {
	    if (!libVES_List_push(lst, libVES_VaultKey_fromJVar(jVar_index(jvks, i), ves))) {
		libVES_List_free(newlst);
		lst = NULL;
	    }
	}
    } else {
	libVES_setError(ves, LIBVES_E_NOTFOUND, "No active keys for the user");
	lst = NULL;
    }
    jVar_free(rsp);
    return lst;
}

libVES_VaultKey *libVES_User_primary(libVES_User *user, const char *passwd, char **sesstkn, libVES *ves) {
    if (!user) return NULL;
    jVar *rsp = libVES_REST_login(ves, "me?fields=sessionToken,currentVaultKey(id,type,algo,publicKey,privateKey)", NULL, user->email, passwd);
    if (!rsp) return NULL;
    if (sesstkn) *sesstkn = jVar_getString0(jVar_get(rsp, "sessionToken"));
    return libVES_VaultKey_fromJVar(jVar_get(rsp, "currentVaultKey"), ves);
}

libVES_User *libVES_User_loadFields(libVES_User *user, libVES *ves) {
    if (!user || !user->id) return NULL;
    if (user->email) return user;
    if (!ves) return NULL;
    char uri[160];
    sprintf(uri, "users/%lld?fields=email,firstName,lastName", user->id);
    jVar *rsp = libVES_REST(ves, uri, NULL);
    if (!rsp) return NULL;
    libVES_User_parseJVar(user, rsp);
    jVar_free(rsp);
    return user;
}

char *libVES_User_getName1(libVES_User *user) {
    if (!user || (!user->firstName && !user->lastName)) return NULL;
    int lf = user->firstName ? strlen(user->firstName) : 0;
    int ll = user->lastName ? strlen(user->lastName) : 0;
    char *res = malloc(lf + ll + 2);
    if (lf) memcpy(res, user->firstName, lf);
    if (ll) {
	res[lf] = ' ';
	strcpy(res + (lf ? lf + 1 : 0), user->lastName);
    } else res[lf] = 0;
    return res;
}

libVES_User *libVES_User_copy(libVES_User *user) {
    if (!user || !user->id) return NULL;
    libVES_User *res = malloc(sizeof(libVES_User));
    res->id = user->id;
    res->email = res->firstName = res->lastName = NULL;
    return res;
}

void libVES_User_free(libVES_User *user) {
    if (!user) return;
    free(user->email);
    free(user->firstName);
    free(user->lastName);
    free(user);
}
