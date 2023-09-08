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
 * libVES/Event.c             libVES: Event object
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../jVar.h"
#include "../libVES.h"
#include "User.h"
#include "VaultKey.h"
#include "Util.h"
#include "REST.h"
#include "Session.h"


libVES_Session *libVES_Session_fromJVar(jVar *data, libVES *ves) {
    if (!data) return NULL;
    libVES_Session *ses = malloc(sizeof(libVES_Session));
    if (!ses) return NULL;
    ses->id = jVar_getInt(jVar_get(data, "id"));
    ses->vkey = NULL;
    ses->user = NULL;
    ses->remote = NULL;
    ses->userAgent = NULL;
    ses->createdAt = ses->expiresAt = ses->accessAt = 0;
    return libVES_REFINIT(ses);
}

void libVES_Session_parseJVar(libVES_Session *ses, jVar *data, libVES *ves) {
    jVar *jv = jVar_get(data, "vaultKey");
    if (jv) {
	(void)libVES_REFDN(VaultKey, ses->vkey);
	ses->vkey = libVES_VaultKey_fromJVar(jv, ves);
	(void)libVES_REFUP(VaultKey, ses->vkey);
    }
    jv = jVar_get(data, "user");
    if (jv) {
	(void)libVES_REFDN(User, ses->user);
	ses->user = libVES_User_fromJVar(jv);
	(void)libVES_REFUP(User, ses->user);
    }
    jv = jVar_get(data, "createdAt");
    if (jv) ses->createdAt = libVES_date2usec(jVar_getStringP(jv));
    jv = jVar_get(data, "expiresAt");
    if (jv) ses->expiresAt = libVES_date2usec(jVar_getStringP(jv));
    jv = jVar_get(data, "accessAt");
    if (jv) ses->accessAt = libVES_date2usec(jVar_getStringP(jv));
}

int libVES_Session_load(libVES_Session *ses, libVES *ves) {
    if (!ses || !ses->id) return 0;
    char buf[160];
    sprintf(buf, "sessions/%lld?fields=remote,userAgent,vaultKey,user,createdAt,expiresAt,accessAt", ses->id);
    jVar *res = libVES_REST(ves, buf, NULL);
    if (!res) return 0;
    return libVES_Session_parseJVar(ses, res, ves), 1;
}

long long int libVES_Session_getId(libVES_Session *ses) {
    return ses ? ses->id : 0;
}

libVES_VaultKey *libVES_Session_getVaultKey(libVES_Session *ses) {
    return ses ? ses->vkey : NULL;
}

libVES_User *libVES_Session_getUser(libVES_Session *ses) {
    return ses ? ses->user : NULL;
}

long long libVES_Session_getCreatedAt(libVES_Session *ses) {
    return ses ? ses->createdAt : 0;
}

long long libVES_Session_getExpiresAt(libVES_Session *ses) {
    return ses ? ses->expiresAt : 0;
}

long long libVES_Session_getAccessAt(libVES_Session *ses) {
    return ses ? ses->accessAt : 0;
}

const char *libVES_Session_getRemote(libVES_Session *ses) {
    return ses ? ses->remote : NULL;
}

const char *libVES_Session_getUserAgent(libVES_Session *ses) {
    return ses ? ses->userAgent : NULL;
}

void libVES_Session_free(libVES_Session *ses) {
    if (libVES_REFBUSY(ses)) return;
    (void)libVES_REFDN(VaultKey, ses->vkey);
    (void)libVES_REFDN(User, ses->user);
    free(ses);
}

libVES_Session *libVES_Session_refup(libVES_Session *obj) {
    return libVES_REFUP(Session, obj);
}

libVES_Session *libVES_Session_refdn(libVES_Session *obj) {
    return libVES_REFDN(Session, obj) ? NULL : obj;
}
