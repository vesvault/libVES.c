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
#include "VaultItem.h"
#include "Session.h"
#include "Event.h"
#include "List.h"
#include "Ref.h"
#include "Util.h"


const char *libVES_Event_objectList[6] = {"user", "vaultKey", "vaultItem", "session", "vaultEntry", "domain"};
const char *libVES_Event_actionList[6] = {"created", "updated", "deleted", "lost", "listening", "pending"};

short int libVES_Event_parseType0(char *buf) {
    char *acs = strchr(buf, '.');
    if (!acs) return 0;
    *acs++ = 0;
    return (((libVES_enumStr(buf, libVES_Event_objectList) + 1) << 4) | (libVES_enumStr(acs, libVES_Event_actionList) + 1));
}

short int libVES_Event_parseType(const char *type, int len) {
    char buf[48];
    if (len >= sizeof(buf)) return 0;
    memcpy(buf, type, len);
    buf[len] = 0;
    return libVES_Event_parseType0(buf);
}

char *libVES_Event_typeStr(short int type, char *buf) {
    if (!buf) buf = malloc(32);
    int ob = ((type & LIBVES_EO) >> 4) - 1;
    int ac = (type & LIBVES_EA) - 1;
    const char *obs = libVES_lookupStr(ob, libVES_Event_objectList);
    const char *acs = libVES_lookupStr(ac, libVES_Event_actionList);
    sprintf(buf, "%.15s.%.15s", (obs ? obs : "?"), (acs ? acs : "?"));
    return buf;
}

libVES_Event *libVES_Event_fromJVar(jVar *data, libVES *ves) {
    if (!data) return NULL;
    libVES_Event *event = malloc(sizeof(libVES_Event));
    if (!event) return NULL;
    event->id = jVar_getInt(jVar_get(data, "id"));
    event->vkey = NULL;
    event->vitem = NULL;
    event->user = NULL;
    event->creator = NULL;
    event->session = NULL;
    char *t = jVar_getString0(jVar_get(data, "type"));
    event->type = t ? libVES_Event_parseType0(t) : 0;
    free(t);
    event->recordedAt = libVES_date2usec(jVar_getStringP(jVar_get(data, "recordedAt")));
    libVES_Event_parseJVar(event, data, ves);
    return libVES_REFINIT(event);
}

void libVES_Event_parseJVar(libVES_Event *event, jVar *data, libVES *ves) {
    jVar *jv = jVar_get(data, "vaultKey");
    if (jv) {
	(void)libVES_REFDN(VaultKey, event->vkey);
	event->vkey = libVES_VaultKey_fromJVar(jv, ves);
	(void)libVES_REFUP(VaultKey, event->vkey);
    }
    jv = jVar_get(data, "vaultItem");
    if (jv) {
	(void)libVES_REFDN(VaultItem, event->vitem);
	event->vitem = libVES_VaultItem_fromJVar(jv, ves);
	(void)libVES_REFUP(VaultItem, event->vitem);
    }
    jv = jVar_get(data, "user");
    if (jv) {
	(void)libVES_REFDN(User, event->user);
	event->user = libVES_User_fromJVar(jv);
	(void)libVES_REFUP(User, event->user);
    }
    jv = jVar_get(data, "creator");
    if (jv) {
	(void)libVES_REFDN(User, event->creator);
	event->creator = libVES_User_fromJVar(jv);
	(void)libVES_REFUP(User, event->creator);
    }
    jv = jVar_get(data, "session");
    if (jv) {
	(void)libVES_REFDN(Session, event->session);
	event->session = libVES_Session_fromJVar(jv, ves);
	(void)libVES_REFUP(Session, event->session);
    }
}


long long int libVES_Event_getId(libVES_Event *event) {
    return event ? event->id : 0;
}

short int libVES_Event_getType(libVES_Event *event) {
    return event ? event->type : 0;
}

libVES_VaultKey *libVES_Event_getVaultKey(libVES_Event *event) {
    return event ? event->vkey : NULL;
}

libVES_VaultItem *libVES_Event_getVaultItem(libVES_Event *event, struct libVES *ves) {
    if (!event) return NULL;
    if (ves && event->vitem && !event->vitem->value) {
	libVES_Ref ref = {.domain = NULL};
	ref.internalId = event->vitem->id;
	libVES_VaultItem *vi = libVES_VaultItem_get(&ref, ves);
	if (vi) {
	    (void)libVES_REFDN(VaultItem, event->vitem);
	    event->vitem = libVES_REFUP(VaultItem, vi);
	}
    }
    return event->vitem;
}

libVES_User *libVES_Event_getUser(libVES_Event *event) {
    return event ? event->user : NULL;
}

libVES_User *libVES_Event_getCreator(libVES_Event *event) {
    return event ? event->creator : NULL;
}

libVES_Session *libVES_Event_getSession(libVES_Event *event) {
    return event ? event->session : NULL;
}

long long libVES_Event_getRecordedAt(libVES_Event *event) {
    return event ? event->recordedAt : 0;
}

void libVES_Event_free(libVES_Event *event) {
    if (libVES_REFBUSY(event)) return;
    (void)libVES_REFDN(VaultKey, event->vkey);
    (void)libVES_REFDN(VaultItem, event->vitem);
    (void)libVES_REFDN(User, event->user);
    (void)libVES_REFDN(User, event->creator);
    (void)libVES_REFDN(Session, event->session);
    free(event);
}


int libVES_Event_cmpLST(void *entry, void *match) {
    return ((libVES_Event *) entry)->id < ((libVES_Event *) match)->id ? -1
	: (((libVES_Event *) entry)->id == ((libVES_Event *) match)->id && ((libVES_Event *) entry)->id ? 0 : 1);
}

void libVES_Event_freeLST(void *entry) {
    libVES_Event_free(entry);
}

const libVES_ListCtl libVES_Event_ListCtl = { .cmpfn = &libVES_Event_cmpLST, .freefn = &libVES_Event_freeLST };
