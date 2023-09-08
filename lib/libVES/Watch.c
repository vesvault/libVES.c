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
 * libVES/Watch.c              libVES: Event Watch
 *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../libVES.h"
#include "../jVar.h"
#include "List.h"
#include "Event.h"
#include "VaultKey.h"
#include "VaultItem.h"
#include "Ref.h"
#include "REST.h"
#include "Util.h"
#include "Watch.h"


static void *libVES_Watch_objfn_Event_vkey(libVES_Watch *watch, jVar *data) {
    libVES_Event *event = libVES_Event_fromJVar(data, watch->ves);
    (void)libVES_REFDN(VaultKey, event->vkey);
    event->vkey = libVES_REFUP(VaultKey, watch->ves->vaultKey);
    return event;
}

static void *libVES_Watch_objfn_Event(libVES_Watch *watch, jVar *data) {
    return libVES_Event_fromJVar(data, watch->ves);
}

const libVES_WatchCtl libVES_WatchCtl_VaultKey_events = {
    .field = "events",
    .details = "(vaultItem(id,type,file(externals)),user,creator,session)",
    .listctl = &libVES_Event_ListCtl,
    .objfn = &libVES_Watch_objfn_Event_vkey
};

const libVES_WatchCtl libVES_WatchCtl_VaultItem_events = {
    .field = "events",
    .details = "(vaultKey(id,type,algo,publicKey,user,creator),vaultItem(id,type,file(externals)),user,creator)",
    .listctl = &libVES_Event_ListCtl,
    .objfn = &libVES_Watch_objfn_Event
};

const libVES_WatchCtl libVES_WatchCtl_User_events = {
    .field = "events",
    .details = "(vaultKey(id,type,algo,publicKey,user,creator),vaultItem(id,type,file(externals)),user,creator,session)",
    .listctl = &libVES_Event_ListCtl,
    .objfn = &libVES_Watch_objfn_Event_vkey
};


libVES_Watch *libVES_Watch_new(const libVES_WatchCtl *ctl, libVES *ves) {
    libVES_Watch *w = malloc(sizeof(libVES_Watch));
    if (!w) return NULL;
    w->ctl = ctl;
    w->ves = ves;
    w->list = NULL;
    w->lastptr = NULL;
    w->flags = 0;
    w->firstId = w->lastId = 0;
    w->tmoutfn = NULL;
    return w;
}

libVES_Watch *libVES_Watch_VaultKey_events(struct libVES *ves) {
    libVES_VaultKey *vkey = libVES_getVaultKey(ves);
    if (!vkey) return NULL;
    libVES_Watch *watch = libVES_Watch_new(&libVES_WatchCtl_VaultKey_events, ves);
    sprintf(watch->uri, "vaultKeys/%lld", vkey->id);
    return watch;
}

libVES_Watch *libVES_Watch_User_events(struct libVES *ves) {
    libVES_Watch *watch = libVES_Watch_new(&libVES_WatchCtl_User_events, ves);
    strcpy(watch->uri, "me");
    return watch;
}

libVES_Watch *libVES_Watch_Domain_events(struct libVES *ves) {
    if (!ves->external) return NULL;
    libVES_Watch *watch = libVES_Watch_new(&libVES_WatchCtl_User_events, ves);
    sprintf(watch->uri, "domains/%.48s", libVES_Ref_getDomain(ves->external));
    return watch;

}

libVES_Watch *libVES_Watch_VaultItem_events(struct libVES *ves, struct libVES_VaultItem *vitem) {
    if (!ves || !vitem) return NULL;
    libVES_Watch *watch = libVES_Watch_new(&libVES_WatchCtl_VaultItem_events, ves);
    sprintf(watch->uri, "vaultItems/%lld", vitem->id);
    return watch;
}

int libVES_Watch_start(libVES_Watch *watch, long long start) {
    if (start >= 0) return !!libVES_Watch_load(watch, start, 0, 0);
    else return !!libVES_Watch_load(watch, 0, -start, LIBVES_W_REV);
}

void **libVES_Watch_traverse(libVES_Watch *watch, int flags) {
    return watch->lastptr = (flags & LIBVES_W_REV) ? libVES_List_prev(watch->list, watch->lastptr, void) : libVES_List_next(watch->list, watch->lastptr, void);
}

libVES_List *libVES_Watch_load(libVES_Watch *watch, long long start, int ct, int flags) {
    if (!watch) return NULL;
    libVES_List_free(watch->list);
    watch->list = NULL;
    char url[480];
    int fpoll = (flags & watch->flags & LIBVES_W_POLL) && !(flags & LIBVES_W_REV);
    long long poll = fpoll ? (watch->tmoutfn ? watch->tmoutfn(watch) : LIBVES_WATCH_TMOUT) : 0;
    char *d = url;
    d += sprintf(d, "%s%s?fields=%s%s%%5B",
	(poll > 0 ? watch->ves->pollUrl : watch->ves->apiUrl),
	watch->uri,
	watch->ctl->field,
	watch->ctl->details
    );
    if (start > 0) d += sprintf(d, "%lld", start);
    d += sprintf(d, ((flags & LIBVES_W_REV) ? "-" : "%%2B"));
    if (ct > 0) d += sprintf(d, "%d", ct);
    d += sprintf(d, "%%5D");
    if (poll > 0) sprintf(d, "&poll=%d.%06d", (int)(poll / 1000000), (int)(poll % 1000000));
    jVar *res = libVES_REST(watch->ves, url, NULL);
    if (!res) return NULL;
    jVar *fld = jVar_get(res, watch->ctl->field);
    int l = jVar_count(fld);
    if (!l && !fpoll && (flags & (LIBVES_W_POLL | LIBVES_W_REV)) == LIBVES_W_POLL) {
	watch->flags |= LIBVES_W_POLL;
	poll = 1;
    }
    if (l > 0 || poll > 0) {
	watch->list = libVES_List_new(watch->ctl->listctl);
	if (flags & LIBVES_W_REV) watch->flags |= LIBVES_W_REV;
	else watch->flags &= ~LIBVES_W_REV;
	int i;
	for (i = 0; i < l; i++) {
	    void *obj = watch->ctl->objfn(watch, jVar_index(fld, i));
	    if (obj) libVES_List_push(watch->list, obj);
	}
    }
    jVar_free(res);
    return watch->list;
}

void *libVES_Watch_nextptr(libVES_Watch *watch, int flags) {
    if (!watch) return NULL;
    int back = ((flags ^ watch->flags) & LIBVES_W_REV);
    while (1) {
	if (watch->list) libVES_Watch_traverse(watch, back);
	if (watch->lastptr) break;
	if (!libVES_Watch_load(watch, ((flags & LIBVES_W_REV) ? (watch->firstId > 0 ? watch->firstId - 1 : 0) : watch->lastId + 1), 0, flags)) break;
    }
    if (watch->lastptr) {
	void *obj = *watch->lastptr;
	long long id = *((long long *)obj);
	if (flags & LIBVES_W_REV) {
	    if (id > 0) {
		if (!watch->firstId || id < watch->firstId) watch->firstId = id;
		if (!watch->lastId) watch->lastId = id;
	    }
	} else {
	    if (id > watch->lastId) watch->lastId = id;
	    if (!watch->firstId && id > 0) watch->firstId = id;
	}
	return obj;
    }
    return NULL;
}

void libVES_Watch_free(libVES_Watch *watch) {
    if (!watch) return;
    libVES_REFDN(List, watch->list);
    free(watch);
}

