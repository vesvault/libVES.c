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
 * libVES/List.c              libVES: Dynamic list
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "List.h"

const libVES_ListCtl libVES_ListCtl_NULL = { .cmpfn = NULL, .freefn = NULL };

libVES_List *libVES_List_new(const struct libVES_ListCtl *ctl) {
    libVES_List *lst = malloc(sizeof(libVES_List));
    lst->max = lst->len = 0;
    lst->list = NULL;
    lst->ctl = ctl;
    return lst;
}

void *libVES_List_add(libVES_List *lst, void *entry, int pos) {
    if (!lst || !entry) return NULL;
    int i;
    int (*cmpfn)(void *, void *) = lst->ctl->cmpfn;
    void *v;
    for (i = 0; i < lst->len; i++) {
	v = lst->list[i];
	if (v == entry) return entry;
	else if (cmpfn && !cmpfn(entry, v)) {
	    if (lst->ctl->freefn) {
		lst->ctl->freefn(v);
		if (v != lst->list[i]) continue;
	    }
	    return lst->list[i] = entry;
	}
    }
    if (lst->len >= lst->max) {
	if (lst->max) lst->list = realloc(lst->list, (lst->max = lst->max > 256 ? lst->max : 256) * 2 * sizeof(lst->list[0]));
	else {
	    void **newlst = malloc((lst->max = lst->len + 8) * sizeof(lst->list[0]));
	    if (lst->len) memcpy(newlst, lst->list, lst->len * sizeof(lst->list[0]));
	    lst->list = newlst;
	}
    }
    if (pos < 0) {
	pos += lst->len + 1;
	if (pos < 0) pos = 0;
    } else {
	if (pos > lst->len) pos = lst->len;
    }
    memmove(lst->list + pos + 1, lst->list + pos, (lst->len++ - pos) * sizeof(lst->list[0]));
    return lst->list[pos] = entry;
}

void libVES_List_remove(libVES_List *lst, void *entry) {
    if (!lst || !entry) return;
    int i;
    int (*cmpfn)(void *, void *) = lst->ctl->cmpfn;
    void *v;
    for (i = 0; i < lst->len; i++) {
	v = lst->list[i];
	if (v != entry && (!cmpfn || cmpfn(entry, v))) continue;
	if (lst->ctl->freefn) lst->ctl->freefn(v);
	if (v != lst->list[i]) break;
	memmove(lst->list + i, lst->list + i + 1, (--lst->len - i) * sizeof(lst->list[0]));
	if (!lst->len) {
	    free(lst->list);
	    lst->list = NULL;
	    lst->max = 0;
	}
	break;
    }
}

void *libVES_List_find(libVES_List *lst, void *entry) {
    if (!lst || !entry) return NULL;
    int i;
    int (*cmpfn)(void *, void *) = lst->ctl->cmpfn;
    for (i = 0; i < lst->len; i++) if (lst->list[i] == entry || (cmpfn && !cmpfn(entry, lst->list[i]))) return lst->list[i];
    return NULL;
}

void libVES_List_free(libVES_List *lst) {
    if (!lst) return;
    int i;
    if (lst->ctl->freefn) for (i = 0; i < lst->len; i++) lst->ctl->freefn(lst->list[i]);
    free(lst->list);
    free(lst);
}
