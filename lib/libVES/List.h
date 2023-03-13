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
 * libVES/List.h              libVES: Dynamic list header
 *
 ***************************************************************************/
typedef struct libVES_List {
    const struct libVES_ListCtl *ctl;
    void **list;
    size_t len;
    size_t max;
    int refct;
} libVES_List;

typedef struct libVES_ListCtl {
    int (*cmpfn)(void *, void *);
    void (*freefn)(void *);
} libVES_ListCtl;

extern const libVES_ListCtl libVES_ListCtl_NULL;

libVES_List *libVES_List_new(const struct libVES_ListCtl *ctl);
void *libVES_List_add(struct libVES_List *lst, void *entry, int pos);
void libVES_List_remove(struct libVES_List *lst, void *entry);
#define libVES_List_unshift(lst, entry)		libVES_List_add(lst, entry, 0)
#define libVES_List_push(lst, entry)		libVES_List_add(lst, entry, -1)
void *libVES_List_find(struct libVES_List *lst, void *entry);
void libVES_List_free(struct libVES_List *lst);

#define libVES_List_STATIC(var, ctrl, length, ...)	const void *var ## LST[length] = { __VA_ARGS__ }; libVES_List var = { .ctl = (ctrl), .len = length, .max = 0, .list = (void **) var ## LST }
#define libVES_List_STATIC0(var, ctrl)			libVES_List var = { .ctl = (ctrl), .len = 0, .max = 0, .list = NULL }
