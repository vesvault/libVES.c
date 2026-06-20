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
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
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
void **libVES_List_nextptr(struct libVES_List *lst, void **ptr);
void **libVES_List_prevptr(struct libVES_List *lst, void **ptr);
#define libVES_List_next(lst, ptr, type)	((type **)libVES_List_nextptr(lst, (void **)ptr))
#define libVES_List_prev(lst, ptr, type)	((type **)libVES_List_prevptr(lst, (void **)ptr))
void libVES_List_free(struct libVES_List *lst);

#define libVES_List_STATIC(var, ctrl, length, ...)	const void *var ## LST[length] = { __VA_ARGS__ }; libVES_List var = { .ctl = (ctrl), .len = length, .max = 0, .list = (void **) var ## LST }
#define libVES_List_STATIC0(var, ctrl)			libVES_List var = { .ctl = (ctrl), .len = 0, .max = 0, .list = NULL }
