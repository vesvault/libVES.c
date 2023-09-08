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
 * libVES/Watch.h              libVES: Event Watch
 *
 ***************************************************************************/

struct libVES;
struct libVES_VaultItem;
struct libVES_Event;
struct jVar;

typedef struct libVES_Watch {
    struct libVES *ves;
    struct libVES_List *list;
    void **lastptr;
    long long firstId;
    long long lastId;
    char uri[64];
    const struct libVES_WatchCtl *ctl;
    long long (* tmoutfn)(struct libVES_Watch *);
    int flags;
} libVES_Watch;

typedef struct libVES_WatchCtl {
    const char *field;
    const char *details;
    void *(* objfn)(struct libVES_Watch *, struct jVar *);
    const struct libVES_ListCtl *listctl;
} libVES_WatchCtl;

#define	LIBVES_W_REV		0x01
#define	LIBVES_W_POLL		0x02
#define	LIBVES_W_NOLOAD		0x04

#define	LIBVES_WATCH_TMOUT	900000000

libVES_Watch *libVES_Watch_new(const struct libVES_WatchCtl *ctl, struct libVES *ves);

libVES_Watch *libVES_Watch_VaultKey_events(struct libVES *ves);
libVES_Watch *libVES_Watch_User_events(struct libVES *ves);
libVES_Watch *libVES_Watch_Domain_events(struct libVES *ves);
libVES_Watch *libVES_Watch_VaultItem_events(struct libVES *ves, struct libVES_VaultItem *vitem);

int libVES_Watch_start(libVES_Watch *watch, long long start);
struct libVES_List *libVES_Watch_load(libVES_Watch *watch, long long start, int ct, int flags);

void *libVES_Watch_nextptr(libVES_Watch *watch, int flags);
#define libVES_Watch_prevptr(watch, flags)	libVES_Watch_nextptr(watch, (flags | LIBVES_W_REV))

#define	libVES_Watch_next(watch, flags, type)	((type *)libVES_Watch_nextptr(watch, flags))
#define	libVES_Watch_prev(watch, flags, type)	((type *)libVES_Watch_prevptr(watch, flags))

void libVES_Watch_free(libVES_Watch *watch);
