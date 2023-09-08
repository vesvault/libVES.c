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
 * libVES/Event.h             libVES: Event object header
 *
 ***************************************************************************/

typedef struct libVES_Event {
    long long int id;
    long long recordedAt;
    struct libVES_VaultKey *vkey;
    struct libVES_VaultItem *vitem;
    struct libVES_User *user;
    struct libVES_User *creator;
    struct libVES_Session *session;
    short int type;
    int refct;
} libVES_Event;

struct libVES;
struct jVar;

#define	LIBVES_EO		0xf0
#define	LIBVES_EO_USER		0x10
#define	LIBVES_EO_KEY		0x20
#define	LIBVES_EO_ITEM		0x30
#define	LIBVES_EO_SESSION	0x40
#define	LIBVES_EO_ENTRY		0x50
#define	LIBVES_EO_DOMAIN	0x60

#define	LIBVES_EA		0x0f
#define	LIBVES_EA_CREATED	0x01
#define	LIBVES_EA_UPDATED	0x02
#define	LIBVES_EA_DELETED	0x03
#define	LIBVES_EA_LOST		0x04
#define	LIBVES_EA_LISTENING	0x05
#define	LIBVES_EA_PENDING	0x06

extern const struct libVES_ListCtl libVES_Event_ListCtl;

libVES_Event *libVES_Event_fromJVar(struct jVar *data, struct libVES *ves);
void libVES_Event_parseJVar(libVES_Event *event, struct jVar *data, struct libVES *ves);

long long int libVES_Event_getId(libVES_Event *event);
short int libVES_Event_getType(libVES_Event *event);
struct libVES_VaultKey *libVES_Event_getVaultKey(libVES_Event *event);
struct libVES_VaultItem *libVES_Event_getVaultItem(libVES_Event *event, struct libVES *ves);
struct libVES_User *libVES_Event_getUser(libVES_Event *event);
struct libVES_User *libVES_Event_getCreator(libVES_Event *event);
struct libVES_Session *libVES_Event_getSession(libVES_Event *event);
long long libVES_Event_getRecordedAt(libVES_Event *event);

short int libVES_Event_parseType(const char *type, int len);
char *libVES_Event_typeStr(short int type, char *buf);

void libVES_Event_free(libVES_Event *event);
