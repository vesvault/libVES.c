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
