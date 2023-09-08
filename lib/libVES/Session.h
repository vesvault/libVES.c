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
 * libVES/Session.h           libVES: Session info object header
 *
 ***************************************************************************/

typedef struct libVES_Session {
    long long int id;
    long long createdAt;
    long long expiresAt;
    long long accessAt;
    char *remote;
    char *userAgent;
    struct libVES_VaultKey *vkey;
    struct libVES_User *user;
    int refct;
} libVES_Session;

struct libVES;
struct jVar;

libVES_Session *libVES_Session_fromJVar(struct jVar *data, struct libVES *ves);
void libVES_Session_parseJVar(libVES_Session *ses, struct jVar *data, struct libVES *ves);

long long int libVES_Session_getId(libVES_Session *ses);
struct libVES_VaultKey *libVES_Session_getVaultKey(libVES_Session *ses);
struct libVES_User *libVES_Session_getUser(libVES_Session *ses);
long long libVES_Session_getCreatedAt(libVES_Session *ses);
long long libVES_Session_getExpiresAt(libVES_Session *ses);
long long libVES_Session_getAccessAt(libVES_Session *ses);
const char *libVES_Session_getRemote(libVES_Session *ses);
const char *libVES_Session_getUserAgent(libVES_Session *ses);

void libVES_Session_free(libVES_Session *ses);

/***************************************************************************
 * App level refcount management. After calling refup() any calls to
 * *_free() on obj will be ignored. Call refdn() to automatically
 * deallocate the object.
 * refup() returns obj, refdn returns obj or NULL if the object have been
 * deallocated by the call.
 * Both calls are NULL safe.
 ***************************************************************************/
libVES_Session *libVES_Session_refup(libVES_Session *obj);
libVES_Session *libVES_Session_refdn(libVES_Session *obj);
