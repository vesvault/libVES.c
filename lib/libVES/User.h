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
 * libVES/User.h              libVES: User object header
 *
 ***************************************************************************/

typedef struct libVES_User {
    long long int id;
    char *email;
    char *firstName;
    char *lastName;
    int refct;
} libVES_User;
struct libVES_VaultKey;
struct libVES;

/***************************************************************************
 * Parse the userRef part of VES URI (ves://domain/externalId/userRef)
 ***************************************************************************/
libVES_User *libVES_User_fromPath(const char **path);

libVES_User *libVES_User_fromJVar(struct jVar *data);
struct jVar *libVES_User_toJVar(libVES_User *user);
struct libVES_List *libVES_User_vaultKeys2(libVES_User *user, struct libVES_List *lst, struct libVES *ves, const char *reqs, const char *rsps);

/***************************************************************************
 * Primary Vault Keys, current and shadow.
 * Push to lst, or to a new Vault Key list lst == NULL.
 ***************************************************************************/
#define libVES_User_activeVaultKeys(user, lst, ves)	libVES_User_vaultKeys2(user, lst, ves, "users?fields=activeVaultKeys(id,type,algo,publicKey)", "activeVaultKeys")

/***************************************************************************
 * Vault Keys for the user.
 * Push to lst, or to a new Vault Key list lst == NULL.
 ***************************************************************************/
#define libVES_User_vaultKeys(user, lst, ves)	libVES_User_vaultKeys2(user, lst, ves, "users?fields=vaultKeys(id,type,algo,publicKey,privateKey)", "vaultKeys")

/***************************************************************************
 * Authenticate using VESvault password, populate sesstkn,
 * return current primary Vault Key
 ***************************************************************************/
struct libVES_VaultKey *libVES_User_primary(libVES_User *user, const char *passwd, char **sesstkn, struct libVES *ves);

libVES_User *libVES_User_loadFields(libVES_User *user, struct libVES *ves);
#define libVES_User_getId(user)			((user) ? (user)->id : 0)
#define libVES_User_getEmail(user)		((user) ? (user)->email : NULL)
#define libVES_User_getFirstName(user)		((user) ? (user)->firstName : NULL)
#define libVES_User_getLastName(user)		((user) ? (user)->lastName : NULL)
char *libVES_User_getName1(libVES_User *user);
libVES_User *libVES_User_copy(libVES_User *user);
void libVES_User_free(libVES_User *user);
