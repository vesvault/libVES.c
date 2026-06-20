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
