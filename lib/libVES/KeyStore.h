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
 * KeyStore.h                    libVES: Local key storage
 *
 ***************************************************************************/


#define	LIBVES_KS_NOPIN		0x01
#define	LIBVES_KS_NOSYNC	0x02
#define	LIBVES_KS_SAVE		0x04
#define	LIBVES_KS_PERSIST	0x08
#define	LIBVES_KS_SESS		0x10
#define	LIBVES_KS_RESYNC	0x20
#define	LIBVES_KS_FORGET	0x40
#define	LIBVES_KS_PRIMARY	0x80
#define	LIBVES_KS_ELEVATE	0x0100

struct libVES_KeyStore_dialog;
struct libVES_Ref;
struct libVES_KeyAlgo;

typedef struct libVES_KeyStore {
    int (* getfn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, char *val, int maxlen, int flags);
    int (* putfn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, const char *val, int len, int flags);
    int (* deletefn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, int flags);
    void *(* dialogfn)(struct libVES_KeyStore_dialog *dlg);
    void *(* dialogcb)(struct libVES_KeyStore_dialog *dlg);
    const struct libVES_KeyStore_api *api;
    void *store;
    void *ctl;
    /* Key algo for the ephemeral e2ee exchange key. NULL = ECDH default. */
    const struct libVES_KeyAlgo *keyAlgo;
} libVES_KeyStore;

#define	LIBVES_KSD_INIT		0
#define	LIBVES_KSD_OPEN		1
#define	LIBVES_KSD_ERROR	2
#define	LIBVES_KSD_CLOSE	3
#define	LIBVES_KSD_EXPIRE	4
#define	LIBVES_KSD_DONE		15
#define	LIBVES_KSD_PIN		16
#define	LIBVES_KSD_PINRETRY	17
#define	LIBVES_KSD_SYNC		32
#define	LIBVES_KSD_NOUSER	33

typedef struct libVES_KeyStore_dialog {
    int len;
    int state;
    int retry;
    int flags;
    struct libVES_KeyStore *ks;
    struct libVES *ves;
    const struct libVES_KeyStore_api *api;
    void *ref;
    const char *domain;
    const char *extid;
    const char *email;
    const char *syncode;
    char *pin;
    int pinmax;
} libVES_KeyStore_dialog;

struct libVES_KeyStore_api {
    const char *locker;
    const char *msg;
    const char *exportkey;
    const char *importdone;
};

extern struct libVES_KeyStore_api libVES_KeyStore_api_default;


#define LIBVES_KEYSTORE_EXT2(name)	libVES_KeyStore_ ## name
#define LIBVES_KEYSTORE_EXT(name)	LIBVES_KEYSTORE_EXT2(name)
#ifdef LIBVES_KEYSTORE
extern struct libVES_KeyStore LIBVES_KEYSTORE_EXT(LIBVES_KEYSTORE);
#define libVES_KeyStore_default &LIBVES_KEYSTORE_EXT(LIBVES_KEYSTORE)
#endif


/***************************************************************************
 * Unlock ves using ks libVES_KeyStore module. Flags are LIBVES_KS_*
 * Set ks = NULL to use the default keystore.
 ***************************************************************************/
struct libVES *libVES_KeyStore_unlock(struct libVES_KeyStore *ks, struct libVES *ves, int flags);

/***************************************************************************
 * Save an externally supplied key identified by ref in the keystore ks.
 * Set ks = NULL to use the default keystore.
 ***************************************************************************/
int libVES_KeyStore_savekey(struct libVES_KeyStore *ks, const struct libVES_Ref *ref, size_t keylen, const char *key);
