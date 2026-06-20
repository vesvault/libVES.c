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
 * VESlocker.h                   libVES: Secure key storage
 *
 ***************************************************************************/

#include <stddef.h>

#define	VESLOCKER_E_OK		0
#define	VESLOCKER_E_LIB		-1
#define	VESLOCKER_E_BUF		-2
#define	VESLOCKER_E_API		-3
#define	VESLOCKER_E_CRYPTO	-4
#define	VESLOCKER_E_RETRY	-40

#define	VESlocker_idsize	32
#define	VESlocker_seedsize	32
#define	VESlocker_chsize	32
#define	VESlocker_keysize	32
#define	VESlocker_bufsize	libVES_b64encsize(VESlocker_keysize)
#define	VESlocker_gcmsize	16
#define	VESlocker_encsize(vl, len)	(strlen(vl->apiUrl) + libVES_b64encsize(VESlocker_idsize) + libVES_b64encsize(VESlocker_seedsize) + libVES_b64encsize(len + VESlocker_gcmsize) + 1)
#define	VESlocker_decsize(e)		(libVES_b64decsize(strlen(e->value)))

typedef struct VESlocker {
    const char *apiUrl;
    char *allocurl;
    void *curl;
    void (* httpInitFn)(struct VESlocker *);
    void *ref;
    struct {
	char seed[VESlocker_seedsize];
	char key[VESlocker_keysize];
    } enc;
    struct {
	char seed[VESlocker_seedsize];
	char key[VESlocker_keysize];
    } dec;
    int error;
    long httpcode;
    long retry;
} VESlocker;

typedef struct VESlocker_entry {
    char *url;
    char *entryid;
    char *seed;
    char *value;
    char *extra;
    char data[0];
} VESlocker_entry;


struct VESlocker *VESlocker_new(const char *url);
struct VESlocker_entry *VESlocker_entry_parse(const char *vlentry);
#define	VESlocker_entry_free(e)		free(e)
int VESlocker_getkey(struct VESlocker *vl, const char *entryid, const char *seed, const char *pin, char *key);
int VESlocker_getkey_n(struct VESlocker *vl, const char *entryid, const char *seed, size_t seedlen, const char *pin, char *key);
int VESlocker_encval(struct VESlocker *vl, const char *val, size_t len, char *ctext);
int VESlocker_decval(struct VESlocker *vl, const char *ctext, char *val);
char *VESlocker_encrypt(struct VESlocker *vl, const char *data, size_t len, const char *pin, char *vlentry);
int VESlocker_decrypt(struct VESlocker *vl, const struct VESlocker_entry *e, const char *pin, char **pval);
void VESlocker_free(struct VESlocker *vl);
