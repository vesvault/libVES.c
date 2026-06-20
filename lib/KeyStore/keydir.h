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
 * keydir.c                       libVES: Local directory key storage
 *
 ***************************************************************************/

struct libVES_KeyStore;

struct libVES_KeyStore_keydir {
    const char **(* pathfn)(struct libVES_KeyStore *ks);
    void (* cleanfn)(struct libVES_KeyStore *ks);
    struct {
	int (* getfn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, char *val, int maxlen, int flags);
	int (* putfn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, const char *val, int len, int flags);
	int (* deletefn)(struct libVES_KeyStore *ks, const char *domain, const char *extid, int flags);
    } chain;
};


int libVES_KeyStore_keydir_get(struct libVES_KeyStore *ks, const char *domain, const char *extid, char *val, int maxlen, int flags);
int libVES_KeyStore_keydir_put(struct libVES_KeyStore *ks, const char *domain, const char *extid, const char *val, int len, int flags);
int libVES_KeyStore_keydir_delete(struct libVES_KeyStore *ks, const char *domain, const char *extid, int flags);
#define libVES_KeyStore_keydir_cleanup(ks)	((struct libVES_KeyStore_keydir *)((ks)->store))->cleanfn(ks)
