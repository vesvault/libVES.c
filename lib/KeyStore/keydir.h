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
