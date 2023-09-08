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
 * VESlocker.h                   libVES: Secure key storage
 *
 ***************************************************************************/

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
int VESlocker_encval(struct VESlocker *vl, const char *val, size_t len, char *ctext);
int VESlocker_decval(struct VESlocker *vl, const char *ctext, char *val);
char *VESlocker_encrypt(struct VESlocker *vl, const char *data, size_t len, const char *pin, char *vlentry);
int VESlocker_decrypt(struct VESlocker *vl, const struct VESlocker_entry *e, const char *pin, char **pval);
void VESlocker_free(struct VESlocker *vl);
