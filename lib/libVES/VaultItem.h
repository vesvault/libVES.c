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
 * libVES/VaultItem.h         libVES: Vault Item object header
 *
 ***************************************************************************/

typedef struct libVES_VaultItem {
    long long int id;
    short int type;
    short int objectType;
    int flags;
    size_t len;
    char *value;
    union {
	void *object;
	struct libVES_File *file;
	struct libVES_VaultKey *vaultKey;
    };
    struct jVar *meta;
    struct jVar *entries;
    int refct;
    size_t sharelen;
    struct libVES_VaultKey *share[];
} libVES_VaultItem;

struct libVES_Ref;

#define LIBVES_VI_STRING	0
#define LIBVES_VI_FILE		1
#define LIBVES_VI_PASSWORD	2
#define LIBVES_VI_SECRET	3

#define LIBVES_SH_CLN		0x01
#define LIBVES_SH_PRI		0x02
#define LIBVES_SH_ADD		0x10
#define LIBVES_SH_UPD		0x20
#define LIBVES_SH_IGN		0x4000
#define LIBVES_SH_DEL		0x8000
#define LIBVES_SH_SET		(LIBVES_SH_ADD | LIBVES_SH_CLN)

#define LIBVES_SH_META		0x0100

extern const struct libVES_ListCtl libVES_VaultItem_ListCtl;
extern const char *libVES_VaultItem_types[];

libVES_VaultItem *libVES_VaultItem_new();
#define libVES_VaultItem_isNew(vitem)	(vitem && (vitem->flags & LIBVES_SH_ADD))
struct jVar *libVES_VaultItem_Ref_toJVar(struct libVES_Ref *ref);
struct jVar *libVES_VaultItem_toJVar(libVES_VaultItem *vitem);
libVES_VaultItem *libVES_VaultItem_fromJVar(struct jVar *data, struct libVES *ves);
void libVES_VaultItem_parseJVar(struct libVES_VaultItem *vitem, struct jVar *jvar);

/***************************************************************************
 * Load and/or create a Vault Item from ves URI
 * (ves://domain/externalId or ves:///internalId)
 ***************************************************************************/
#define libVES_VaultItem_fromURI(uri, ves)		((libVES_VaultItem *) libVES_objectFromURI(uri, ves, LIBVES_O_VITEM | LIBVES_O_GET | LIBVES_O_NEW, NULL))
#define libVES_VaultItem_loadFromURI(uri, ves)		((libVES_VaultItem *) libVES_objectFromURI(uri, ves, LIBVES_O_VITEM | LIBVES_O_GET, NULL))
#define libVES_VaultItem_createFromURI(uti, ves)	((libVES_VaultItem *) libVES_objectFromURI(uri, ves, LIBVES_O_VITEM | LIBVES_O_NEW, NULL))

/***************************************************************************
 * Get VES URI - ves://domain/externalId, use free() to deallocate
 ***************************************************************************/
char *libVES_VaultItem_toURI(libVES_VaultItem *vitem);

/***************************************************************************
 * Get internalId URI - ves:///internalId, use free() to deallocate
 ***************************************************************************/
char *libVES_VaultItem_toURIi(libVES_VaultItem *vitem);

/***************************************************************************
 * Create a new VaultItem. Use libVES_VaultItem_set*() to set the value,
 * libVES_VaultItem_entries() to share, libVES_VaultItem_post() to commit,
 * libVES_VaultItem_free() when done.
 ***************************************************************************/
libVES_VaultItem *libVES_VaultItem_create(struct libVES_Ref *ref);

/***************************************************************************
 * Returns the pointer to the raw decrypted value, not NUL terminated, the
 * length is libVES_VaultItem_getLen()
 ***************************************************************************/
const char *libVES_VaultItem_getValue(libVES_VaultItem *vitem);

/***************************************************************************
 * Returns the length of the raw decrypted value, -1 if not available
 ***************************************************************************/
int libVES_VaultItem_getLen(libVES_VaultItem *vitem);

/***************************************************************************
 * Copy the decrypted value as a string with length, use buf = NULL to
 * allocate a new buffer. Returns the buffer pointer, or NULL if not
 * available
 ***************************************************************************/
char *libVES_VaultItem_toStringl(libVES_VaultItem *vitem, size_t *len, char *buf);

/***************************************************************************
 * Set the raw content and type
 ***************************************************************************/
int libVES_VaultItem_setValue(libVES_VaultItem *vitem, size_t len, const char *value, int type);
int libVES_VaultItem_setValue0(libVES_VaultItem *vitem, size_t len, char *value, int type);

/***************************************************************************
 * A stream cipher object stored in the Vault Item
 ***************************************************************************/
struct libVES_Cipher *libVES_VaultItem_getCipher(libVES_VaultItem *vitem, struct libVES *ves);
int libVES_VaultItem_setCipher(libVES_VaultItem *vitem, struct libVES_Cipher *ci);

/***************************************************************************
 * Treat the Vault Item content as JSON string
 ***************************************************************************/
struct jVar *libVES_VaultItem_getObject(libVES_VaultItem *vitem);
int libVES_VaultItem_setObject(libVES_VaultItem *vitem, struct jVar *obj);

/***************************************************************************
 * Prepare entries to share/unshare the Vault Item with the Vault Key,
 * call libVES_VaultItem_post() to commit
 ***************************************************************************/
struct jVar *libVES_VaultItem_share(libVES_VaultItem *vitem, struct libVES_VaultKey *vkey, int flags);

/***************************************************************************
 * Prepare entries to share/unshare the Vault Item with the list of Vault Keys,
 * call libVES_VaultItem_post() to commit
 ***************************************************************************/
struct jVar *libVES_VaultItem_entries(libVES_VaultItem *vitem, struct libVES_List *share, int flags);

/***************************************************************************
 * Iterate through previously shared vault keys.
 * ptr = NULL returns the pointer to the first shared VaultKey,
 * returns NULL at the end of the share list.
 ***************************************************************************/
struct libVES_VaultKey **libVES_VaultItem_nextShare(libVES_VaultItem *vitem, struct libVES_VaultKey **ptr);

/***************************************************************************
 * Find a pointer to the shared VaultKey with the id matching vkey.
 * NULL if not found.
 ***************************************************************************/
struct libVES_VaultKey **libVES_VaultItem_findShare(libVES_VaultItem *vitem, struct libVES_VaultKey *vkey);

/***************************************************************************
 * Retrieve an existing VaultItem and decrypt the value if possible. Use
 * libVES_VaultItem_free() to deallocate. Call libVES_Ref_free(ref) before
 * deallocating the returned VaultItem.
 * Retunrs NULL if not available.
 ***************************************************************************/
libVES_VaultItem *libVES_VaultItem_get(struct libVES_Ref *ref, struct libVES *ves);

/***************************************************************************
 * Commit the changes to the VES repository. Returns true on success.
 ***************************************************************************/
int libVES_VaultItem_post(libVES_VaultItem *vitem, struct libVES *ves);

/***************************************************************************
 * Delete the VaultItem from the VES repository. Returns true on success.
 ***************************************************************************/
int libVES_VaultItem_delete(libVES_VaultItem *vitem, struct libVES *ves);

/***************************************************************************
 * List all Vault Items shared with vkey
 ***************************************************************************/
struct libVES_List *libVES_VaultItem_list(struct libVES_VaultKey *vkey);

/***************************************************************************
 * Get a Verify Token that can be used instead of libVES Session Token to
 * allow retrieving vaultEntries/vaultKey/file on the vitem
 * without granting any other permissions.
 * free() the token when done.
 * If the access needs to be restricted to creator and external only -
 * use libVES_File_fetchVerifyToken(libVES_VaultItem_getFile(vitem), ves)
 ***************************************************************************/
#define libVES_VaultItem_fetchVerifyToken(vitem, ves)	libVES_fetchVerifyToken("vaultItems", libVES_VaultItem_getId(vitem), ves)

/***************************************************************************
 * Send a GET request to the external url with VES authorization
 * X-VES-Authorization: vaultItem.{vitem->id}.{verifyToken}
 * Return jVar response on success, NULL on error, use libVES_getError(ves)
 * assign the http status code to *pcode if not NULL
 ***************************************************************************/
struct jVar *libVES_VaultItem_VESauthGET(struct libVES_VaultItem *vitem, struct libVES *ves, const char *url, long *pcode);

/***************************************************************************
 * Get the item metadata jVar object, do not deallocate. To alter the
 * existing metadata, add/remove keys on the returned jVar, then call
 * libVES_VaultItem_setMeta() with the same jVar object
 ***************************************************************************/
struct jVar *libVES_VaultItem_getMeta(libVES_VaultItem *vitem);

/***************************************************************************
 * Set the item metadata jVar object, do not deallocate meta after this call
 ***************************************************************************/
int libVES_VaultItem_setMeta(libVES_VaultItem *vitem, struct jVar *meta);

const char *libVES_VaultItem_typeStr(int type);
int libVES_VaultItem_typeFromStr(const char *str);

int libVES_VaultItem_isDeleted(libVES_VaultItem *vitem);
int libVES_VaultItem_force(libVES_VaultItem *vitem);
long long libVES_VaultItem_getId(libVES_VaultItem *vkey);
int libVES_VaultItem_getType(libVES_VaultItem *vitem);
struct libVES_User *libVES_VaultItem_getCreator(libVES_VaultItem *vitem);
struct libVES_Ref *libVES_VaultItem_getExternal(libVES_VaultItem *vitem);
struct libVES_File *libVES_VaultItem_getFile(libVES_VaultItem *vitem);
struct libVES_VaultKey *libVES_VaultItem_getVaultKey(libVES_VaultItem *vitem);

/***************************************************************************
 * App level refcount management. After calling refup() any calls to
 * *_free() on obj will be ignored. Call refdn() to automatically
 * deallocate the object.
 * refup() returns obj, refdn returns obj or NULL if the object have been
 * deallocated by the call.
 * Both calls are NULL safe.
 ***************************************************************************/
libVES_VaultItem *libVES_VaultItem_refup(libVES_VaultItem *obj);
libVES_VaultItem *libVES_VaultItem_refdn(libVES_VaultItem *obj);

void libVES_VaultItem_free(libVES_VaultItem *vitem);

