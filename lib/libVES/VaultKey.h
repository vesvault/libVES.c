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
 * libVES/VaultKey.h          libVES: Vault Key object header
 *
 ***************************************************************************/

typedef struct libVES_VaultKey {
    long long int id;
    const struct libVES_KeyAlgo *algo;
    int type;
    struct libVES *ves;
    struct libVES_User *user;
    char *publicKey;
    void *pPub;
    char *privateKey;
    void *pPriv;
    struct libVES_Ref *external;
    struct libVES_VaultItem *vitem;
    struct jVar *entries;
    char *appUrl;
    int refct;
} libVES_VaultKey;

typedef struct libVES_veskey {
    size_t keylen;
    char veskey[];
} libVES_veskey;

struct jVar;

#define LIBVES_VK_CURRENT	0
#define LIBVES_VK_SHADOW	1
#define LIBVES_VK_TEMP		2
#define LIBVES_VK_LOST		3
#define LIBVES_VK_SECONDARY	4
#define LIBVES_VK_RECOVERY	5
#define LIBVES_VK_PENDING	6
#define LIBVES_VK_DELETED	7

#ifndef LIBVES_MAXLEN_KEY
#define LIBVES_MAXLEN_KEY	65535
#endif
#ifndef LIBVES_MAXLEN_ENCDATA
#define LIBVES_MAXLEN_ENCDATA	65535
#endif

typedef struct libVES_KeyAlgo {
    char *str;
    char *name;
    int len;
    libVES_VaultKey *(*newfn)(const struct libVES_KeyAlgo *algo, void *pkey, struct libVES_veskey *veskey, struct libVES *ves);
    char *(*pub2strfn)(libVES_VaultKey *vkey, void *pkey);
    void *(*str2pubfn)(libVES_VaultKey *vkey, const char *str);
    char *(*priv2strfn)(libVES_VaultKey *vkey, void *pkey, struct libVES_veskey *veskey);
    void *(*str2privfn)(libVES_VaultKey *vkey, const char *str, struct libVES_veskey *veskey);
    void *(*priv2pubfn)(libVES_VaultKey *vkey, void *pkey);
    int (*encfn)(libVES_VaultKey *vkey, const char *plaintext, size_t *ptlen, char *ciphertext, char *key, size_t *keylen);
    int (*decfn)(libVES_VaultKey *vkey, const char *ciphertext, size_t *ctlen, char *plaintext, char *key, size_t *keylen);
    int (*signfn)(libVES_VaultKey *vkey, const char *plaintext, size_t ptlen, char *signature);
    int (*verifyfn)(libVES_VaultKey *vkey, const char *plaintext, size_t ptlen, const char *signature, size_t sglen);
    void (*lockfn)(libVES_VaultKey *vkey);
    int (*dumpfn)(libVES_VaultKey *vkey, int fd, int flags);
    void (*freefn)(libVES_VaultKey *vkey);
    void *(*pkeygenfn)(const struct libVES_KeyAlgo *algo, const char *algostr);
    void (*pkeyfreefn)(const struct libVES_KeyAlgo *algo, void *pkey);
    int (*methodstrfn)(const struct libVES_KeyAlgo *algo, char *buf, size_t buflen, int idx);
} libVES_KeyAlgo;

#define libVES_KeyAlgo_pseudo(newfn_ptr)		(*((libVES_KeyAlgo *) (((char *) &newfn_ptr) - offsetof(libVES_KeyAlgo, newfn))))
#define libVES_KeyAlgo_callable(algo, func)		(algo->len >= offsetof(libVES_KeyAlgo, func) + sizeof((algo)->func) && (algo)->func)
#define libVES_KeyAlgo_pkeygen(algo, algostr)		(algo)->pkeygenfn(algo, algostr)
#define libVES_KeyAlgo_pkeyfree(algo, algostr)		(algo)->pkeyfreefn(algo, algostr)
#define libVES_KeyAlgo_methodstr(algo, buf, buflen, idx)	(libVES_KeyAlgo_callable(algo, methodstrfn) ? (algo)->methodstrfn(algo, buf, buflen, idx) : -1)

extern const char *libVES_VaultKey_types[];
extern struct libVES_List libVES_VaultKey_algos;

/***************************************************************************
 * Create a Vault Key from private key structure pkey,
 * generate a new private key if pkey == NULL
 ***************************************************************************/
libVES_VaultKey *libVES_VaultKey_new(int type, const struct libVES_KeyAlgo *algo, void *pkey, struct libVES_veskey *veskey, struct libVES *ves);

#define libVES_VaultKey_isNew(vkey)		(vkey && !vkey->id)
libVES_VaultKey *libVES_VaultKey_fromJVar(struct jVar *j_vkey, struct libVES *ves);
void libVES_VaultKey_parseJVar(struct libVES_VaultKey *vkey, struct jVar *jvar);

/***************************************************************************
 * Parse a Vault Key from VES URI,
 * ves://domain/externalId/[userRef] | ves:///internalId/ | ves:////userRef
 ***************************************************************************/
#define libVES_VaultKey_fromURI(uri, ves)	((libVES_VaultKey *) libVES_objectFromURI(uri, ves, LIBVES_O_VKEY | LIBVES_O_GET | LIBVES_O_NEW, NULL))

/***************************************************************************
 * Push Vault Key(s) parsed from the URI into lst,
 * if lst == NULL a new list will be created
 * return lst, or NULL on error
 * One Vault Key will be matched for an App Vault or internalId,
 * up to 2 (current + shadow) for a Primary Vault (ves:////userRef)
 ***************************************************************************/
struct libVES_List *libVES_VaultKey_listFromURI(const char **path, struct libVES *ves, struct libVES_List *lst);

struct jVar *libVES_VaultKey_toJVar(libVES_VaultKey *vkey);

/***************************************************************************
 * Get VES URI - ves://domain/externalId/, use free() to deallocate
 ***************************************************************************/
char *libVES_VaultKey_toURI(libVES_VaultKey *vkey);

/***************************************************************************
 * Get internalId URI - ves:///internalId/, use free() to deallocate
 ***************************************************************************/
char *libVES_VaultKey_toURIi(libVES_VaultKey *vkey);

/***************************************************************************
 * Retrieve or create a Vault Key from ref and optional user
 * ref and user may get strong refcounted by the resulting libVES_VaultKey,
 * use libVES_Ref_free(ref), libVES_User_free(user) before the resulting
 * libVES_VaultKey is deallocated.
 ***************************************************************************/
#define libVES_VaultKey_get(ref, ves, user)	libVES_VaultKey_get2(ref, ves, user, NULL, LIBVES_O_GET | LIBVES_O_NEW)

libVES_VaultKey *libVES_VaultKey_free_ref_user(libVES_VaultKey *vkey, struct libVES_Ref *ref, struct libVES_User *user);

libVES_VaultKey *libVES_VaultKey_get2(struct libVES_Ref *ref, struct libVES *ves, struct libVES_User *user, char **sesstkn, int flags);
libVES_VaultKey *libVES_VaultKey_create(struct libVES_Ref *ref, struct libVES *ves, struct libVES_User *user);
libVES_VaultKey *libVES_VaultKey_createFrom(libVES_VaultKey *vkey);
struct libVES_VaultItem *libVES_VaultKey_propagate(libVES_VaultKey *vkey);

/***************************************************************************
 * Unlock the Vault Key using the veskey.
 * If veskey == NULL - attempt to unlock indirectly
 * using libVES_VaultKey_getVESkey()
 * a VESkey stored
 * in an associated Vault Item.
 ***************************************************************************/
void *libVES_VaultKey_unlock(libVES_VaultKey *vkey, struct libVES_veskey *veskey);

/***************************************************************************
 * Lock the Vault Key, wipe all private data from memory.
 ***************************************************************************/
void libVES_VaultKey_lock(libVES_VaultKey *vkey);

/***************************************************************************
 * Retrieve a VESkey from an associated Vault Item if possible.
 ***************************************************************************/
struct libVES_veskey *libVES_VaultKey_getVESkey(libVES_VaultKey *vkey);

/***************************************************************************
 * Decrypt the Vault Item content. Return decrypted length, or -1 on error.
 ***************************************************************************/
int libVES_VaultKey_decrypt(libVES_VaultKey *vkey, const char *ciphertext, char **plaintext);

/***************************************************************************
 * Encrypt the Vault Item content, return base64 encoded encrypted string
 * or NULL on error.
 ***************************************************************************/
char *libVES_VaultKey_encrypt(libVES_VaultKey *vkey, const char *plaintext, size_t ptlen);

/***************************************************************************
 * Re-encrypt the entries for all Vault Items from fromVkey to vkey
 ***************************************************************************/
struct jVar *libVES_VaultKey_rekeyFrom(libVES_VaultKey *vkey, libVES_VaultKey *fromVkey, int flags);

/***************************************************************************
 * Find an active Vault Key for a Vault associated with vkey.
 * If exists and is different from vkey - re-encrypt the entries for all
 * Vault Items from vkey to active key. Return true if successful.
 ***************************************************************************/
int libVES_VaultKey_rekey(libVES_VaultKey *vkey);

/***************************************************************************
 * Try to apply the unlocked vkey to the associated libVES instance,
 * either by rekeying it, or by setting as the vaultKey on libVES.
 * Intended for unlocked temp keys.
 * If true - applied successfully, do NOT alter or deallocate vkey.
 * Otherwise - vkey cannot be applied, deallocate as usual.
 ***************************************************************************/
int libVES_VaultKey_apply(libVES_VaultKey *vkey);

int libVES_VaultKey_post(libVES_VaultKey *vkey);
int libVES_VaultKey_typeFromStr(const char *str);
const char *libVES_VaultKey_typeStr(int type);
const libVES_KeyAlgo *libVES_VaultKey_algoFromStr(const char *str);
#define libVES_VaultKey_algoStr(algo)		((algo) ? (algo)->str : NULL)
#define libVES_VaultKey_getId(vkey)		((vkey) ? (vkey)->id : 0)
#define libVES_VaultKey_getType(vkey)		((vkey) ? (vkey)->type : -1)
#define libVES_VaultKey_getAlgo(vkey)		((vkey) ? (vkey)->algo : NULL)
#define libVES_VaultKey_getPublicKey(vkey)	((vkey) ? (vkey)->publicKey : NULL)

/***************************************************************************
 * Encrypted private key (PEM), load from the API if not loaded yet.
 * Do not deallocate.
 ***************************************************************************/
char *libVES_VaultKey_getPrivateKey(libVES_VaultKey *vkey);

/***************************************************************************
 * The private key (PEM), decrypted if the Vault Key is unlocked,
 * encrypted otherwise. Use free() to deallocate.
 ***************************************************************************/
char *libVES_VaultKey_getPrivateKey1(libVES_VaultKey *vkey);

#define libVES_VaultKey_getExternal(vkey)	((vkey) ? (vkey)->external : NULL)
struct libVES_User *libVES_VaultKey_getUser(libVES_VaultKey *vkey);

/***************************************************************************
 * Output the algorithm specific human readable key info to fd.
 ***************************************************************************/
int libVES_VaultKey_dump(libVES_VaultKey *vkey, int fd, int flags);

/***************************************************************************
 * App URL for a new temp key, to be sent in the notification email
 ***************************************************************************/
int libVES_VaultKey_setAppUrl(libVES_VaultKey *vkey, const char *url);

void libVES_VaultKey_free(libVES_VaultKey *vkey);

/***************************************************************************
 * Unlike stream ciphers, Vault Key algorithms should be treated
 * conservatively to minimize cross-platform issues.
 ***************************************************************************/
void libVES_VaultKey_registerAlgo(const struct libVES_KeyAlgo *algo);

extern const struct libVES_ListCtl libVES_VaultKey_ListCtl;
extern const struct libVES_ListCtl libVES_VaultKey_ListCtlU;

/***************************************************************************
 * VESkey, a binary with length
 * Generate a random one if veskey == NULL, see libVES_veskey_generate()
 ***************************************************************************/
libVES_veskey *libVES_veskey_new(size_t keylen, const char *veskey);

/***************************************************************************
 * Generate a random ascii VESkey
 * The character frequency is biased to improve human readability,
 * the entropy is ~ 203 bit for keylen == 32 (vs 256 bit for a random binary)
 * Character frequency graph:
 * https://i.imgur.com/o2oTDLz.png (credits: https://reddit.com/u/skeeto)
 ***************************************************************************/
#define libVES_veskey_generate(keylen)		libVES_veskey_new(keylen, NULL)

void libVES_veskey_free(libVES_veskey *veskey);
