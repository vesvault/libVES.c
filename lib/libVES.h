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
 * libVES.h                   libVES: Main header
 *
 ***************************************************************************/
#define LIBVES_VERSION_NUMBER	0x01020800L
#define LIBVES_VERSION_CODE	"1.28"
#define LIBVES_VERSION_STR	"libVES.c " LIBVES_VERSION_CODE " (c) 2018 - 2024 VESvault Corp"
#define LIBVES_VERSION_SHORT	"libVES/" LIBVES_VERSION_CODE

struct libVES_Ref;
struct libVES_User;
struct jVar;
struct libVES_veskey;

typedef struct libVES {
    const char *apiUrl;
    const char *appName;
    struct libVES_Ref *external;
    char *sessionToken;
    struct libVES_VaultKey *vaultKey;
    struct libVES_User *me;
    struct libVES_VaultKey *(*genVaultKeyFn)(struct libVES *ves, int type, struct libVES_Ref *ref, struct libVES_User *user);
    void (*attnFn)(struct libVES *ves, struct jVar *attn);
    struct CURL *curl;
    void (*httpInitFn)(struct libVES *ves);
    const char *errorMsg;
    char *errorBuf;
    const struct libVES_CiAlgo *cipherAlgo;
    const struct libVES_KeyAlgo *keyAlgo;
    struct libVES_List *unlockedKeys;
    short int veskeyLen;
    short int error;
    char debug;
    unsigned short int sessionTimeout;
    long long sessionExpire;
    const char *pollUrl;
    void *ref;
} libVES;


enum { LIBVES_O_APIURL, LIBVES_O_APPNAME, LIBVES_O_ATTNFN, LIBVES_O_CURL, LIBVES_O_HTTPINITFN,
    LIBVES_O_GENFN, LIBVES_O_CIPHERALGO, LIBVES_O_KEYALGO, LIBVES_O_POLLURL, LIBVES_O_VESKEYLEN,
    LIBVES_O_SESSTMOUT, LIBVES_O_DEBUG, LIBVES_O_REF };

#define LIBVES_E_OK		0
#define LIBVES_E_PARAM		1
#define LIBVES_E_CONN		2
#define LIBVES_E_PARSE		3
#define LIBVES_E_CRYPTO		4
#define LIBVES_E_UNLOCK		5
#define LIBVES_E_DENIED		6
#define LIBVES_E_NOTFOUND	7
#define LIBVES_E_SERVER		8
#define LIBVES_E_UNSUPPORTED	9
#define LIBVES_E_INCORRECT	10
#define LIBVES_E_ASSERT		11
#define LIBVES_E_DIALOG		12
#define LIBVES_E_QUOTA		13
#define LIBVES_E_INTERNAL	31

#define LIBVES_O_FILE		0x01
#define LIBVES_O_VKEY		0x02
#define LIBVES_O_VITEM		0x04

#define LIBVES_O_NEW		0x10
#define LIBVES_O_GET		0x20

#ifndef LIBVES_API_URL
#define LIBVES_API_URL		"https://api.ves.host/v1/"
#endif

#ifndef LIBVES_POLL_URL
#define LIBVES_POLL_URL		"https://poll.ves.host/v1/"
#endif

#ifndef LIBVES_VESKEY_LEN
#define LIBVES_VESKEY_LEN	32
#endif

#ifndef LIBVES_SESS_TMOUT
#define LIBVES_SESS_TMOUT	28800
#endif

extern const char *libVES_version;

/***************************************************************************
 * Global initialization. Optionally, call libVES_init() before creating any
 * instances of libVES to set the app name.
 * appName = "App_Name/version" (User-Agent format),
 * defaults to "(unspecified app)"
 ***************************************************************************/
void libVES_init(const char *appName);

/***************************************************************************
 * A new instance of libVES. vaultURI is an App Vault ves://domain/externalID/
 * or NULL
 ***************************************************************************/
libVES *libVES_new(const char *vaultURI);

/***************************************************************************
 * A new instance of libVES. ref is an app vaule reference.
 * ref gets strong refcounted, call libVES_Ref_free(ref) before deallocating
 * the libVES instance.
 ***************************************************************************/
libVES *libVES_fromRef(struct libVES_Ref *ref);

/***************************************************************************
 * Instantiate a child instance of libVES. The child instance inherits all
 * context and unlocked keys from the parent. Once instantiated, it's safe
 * to use the parent and children concurrently in threads, as long as no
 * context altering operations are performed on the main libVES_VaultKey
 * or the libVES_User instance (ves->me), such as locking/unlocking or
 * loading additional fields. All children must be libVES_free()'d before
 * the parent.
 ***************************************************************************/
libVES *libVES_child(libVES *pves);

/***************************************************************************
 * Get an option value, optn = LIBVES_O_*
 ***************************************************************************/
void *libVES_getOption(libVES *ves, int optn);

/***************************************************************************
 * Set an option value, optn = LIBVES_O_*, returns true on success
 ***************************************************************************/
int libVES_setOption(libVES *ves, int optn, void *val);

/***************************************************************************
 * Return the code of the last error, LIBVES_E_*.
 * The code is reset to LIBVES_E_OK after the call.
 ***************************************************************************/
int libVES_getError(libVES *ves);

/***************************************************************************
 * If the error code matches err - reset the code to LIBVES_E_OK
 * and return true. Otherwise return false without altering the error code.
 ***************************************************************************/
int libVES_checkError(libVES *ves, int err);

/***************************************************************************
 * Error description string for error code err.
 ***************************************************************************/
const char *libVES_errorStr(int err);

/***************************************************************************
 * Populate the error description str for the last error code on ves, and
 * an error detailds message msg.
 * The error code on ves is reset to LIBVES_E_OK after the call.
 ***************************************************************************/
int libVES_getErrorInfo(libVES *ves, const char **str, const char **msg);

/***************************************************************************
 * Convert a VES URI into an object, libVES_VaultKey or libVES_VaultItem.
 * flags are a combination of LIBVES_O_*
 * Returns the object, sets *type to LIBVES_O_* if type != NULL
 ***************************************************************************/
void *libVES_objectFromURI(const char **uri, struct libVES *ves, int flags, int *type);

struct libVES_VaultKey *libVES_defaultGenVaultKey(libVES *ves, int type, struct libVES_Ref *ref, struct libVES_User *user);
void libVES_defaultAttn(libVES *ves, struct jVar *attn);
char *libVES_fetchVerifyToken(const char *objuri, long long int objid, struct libVES *ves);

/***************************************************************************
 * The App Vault Reference associated with the instance of libVES
 ***************************************************************************/
#define libVES_getExternal(ves)	((ves) ? (ves)->external : NULL)

/***************************************************************************
 * The App Vault Key associated with the instance of libVES, do not deallocate
 ***************************************************************************/
struct libVES_VaultKey *libVES_getVaultKey(libVES *ves);

/***************************************************************************
 * Create a new Vault Key for the App Vault associated with the instance
 * of libVES. API restrictions apply.
 ***************************************************************************/
struct libVES_VaultKey *libVES_createVaultKey(libVES *ves);

/***************************************************************************
 * Unlock the App Vault, returns the Vault Key, or NULL on error.
 ***************************************************************************/
struct libVES_VaultKey *libVES_unlock_veskey(libVES *ves, const struct libVES_veskey *veskey);
struct libVES_VaultKey *libVES_unlock(libVES *ves, size_t keylen, const char *veskey);

/***************************************************************************
 * Check if the libVES instance is unlocked
 ***************************************************************************/
#define	libVES_unlocked(ves)		(!!libVES_unlock_veskey(ves, NULL))

/***************************************************************************
 * Lock all Vault Keys previously unlocked on ves.
 ***************************************************************************/
void libVES_lock(libVES *ves);

/***************************************************************************
 * Refresh the Session Token for the unlocked Vault Key,
 * returns 1 on success, 0 on error.
 ***************************************************************************/
int libVES_refreshSession(libVES *ves);

/***************************************************************************
 * Refresh the Session Token for the unlocked Vault Key if the session is
 * timing out, returns 1 on success, 0 on error.
 ***************************************************************************/
int libVES_checkSession(libVES *ves);

/***************************************************************************
 * API session authorization token, an ascii string. Do not deallocate.
 * Created by libVES_unlock() or libVES_primary().
 ***************************************************************************/
#define libVES_getSessionToken(ves)	((ves) ? (ves)->sessionToken : NULL)

/***************************************************************************
 * Set the API session authorization token, from another API session
 ***************************************************************************/
void libVES_setSessionToken(libVES *ves, const char *token);

/***************************************************************************
 * Authorize the Primary Vault session using VESvault password.
 * Returns the current primary Vault Key, that can be further unlocked
 * using libVES_VaultKey_unlock()
 ***************************************************************************/
struct libVES_VaultKey *libVES_primary(libVES *ves, const char *email, const char *passwd);

/***************************************************************************
 * The owner of the Vault associated with ves. Do not deallocate.
 ***************************************************************************/
struct libVES_User *libVES_me(libVES *ves);

/***************************************************************************
 * Get raw string content of the Vault Item identified by uri.
 * If buf == NULL - allocate a new buffer of proper length, the returned buffer
 * is to be deallocated with free().
 * If buf != NULL && len != NULL - fail if *len is less that required length.
 * If len != NULL - populate the actual length *len on success.
 * If len == NULL - terminate the buffer with "\0".
 ***************************************************************************/
char *libVES_getValue(libVES *ves, const char *uri, size_t *len, char *buf);

/***************************************************************************
 * Put a raw string value into an existing or new Vault Item,
 * share with listed Vault URIs if shareURI != NULL
 ***************************************************************************/
int libVES_putValue(libVES *ves, const char *uri, size_t len, const char *value, size_t sharelen, const char **shareURI);

/***************************************************************************
 * Return 1 if the Vault Item identified by uri exists, 0 if doesn't exist,
 * -1 on error. This function does not need any kind of authentication,
 * can be run on newly instantiated ves.
 ***************************************************************************/
int libVES_fileExists(libVES *ves, const char *uri);

/***************************************************************************
 * Share an existing Vault Item identified by uri, with shareURI
 ***************************************************************************/
int libVES_shareFile(libVES *ves, const char *uri, size_t sharelen, const char **shareURI);

/***************************************************************************
 * Flag the Vault Item identified by uri as deleted.
 ***************************************************************************/
int libVES_deleteFile(libVES *ves, const char *uri);

/***************************************************************************
 * Perform pending internal tasks, such as temp key propagation.
 * Can be called periodically to sync the temp keys for the newly created
 * recipients of the User's vault items who are in process of setting up
 * their VES accounts.
 ***************************************************************************/
void libVES_attn(struct libVES *ves);

/***************************************************************************
 * Deallocate libVES, wipe all private content from memory
 ***************************************************************************/
void libVES_free(libVES *ves);

/***************************************************************************
 * Recursively erase any sensitive data from a jVar structure
 ***************************************************************************/
void libVES_cleanseJVar(struct jVar *jvar);

/***************************************************************************
 * Base64 encoded len to binary size
 ***************************************************************************/
#define libVES_b64decsize(len)		((len) * 3 / 4)

/***************************************************************************
 * Binary len to base64 encoded size, including trailing NUL
 ***************************************************************************/
#define libVES_b64encsize(len)		(((len) + 2) / 3 * 4 + 1)

/***************************************************************************
 * Base64 decode, *dec is allocated if NULL, binary size is returned
 ***************************************************************************/
size_t libVES_b64decode(const char *b64, char **dec);
size_t libVES_b64decodel(const char *b64, int len, char **dec);

/***************************************************************************
 * Base64 encode, returns b64 or malloc'd string if b64==NULL, filled with
 * NUL terminated encoded content
 * libVES_b64encode_web produces an RFC4648 section 5 url-safe encoding
 * libVES_b64encode_map takes a custom map, 64 chars + the padding char
 ***************************************************************************/
char *libVES_b64encode(const char *data, size_t len, char *b64);
char *libVES_b64encode_web(const char *data, size_t len, char *b64);
char *libVES_b64encode_map(const char *map, const char *data, size_t len, char *b64);

/***************************************************************************
 * Assign ves->me if not assigned yet, useful for primary vault operations.
 * The user is refcounted if assigned, it's safe to use libVES_User_free(user)
 ***************************************************************************/
void libVES_setUser(struct libVES *ves, struct libVES_User *user);
