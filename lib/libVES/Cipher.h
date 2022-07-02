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
 * libVES/Cipher.h            libVES: Stream cipher header
 *
 ***************************************************************************/
typedef struct libVES_Cipher {
    const struct libVES_CiAlgo *algo;
    struct libVES *ves;
    void *ctx;
    struct jVar *meta;
    int flags;
    union {
	char key[0];
	struct {
	    unsigned char key[32];
	    unsigned char seed[12];
	    unsigned char iv[12];
	    size_t offs;
	    union {
		char *pbuf;
		struct {
		    void *mdctx;
		    char gbuf[16];
		};
	    };
	    char end[0];
	} gcm;
	struct {
	    unsigned char key[32];
	    unsigned char seed[32];
	    unsigned char iv[32];
	    char end[0];
	} cfb;
    };
} libVES_Cipher;

typedef struct libVES_CiAlgo {
    const char *str;
    const char *name;
    struct libVES_Cipher *(*newfn)(const struct libVES_CiAlgo *algo, struct libVES *ves, size_t, const char *);
    int (*keylenfn)(struct libVES_Cipher *ci);
    int (*decfn)(struct libVES_Cipher *, int, const char *, size_t, char *);
    int (*encfn)(struct libVES_Cipher *, int, const char *, size_t, char *);
    struct libVES_Seek *(*seekfn)(struct libVES_Cipher *, struct libVES_Seek *);
    void (*resetfn)(struct libVES_Cipher *);
    void (*freefn)(struct libVES_Cipher *);
} libVES_CiAlgo;

#define LIBVES_CF_ENC	0x01
#define LIBVES_CF_DEC	0x02
#define LIBVES_CF_EXACT	0x10

typedef struct libVES_Seek {
    off_t plainPos;
    off_t cipherPos;
    off_t cipherFbPos;
    size_t cipherFbLen;
    void *cipherFb;
    int flags;
} libVES_Seek;

#define LIBVES_SK_ENC	0x01
#define LIBVES_SK_DEC	0x02
#define LIBVES_SK_RDY	0x0100
#define LIBVES_SK_FBK	0x0200
#define LIBVES_SK_ERR	0x8000
#define LIBVES_SK_NEW	0

#define libVES_Cipher_KEYLENforVEntry	(sizeof(((libVES_Cipher *)0)->gcm.key) + sizeof(((libVES_Cipher *)0)->gcm.seed))
#define libVES_Cipher_PADLENforVEntry	48

extern struct libVES_List libVES_Cipher_algos;

/***************************************************************************
 * New cipher object. If key == NULL - generate a random key.
 ***************************************************************************/
libVES_Cipher *libVES_Cipher_new(const struct libVES_CiAlgo *algo, struct libVES *ves, size_t keylen, const char *key);

/***************************************************************************
 * New cipher, default algorithm, randomly generated key.
 ***************************************************************************/
#define libVES_Cipher_generate(ves)	libVES_Cipher_new(ves->cipherAlgo, ves, 0, NULL)

libVES_Cipher *libVES_Cipher_forVEntry(size_t keylen, const char *key, struct libVES *ves);
int libVES_Cipher_proceed(libVES_Cipher *ci, int final, const char *srctext, size_t srclen, char **dsttext, int func(libVES_Cipher *ci, int final, const char *src, size_t srclen, char *dst));

/***************************************************************************
 * Decrypt stream. Returns the decrypted length, -1 on error,
 * If *plaintext == NULL - the buffer is allocated automatically.
 ***************************************************************************/
int libVES_Cipher_decrypt(libVES_Cipher *ci, int final, const char *ciphertext, size_t ctlen, char **plaintext);

/***************************************************************************
 * Encrypt stream. Returns the encrypted length, -1 on error.
 * If *ciphertext == NULL - the buffer is allocated automatically.
 ***************************************************************************/
int libVES_Cipher_encrypt(libVES_Cipher *ci, int final, const char *plaintext, size_t ptlen, char **ciphertext);

/***************************************************************************
 * Calculate the max expected length of a plaintext.
 * If (flags & LIBVES_CF_EXACT) is set after the call - the returned value
 * is the exact length.
 ***************************************************************************/
#define libVES_Cipher_decsize(ci, final, ciphertext, ptlen)	libVES_Cipher_decrypt(ci, final, ciphertext, ptlen, NULL)

/***************************************************************************
 * Calculate the max expected length of a ciphertext.
 * If (flags & LIBVES_CF_EXACT) is set after the call - the returned value
 * is the exact length.
 ***************************************************************************/
#define libVES_Cipher_encsize(ci, final, plaintext, ptlen)	libVES_Cipher_encrypt(ci, final, plaintext, ptlen, NULL)

/***************************************************************************
 * Seek to a specific position in plaintext & ciphertext.
 * Synopsis:
 *   libVES_Seek *sk = libVES_Cipher_seek(ci, NULL);
 *   // Set (sk->plainPos) or (sk->cipherPos) to the desired position      //
 *   sk = libVES_Cipher_seek(ci, sk);
 *   if (sk->flags & LIBVES_SK_FBK) {
 *     // Seek the ciphertext to (sk->cipherFbPos),                        //
 *     // Read at least (sk->cipherFbLen) bytes from the ciphertext,       //
 *     // Point (sk->cipherFb) to the read bytes.                          //
 *     sk = libVES_Cipher_seek(ci, sk);
 *   }
 *   if (sk->flags & LIBVES_SK_RDY) {
 *     // Seek the plaintext to (sk->plainPos),                            //
 *     // Seek the ciphertext to (sk->cipherPos),                          //
 *     // Proceed with encryption / decryption.                            //
 *   }
 ***************************************************************************/
struct libVES_Seek *libVES_Cipher_seek(libVES_Cipher *ci, struct libVES_Seek *sk);

char *libVES_Cipher_toStringl(libVES_Cipher *ci, size_t *len, char *buf);

struct jVar *libVES_Cipher_getMeta(libVES_Cipher *ci);
int libVES_Cipher_setMeta(libVES_Cipher *ci, struct jVar *jv);

#define libVES_Cipher_algoStr(algo)	((algo) ? (algo)->str : NULL)
const libVES_CiAlgo *libVES_Cipher_algoFromStr(const char *str);
void libVES_Cipher_reset(libVES_Cipher *ci);
void libVES_Cipher_free(libVES_Cipher *ci);

#define libVES_Seek_free(sk)	free(sk)

/***************************************************************************
 * Apps are encouraged to use custom stream cipher algorithms.
 * Make sure the string identifier of the algorithm (algo->str)
 * is unique within the scope of any apps the Vault Items can be shared with.
 * Registered algorithm is available to all libVES instances within the process.
 ***************************************************************************/
void libVES_Cipher_registerAlgo(const struct libVES_CiAlgo *algo);

/***************************************************************************
 * "NULL" cipher. No encryption implemented, secret metadata only.
 ***************************************************************************/
extern const struct libVES_CiAlgo libVES_CiAlgo_NULL;
