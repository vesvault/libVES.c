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
 * ves-util.h                 VES Utility Main Header
 *
 ***************************************************************************/
#define VESUTIL_VERSION_CODE	"0.903b"
#define VESUTIL_VERSION_STR	"VES util " VESUTIL_VERSION_CODE " (c) 2018 VESvault Corp"
#define VESUTIL_VERSION_SHORT	"ves/" VESUTIL_VERSION_CODE
#define	E_PARAM		64
#define E_IO		65

#define return_VESerror2(scope, ves)		{ const char *str, *msg; int e = libVES_getErrorInfo(ves, &str, &msg); if (params.debug >= 0) fprintf(stderr, "%s %s (%s)\n", (scope), (str ? str : "Unknown error"), (msg ? msg : "")); return e ? e : E_PARAM; }
#define return_VESerror(scope)			return_VESerror2(scope, ctx.ves)
#define MEM_chk_list(st, list) { \
    size_t len = (st) ? (st)->len : 0; \
    if (len < 8) len = 8; \
    void *p = (st); \
    if (!p || ((len + 1) ^ len) > len + 1) { \
	(st) = realloc((st), sizeof(*(st)) + 2 * len * sizeof(*((st)->list))); \
	if (!p) (st)->len = 0; \
    } \
}

struct share_st {
    size_t len;
    struct {
	int flags;
	char *path;
    } share[];
};

struct setfn_st {
    void *data;
    int mode;
    int (*setfn)(void *, int);
};

struct libVES;
struct libVES_VaultKey;
struct libVES_VaultItem;
struct libVES_Cipher;

struct ctx_st {
    struct libVES *ves;
    struct libVES_VaultKey *vkey;
    struct libVES_VaultItem *vitem;
    struct libVES_Cipher *ci;
};

extern struct param_st {
    char *user;
    char *object;
    char *key;
    char *token;
    char *primary;
    char *passwd;
    struct {
	int width;
	int col;
	int detect;
    } dump;
    struct {
	size_t len;
	struct {
	    struct setfn_st set;
	    int (*outfn)(int, struct ctx_st *);
	} out[];
    } *out;
    struct setfn_st ptext, ctext;
    struct libVES_veskey *uveskey, *veskey;
    struct share_st *share;
    struct jVar *value;
    struct jVar *meta;
    char *cipher;
    struct jVar *cimeta;
    int (*cifn)(struct libVES_Cipher *);
    char *apiUrl;
    char *priv;
    const struct libVES_KeyAlgo *keyAlgo;
    int flags;
    short int itemType;
    char debug;
} params;

#define PF_VK_RD	0x01
#define PF_VK_WR	0x02
#define PF_VI_RD	0x04
#define PF_VI_WR	0x08
#define PF_CI_RD	0x10
#define PF_CI_WR	0x20
#define PF_CI_EN	0x40
#define PF_VK_CR	0x80
#define PF_RD		0x1000
#define PF_VK_FR	0x2000
#define PF_VK_PROP	0x4000
#define	PF_VK_REKEY	0x8000
#define PF_DEL		0x0100
#define PF_FRC		0x0200
#define PF_LCK		0x0400
#define PF_NEW		0x0800

#define SF_WR		0x01

#define VES_throw(scope, str, val, ret)	{ \
    fprintf(stderr, scope " %s: %s\n", (str), (val)); \
    return (ret); \
}

#define IO_throw(scope, str, ret)	{ \
    fprintf(stderr, scope "%s: %s (%d)\n", (str), strerror(errno), errno); \
    return (ret); \
}
