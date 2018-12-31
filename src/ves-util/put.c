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
 * ves-util/put.c             VES Utility: Parameter value handlers
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <libVES.h>
#include <jVar.h>
#include <libVES/VaultKey.h>
#include <libVES/VaultItem.h>
#include "../ves-util.h"
#include "put.h"

void *put_veskey(const char *str, size_t len, void **pdata) {
    return *pdata = (void *) libVES_veskey_new(len, str);
}

void *put_sh(const char *path, int flags, struct share_st **sh) {
    MEM_chk_list(*sh, share);
    (*sh)->share[(*sh)->len].path = strdup(path);
    (*sh)->share[(*sh)->len++].flags = flags;
    return *sh;
}

void *put_share(const char *str, size_t len, void **ptr) {
    return put_sh(str, LIBVES_SH_ADD, (struct share_st **) ptr);
}

void *put_unshare(const char *str, size_t len, void **ptr) {
    return put_sh(str, LIBVES_SH_DEL, (struct share_st **) ptr);
}

void *put_setshare(const char *str, size_t len, void **ptr) {
    return put_sh(str, LIBVES_SH_ADD | LIBVES_SH_CLN, (struct share_st **) ptr);
}

void *put_jvar(const char *str, size_t len, void **ptr) {
    return *ptr = (void *) jVar_stringl(str, len);
}

void *put_jvarobj(const char *str, size_t len, void **ptr) {
    jVar *jv = jVar_parse(str, len);
    if (!jVar_isObject(jv)) {
	jVar_free(jv);
	VES_throw("[put_jvarobj]", "Not a valid JSON object", str, NULL);
    }
    return *ptr = (void *) jv;
}

void *put_keyalgo(const char *str, size_t len, void **ptr) {
    return *ptr = (void *) libVES_VaultKey_algoFromStr(str);
}
