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
#include "keystore_flags.h"
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
    return *ptr = libVES_VaultKey_algoFromStr(str) ? (void *)strdup(str) : NULL;
}

void *put_watch(const char *str, size_t len, void **ptr) {
    struct param_watch { long long startId; int count; int follow; int timeout; } *w = (void *) ptr;
    const char *s = str;
    char *end;
    if (*s == '=') {
	long long id = strtoll(++s, &end, 10);
	if (end == s || id <= 0) VES_throw("[put_watch]", "Expected an event id after '='", str, NULL);
	w->startId = id;
	s = end;
	if (*s == ':') {
	    long n = strtol(++s, &end, 10);
	    if (end == s || n <= 0) VES_throw("[put_watch]", "Expected a positive count after ':'", str, NULL);
	    w->count = (int) n;
	    s = end;
	}
    } else if (*s >= '0' && *s <= '9') {
	w->count = (int) strtol(s, &end, 10);
	s = end;
    }
    if (*s == '+') {
	w->follow = 1;
	s++;
	if (*s >= '0' && *s <= '9') {
	    long t = strtol(s, &end, 10);
	    if (t <= 0) VES_throw("[put_watch]", "Expected a positive timeout after '+'", str, NULL);
	    w->timeout = (int) t;
	    s = end;
	}
    }
    if (*s) VES_throw("[put_watch]", "Invalid watch spec, use [COUNT|=ID[:COUNT]][+[SECONDS]]", str, NULL);
    return ptr;
}

void *put_keystore(const char *str, size_t len, void **ptr) {
    const char *s = str;
    const char *tail = s + len;
    while (s < tail) {
	const char *next = memchr(s, ',', tail - s);
	if (!next) next = tail;
	if (next > s) {
	    struct keystore_flag *f;
	    for (f = keystore_flags; f->tag; f++) {
		if (next - s == strlen(f->tag) && !strncmp(s, f->tag, next - s)) {
		    *(int *)ptr |= f->val;
		    break;
		}
	    }
	    if (!f->tag) VES_throw("[put_keystore]", "Unknown flag (see -El)", s, NULL);
	}
	s = next + 1;
    }
    return ptr;
}
