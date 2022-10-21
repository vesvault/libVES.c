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
 * ves-util/hook.c            VES Utility: Hook functions
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <libVES.h>
#include <libVES/VaultKey.h>
#include <libVES/KeyAlgo_EVP.h>
#include <libVES/Ref.h>
#include <libVES/User.h>
#include "../ves-util.h"
#include "hook.h"


libVES_VaultKey *hook_genVaultKey(libVES *ves, int type, libVES_Ref *ref, libVES_User *user) {
    libVES_veskey *v = params.veskey;
    if (!v && (params.flags & PF_NEW)) v = params.uveskey;
    libVES_veskey *vnew = v ? NULL : (v = libVES_veskey_generate(ves->veskeyLen));
    libVES_VaultKey *vkey = libVES_VaultKey_new(type, (params.keyAlgo ? params.keyAlgo : (params.priv ? &libVES_KeyAlgo_autoPEM : ves->keyAlgo)), (params.keyAlgo && params.priv ? params.keyAlgo->str2privfn(((void *)&ves - offsetof(libVES_VaultKey, ves)), params.priv, params.uveskey): NULL), v, ves);
    libVES_veskey_free(vnew);
    return vkey;
}

char *hook_progPath = NULL;

void hook_httpInitFn(libVES *ves) {
    const char caName[] = "curl-ca-bundle.crt";
    static char *caPath = NULL;
    static char chkd = 0;
    if (!chkd) {
	int l = hook_progPath ? strlen(hook_progPath) : 0;
	caPath = malloc(l + sizeof(caName) + 1);
	char *p;
	if (hook_progPath) {
	    memcpy(caPath, hook_progPath, l);
	    p = caPath + l - 1;
	    while (p >= caPath) {
		if (*p == '/' || *p == '\\') break;
		p--;
	    }
	    p++;
	} else p = caPath;
	strcpy(p, caName);
	struct stat st;
	if (stat(caPath, &st) < 0) {
	    free(caPath);
	    caPath = NULL;
	}
	chkd = 1;
    }
    if (caPath) curl_easy_setopt(ves->curl, CURLOPT_CAINFO, caPath);
}
