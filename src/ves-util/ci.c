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
 * ves-util/ci.c              VES Utility: Stream cipher handlers
 *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <libVES.h>
#include <libVES/Cipher.h>
#include "../ves-util.h"
#include "ci.h"

int ci_process(int in, int out, libVES_Cipher *ci, int (*fn)(libVES_Cipher *, int, const char *, size_t, char **)) {
    char buf[16384];
    char *outbuf = malloc(fn(ci, 0, NULL, sizeof(buf), NULL));
    int r, w, cl;
    int tl = 0;
    while ((r = read(in, buf, sizeof(buf))) >= 0) {
	cl = fn(ci, r == 0, buf, r, &outbuf);
	if (cl >= 0) {
	    int wp = 0;
	    while (wp < cl) {
		w = write(out, outbuf + wp, cl - wp);
		if (w >= 0) {
		    wp += w;
		    tl += w;
		} else break;
	    }
	}
	if (r <= 0 || w < 0 || cl < 0) break;
    }
    free(outbuf);
    if (cl < 0) {
	const char *err, *msg;
	libVES_getErrorInfo(ci->ves, &err, &msg);
	VES_throw("[ci_process]", err, msg, -1);
    }
    if (r < 0) { IO_throw("[read]", "(in)", -1); }
    else if (w < 0) { IO_throw("[write]", "(out)", -1); }
    else return tl;
}

int ci_get_fd(struct setfn_st *st, int dflt) {
    return st->setfn ? st->setfn(st->data, st->mode) : dflt;
}

int ci_encrypt(libVES_Cipher *ci) {
    int ptext = ci_get_fd(&params.ptext, 0);
    if (ptext < 0) return -1;
    int ctext = ci_get_fd(&params.ctext, 1);
    if (ctext < 0) return -1;
    return ci_process(ptext, ctext, ci, &libVES_Cipher_encrypt);
}

int ci_decrypt(libVES_Cipher *ci) {
    int ctext = ci_get_fd(&params.ctext, 0);
    if (ctext < 0) return -1;
    int ptext = ci_get_fd(&params.ptext, 1);
    if (ptext < 0) return -1;
    return ci_process(ctext, ptext, ci, &libVES_Cipher_decrypt);
}
