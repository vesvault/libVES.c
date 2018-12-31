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
    if (cl < 0) VES_throw("[ci_process]", "[libVES_Cipher]", libVES_errorStr(libVES_getError(ci->ves)), -1);
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
