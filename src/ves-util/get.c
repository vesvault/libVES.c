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
 * ves-util/get.c             VES Utility: Input handlers
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
#include "../ves-util.h"
#include "get.h"
#include "tty.h"

void *fd_get_contents(int fd, size_t *len) {
    int bufl = 4096;
    char *buf = malloc(bufl);
    int offs = 0;
    int r;
    while ((r = read(fd, buf + offs, bufl - offs)) > 0) {
	offs += r;
	if (offs * 4 > bufl * 3) buf = realloc(buf, bufl = offs * 2);
    }
    if (r < 0) {
	free(buf);
	return NULL;
    }
    return realloc(buf, *len = offs);
}

void *get_file(const char *str, size_t *len, void **ptr) {
    int fd = open(str, O_RDONLY);
    if (fd < 0) IO_throw("[open]", str, NULL);
    void *res = fd_get_contents(fd, len);
    if (!res) IO_throw("[read]", str, NULL);
    close(fd);
    return res;
}

void *get_fd(const char *str, size_t *len, void **ptr) {
    int fd;
    if (sscanf(str, "%d", &fd) != 1) VES_throw("[get_fd]", "Numeric file descriptor expected", str, NULL);
    char *res = fd_get_contents(fd, len);
    if (!res) IO_throw("[read]", "(fd)", NULL);
    return res;
}

void *get_noecho(const char *str, size_t *len, void **ptr) {
    char *res = tty_getpass(str, 255);
    if (!res) IO_throw("[tty_getpass]", str, NULL);
    *len = strlen(res);
    return res;
}
