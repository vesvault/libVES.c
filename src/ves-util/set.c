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
 * ves-util/set.c             VES Utility: -f / -F modifier handlers
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include "../ves-util.h"
#include "set.h"

int set_file(void *data, int mode) {
    int fd = open(data, (mode & SF_WR ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY), 0600);
    if (fd < 0) IO_throw("[open]", (char *) data, -1);
    return fd;
}

int set_fd(void *data, int mode) {
    int fd;
    if (sscanf(data, "%d", &fd) != 1) VES_throw("[set_fd]", "Numeric file descriptor expected", (char *) data, -1);
    return fd;
}
