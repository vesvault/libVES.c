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
 * ves-util/tty_u.c           VES Utility: Terminal Operations (Unix)
 *
 ***************************************************************************/
#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "tty.h"


int tty_get_width(int fd) {
    struct winsize wsize;
    if (ioctl(fd, TIOCGWINSZ, &wsize) >= 0) return wsize.ws_col;
    return -1;
}

char *tty_getpass(const char *prompt, size_t maxlen) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return NULL;
    struct termios t;
    if (tcgetattr(fd, &t) < 0) return NULL;
    t.c_lflag &= ~ECHO;
    if (tcsetattr(fd, TCSANOW, &t) < 0) return NULL;
    char *buf = malloc(maxlen + 1);
    if (!buf) return NULL;
    char *bufp = buf;
    char *tail = buf + maxlen;
    int r = -1;
    if (write(fd, prompt, strlen(prompt)) >= 0) {
	while ((r = read(fd, bufp, 1)) > 0 && bufp < tail) {
	    if (*bufp == 0x0a) break;
	    bufp++;
	}
    }
    *bufp = 0;
    if (tcgetattr(fd, &t) < 0) r = -1;
    t.c_lflag |= ECHO;
    if (tcsetattr(fd, TCSANOW, &t) < 0) r = -1;
    write(fd, "\r\n", 2);
    close(fd);
    if (r >= 0) return buf;
    free(buf);
    return NULL;
}

int tty_is_ansi(int fd) {
    return tty_get_width(fd) > 0;
}
