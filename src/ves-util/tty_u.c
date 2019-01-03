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
