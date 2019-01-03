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
 * ves-util/tty_w.c           VES Utility: Terminal Operations (Windows)
 *
 ***************************************************************************/
#include <stddef.h>
#include <sys/types.h>
#include <windows.h>
#include <fcntl.h>
#include "tty.h"


int tty_get_width(int fd) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(_get_osfhandle(fd), &csbi);
    return csbi.srWindow.Right - csbi.srWindow.Left;
}

char *tty_getpass(const char *prompt, size_t maxlen) {
    DWORD mode;
    HANDLE hdl = CreateFile( "CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
    if (hdl == INVALID_HANDLE_VALUE) return NULL;
    HANDLE hdlw = CreateFile( "CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0 );
    if (hdlw == INVALID_HANDLE_VALUE) return NULL;
    if (!GetConsoleMode(hdl, &mode)) return NULL;
    mode &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hdl, mode)) return NULL;
    char *buf = malloc(maxlen + 1);
    if (!buf) return NULL;
    char *bufp = buf;
    char *tail = buf + maxlen;
    int r = -1;
    if (WriteConsole(hdlw, prompt, strlen(prompt), NULL, 0)) {
	while (bufp < tail && (ReadConsole(hdl, bufp, 1, &r, 0))) {
	    if (*bufp == 0x0d || *bufp == 0x0a) break;
	    bufp++;
	}
    }
    mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(hdl, mode);
    CloseHandle(hdl);
    *bufp = 0;
    WriteConsole(hdlw, "\r\n", 2, NULL, 0);
    CloseHandle(hdlw);
    if (r >= 0) return buf;
    free(buf);
    return NULL;
}

int tty_is_ansi(int fd) {
    int mode;
    return GetConsoleMode(_get_osfhandle(fd), &mode) && (mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING) && SetConsoleMode(_get_osfhandle(fd), mode);
}
