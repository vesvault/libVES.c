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
 * ves-util/tty_w.c           VES Utility: Terminal Operations (Windows)
 *
 ***************************************************************************/
#include <stddef.h>
#include <sys/types.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include "tty.h"


int tty_get_width(int fd) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo((HANDLE)_get_osfhandle(fd), &csbi);
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
    DWORD r = 0;
    int ok = 0;
    if (WriteConsole(hdlw, prompt, strlen(prompt), NULL, 0)) {
	while (bufp < tail && (ReadConsole(hdl, bufp, 1, &r, 0))) {
	    ok = 1;
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
    if (ok) return buf;
    free(buf);
    return NULL;
}

int tty_is_ansi(int fd) {
    DWORD mode;
    HANDLE hdl = (HANDLE)_get_osfhandle(fd);
    return GetConsoleMode(hdl, &mode) && (mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING) && SetConsoleMode(hdl, mode);
}
