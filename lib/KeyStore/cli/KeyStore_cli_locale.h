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
 * (c) 2023 VESvault Corp
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
 * KeyStore_cli.c                   libVES: CLI key store module
 *
 ***************************************************************************/

extern struct libVES_KeyStore_cli_locale libVES_KeyStore_cli_locale_default;

struct libVES_KeyStore_cli_locale {
    const char **head;
    const char **keyname;
    const char **keyname2;
    const char **domain;
    const char **domain2;
    const char **user;
    const char **user2;
    const char **pin;
    const char **pin2;
    const char **retry;
    const char **retry2;
    const char **syncode;
    const char **syncode2;
    const char **nouser;
    const char **primary;
};
