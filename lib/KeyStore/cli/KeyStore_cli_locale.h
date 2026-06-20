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
    const char **noemail;
    const char **primary;
    const char **domadm;
};
