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
 * ves-util/ci.h              VES Utility: Header for stream cipher handlers
 *
 ***************************************************************************/
struct libVES_Cipher;
struct libVES_VaultKey;
struct jVar;
struct setfn_st;

int ci_get_fd(struct setfn_st *st, int dflt);
int ci_encrypt(struct libVES_Cipher *ci);
int ci_decrypt(struct libVES_Cipher *ci);
int ci_encrypt_hdr(struct libVES_Cipher *ci, const char *hdr, size_t hdrlen);
int ci_decrypt_fd(struct libVES_Cipher *ci, int ctext);
int ci_header(const char *key, size_t keylen, struct jVar *meta, struct libVES_VaultKey **rcpt, int n, char **hdr, size_t *hdrlen);
int ci_read_header(int fd, char **hdr, size_t *hdrlen);
int ci_header_open(const char *hdr, size_t hdrlen, struct libVES_VaultKey *vkey, char **key, size_t *keylen, struct jVar **meta);
