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
 * ves-util/out.h             VES Utility: Header for output handlers
 *
 ***************************************************************************/
int out_list(int fdi, struct ctx_st *ctx);
int out_explore(int fdi, struct ctx_st *ctx);
int out_events(int fdi, struct ctx_st *ctx);
int out_value(int fd, struct ctx_st *ctx);
int out_meta(int fd, struct ctx_st *ctx);
int out_cimeta(int fd, struct ctx_st *ctx);
int out_cipher(int fd, struct ctx_st *ctx);
int out_token(int fd, struct ctx_st *ctx);
int out_pub(int fd, struct ctx_st *ctx);
int out_priv(int fd, struct ctx_st *ctx);
int out_email(int fd, struct ctx_st *ctx);
int out_veskey(int fd, struct ctx_st *ctx);
int out_keyAlgos(int fdi, struct ctx_st *ctx);
int out_keyalgo(int fd, struct ctx_st *ctx);
int out_ciAlgos(int fdi, struct ctx_st *ctx);
int out_keystore_flags(int fdi, struct ctx_st *ctx);
int out_share(int fd, struct ctx_st *ctx);

void out_ansi_str(int fd, const char *str);

#define OUT_IO_assert(scope, res)	if ((res) < 0) IO_throw(scope, "write", E_IO)
