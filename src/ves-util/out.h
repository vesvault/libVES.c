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
 * ves-util/out.h             VES Utility: Header for output handlers
 *
 ***************************************************************************/
int out_list(int fdi, struct ctx_st *ctx);
int out_explore(int fdi, struct ctx_st *ctx);
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
int out_ciAlgos(int fdi, struct ctx_st *ctx);
int out_keystore_flags(int fdi, struct ctx_st *ctx);
int out_share(int fd, struct ctx_st *ctx);

void out_ansi_str(int fd, const char *str);

#define OUT_IO_assert(scope, res)	if ((res) < 0) IO_throw(scope, "write", E_IO)
