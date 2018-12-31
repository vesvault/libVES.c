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
 * ves-util/put.h             VES Utility: Header for parameter value handlers
 *
 ***************************************************************************/
void *put_veskey(const char *str, size_t len, void **ptr);
void *put_share(const char *str, size_t len, void **ptr);
void *put_unshare(const char *str, size_t len, void **ptr);
void *put_setshare(const char *str, size_t len, void **ptr);
void *put_jvar(const char *str, size_t len, void **ptr);
void *put_jvarobj(const char *str, size_t len, void **ptr);
void *put_keyalgo(const char *str, size_t len, void **ptr);
