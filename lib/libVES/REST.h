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
 * libVES/REST.h              libVES: REST API communications header
 *
 ***************************************************************************/
struct libVES;
struct jVar;
struct curl_slist;

struct jVar *libVES_REST(struct libVES *ves, const char *uri, struct jVar *body);
struct jVar *libVES_REST_login(struct libVES *ves, const char *uri, struct jVar *body, const char *username, const char *passwd);
struct jVar *libVES_REST_VESauthGET(struct libVES *ves, const char *url, long *pcode, const char *fmt, ...);
struct jVar *libVES_REST_hdrs(struct libVES *ves, const char *uri, struct jVar *body, struct curl_slist *hdrs);
struct jVar *libVES_REST_req(struct libVES *ves, const char *url, jVar *body, struct curl_slist *hdrs, long *pcode);
void libVES_REST_done(struct libVES *ves);
