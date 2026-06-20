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
