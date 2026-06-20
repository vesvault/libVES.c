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
void *put_keystore(const char *str, size_t len, void **ptr);
void *put_watch(const char *str, size_t len, void **ptr);
