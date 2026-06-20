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
 * libVES/Util.h              libVES: Internal utilities header
 *
 ***************************************************************************/
struct libVES;
struct libVES_List;
struct libVES_VaultKey;

#define libVES_lookupStr(idx, lst)		((idx >= 0 && idx < sizeof(lst) / sizeof(*lst)) ? lst[idx] : NULL)
int libVES_enumStrl(const char *str, size_t len, const char **list);
#define libVES_enumStr(str, list)	libVES_enumStrl(str, sizeof(list) / sizeof(*list), list)

struct libVES;
void libVES_initEVP();
void libVES_setError(struct libVES *ves, int err, const char *msg);
void libVES_setError0(struct libVES *ves, int err, char *msg);
void libVES_setErrorEVP(struct libVES *ves, int err, const char *scope);
#define libVES_addUnlocked(ves, vkey)		libVES_List_unshift((ves)->unlockedKeys, vkey)
#define libVES_removeUnlocked(ves, vkey)	libVES_List_remove((ves)->unlockedKeys, vkey)
#define libVES_throw(ves, err, msg, ret)	return (libVES_setError((ves), (err), (msg)), (ret))
#define libVES_throwEVP(ves, err, scope, ret)	return (libVES_setErrorEVP((ves), (err), (scope)), (ret))
#define libVES_assert(ves, expr, ret)		if (!(expr)) libVES_throw(ves, LIBVES_E_ASSERT, #expr, ret)

extern const struct libVES_ListCtl libVES_algoListCtl;
#define libVES_registerAlgo(algo, lst)		libVES_List_push(lst, algo)
void *libVES_lookupAlgo(const char *str, struct libVES_List *lst);

char *libVES_buildURI(int argc, ...);

long long libVES_date2usec(const char *date);

int libVES_stricmp(const char *s1, const char *s2);


#define libVES_REFINIT(ptr)			((void)((ptr) && ((ptr)->refct = 0)), (ptr))
#define libVES_REFUP(type, ptr)			((void)((ptr) && ((libVES_ ## type *)(ptr))->refct++), (ptr))
#define libVES_REFDN(type, ptr)			(!(ptr) || (--((libVES_ ## type *)(ptr))->refct > 0) || (libVES_ ## type ## _free(ptr), 1))
#define libVES_REFRM(ptr)			(!(ptr) || ((void)--(ptr)->refct, (ptr) = NULL))
#define libVES_REFBUSY(ptr)			(!(ptr) || (ptr)->refct > 0)
