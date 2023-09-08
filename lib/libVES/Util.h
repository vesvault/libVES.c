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


#define libVES_REFINIT(ptr)			((void)((ptr) && ((ptr)->refct = 0)), (ptr))
#define libVES_REFUP(type, ptr)			((void)((ptr) && ((libVES_ ## type *)(ptr))->refct++), (ptr))
#define libVES_REFDN(type, ptr)			(!(ptr) || (--((libVES_ ## type *)(ptr))->refct > 0) || (libVES_ ## type ## _free(ptr), 1))
#define libVES_REFRM(ptr)			(!(ptr) || ((void)--(ptr)->refct, (ptr) = NULL))
#define libVES_REFBUSY(ptr)			(!(ptr) || (ptr)->refct > 0)
