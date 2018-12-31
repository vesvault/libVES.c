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
 * libVES/Ref.h               libVES: Object reference header
 *
 ***************************************************************************/

typedef struct libVES_Ref {
    char *domain;
    union {
	char externalId[0];
	long long int internalId;
    };
} libVES_Ref;

/***************************************************************************
 * New internalID ref, ves:///internalId[/...]
 ***************************************************************************/
libVES_Ref *libVES_Ref_new(long long int intId);

/***************************************************************************
 * New externalID ref, ves://domain/externalId[/...]
 ***************************************************************************/
libVES_Ref *libVES_External_new(const char *domain, const char *extId);

/***************************************************************************
 * Parse the domain and externalId, or the internalId, from the URI.
 * Upon return, *uri points to the next char after the parsed part.
 ***************************************************************************/
libVES_Ref *libVES_Ref_fromURI(const char **uri, struct libVES *ves);

libVES_Ref *libVES_External_fromJVar(struct jVar *data);
struct jVar *libVES_Ref_toJVar(libVES_Ref *ref, struct jVar *dst);
libVES_Ref *libVES_Ref_copy(libVES_Ref *ref);
#define libVES_Ref_free(ref)	free(ref)
