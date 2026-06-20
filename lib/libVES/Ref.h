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
 * libVES/Ref.h               libVES: Object reference header
 *
 ***************************************************************************/

typedef struct libVES_Ref {
    char *domain;
    int refct;
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

const char *libVES_Ref_getDomain(libVES_Ref *ref);
const char *libVES_Ref_getExternalId(libVES_Ref *ref);
long long libVES_Ref_getInternalId(libVES_Ref *ref);

void libVES_Ref_free(libVES_Ref *ref);

/***************************************************************************
 * App level refcount management. After calling refup() any calls to
 * *_free() on obj will be ignored. Call refdn() to automatically
 * deallocate the object.
 * refup() returns obj, refdn returns obj or NULL if the object have been
 * deallocated by the call.
 * Both calls are NULL safe.
 ***************************************************************************/
libVES_Ref *libVES_Ref_refup(libVES_Ref *obj);
libVES_Ref *libVES_Ref_refdn(libVES_Ref *obj);
