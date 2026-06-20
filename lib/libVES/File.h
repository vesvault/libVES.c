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
 * libVES/File.h              libVES: File object, for user vault items.
 *                            Internal to libVES in this version.
 *
 ***************************************************************************/

typedef struct libVES_File {
    long long int id;
    char *name;
    char *mime;
    char *path;
    struct libVES_Ref *external;
    struct libVES_User *creator;
    int refct;
} libVES_File;

libVES_File *libVES_File_new(struct libVES_Ref *ref);
libVES_File *libVES_File_fromJVar(struct jVar *data);
struct jVar *libVES_File_toJVar(libVES_File *file);
char *libVES_File_toURI(libVES_File *file);

/***************************************************************************
 * Get a Verify Token that can be used instead of libVES Session Token to
 * allow retrieving creator and external on the file
 * without granting any other permissions.
 * free() the token when done.
 * See also libVES_VaultItem_fetchVerifyToken()
 ***************************************************************************/
#define libVES_File_fetchVerifyToken(file, ves)		((file) ? libVES_fetchVerifyToken("files", (file)->id, ves) : NULL)

#define libVES_File_getCreator(file)	((file) ? (file)->creator : NULL)

int libVES_File_setCreator(libVES_File *file, struct libVES_User *user);

void libVES_File_free(libVES_File *file);
