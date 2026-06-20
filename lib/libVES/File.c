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
 * libVES/File.c              libVES: File object, for user vault items
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../jVar.h"
#include "../libVES.h"
#include "Ref.h"
#include "File.h"
#include "User.h"
#include "Util.h"

libVES_File *libVES_File_new(libVES_Ref *ref) {
    libVES_File *file = malloc(sizeof(libVES_File));
    if (!file) return NULL;
    file->id = 0;
    file->name = file->path = file->mime = NULL;
    file->external = ref;
    (void)libVES_REFUP(Ref, file->external);
    file->creator = NULL;
    return libVES_REFINIT(file);
}

libVES_File *libVES_File_fromJVar(jVar *data) {
    if (!data) return NULL;
    libVES_File *file = malloc(sizeof(libVES_File));
    if (!file) return NULL;
    file->id = jVar_getInt(jVar_get(data, "id"));
    file->name = jVar_getString0(jVar_get(data, "name"));
    file->path = jVar_getString0(jVar_get(data, "path"));
    file->mime = jVar_getString0(jVar_get(data, "mime"));
    file->external = libVES_External_fromJVar(jVar_get(data, "externals"));
    (void)libVES_REFUP(Ref, file->external);
    file->creator = libVES_User_fromJVar(jVar_get(data, "creator"));
    (void)libVES_REFUP(User, file->creator);
    return libVES_REFINIT(file);
}

int libVES_File_setCreator(libVES_File *file, struct libVES_User *user) {
    if (!file) return 0;
    libVES_User *old = file->creator;
    file->creator = libVES_REFUP(User, user);
    libVES_REFDN(User, old);
    return 1;
}

jVar *libVES_File_toJVar(libVES_File *file) {
    if (!file) return NULL;
    jVar *res = jVar_object();
    if (file->external) libVES_Ref_toJVar(file->external, res);
    if (file->name) jVar_put(res, "name", jVar_string(file->name));
    if (file->mime) jVar_put(res, "mime", jVar_string(file->mime));
    if (file->path) jVar_put(res, "path", jVar_string(file->path));
    if (file->creator) jVar_put(res, "creator", libVES_User_toJVar(file->creator));
    return res;
}

char *libVES_File_toURI(libVES_File *file) {
    if (!file || !file->external) return NULL;
    return libVES_buildURI(2, file->external->domain, file->external->externalId);
}

void libVES_File_free(libVES_File *file) {
    if (libVES_REFBUSY(file)) return;
    free(file->name);
    free(file->path);
    free(file->mime);
    (void)libVES_REFDN(User, file->creator);
    (void)libVES_REFDN(Ref, file->external);
    free(file);
}
