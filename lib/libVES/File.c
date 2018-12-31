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
    file->id = 0;
    file->name = file->path = file->mime = NULL;
    file->external = ref;
    file->owner = NULL;
    return file;
}

libVES_File *libVES_File_fromJVar(jVar *data) {
    if (!data) return NULL;
    libVES_File *file = malloc(sizeof(libVES_File));
    file->id = jVar_getInt(jVar_get(data, "id"));
    file->name = jVar_getString0(jVar_get(data, "name"));
    file->path = jVar_getString0(jVar_get(data, "path"));
    file->mime = jVar_getString0(jVar_get(data, "mime"));
    file->external = libVES_External_fromJVar(jVar_get(data, "externals"));
    file->owner = libVES_User_fromJVar(jVar_get(data, "owner"));
    return file;
}

jVar *libVES_File_toJVar(libVES_File *file) {
    if (!file) return NULL;
    jVar *res = jVar_object();
    if (file->external) libVES_Ref_toJVar(file->external, res);
    if (file->name) jVar_put(res, "name", jVar_string(file->name));
    if (file->mime) jVar_put(res, "mime", jVar_string(file->mime));
    if (file->path) jVar_put(res, "path", jVar_string(file->path));
    if (file->owner) jVar_put(res, "owner", libVES_User_toJVar(file->owner));
    return res;
}

char *libVES_File_toURI(libVES_File *file) {
    if (!file) return NULL;
    return libVES_buildURI(2, file->external->domain, file->external->externalId);
}

void libVES_File_free(libVES_File *file) {
    if (!file) return;
    free(file->name);
    free(file->path);
    free(file->mime);
    libVES_User_free(file->owner);
    libVES_Ref_free(file->external);
    free(file);
}
