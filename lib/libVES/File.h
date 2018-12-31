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
    struct libVES_User *owner;
} libVES_File;

libVES_File *libVES_File_new(struct libVES_Ref *ref);
libVES_File *libVES_File_fromJVar(struct jVar *data);
struct jVar *libVES_File_toJVar(libVES_File *file);
char *libVES_File_toURI(libVES_File *file);
void libVES_File_free(libVES_File *file);
