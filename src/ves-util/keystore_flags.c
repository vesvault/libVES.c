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
 * ves-util/keystore_flags.c  VES Utility: -E option flags
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libVES/KeyStore.h>
#include "../ves-util.h"
#include "keystore_flags.h"

struct keystore_flag keystore_flags[] = {
    { .val = 0, .tag = "default", .info = "Default options" },
    { .val = LIBVES_KS_NOPIN, .tag = "nopin", .info = "Disable VESlocker PIN dialog, fail if no plaintext key stored. Does not disable PIN dialog on sync, `nopin,nosync` to do so" },
    { .val = LIBVES_KS_NOSYNC, .tag = "nosync", .info = "Disable VES account syncing, fail if not previously synced" },
    { .val = LIBVES_KS_SESS, .tag = "sess", .info = "No app key required, use a persistent session token for a write-only vault access if available" },
    { .val = LIBVES_KS_SAVE, .tag = "save", .info = "Save a plaintext app key for further access without PIN. Use `save,sess` to save a persistent session token" },
    { .val = LIBVES_KS_FORGET, .tag = "forget", "Delete a previously synced account, a saved plaintext app key (`forget,nopin`) or a session token (`forget,sess`)" },
    { .val = LIBVES_KS_RESYNC, .tag = "resync", "Force VES account syncing" },
    { .val = LIBVES_KS_PRIMARY, .tag = "primary", "Use the primary session token and keep the primary vault unlocked" },
    { .val = LIBVES_KS_PERSIST, .tag = "persist", "Obtain a persistent non-expiring session token. This is implied in `sess,save`" },
    { .tag = NULL }
};
