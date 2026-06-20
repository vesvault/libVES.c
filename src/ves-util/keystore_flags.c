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
    { .val = LIBVES_KS_PRIMARY, .tag = "primary", "Use the primary session token and keep the primary vault unlocked. Typically combined with `elevate` when creating or rekeying secondary keys" },
    { .val = LIBVES_KS_PERSIST, .tag = "persist", "Obtain a persistent non-expiring session token. This is implied in `sess,save`" },
    { .val = LIBVES_KS_ELEVATE, .tag = "elevate", "Elevated authorization for the primary key, required for managing secondary keys. When creating a new secondary key from a synced account, combine with `primary` (e.g. `save,elevate,primary`) so the primary stays unlocked through the post" },
    { .tag = NULL }
};
