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
 * (c) 2022 VESvault Corp
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
 * libVES/KeyAlgo_OQS.h       libVES: Vault Key algo header, via libOQS
 *
 ***************************************************************************/

/***************************************************************************
 * libOQS KEM Wrapper
 ***************************************************************************/
typedef struct libVES_KeyAlgo_OQS_Key {
    struct OQS_KEM *kem;
    void *pub;
    void *priv;
} libVES_KeyAlgo_OQS_Key;

extern const struct libVES_KeyAlgo libVES_KeyAlgo_OQS;
/* FIPS 203 standardized parameter set. Must match a libOQS algorithm
 * identifier; "Kyber768" was removed in libOQS 0.12 in favor of "ML-KEM-768".
 * Existing keys carry their own algorithm in the stored method string, so this
 * default only affects newly generated keys.
 *
 * configure --with-oqs-algo=ALGO overrides it via LIBVES_KEYALGO_OQS_DEFAULT
 * in config.h, and verifies the choice against the installed liboqs. config.h
 * is not installed, so a consumer including this header out of includedir sees
 * the built-in default; the value that matters is the one KeyAlgo_OQS.c was
 * compiled with. Keep the literal below in sync with the fallback #error in
 * KeyAlgo_OQS.c. */
#ifdef LIBVES_KEYALGO_OQS_DEFAULT
#define libVES_KeyAlgo_OQS_defaultAlgo		LIBVES_KEYALGO_OQS_DEFAULT
#else
#define libVES_KeyAlgo_OQS_defaultAlgo		"ML-KEM-768"
#endif

#define libVES_KeyAlgo_OQS_OID			"1.3.6.1.4.1.53675.3.5"
