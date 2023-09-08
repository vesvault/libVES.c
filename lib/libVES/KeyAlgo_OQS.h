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
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
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
#define libVES_KeyAlgo_OQS_defaultAlgo		"Kyber768"

#define libVES_KeyAlgo_OQS_OID			"1.3.6.1.4.1.53675.3.5"
