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
 * libVES/CiAlgo_AES.h        libVES: Stream cipher AES* algorithm header
 *
 ***************************************************************************/

/***************************************************************************
 * AES256GCM1K
 * Chunked seekable GCM stream cipher with integrity check.
 ***************************************************************************/
extern const struct libVES_CiAlgo libVES_CiAlgo_AES256GCM1K;

/***************************************************************************
 * AES256CFB
 * Seekable CFB stream cipher, no integrity check.
 ***************************************************************************/
extern const struct libVES_CiAlgo libVES_CiAlgo_AES256CFB;

/***************************************************************************
 * AES256GCMp
 * Padded GCM, used internally for Vault Item content.
 ***************************************************************************/
extern const struct libVES_CiAlgo libVES_CiAlgo_AES256GCMp;
