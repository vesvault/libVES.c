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
 * libVES/CiAlgo_AES.h        libVES: Stream cipher AES* algorithm header
 *
 ***************************************************************************/


typedef struct libVES_CiAlgo_AESgcm {
    unsigned char key[32];
    unsigned char seed[12];
    unsigned char iv[12];
    size_t offs;
    union {
	char *pbuf;
	struct {
	    void *mdctx;
	    char gbuf[16];
	};
    };
} libVES_CiAlgo_AESgcm;

typedef struct libVES_CiAlgo_AEScfb {
    unsigned char key[32];
    unsigned char seed[32];
    unsigned char iv[32];
} libVES_CiAlgo_AEScfb;


#define libVES_Cipher_KEYLENforVEntry	(sizeof(((libVES_CiAlgo_AESgcm *)0)->key) + sizeof(((libVES_CiAlgo_AESgcm *)0)->seed))
#define libVES_Cipher_PADLENforVEntry	48


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
