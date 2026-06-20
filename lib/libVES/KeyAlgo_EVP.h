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
 * libVES/KeyAlgo_EVP.h       libVES: Vault Key algo header, via OpenSSL EVP
 *
 ***************************************************************************/

/***************************************************************************
 * RSA via EVP
 ***************************************************************************/
extern const struct libVES_KeyAlgo libVES_KeyAlgo_RSA;
#define libVES_KeyAlgo_RSA_defaultBits		4096

/***************************************************************************
 * ECDH via EVP
 ***************************************************************************/
extern const struct libVES_KeyAlgo libVES_KeyAlgo_ECDH;
#define libVES_KeyAlgo_ECDH_defaultCurve	NID_secp521r1

extern void *libVES_KeyAlgo_autoEVPfn;
extern void *libVES_KeyAlgo_autoPEMfn;

/***************************************************************************
 * Pseudo algo - autodetect from EVP private key
 ***************************************************************************/
#define libVES_KeyAlgo_autoEVP		libVES_KeyAlgo_pseudo(libVES_KeyAlgo_autoEVPfn)

/***************************************************************************
 * Pseudo algo - autodetect from PEM private key
 ***************************************************************************/
#define libVES_KeyAlgo_autoPEM		libVES_KeyAlgo_pseudo(libVES_KeyAlgo_autoPEMfn)

/***************************************************************************
 * Private PEM to EVP, use veskey if encrypted
 ***************************************************************************/
struct evp_pkey_st *libVES_KeyAlgo_EVP_fromPEM(const struct libVES_veskey *veskey, const char *pem);

/***************************************************************************
 * Private EVP to PEM, encrypted if veskey != NULL
 ***************************************************************************/
char *libVES_KeyAlgo_EVP_toPEM(const struct libVES_veskey *veskey, struct evp_pkey_st *pkey);


int libVES_KeyAlgo_EVP_veskey_cb(char *buf, int size, int rwflag, void *u);
