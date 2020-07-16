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
#define libVES_KeyAlgo_ECDH_defaultCurve	NID_secp384r1

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
struct evp_pkey_st *libVES_KeyAlgo_EVP_fromPEM(struct libVES_veskey *veskey, const char *pem);

/***************************************************************************
 * Private EVP to PEM, encrypted if veskey != NULL
 ***************************************************************************/
char *libVES_KeyAlgo_EVP_toPEM(struct libVES_veskey *veskey, struct evp_pkey_st *pkey);
