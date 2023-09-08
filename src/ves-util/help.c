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
 * ves-util/help.c            VES Utility: Help message
 *
 ***************************************************************************/
#include "help.h"

const char *VESbanner =
"          \x1b[1;31m___\x1b[0m       ___\n"
"         \x1b[1;31m/   \\\x1b[0m     /   \\    \x1b[1mVESvault\x1b[0m\n"
"         \x1b[1;31m\\__ /\x1b[0m     \\ __/    Encrypt Everything without fear of losing the Key\n"
"            \x1b[1;31m\\\\\x1b[0m     //                   \x1b[1;34mhttps://vesvault.com https://ves.host\n\x1b[0m"
"             \x1b[1;31m\\\\\x1b[0m   //\n"
"     ___      \x1b[1;31m\\\\\x1b[0m_//\n"
"    /   \\     /   \\         \x1b[1mlibVES\x1b[0m:                      VESvault API library\n"
"    \\__ /     \\ __/\n"
"       \\\\     //            \x1b[1mVES Utility\x1b[0m:   A command line interface to libVES\n"
"        \\\\   //\n"
"         \\\\_//              - Key Management and Exchange\n"
"         /   \\              - Item Encryption and Sharing\n"
"         \\___/              - Stream Encryption\n"
"\n"
"Use '\x1b[1mves --help\x1b[0m' for command line options list\n"
"See \x1b[1;34mhttps://ves.host/docs/ves-util\x1b[0m for more comprehensive documentation.\n"
;

const char *VEShelp =
       "Usage summary:\n"
       "ves [authentication] operation ...\n"
       "\n"
       "See https://ves.host/docs/ves-util for more comprehensive documentation.\n"
       "\n"
       "Authentication and Vault Management:\n"
       "  -a URI, --account=...         Select an App Vault,\n"
       "                                URI = \"[ves:]//domain/externalId/\"\n"
       "  -E [flag[,flag...]]           Use a local Encryption Key Store\n"
       "        -El                     List available Key Store flags\n"
       "  -u VESKEY, --unlock=VESKEY    Unlock the App Vault using VESKEY\n"
       "        -uf FILE                Unlock the App Vault using VESkey read from FILE\n"
       "        -up, -upf FILE          Print the App Vault VESkey (-A required)\n"
       "  -A EMAIL, --primary=...       Select a VES Account / Primary Vault,\n"
       "                                EMAIL = \"email\" | \"ves:////email\"\n"
       "  -T TOKEN, --token=...         Apply a Session Token\n"
       "        -Tp, -Tpf FILE          Print the current Session Token\n"
       "  -L, --lock                    Keep the Vault locked\n"
       "  -n, --new                     Create a new App Vault (-a & -A required,\n"
       "                                -G | -y | -u are used if provided)\n"
       "\n"
       "Vault Item Operations:\n"
       "  -o URI, --vault-item=...      Select a Vault Item,\n"
       "                                URI = \"[ves:][//domain/]externalId\"\n"
       "  -i DATA, item=...             Set the raw content of the Vault Item\n"
       "        -if FILE                Content for the Vault Item from FILE\n"
       "                                (size limits apply, use -P & -C for large files)\n"
       "        -ip, -ipf FILE          Print the raw content of the Vaut Item\n"
       "  -s URI[,URI...], --share=...  Share the Vault Items with specified Vaults,\n"
       "                                any existing shares will remain intact,\n"
       "                                URI = \"[ves:][//domain/]externalId/[userRef]\"\n"
       "  -r URI[,URI...], --unshare=...\n"
       "                                Stop sharing the Vault Item with specific Vaults\n"
       "  -S URI[,URI...], --set-share=...\n"
       "                                Share the Vault Items with specified Vaults,\n"
       "                                any other shares will be removed\n"
       "        -Sp, -Spf FILE          Print the share list for the item:\n"
       "                                    key_id <SP> key_uri <SP> key_type <LF>\n"
       "  -m JSON, --meta=...           Specify plaintext metadata for the Vault Item\n"
       "        -mp, -mpf FILE          Print JSON plaintext Vault Item metadata\n"
       "  --delete                      Delete the Vault Item\n"
       "  -U, --force                   Force the update of the Vault Item,\n"
       "                                Undelete a deleted Vault Item\n"
       "  -X, --explore                 Print human readable info about the Vault Item\n"
       "\n"
       "Stream Cipher Operations:\n"
       "                                All Stream Cipher actions require -o Vault Item\n"
       "                                that stores the symmetric cipher key, and can be\n"
       "                                combined with appropriate Vault Item options\n"
       "  -c ALGO, --cipher ALGO        Create a new stream cipher key for ALGO,\n"
       "                                (can be combined with -i to supply a raw key)\n"
       "        -cp, -cpf FILE          Print the algorithm of the cipher key (if any)\n"
       "        -cl                     List supported stream cipher algos\n"
       "  -z JSON, --cipher-meta=...    Specify secret metadata for the cipher key\n"
       "        -zp, -zpf FILE          Print JSON secret cipher metadata\n"
       "  -e, --encrypt                 Stream encryption, -P >> -C | stdin >> stdout\n"
       "  -d, --decrypt                 Stream decryption, -C >> -P | stdin >> stdout\n"
       "  -P[f] FILE, --plaintext=...   Plaintext file for -e | -d\n"
       "  -C[f] FILE, --ciphertext=...  Ciphertext file for -e | -d\n"
       "\n"
       "Vault Key Operations:\n"
       "  -k URI, --vault-key=...       Select a Vault Key,\n"
       "                                URI = \"[ves:][//domain/]externalId/[userRef]\"\n"
       "  -l, --list                    List Vault Items shared with the Vault Key,\n"
       "                                (can be used without -k to act on -a | -A)\n"
       "  -v VESKEY, --veskey=...       Supply a VESkey for generated Vault Key, or -k\n"
       "        -vp, -vpf FILE          Print the current VESkey for -k\n"
       "  -g, --generate                Generate or re-generate the Vault Key\n"
       "  -y KEY, --private-key=...     Supply a PEM private key to create the Vault Key\n"
       "        -yf FILE                Private key from the PEM FILE\n"
       "        -yp, -ypf FILE          Print the PEM private key, non-encrypted if the\n"
       "                                key is unlocked, encrypted otherwise\n"
       "  -Y[p], --public-key, -Ypf FILE\n"
       "                                Print a PEM public key\n"
       "  -G ALGO, --key-algo=...       Algorithm to generate the Vault Key\n"
       "        -Gp, -Gpf FILE          Print the algorithm name\n"
       "        -Gl                     List supported Vault Key algos\n"
       "  --delete                      Delete the Vault Key (API restrictions apply)\n"
       "  -R, --rekey                   Share all Vault Items on the key with the\n"
       "                                active key for the matching Vault\n"
       "  -K, --propagate               Share the VESkey vault item with the owner's\n"
       "                                respective Primary and/or App Vault\n"
       "  -M, --manual                  Disable automatic propagation and rekeying for\n"
       "                                Temporary Vault Keys\n"
       "  -X, --explore                 Print human readable info about the Vault Key\n"
       "\n"
       "Action Modifiers:\n"
       "  -p, --print                   Print the current value of the preceding option.\n"
       "  -f FILE, --flie=...           Read a value from, or write to, a file.\n"
       "  -F FDESC, --fd=...            Read a value from, or write to, a file descriptor,\n"
       "                                (can be used anywhere instead of -f)"
       "\n"
       "Miscellaneous:\n"
       "  -x, --debug                   Display debugging messages.\n"
       "        -xx                     More detailed debugging.\n"
       "  -q, --quiet                   Suppress error messages, except for arg errors.\n"
       "                                Return error codes only\n"
       "                                (can be used with -o without authentication\n"
       "                                to check if the Vault Item exists, by exit code)\n"
       "  -V, --version                 Print version information and exit\n"
       "  -h, --help                    Print this help screen and exit\n"
;
