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
 * (c) 2023 VESvault Corp
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
 * KeyStore_cli.c                   libVES: CLI key store module
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include "KeyStore_cli_locale.h"


static const char *s_head[] = { "\r\n", "\x1b[1;32m", "libVES", "\x1b[0m", ": ", "\x1b[1;35m", "Key Store access requested", "\x1b[0m", "\r\n", NULL };
static const char *s_keyname[] = { "\tKey:    [", "\x1b[1m", NULL };
static const char *s_2[] = { "\x1b[0m", "]", "\r\n", NULL };
static const char *s_domain[] = { "\tDomain: [", "\x1b[1m", NULL };
static const char *s_user[] = { "\tUser:   [", "\x1b[1m", NULL };
static const char *s_pin[] = { "Enter PIN: ", NULL };
static const char *s_pin2[] = { "\r\n", NULL };
static const char *s_retry[] = { "Last entered PIN not checked. Retry in ", NULL };
static const char *s_retry2[] = { " sec", "\r\n" , NULL };
static const char *s_syncode[] = { "* open VESvault in the browser/app where this account is set up,", "\r\n",
	"* select \"", "\x1b[1;36m", "Add Another Browser/App", "\x1b[0m", "\" in the menu," "\r\n",
	"* upon entering the PIN, select the following Sync Code:", "\r\n", "\t[", "\x1b[1m", NULL };
static const char *s_syncode2[] = { "\x1b[0m", "]", "\r\n", 
	"* this dialog will continue once done.", "\r\n", NULL };
static const char *s_nouser[] = { "VES account is not set up.", "\r\n",
	"* Go to https://vesvault.com", "\r\n",
	"* Select \"", "\x1b[1;36m", "Create/Connect a VES Account", "\x1b[0m", "\" from the right menu", "\r\n", NULL };
static const char *s_noemail[] = { "Unknown VES account owner.", "\r\n", NULL };
static const char *s_primary[] = { "\tKey:    [", "\x1b[1;31m", "primary", "\x1b[0m", "]", "\r\n", NULL };
static const char *s_domadm[] = { "\t        [", "\x1b[1;31m", "domain admin", "\x1b[0m", "]", "\r\n", NULL };

struct libVES_KeyStore_cli_locale libVES_KeyStore_cli_locale_default = {
    .head = s_head,
    .keyname = s_keyname,
    .keyname2 = s_2,
    .domain = s_domain,
    .domain2 = s_2,
    .user = s_user,
    .user2 = s_2,
    .pin = s_pin,
    .pin2 = s_pin2,
    .retry = s_retry,
    .retry2 = s_retry2,
    .syncode = s_syncode,
    .syncode2 = s_syncode2,
    .nouser = s_nouser,
    .noemail = s_noemail,
    .primary = s_primary,
    .domadm = s_domadm
};
