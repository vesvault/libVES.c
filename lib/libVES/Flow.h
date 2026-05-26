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
 * (c) 2026 VESvault Corp
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
 * libVES/Flow.h              libVES: VESflow e2ee VES authentication
 *
 ***************************************************************************/

typedef struct libVES_Flow {
    struct VESflow *flow;
    struct libVES *ves;
    const char *domain;
    const char *externalId;
    const char *flowurl;
    char *rwurl;
    char localurl[1];
} libVES_Flow;

#define LIBVES_FLOW_URL  "https://vesvault.com/vv/unlock"

/***************************************************************************
 * Instantiate a web-based e2ee libVES authenticator for a native app.
 * The ves parameter must be an instance of libVES with a VES domain
 * assigned, VES with authenticate an app vault within this domain.
 * Example: ves = libVES_new("ves://domain/\*")
 * The external ID may be "*", or an email address that will be used as an
 * account  hint for the VES authorization page.
 * The localurl parameter must be a URL serviced by the app, the VES
 * authenticator will add a hash fragment string to it to be used with
 * a subsequent libVES_Flow_auth call to unlock ves.
 ***************************************************************************/
struct libVES_Flow *libVES_Flow_new(struct libVES *ves, const char *localurl);

/***************************************************************************
 * Start the VES authentication. The flow instance comes from
 * a libVES_Flow_new() call, an optional url may contain additional
 * parameters for VES, normally relative starting with "?". Set url to NULL
 * to use default options.
 ***************************************************************************/
const char *libVES_Flow_start(struct libVES_Flow *flow, const char *url);

/***************************************************************************
 * Complete the authentication. The url is a redirect from the VES
 * authentication page, the hash fragment contains the e2ee and key exchange
 * data. Unlocks the libVES instance and returns it on success, returns NULL
 * on failure.
 ***************************************************************************/
struct libVES *libVES_Flow_auth(struct libVES_Flow *flow, const char *url);

/***************************************************************************
 * Retrieve a rewritten url, with a stripped hash fragment, after a
 * successful libVES_Flow_Auth() call.
 ***************************************************************************/
const char *libVES_Flow_geturl(struct libVES_Flow *flow);

/***************************************************************************
 * Destroy the uthenticator instance. Does not destroy the associated libVES
 * instance.
 ***************************************************************************/
void libVES_Flow_free(struct libVES_Flow *flow);
