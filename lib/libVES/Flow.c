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
 * libVES/Flow.c              libVES: VESflow e2ee VES authentication
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "../libVES.h"
#include "../jVar.h"
#include "../VESflow.h"
#include "Ref.h"
#include "VaultKey.h"
#include "Util.h"
#include "Flow.h"

libVES_Flow *libVES_Flow_new(libVES *ves, const char *localurl) {
    if (!ves || !localurl) return NULL;
    libVES_Ref *ext = libVES_getExternal(ves);
    const char *dom;
    if (!ext || !(dom = libVES_Ref_getDomain(ext))) return libVES_setError(ves, LIBVES_E_PARAM, "Domain expected on the libVES instance passed to Flow"), NULL;
    libVES_Flow *f = malloc(sizeof(libVES_Flow) + strlen(localurl));
    f->ves = ves;
    f->domain = dom;
    f->externalId = libVES_Ref_getExternalId(ext);
    if (f->externalId && !strchr(f->externalId, '@')) f->externalId = NULL;
    f->flow = VESflow_new("VES", NULL);
    f->rwurl = NULL;
    f->flowurl = LIBVES_FLOW_URL;
    strcpy(f->localurl, localurl);
    return f;
}

struct libVES_Flow_urlp {
    const char *query;
    const char *hash;
    const char *end;
};

static void libVES_Flow_parseurl(struct libVES_Flow_urlp *p, const char *url) {
    if (url) {
        p->end = url + strlen(url);
        p->query = strchr(url, '?');
        p->hash = strchr(url, '#');
        if (!p->hash) p->hash = p->end;
        if (!p->query || p->query > p->hash) p->query = p->hash;
    } else {
        p->query = p->hash = p->end = NULL;
    }
}

static int libVES_Flow_addurlparam(libVES_Flow *flow, const char *key, const char *val, char *url) {
    char *d = url;
    d += strlen(strcpy(d, key));
    *d++ = '=';
    if (val) d += VESflow_urlencode(flow->flow, val, strlen(val), d);
    return d - url;
}

static int libVES_Flow_addurlstr(libVES_Flow *flow, const char *str, const char *e, char *url) {
    int len = e - str;
    memcpy(url, str, len);
    return len;
}

static void libVES_Flow_setError(libVES_Flow *flow, int er) {
    char err[128];
    sprintf(err, "VESflow error (%d)", er);
    libVES_setError(flow->ves, LIBVES_E_INTERNAL, err);
}

const char *libVES_Flow_start(struct libVES_Flow *flow, const char *url) {
    if (!flow) return NULL;
    free(flow->rwurl);
    flow->rwurl = NULL;
    int arglen = strlen(flow->domain) + strlen(flow->localurl) + 32;
    if (flow->externalId) arglen += strlen(flow->externalId) + 16;
    char *flowurl = libVES_resolveUrl(flow->ves, flow->flowurl);
    char *authurl = malloc(strlen(flowurl) + 3 * arglen + (url ? strlen(url) : 0));
    char *d = authurl;
    const char *base = !url || url[0] == '?' || url[0] == '#' ? flowurl : NULL;
    struct libVES_Flow_urlp bp, up;
    char qc = '?';
    libVES_Flow_parseurl(&bp, base);
    libVES_Flow_parseurl(&up, url);
    if (base) {
        d += libVES_Flow_addurlstr(flow, base, bp.hash, d);
        if (*bp.query == '?') qc = '&';
    }
    if (url) {
        const char *s = url;
        if (*s == '?') {
            *d++ = qc;
            s++;
            qc = '&';
        }
        d += libVES_Flow_addurlstr(flow, s, up.hash, d);
    }
    *d++ = qc;
    d += libVES_Flow_addurlparam(flow, "domain", flow->domain, d);
    *d++ = '&';
    d += libVES_Flow_addurlparam(flow, "url", flow->localurl, d);
    if (flow->externalId) {
        *d++ = '&';
        d += libVES_Flow_addurlparam(flow, "email", flow->externalId, d);
    }
    if (base) d += libVES_Flow_addurlstr(flow, bp.hash, bp.end, d);
    if (url) d += libVES_Flow_addurlstr(flow, up.hash, up.end, d);
    *d = 0;
    int rs = VESflow_send(flow->flow, authurl, &flow->rwurl, NULL);
    free(authurl);
    free(flowurl);
    if (rs == VESFLOW_E_OK) return flow->rwurl;
    return libVES_Flow_setError(flow, rs), NULL;
}

struct libVES *libVES_Flow_auth(struct libVES_Flow *flow, const char *url) {
    if (!flow) return NULL;
    free(flow->rwurl);
    flow->rwurl = NULL;
    jVar *jauth = NULL;
    int rs = VESflow_recv(flow->flow, url, &flow->rwurl, &jauth, NULL);
    libVES *ves = NULL;
    if (rs == VESFLOW_E_OK) {
        const char *extid = jVar_getStringP(jVar_get(jauth, "externalId"));
        jVar *jvk = jVar_get(jauth, "VESkey");
        const char *vk = jVar_getStringP(jvk);
        int vkl = jVar_cpString(jvk, NULL, -1);
        if (!extid || !vk || vkl < 0) libVES_setError(flow->ves, LIBVES_E_INTERNAL, "Bad flow response");
        else {
            ves = flow->ves;
            libVES_lock(ves);
            libVES_REFDN(VaultKey, ves->vaultKey);
            ves->vaultKey = NULL;
            libVES_REFDN(Ref, ves->external);
            libVES_Ref *ext = libVES_External_new(flow->domain, extid);
            ves->external = libVES_REFUP(Ref, ext);
            libVES_veskey *veskey = libVES_veskey_new(vkl, vk);
            libVES_unlock_veskey(ves, veskey) || (ves = NULL);
            libVES_veskey_free(veskey);
        }
    } else libVES_Flow_setError(flow, rs);
    libVES_cleanseJVar(jauth);
    jVar_free(jauth);
    return ves;
}

const char *libVES_Flow_geturl(struct libVES_Flow *flow) {
    return flow ? flow->rwurl : NULL;
}

void libVES_Flow_free(struct libVES_Flow *flow) {
    if (flow) {
        VESflow_free(flow->flow);
        free(flow->rwurl);
    }
    free(flow);
}

