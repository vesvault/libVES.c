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
 * VESflow.h                   libVES: URL-based e2ee messaging flow
 *
 ***************************************************************************/

typedef struct VESflow {
    struct VESflow_KeyStore *ks;
    void *ksref;
    struct VESflow_KeyEntry {
        struct VESflow_KeyEntry *chain;
        struct jVar *key;
        int type;
        char ref[1];
    } *keys;
    const char *defaultAlgo;
    const unsigned char *escapemap;
    const char *url;
    char name[1];
} VESflow;

typedef struct VESflow_KeyStore {
    struct jVar *(* getfn)(void *ksref, const char *ref, int type);
    int (* putfn)(void *ksref, const char *ref, int type, struct jVar *jkey);
} VESflow_KeyStore;

typedef struct VESflow_KeyAlgo {
    const char *(* algo)(struct jVar *jkey);
    struct jVar *(* keygen)(const char *ref);
    struct jVar *(* priv2pub)(struct jVar *jpriv);
    int (* derive)(struct jVar *jpub, struct jVar *jpriv, char **psh, int *pshlen, char **pkc, int *pkclen);
} VESflow_KeyAlgo;

#define VESFLOW_DEFAULTNAME     "default"
#define VESFLOW_DEFAULTALGO     "P-256"

#define VESFLOW_E_OK    0
#define VESFLOW_E_XCHG  -1
#define VESFLOW_E_ARG   -2
#define VESFLOW_E_KEY   -3
#define VESFLOW_E_DATA  -4
#define VESFLOW_E_ENC   -5
#define VESFLOW_E_MSG   -6


enum { VESFLOW_K_RPUB, VESFLOW_K_LPRIV, VESFLOW_K_LPUB };

struct jVar;

struct VESflow *VESflow_new(const char *name, const char *url);
int VESflow_send(struct VESflow *flow, const char *url, char **rwurl, struct jVar *data);
int VESflow_recv(struct VESflow *flow, const char *url, char **rwurl, struct jVar **pdata, const char *srcurl);
int VESflow_urlencode(struct VESflow *flow, const char *src, int len, char *dst);
int VESflow_urldecode(struct VESflow *flow, const char *src, int len, char *dst);
void VESflow_setKeyStore(struct VESflow *flow, struct VESflow_KeyStore *ks, void *ksref);
void VESflow_free(struct VESflow *flow);

