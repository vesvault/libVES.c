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
 * VESlocker.c                   libVES: Secure key storage
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <time.h>
#include "libVES.h"
#include "VESlocker.h"


const char *VESlocker_apiUrl = "https://veslocker.com/api/VESlocker.php";

VESlocker *VESlocker_new(const char *url) {
    VESlocker *vl = malloc(sizeof(VESlocker));
    vl->apiUrl = url ? url : VESlocker_apiUrl;
    vl->allocurl = NULL;
    vl->curl = 0;
    vl->httpInitFn = NULL;
    vl->error = VESLOCKER_E_OK;
    return vl;
}

static size_t VESlocker_http_callbk(void *ptr, size_t size, size_t nmemb, void *stream) {
    int len = size * nmemb;
    char *buf = stream;
    int l = strlen(buf);
    if (l + len > VESlocker_bufsize - 1) len = VESlocker_bufsize - l - 1;
    memcpy(buf + l, ptr, len);
    buf[l + len] = 0;
    return len;
}

static size_t VESlocker_hdr_callbk(char* buffer, size_t size, size_t nitems, void* userdata) {
    if (nitems > 8 && !strncmp(buffer, "Refresh:", 8)) {
	char fmt[16];
	sprintf(fmt, "%%%lulu", nitems);
	sscanf(buffer + 8, fmt, &((VESlocker *)userdata)->retry);
    }
    return nitems;
}

int VESlocker_getkey(VESlocker *vl, const char *entryid, const char *seed, const char *pin, char *key) {
    char post[128];
    char *d = post;
    strcpy(d, "id=");
    d += 3;
    d += strlen(libVES_b64encode_web(entryid, VESlocker_idsize, d));
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    unsigned int shalen = VESlocker_chsize;
    unsigned char *sha = (unsigned char*)post + sizeof(post) - VESlocker_chsize;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) > 0
	&& EVP_DigestUpdate(mdctx, seed, VESlocker_seedsize) > 0
	&& EVP_DigestUpdate(mdctx, pin, strlen(pin)) > 0
	&& EVP_DigestFinal_ex(mdctx, sha, &shalen) > 0) {
	strcpy(d, "&challenge=");
	d += 11;
	d += strlen(libVES_b64encode_web((char *)sha, shalen, d));
    } else return EVP_MD_CTX_free(mdctx), vl->error - VESLOCKER_E_LIB;
    EVP_MD_CTX_free(mdctx);
    if (!vl->curl) vl->curl = curl_easy_init();
    if (vl->httpInitFn) vl->httpInitFn(vl);
#ifdef VESLOCKER_DEBUG
    fprintf(stderr, "post = %s\n", post);
    curl_easy_setopt(vl->curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(vl->curl, CURLOPT_URL, vl->apiUrl);
    struct curl_slist *hdrs = curl_slist_append(NULL, "User-Agent: VESlocker (https://veslocker.com)");
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(vl->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(vl->curl, CURLOPT_POSTFIELDSIZE, d - post);
    curl_easy_setopt(vl->curl, CURLOPT_HTTPHEADER, hdrs);
    char cbuf[VESlocker_bufsize];
    cbuf[0] = 0;
    curl_easy_setopt(vl->curl, CURLOPT_WRITEFUNCTION, &VESlocker_http_callbk);
    curl_easy_setopt(vl->curl, CURLOPT_WRITEDATA, cbuf);
    curl_easy_setopt(vl->curl, CURLOPT_HEADERFUNCTION, &VESlocker_hdr_callbk);
    curl_easy_setopt(vl->curl, CURLOPT_HEADERDATA, vl);
    int curlerr = curl_easy_perform(vl->curl);
    if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(vl->curl, CURLINFO_RESPONSE_CODE, &vl->httpcode);
    curl_slist_free_all(hdrs);
    curl_easy_reset(vl->curl);
    if (curlerr != CURLE_OK) return vl->error = VESLOCKER_E_LIB;
    switch (vl->httpcode) {
	case 403:
	    return vl->error = VESLOCKER_E_RETRY;
	case 200:
	    if (libVES_b64decode(cbuf, &key) == VESlocker_keysize) return 0;
	default:
	    return vl->error = VESLOCKER_E_API;
    }
}

VESlocker_entry *VESlocker_entry_parse(const char *vlentry) {
    if (!vlentry) return NULL;
    VESlocker_entry *e = malloc(sizeof(VESlocker_entry) + strlen(vlentry) + 1);
    if (!e) return NULL;
    strcpy(e->data, vlentry);
    e->entryid = strchr(e->data, '#');
    if (e->entryid) {
	*e->entryid++ = 0;
	e->url = e->data;
    } else {
	e->entryid = e->data;
	e->url = NULL;
    }
    e->seed = strchr(e->entryid, '.');
    if (e->seed) *e->seed++ = 0;
    e->value = e->seed ? strchr(e->seed, '.') : NULL;
    if (e->value) *e->value++ = 0;
    e->extra = e->value ? strchr(e->value, '.') : NULL;
    if (e->extra) *e->extra++ = 0;
    return e;
}

const char *VESlocker_seturl(VESlocker *vl, const char *url) {
    free(vl->allocurl);
    return vl->apiUrl = vl->allocurl = strdup(url);
}

int VESlocker_encval(VESlocker *vl, const char *val, size_t len, char *ctext) {
    int rs;
    int ctlen = len;
    int ctlenf = len;
    unsigned char *ctbuf = (unsigned char *)ctext + libVES_b64encsize(len + VESlocker_gcmsize) - len - VESlocker_gcmsize;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if ((EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (const unsigned char *)vl->enc.key, (const unsigned char *)vl->enc.seed) > 0)
	&& (EVP_EncryptUpdate(ctx, ctbuf, &ctlen, (const unsigned char *)val, len) > 0)
	&& (EVP_EncryptFinal_ex(ctx, ctbuf + ctlen, &ctlenf) > 0)
	&& (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VESlocker_gcmsize, ctbuf + ctlen + ctlenf) > 0)) {
	ctlen += ctlenf + VESlocker_gcmsize;
	rs = strlen(libVES_b64encode_web((char *)ctbuf, ctlen, ctext));
    } else rs = vl->error = VESLOCKER_E_CRYPTO;
    EVP_CIPHER_CTX_free(ctx);
    return rs;
}

int VESlocker_decval(VESlocker *vl, const char *ctext, char *val) {
    int rs;
    int len = libVES_b64decode(ctext, &val) - VESlocker_gcmsize;
    if (len < 0) return vl->error = VESLOCKER_E_CRYPTO;
    int ptlen = len;
    int ptlenf = len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if ((EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (const unsigned char *)vl->dec.key, (const unsigned char *)vl->dec.seed) > 0)
	&& (EVP_DecryptUpdate(ctx, (unsigned char *)val, &ptlen, (const unsigned char *)val, len) > 0)
	&& (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VESlocker_gcmsize, (unsigned char *)val + len) > 0)
	&& (EVP_DecryptFinal_ex(ctx, (unsigned char *)val + ptlen, &ptlenf) > 0)) {
	rs = ptlen + ptlenf;
    } else rs = vl->error = VESLOCKER_E_CRYPTO;
    EVP_CIPHER_CTX_free(ctx);
    return rs;
}

char *VESlocker_encrypt(VESlocker *vl, const char *val, size_t len, const char *pin, char *vlentry) {
    char entryid[VESlocker_idsize];
    char *allocd = NULL;
    if (!val || !pin) return NULL;
    if (!vlentry && !(vlentry = allocd = malloc(VESlocker_encsize(vl, len)))) return NULL;
    RAND_bytes((unsigned char *)entryid, sizeof(entryid));
    RAND_bytes((unsigned char *)vl->enc.seed, sizeof(vl->enc.seed));
    strcpy(vlentry, vl->apiUrl);
    char *d = vlentry + strlen(vlentry);
    *d++ = '#';
    d += strlen(libVES_b64encode_web(entryid, sizeof(entryid), d));
    *d++ = '.';
    d += strlen(libVES_b64encode_web(vl->enc.seed, sizeof(vl->enc.seed), d));
    *d++ = '.';
    if (VESlocker_getkey(vl, entryid, vl->enc.seed, pin, vl->enc.key) < 0 || VESlocker_encval(vl, val, len, d) < 0) return free(allocd), NULL;
    return vlentry;
}

int VESlocker_decrypt(VESlocker *vl, const VESlocker_entry *e, const char *pin, char **pval) {
    char entryid[VESlocker_idsize];
    char *pentryid = entryid;
    char *pseed = vl->dec.seed;
    if (!e || !e->value) return vl->error = VESLOCKER_E_BUF;
    if (!pval) return VESlocker_decsize(e);
    if (!*pval && !((*pval = malloc(VESlocker_decsize(e))))) return vl->error = VESLOCKER_E_BUF;
    if (e->url) VESlocker_seturl(vl, e->url);
    int l = libVES_b64decode(e->entryid, &pentryid);
    if (l < VESlocker_idsize) memset(entryid + l, 0, VESlocker_idsize - l);
    l = libVES_b64decode(e->seed, &pseed);
    if (l < VESlocker_seedsize) memset(vl->dec.seed + l, 0, VESlocker_seedsize - l);
    int r = VESlocker_getkey(vl, entryid, vl->dec.seed, pin, vl->dec.key);
    if (r < 0) return r;
    return VESlocker_decval(vl, e->value, *pval);
}

void VESlocker_free(VESlocker *vl) {
    if (!vl) return;
    OPENSSL_cleanse(&vl->dec, sizeof(vl->dec));
    OPENSSL_cleanse(&vl->enc, sizeof(vl->enc));
    free(vl->allocurl);
    if (vl->curl) curl_easy_cleanup(vl->curl);
    free(vl);
}
