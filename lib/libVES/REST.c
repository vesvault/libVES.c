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
 * libVES/REST.c              libVES: REST API communications via libcURL
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdarg.h>
#include "../jVar.h"
#include "../libVES.h"
#include "REST.h"
#include "Util.h"

struct libVES_curl_buf {
    jVarParser *parser;
    libVES *ves;
};

size_t libVES_REST_callbk(void *ptr, size_t size, size_t nmemb, void *stream) {
    int len = size * nmemb;
    struct libVES_curl_buf *cbuf = stream;
    if (cbuf->ves->debug > 1) fprintf(stderr, "<<<< %.*s\n", len, (char *) ptr);
    if (!cbuf->parser) cbuf->parser = jVarParser_new(NULL);
    cbuf->parser = jVarParser_parse(cbuf->parser, ptr, len);
    return len;
}

void *libVES_REST_init(libVES *ves) {
    if (!ves) return NULL;
    if (!ves->curl) ves->curl = curl_easy_init();
    return ves->curl;
}

jVar *libVES_REST_req(libVES *ves, const char *url, jVar *body, struct curl_slist *hdrs, long *pcode) {
    if (ves->httpInitFn) ves->httpInitFn(ves);
    if (ves->debug > 0) curl_easy_setopt(ves->curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(ves->curl, CURLOPT_URL, url);
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    char buf[1024];
    sprintf(buf, "User-Agent: %s (https://ves.host) %s (%s)", LIBVES_VERSION_SHORT, ves->appName, curl_version());
    hdrs = curl_slist_append(hdrs, buf);
    char *json;
    if (body) {
	hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
	json = jVar_toJSON(body);
	if (ves->debug > 1) fprintf(stderr, ">>>> %s\n", json);
	curl_easy_setopt(ves->curl, CURLOPT_POSTFIELDS, json);
	curl_easy_setopt(ves->curl, CURLOPT_POSTFIELDSIZE, strlen(json));
    } else json = NULL;
    curl_easy_setopt(ves->curl, CURLOPT_HTTPHEADER, hdrs);
    struct libVES_curl_buf cbuf = {
	.parser = NULL,
	.ves = ves
    };
    curl_easy_setopt(ves->curl, CURLOPT_WRITEFUNCTION, &libVES_REST_callbk);
    curl_easy_setopt(ves->curl, CURLOPT_WRITEDATA, &cbuf);
    int curlerr = curl_easy_perform(ves->curl);
    if (curlerr == CURLE_OK && pcode) curlerr = curl_easy_getinfo(ves->curl, CURLINFO_RESPONSE_CODE, pcode);
    curl_slist_free_all(hdrs);
    curl_easy_reset(ves->curl);
    free(json);
    jVar *rsp;
    if (cbuf.parser) {
	int cpl = jVarParser_isComplete(cbuf.parser);
	rsp = jVarParser_done(cbuf.parser);
	if (!cpl) {
	    jVar_free(rsp);
	    rsp = NULL;
	}
    } else {
	rsp = NULL;
    }
    if (curlerr != CURLE_OK) {
	jVar_free(rsp);
	const char *curlstr = curl_easy_strerror(curlerr);
	char *errstr = malloc(128 + (curlstr ? strlen(curlstr) : 0));
	if (errstr) sprintf(errstr, "cURL error %d: %s", curlerr, curlstr);
	libVES_throw(ves, LIBVES_E_CONN, errstr, NULL);
    }
    if (!rsp) libVES_throw(ves, LIBVES_E_PARSE, "Error parsing JSON response", NULL);
    return rsp;
}

jVar *libVES_REST_hdrs(libVES *ves, const char *uri, jVar *body, struct curl_slist *hdrs) {
    char buf[1024];
    sprintf(buf, "%s%s", ves->apiUrl, uri);
    if (ves->attnFn) {
	char *p = buf + strlen(buf);
	*p++ = strchr(buf, '?') ? '&' : '?';
	strcpy(p, "attn=%2A");
    }
    long code;
    jVar *rsp = libVES_REST_req(ves, buf, body, hdrs, &code);
    if (!rsp) return NULL;
    int err;
    char *errstr = NULL;
    switch (code) {
	case 200:
	    err = LIBVES_E_OK;
	    break;
	case 401:
	case 403:
	    err = LIBVES_E_DENIED;
	    break;
	case 404:
	    err = LIBVES_E_NOTFOUND;
	    break;
	default:
	    err = LIBVES_E_SERVER;
	    break;
    }
    jVar *res = NULL;
    if (ves->attnFn) {
	jVar *attn = jVar_get(rsp, "attn");
	if (attn) {
	    ves->attnFn(ves, attn);
	    ves->attnFn = NULL;
	}
    }
    if (err == LIBVES_E_OK) {
	res = jVar_get(rsp, "result");
	res = jVar_isObject(res) ? jVar_detach(res) : NULL;
	if (!res) libVES_setError(ves, LIBVES_E_PARSE, "Missing result in the API server response");
    } else {
	jVar *rerr = jVar_index(jVar_get(rsp, "errors"), 0);
	if (rerr) {
	    const char *rtype = jVar_getStringP(jVar_get(rerr, "type"));
	    const char *rmsg = jVar_getStringP(jVar_get(rerr, "message"));
	    errstr = malloc(128 + (rtype ? strlen(rtype) : 0) + (rmsg ? strlen(rmsg) : 0));
	    if (errstr) sprintf(errstr, "API: HTTP %ld - %s: %s", code, rtype, rmsg);
	} else {
	    errstr = malloc(128);
	    if (errstr) sprintf(errstr, "API: HTTP %ld", code);
	}
	libVES_setError0(ves, err, errstr);
    }
    jVar_free(rsp);
    return res;
}

jVar *libVES_REST(libVES *ves, const char *uri, jVar *body) {
    if (!libVES_REST_init(ves)) return NULL;
    char buf[256];
    struct curl_slist *hdrs = NULL;
    if (ves->sessionToken) {
	sprintf(buf, "Authorization: Bearer %.80s", ves->sessionToken);
	hdrs = curl_slist_append(hdrs, buf);
    }
    return libVES_REST_hdrs(ves, uri, body, hdrs);
}

jVar *libVES_REST_login(libVES *ves, const char *uri, jVar *body, const char *username, const char *passwd) {
    if (!libVES_REST_init(ves)) return NULL;
    size_t lu, lp;
    if (!username || !passwd || (lu = strlen(username)) + (lp = strlen(passwd)) > 160) libVES_throw(ves, LIBVES_E_PARAM, "Username/passwd for HTTP auth are missing or invalid", NULL);
    char buf[1024] = "Authorization: Basic \0";
    char *bufp = buf + sizeof(buf) - lu - lp - 4;
    memcpy(bufp, username, lu);
    bufp[lu] = ':';
    memcpy(bufp + lu + 1, passwd, lp);
    libVES_b64encode(bufp, lu + lp + 1, buf + strlen(buf));
    return libVES_REST_hdrs(ves, uri, body, curl_slist_append(NULL, buf));
}

jVar *libVES_REST_VESauthGET(libVES *ves, const char *url, long *pcode, const char *fmt, ...) {
    if (!libVES_REST_init(ves)) return NULL;
    char auth[1024];
    strcpy(auth, "X-VES-Authorization: ");
    va_list va;
    va_start(va, fmt);
    vsprintf(auth + strlen(auth), fmt, va);
    va_end(va);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth);
    const char *h = strchr(url, '#');
    if (h) {
	char *url2 = strdup(url);
	if (!url2) return NULL;
	char *p = url2 + (h - url);
	*p++ = 0;
	switch (*p) {
	    case '/':
		p++;
		break;
	    case 0:
		p = NULL;
	    default:
		break;
	}
	jVar *rsp = libVES_REST_req(ves, url2, NULL, hdrs, pcode);
	jVar *rs = rsp;
	while (rs && p) {
	    char *p1 = strchr(p, '/');
	    if (p1) *p1++ = 0;
	    if (jVar_isObject(rs)) {
		rs = jVar_get(rs, p);
	    } else if (jVar_isArray(rs)) {
		int idx, c;
		rs = sscanf(p, "%d%c", &idx, &c) == 1 ? jVar_index(rs, idx) : NULL;
	    } else {
		rs = NULL;
	    }
	    p = p1;
	}
	free(url2);
	if (rs != rsp) {
	    if (rs) rs = jVar_detach(rs);
	    jVar_free(rsp);
	}
	return rs;
    }
    return libVES_REST_req(ves, url, NULL, hdrs, pcode);
}

void libVES_REST_done(libVES *ves) {
    if (ves->curl) curl_easy_cleanup(ves->curl);
    ves->curl = NULL;
}
