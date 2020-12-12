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

void *libVES_REST_hdrs(libVES *ves, const char *uri, jVar *body, struct curl_slist *hdrs) {
    if (ves->httpInitFn) ves->httpInitFn(ves);
    if (ves->debug > 0) curl_easy_setopt(ves->curl, CURLOPT_VERBOSE, 1);
    char buf[4096];
    sprintf(buf, "%s%s", ves->apiUrl, uri);
    if (ves->attnFn) {
	char *p = buf + strlen(buf);
	*p++ = strchr(buf, '?') ? '&' : '?';
	strcpy(p, "attn=%2A");
    }
    curl_easy_setopt(ves->curl, CURLOPT_URL, buf);
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
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
    struct libVES_curl_buf cbuf;
    cbuf.parser = NULL;
    cbuf.ves = ves;
    curl_easy_setopt(ves->curl, CURLOPT_WRITEFUNCTION, &libVES_REST_callbk);
    curl_easy_setopt(ves->curl, CURLOPT_WRITEDATA, &cbuf);
    int curlerr = curl_easy_perform(ves->curl);
    long code;
    if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(ves->curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_reset(ves->curl);
    free(json);
    int err;
    char *errstr = NULL;
    if (curlerr == CURLE_OK) {
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
	jVar *rsp = NULL;
	jVar *res = NULL;
	if (cbuf.parser) {
	    if (jVarParser_isComplete(cbuf.parser)) rsp = jVarParser_done(cbuf.parser);
	    else jVarParser_free(cbuf.parser);
	}
	if (ves->attnFn) {
	    jVar *attn = jVar_get(rsp, "attn");
	    if (attn) {
		ves->attnFn(ves, attn);
		ves->attnFn = NULL;
	    }
	}
	if (err == LIBVES_E_OK) {
	    if (rsp) {
		res = jVar_get(rsp, "result");
		res = jVar_isObject(res) ? jVar_detach(res) : NULL;
		if (!res) libVES_setError(ves, LIBVES_E_PARSE, "Missing result in the API server response");
	    } else {
		libVES_throw(ves, LIBVES_E_PARSE, "Error parsing JSON response from the API server", NULL);
	    }
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
    } else {
	const char *curlstr = curl_easy_strerror(curlerr);
	errstr = malloc(128 + (curlstr ? strlen(curlstr) : 0));
	if (errstr) sprintf(errstr, "cURL error %d: %s", curlerr, curlstr);
	err = LIBVES_E_CONN;
    }
    if (err != LIBVES_E_OK) libVES_setError0(ves, err, errstr);
    return NULL;
}

void *libVES_REST(libVES *ves, const char *uri, jVar *body) {
    if (!libVES_REST_init(ves)) return NULL;
    char buf[256];
    struct curl_slist *hdrs = NULL;
    if (ves->sessionToken) {
	sprintf(buf, "Authorization: Bearer %.80s", ves->sessionToken);
	hdrs = curl_slist_append(hdrs, buf);
    }
    return libVES_REST_hdrs(ves, uri, body, hdrs);
}

void *libVES_REST_login(libVES *ves, const char *uri, jVar *body, const char *username, const char *passwd) {
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

void libVES_REST_done(libVES *ves) {
    if (ves->curl) curl_easy_cleanup(ves->curl);
    ves->curl = NULL;
}
