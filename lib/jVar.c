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
 * jVar.c                     jVar: JSON object manipulation library
 *
 ***************************************************************************/
#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "jVar.h"


void jVar_chkMem(jVar *val, size_t len) {
    if (val->memSize < len || !val->vBuf) {
	if (val->memSize < 256) val->memSize = 256;
	while (val->memSize < len) val->memSize <<= 1;
	val->vBuf = val->vBuf ? realloc(val->vBuf, val->memSize) : malloc(val->memSize);
	assert(val->vBuf);
    }
}

void jVar_free(jVar *val) {
    if (!val) return;
    size_t i;
    switch (val->type) {
	case JVAR_OBJECT:
	    for (i = 0; i < val->len; i++) {
		jVar_free(val->vObject[i].key);
		jVar_free(val->vObject[i].val);
	    }
	    free(val->vObject);
	    break;
	case JVAR_ARRAY:
	    for (i = 0; i < val->len; i++) jVar_free(val->vArray[i]);
	    free(val->vArray);
	    break;
	case JVAR_STRING:
	case JVAR_JSON:
	    free(val->vString);
	    break;
    }
    free(val);
}

jVar *jVar_clone(jVar *val) {
    if (!val) return NULL;
    jVar *res;
    size_t i;
    switch (val->type) {
	case JVAR_NULL: return jVar_null();
	case JVAR_BOOL: return jVar_bool(val->vBool);
	case JVAR_INT: return jVar_int(val->vInt);
	case JVAR_FLOAT: return jVar_float(val->vFloat);
	case JVAR_STRING: return jVar_stringl(val->vString, val->len);
	case JVAR_JSON: return jVar_JSON(val->vString);
	case JVAR_ARRAY:
	    res = jVar_array();
	    for (i = 0; i < val->len; i++) jVar_push(res, jVar_clone(val->vArray[i]));
	    return res;
	case JVAR_OBJECT:
	    res = jVar_object();
	    for (i = 0; i < val->len; i++) jVar_putl(res, val->vObject[i].key->vString, val->vObject[i].key->len, jVar_clone(val->vObject[i].val));
	    return res;
	default: return NULL;
    }
}

jVar *jVar_detach(jVar *val) {
    if (!val) return NULL;
    switch (val->type) {
	case JVAR_ARRAY:
	case JVAR_OBJECT:
	case JVAR_STRING:
	case JVAR_JSON: {
	    jVar *res = malloc(sizeof(jVar));
	    if (!res) return NULL;
	    memcpy(res, val, sizeof(jVar));
	    val->vBuf = NULL;
	    val->len = 0;
	    val->memSize = 0;
	    return res;
	}
	case JVAR_NULL:
	case JVAR_BOOL:
	case JVAR_INT:
	case JVAR_FLOAT:
	    return jVar_clone(val);
	default:
	    return NULL;
    }
}

jVar_TInt jVar_getInt(jVar *val) {
    if (!val) return 0;
    switch (val->type) {
	case JVAR_INT:
	    return val->vInt;
	case JVAR_FLOAT:
	    return (jVar_TInt) val->vFloat;
	case JVAR_BOOL:
	    return val->vBool;
	default:
	    return 0;
    }
}

jVar_TFloat jVar_getFloat(jVar *val) {
    if (!val) return 0;
    switch (val->type) {
	case JVAR_INT:
	    return (jVar_TFloat) val->vInt;
	case JVAR_FLOAT:
	    return val->vFloat;
	case JVAR_BOOL:
	    return (jVar_TFloat) val->vBool;
	default:
	    return 0;
    }
}

jVar_TBool jVar_getBool(jVar *val) {
    if (!val) return 0;
    switch (val->type) {
	case JVAR_INT:
	    return val->vInt != 0;
	case JVAR_FLOAT:
	    return val->vFloat != 0;
	case JVAR_BOOL:
	    return val->vBool;
	case JVAR_STRING:
	case JVAR_OBJECT:
	case JVAR_ARRAY:
	    return val->len > 0;
	default:
	    return 0;
    }
}

int jVar_cpStringN(jVar *val, char *str, size_t len) {
    char numBuf[64];
    if (!val) return -1;
    switch (val->type) {
	case JVAR_INT:
	    sprintf(numBuf, "%lld", val->vInt);
	    break;
	case JVAR_FLOAT:
	    sprintf(numBuf, "%Lg", val->vFloat);
	    break;
	default: return -1;
    }
    size_t l = strlen(numBuf);
    if (!str) return l;
    if (l > len) l = len;
    memcpy(str, numBuf, l);
    return l;
}

int jVar_cpString(jVar *val, char *str, size_t len) {
    if (!val) return -1;
    switch (val->type) {
	case JVAR_STRING:
	    if (!str) return val->len;
	    size_t l = len > val->len ? val->len : len;
	    memcpy(str, val->vString, l);
	    return l;
	case JVAR_BOOL:
	    if (!str) return val->vBool ? 1 : 0;
	    if (val->vBool && len > 0) {
		*str = '1';
		return 1;
	    }
	    return 0;
	case JVAR_INT:
	case JVAR_FLOAT:
	    return jVar_cpStringN(val, str, len);
	default: return -1;
    }
}

char *jVar_getString0(jVar *val) {
    if (!jVar_isString(val)) return jVar_getString(val);
    char *res = jVar_getStringP(val);
    val->len = 0;
    val->vString = NULL;
    return res;
}

char *jVar_getStringP(jVar *val) {
    if (!jVar_isString(val)) return NULL;
    jVar_chkMem(val, val->len + 1);
    val->vString[val->len] = 0;
    return val->vString;
}

char *jVar_getString(jVar *val) {
    int len = jVar_cpString(val, NULL, -1);
    if (len < 0) return NULL;
    char *str = malloc(len + 1);
    if (!str) return NULL;
    str[jVar_cpString(val, str, len)] = 0;
    return str;
}

int jVar_getEnum(jVar *val, const char **list) {
    if (!jVar_isString(val)) return -1;
    const char **p = list;
    const char *s;
    int idx = 0;
    while ((s = *p++)) {
	if (val->len == strlen(s) && !strncmp(s, val->vString, val->len)) return idx;
	idx++;
    }
    return -1;
}

jVar *jVar_index(jVar *array, size_t idx) {
    if (!jVar_isArray(array) || idx >= array->len || idx < 0) return NULL;
    return array->vArray[idx];
}

jVar *jVar_getl(jVar *obj, const char *key, size_t keyl) {
    if (!jVar_isObject(obj) || !key) return NULL;
    size_t i;
    for (i = 0; i < obj->len; i++) {
	if (obj->vObject[i].key->len == keyl && !strncmp(obj->vObject[i].key->vString, key, keyl)) return obj->vObject[i].val;
    }
    return NULL;
}

jVar *jVar_get(jVar *obj, const char *key) {
    return jVar_getl(obj, key, strlen(key));
}

int jVar_count(jVar *val) {
    if (!val) return 0;
    switch(val->type) {
	case JVAR_ARRAY:
	case JVAR_OBJECT:
	    return val->len;
	case JVAR_STRING:
	case JVAR_BOOL:
	case JVAR_INT:
	case JVAR_FLOAT:
	    return 1;
	default:
	    return 0;
    }
}

jVar *jVar_push(jVar *array, jVar *element) {
    if (!jVar_isArray(array)) return NULL;
    jVar_chkMem(array, (array->len + 1) * sizeof(*array->vArray));
    array->vArray[array->len++] = element;
    return array;
}

jVar *jVar_putl(jVar *obj, const char *key, size_t keyl, jVar *val) {
    if (!jVar_isObject(obj)) return NULL;
    size_t i;
    for (i = 0; i < obj->len; i++) {
	if (!strncmp(obj->vObject[i].key->vString, key, keyl)) {
	    jVar_free(obj->vObject[i].val);
	    if (val) obj->vObject[i].val = val;
	    else {
		memmove(obj->vObject + i, obj->vObject + i + 1, (obj->len - i - 1) * sizeof(obj->vObject[i]));
		obj->len--;
	    }
	    return obj;
	}
    }
    jVar_chkMem(obj, (obj->len + 1) * sizeof(*obj->vObject));
    obj->vObject[obj->len].key = jVar_stringl(key, keyl);
    obj->vObject[obj->len++].val = val;
    return obj;
}

jVar *jVar_put(jVar *obj, const char *key, jVar *val) {
    return jVar_putl(obj, key, strlen(key), val);
}

void jVar_concatl(jVar *val, const char *str, size_t len) {
    jVar_chkMem(val, val->len + len);
    memcpy(val->vString + val->len, str, len);
    val->len += len;
}

void jVar_concat(jVar *val, const char *str) {
    jVar_concatl(val, str, strlen(str));
}

void jVar_setStringl0(jVar *val, char *str, size_t len, size_t extra) {
    if (!jVar_isString(val)) return;
    free(val->vString);
    val->vString = str;
    val->len = len;
    val->memSize = len + extra;
}

void jVar_setString0(jVar *val, char *str) {
    if (str) jVar_setStringl0(val, str, strlen(str), 1);
}

jVar *jVar_null() {
    jVar *val = malloc(offsetof(jVar,vInt));
    if (val) val->type = JVAR_NULL;
    return val;
}

jVar *jVar_bool(jVar_TBool v) {
    jVar *val = malloc(offsetof(jVar,vBool) + sizeof(val->vBool));
    if (!val) return NULL;
    val->type = JVAR_BOOL;
    val->vBool = v != 0;
    return val;
}

jVar *jVar_int(jVar_TInt v) {
    jVar *val = malloc(offsetof(jVar,vInt) + sizeof(val->vInt));
    if (!val) return NULL;
    val->type = JVAR_INT;
    val->vInt = v;
    return val;
}

jVar *jVar_float(jVar_TFloat v) {
    jVar *val = malloc(offsetof(jVar,vFloat) + sizeof(val->vFloat));
    if (!val) return NULL;
    val->type = JVAR_FLOAT;
    val->vFloat = v;
    return val;
}

jVar *jVar_stringl(const char *v, size_t len) {
    char *buf = malloc(len + 16);
    if (!buf) return NULL;
    if (v) memcpy(buf, v, len);
    return jVar_stringl0(buf, len, 16);
}

jVar *jVar_stringl0(char *v, size_t len, size_t extra) {
    if (!v) return NULL;
    jVar *val = malloc(sizeof(jVar));
    if (!val) return NULL;
    val->type = JVAR_STRING;
    val->len = len;
    val->vString = v;
    val->len = len;
    val->memSize = len + extra;
    return val;
}

jVar *jVar_string(const char *v) {
    return jVar_stringl(v, v ? strlen(v) : 0);
}

jVar *jVar_string0(char *v) {
    if (!v) return NULL;
    return jVar_stringl0(v, strlen(v), 1);
}

jVar *jVar_JSON(const char *json) {
    jVar *val = jVar_string(json);
    if (!val) return NULL;
    val->type = JVAR_JSON;
    jVar_chkMem(val, val->len + 1);
    val->vString[val->len] = 0;
    return val;
}

jVar *jVar_array() {
    jVar *val = malloc(sizeof(jVar));
    if (!val) return NULL;
    val->type = JVAR_ARRAY;
    val->len = 0;
    val->memSize = 0;
    val->vArray = NULL;
    return val;
}

jVar *jVar_object() {
    jVar *val = malloc(sizeof(jVar));
    if (!val) return NULL;
    val->type = JVAR_OBJECT;
    val->len = 0;
    val->memSize = 0;
    val->vObject = NULL;
    return val;
}

jVar *jVar_parse(const char *json, size_t l) {
    if (l < 0) l = strlen(json);
    jVarParser *jp = jVarParser_new(NULL);
    jVarParser *jp2 = jVarParser_parse(jp, json, l);
    if (jVarParser_isComplete(jp2)) return jVarParser_done(jp2);
    else {
	jVar_free(jVarParser_done(jp2));
    }
    return NULL;
}

int jVar_render(jVar *val, jVar *json, void (* buffn)(jVar *)) {
    if (!val) return 0;
    size_t i;
    switch (val->type) {
	case JVAR_NULL:
	    jVar_concatl(json, "null", 4);
	    break;
	case JVAR_BOOL:
	    if (val->vBool) jVar_concatl(json, "true" ,4);
	    else jVar_concatl(json, "false", 5);
	    break;
	case JVAR_INT:
	case JVAR_FLOAT:
	    jVar_chkMem(json, 48);
	    json->len += jVar_cpStringN(val, json->vString + json->len, 48);
	    break;
	case JVAR_STRING: {
	    const char hex[] = "0123456789ABCDEF";
	    jVar_chkMem(json, json->len + val->len * 6 + 2);
	    char *p = json->vString + json->len;
	    *p++ = '"';
	    unsigned const char *s = (unsigned char *) val->vString;
	    unsigned const char *se = s + val->len;
	    while (s < se) {
		unsigned short c;
		switch (c = *s++) {
		    case '\\':
		    case '"':
		    case '/':
			*p++ = '\\';
		    default:
			if (c >= 0x20 && c < 0x7f) *p++ = c;
			else {
			    *p++ = '\\';
			    if (c >= 0x80) {
				int r;
				if (c < 0xc0) return 0;
				else if (c < 0xe0) {
				    c &= 0x1f;
				    r = 1;
				} else if (c < 0xf0) {
				    c &= 0x0f;
				    r = 2;
				} else return 0;
				while (r-- > 0) {
				    if (s >= se || *s < 0x80 || *s >= 0xc0) return 0;
				    c = (c << 6) | (*s++ & 0x3f);
				}
			    }
			    switch (c) {
				case 0x0d:
				    *p++ = 'r';
				    break;
				case 0x0a:
				    *p++ = 'n';
				    break;
				case 0x09:
				    *p++ = 't';
				    break;
				default:
				    *p++ = 'u';
				    *p++ = hex[c >> 12];
				    *p++ = hex[(c >> 8) & 0x0f];
				    *p++ = hex[(c >> 4) & 0x0f];
				    *p++ = hex[c & 0x0f];
			    }
			}
		}
	    }
	    *p++ = '"';
	    json->len = p - json->vString;
	    break;
	}
	case JVAR_ARRAY:
	    jVar_concatl(json, "[", 1);
	    for (i = 0; i < val->len; i++) {
		if (i > 0) jVar_concatl(json, ",", 1);
		if (buffn) buffn(json);
		if (!jVar_render(val->vArray[i], json, buffn)) return 0;
	    }
	    if (buffn) buffn(json);
	    jVar_concatl(json, "]", 1);
	    break;
	case JVAR_OBJECT:
	    jVar_concatl(json, "{", 1);
	    for (i = 0; i < val->len; i++) {
		if (i > 0) jVar_concatl(json, ",", 1);
		if (buffn) buffn(json);
		if (!jVar_render(val->vObject[i].key, json, buffn)) return 0;
		jVar_concatl(json, ":", 1);
		if (buffn) buffn(json);
		if (!jVar_render(val->vObject[i].val, json, buffn)) return 0;
	    }
	    if (buffn) buffn(json);
	    jVar_concatl(json, "}", 1);
	    break;
	case JVAR_JSON:
	    jVar_concatl(json, val->vString, val->len);
	    break;
	default:
	    return 0;
    }
    return 1;
}

char *jVar_toJSON(jVar *val) {
    jVar *json = jVar_JSON(NULL);
    if (!jVar_render(val, json, NULL)) {
	jVar_free(json);
	return NULL;
    }
    jVar_chkMem(json, json->len + 1);
    char *buf = json->vString;
    buf[json->len] = 0;
    free(json);
    return buf;
}



jVarParser *jVarParser_new(jVarParser *parent) {
    jVarParser *p = malloc(sizeof(jVarParser));
    if (!p) return NULL;
    p->state = JVAR_PARSE_INITIAL;
    p->result = NULL;
    p->key = NULL;
    p->carry = NULL;
    p->chain = parent;
    if (parent) {
	p->head = parent->head;
	p->tail = parent->tail;
    }
    return p;
}

void jVarParser_free(jVarParser *p) {
    if (!p) return;
    jVar_free(p->key);
    jVar_free(p->carry);
    jVar_free(p->result);
    free(p);
}

jVar *jVarParser_done(jVarParser *p) {
    jVar *res = p->chain ? jVarParser_done(p->chain) : p->result;
    p->result = NULL;
    jVarParser_free(p);
    return res;
}

const char *jVarParser_trim(jVarParser *p) {
    while (p->head < p->tail) {
	switch (*(p->head)) {
	    case ' ': case 0x09: case 0x0d: case 0x0a:
		break;
	    default:
		return p->head;
	}
	p->head++;
    }
    return p->head;
}

int jVarParser_match(jVarParser *p, const char *s) {
    size_t l1 = strlen(s);
    size_t l2 = jVarParser_length(p);
    if (l2 < l1) return 0;
    if (!memcmp(p->head,s,l1)) {
	p->head += l1;
	return 1;
    } else return -1;
}

jVarParser *jVarParser_proceed(jVarParser *p,jVarParser *child) {
    int type;
    if (p->result) type = p->result->type;
    else {
	const char *head = jVarParser_trim(p);
	if (jVarParser_length(p)) {
	    char c;
	    switch (c = *head) {
		case '"':
		    type = JVAR_STRING;
		    break;
		case '{':
		    type = JVAR_OBJECT;
		    break;
		case '[':
		    type = JVAR_ARRAY;
		    break;
		case 'n':
		    type = JVAR_NULL;
		    break;
		case 't': case 'f':
		    type = JVAR_BOOL;
		    break;
		case '.':
		    type = JVAR_FLOAT;
		    break;
		default:
		    if ((c>='0' && c<='9') || c=='+' || c=='-') {
			type = JVAR_INT;
			break;
		    } else {
			p->state = JVAR_PARSE_ERROR;
			return p;
		    }
	    }
	} else return p;
    }
    int m;
    switch (type) {
	case JVAR_NULL:
	    m = jVarParser_match(p, "null");
	    if (m > 0) {
		p->result = jVar_null();
		p->state = JVAR_PARSE_COMPLETE;
	    } else if (m < 0) p->state = JVAR_PARSE_ERROR;
	    break;
	case JVAR_BOOL:
	    m = jVarParser_match(p, "true");
	    if (m > 0) {
		p->result = jVar_bool(1);
		p->state = JVAR_PARSE_COMPLETE;
		break;
	    } else if (!m) break;
	    m = jVarParser_match(p, "false");
	    if (m > 0) {
		p->result = jVar_bool(0);
		p->state = JVAR_PARSE_COMPLETE;
		break;
	    } else if (!m) break;
	    p->state = JVAR_PARSE_ERROR;
	    break;
	case JVAR_INT:
	case JVAR_FLOAT: {
	    const char *h = p->head;
	    const char *t = p->tail;
	    char c;
	    if (p->state == JVAR_PARSE_INITIAL) p->state = JVAR_PARSE_INCOMPLETE;
	    if (p->result) h--;
	    while (++h < t) {
		switch (c = *h) {
		    case '+':
		    case '-':
			if (p->state == JVAR_PARSE_EXP1) p->state = JVAR_PARSE_EXP2;
			else t = h;
			break;
		    case '.':
			if (type == JVAR_INT) type = JVAR_FLOAT;
			else t = h;
			break;
		    case 'e':
		    case 'E':
			type = JVAR_FLOAT;
			if (p->state == JVAR_PARSE_INCOMPLETE) p->state = JVAR_PARSE_EXP1;
			else t = h;
			break;
		    default:
			if (c < '0' || c > '9') t = h;
			else if (p->state == JVAR_PARSE_EXP1) p->state = JVAR_PARSE_EXP2;
		}
	    }
	    size_t len = t - p->head;
	    char fmt[32];
	    if (p->result && p->result->type != type) {
		jVar_free(p->result);
		p->result = NULL;
	    }
	    if (!p->result) p->result = (type == JVAR_FLOAT ? jVar_float(0) : jVar_int(0));
	    void *valptr = (type == JVAR_FLOAT ? (void *) &p->result->vFloat : (void *) &p->result->vInt);
	    const char *s;
	    if (p->key || t >= p->tail) {
		if (!p->key) p->key = jVar_stringl(p->head, len);
		else jVar_concatl(p->key, p->head, len);
		s = p->key->vString;
		len = p->key->len;
	    } else s = p->head;
	    sprintf(fmt, (type == JVAR_FLOAT ? "%%%dLg" : "%%%dlld"), (int) len);
	    if (sscanf(s, fmt, valptr) != 1 && t < p->tail) p->state = JVAR_PARSE_ERROR;
	    else {
		p->head = t;
		if (t < p->tail) p->state = JVAR_PARSE_COMPLETE;
	    }
	    break;
	}
	case JVAR_STRING: {
	    if (p->state == JVAR_PARSE_INITIAL) {
		p->head++;
		p->result = jVar_string(NULL);
		p->state = JVAR_PARSE_INCOMPLETE;
	    }
	    jVar *jstr = p->result;
	    while (p->state == JVAR_PARSE_INCOMPLETE && p->head < p->tail) {
		jVar_chkMem(jstr, jstr->len + 4);
		char *buf = jstr->vString + jstr->len;
		unsigned char c = *(p->head);
		switch (c) {
		    case '"':
			p->state = JVAR_PARSE_COMPLETE;
			p->head++;
			break;
		    case '\\': {
			const char *h = p->head + 1;
			if (h >= p->tail) return p;
			switch (*h++) {
			    case 'r': *buf++ = 0x0d; break;
			    case 'n': *buf++ = 0x0a; break;
			    case 't': *buf++ = 0x09; break;
			    case 'b': *buf++ = 0x08; break;
			    case 'f': *buf++ = 0x0c; break;
			    case 'u': {
				if (h + 4 > p->tail) return p;
				unsigned int hval = 0;
				int i;
				for (i = 1; i <= 4; i++) {
				    unsigned char ch = *h++;
				    hval <<= 4;
				    if (ch >= '0' && ch <= '9') hval += ch - '0';
				    else if (ch >= 'A' && ch <= 'F') hval += ch - 0x37;
				    else if (ch >= 'a' && ch <= 'f') hval += ch - 0x57;
				    else {
					p->state = JVAR_PARSE_ERROR;
					break;
				    }
				}
				if (hval < 0x0080) *buf++ = hval;
				else {
				    if (hval < 0x0800) *buf++ = (hval >> 6) | 0xc0;
				    else {
					*buf++ = (hval >> 12) | 0xe0;
					*buf++ = ((hval >> 6) & 0x3f) | 0x80;
				    }
				    *buf++ = (hval & 0x3f) | 0x80;
				}
				break;
			    }
			    case '"': case '\\': case '/':
				*buf++ = *(h - 1);
				break;
			    default:
				p->state = JVAR_PARSE_ERROR;
				break;
			}
			p->head = h;
			break;
		    }
		    default:
			if (c < 0x20) p->state = JVAR_PARSE_ERROR;
			else {
			    *buf++ = c;
			    p->head++;
			}
			break;
		}
		jstr->len = buf - jstr->vString;
	    }
	    break;
	}
	case JVAR_ARRAY:
	case JVAR_OBJECT:
	    if (p->state == JVAR_PARSE_INITIAL) {
		p->head++;
		p->state = JVAR_PARSE_INCOMPLETE;
		if (type == JVAR_OBJECT) p->result = jVar_object();
		else p->result = jVar_array();
		p->key = NULL;
	    }
	    while (1) {
		if (child) {
		    if (child->result) {
			if (type == JVAR_OBJECT) {
			    if (p->key) {
				jVar_putl(p->result, p->key->vString, p->key->len, child->result);
				jVar_free(p->key);
				p->key = NULL;
			    } else {
				p->key = child->result;
				if (!jVar_isString(p->key)) p->state = JVAR_PARSE_ERROR;
			    }
			} else jVar_push(p->result, child->result);
		    } else p->state = JVAR_PARSE_ERROR;
		    p->head = child->head;
		    p->tail = child->tail;
		    child->result = NULL;
		    jVarParser_free(child);
		    child = NULL;
		}
		const char *h = jVarParser_trim(p);
		if (!jVarParser_length(p)) break;
		switch (*h) {
		    case ']':
			if (type != JVAR_ARRAY) p->state = JVAR_PARSE_ERROR;
			else {
			    p->state = JVAR_PARSE_COMPLETE;
			    p->head++;
			}
			break;
		    case '}':
			if (type != JVAR_OBJECT || p->key) p->state = JVAR_PARSE_ERROR;
			else {
			    p->state = JVAR_PARSE_COMPLETE;
			    p->head++;
			}
			break;
		    case ',':
			if (!p->key && p->result->len) h++;
			else p->state = JVAR_PARSE_ERROR;
			break;
		    case ':':
			if (p->key) h++;
			else p->state = JVAR_PARSE_ERROR;
			break;
		    default:
			if (p->key || p->result->len) p->state = JVAR_PARSE_ERROR;
			break;
		}
		if (p->state == JVAR_PARSE_INCOMPLETE) {
		    jVarParser *next = jVarParser_new(p);
		    next->head = h;
		    child = jVarParser_proceed(next,NULL);
		    if (!jVarParser_isComplete(child)) return child;
		} else {
		    if (p->key) {
			jVar_free(p->key);
			p->key = NULL;
		    }
		    break;
		}
	    }
	    break;
	default:
	    p->state = JVAR_PARSE_ERROR;
	    break;
    }
    return p;
}


jVarParser *jVarParser_parse(jVarParser *p, const char *head, size_t len) {
    switch (p->state) {
	case JVAR_PARSE_COMPLETE:
	    p->head = head;
	    p->tail = head + len;
	    jVarParser_trim(p);
	case JVAR_PARSE_ERROR:
	    return p;
	default: {
	    jVarParser *next;
	    jVar *cr;
	    if ((cr = p->carry)) {
		p->carry = NULL;
		int al = len > 16 ? 16 : len;
		jVar_concatl(cr, head, al);
		const char *ch = p->head = cr->vString;
		p->tail = p->head + cr->len;
		next = jVarParser_proceed(p,NULL);
		int al2 = al - jVarParser_length(next);
		if (al2 < 0) {
		    if (next->carry) jVar_free(next->carry);
		    next->carry = cr;
		    if (al < len) next->state = JVAR_PARSE_ERROR;
		    else {
			int df = next->head - ch;
			cr->len -= df;
			memmove(cr->vString, cr->vString + df, cr->len);
			next->head -= df;
			next->tail -= df;
		    }
		    return next;
		}
		jVar_free(cr);
		next->head = head + al2;
		next->tail = head + len;
		if (!jVarParser_isComplete(next)) next = jVarParser_proceed(next, NULL);
	    } else {
		p->head = head;
		p->tail = head + len;
		next = jVarParser_proceed(p,NULL);
	    }
	    while (next->chain && jVarParser_isComplete(next)) next = jVarParser_proceed(next->chain,next);
	    if (jVarParser_isComplete(next)) jVarParser_trim(next);
	    else if (!jVarParser_isError(next) && jVarParser_length(next)) {
		if (next->carry) jVar_free(next->carry);
		next->carry = jVar_stringl(next->head, jVarParser_length(next));
		next->head += next->carry->len;
	    }
	    return next;
	}
    }
}

