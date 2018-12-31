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
 * jVar.h                     jVar: JSON object manipulation library header
 *
 ***************************************************************************/
#define JVAR_VERSION_NUMBER	0x01000000L

#define jVar_TInt	long long int
#define jVar_TFloat	long double
#define jVar_TBool	int

typedef struct jVar {
    int type;
    union {
	jVar_TBool vBool;
	jVar_TInt vInt;
	jVar_TFloat vFloat;
	struct {
	    union {
		void *vBuf;
		char *vString;
		struct jVar **vArray;
		struct {
		    struct jVar *key;
		    struct jVar *val;
		} *vObject;
	    };
	    size_t len;
	    size_t memSize;
	};
    };
} jVar;

#define JVAR_NULL	0
#define JVAR_BOOL	1
#define JVAR_INT	2
#define JVAR_FLOAT	3
#define JVAR_STRING	4
#define JVAR_ARRAY	5
#define JVAR_OBJECT	6
#define JVAR_JSON	7

jVar *jVar_object();
jVar *jVar_array();
jVar *jVar_string(const char *str);
jVar *jVar_stringl(const char *str, size_t len);
jVar *jVar_string0(char *str);
jVar *jVar_stringl0(char *str, size_t len, size_t extra);
jVar *jVar_int(jVar_TInt val);
jVar *jVar_float(jVar_TFloat val);
jVar *jVar_bool(jVar_TBool val);
jVar *jVar_null();
jVar *jVar_JSON(const char *json);
jVar *jVar_put(jVar *obj, const char *key, jVar *val);
jVar *jVar_putl(jVar *obj, const char *key, size_t keyl, jVar *val);
jVar *jVar_push(jVar *array, jVar *element);
jVar *jVar_get(jVar *obj, const char *key);
jVar *jVar_getl(jVar *obj, const char *key, size_t keyl);
jVar *jVar_index(jVar *array, size_t index);
void jVar_setStringl0(jVar *val, char *str, size_t len, size_t extra);
void jVar_setString0(jVar *val, char *str);
int jVar_cpString(jVar *val, char *str, size_t len);
char *jVar_getString(jVar *str);
char *jVar_getString0(jVar *str);
char *jVar_getStringP(jVar *str);
int jVar_getEnum(jVar *val, const char **list);
jVar_TInt jVar_getInt(jVar *num);
jVar_TFloat jVar_getFloat(jVar *num);
jVar_TBool jVar_getBool(jVar *num);
int jVar_count(jVar *val);
char *jVar_toJSON();
jVar *jVar_parse(const char *json, size_t len);
jVar *jVar_clone(jVar *val);
jVar *jVar_detach(jVar *val);
void jVar_free(jVar *val);

#define jVar_isNull(val)	(val && val->type == JVAR_NULL)
#define jVar_isObject(val)	(val && val->type == JVAR_OBJECT)
#define jVar_isArray(val)	(val && val->type == JVAR_ARRAY)
#define jVar_isInt(val)		(val && val->type == JVAR_INT)
#define jVar_isFloat(val)	(val && val->type == JVAR_FLOAT)
#define jVar_isBool(val)	(val && val->type == JVAR_BOOL)
#define jVar_isString(val)	(val && val->type == JVAR_STRING)


#define	JVAR_PARSE_INITIAL	0
#define	JVAR_PARSE_INCOMPLETE	1
#define	JVAR_PARSE_COMPLETE	2
#define	JVAR_PARSE_ERROR	3
#define JVAR_PARSE_EXP1		11
#define JVAR_PARSE_EXP2		12

typedef struct  jVarParser {
    int state;
    struct jVarParser *chain;
    const char *head;
    const char *tail;
    struct jVar *result;
    struct jVar *key;
    struct jVar *carry;
} jVarParser;

#define jVarParser_length(p)		(p->tail - p->head)
#define jVarParser_isComplete(p)	(p->state == JVAR_PARSE_COMPLETE)
#define jVarParser_isError(p)		(p->state == JVAR_PARSE_ERROR)

jVarParser *jVarParser_new(jVarParser *parent);
void jVarParser_free(jVarParser *p);
jVar *jVarParser_done(jVarParser *p);
jVarParser *jVarParser_parse(jVarParser *p, const char *head, size_t len);
