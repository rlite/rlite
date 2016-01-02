#include <rina/rina-utils.h>

#ifdef __KERNEL__

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>

#define COMMON_ALLOC(_sz)   kmalloc(_sz, GFP_KERNEL)
#define COMMON_FREE(_p)   kfree(_p)
#define COMMON_PRINT(format, ...) printk(format, ##__VA_ARGS__)
#define COMMON_STRDUP(_s)   kstrdup(_s, GFP_KERNEL)
#define COMMON_EXPORT(_n)   EXPORT_SYMBOL_GPL(_n)

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define COMMON_ALLOC(_sz)   malloc(_sz)
#define COMMON_FREE(_p)   free(_p)
#define COMMON_PRINT(format, ...) printf(format, ##__VA_ARGS__)
#define COMMON_STRDUP(_s)   strdup(_s)
#define COMMON_EXPORT(_n)

#endif

/* Serialize a numeric variable _v of type _t. */
#define serialize_obj(_p, _t, _v)       \
        do {                            \
            *((_t *)_p) = _v;           \
            _p += sizeof(_t);           \
        } while (0)

/* Deserialize a numeric variable of type _t from _p into _r. */
#define deserialize_obj(_p, _t, _r)     \
        do {                            \
            *(_r) = *((_t *)_p);        \
            _p += sizeof(_t);           \
        } while (0)

typedef char *string_t;

/* Size of a serialized string, not including the storage for the size
 * field itself. */
static unsigned int
string_prlen(const char *s)
{
    unsigned int slen;

    slen = s ? strlen(s) : 0;

    return slen > 255 ? 255 : slen;
}

/* Size of a serialized RINA name. */
unsigned int
rina_name_serlen(const struct rina_name *name)
{
    unsigned int ret = 4 * sizeof(uint8_t);

    if (!name) {
        return ret;
    }

    return ret + string_prlen(name->apn) + string_prlen(name->api)
            + string_prlen(name->aen) + string_prlen(name->aei);
}

/* Serialize a C string. */
void
serialize_string(void **pptr, const char *s)
{
    uint8_t slen;

    slen = string_prlen(s);
    serialize_obj(*pptr, uint8_t, slen);

    memcpy(*pptr, s, slen);
    *pptr += slen;
}

/* Deserialize a C string. */
int
deserialize_string(const void **pptr, char **s)
{
    uint8_t slen;

    deserialize_obj(*pptr, uint8_t, &slen);
    if (slen) {
        *s = COMMON_ALLOC(slen + 1);
        if (!(*s)) {
            return -1;
        }

        memcpy(*s, *pptr, slen);
        (*s)[slen] = '\0';
        *pptr += slen;
    } else {
        *s = NULL;
    }

    return 0;
}

/* Serialize a RINA name. */
void
serialize_rina_name(void **pptr, const struct rina_name *name)
{
    serialize_string(pptr, name->apn);
    serialize_string(pptr, name->api);
    serialize_string(pptr, name->aen);
    serialize_string(pptr, name->aei);
}

/* Deserialize a RINA name. */
int
deserialize_rina_name(const void **pptr, struct rina_name *name)
{
    int ret;

    memset(name, 0, sizeof(*name));

    ret = deserialize_string(pptr, &name->apn);
    if (ret) {
        return ret;
    }

    ret = deserialize_string(pptr, &name->api);
    if (ret) {
        return ret;
    }

    ret = deserialize_string(pptr, &name->aen);
    if (ret) {
        return ret;
    }

    ret = deserialize_string(pptr, &name->aei);

    return ret;
}

unsigned int
rina_msg_serlen(struct rina_msg_layout *numtables,
                const struct rina_msg_base *msg)
{
    unsigned int ret = numtables[msg->msg_type].copylen;
    struct rina_name *name;
    string_t *str;
    int i;

    name = (struct rina_name *)(((void *)msg) + ret);
    for (i = 0; i < numtables[msg->msg_type].names; i++, name++) {
        ret += rina_name_serlen(name);
    }

    str = (string_t *)name;
    for (i = 0; i < numtables[msg->msg_type].strings; i++, str++) {
        ret += sizeof(uint8_t) + string_prlen(*str);
    }

    return ret;
}
COMMON_EXPORT(rina_msg_serlen);

/* Serialize msg into serbuf. */
unsigned int
serialize_rina_msg(struct rina_msg_layout *numtables,
                   void *serbuf, const struct rina_msg_base *msg)
{
    void *serptr = serbuf;
    unsigned int serlen;
    unsigned int copylen;
    struct rina_name *name;
    string_t *str;
    int i;

    copylen = numtables[msg->msg_type].copylen;
    memcpy(serbuf, msg, copylen);

    serptr = serbuf + copylen;
    name = (struct rina_name *)(((void *)msg) + copylen);
    for (i = 0; i < numtables[msg->msg_type].names; i++, name++) {
        serialize_rina_name(&serptr, name);
    }

    str = (string_t *)(name);
    for (i = 0; i < numtables[msg->msg_type].strings; i++, str++) {
        serialize_string(&serptr, *str);
    }

    serlen = serptr - serbuf;

    return serlen;
}
COMMON_EXPORT(serialize_rina_msg);

/* Deserialize from serbuf into msgbuf. */
int
deserialize_rina_msg(struct rina_msg_layout *numtables,
                     const void *serbuf, unsigned int serbuf_len,
                     void *msgbuf, unsigned int msgbuf_len)
{
    struct rina_msg_base *bmsg = (struct rina_msg_base *)serbuf;
    struct rina_name *name;
    string_t *str;
    unsigned int copylen;
    const void *desptr;
    int ret;
    int i;

    copylen = numtables[bmsg->msg_type].copylen;
    memcpy(msgbuf, serbuf, copylen);

    desptr = serbuf + copylen;
    name = (struct rina_name *)(msgbuf + copylen);
    for (i = 0; i < numtables[bmsg->msg_type].names; i++, name++) {
        ret = deserialize_rina_name(&desptr, name);
        if (ret) {
            return ret;
        }
    }

    str = (string_t *)name;
    for (i = 0; i < numtables[bmsg->msg_type].strings; i++, str++) {
        ret = deserialize_string(&desptr, str);
        if (ret) {
            return ret;
        }
    }

    if ((desptr - serbuf) != serbuf_len) {
        return -1;
    }

    return 0;
}
COMMON_EXPORT(deserialize_rina_msg);

unsigned int rina_numtables_max_size(struct rina_msg_layout *numtables,
                                     unsigned int n)
{
    unsigned int max = 0;
    int i = 0;

    for (i = 0; i < n; i++) {
        unsigned int cur = numtables[i].copylen +
                           numtables[i].names * sizeof(struct rina_name);

        if (cur > max) {
            max = cur;
        }
    }

    return max;
}

void
rina_name_free(struct rina_name *name)
{
    if (!name) {
        return;
    }

    if (name->apn) {
        COMMON_FREE(name->apn);
    }

    if (name->api) {
        COMMON_FREE(name->api);
    }

    if (name->aen) {
        COMMON_FREE(name->aen);
    }

    if (name->aei) {
        COMMON_FREE(name->aei);
    }
}
COMMON_EXPORT(rina_name_free);

void
rina_msg_free(struct rina_msg_layout *numtables,
              struct rina_msg_base *msg)
{
    unsigned int copylen = numtables[msg->msg_type].copylen;
    struct rina_name *name;
    int i;

    /* Skip the copiable part and scan all the RINA names contained in
     * the message. */
    name = (struct rina_name *)(((void *)msg) + copylen);
    for (i = 0; i < numtables[msg->msg_type].names; i++, name++) {
        rina_name_free(name);
    }
}

void
rina_name_move(struct rina_name *dst, struct rina_name *src)
{
    if (!dst || !src) {
        return;
    }

    dst->apn = src->apn;
    src->apn = NULL;

    dst->api = src->api;
    src->api = NULL;

    dst->aen = src->aen;
    src->aen = NULL;

    dst->aei = src->aei;
    src->aei = NULL;
}
COMMON_EXPORT(rina_name_move);

int
rina_name_copy(struct rina_name *dst, const struct rina_name *src)
{
    if (!dst || !src) {
        return 0;
    }

    dst->apn = src->apn ? COMMON_STRDUP(src->apn) : NULL;
    dst->api = src->api ? COMMON_STRDUP(src->api) : NULL;
    dst->aen = src->aen ? COMMON_STRDUP(src->aen) : NULL;
    dst->aei = src->aei ? COMMON_STRDUP(src->aei) : NULL;

    return 0;
}
COMMON_EXPORT(rina_name_copy);

char *
rina_name_to_string(const struct rina_name *name)
{
    char *str = NULL;
    char *cur;
    unsigned int apn_len;
    unsigned int api_len;
    unsigned int aen_len;
    unsigned int aei_len;

    if (!name) {
        return NULL;
    }

    apn_len = name->apn ? strlen(name->apn) : 0;
    api_len = name->api ? strlen(name->api) : 0;
    aen_len = name->aen ? strlen(name->aen) : 0;
    aei_len = name->aei ? strlen(name->aei) : 0;

    str = cur = COMMON_ALLOC(apn_len + 1 + api_len + 1 +
                             aen_len + 1 + aei_len + 1);
    if (!str) {
        return NULL;
    }

    memcpy(cur, name->apn, apn_len);
    cur += apn_len;

    *cur = '/';
    cur++;

    memcpy(cur, name->api, api_len);
    cur += api_len;

    *cur = '/';
    cur++;

    memcpy(cur, name->aen, aen_len);
    cur += aen_len;

    *cur = '/';
    cur++;

    memcpy(cur, name->aei, aei_len);
    cur += aei_len;

    *cur = '\0';

    return str;
}
COMMON_EXPORT(rina_name_to_string);

int
rina_name_from_string(const char *str, struct rina_name *name)
{
    char *apn, *api, *aen, *aei;
    char *strc = COMMON_STRDUP(str);
    char **strp = &strc;

    memset(name, sizeof(*name), 0);

    if (!strc) {
        return -1;
    }

    apn = strsep(strp, "/");
    api = strsep(strp, "/");
    aen = strsep(strp, "/");
    aei = strsep(strp, "/");

    if (!apn || !api || !aen || !aei) {
        COMMON_FREE(strc);
        return -1;
    }

    rina_name_fill(name, apn, api, aen, aei);
    COMMON_FREE(strc);

    return 0;
}
COMMON_EXPORT(rina_name_from_string);

int
rina_name_cmp(const struct rina_name *one, const struct rina_name *two)
{
    if (!one || !two) {
        return !(one == two);
    }

    if (!!one->apn ^ !!two->apn) {
        return -1;
    }
    if (one->apn && strcmp(one->apn, two->apn)) {
        return -1;
    }

    if (!!one->api ^ !!two->api) {
        return -1;
    }
    if (one->api && strcmp(one->api, two->api)) {
        return -1;
    }

    if (!!one->aen ^ !!two->aen) {
        return -1;
    }
    if (one->aen && strcmp(one->aen, two->aen)) {
        return -1;
    }

    if (!!one->aei ^ !!two->aei) {
        return -1;
    }
    if (one->aei && strcmp(one->aei, two->aei)) {
        return -1;
    }

    return 0;
}
COMMON_EXPORT(rina_name_cmp);

void
rina_name_fill(struct rina_name *name, const char *apn,
               const char *api, const char *aen, const char *aei)
{
    name->apn = (apn && strlen(apn)) ? COMMON_STRDUP(apn) : NULL;
    name->api = (api && strlen(api)) ? COMMON_STRDUP(api) : NULL;
    name->aen = (aen && strlen(aen)) ? COMMON_STRDUP(aen) : NULL;
    name->aei = (aei && strlen(aei)) ? COMMON_STRDUP(aei) : NULL;
}
COMMON_EXPORT(rina_name_fill);

int
rina_name_valid(const struct rina_name *name)
{
    if (!name || !name->apn || strlen(name->apn) == 0) {
        return 0;
    }

    return 1;
}
COMMON_EXPORT(rina_name_valid);
