/*
 * rlite misc functionalities (serialization, rina names, ...)
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "rlite/utils.h"

#ifdef __KERNEL__

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "rlite-kernel.h"

#define COMMON_ALLOC(_sz, _sl)      rl_alloc(_sz, _sl ? GFP_KERNEL : GFP_ATOMIC, RL_MT_UTILS)
#define COMMON_FREE(_p)             rl_free(_p, RL_MT_UTILS)
#define COMMON_PRINT(format, ...)   printk(format, ##__VA_ARGS__)
#define COMMON_STRDUP(_s, _sl)      rl_strdup(_s, _sl ? GFP_KERNEL : GFP_ATOMIC, RL_MT_UTILS)
#define COMMON_EXPORT(_n)           EXPORT_SYMBOL(_n)
#define COMMON_STATIC

#else /* user-space */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define COMMON_ALLOC(_sz, _unused)  rl_alloc(_sz, RL_MT_UTILS)
#define COMMON_FREE(_p)             rl_free(_p, RL_MT_UTILS)
#define COMMON_PRINT(format, ...)   printf(format, ##__VA_ARGS__)
#define COMMON_STRDUP(_s, _unused)  rl_strdup(_s, RL_MT_UTILS)
#define COMMON_EXPORT(_n)
#define COMMON_STATIC               static

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

    return slen > 65535 ? 65535 : slen;
}

/* Size of a serialized RLITE name. */
unsigned int
rina_name_serlen(const struct rina_name *name)
{
    unsigned int ret = 4 * sizeof(uint16_t);

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
    uint16_t slen;

    slen = string_prlen(s);
    serialize_obj(*pptr, uint16_t, slen);

    memcpy(*pptr, s, slen);
    *pptr += slen;
}

/* Deserialize a C string. */
int
deserialize_string(const void **pptr, char **s)
{
    uint16_t slen;

    deserialize_obj(*pptr, uint16_t, &slen);
    if (slen) {
        *s = COMMON_ALLOC(slen + 1, 1);
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

/* Serialize a buffer. */
static void
serialize_buffer(void **pptr, const struct rl_buf_field *bf)
{
    serialize_obj(*pptr, uint32_t, bf->len);

    memcpy(*pptr, bf->buf, bf->len);
    *pptr += bf->len;
}

/* Deserialize a buffer. */
static int
deserialize_buffer(const void **pptr, struct rl_buf_field *bf)
{
    deserialize_obj(*pptr, uint32_t, &bf->len);
    if (bf->len) {
        bf->buf = COMMON_ALLOC(bf->len, 1);
        if (!(bf->buf)) {
            return -1;
        }

        memcpy(bf->buf, *pptr, bf->len);
        *pptr += bf->len;
    } else {
        bf->buf = NULL;
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
rl_msg_serlen(struct rl_msg_layout *numtables,
                size_t num_entries,
                const struct rl_msg_base *msg)
{
    unsigned int ret;
    struct rina_name *name;
    string_t *str;
    const struct rl_buf_field *bf;
    int i;

    if (msg->msg_type >= num_entries) {
        PE("Invalid numtables access [msg_type=%u]\n", msg->msg_type);

        return -1;
    }

    ret = numtables[msg->msg_type].copylen;

    name = (struct rina_name *)(((void *)msg) + ret);
    for (i = 0; i < numtables[msg->msg_type].names; i++, name++) {
        ret += rina_name_serlen(name);
    }

    str = (string_t *)name;
    for (i = 0; i < numtables[msg->msg_type].strings; i++, str++) {
        ret += sizeof(uint16_t) + string_prlen(*str);
    }

    bf = (const struct rl_buf_field *)str;
    for (i = 0; i < numtables[msg->msg_type].buffers; i++, bf++) {
        ret += sizeof(bf->len) + bf->len;
    }

    return ret;
}
COMMON_EXPORT(rl_msg_serlen);

/* Serialize msg into serbuf. */
unsigned int
serialize_rlite_msg(struct rl_msg_layout *numtables, size_t num_entries,
                   void *serbuf, const struct rl_msg_base *msg)
{
    void *serptr = serbuf;
    unsigned int serlen;
    unsigned int copylen;
    struct rina_name *name;
    string_t *str;
    const struct rl_buf_field *bf;
    int i;

    if (msg->msg_type >= num_entries) {
        PE("Invalid numtables access [msg_type=%u]\n", msg->msg_type);

        return -1;
    }

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

    bf = (const struct rl_buf_field *)str;
    for (i = 0; i < numtables[msg->msg_type].buffers; i++, bf++) {
        serialize_buffer(&serptr, bf);
    }

    serlen = serptr - serbuf;

    return serlen;
}
COMMON_EXPORT(serialize_rlite_msg);

/* Deserialize from serbuf into msgbuf. */
int
deserialize_rlite_msg(struct rl_msg_layout *numtables, size_t num_entries,
                     const void *serbuf, unsigned int serbuf_len,
                     void *msgbuf, unsigned int msgbuf_len)
{
    struct rl_msg_base *bmsg = RLITE_MB(serbuf);
    struct rina_name *name;
    string_t *str;
    struct rl_buf_field *bf;
    unsigned int copylen;
    const void *desptr;
    int ret;
    int i;

    if (bmsg->msg_type >= num_entries) {
        PE("Invalid numtables access [msg_type=%u]\n", bmsg->msg_type);

        return -1;
    }

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

    bf = (struct rl_buf_field *)str;
    for (i = 0; i < numtables[bmsg->msg_type].buffers; i++, bf++) {
        ret = deserialize_buffer(&desptr, bf);
    }

    if ((desptr - serbuf) != serbuf_len) {
        return -1;
    }

    return 0;
}
COMMON_EXPORT(deserialize_rlite_msg);

void
rl_msg_free(struct rl_msg_layout *numtables, size_t num_entries,
              struct rl_msg_base *msg)
{
    unsigned int copylen = numtables[msg->msg_type].copylen;
    struct rina_name *name;
    string_t *str;
    int i;

    if (msg->msg_type >= num_entries) {
        PE("Invalid numtables access [msg_type=%u]\n", msg->msg_type);

        return;
    }

    /* Skip the copiable part and scan all the names contained in
     * the message. */
    name = (struct rina_name *)(((void *)msg) + copylen);
    for (i = 0; i < numtables[msg->msg_type].names; i++, name++) {
        rina_name_free(name);
    }

    str = (string_t *)(name);
    for (i = 0; i < numtables[msg->msg_type].strings; i++, str++) {
        if (*str) {
            COMMON_FREE(*str);
        }
    }
}
COMMON_EXPORT(rl_msg_free);

unsigned int rl_numtables_max_size(struct rl_msg_layout *numtables,
                                     unsigned int n)
{
    unsigned int max = 0;
    int i = 0;

    for (i = 0; i < n; i++) {
        unsigned int cur = numtables[i].copylen +
                           numtables[i].names * sizeof(struct rina_name) +
                           numtables[i].strings * sizeof(char *);

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
        name->apn = NULL;
    }

    if (name->api) {
        COMMON_FREE(name->api);
        name->api = NULL;
    }

    if (name->aen) {
        COMMON_FREE(name->aen);
        name->aen = NULL;
    }

    if (name->aei) {
        COMMON_FREE(name->aei);
        name->aei = NULL;
    }
}
COMMON_EXPORT(rina_name_free);

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

#if 0
    rina_name_free(dst);
#endif

    dst->apn = src->apn ? COMMON_STRDUP(src->apn, 1) : NULL;
    dst->api = src->api ? COMMON_STRDUP(src->api, 1) : NULL;
    dst->aen = src->aen ? COMMON_STRDUP(src->aen, 1) : NULL;
    dst->aei = src->aei ? COMMON_STRDUP(src->aei, 1) : NULL;

    return 0;
}
COMMON_EXPORT(rina_name_copy);

COMMON_STATIC int
__rina_name_fill(struct rina_name *name, const char *apn,
                 const char *api, const char *aen, const char *aei,
                 int maysleep)
{
    if (!name) {
        return -1;
    }

    name->apn = (apn && strlen(apn)) ? COMMON_STRDUP(apn, maysleep) : NULL;
    name->api = (api && strlen(api)) ? COMMON_STRDUP(api, maysleep) : NULL;
    name->aen = (aen && strlen(aen)) ? COMMON_STRDUP(aen, maysleep) : NULL;
    name->aei = (aei && strlen(aei)) ? COMMON_STRDUP(aei, maysleep) : NULL;

    if ((apn && strlen(apn) && !name->apn) ||
            (api && strlen(api) && !name->api) ||
            (aen && strlen(aen) && !name->aen) ||
            (aei && strlen(aei) && !name->aei)) {
        rina_name_free(name);
        PE("FAILED\n");
        return -1;
    }

    return 0;

}
COMMON_EXPORT(__rina_name_fill);

int
rina_name_fill(struct rina_name *name, const char *apn,
               const char *api, const char *aen, const char *aei)
{
    return __rina_name_fill(name, apn, api, aen, aei, 1);
}
COMMON_EXPORT(rina_name_fill);

COMMON_STATIC char *
__rina_name_to_string(const struct rina_name *name, int maysleep)
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
                             aen_len + 1 + aei_len + 1, maysleep);
    if (!str) {
        return NULL;
    }

    memcpy(cur, name->apn, apn_len);
    cur += apn_len;

    *cur = ':';
    cur++;

    memcpy(cur, name->api, api_len);
    cur += api_len;

    *cur = ':';
    cur++;

    memcpy(cur, name->aen, aen_len);
    cur += aen_len;

    *cur = ':';
    cur++;

    memcpy(cur, name->aei, aei_len);
    cur += aei_len;

    *cur = '\0';

    return str;
}
COMMON_EXPORT(__rina_name_to_string);

char *
rina_name_to_string(const struct rina_name *name)
{
    return __rina_name_to_string(name, 1);
}
COMMON_EXPORT(rina_name_to_string);

int
rina_sername_valid(const char *str)
{
    const char *orig_str = str;
    int cnt = 0;

    if (!str || strlen(str) == 0) {
        return 0;
    }

    while (*str != '\0') {
        if (*str == ':') {
            if (++ cnt > 3) {
                return 0;
            }
        }
        str ++;
    }

    return (*orig_str == ':') ? 0 : 1;
}
COMMON_EXPORT(rina_sername_valid);

COMMON_STATIC int
__rina_name_from_string(const char *str, struct rina_name *name, int maysleep)
{
    char *apn, *api, *aen, *aei;
    char *strc = COMMON_STRDUP(str, maysleep);
    char *strc_orig = strc;
    char **strp = &strc;

    memset(name, 0, sizeof(*name));

    if (!strc) {
        return -1;
    }

    apn = strsep(strp, ":");
    api = strsep(strp, ":");
    aen = strsep(strp, ":");
    aei = strsep(strp, ":");

    if (!apn) {
        /* The ':' are not necessary if some of the api, aen, aei
         * are not present. */
        COMMON_FREE(strc_orig);
        return -1;
    }

    __rina_name_fill(name, apn, api, aen, aei, maysleep);
    COMMON_FREE(strc_orig);

    return 0;
}
COMMON_EXPORT(__rina_name_from_string);

int
rina_name_from_string(const char *str, struct rina_name *name)
{
    return __rina_name_from_string(str, name, 1);
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

int
rina_name_valid(const struct rina_name *name)
{
    if (!name || !name->apn || strlen(name->apn) == 0) {
        return 0;
    }

    return 1;
}
COMMON_EXPORT(rina_name_valid);

void
flow_config_dump(const struct rl_flow_config *c)
{
    if (!c) {
        return;
    }

    COMMON_PRINT("Flow configuration:\n"
                "   msg_boundaries=%u\n"
                "   in_order_delivery=%u\n"
                "   max_sdu_gap=%llu\n"
                "   dtcp_present=%u\n"
                "   dtcp.initial_a=%u\n"
                "   dtcp.bandwidth=%u\n"
                "   dtcp.flow_control=%u\n"
                "   dtcp.rtx_control=%u\n",
                c->msg_boundaries,
                c->in_order_delivery,
                (long long unsigned)c->max_sdu_gap,
                c->dtcp_present,
                c->dtcp.initial_a,
                c->dtcp.bandwidth,
                c->dtcp.flow_control,
                c->dtcp.rtx_control);

    if (c->dtcp.fc.fc_type == RLITE_FC_T_WIN) {
        COMMON_PRINT("   dtcp.fc.max_cwq_len=%lu\n"
                    "   dtcp.fc.initial_credit=%lu\n",
                    (long unsigned)c->dtcp.fc.cfg.w.max_cwq_len,
                    (long unsigned)c->dtcp.fc.cfg.w.initial_credit);
    } else if (c->dtcp.fc.fc_type == RLITE_FC_T_RATE) {
        COMMON_PRINT("   dtcp.fc.sending_rate=%lu\n"
                    "   dtcp.fc.time_period=%lu\n",
                    (long unsigned)c->dtcp.fc.cfg.r.sending_rate,
                    (long unsigned)c->dtcp.fc.cfg.r.time_period);
    }

    COMMON_PRINT("   dtcp.rtx.max_time_to_retry=%u\n"
                "   dtcp.rtx.data_rxms_max=%u\n"
                "   dtcp.rtx.initial_tr=%u\n",
                c->dtcp.rtx.max_time_to_retry,
                c->dtcp.rtx.data_rxms_max,
                c->dtcp.rtx.initial_tr);
}
COMMON_EXPORT(flow_config_dump);

void
rl_flow_spec_default(struct rina_flow_spec *spec)
{
    memset(spec, 0, sizeof(*spec));
    spec->max_sdu_gap = (rlm_seq_t)-1;  /* unbounded allowed gap */
    spec->avg_bandwidth = 0;        /* don't care about bandwidth */
    spec->max_delay = 0;            /* don't care about delay */
    spec->max_jitter = 0;           /* don't care about jitter */
    spec->in_order_delivery = 0;    /* don't require that */
    spec->msg_boundaries = 1;       /* UDP-like */
    rina_flow_spec_fc_set(spec, 0); /* no flow control */
}
COMMON_EXPORT(rl_flow_spec_default);
