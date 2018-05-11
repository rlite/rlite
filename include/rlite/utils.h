/*
 * rlite misc functionalities (serialization, rina names, etc.).
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __RLITE_SERDES_H__
#define __RLITE_SERDES_H__

#include "rlite/common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rl_msg_layout {
    unsigned int copylen;
    unsigned int names;
    unsigned int strings;
    unsigned int buffers;
    unsigned int arrays;
};

struct rl_msg_buf_field {
    void *buf;
    uint32_t len;
};

struct rl_msg_array_field {
    uint32_t elem_size;
    uint32_t num_elements;
    union {
        void *raw;
        uint8_t *bytes;
        uint16_t *words;
        uint32_t *dwords;
        uint64_t *qwords;
    } slots;
};

int rina_sername_valid(const char *str);
unsigned rina_name_serlen(const struct rina_name *name);
void serialize_rina_name(void **pptr, const struct rina_name *name);
unsigned int serialize_rlite_msg(struct rl_msg_layout *numtables,
                                 size_t num_entries, void *serbuf,
                                 const struct rl_msg_base *msg);
int deserialize_rina_name(const void **pptr, struct rina_name *name,
                          int *sleft);
int deserialize_rlite_msg(struct rl_msg_layout *numtables, size_t num_entries,
                          const void *serbuf, unsigned int serbuf_len,
                          void *msgbuf, unsigned int msgbuf_len);
unsigned int rl_msg_serlen(struct rl_msg_layout *numtables, size_t num_entries,
                           const struct rl_msg_base *msg);
unsigned int rl_numtables_max_size(struct rl_msg_layout *numtables,
                                   unsigned int n);
void rina_name_free(struct rina_name *name);
void rl_msg_free(struct rl_msg_layout *numtables, size_t num_entries,
                 struct rl_msg_base *msg);
void rina_name_move(struct rina_name *dst, struct rina_name *src);
int rina_name_copy(struct rina_name *dst, const struct rina_name *src);
char *rina_name_to_string(const struct rina_name *name);
int rina_name_from_string(const char *str, struct rina_name *name);
int rina_name_cmp(const struct rina_name *one, const struct rina_name *two);
int rina_name_fill(struct rina_name *name, const char *apn, const char *api,
                   const char *aen, const char *aei);
int rina_name_valid(const struct rina_name *name);

void flow_config_dump(const struct rl_flow_config *c);

void rl_flow_spec_default(struct rina_flow_spec *spec);

#ifdef __KERNEL__
/* GFP variations of some of the functions above. */
int __rina_name_fill(struct rina_name *name, const char *apn, const char *api,
                     const char *aen, const char *aei, int maysleep);

char *__rina_name_to_string(const struct rina_name *name, int maysleep);
int __rina_name_from_string(const char *str, struct rina_name *name,
                            int maysleep);
#else /* !__KERNEL__ */

/* Logging macros. */

#include <time.h>

static inline const char *
hms_string(void)
{
    static char tbuf[9];
    time_t ctime = time(NULL);
    struct tm *time_info;

    time_info = localtime(&ctime);

    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", time_info);

    return tbuf;
}

extern int rl_verbosity;

#define DOPRINT(FMT, ...)                                                      \
    do {                                                                       \
        printf(FMT, ##__VA_ARGS__);                                            \
        fflush(stdout);                                                        \
    } while (0)

#define PRINTFUN1(FMT, ...) DOPRINT(FMT, ##__VA_ARGS__)
#define PRINTFUN2(LEV, FMT, ...)                                               \
    DOPRINT("[%s:" LEV "]%s: " FMT, hms_string(), __func__, ##__VA_ARGS__)

#define PD(FMT, ...)                                                           \
    if (rl_verbosity >= RL_VERB_DBG)                                           \
    PRINTFUN2("DBG", FMT, ##__VA_ARGS__)
#define PD_S(FMT, ...)                                                         \
    if (rl_verbosity >= RL_VERB_DBG)                                           \
    PRINTFUN1(FMT, ##__VA_ARGS__)

#define PI(FMT, ...)                                                           \
    if (rl_verbosity >= RL_VERB_INFO)                                          \
    PRINTFUN2("INF", FMT, ##__VA_ARGS__)
#define PI_S(FMT, ...)                                                         \
    if (rl_verbosity >= RL_VERB_INFO)                                          \
    PRINTFUN1(FMT, ##__VA_ARGS__)

#define PW(FMT, ...)                                                           \
    if (rl_verbosity >= RL_VERB_WARN)                                          \
    PRINTFUN2("WRN", FMT, ##__VA_ARGS__)

#define PV(FMT, ...)                                                           \
    if (rl_verbosity >= RL_VERB_VERY)                                          \
    PRINTFUN2("DBG", FMT, ##__VA_ARGS__)
#define PV_S(FMT, ...)                                                         \
    if (rl_verbosity >= RL_VERB_VERY)                                          \
    PRINTFUN1(FMT, ##__VA_ARGS__)

#define PE(FMT, ...) PRINTFUN2("ERR", FMT, ##__VA_ARGS__)

/* Memtrack support for user-space components. */

typedef enum {
    RL_MT_UTILS = 0,
    RL_MT_CONF,
    RL_MT_MSG,
    RL_MT_API,
    RL_MT_EVLOOP,
    RL_MT_UIPCP,
    RL_MT_TOPO,
    RL_MT_MISC,
    RL_MT_SHIM,
    RL_MT_SHIMDATA,
    RL_MT_NEIGHFLOW,
    RL_MT_MAX
} rl_memtrack_t;

#ifdef RL_MEMTRACK
void *rl_alloc(size_t size, rl_memtrack_t ty);
char *rl_strdup(const char *s, rl_memtrack_t ty);
void rl_free(void *obj, rl_memtrack_t ty);
void rl_mt_adjust(int val, rl_memtrack_t ty);
void rl_memtrack_dump_stats(void);
#else /* ! RL_MEMTRACK */
#define rl_alloc(_sz, _ty) malloc(_sz)
#define rl_strdup(_s, _ty) strdup(_s)
#define rl_free(_obj, _ty) free(_obj)
#define rl_mt_adjust(_1, _2)
#endif /* ! RL_MEMTRACK */

#endif /* !__KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* __RLITE_SERDES_H__ */
