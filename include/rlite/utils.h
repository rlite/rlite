/*
 * librlite misc functionalities (serialization, rina names, etc.).
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_SERDES_H__
#define __RLITE_SERDES_H__

#include "rlite/common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rlite_msg_layout {
    unsigned int copylen;
    unsigned int names;
    unsigned int strings;
    unsigned int buffers;
};

struct rl_buf_field {
    void        *buf;
    uint32_t    len;
};

unsigned rina_name_serlen(const struct rina_name *name);
void serialize_string(void **pptr, const char *s);
void serialize_rina_name(void **pptr, const struct rina_name *name);
unsigned int serialize_rlite_msg(struct rlite_msg_layout *numtables,
                                size_t num_entries,
                                void *serbuf,
                                const struct rlite_msg_base *msg);
int deserialize_string(const void **pptr, char **s);
int deserialize_rina_name(const void **pptr, struct rina_name *name);
int deserialize_rlite_msg(struct rlite_msg_layout *numtables, size_t num_entries,
                         const void *serbuf, unsigned int serbuf_len,
                         void *msgbuf, unsigned int msgbuf_len);
unsigned int rlite_msg_serlen(struct rlite_msg_layout *numtables,
                             size_t num_entries,
                             const struct rlite_msg_base *msg);
unsigned int rlite_numtables_max_size(struct rlite_msg_layout *numtables,
                                unsigned int n);
void rina_name_free(struct rina_name *name);
void rlite_msg_free(struct rlite_msg_layout *numtables, size_t num_entries,
                   struct rlite_msg_base *msg);
void rina_name_move(struct rina_name *dst, struct rina_name *src);
int rina_name_copy(struct rina_name *dst, const struct rina_name *src);
char *rina_name_to_string(const struct rina_name *name);
int rina_name_from_string(const char *str, struct rina_name *name);
int rina_name_cmp(const struct rina_name *one, const struct rina_name *two);
int rina_name_fill(struct rina_name *name, const char *apn,
                   const char *api, const char *aen, const char *aei);
int rina_name_valid(const struct rina_name *name);

void flow_config_dump(const struct rlite_flow_config *c);

#ifdef __KERNEL__
/* GFP variations of some of the functions above. */
int __rina_name_fill(struct rina_name *name, const char *apn,
                      const char *api, const char *aen, const char *aei,
                      int maysleep);

char * __rina_name_to_string(const struct rina_name *name, int maysleep);
int __rina_name_from_string(const char *str, struct rina_name *name,
                            int maysleep);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_SERDES_H__ */
