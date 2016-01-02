#ifndef __RINA_SERDES_H__
#define __RINA_SERDES_H__

/*
 * When compiling from userspace include <stdint.h>,
 * when compiling from kernelspace include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include <rina/rina-common.h>

struct rina_msg_layout {
    unsigned int copylen;
    unsigned int names;
    unsigned int strings;
};

unsigned rina_name_serlen(const struct rina_name *name);
void serialize_string(void **pptr, const char *s);
void serialize_rina_name(void **pptr, const struct rina_name *name);
unsigned int serialize_rina_msg(struct rina_msg_layout *numtables,
                                void *serbuf,
                                const struct rina_msg_base *msg);
int deserialize_string(const void **pptr, char **s);
int deserialize_rina_name(const void **pptr, struct rina_name *name);
int deserialize_rina_msg(struct rina_msg_layout *numtables,
                         const void *serbuf, unsigned int serbuf_len,
                         void *msgbuf, unsigned int msgbuf_len);
unsigned int rina_msg_serlen(struct rina_msg_layout *numtables,
                             const struct rina_msg_base *msg);
unsigned int rina_numtables_max_size(struct rina_msg_layout *numtables,
                                unsigned int n);
void rina_name_free(struct rina_name *name);
void rina_msg_free(struct rina_msg_layout *numtables,
                   struct rina_msg_base *msg);
void rina_name_move(struct rina_name *dst, struct rina_name *src);
int rina_name_copy(struct rina_name *dst, const struct rina_name *src);
char *rina_name_to_string(const struct rina_name *name);
int rina_name_cmp(const struct rina_name *one, const struct rina_name *two);
void rina_name_fill(struct rina_name *name, const char *apn,
                    const char *api, const char *aen, const char *aei);
int rina_name_valid(const struct rina_name *name);

#endif  /* __RINA_SERDES_H__ */
