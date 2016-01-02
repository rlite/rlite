#ifndef __RINA_SERDES_H__
#define __RINA_SERDES_H__

#include <rina/rina-ctrl.h>


unsigned rina_name_serlen(const struct rina_name *name);
void serialize_string(void **pptr, const char *s);
void serialize_rina_name(void **pptr, const struct rina_name *name);
unsigned int serialize_rina_msg(void *serbuf,
                   const struct rina_ctrl_base_msg *msg);
int deserialize_string(const void **pptr, char **s);
int deserialize_rina_name(const void **pptr, struct rina_name *name);
int deserialize_rina_msg(const void *serbuf, unsigned int serbuf_len,
                     void *msgbuf, unsigned int msgbuf_len);
unsigned int rina_msg_serlen(const struct rina_ctrl_base_msg *msg);
void rina_name_free(struct rina_name *name);
void rina_msg_free(struct rina_ctrl_base_msg *msg);
void rina_name_move(struct rina_name *dst, struct rina_name *src);
int rina_name_copy(struct rina_name *dst, const struct rina_name *src);
char *rina_name_to_string(const struct rina_name *name);

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

#endif  /* __RINA_SERDES_H__ */
