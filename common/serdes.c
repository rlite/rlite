#include <rina/rina-ctrl.h>
#include <rina/serdes.h>

#ifdef __KERNEL__

#include <linux/string.h>
#include <linux/slab.h>

#define COMMON_ALLOC(_sz)   kmalloc(_sz, GFP_KERNEL)

#else

#include <stdlib.h>
#include <string.h>

#define COMMON_ALLOC(_sz)   malloc(_sz)

#endif

/* Size of a serialized string, not including the storage for the size
 * field itself. */
unsigned int
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
    *s = COMMON_ALLOC(slen + 1);
    if (!(*s)) {
        return -1;
    }

    memcpy(*s, *pptr, slen);
    (*s)[slen] = '\0';
    *pptr += slen;

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

struct rina_msg_layout {
    unsigned int copylen;
    unsigned int names;
};

static struct rina_msg_layout rina_msg_numtables[] = {
    [RINA_CTRL_CREATE_IPCP] = {
        .copylen = sizeof(struct rina_ctrl_create_ipcp) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CTRL_CREATE_IPCP_RESP] = {
        .copylen = sizeof(struct rina_ctrl_create_ipcp_resp),
        .names = 0,
    },
    [RINA_CTRL_DESTROY_IPCP] = {
        .copylen = sizeof(struct rina_ctrl_destroy_ipcp),
        .names = 0,
    },
    [RINA_CTRL_DESTROY_IPCP_RESP] = {
        .copylen = sizeof(struct rina_ctrl_destroy_ipcp_resp),
        .names = 0,
    },
    [RINA_CTRL_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};

/* Serialize msg into serbuf. */
unsigned int
serialize_rina_msg(void *serbuf, unsigned int serbuf_len,
                   const struct rina_ctrl_base_msg *msg)
{
    void *serptr = serbuf;
    unsigned int serlen;
    unsigned int copylen;
    struct rina_name *name;
    int i;

    copylen = rina_msg_numtables[msg->msg_type].copylen;
    memcpy(serbuf, msg, copylen);
    name = (struct rina_name *)(((void *)msg) + copylen);
    serptr = serbuf + copylen;
    for (i = 0; i < rina_msg_numtables[msg->msg_type].names; i++, name++) {
        serialize_rina_name(&serptr, name);
    }
    serlen = serptr - serbuf;

    return serlen;
}

/* Deserialize from serbuf into msgbuf. */
int
deserialize_rina_msg(const void *serbuf, unsigned int serbuf_len,
                     void *msgbuf, unsigned int msgbuf_len)
{
    struct rina_ctrl_base_msg *bmsg = (struct rina_ctrl_base_msg *)serbuf;
    struct rina_name *name;
    size_t copylen;
    const void *desptr;
    int ret;
    int i;

    copylen = rina_msg_numtables[bmsg->msg_type].copylen;
    memcpy(msgbuf, serbuf, copylen);
    desptr = serbuf + copylen;
    name = (struct rina_name *)(msgbuf + copylen);
    for (i = 0; i < rina_msg_numtables[bmsg->msg_type].names; i++, name++) {
        ret = deserialize_rina_name(&desptr, name);
        if (ret) {
            return ret;
        }
    }
    if ((desptr - serbuf) != serbuf_len) {
        return -1;
    }

    return 0;
}
