#include <rina/serdes.h>

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <stdlib.h>
#include <string.h>
#endif

/* Size of a serialized string, not including the storage for the size
 * field itself. */
unsigned int
string_prlen(char *s)
{
    unsigned int slen;

    slen = s ? strlen(s) : 0;

    return slen > 255 ? 255 : slen;
}

/* Size of a serialized RINA name. */
unsigned int
rina_name_serlen(struct rina_name *name)
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
serialize_string(void **pptr, char *s)
{
    uint8_t slen;

    slen = string_prlen(s);
    serialize_obj(*pptr, uint8_t, slen);

    memcpy(*pptr, s, slen);
    *pptr += slen;
}

/* Serialize a RINA name. */
void
serialize_rina_name(void **pptr, struct rina_name *name)
{
    serialize_string(pptr, name->apn);
    serialize_string(pptr, name->api);
    serialize_string(pptr, name->aen);
    serialize_string(pptr, name->aei);
}

