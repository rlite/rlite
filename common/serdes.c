#include <rina/serdes.h>
#include <string.h>

/* Size of a serialized string, not including the storage for the size
 * field itself. */
size_t
string_prlen(char *s)
{
    size_t slen;

    slen = s ? strlen(s) : 0;

    return slen > 255 ? 255 : slen;
}

/* Size of a serialized RINA name. */
size_t
rina_name_serlen(struct rina_name *name)
{
    size_t ret = 4 * sizeof(uint8_t);

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

