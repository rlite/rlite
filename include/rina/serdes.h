#ifndef __RINA_SERDES_H__
#define __RINA_SERDES_H__

#include <rina/rina-ctrl.h>


unsigned int string_prlen(char *s);
unsigned rina_name_serlen(struct rina_name *name);
void serialize_string(void **pptr, char *s);
void serialize_rina_name(void **pptr, struct rina_name *name);

/* Serialize a numeric variable _v of type _t. */
#define serialize_obj(_p, _t, _v)       \
        do {                            \
            *((_t *)_p) = _v;           \
            _p += sizeof(_t);           \
        } while (0)


#endif  /* __RINA_SERDES_H__ */
