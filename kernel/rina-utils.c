#include "rina-utils.h"
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>


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

    str = cur = kmalloc(apn_len + 1 + api_len + 1 +
                        aen_len + 1 + aei_len + 1,
                        GFP_KERNEL);
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

