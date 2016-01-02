#include "rina-utils.h"
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>


char *
rina_name_to_string(const struct rina_name *name)
{
    char *str = NULL;
    char *cur;

    if (!name) {
        return NULL;
    }

    str = cur = kmalloc(name->apn_len + 1 + name->api_len + 1 +
                        name->aen_len + 1 + name->aei_len + 1,
                        GFP_KERNEL);
    if (!str) {
        return NULL;
    }

    if (name->apn) {
        memcpy(cur, name->apn, name->apn_len);
        cur += name->apn_len;
    }

    *cur = '/';
    cur++;

    if (name->api) {
        memcpy(cur, name->api, name->api_len);
        cur += name->api_len;
    }

    *cur = '/';
    cur++;

    if (name->aen) {
        memcpy(cur, name->aen, name->aen_len);
        cur += name->aen_len;
    }

    *cur = '/';
    cur++;

    if (name->aei) {
        memcpy(cur, name->aei, name->aei_len);
        cur += name->aei_len;
    }

    *cur = '\0';

    return str;
}

static int
copy_buf_from_user(char **dstp, uint16_t *dst_len_p, char __user *src, uint16_t src_len)
{
    if (src) {
        *dst_len_p = src_len;
        *dstp = kmalloc(src_len, GFP_KERNEL);
        if (unlikely(!(*dstp))) {
            return -ENOMEM;
        }
        if (unlikely(copy_from_user(*dstp, src, src_len))) {
            kfree(*dstp);
            return -EFAULT;
        }
    } else {
        *dstp = NULL;
        *dst_len_p = 0;
    }

    return 0;
}

int
copy_name_from_user(struct rina_name *dst, const struct rina_name __user *src)
{
    size_t ret;

    ret = copy_buf_from_user(&dst->apn, &dst->apn_len, src->apn, src->apn_len);
    if (unlikely(ret)) {
        return ret;
    }

    ret = copy_buf_from_user(&dst->api, &dst->api_len, src->api, src->api_len);
    if (unlikely(ret)) {
        return ret;
    }

    ret = copy_buf_from_user(&dst->aen, &dst->aen_len, src->aen, src->aen_len);
    if (unlikely(ret)) {
        return ret;
    }

    ret = copy_buf_from_user(&dst->aei, &dst->aei_len, src->aei, src->aei_len);
    if (unlikely(ret)) {
        return ret;
    }

    return 0;
}
