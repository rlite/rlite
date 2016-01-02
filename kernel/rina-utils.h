#ifndef __RINA_UTILS_H__
#define __RINA_UTILS_H__

#include <linux/types.h>
#include <rina/rina-ctrl.h>


char *rina_name_to_string(const struct rina_name *name);
void rina_name_free(struct rina_name *name);
int copy_name_from_user(struct rina_name *dst,
                        const struct rina_name __user *src);

#endif  /* __RINA_UTILS_H__ */
