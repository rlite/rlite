#ifndef __RINA_IPCP_H__
#define __RINA_IPCP_H__

#include <rina/rina-utils.h>


struct ipcp_ops {
    void (*destroy)(void *data);
    int (*assign_to_dif)(void *data, struct rina_name *dif_name);
    int (*application_register)(void *data, struct rina_name *app_name);
    int (*application_unregister)(void *data, struct rina_name *app_name);
    int (*sdu_write)(void *data, void *sdu, unsigned int sdu_len);
};

struct ipcp_factory {
    uint8_t dif_type;
    void *(*create)(void);
    struct ipcp_ops ops;
    struct list_head node;
};

int rina_ipcp_factory_register(struct ipcp_factory *factory);
int rina_ipcp_factory_unregister(uint8_t dif_type);

#endif  /* __RINA_IPCP_H__ */
