#ifndef __RINA_IPCP_H__
#define __RINA_IPCP_H__

#include <rina/rina-utils.h>


struct ipcp_entry;

struct ipcp_ops {
    void (*destroy)(struct ipcp_entry *ipcp);
    int (*assign_to_dif)(struct ipcp_entry *ipcp, struct rina_name *dif_name);
    int (*application_register)(struct ipcp_entry *ipcp, struct rina_name *app_name);
    int (*application_unregister)(struct ipcp_entry *ipcp, struct rina_name *app_name);
    int (*sdu_write)(struct ipcp_entry *ipcp, void *sdu, unsigned int sdu_len);
};

struct ipcp_entry {
    uint16_t            id;    /* Key */
    struct rina_name    name;
    struct rina_name    dif_name;
    uint8_t             dif_type;
    struct ipcp_ops     ops;
    void                *priv;
    struct hlist_node   node;
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
