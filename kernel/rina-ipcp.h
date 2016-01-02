#ifndef __RINA_IPCP_H__
#define __RINA_IPCP_H__

#include <rina/rina-utils.h>
#include <linux/mutex.h>


struct ipcp_entry;
struct flow_entry;

struct ipcp_ops {
    void (*destroy)(struct ipcp_entry *ipcp);
    int (*assign_to_dif)(struct ipcp_entry *ipcp, struct rina_name *dif_name);
    int (*application_register)(struct ipcp_entry *ipcp, struct rina_name *app_name);
    int (*application_unregister)(struct ipcp_entry *ipcp, struct rina_name *app_name);
    int (*flow_allocate_req)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_allocate_resp)(struct ipcp_entry *ipcp, struct flow_entry *flow);
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
    struct mutex        lock;
    struct list_head    registered_applications;
};

struct ipcp_factory {
    uint8_t dif_type;
    void *(*create)(struct ipcp_entry *ipcp);
    struct ipcp_ops ops;
    struct list_head node;
};

enum {
    FLOW_STATE_NULL = 0,
    FLOW_STATE_PENDING,
    FLOW_STATE_ALLOCATED,
};

struct rina_ctrl;

struct flow_entry {
    uint16_t            local_port;  /* key */
    uint16_t            remote_port;
    uint8_t             state;
    struct rina_name    local_application;
    struct rina_name    remote_application;
    struct ipcp_entry   *ipcp;
    struct rina_ctrl    *rc;
    uint32_t            event_id; /* requestor event id */

    struct mutex        lock;
    struct hlist_node   node;
};

int rina_ipcp_factory_register(struct ipcp_factory *factory);
int rina_ipcp_factory_unregister(uint8_t dif_type);

int rina_flow_allocate_req_arrived(struct ipcp_entry *ipcp,
                                   uint16_t remote_port,
                                   struct rina_name *local_application,
                                   struct rina_name *remote_application);

int rina_flow_allocate_resp_arrived(struct ipcp_entry *ipcp,
                                    uint16_t local_port,
                                    uint8_t response);

#endif  /* __RINA_IPCP_H__ */
