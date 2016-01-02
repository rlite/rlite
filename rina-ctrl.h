#ifndef __RINA_CTRL_H__
#define __RINA_CTRL_H__

#include <linux/types.h>

/* Application naming information:
 *   - Application Process Name
 *   - Application Process Instance
 *   - Application Entity Name
 *   - Application Entity Instance
 */
struct rina_name {
    char *apn;
    char *api;
    char *aen;
    char *aei;
};

/* Information about a DIF */
struct dif_information {
    struct rina_name dif_name;
};

/* DIF types */
enum {
    DIF_TYPE_NORMAL = 1,
    DIF_TYPE_SHIM_DUMMY,
};

/* Message types */
enum {
    RINA_CTRL_CREATE_IPCP = 1,
    RINA_CTRL_ASSIGN_TO_DIF,
    RINA_CTRL_MSG_MAX,
};

typedef uint16_t rina_msg_t;

struct rina_ctrl_create_ipcp {
    rina_msg_t msg_type;
    struct rina_name name;
    uint8_t dif_type;
};

struct rina_ctrl_assign_to_dif {
    rina_msg_t msg_type;
    uint32_t ipcp_id;
    struct dif_information dif_info;
};

#endif  /* __RINA_CTRL_H__ */
