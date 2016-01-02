#ifndef __RINA_APPLICATION_MSG_H__
#define __RINA_APPLICATION_MSG_H__

#include <stdint.h>

#include <rina/rina-ipcp-types.h>
#include <rina/rina-common.h>


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RINA_APPLICATION_REGISTER = 1,
    RINA_APPLICATION_UNREGISTER, /* 2 */

    RINA_APPLICATION_MSG_MAX,
};

struct rina_msg_appl_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    struct rina_name application_name;
    struct rina_name dif_name;
} __attribute__((packed));

#endif  /* __RINA_APPLICATION_MSG_H__ */
