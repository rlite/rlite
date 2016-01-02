#ifndef __RINA_APPLICATION_MSG_H__
#define __RINA_APPLICATION_MSG_H__

#include <stdint.h>

#include <rina/rina-ipcp-types.h>
#include <rina/rina-common.h>
#include <rina/rina-utils.h>


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RINA_APPL_REGISTER = 1,
    RINA_APPL_REGISTER_RESP,   /* 2 */
    RINA_APPL_UNREGISTER,      /* 3 */
    RINA_APPL_UNREGISTER_RESP, /* 4 */

    RINA_APPL_MSG_MAX,
};

/* Numtables for application <==> ipcm messages exchange. */

extern struct rina_msg_layout rina_application_numtables[RINA_APPL_MSG_MAX];

struct rina_amsg_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    struct rina_name application_name;
    struct rina_name dif_name;
} __attribute__((packed));

#endif  /* __RINA_APPLICATION_MSG_H__ */
