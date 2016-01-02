#ifndef __RINA_COMMON_H__
#define __RINA_COMMON_H__


#define RINA_IPCM_UNIX_NAME     "/tmp/rina-ipcm"

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
} __attribute__((packed));

typedef uint16_t rina_msg_t;

/* All the possible messages begin like this. */
struct rina_msg_base {
    rina_msg_t msg_type;
    uint32_t event_id;
} __attribute__((packed));

/* A simple response message layout that can be shared by many
 * different types. */
struct rina_msg_base_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
} __attribute__((packed));

struct rina_ioctl_info {
    uint32_t port_id;
    uint16_t ipcp_id;
    uint8_t  application;
};

/* Logging macros. */
#define PD_ON  /* Enable debug print. */
#define PI_ON  /* Enable info print. */

#ifdef __KERNEL__
#define PRINTFUN printk
#else
#define PRINTFUN printf
#endif

#ifdef PD_ON
#define PD(format, ...) PRINTFUN(format, ##__VA_ARGS__)
#else
#define PD(format, ...)
#endif

#ifdef PI_ON
#define PI(format, ...) PRINTFUN(format, ##__VA_ARGS__)
#else
#define PI(formt, ...)
#endif

#define PN(format, ...)
#define PE(format, ...) PRINTFUN(format, ##__VA_ARGS__)

#endif  /* __RINA_COMMON_H__ */
