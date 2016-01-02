#ifndef __RINA_COMMON_H__
#define __RINA_COMMON_H__


#define RINA_UIPCPS_UNIX_NAME     "/var/rina/uipcp-server"

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

/* Bind the flow identified by port_id to
 * this rina_io device. */
#define RINA_IO_MODE_APPL_BIND    86
/* Use this device to write/read management
 * PDUs for the IPCP specified by ipcp_id. */
#define RINA_IO_MODE_IPCP_MGMT    88

struct rina_ioctl_info {
    uint8_t mode;
    uint32_t port_id;
    uint16_t ipcp_id;
} __attribute__((packed));

#define RINA_MGMT_HDR_T_OUT_LOCAL_PORT      1
#define RINA_MGMT_HDR_T_OUT_DST_ADDR        2
#define RINA_MGMT_HDR_T_IN                  3

/* Header used across user/kernel boundary when writing/reading
 * management SDUs from rina-io devices working in RINA_IO_MODE_IPCP_MGMT
 * mode.
 * Userspace can write a management SDU specifying either a local
 * port (type OUT_LOCAL_PORT) or a destination address (OUT_DST_ADDR). In
 * the former case 'local_port' should refer to an existing N-1 flow
 * ('remote_addr' is ignored), while in the latter 'remote_addr' should
 * refer to an N-IPCP that will be reached as specified by the PDUFT
 * ('local_port' is ignored).
 * When reading a management SDU, the header will contain the local port
 * where the SDU was received and the source (remote) address that sent it.
 */
struct rina_mgmt_hdr {
    uint8_t type;
    uint32_t local_port;
    uint64_t remote_addr;
} __attribute__((packed));


/* Flow specifications and QoS cubes related definitions. */

struct rate_based_config {
    uint64_t sending_rate;
    uint64_t time_period; /* us */
} __attribute__((packed));

struct window_based_config {
    uint64_t max_cwq_len; /* closed window queue */
    uint64_t initial_credit;
} __attribute__((packed));

#define RINA_FC_T_NONE      0
#define RINA_FC_T_WIN       1
#define RINA_FC_T_RATE      2

struct fc_config {
    uint8_t fc_type;
    union {
        struct rate_based_config r;
        struct window_based_config w;
    } cfg;
} __attribute__((packed));

struct rtx_config {
    uint32_t max_time_to_retry; /* R div initial_tr */
    uint16_t data_rxms_max;
    uint32_t initial_tr;
} __attribute__((packed));

struct dtcp_config {
    uint8_t flow_control;
    struct fc_config fc;
    uint8_t rtx_control;
    struct rtx_config rtx;
    uint32_t initial_a;  /* A */
} __attribute__((packed));

struct rina_flow_config {
    uint8_t partial_delivery;
    uint8_t incomplete_delivery;
    uint8_t in_order_delivery;
    uint64_t max_sdu_gap;
    uint8_t dtcp_present;
    struct dtcp_config dtcp;
} __attribute__((packed));

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

#define PE(format, ...) PRINTFUN(format, ##__VA_ARGS__)

#define NPD(format, ...)

#ifdef __KERNEL__

#define time_sec_cur     (jiffies_to_msecs(jiffies) / 1000U)

/* Rate-limited version, lps indicate how many per second. */
#define RPD(lps, format, ...)                           \
    do {                                                \
        static int t0, __cnt;                           \
        if (t0 != time_sec_cur) {                       \
            t0 = time_sec_cur;                          \
            __cnt = 0;                                  \
        }                                               \
        if (__cnt++ < lps)                              \
        PD(format, ##__VA_ARGS__);                      \
    } while (0)

#endif

#endif  /* __RINA_COMMON_H__ */
