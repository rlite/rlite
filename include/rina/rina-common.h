#ifndef __RINA_COMMON_H__
#define __RINA_COMMON_H__

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

#endif  /* __RINA_COMMON_H__ */
