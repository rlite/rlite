#ifndef __UIPCP_RIB_H__
#define __UIPCP_RIB_H__

#ifdef __cplusplus
extern "C" {
#endif

struct uipcp_rib;

struct uipcp_rib *rib_create(void);
void rib_destroy(struct uipcp_rib *rib);

#ifdef __cplusplus
}
#endif

#endif /* __UIPCP_RIB_H__ */
