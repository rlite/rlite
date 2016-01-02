#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>
#include <rina/rina-common.h>
#include "list.h"

struct pending_entry {
    struct rina_msg_base *msg;
    size_t msg_len;
    struct rina_msg_base *resp;

    unsigned int wait_for_completion;
    int op_complete;
    pthread_cond_t op_complete_cond;

    struct list_head node;
};

void pending_queue_fini(struct list_head *list);
struct pending_entry *pending_queue_remove_by_event_id(struct list_head *list,
                                                       uint32_t event_id);

#endif  /* __LIST_H__ */
