#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>
#include "rlite/common.h"
#include "rlite/list.h"

struct pending_entry {
    struct rlite_msg_base *msg;
    size_t msg_len;
    struct rlite_msg_base *resp;

    unsigned int wait_for_completion;
    int op_complete;
    pthread_cond_t op_complete_cond;

    struct list_head node;
};

void pending_queue_fini(struct list_head *list);

struct pending_entry *pending_queue_remove_by_event_id(struct list_head *list,
                                                       uint32_t event_id);

struct pending_entry *pending_queue_remove_by_msg_type(struct list_head *list,
                                                       unsigned int msg_type);

#endif  /* __LIST_H__ */
