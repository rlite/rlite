#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>
#include <rina/rina-common.h>

struct pending_entry {
    struct pending_entry *next;
    struct rina_msg_base *msg;
    size_t msg_len;
};

struct pending_queue {
    struct pending_entry *head;
    struct pending_entry *tail;
    size_t count;
};

int pending_queue_init(struct pending_queue *q);
void pending_queue_enqueue(struct pending_queue *q,
                           struct pending_entry *e);
struct pending_entry *pending_queue_dequeue(struct pending_queue *q);
void pending_queue_fini(struct pending_queue *q);
struct pending_entry *pending_queue_remove_by_event_id(struct pending_queue *q,
                                                       uint32_t event_id);

#endif  /* __LIST_H__ */
