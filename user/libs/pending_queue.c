#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "rlite/common.h"
#include "pending_queue.h"
#include "rlite/list.h"


struct pending_entry *
pending_queue_remove_by_event_id(struct list_head *list, uint32_t event_id)
{
    struct pending_entry *cur;
    struct pending_entry *found = NULL;

    list_for_each_entry(cur, list, node) {
        if (cur->msg->event_id == event_id) {
            found = cur;
            break;
        }
    }

    if (found) {
        list_del(&found->node);
    }

    return found;
}

struct pending_entry *
pending_queue_remove_by_msg_type(struct list_head *list, unsigned int msg_type)
{
    struct pending_entry *cur;
    struct pending_entry *found = NULL;

    list_for_each_entry(cur, list, node) {
        if (cur->msg->msg_type == msg_type) {
            found = cur;
            break;
        }
    }

    if (found) {
        list_del(&found->node);
    }

    return found;
}

void
pending_queue_fini(struct list_head *list)
{
    struct pending_entry *e, *tmp;

    list_for_each_entry_safe(e, tmp, list, node) {
        list_del(&e->node);
        if (e->msg) {
            free(e->msg);
        }
        if (e->resp) {
            free(e->resp);
        }
        free(e);
    }
}
