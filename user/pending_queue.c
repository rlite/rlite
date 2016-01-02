#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "rinalite/rinalite-common.h"
#include "pending_queue.h"
#include "rinalite-list.h"


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

void
pending_queue_fini(struct list_head *list)
{
    struct list_head *cur;
    struct pending_entry *e;

    for (;;) {
        cur = list_pop_front(list);
        if (cur) {
            e = container_of(cur, struct pending_entry, node);
            free(e);
        } else {
            break;
        }
    }
}
