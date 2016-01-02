#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <rina/rina-ctrl.h>
#include "pending_queue.h"


int
pending_queue_init(struct pending_queue *q)
{
    q->head = q->tail = NULL;
    q->count = 0;

    return 0;
}

void
pending_queue_enqueue(struct pending_queue *q, struct pending_entry *e)
{
    if (!e || !e->msg) {
        return;
    }
    e->next = NULL;

    if (q->tail) {
        q->tail->next = e;
        q->tail = e;
    } else {
        q->head = q->tail = e;
    }

    q->count++;
}

struct pending_entry *
pending_queue_dequeue(struct pending_queue *q)
{
    struct pending_entry *e = NULL;

    if (q->head) {
        q->count--;

        e = q->head;
        q->head = e->next;
        if (!q->count) {
            q->tail = q->head = NULL;
        }
    }

    return e;
}

struct pending_entry *
pending_queue_remove_by_event_id(struct pending_queue *q, uint32_t event_id)
{
    struct pending_entry *cur = q->head;
    struct pending_entry *prev = NULL;

    while (cur) {
        if (cur->msg->event_id == event_id) {
            if (prev) {
                prev->next = cur->next;
            }

            if (cur == q->head) {
                q->head = cur->next;
            }

            if (cur == q->tail) {
                q->tail = prev;
            }

            q->count--;

            return cur;
        }

        prev = cur;
        cur = cur->next;
    }

    return NULL;
}

void
pending_queue_fini(struct pending_queue *q)
{
    struct pending_entry *e;

    for (;;) {
        e = pending_queue_dequeue(q);
        if (e) {
            free(e);
        } else {
            break;
        }
    }
}
