/*
 * Common routines used by librlite and librlite-evloop libraries.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CTRL_UTILS_H__
#define __CTRL_UTILS_H__

#include <stdint.h>
#include <pthread.h>
#include "rlite/common.h"
#include "rlite/list.h"


/* This header exports functionalities needed by both rlite and
 * rlite-evloop libraries, but that we don't want to export in
 * the public header ctrl.h. */

struct pending_entry {
    struct rl_msg_base *msg;
    size_t msg_len;
    struct rl_msg_base *resp;

    unsigned int wait_for_completion;
    int op_complete;
    pthread_cond_t op_complete_cond;

    struct list_head node;
};

void
pending_queue_fini(struct list_head *list);

struct pending_entry *
pending_queue_remove_by_event_id(struct list_head *list,
                                 uint32_t event_id);

struct pending_entry *
pending_queue_remove_by_msg_type(struct list_head *list,
                                 unsigned int msg_type);

#endif  /* __CTRL_UTILS_H__ */
