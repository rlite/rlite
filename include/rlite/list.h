/*
 * Trivial double-linked lists.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __TEMPLATE_LIST_H__
#define __TEMPLATE_LIST_H__

struct list_head {
    struct list_head *prev;
    struct list_head *succ;
};

#define LIST_STATIC_DECL(xyz) struct list_head xyz = {&(xyz), &(xyz)}

static inline void
list_init(struct list_head *list)
{
    list->prev = list->succ = list;
}

static inline int
list_empty(struct list_head *list)
{
    return list == list->prev;
}

static inline void
list_add_front(struct list_head *elem, struct list_head *list)
{
    list->succ->prev = elem;
    elem->prev       = list;
    elem->succ       = list->succ;
    list->succ       = elem;
}

static inline void
list_add_tail(struct list_head *elem, struct list_head *list)
{
    list->prev->succ = elem;
    elem->succ       = list;
    elem->prev       = list->prev;
    list->prev       = elem;
}

static inline struct list_head *
list_pop_front(struct list_head *list)
{
    struct list_head *ret;

    if (list->succ == list) {
        /* Empty list. */
        return NULL;
    }

    ret = list->succ;

    ret->succ->prev = list;
    list->succ      = ret->succ;

    ret->succ = ret->prev = ret;

    return ret;
}

static inline void
list_del(struct list_head *elem)
{
    elem->prev->succ = elem->succ;
    elem->succ->prev = elem->prev;
}

static inline void
list_del_init(struct list_head *elem)
{
    list_del(elem);
    list_init(elem);
}

#define offsetof1(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member)                                        \
    ({                                                                         \
        const typeof(((type *)0)->member) *__mptr = (ptr);                     \
        (type *)((char *)__mptr - offsetof1(type, member));                    \
    })

/* The list_first_entry() macro assumes a first entry exists. */
#define list_first_entry(_list, _type, _member)                                \
    container_of((_list)->succ, _type, _member)

#define list_next_entry(_cur, _member)                                         \
    container_of((_cur)->_member.succ, typeof(*(_cur)), _member)

#define list_for_each_entry(_cur, _list, _member)                              \
    for (_cur = list_first_entry(_list, typeof(*_cur), _member);               \
         &_cur->_member != (_list); _cur = list_next_entry(_cur, _member))

#define list_for_each_entry_safe(_cur, _tmp, _list, _member)                   \
    for (_cur = list_first_entry(_list, typeof(*_cur), _member),               \
        _tmp  = list_next_entry(_cur, _member);                                \
         &_cur->_member != (_list);                                            \
         _cur = _tmp, _tmp = list_next_entry(_tmp, _member))

#endif /* __TEMPLATE_LIST_H__ */
