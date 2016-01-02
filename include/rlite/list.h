#ifndef __TEMPLATE_LIST_H__
#define __TEMPLATE_LIST_H__

struct list_head {
        struct list_head *prev;
        struct list_head *succ;
};

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
        elem->prev = list;
        elem->succ = list->succ;
        list->succ = elem;
}

static inline void
list_add_tail(struct list_head *elem, struct list_head *list)
{
        list->prev->succ = elem;
        elem->succ = list;
        elem->prev = list->prev;
        list->prev = elem;
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
    list->succ = ret->succ;

    ret->succ = ret->prev = ret;

    return ret;
}

static inline void
list_del(struct list_head *elem)
{
    elem->prev->succ = elem->succ;
    elem->succ->prev = elem->prev;
}

#define offsetof1(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof1(type,member) );})

#define list_for_each_entry(_cur, _list, _member)                            \
        for (_cur = container_of((_list)->succ, typeof(*_cur), _member);     \
             &_cur->_member != (_list);                                      \
            _cur = container_of(_cur->_member.succ, typeof(*_cur), _member))

/* The list_first_entry() macro assumes a first entry exists. */
#define list_first_entry(_list, _type, _member)                 \
            container_of((_list)->succ, _type, _member)

#endif  /* __TEMPLATE_LIST_H__ */
