#ifndef __TEMPLATE_LIST_H__
#define __TEMPLATE_LIST_H__aa

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

struct list_head {
        struct list_head *prev;
        struct list_head *succ;
};

static inline void
list_init(struct list_head *list)
{
        list->prev = list->succ = list;
}

static inline void
list_add_front(struct list_head *list, struct list_head *elem)
{
        list->succ->prev = elem;
        elem->prev = list;
        elem->succ = list->succ;
        list->succ = elem;
}

static inline void
list_add_tail(struct list_head *list, struct list_head *elem)
{
        list->prev->succ = elem;
        elem->succ = list;
        elem->prev = list->prev;
        list->prev = elem;
}

#endif  /* __TEMPLATE_LIST_H__ */
