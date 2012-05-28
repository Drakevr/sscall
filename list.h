#ifndef _LIST_H
#define _LIST_H

#define offsetof(TYPE, MEMBER) ((size_t)__builtin_offsetof(TYPE, MEMBER))
#define container_of(ptr, type, member) ({ const typeof( ((type *)0)->member ) *__mptr = (ptr); (type *)( (char *)__mptr - offsetof(type,member) ); })

/**
 * list_entry - get the struct for this entry
 * @ptr: the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_for_each  -  iterate over a list
 * @pos: the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
	     pos = pos->next)
/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos: the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
	     pos = n, n = pos->next)

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define LIST_HEAD_INIT(name) { &(name), &(name) } /* assign both next and prev to point to &name */

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

static inline void
INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void
list_add(struct list_head *new, struct list_head *head)
{
	head->next->prev = new;
	new->next = head->next;
	new->prev = head;
	head->next = new;
}

static inline void
list_add_tail(struct list_head *new, struct list_head *head)
{
	head->prev->next = new;
	new->next = head;
	new->prev = head->prev;
	head->prev = new;
}

static inline void
list_del(struct list_head *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->next = NULL;
	entry->prev = NULL;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int
list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#endif
