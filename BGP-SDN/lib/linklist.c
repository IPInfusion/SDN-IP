/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "linklist.h"

/* Allocate new list. */
struct list *
list_new ()
{
  struct list *new;

  new = XCALLOC (MTYPE_LINK_LIST, sizeof (struct list));
  if (new == NULL)
    return NULL;

  return new;
}


struct list *list_create(list_cmp_cb_t cmp, list_del_cb_t del)
{
  struct list *new;

  new = XCALLOC (MTYPE_LINK_LIST, sizeof (struct list));
  if (new == NULL)
    return NULL;

  new->cmp = cmp;
  new->del = del;
  return new;
}

/* Assume the memory is allocated by user. 
*/
struct list *list_init(struct list  *list, 
		       list_cmp_cb_t cmp, 
		       list_del_cb_t del)
{
  pal_mem_set(list, 0, sizeof(*list));
  list->cmp = cmp;
  list->del = del;
  return list;
}

/* Free list. */
void
list_free (struct list *list)
{
  XFREE (MTYPE_LINK_LIST, list);
}

/* Allocate new listnode.  Internal use only. */
static struct listnode *
listnode_new ()
{
  struct listnode *node;

  node = XCALLOC (MTYPE_LIST_NODE, sizeof (struct listnode));
  return node;
}

/* Free listnode. */
static void
listnode_free (struct listnode *node)
{
  XFREE (MTYPE_LIST_NODE, node);
}

/* Add new data to the list. */
struct listnode *
listnode_add (struct list *list, void *val)
{
  struct listnode *node;

  if ( (!list) || (!val) )
    return NULL;

  node = listnode_new ();
  if ( !node )
    return NULL;

  node->prev = list->tail;
  node->data = val;

  if (list->head == NULL)
    list->head = node;
  else
    list->tail->next = node;
  list->tail = node;

  list->count++;

  return node;
}

/* Add new node with sort function. */
struct listnode *
listnode_add_sort (struct list *list, void *val)
{
  struct listnode *n;
  struct listnode *new;

  new = listnode_new ();
  if (! new)
    return NULL;

  new->data = val;

  if (list->cmp)
    {
      for (n = list->head; n; n = n->next)
        {
          if ((list->cmp(val, n->data)) < 0)
            {       
              new->next = n;
              new->prev = n->prev;

              if (n->prev)
                n->prev->next = new;
              else
                list->head = new;
              n->prev = new;
              list->count++;
              return new;
            }
        }
    }

  new->prev = list->tail;

  if (list->tail)
    list->tail->next = new;
  else
    list->head = new;

  list->tail = new;
  list->count++;
  return new;
}

/* Insert the val into the list at a node based on the value in val
 * such that the list is in ascending order of values and
 * return the position of the node in the list.
 */
u_int16_t
listnode_add_sort_index (struct list *list, u_int32_t *val)
{
   u_int16_t count = 0;
   struct listnode *n;
   struct listnode *new;
   u_int32_t *nodeval;

   if (! list)
     return 0;

   new = XCALLOC (MTYPE_LIST_NODE, sizeof (struct listnode));
   if (! new)
     return 0;

   new->data = val;

   for (n = list->head; n; n = n->next)
     {
       nodeval = n->data;
       count++;
       if (*val < *nodeval)
         {
           new->next = n;
           new->prev = n->prev;

           if (n->prev)
             n->prev->next = new;
           else
             list->head = new;

           n->prev = new;
           list->count++;
           return count;
         }
     }
   new->prev = list->tail;

   if (list->tail)
     list->tail->next = new;
   else
     list->head = new;

   list->tail = new;
   list->count++;
   count++;
   return count;
}

/* Add a unique new node with sort function. */
/* Returns 0 if a new node has been added */
/* Returns 1 if the node is duplicate */
int
listnode_add_sort_nodup (struct list *list, void *val)
{
  struct listnode *n;
  struct listnode *new;
  int ret;

  new = listnode_new ();
  if (new == NULL) {
    return 2;
  }
  new->data = val;

  if (list->cmp)
    {
      for (n = list->head; n; n = n->next)
        {
          ret = list->cmp(val, n->data);
          if (ret < 0)
            {       
              new->next = n;
              new->prev = n->prev;

              if (n->prev)
                n->prev->next = new;
              else
                list->head = new;
              n->prev = new;
              list->count++;
              return 0;
            }
          /* Duplicate node */
          else if (ret == 0)
            {
              listnode_free (new);
              return 1;
            }
        }
    }

  new->prev = list->tail;

  if (list->tail)
    list->tail->next = new;
  else
    list->head = new;

  list->tail = new;
  list->count++;
  return 0;
}

struct listnode *
listnode_add_before (struct list *list, struct listnode *pp, void *val)
{
  struct listnode *new;
                                                                                
  new = listnode_new ();
  if (! new)
    return NULL;
                                                                                
  if (pp == NULL)
    {
      if (list->head)
        list->head->prev = new;
      else
        list->tail = new;
                                                                                
      new->next = list->head;
      new->prev = pp;
                                                                                
      list->head = new;
    }
  else
    {
      new->next = pp;
      new->prev = pp->prev;
                                                                                
      if (pp->prev)
        pp->prev->next  = new;
      else
        list->head = new;
                                                                                
      pp->prev = new;
    }                                                                               
  new->data = val;
  list->count++;
  return new;
}



struct listnode *
listnode_add_after (struct list *list, struct listnode *pp, void *val)
{
  struct listnode *nn;

  nn = listnode_new ();
  if (! nn)
    return NULL;

  nn->data = val;

  if (pp == NULL)
    {
      if (list->head)
        list->head->prev = nn;
      else
        list->tail = nn;

      nn->next = list->head;
      nn->prev = pp;

      list->head = nn;
    }
  else
    {
      if (pp->next)
        pp->next->prev = nn;
      else
        list->tail = nn;

      nn->next = pp->next;
      nn->prev = pp;

      pp->next = nn;
    }
  list->count++;

  return nn;
}

/* Delete specific date pointer from the list. */
void
listnode_delete (struct list *list, void *val)
{
  struct listnode *node;
  
  if ( (!list) || (!val) )
    return;

  for (node = list->head; node; node = node->next)
    {
      if (node->data == val)
        {
          if (node->prev)
            node->prev->next = node->next;
          else
            list->head = node->next;

          if (node->next)
            node->next->prev = node->prev;
          else
            list->tail = node->prev;

          list->count--;

          listnode_free (node);
          return;
        }
    }
}

/* Delete specific data pointer from the list and
 * also call the data free function if any. */
void
listnode_delete_data (struct list *list, void *val)
{
  struct listnode *node;
  
  if ( (!list) || (!val) )
    return;

  for (node = list->head; node; node = node->next)
    {
      if (node->data == val)
        {
          if (node->prev)
            node->prev->next = node->next;
          else
            list->head = node->next;

          if (node->next)
            node->next->prev = node->prev;
          else
            list->tail = node->prev;

          list->count--;

          if (list->del)
            list->del(node->data);

          listnode_free (node);
          return;
        }
    }
}

/* Delete specific node from the list containing data. */
int
list_delete_data (struct list *list, void *val)
{
  struct listnode *node;
  int ret;
  
  if ( (!list) || (!val) || !list->cmp )
    return -1;

  for (node = list->head; node; node = node->next)
    {
      if (node->data == NULL)
        continue;

      ret = list->cmp(val, node->data);
      if (ret == 0)
        {
          if (node->prev)
            node->prev->next = node->next;
          else
            list->head = node->next;

          if (node->next)
            node->next->prev = node->prev;
          else
            list->tail = node->prev;

          list->count--;

          if (list->del)
            list->del(node->data);

          listnode_free (node);
          return 0;
        }
    }
  return -1;
}

/* Return first node's data if it is there.  */
void *
listnode_head (struct list *list)
{
  struct listnode *node;

  node = list->head;

  if (node)
    return node->data;
  return NULL;
}

/* Delete all listnode from the list. */
void
list_delete_all_node (struct list *list)
{
  struct listnode *node;
  struct listnode *next;

  for (node = list->head; node; node = next)
    {
      next = node->next;
      if (list->del)
        {
          if(node)
            if(node->data)
              list->del(node->data);
        }
      listnode_free (node);
      list->head = next;
    }
  list->head = list->tail = NULL;
  list->count = 0;
}

/* Delete all listnode then free list itself. */
void
list_delete (struct list *list)
{
  list_delete_all_node (list);
  list_free (list);
}

void
list_delete_list (struct list *list)
{
  struct listnode *node;
  struct listnode *next;

  for (node = list->head; node; node = next)
    {
      next = node->next;
      if (list->del)
        list->del(node->data);
      listnode_free (node);
    }
  list_free (list);
}

/* Lookup the node which has given data. */
struct listnode *
listnode_lookup (struct list *list, void *data)
{
  struct listnode *node;

  for (node = list->head; node; NEXTNODE (node))
    if (data == GETDATA (node))
      return node;
  return NULL;
}

/* Lookup the node which has given data. */
void *
list_lookup_data (struct list *list, void *data)
{
  struct listnode *node;
  int ret;

  if (!list || !data || !list->cmp)
    return NULL;

  for (node = list->head; node; NEXTNODE (node))
    {
      if (node->data == NULL)
        continue;

      ret = list->cmp(data, node->data);

      if (ret == 0)
        return node->data;
    }
  return NULL;
}


/* Delete the node from list.  For ospfd and ospf6d. */
void
list_delete_node (struct list *list, struct listnode *node)
{
  if (node->prev)
    node->prev->next = node->next;
  else
    list->head = node->next;
  if (node->next)
    node->next->prev = node->prev;
  else
    list->tail = node->prev;
  list->count--;

  listnode_free (node);
}

/* ospf_spf.c */
void
list_add_node_prev (struct list *list, struct listnode *current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  if (node == NULL)
    return;

  node->next = current;
  node->data = val;

  if (current->prev == NULL)
    list->head = node;
  else
    current->prev->next = node;

  node->prev = current->prev;
  current->prev = node;

  list->count++;
}

/* ospf_spf.c */
void
list_add_node_next (struct list *list, struct listnode *current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  if (node == NULL) {
    return;
  }
  node->prev = current;
  node->data = val;

  if (current->next == NULL)
    list->tail = node;
  else
    current->next->prev = node;

  node->next = current->next;
  current->next = node;

  list->count++;
}

/* ospf_spf.c */
void
list_add_list (struct list *l, struct list *m)
{
  struct listnode *n;

  for (n = LISTHEAD (m); n; NEXTNODE (n))
    listnode_add (l, n->data);
}
