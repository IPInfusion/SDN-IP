/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "bgp_ptree.h"

/*
  This generic Patricia Tree structure may be used for variable length
  keys. Please note that key_len being passed to the routines is in bits,
  and not in bytes.

  Also note that this tree may not work if both IPv4 and IPv6 prefixes are
  stored in the table at the same time, since the prefix length values for
  the IPv4 and IPv6 addresses can be non-unique, and so can the bit
  representation of the address.
  If only host addresses are being stored, then this table may be used to
  store IPv4 and IPv6 addresses at the same time, since the prefix lengths
  will be 32 bits for the former, and 128 bits for the latter.
*/

/* Initialize tree. max_key_len is in bits. */

struct bgp_ptree *
bgp_ptree_init (u_int16_t max_key_len)
{
  struct bgp_ptree *tree;

  if (! max_key_len)
    return NULL;

  tree = XCALLOC (MTYPE_PTREE, sizeof (struct bgp_ptree));
  tree->max_key_len = max_key_len;

  return tree;
}

/* Free route tree. */
void
bgp_ptree_free (struct bgp_ptree *rt)
{
  struct bgp_node *tmp_node;
  struct bgp_node *node;

  if (rt == NULL)
    return;

  node = rt->top;

  while (node)
    {
      if (node->p_left)
	{
	  node = node->p_left;
	  continue;
	}

      if (node->p_right)
	{
	  node = node->p_right;
	  continue;
	}

      tmp_node = node;
      node = node->parent;

      if (node != NULL)
	{
	  if (node->p_left == tmp_node)
	    node->p_left = NULL;
	  else
	    node->p_right = NULL;

	  bgp_ptree_node_free (tmp_node);
	}
      else
	{
	  bgp_ptree_node_free (tmp_node);
	  break;
	}
    }

  XFREE (MTYPE_PTREE, rt);
  return;
}

/* Remove route tree. */
void
bgp_ptree_finish (struct bgp_ptree *rt)
{
  bgp_ptree_free (rt);
}

int
bgp_ptree_bit_to_octets (u_int16_t key_len)
{
  return MAX ((key_len + 7) / 8, BGP_PTREE_KEY_MIN_LEN);
}

/* Set key in node. */
void
bgp_ptree_key_copy (struct bgp_node *node, u_char *key, u_int16_t key_len)
{
  int octets;

  if (key_len == 0)
    return;

  octets = bgp_ptree_bit_to_octets (key_len);
  pal_mem_cpy (BGP_PTREE_NODE_KEY (node), key, octets);
}

/* Allocate new route node. */
struct bgp_node *
bgp_ptree_node_create (u_int16_t key_len)
{
  struct bgp_node *pn;
  int octets;

  octets = bgp_ptree_bit_to_octets (key_len);

  pn = XCALLOC (MTYPE_PTREE_NODE, sizeof (struct bgp_node) + octets);
  if (! pn)
    return NULL;

  pn->key_len = key_len;

  return pn;
}

/* Utility mask array. */
static const u_char maskbit[] =
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* Match keys. If n includes p prefix then return TRUE else return FALSE. */
int
bgp_ptree_key_match (u_char *np, u_int16_t n_len, u_char *pp, u_int16_t p_len)
{
  int shift;
  int offset;

  if (n_len > p_len)
    return PAL_FALSE;

  offset = MIN (n_len, p_len) / 8;
  shift = MIN (n_len, p_len) % 8;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return PAL_FALSE;

  while (offset--)
    if (np[offset] != pp[offset])
      return PAL_FALSE;

  return PAL_TRUE;
}

/* Allocate new route node with ptree_key set. */
struct bgp_node *
bgp_ptree_node_set (struct bgp_ptree *tree, u_char *key, u_int16_t key_len)
{
  struct bgp_node *node;

  node = bgp_ptree_node_create (key_len);
  if (! node)
    return NULL;

  /* Copy over key. */
  bgp_ptree_key_copy (node, key, key_len);
  node->tree = tree;

  return node;
}

/* Free route node. */
void
bgp_ptree_node_free (struct bgp_node *node)
{
  if (node)
    {
      /* Set all the pointer fields to NULL before freeing */
      node->link[0] = NULL;
      node->link[1] = NULL;
      node->tree    = NULL;
      node->parent  = NULL;
      node->info    = NULL;
      node->adj_out = NULL;
      node->adj_in  = NULL;
      XFREE (MTYPE_BGP_NODE, node);
   }

}

/* Common ptree_key route genaration. */
static struct bgp_node *
bgp_ptree_node_common (struct bgp_node *n, u_char *pp, u_int16_t p_len)
{
  int i;
  int j;
  u_char diff;
  u_char mask;
  u_int16_t key_len;
  struct bgp_node *new;
  u_char *np;
  u_char *newp;
  u_char boundary = 0;

  np = BGP_PTREE_NODE_KEY (n);

  for (i = 0; i < p_len / 8; i++)
    if (np[i] != pp[i])
      break;

  key_len = i * 8;

  if (key_len != p_len)
    {
      diff = np[i] ^ pp[i];
      mask = 0x80;
      while (key_len < p_len && !(mask & diff))
	{
          if (boundary == 0)
            boundary = 1;
	  mask >>= 1;
	  key_len++;
	}
    }

  /* Fill new key. */
  new = bgp_ptree_node_create (key_len);
  if (! new)
    return NULL;

  newp = BGP_PTREE_NODE_KEY (new);

  for (j = 0; j < i; j++)
    newp[j] = np[j];

  if (boundary)
    newp[j] = np[j] & maskbit[new->key_len % 8];

  return new;
}

/* Check bit of the ptree_key. */
int
bgp_ptree_check_bit (struct bgp_ptree *tree, u_char *p, u_int16_t key_len)
{
  int offset;
  int shift;

  pal_assert (tree->max_key_len >= key_len);

  offset = key_len / 8;
  shift = 7 - (key_len % 8);

  return (p[offset] >> shift & 1);
}

static void
bgp_ptree_set_link (struct bgp_node *node, struct bgp_node *new)
{
  int bit;

  bit = bgp_ptree_check_bit (new->tree, BGP_PTREE_NODE_KEY (new), node->key_len);

  pal_assert (bit == 0 || bit == 1);

  node->link[bit] = new;
  new->parent = node;
}

/* Lock node. */
struct bgp_node *
bgp_ptree_lock_node (struct bgp_node *node)
{
  node->lock++;
  return node;
}

/* Unlock node. */
void
bgp_ptree_unlock_node (struct bgp_node *node)
{
  node->lock--;

  if (node->lock == 0)
    bgp_ptree_node_delete (node);
}

/* Find matched ptree_key. */
struct bgp_node *
bgp_ptree_node_match (struct bgp_ptree *tree, u_char *key, u_int16_t key_len)
{
  struct bgp_node *node;
  struct bgp_node *matched;

  if (key_len > tree->max_key_len)
    return NULL;

  matched = NULL;
  node = tree->top;

  /* Walk down tree.  If there is matched route then store it to
     matched. */
  while (node && (node->key_len <= key_len)) 
    { 
       if (node->info == NULL)
         {
           node = node->link[bgp_ptree_check_bit (tree, key, node->key_len)];
           continue;
         }

       if (!bgp_ptree_key_match (BGP_PTREE_NODE_KEY (node),
                            node->key_len, key, key_len))
         break;

      matched = node;
      node = node->link[bgp_ptree_check_bit (tree, key, node->key_len)];
    }

  /* If matched route found, return it. */
  if (matched)
    return bgp_ptree_lock_node (matched);

  return NULL;
}


/* Lookup same ptree_key node.  Return NULL when we can't find the node. */
struct bgp_node *
bgp_ptree_node_lookup (struct bgp_ptree *tree, u_char *key, u_int16_t key_len)
{
  struct bgp_node *node;

  if (key_len > tree->max_key_len)
    return NULL;

  node = tree->top;
  while (node && node->key_len <= key_len
         && bgp_ptree_key_match (BGP_PTREE_NODE_KEY (node),
                             node->key_len, key, key_len))
    {
      if (node->key_len == key_len && node->info)
        return bgp_ptree_lock_node (node);

      node = node->link[bgp_ptree_check_bit(tree, key, node->key_len)];
    }

  return NULL;
}

/*
 * Lookup same ptree_key node in sub-tree rooted at 'start_node'.
 * Return NULL when we can't find the node.
 */
struct bgp_node *
bgp_ptree_node_sub_tree_lookup (struct bgp_ptree *tree,
                            struct bgp_node *start_node,
                            u_char *key,
                            u_int16_t key_len)
{
  struct bgp_node *node;

  if (! start_node || key_len > tree->max_key_len)
    return NULL;

  node = start_node;
  while (node && node->key_len <= key_len
         && bgp_ptree_key_match (BGP_PTREE_NODE_KEY (node),
                             node->key_len, key, key_len))
    {
      if (node->key_len == key_len && node->info)
        return bgp_ptree_lock_node (node);

      node = node->link[bgp_ptree_check_bit(tree, key, node->key_len)];
    }

  return NULL;
}

/* Add node to routing tree. */
struct bgp_node *
bgp_ptree_node_get (struct bgp_ptree *tree, u_char *key, u_int16_t key_len)
{
  struct bgp_node *new, *node, *match;

  if (key_len > tree->max_key_len)
    return NULL;

  match = NULL;
  node = tree->top;
  while (node && node->key_len <= key_len && 
	 bgp_ptree_key_match (BGP_PTREE_NODE_KEY (node), node->key_len, key, key_len))
    {
      if (node->key_len == key_len)
	return bgp_ptree_lock_node (node);
    
      match = node;
      node = node->link[bgp_ptree_check_bit (tree, key, node->key_len)];
    }

  if (node == NULL)
    {
      new = bgp_ptree_node_set (tree, key, key_len);
      if (match)
	bgp_ptree_set_link (match, new);
      else
	tree->top = new;
    }
  else
    {
      new = bgp_ptree_node_common (node, key, key_len);
      if (! new)
	return NULL;
      new->tree = tree;
      bgp_ptree_set_link (new, node);

      if (match)
	bgp_ptree_set_link (match, new);
      else
	tree->top = new;

      if (new->key_len != key_len)
	{
	  match = new;
	  new = bgp_ptree_node_set (tree, key, key_len);
	  bgp_ptree_set_link (match, new);
	}
    }

  bgp_ptree_lock_node (new);
  return new;
}

/* Delete node from the routing tree. */
void
bgp_ptree_node_delete (struct bgp_node *node)
{
  struct bgp_node *child, *parent;

  pal_assert (node->lock == 0);
  pal_assert (node->info == NULL);

  if (node->p_left && node->p_right)
    return;

  if (node->p_left)
    child = node->p_left;
  else
    child = node->p_right;

  parent = node->parent;

  if (child)
    child->parent = parent;

  if (parent)
    {
      if (parent->p_left == node)
	parent->p_left = child;
      else
	parent->p_right = child;
    }
  else
    node->tree->top = child;

  bgp_ptree_node_free (node);

  /* If parent node is stub then delete it also. */
  if (parent && parent->lock == 0)
    bgp_ptree_node_delete (parent);
}

/* Delete All Ptree Nodes */
void
bgp_ptree_node_delete_all (struct bgp_ptree *rt)
{
  struct bgp_node *tmp_node;
  struct bgp_node *node;

  if (rt == NULL)
    return;

  node = rt->top;

  while (node)
    {
      if (node->p_left)
        {
          node = node->p_left;
          continue;
        }

      if (node->p_right)
        {
          node = node->p_right;
          continue;
        }

      tmp_node = node;
      node = node->parent;

      if (node != NULL)
        {
          if (node->p_left == tmp_node)
            node->p_left = NULL;
          else
            node->p_right = NULL;

          bgp_ptree_node_free (tmp_node);
        }
      else
        {
          bgp_ptree_node_free (tmp_node);
          rt->top = NULL;
          break;
        }
    }

  return;
}

/* Get fist node and lock it.  This function is useful when one want
   to lookup all the node exist in the routing tree. */
struct bgp_node *
bgp_ptree_top (struct bgp_ptree *tree)
{
  /* If there is no node in the routing tree return NULL. */
  if (tree == NULL || tree->top == NULL)
    return NULL;

  /* Lock the top node and return it. */
  return bgp_ptree_lock_node (tree->top);
}

/* Unlock current node and lock next node then return it. */
struct bgp_node *
bgp_ptree_next (struct bgp_node *node)
{
  struct bgp_node *next, *start;

  /* Node may be deleted from ptree_unlock_node so we have to preserve
     next node's pointer. */

  if (node->p_left)
    {
      next = node->p_left;
      bgp_ptree_lock_node (next);
      bgp_ptree_unlock_node (node);
      return next;
    }
  if (node->p_right)
    {
      next = node->p_right;
      bgp_ptree_lock_node (next);
      bgp_ptree_unlock_node (node);
      return next;
    }

  start = node;
  while (node->parent)
    {
      if (node->parent->p_left == node && node->parent->p_right)
	{
	  next = node->parent->p_right;
	  bgp_ptree_lock_node (next);
	  bgp_ptree_unlock_node (start);
	  return next;
	}
      node = node->parent;
    }
  bgp_ptree_unlock_node (start);
  return NULL;
}

/* Unlock current node and lock next node until limit. */
struct bgp_node *
bgp_ptree_next_until (struct bgp_node *node, struct bgp_node *limit)
{
  struct bgp_node *next, *start;

  /* Node may be deleted from ptree_unlock_node so we have to preserve
     next node's pointer. */

  if (node->p_left)
    {
      next = node->p_left;
      bgp_ptree_lock_node (next);
      bgp_ptree_unlock_node (node);
      return next;
    }
  if (node->p_right)
    {
      next = node->p_right;
      bgp_ptree_lock_node (next);
      bgp_ptree_unlock_node (node);
      return next;
    }

  start = node;
  while (node->parent && node != limit)
    {
      if (node->parent->p_left == node && node->parent->p_right)
	{
	  next = node->parent->p_right;
	  bgp_ptree_lock_node (next);
	  bgp_ptree_unlock_node (start);
	  return next;
	}
      node = node->parent;
    }
  bgp_ptree_unlock_node (start);
  return NULL;
}

/* Check if the tree contains nodes with info set. */
int
bgp_ptree_has_info (struct bgp_ptree *tree)
{
  struct bgp_node *node;

  if (tree == NULL)
    return 0;

  node = tree->top;
  while (node)
    {
      if (node->info)
        return 1;

      if (node->p_left)
        {
          node = node->p_left;
          continue;
        }

      if (node->p_right)
        {
          node = node->p_right;
          continue;
        }

      while (node->parent)
        {
          if (node->parent->p_left == node && node->parent->p_right)
            {
              node = node->parent->p_right;
              break;
            }
          node = node->parent;
        }

      if (node->parent == NULL)
        break;
    }

  return 0;
}

struct bgp_ptree *
bgp_table_init (u_int16_t afi)
{
  struct bgp_ptree * tree;

  tree = bgp_ptree_init(BGP_MAX_KEY_LEN);
  if (tree)
    {
      if (afi == BGP_IPV4_ADDR_AFI)
         tree->family = BGP_IPV4_ADDR_AFI; 
      else if(afi == BGP_IPV6_ADDR_AFI)
          tree->family = BGP_IPV6_ADDR_AFI;
      else tree->family = afi;
    }

  return tree;
}

void
bgp_table_finish (struct bgp_ptree *tree)
{
  bgp_ptree_finish (tree);
}

void
bgp_unlock_node (struct bgp_node *node)
{
   bgp_ptree_unlock_node (node);
}
void 
bgp_node_delete (struct bgp_node *node)
{
  bgp_ptree_node_delete (node);
}

struct bgp_node *
bgp_table_top (struct bgp_ptree * tree)
{
  return bgp_ptree_top (tree);
}

struct bgp_node *
bgp_route_next (struct bgp_node * node)
{
  return bgp_ptree_next (node);
}

struct bgp_node *
bgp_route_next_until (struct bgp_node * node, struct bgp_node * limit)
{
  return bgp_ptree_next_until (node, limit);
}

struct bgp_node *
bgp_node_get (struct bgp_ptree *tree, struct prefix *p)
{
  struct bgp_node *node = NULL;
  u_char key[20];
  u_int16_t key_len;
  u_int16_t octect;
  u_int8_t afi_len = 1;

  pal_mem_set(key,0,sizeof(key));

  if (tree->family == BGP_IPV4_IPV6_ADDR_AFI)
    {    
      octect = bgp_ptree_bit_to_octets (p->prefixlen + BGP_AFI_LENGTH_IN_BITS);
      key [0] = p->family;
      pal_mem_cpy ((key + afi_len),&p->u.prefix, (octect - afi_len) );
      key_len = p->prefixlen + BGP_AFI_LENGTH_IN_BITS;
    } 
  else
    if ((tree->family == BGP_IPV4_ADDR_AFI)||
       (tree->family == BGP_IPV6_ADDR_AFI))
      {
        octect = bgp_ptree_bit_to_octets (p->prefixlen);
        pal_mem_cpy (key,&p->u.prefix, octect);
        key_len = p->prefixlen;		
      }
    else
      {
         /*Searching in a wrong tree */
         return NULL;
      }

  node = bgp_ptree_node_get (tree, key, key_len);
  return node;
}

struct bgp_node *
bgp_node_lookup (struct bgp_ptree * tree, struct prefix * p)
{
  struct bgp_node * node = NULL;
  u_char key[20];
  u_int16_t key_len;
  u_int16_t octect;
  u_int8_t afi_len = 1;
  pal_mem_set (key, 0, sizeof (key));
  
  if (tree->family == BGP_IPV4_IPV6_ADDR_AFI)
    { 
      octect = bgp_ptree_bit_to_octets (p->prefixlen + BGP_AFI_LENGTH_IN_BITS);
      key [0] = p->family;
      pal_mem_cpy((key + afi_len),&p->u.prefix,(octect - afi_len) ); 
      key_len = p->prefixlen + BGP_AFI_LENGTH_IN_BITS;
     }
   else
     if((tree->family == BGP_IPV4_ADDR_AFI)||
         (tree->family == BGP_IPV6_ADDR_AFI))
        {
          octect = bgp_ptree_bit_to_octets (p->prefixlen);
          pal_mem_cpy (key, &p->u.prefix, octect); 
          key_len = p->prefixlen;
	}
      else
        {
          /*Searching in a wrong tree */
          return NULL;
        }
	
    node = bgp_ptree_node_lookup (tree, key, key_len);

  return node;
}

struct bgp_node *
bgp_lock_node (struct bgp_node *node)
{
  return bgp_ptree_lock_node (node);
}

struct bgp_node *
bgp_node_match (struct bgp_ptree * tree, struct prefix *p)
{
  struct bgp_node * node = NULL;
  u_char key [20];
  u_int16_t key_len;
  u_int16_t octect;
  u_int8_t   afi_len = 1;

  pal_mem_set (key, 0, sizeof (key));	

  if (tree->family == BGP_IPV4_IPV6_ADDR_AFI)
    { 
      key_len = p->prefixlen + BGP_AFI_LENGTH_IN_BITS;
      octect = bgp_ptree_bit_to_octets (key_len);
      key [0] = p->family;
      pal_mem_cpy ((key + afi_len),&p->u.prefix, octect - afi_len);
    }
  else 
      if ((tree->family == BGP_IPV4_ADDR_AFI)||
          (tree->family == BGP_IPV6_ADDR_AFI))
        {
          octect = bgp_ptree_bit_to_octets (p->prefixlen);
          pal_mem_cpy (key,&p->u.prefix, octect);
          key_len = p->prefixlen;
        }
      else
        {
          /*Searching in a wrong tree */
          return NULL;
      	}
	
  node = bgp_ptree_node_match (tree, key, key_len);

  return node;
}

void
bgp_ptree_get_prefix_from_node (struct bgp_node *node, struct prefix *rnp)
{
  u_int16_t octect;
  u_int8_t  afi_len = 1;
   
  pal_mem_set(rnp,0,sizeof(struct prefix));
	  
  if (node == NULL)
    return;

  if (node->tree->family == BGP_IPV4_IPV6_ADDR_AFI)
    { 
      octect = bgp_ptree_bit_to_octets (node->key_len);
      rnp->family = node->key [0];
      pal_mem_cpy (&rnp->u.prefix, &node->key [1], octect - afi_len);
      rnp->prefixlen = node->key_len - BGP_AFI_LENGTH_IN_BITS;
    }
  else
      if ((node->tree->family == BGP_IPV4_ADDR_AFI)||
          (node->tree->family == BGP_IPV6_ADDR_AFI))
        {
          octect = bgp_ptree_bit_to_octets(node->key_len);
          pal_mem_cpy(&rnp->u.prefix,&node->key[0],(octect));		
          rnp->prefixlen = node->key_len;
          if (node->tree->family == BGP_IPV4_ADDR_AFI)
            rnp->family = AF_INET;
          else
            {
              if (node->tree->family == BGP_IPV6_ADDR_AFI)
	 	rnp->family = AF_INET6;
            }
        }
      else
        {
          /*Searching in a wrong tree */
          return; 
         }
}

