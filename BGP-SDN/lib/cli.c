/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

/* New CLI parser.  */

/* New CLI parser decouple command line parser and it's execution
   mechanism.  Old CLI parser mixed connection handler VTY into CLI
   parser.  We've learned the architecture is not flexible enough.  So
   new parser concentrate only for CLI parsing.

   CLI tree maintain all of the commands.  We can have multiple CLI
   tree for different purposes.  To parse the string, we just have to
   pass the CLI tree with some parameters such as CLI mode, user
   privilege and the string to be parsed.

   CLI help strings are now defined as an array.  It used to be a
   single string.  So compiler could not share a memory for multiple
   occurrence string such as "show" or "ip".  This will save many
   memory.

   VIEW_NODE and ENABLE_MODE are merged into a single mode EXEC_MODE.
   VIEW_NODE commands is installed as privilege level 1 comand.
   ENABLE_MODE commands is installed as privilege level 15 command.
   So there is no need of installing a command into both VIEW_NODE and
   ENABLE_NODE.  A command installed as privilege level 1 is available
   to a user which has privilege level 15.

   New CLI can extend IFNAME to pre-defined interface list.  User can
   use completion mechanism for it.  Once we define interface list as
   fastEthernet <0-3>.  It will be expaneded accordingly.

   CLI parser does not have any support for callback functionality.
   New framework "show" provides call back mechanism separately.
*/

#include <pal.h>

#include "cli.h"
#include "modbmap.h"
#include "snprintf.h"

/* IFNAME token expansion definition.  ifname_expand_token is used for
   replacing IFNAME token to real keyword.  Please note that the
   keyword must be separated by | and entire string must be enclosed
   by ` and '.  So when fastEthernet <0-23> and gigibitEthernet <0-1>
   is define, it the ifname_expand_token should be like this:

   char *ifname_expand_token = "`fastEthernet <0-23>|gigibitEthernet <0-1>'";

   For each keyword, we need to define corresponding help string.  It
   is defined as array of help string.  So for above example,

   char *ifname_expand_help[] =
     {
       "FastEthernet interface",
       "FastEthernet interface index",
       "GigabitEthernet interface",
       "GigabitEthernet interface index"
     };

   When ifname_expand_token is set to NULL, IFNAME is treated as WORD
   token.  So any word will match to IFNAME.

   Here is another example for L2/L3 swtch case.

   char *ifname_expand_token = "`vlan <1-4094>|loopback'";
   char *ifname_expand_help[] =
     {
       "VLAN",
       "VID",
       "Loopback interface configuration"
     };

*/

char *ifname_expand_token = NULL;
char *ifname_expand_help[] = {NULL};

/* CLI macros.  */
#define WHITE_SPACE(C)     ((C) == ' ' || (C) == '\t' || (C) == '\n')
#define DELIMITER(C)       (WHITE_SPACE(C) || (C) == '\0')
#define COMMENT_CHAR(C)    ((C) == '!' || (C) == '#')

#define DECIMAL_STRLEN_MAX 10

#define MTYPE_CLI_TREE      MTYPE_TMP
#define MTYPE_CLI_NODE      MTYPE_TMP
#define MTYPE_CLI_ARGUMENT  MTYPE_TMP

char *
cli_skip_white_space(char *cmd_str)
{
  while (WHITE_SPACE (*cmd_str))
    cmd_str++;
  return cmd_str;
}

/* Each mode's description string.*/
const char *
cli_mode_str (int mode)
{
  switch (mode)
    {
    case EXEC_MODE:
      return "Exec";
    case CONFIG_MODE:
      return "Configure";
    case INTERFACE_MODE:
      return "Interface configuration";
    case KEYCHAIN_MODE:
      return "Key-chain configuration";
    case KEYCHAIN_KEY_MODE:
      return "Key-chain key configuration";
    case RMAP_MODE:
      return "Route Map configuration";
    case BGP_MODE:
      return "Router configuration";
      break;
    case BGP_IPV4_MODE:
    case BGP_IPV4M_MODE:
#ifdef HAVE_IPV6 /**/
    case BGP_IPV6_MODE:
#endif /*HAVE_IPV6*/
      return "Router Address Family configuration";
      break;
    case VR_MODE:
      return "Virtual-router instance configuration";
      break;
    case LINE_MODE:
    case VTY_MODE:
      return "Line configuration";
      break;
    default:
      return "";
    }
}

/* Get a token from the string.  */
char *
cli_get_token (char *str, enum cli_token *type, char **val)
{
  int i = 0;
  char *cp = str;
  static char buf[MAX_TOKEN_LENGTH];

  /* Skip white spaces.  */
  while (pal_char_isspace ((int) *cp) && *cp != '\0')
    cp++, str++;

  /* Only white spaces, return NULL.  */
  if (*cp == '\0')
    return NULL;

  /* Check special character.  */
  switch (*cp)
    {
    case '(':
      *type = cli_token_paren_open;
      return ++cp;

    case ')':
      *type = cli_token_paren_close;
      return ++cp;

    case '{':
      *type = cli_token_cbrace_open;
      return ++cp;

    case '}':
      *type = cli_token_cbrace_close;
      return ++cp;

    case '[':
      *type = cli_token_brace_open;
      return ++cp;

    case ']':
      *type = cli_token_brace_close;
      return ++cp;

    case '`':
      *type = cli_token_ifname_open;
      return ++cp;

    case '\'':
      *type = cli_token_ifname_close;
      return ++cp;

    case '|':
      /* '||' treated as keyword '|' for output modifier pipe.  */
      if (*(cp + 1) == '|')
        {
          buf[0] = '|';
          buf[1] = '\0';
          *val = buf;
          *type = cli_token_pipe;
          return (cp + 2);
        }
      else
        {
          *type = cli_token_separator;
          return ++cp;
        }

    case '>':
      *type = cli_token_redirect;
      buf[0] = '>';
      buf[1] = '\0';
      *val = buf;
      return ++cp;

    case '*':
      buf[0] = '*';
      buf[1] = '\0';
      *val = buf;
      *type = cli_token_keyword;
      return ++cp;

    case '.':
      *type = cli_token_dot;
      return ++cp;

    case '?':
      *type = cli_token_question;
      return ++cp;

    default:
      break;
    }

  /* Range value.  */
  if (*cp == '<')
    {
      while (*cp == '<' || *cp == '>' || *cp == '-' || *cp == '+' || *cp == '/'
             || pal_char_isalnum ((int)*cp))
        buf[i++] = *cp++;
      buf[i] = '\0';

      *val = buf;
      *type = cli_token_range;
      return cp;
    }

  /* Special words.  */
  if (pal_char_isupper ((int)*cp))
    {
      while (pal_char_isalnum ((int)*cp) || *cp == '.' || *cp == '/'
             || *cp == ':' || *cp == '_' || *cp == '-')
        buf[i++] = *cp++;
      buf[i] = '\0';
      *val = buf;

      if (pal_strcmp (buf, "LINE") == 0)
        *type = cli_token_line;
      else if (pal_strcmp (buf, "WORD") == 0)
        *type = cli_token_word;
      else if (pal_strcmp (buf, "IFNAME") == 0)
        *type = cli_token_ifname;
      else if (pal_strcmp (buf, "A.B.C.D") == 0)
        *type = cli_token_ipv4;
      else if (pal_strcmp (buf, "A.B.C.D/M") == 0)
        *type = cli_token_ipv4_prefix;
      else if (pal_strcmp (buf, "X:X::X:X") == 0)
        *type = cli_token_ipv6;
      else if (pal_strcmp (buf, "X:X::X:X/M") == 0)
        *type = cli_token_ipv6_prefix;
      else if (pal_strcmp (buf, "HH:MM:SS") == 0)
        *type = cli_token_time;
      else if (pal_strcmp (buf, "AA:NN") == 0)
        *type = cli_token_community;
      else if (pal_strcmp (buf, "XX:XX:XX:XX:XX:XX") == 0)
        *type = cli_token_mac_address;
      else
        *type = cli_token_word;
      return cp;
    }

  /* Keyword.  */
  if (pal_char_isalnum ((int)*cp))
    {
      while (pal_char_isalnum ((int)*cp) || *cp == '-' || *cp == '+')
        buf[i++] = *cp++;
      buf[i] = '\0';
      *val = buf;
      *type = cli_token_keyword;
      return cp;
    }

  return NULL;
}

/* Lookup cli node which has same type and string node.  */
static struct cli_node *
cli_keyword_lookup (vector current, enum cli_token type, char *str)
{
  int i, j;
  struct cli_node *n;
  struct cli_node *node;

  for (i = 0; i < vector_max (current); i++)
    if ((node = vector_slot (current, i)) != NULL)
      for (j = 0; j < vector_max (node->keywords); j++)
        if ((n = vector_slot (node->keywords, j)) != NULL)
          if (n->type == type && pal_strcmp (n->str, str) == 0)
            return n;
  return NULL;
}

/* Each mode's prompt string.  */
const char *
cli_prompt_str (int mode)
{
  switch (mode)
    {
    case LOGIN_MODE:
      return "Login:";
      break;
    case AUTH_MODE:
    case AUTH_ENABLE_MODE:
      return "Password:";
      break;
    case CONFIG_MODE:
      return "(config)";
      break;
    case INTERFACE_MODE:
      return "(config-if)";
      break;
    case KEYCHAIN_MODE:
      return "(config-keychain)";
      break;
    case KEYCHAIN_KEY_MODE:
      return "(config-keychain-key)";
      break;
    case RMAP_MODE:
      return "(config-route-map)";
      break;
    case BGP_MODE:
      return "(config-router)";
      break;
    case BGP_IPV4_MODE:
    case BGP_IPV4M_MODE:
#ifdef HAVE_IPV6 /**/
    case BGP_IPV6_MODE:
#endif /* HAVE_IPV6*/
      return "(config-router-af)";
      break;
    case VR_MODE:
      return "(config-vr)";
      break;
    case LINE_MODE:
    case VTY_MODE:
      return "(config-line)";
      break;
    default:
      return "";
      break;
    }
}

/* Allocate a new CLI tree.  */
struct cli_tree *
cli_tree_new ()
{
  struct cli_tree *ctree;

  ctree = XCALLOC (MTYPE_CLI_TREE, sizeof (struct cli_tree));
  ctree->modes = vector_init (VECTOR_MIN_SIZE);
  ctree->v = vector_init (VECTOR_MIN_SIZE);
  ctree->t = vector_init (VECTOR_MIN_SIZE);
  ctree->config_write = vector_init (VECTOR_MIN_SIZE);
  ctree->advanced = 1;
  return ctree;
}

/* Free up CLI tree.  */
void
cli_tree_free (struct cli_tree *ctree)
{
  vector_free (ctree->v);
  vector_free (ctree->t);
  vector_free (ctree->config_write);
  XFREE (MTYPE_CLI_TREE, ctree);
}

/* Show command list. */
static vector
cli_command_node_lookup_history (struct cli_node *root, struct cli_node *node)
{
  vector history;
  vector parent;
  enum cli_token type;
  char *val;
  char *str = node->cel->str;
  int skip = 0;
  struct cli_node *next = NULL;

  history = vector_init (VECTOR_MIN_SIZE);
  vector_set (history, root);
  parent = vector_init (VECTOR_MIN_SIZE);
  vector_set (parent, root);

  while ((str = cli_get_token (str, &type, &val)))
      switch (type)
      {
        case cli_token_paren_open:
        case cli_token_cbrace_open:
        case cli_token_brace_open:
        case cli_token_ifname_open:
        case cli_token_dot:
        case cli_token_question:
        case cli_token_unknown:
          break;

        case cli_token_separator:
          skip = 1;
          break;

        case cli_token_paren_close:
        case cli_token_ifname_close:
          skip = 0;
          break;

        case cli_token_cbrace_close:
        case cli_token_brace_close:
          goto ret;

        default:
          if (!skip)
            {
              next = cli_keyword_lookup (parent, type, val);
              /* Go to next node.  */
              if (next != NULL)
                {
                  vector_reset (parent);
                  vector_set (parent, next);
                  vector_set (history, next);
                }
            }
          break;
      }

ret:
  vector_free (parent);

  return history;
}

static void
cli_command_node_dump (struct cli *cli, struct cli_node *root, struct cli_node *node,
                       u_char privilege, int depth, vector parent)
{
  int i;
  struct cli_node *next;
  vector history = NULL;

  if (privilege < node->privilege)
    return;

  if (CHECK_FLAG (node->flags, CLI_FLAG_HIDDEN))
    return;

  if (node->cel)
    {
      if (node->type == cli_token_alias)
        {
          cli_out (cli, "  %s\n", node->str);
          return;
        }
      else
        {
          history = cli_command_node_lookup_history(root, node);
          if ((vector_cmp(parent, history) == 0))
            cli_out (cli, "  %s\n", node->cel->str);
          vector_free(history);
        }
    }

  if (CHECK_FLAG (node->flags, CLI_FLAG_RECURSIVE)
      || CHECK_FLAG (node->flags, CLI_FLAG_TRAVERSE))
    return;

  for (i = 0; i < vector_max (node->keywords); i++)
    if ((next = vector_slot (node->keywords, i)) != NULL)
      if (next != node)
        {
          vector_set_index(parent, depth + 1, next);
          cli_command_node_dump (cli, root, next, privilege, depth + 1, parent);
          vector_unset(parent, depth + 1);
        }
}

static void
cli_command_dump (struct cli *cli, struct cli_tree *ctree, int mode,
                  u_char privilege)
{
  struct cli_node *node;
  vector parent;

  if (mode > MAX_MODE)
    return;

  node = vector_lookup_index (ctree->modes, mode);
  if (! node)
    return;

  parent = vector_init (VECTOR_MIN_SIZE);
  vector_set (parent, node);

  cli_command_node_dump (cli, node, node, privilege, 0, parent);

  vector_free (parent);
}

/* Dispaly CLI tree structure.  */
static void
cli_tree_node_dump (struct cli *cli, struct cli_node *node, u_char privilege,
                    int depth)
{
  int i;
  struct cli_node *next;

  if (privilege < node->privilege)
    return;

  if (node->str)
    {
      if (depth == 1)
        cli_out (cli, "+-%s", node->str);
      else
        cli_out (cli, "%*s+-%s", (depth - 1) * 2, " ", node->str);
    }

  if (node->cel)
    cli_out (cli, " [%s]", node->cel->str);

  cli_out (cli, "\n");

  if (CHECK_FLAG (node->flags, CLI_FLAG_RECURSIVE)
      || CHECK_FLAG (node->flags, CLI_FLAG_TRAVERSE))
    return;

  for (i = 0; i < vector_max (node->keywords); i++)
    if ((next = vector_slot (node->keywords, i)) != NULL)
      if (next != node)
        cli_tree_node_dump (cli, next, privilege, depth + 1);
}

/* CLI tree dump function.  */
static void
cli_tree_dump (struct cli *cli, struct cli_tree *ctree, int mode,
               u_char privilege)
{
  struct cli_node *node;

  if (mode > MAX_MODE)
    return;

  node = vector_lookup_index (ctree->modes, mode);
  if (! node)
    return;

  cli_out (cli, "%s mode:", cli_mode_str (mode));

  cli_tree_node_dump (cli, node, privilege, 0);
}

/* Allocate a new CLI node. */
struct cli_node *
cli_node_new ()
{
  struct cli_node *node;

  node = XCALLOC (MTYPE_CLI_NODE, sizeof (struct cli_node));
  node->keywords = vector_init (1);

  return node;
}

void
cli_node_free (struct cli_node *node)
{
  vector_free (node->keywords);
  XFREE (MTYPE_CLI_NODE, node);
}

char *
cli_str2int (char *str, u_int32_t *val)
{
  int digit;
  u_int32_t limit, remain;
  int minus;
  u_int32_t max = UINT32_MAX;
  u_int32_t total = 0;
  char *cp = str;
  minus = 0;

  /* Sanify check. */
  if (str == NULL || val == NULL)
    return NULL;

  /* '+' and '-' check.  */
  if (*cp == '+')
    cp++;
  else if (*cp == '-')
    {
      cp++;
      minus = 1;
      max = max / 2 + 1;
    }

  limit = max / 10;
  remain = max % 10;

  /* Parse digits.  */
  while (pal_char_isdigit ((int)*cp))
    {
      digit = *cp++ - '0';

      if (total  > limit || (total == limit && digit > remain))
        return NULL;

      total = total * 10 + digit;
    }

  /* String must be terminated white space or '\0'.  */
  if (! DELIMITER (*cp))
    return NULL;

  /* Everything is ok.  */
  *val = minus ? -total : total;

  return cp;
}

#define DECIMAL_STRLEN_MIN 1
#define DECIMAL_STRLEN_MAX 10

int
cmd_str2int (char *str, int *ret)
{
  int i;
  int len;
  int digit;
  u_int32_t limit, remain;
  int minus = 0;
  u_int32_t max = UINT32_MAX;
  u_int32_t total = 0;

  /* Sanify check. */
  if (str == NULL || ret == NULL)
    return -1;

  /* First set return value as error. */
  *ret = -1;

  len = pal_strlen (str);
  if (*str == '+')
    {
      str++;
      len--;
    }
  else if (*str == '-')
    {
      str++;
      len--;
      minus = 1;
      max = max / 2 + 1;
    }

  limit = max / 10;
  remain = max % 10;

  if (len < DECIMAL_STRLEN_MIN || len > DECIMAL_STRLEN_MAX)
    return -1;

  for (i = 0; i < len; i++)
    {
      if (*str < '0' || *str > '9')
        return -1;

      digit = *str++ - '0';

      if (total  > limit || (total == limit && digit > remain))
        return -1;

      total = total * 10 + digit;
    }

  *ret = 0;
  if (minus && (total == 0))
      return -1;
  if (minus)
    return - total;
  else
    return total;
}

int
cmd_hexstr2int (char *str, int *ret)
{
  int i;
  int len;
  int digit;
  u_int32_t total = 0;
  char *pnt;

  /* Sanify check. */
  if (str == NULL || ret == NULL)
    return -1;

  /* First set return value as error. */
  *ret = -1;

  len = pal_strlen (str);
  pnt = pal_strchr (str, 'x');
  if (pnt)
    {
      str += 2; 
      len -= 2;
    }
  else 
    {
      /*Not a  hex number*/
      return -1;
    }

  if (len < DECIMAL_STRLEN_MIN || len > DECIMAL_STRLEN_MAX)
    return -1;

  for (i = 0; i < len; i++)
    {
      if (*str >= '0' && *str <= '9')
        digit = *str++ - '0';
      else if (*str >= 'A' && *str <= 'F')
        digit = *str++ - 'A' + 10;
      else if (*str >= 'a' && *str <= 'f')
        digit = *str++ - 'a' + 10;
      else
        return -1;
 
      if (total  > UINT32_MAX)
        return -1;

      total = total + (digit * pow(16,(len-(i+1))));
    }

    *ret = 0;
    return total;
}

/* Set range value.  */
void
cli_range_install (struct cli_node *node, char *range)
{
  char *p;
  char *cp;
  u_int32_t max;
  u_int32_t min;

  range++;

  p = pal_strchr (range, '-');
  if (p == NULL)
    return;

  if (p - range > DECIMAL_STRLEN_MAX)
    return;

  *p = '\0';
  cp = cli_str2int (range, &min);
  if (! cp)
    return;

  range = p + 1;

  p = pal_strchr (range, '>');
  if (p == NULL)
    return;

  if (p - range > DECIMAL_STRLEN_MAX)
    return;

  *p = '\0';
  cp = cli_str2int (range, &max);
  if (! cp)
    return;

  node->min = min;
  node->max = max;
}

void
cli_node_add (vector current, struct cli_node *next)
{
  int i;
  struct cli_node *node;

  for (i = 0; i < vector_max (current); i++)
    if ((node = vector_slot (current, i)) != NULL)
      vector_set (node->keywords, next);
}

/* Add a link to self.  */
void
cli_recursive_link (vector current, vector head, u_int16_t flag)
{
  int i;
  struct cli_node *node;

  for (i = 0; i < vector_max (head); i++)
    if ((node = vector_slot (head, i)) != NULL)
      {
        SET_FLAG (node->flags, flag);
        cli_node_add (current, node);
      }
}

void
cli_mark_link (vector current, vector head, u_int16_t flag)
{
  int i;
  struct cli_node *node;

  for (i = 0; i < vector_max (current); i++)
    if ((node = vector_slot (current, i)) != NULL)
      SET_FLAG (node->flags, CLI_FLAG_IFNAME);

  for (i = 0; i < vector_max (head); i++)
    if ((node = vector_slot (head, i)) != NULL)
      SET_FLAG (node->flags, CLI_FLAG_IFNAME);
}

void
cli_element_set (vector current, struct cli_element *cel)
{
  int i;
  struct cli_node *node;

  for (i = 0; i < vector_max (current); i++)
    if ((node = vector_slot (current, i)) != NULL)
      {
        if (node->cel)
          {
#ifdef CLI_DEBUG
            ERR ("Duplicate installation: orig %s\n", node->cel->str);
            ERR ("Duplicate installation: new  %s\n", cel->str);
#endif /* CLI_DEBUG */
          }
        node->cel = cel;
      }
}

/* Check help string exists for the node.  */
void
cli_check_help (struct cli_element *cel, int *index, int *max)
{
  char *val;
  char *str;
  enum cli_token type;
  int i;
  int h;

  i = 0;
  *index = 0;
  *max = 0;
  str = cel->str;

  while ((str = cli_get_token (str, &type, &val)))
    {
      if (type == cli_token_ifname)
        *index = i;

      switch (type)
        {
        case cli_token_paren_open:
        case cli_token_paren_close:
        case cli_token_cbrace_open:
        case cli_token_cbrace_close:
        case cli_token_brace_open:
        case cli_token_brace_close:
        case cli_token_ifname_open:
        case cli_token_ifname_close:
        case cli_token_separator:
        case cli_token_dot:
        case cli_token_question:
          break;
        case cli_token_pipe:
        case cli_token_redirect:
        case cli_token_range:
        case cli_token_keyword:
        case cli_token_alias:
        case cli_token_line:
        case cli_token_word:
        case cli_token_ipv4:
        case cli_token_ipv4_prefix:
        case cli_token_ipv6:
        case cli_token_ipv6_prefix:
        case cli_token_time:
        case cli_token_community:
        case cli_token_mac_address:
        case cli_token_ifname:
        case cli_token_unknown:
          i++;
        }
    }

  h = 0;
  while (cel->help[h])
    h++;

  *max = h;

#ifdef CLI_DEBUG
  if (i > h)
    {
      ERR ("help is missing %s\n", cel->str);
      ERR ("token is %d help is %d\n", i, h);
    }
  if (i < h)
    {
      ERR ("help mismatch for: %s\n", cel->str);
      ERR ("token is %d help is %d\n", i, h);
    }
#endif /* CLI_DEBUG */
}

/* CLI builder.  Internal use only.  */
struct cli_builder
{
  /* Current pointer of the string.  */
  char *str;

  /* Current help index.  */
  int index;
};

/* Build CLI parser tree.  */
int
cli_build (vector parent, vector head, vector tail, struct cli_builder *cb,
           struct cli_element *cel, u_char privilege, int depth)
{
#ifdef CLI_DEBUG
  int len = 0;
#endif /* CLI_DEBUG */
  int dot = 0;
  int question = 0;
  int headline = 1;
  char *val;
  enum cli_token type;
  struct cli_node *node = NULL;

  /* Get token. */
  while ((cb->str = cli_get_token (cb->str, &type, &val)))
    switch (type)
      {
      case cli_token_paren_open:
      case cli_token_cbrace_open:
      case cli_token_brace_open:
      case cli_token_ifname_open:
        {
          /* Parent for each members.  */
          vector p = vector_init (VECTOR_MIN_SIZE);
          vector h = vector_init (VECTOR_MIN_SIZE);
          vector t = vector_init (VECTOR_MIN_SIZE);

          while (type != cli_token_paren_close
                 && type != cli_token_cbrace_close
                 && type != cli_token_brace_close
                 && type != cli_token_ifname_close)
            {
              vector_dup (p, parent);
              type = cli_build (p, h, t, cb, cel, privilege, depth + 1);
            }

          /* In case of brace.  */
          if (type == cli_token_cbrace_close)
            cli_recursive_link (t, h, CLI_FLAG_TRAVERSE);
          else if (type == cli_token_brace_close)
            cli_recursive_link (t, h, CLI_FLAG_RECURSIVE);

          /* Mark ifname flag.  */
          if (type == cli_token_ifname_close)
            cli_mark_link (t, h, CLI_FLAG_IFNAME);

          /* Reset parent. */
          vector_dup (parent, t);

          /* Free temporary member.  */
          vector_free (p);
          vector_free (h);
          vector_free (t);
        }
        break;

      case cli_token_separator:
      case cli_token_paren_close:
      case cli_token_cbrace_close:
      case cli_token_brace_close:
      case cli_token_ifname_close:
        /* Add current node to tail.  */
        if (tail)
          vector_add (tail, parent);
        return type;

      case cli_token_dot:
        /* After '.' the token match to more than once user input.  */
        dot = 1;
        break;

      case cli_token_question:
        /* After '?' is marked as traverse node.  */
        question = 1;
        break;

      case cli_token_unknown:
        /* Unknown token.  */
#ifdef CLI_DEBUG
        ERR ("Unknown token found %s\n", cb->str);
#endif /* CLI_DEBUG */
        return -1;

      default:
        /* Lookup node.  */
        node = cli_keyword_lookup (parent, type, val);

        /* Create a new node.  */
        if (! node)
          {
            node = cli_node_new ();
            node->type = type;
            node->str = XSTRDUP (MTYPE_TMP, val);

            if (cel->help)
              {
                if (cel->help[cb->index])
                  {
#ifdef CLI_DEBUG
                    len = pal_strlen (cel->help[cb->index]);
                    if (cel->help[cb->index][len - 1] == '\n')
                      ERR ("No need of new line %s\n", cel->str);
#endif /* CLI_DEBUG */
                  }
                node->help = cel->help[cb->index];
              }

            if (depth)
              SET_FLAG (node->flags, CLI_FLAG_PAREN);

            if (type == cli_token_range)
              cli_range_install (node,val);

            /* Register to current node vector.  */
            cli_node_add (parent, node);
          }

        /* Increase help string index.  */
        cb->index++;

        /* Update privilege. */
        if (! node->refcnt || privilege < node->privilege)
          node->privilege = privilege;

        /* Hidden flag.  */
        if (CHECK_FLAG (cel->flags, CLI_FLAG_HIDDEN))
          {
            if (! node->refcnt)
              SET_FLAG (node->flags, CLI_FLAG_HIDDEN);
          }
        else
          UNSET_FLAG (node->flags, CLI_FLAG_HIDDEN);

        /* Increment reference count.  */
        node->refcnt++;

        /* Update headline.  */
        if (headline && head)
          {
            vector_set (head, node);
            headline = 0;
          }

        /* Go to next node.  */
        vector_reset (parent);
        vector_set (parent, node);

        /* When dot is specified, put self link to the node.  */
        if (dot)
          {
            cli_node_add (parent, node);
            dot = 0;
          }

        if (question)
          {
            SET_FLAG (node->flags, CLI_FLAG_TRAVERSE);
            question = 1;
          }
      }

  /* Parse is done.  Put entry to the CLI node.  */
  cli_element_set (parent, cel);

  return 0;
}

/* Replace IFNAME token and related help strings.  */
void
cli_ifname_reflect (struct cli_element *cel, int index, int max)
{
  /* Interface name expantion data.  */

  char *sp, *cp;
  char *str;
  int len, ifname_len;
  char **help;
  int help_len;
  int i;
  int remain;

  /* Find IFNAME.  */
  cp = pal_strstr (cel->str, "IFNAME");

  /* When there is no IFNAME in string just return.  */
  if (! cp)
    return;

  /* Start replacement.  */
  len = pal_strlen (cel->str);
  ifname_len = pal_strlen (ifname_expand_token);

  len -= pal_strlen ("IFNAME");
  len += ifname_len;
  sp = str = XMALLOC (MTYPE_TMP, len + 1);

  /* Copy before IFNAME. */
  pal_mem_cpy (str, cel->str, cp - cel->str);

  /* Replace IFNAME.  */
  str += (cp - cel->str);
  pal_mem_cpy (str, ifname_expand_token, ifname_len);

  /* Copy remaing str.  */
  str += ifname_len;
  if (len > str - sp)
    {
      pal_mem_cpy (str, cp + pal_strlen ("IFNAME"), len - (str - sp));
      str += (len - (str - sp));
    }

  /* Put termination null.  */
  *str = '\0';

  /* Replace the string.  */
  cel->str = sp;

  /* Help string treatment.  */
  help_len = sizeof ifname_expand_help / sizeof (char *);
  help = XMALLOC (MTYPE_TMP, sizeof (char *) * (max + help_len));

  /* Copy initial string.  */
  for (i = 0; i < index; i++)
    help[i] = cel->help[i];

  for (i = 0; i < help_len; i++)
    help[index + i] = ifname_expand_help[i];

  remain = max - index - 1;

  for (i = 0; i < remain; i++)
    help[index + help_len + i] = cel->help[index + 1 + i];

  help[index + help_len + i] = NULL;
  cel->help = help;
}

/* Generic CLI Installation. */
int
cli_install_gen (struct cli_tree *ctree, int mode,
                 u_char privilege, u_int16_t flags, struct cli_element *cel)
{
  struct cli_builder cb;
  struct cli_node *node;
  vector parent;
  int index, max;

  /* Set flags. */
  if (flags)
    SET_FLAG (cel->flags, flags);

  /* Check help string is there.  */
  cli_check_help (cel, &index, &max);

  if (mode > MAX_MODE)
    return -1;

  /* Lookup root node.  */
  node = vector_lookup_index (ctree->modes, mode);

  /* Install a new root node.  */
  if (! node)
    {
      node = cli_node_new ();
      vector_set_index (ctree->modes, mode, node);
    }

  /* Update IFNAME token and help string.  */
  if (ifname_expand_token)
    cli_ifname_reflect (cel, index, max);

  /* Set initial value before calling cli_build().  */
  parent = vector_init (VECTOR_MIN_SIZE);
  vector_set (parent, node);
  cb.str = cel->str;
  cb.index = 0;

  cli_build (parent, NULL, NULL, &cb, cel, privilege, 0);

  vector_free (parent);

  return 0;
}

/* Compatible function for non-VR-supported protocols. */
int
cli_install (struct cli_tree *ctree, int mode,
             struct cli_element *cel)
{
  u_char privilege = PRIVILEGE_NORMAL;

  if (mode == EXEC_PRIV_MODE)
    {
      mode = EXEC_MODE;
      privilege = PRIVILEGE_MAX;
    }

  return cli_install_gen (ctree, mode, privilege, 0, cel);
}

/* Compatible function for non-VR-supported protocols. */
int
cli_install_hidden (struct cli_tree *ctree, int mode,
                    struct cli_element *cel)
{
  u_char privilege = PRIVILEGE_NORMAL;

  if (mode == EXEC_PRIV_MODE)
    {
      mode = EXEC_MODE;
      privilege = PRIVILEGE_MAX;
    }

  return cli_install_gen (ctree, mode, privilege, CLI_FLAG_HIDDEN, cel);
}

/* Install daemon CLI command. */
int
cli_install_imi (struct cli_tree *ctree,
                 int mode,
                 modbmap_t module,
                 u_char privilege,
                 u_int16_t flags,
                 struct cli_element *cel)
{
  cel->module = modbmap_vor (2, &PM_IMI, &module);
  cel->new_mode  = MAX_MODE;      /* This is not a mode change command */
  cel->data_type = CFG_DTYP_MAX;
  return cli_install_gen (ctree, mode, privilege, flags, cel);
}


/* Install IMI command.
   This is used to set additional info that is used by IMI:
   - command exit config mode
   - command data type
*/
void
cli_set_imi_cmd (struct cli_element *cel,
                 int           new_mode,
                 cfgDataType_e data_type)
{
  cel->new_mode  = new_mode;
  cel->data_type = data_type;
}

/* Short command such as *s=show, *p=ping installation.  This function
   assumes target node is already installed.  */
void
cli_install_shortcut (struct cli_tree *ctree, int mode,
                      char *desc_str, char *short_str, char *str)
{
  int i;
  struct cli_node *parent;
  struct cli_node *node;
  struct cli_node *shortcut;

  if (mode == EXEC_PRIV_MODE)
    {
      mode = EXEC_MODE;
    }

  /* Lookup root node.  */
  parent = vector_lookup_index (ctree->modes, mode);

  /* Lookup corresponding node.  */
  node = NULL;
  for (i = 0; i < vector_max (parent->keywords); i++)
    if ((node = vector_slot (parent->keywords, i)) != NULL)
      if (node->type == cli_token_keyword && pal_strcmp (node->str, str) == 0)
        break;

  /* Target node is found.  */
  if (node)
    {
      shortcut = XCALLOC (MTYPE_CLI_NODE, sizeof (struct cli_node));
      shortcut->keywords = node->keywords;
      shortcut->cel = node->cel;
      shortcut->type = cli_token_alias;
      shortcut->str = short_str;
      shortcut->help = desc_str;
      vector_set (parent->keywords, shortcut);
    }
}

/* Register */
int
cli_install_config (struct cli_tree *ctree, int mode, CLI_CONFIG_FUNC func)
{
  if (mode > MAX_MODE)
    return -1;

  vector_set_index (ctree->config_write, mode, (void *)func);

  return 0;
}


/* CLI utility functions. */
/* Check if mask is contiguous. */
int
cli_mask_check (struct pal_in4_addr mask)
{
  u_int32_t val;
  int count = 0;
  int bit;
  int i;

  val = pal_ntoh32 (mask.s_addr);
  bit = val & (1 >> 0);
  if (bit)
    count++;

  for (i = 1; i < IPV4_MAX_BITLEN; i++)
    if (((val >> i) & 1) != bit)
      {
        if (count > 0)
          return 0;

        bit = (val >> i) & 1;
        count++;
      }

  return 1;
}


/* User input string match type.  */
enum match_type
  {
    none_match,
    incomplete_match,
    line_match,
    word_match,
#ifdef HAVE_IPV6
    ipv6_prefix_match,
    ipv6_match,
#endif /* HAVE_IPV6 */
    ipv4_prefix_match,
    ipv4_match,
    time_match,
    community_match,
    range_match,
    mac_match,
    partial_match,
    exact_match,
  };

/* String match routine.
   For "hidden" tokens it can only return none_match or exact_match.
   For "non-hidden" tokens it can also return partial_match.
   Consistently, with the above it must return the string pointer.
*/

char *
cli_str_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *p = node->str;
  char *beg_p = cp;

  while (! DELIMITER (*cp) && ! DELIMITER (*p)
         && pal_char_tolower ((int)*p) == pal_char_tolower ((int)*cp))
    p++, cp++;

  /* If hidden command token, return "none_match" and beg_p. */
  if (CHECK_FLAG(node->flags, CLI_FLAG_HIDDEN))
    {
      if (DELIMITER (*cp) && DELIMITER (*p))
        {
          *type = exact_match;
          return cp;
        }
      else
        {
          *type = none_match;
          return beg_p;
        }
    }
  if (! DELIMITER (*cp))
    {
      *type = none_match;
      return cp;
    }

  if (! DELIMITER (*p))
    *type = partial_match;
  else
    *type = exact_match;

  return cp;
}

char *
cli_pipe_match (char *cp, struct cli_node *node, enum match_type *type)
{
  if (*cp == '|')
    {
      *type = exact_match;
      return ++cp;
    }
  else
    {
      *type = none_match;
      return cp;
    }
}

char *
cli_redirect_match (char *cp, struct cli_node *node, enum match_type *type)
{
  if (*cp == '>')
    {
      *type = exact_match;
      return ++cp;
    }
  else
    {
      *type = none_match;
      return cp;
    }
}

/* LINE match routine.  LINE matches to the end of the line.  */
char *
cli_line_match (char *cp, enum match_type *type)
{
  if (*cp == '\0')
    *type = none_match;

  while (*cp != '\0')
    cp++;

  *type = line_match;

  return cp;
}

/* WORD match routine.  WORD matches the word.  */
char *
cli_word_match (char *cp, enum match_type *type)
{
  int quote = 0;
  int backslash = 0;

  if (*cp == '\0')
    *type = none_match;

  while (*cp != '\0')
    {
      if (backslash)
        backslash = 0;
      else
        {
          if (*cp == '\\')
            backslash = 1;
          else
            if (quote)
              {
                if (*cp == '"')
                  quote = 0;
              }
            else
              {
                if (*cp == '"')
                  quote = 1;
                else if (DELIMITER(*cp))
                  break;
              }
        }
      cp++;
    }
  *type = word_match;
  return cp;
}

char *
cli_range_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *sp;
  int minus;
  u_int32_t digit = 0;

  /* Sanify check. */
  if (! cp || ! type)
    return NULL;

  /* Set none match.  */
  *type = none_match;

  /* Remember the starting point.  */
  sp = cp;

  /* Convert the string to digit.  */
  cp = cli_str2int (cp, &digit);
  if (cp == NULL)
    return sp;

 if ((node->cel) && CHECK_FLAG (node->cel->flags, CLI_PLUS_SIGN_FORBIDDEN) && pal_strchr(sp, '+'))
   return sp;

  /* Check the range.  */
  if (*sp == '-')
    {
      minus = digit;
      if ((node->min != 0 || node->max != 0)
          && ((node->min > 0 || minus < (int) node->min)
              || (minus > (int) node->max)))
        return sp;
    }
  else
    if (digit < node->min || digit > node->max)
      return sp;

  /* String must be terminated white space or '\0'.  */
  if (! DELIMITER (*cp))
    return sp;

  /* Everything is ok.  */
  *type = range_match;

  return cp;
}

/* IPv4 address match routine.  When the address is valid but
   incomplete return incomplete match.  */
char *
cli_ipv4_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *sp;
  int dots = 0;
  int nums = 0;
  char buf[4];
  *type = none_match;

  for (;;)
  {
    sp = cp;

    /* Find the next dot - check the number is OK. */
    while (! DELIMITER (*cp))
    {
      if (*cp == '.')
      {
        if (dots >= 3) {
          return cp;
        }
        dots++;
        break;
      }
      if (! pal_char_isdigit ((int) *cp)) {
        return cp;
      }
      cp++;
    }
    /* Check the length of the number is OK - convert. */
    if (cp - sp > 3) {
      return sp;
    }
    else if (cp-sp == 0) { /* A dot at the beginning or an empty string */
      return cp;
    }
    else { /* Convert the number. */
      pal_mem_set (buf, 0, sizeof (buf));
      pal_strncpy (buf, sp, cp - sp);
      if (pal_strtos32 (buf, NULL, 10) > 255) {
        return sp;
      }
      nums++;
    }
    if (DELIMITER (*cp)) {
      break;
    }
    cp++; /* skip the dot */
  }
  if (nums < 4) {
    *type = incomplete_match;
    return cp;
  }
  *type = ipv4_match;
  return cp;
}

char *
cli_ipv4_prefix_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *p;
  char *sp;

  *type = none_match;

  /* Check the string includes '/'.  */
  p = pal_strchr (cp, '/');

  /* This is partial input.  */
  if (! p)
    {
      /* IPv4 address match.  */
      cp = cli_ipv4_match (cp, node, type);

      /* When return value is NULL.  */
      if (*type == none_match)
        return cp;
      else
        {
          /* It is incomplete match.  */
          *type = incomplete_match;
          return cp;
        }
    }

  /* '/' is in the string.  Perform matching to IPv4 address part.  */
  *p = ' ';
  cp = cli_ipv4_match (cp, node, type);
  *p = '/';

  /* IPv4 part must be complete address.  */
  if (! cp)
    return NULL;

  if (*type != ipv4_match)
    return cp;

  /* Check mask length.  */
  cp = p + 1;

  if (DELIMITER (*cp))
    {
      *type = incomplete_match;
      return cp;
    }

  sp = cp;
  while (! DELIMITER (*cp))
    {
      if (! pal_char_isdigit ((int) *cp))
        {
          *type = none_match;
          return cp;
        }
      cp++;
    }

    if (pal_strtos32 (sp, NULL, 10) > 32)
      {
        *type = none_match;
        return cp;
      }

  *type = ipv4_prefix_match;
  return cp;
}

char *
cli_time_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *sp;
  int colons = 0;
  int nums = 0;
  char buf[4];

  *type = none_match;

  for (;;)
    {
      pal_mem_set (buf, 0, sizeof (buf));
      sp = cp;
      while (! DELIMITER (*cp))
        {
          if (*cp == ':')
            {
              if (colons >= 2)
                return NULL;

              if (*(cp + 1) == ':')
                return NULL;

              colons++;
              break;
            }
          if (! pal_char_isdigit ((int) *cp))
            return NULL;

          cp++;
        }

      if (cp - sp > 2)
        return NULL;

      if (cp - sp)
        {
          pal_strncpy (buf, sp, cp - sp);

          if (colons == 0)
            {
              if (pal_strtou32 (buf, NULL, 10) > 12)
                return NULL;
            }
          else
            {
              if (pal_strtou32 (buf, NULL, 10) > 60)
                return NULL;
            }

          nums++;
        }

      if (DELIMITER (*cp))
        break;

      cp++;
    }

  if (nums < 3)
    {
      *type = incomplete_match;
      return cp;
    }

  *type = time_match;
  return cp;
}

char *
cli_community_match (char *cp, struct cli_node *node, enum match_type *type)
{
  *type = none_match;
  return cp;
}

/* Ethernet MAC address match function.  */
char *
cli_mac_address_match (char *cp, enum match_type *type)
{
  char *sp;
  int dots = 0;
  int nums = 0;
  *type = none_match;

  sp = cp;

  /* Loop until we see delimiter.  */
  while (! DELIMITER (*cp))
    {
      if (*cp == ':')
        {
          if (nums == 0)
            return cp;

          if (dots >= 5)
            return cp;

          if (*(cp + 1) == ':')
            return cp + 1;

          dots++;
          cp++;
          sp = cp;
        }
      else
        {
          /* If the character is not alnum, return.  */
          if (! pal_char_isalnum ((int) *cp))
            return cp;

          /* If the character orrur more than two, it it error.  */
          if (cp - sp >= 2)
            return cp;

          /* Increment the character pointer.  */
          nums++;
          cp++;
        }
    }

  /* Matched, check this is exact match or not.  */
  if (dots != 5 || nums != 12)
    *type = incomplete_match;
  else
    *type = mac_match;

  return cp;
}

#ifdef HAVE_IPV6
#define CLI_INET6_BUFSIZ        51

char *
cli_ipv6_match (char *cp, struct cli_node *node, enum match_type *type)
{
  struct pal_in6_addr addr;
  char buf[CLI_INET6_BUFSIZ + 1];
  size_t len;
  int ret;
  *type = none_match;

  /* Delimiter check.  */
  if (DELIMITER (*cp))
    return NULL;

  /* Character check.  */
  len = pal_strspn (cp, "0123456789abcdefABCDEF:.%");

  if (! DELIMITER (cp[len]))
    return NULL;

  if (len > CLI_INET6_BUFSIZ)
    return NULL;

  pal_mem_cpy (buf, cp, len);
  buf[len] = '\0';

  ret = pal_inet_pton (AF_INET6, buf, &addr);
  if (! ret)
    *type = incomplete_match;
  else
    *type = ipv6_match;

  return cp + len;
}

char *
cli_ipv6_prefix_match (char *cp, struct cli_node *node, enum match_type *type)
{
  char *p;
  char *sp;
  *type = none_match;

  /* Check the string includes '/'.  */
  p = pal_strchr (cp, '/');

  /* This is partial input.  */
  if (! p)
    {
      /* IPv4 address match.  */
      cp = cli_ipv6_match (cp, node, type);

      /* When return value is NULL.  */
      if (*type == none_match)
        return cp;
      else
        {
          /* It is incomplete match.  */
          *type = incomplete_match;
          return cp;
        }
    }

  /* '/' is in the string.  Perform matching to IPv4 address part.  */
  *p = ' ';
  cp = cli_ipv6_match (cp, node, type);
  *p = '/';

  /* IPv4 part must be complete address.  */
  if (! cp || *type != ipv6_match)
    return NULL;

  /* Check mask length.  */
  cp = p + 1;

  if (DELIMITER (*cp))
    {
      *type = incomplete_match;
      return cp;
    }

  sp = cp;
  while (! DELIMITER (*cp))
    {
      if (! pal_char_isdigit ((int) *cp))
        {
          *type = none_match;
          return NULL;
        }
      cp++;
    }

  if (pal_strtos32 (sp, NULL, 10) > 128)
    {
      *type = none_match;
      return cp;
    }

  *type = ipv6_prefix_match;
  return cp;
}
#endif /* HAVE_IPV6 */

/* Utility routine to set CLI argument.  */
int
cli_set_arg (struct cli_tree *ctree, char *cp, int len, int merge)
{
  char *p;

  if (ctree->argc >= CLI_ARGC_MAX)
    return -1;

  if (len > CLI_ARGV_MAX_LEN)
    return -1;

  if (merge && ctree->rem)
    {
      int old_len;

      old_len = pal_strlen (ctree->rem);
      p = XREALLOC (MTYPE_CLI_ARGUMENT, ctree->rem, old_len + len + 2);
      p[old_len] = ' ';
      pal_mem_cpy (p + old_len + 1, cp, len);
      p[old_len + 1 + len] = '\0';
      ctree->argv[ctree->argc - 1] = p;
      ctree->rem = p;

      return 0;
    }

  p = XMALLOC (MTYPE_CLI_ARGUMENT, len + 1);
  pal_mem_cpy (p, cp, len);
  p[len] = '\0';

  if (merge)
    ctree->rem = p;
  else
    ctree->rem = NULL;

  ctree->argv[ctree->argc] = p;
  ctree->argc++;

  return 0;
}

/* Utility routine to set CLI modifier argument.  */
int
cli_set_modifier_arg (struct cli_tree *ctree, char *cp, int len)
{
  char *p;

  if (ctree->argc >= CLI_ARGC_MAX)
    return -1;

  if (len > CLI_ARGV_MAX_LEN)
    return -1;

  p = XMALLOC (MTYPE_CLI_ARGUMENT, len + 1);
  pal_mem_cpy (p, cp, len);
  p[len] = '\0';

  ctree->argv_modifier[ctree->argc_modifier] = p;
  ctree->argc_modifier++;

  return 0;
}

int
vector_lookup_value (vector v, void *val)
{
  int i;

  for (i = 0; i < v->max; i++)
    if (v->index[i] == val)
      return 1;
  return 0;
}
#ifdef HAVE_IPV6
int
vector_lookup_ipv4token (vector v)
{
  int i;
  struct cli_node *tn = NULL;

  for (i = 0; i < v->max; i++)
    {
      tn = (struct cli_node*)v->index[i];
      if (tn &&
          ((tn->type == cli_token_ipv4) ||(tn->type == cli_token_ipv4_prefix)))
        return 1;
    }
  return 0;
}
#endif

/* Parse CLI tree recursively.  exec must be set to 1 for parse
   command for execution.  Depth must be 0.  */
int
cli_parse_command (struct cli_tree *ctree, struct cli_node *node, char *cp,
                   int exec, int depth)
{
  int i;
  char *tp;
  char *np;
  struct cli_node *tn, *nn;
  enum match_type current;
  enum match_type match;
  int count;

  /* Reset values.  */
  count = 0;
  tp = np = NULL;
  tn = nn = NULL;
  current = none_match;
  vector_reset (ctree->v);

  /* Skip white spaces.  */
  while (WHITE_SPACE (*cp))
    cp++;

  /* Check this is empty line or not.  */
  if (depth == 0)
    {
      /* Skip comments.  */
      if (COMMENT_CHAR (*cp))
        while (*++cp != '\0')
          ;

      if (*cp == '\0')
        return CLI_PARSE_EMPTY_LINE;

      /* Reset argc.  */
      if (ctree->mode != MODIFIER_MODE)
        ctree->argc = 0;
      ctree->argc_modifier = 0;

      /* Reset show flag.  */
      ctree->show_node = 0;

      /* Reset invalid pointer.  */
      ctree->invalid = NULL;

      /* Reset traverse nodes.  */
      vector_reset (ctree->t);
    }

  /* To go to next node, we have to pick up one node.  */
  for (i = 0; i < vector_max (node->keywords); i++)
    if ((tn = vector_slot (node->keywords, i)) != NULL)
      {
        /* Update invalid pointer to current pointer only if we found a node
         * that is not hidden.
         */
        if (! CHECK_FLAG(tn->flags, CLI_FLAG_HIDDEN))
          if (cp > ctree->invalid)
            ctree->invalid = cp;

        /* Check the privilege level.  */
        if (ctree->privilege < tn->privilege)
          continue;

        if (CHECK_FLAG (tn->flags, CLI_FLAG_TRAVERSE)
            && vector_lookup_value (ctree->t, tn))
          continue;

        if (! exec && CHECK_FLAG (tn->flags, CLI_FLAG_HIDDEN))
          continue;

        if ((pal_strchr(cp, '0')) && (pal_strcmp(tn->str, "<+/-metric>") == 0))
          continue;

        /* Check current nodes.  */
        switch (tn->type)
          {
          case cli_token_keyword:
          case cli_token_alias:
            tp = cli_str_match (cp, tn, &match);
            break;

          case cli_token_pipe:
            tp = cli_pipe_match (cp, tn, &match);
            break;

          case cli_token_redirect:
            tp = cli_redirect_match (cp, tn, &match);
            break;

          case cli_token_line:
            tp = cli_line_match (cp, &match);
            break;

          case cli_token_word:
          case cli_token_ifname:
            tp = cli_word_match (cp, &match);
            break;

          case cli_token_range:
            tp = cli_range_match (cp, tn, &match);
            break;

          case cli_token_ipv4:
            tp = cli_ipv4_match (cp, tn, &match);
            break;

          case cli_token_ipv4_prefix:
            tp = cli_ipv4_prefix_match (cp, tn, &match);
            break;

          case cli_token_time:
            tp = cli_time_match (cp, tn, &match);
            break;

          case cli_token_community:
            tp = cli_word_match (cp, &match);
            break;

          case cli_token_mac_address:
            tp = cli_mac_address_match (cp, &match);
            break;

#ifdef HAVE_IPV6
          case cli_token_ipv6:
            tp = cli_ipv6_match (cp, tn, &match);
            break;

          case cli_token_ipv6_prefix:
            tp = cli_ipv6_prefix_match (cp, tn, &match);
            break;
#endif /* HAVE_IPV6 */

          default:
            match = none_match;
            break;
          }

        /* No match.  */
        if (match == none_match && !CHECK_FLAG(tn->flags, CLI_FLAG_HIDDEN))
          {
            if (tp > ctree->invalid)
              ctree->invalid = tp;
            continue;
          }
#ifdef HAVE_IPV6
        if (!exec)
          {
            if (pal_strstr(cp,".") &&
                ((tn->type == cli_token_ipv6) ||
                 (tn->type == cli_token_ipv6_prefix)))
              {
                if (!vector_lookup_ipv4token(ctree->v))
                  vector_set (ctree->v, tn);
              }
            else
              vector_set (ctree->v, tn);
          }
#else

        /* Put the node to the candidate vector.  */
        if (! exec)
          vector_set (ctree->v, tn);
#endif
        /* Better match is found.  */
        if (match > current)
          {
            if (tp > ctree->invalid && !CHECK_FLAG(tn->flags, CLI_FLAG_HIDDEN))
              ctree->invalid = tp;

            current = match;
            count = 1;
            np = tp;
            nn = tn;
          }
        /* Same style match.  */
        else if (match == current)
          count++;
      }

  /* No match.  */
  if (count == 0 || ! np)
    return CLI_PARSE_NO_MATCH;
  else
    {
      /* Set argc and argv.  */
      if (exec)
        {
          int arg_set = 0;
          int merge = 0;

          if (current == incomplete_match)
            return CLI_PARSE_NO_MATCH;

          if (CHECK_FLAG (nn->flags, CLI_FLAG_IFNAME))
            merge = 1;

          if ((CHECK_FLAG (nn->flags, CLI_FLAG_PAREN)
               || CHECK_FLAG (nn->flags, CLI_FLAG_IFNAME))
              && nn->type == cli_token_keyword)
            {
              /* Argument length check.  */
              if (pal_strlen (nn->str) > CLI_ARGV_MAX_LEN)
                return CLI_PARSE_ARGV_TOO_LONG;

              /* Modifier argument is treated separately.  */
              if (ctree->mode == MODIFIER_MODE)
                arg_set = cli_set_modifier_arg (ctree, nn->str,
                                                pal_strlen (nn->str));
              else
                arg_set = cli_set_arg (ctree, nn->str, pal_strlen (nn->str),
                                       merge);
            }
          else if (current == line_match
                   || current == word_match
                   || current == range_match
                   || current == ipv4_match
                   || current == mac_match
                   || current == ipv4_prefix_match
#ifdef HAVE_IPV6
                   || current == ipv6_match
                   || current == ipv6_prefix_match
#endif /* HAVE_IPV6 */
                   || current == time_match
                   || current == community_match
                   )
            {
              /* Argument length check.  */
              if ((np - cp) > CLI_ARGV_MAX_LEN)
                return CLI_PARSE_ARGV_TOO_LONG;

              /* Modifier argument is treated separately.  */
              if (ctree->mode == MODIFIER_MODE)
                arg_set = cli_set_modifier_arg (ctree, cp, np - cp);
              else
                arg_set = cli_set_arg (ctree, cp, np - cp, merge);
            }

          if (arg_set < 0)
            return CLI_PARSE_NO_MATCH;
        }

      /* Skip trailing white spaces.  */
      cp = np;
      while (WHITE_SPACE (*cp))
        cp++;

      /* Set to 1 when trainig space is skipped.  Help description
         output behavior is different.  */
      if (cp != np)
        {
          /* When this is incomplete match, we should return error at
             here.  */
          if (current == incomplete_match)
            return CLI_PARSE_NO_MATCH;

          ctree->expand_node = 1;
        }
      else
        ctree->expand_node = 0;

      /* Too many matches.  */
      if (count > 1)
        return CLI_PARSE_AMBIGUOUS;

      /* Show flag check.  */
      if (CHECK_FLAG (nn->flags, CLI_FLAG_SHOW))
        ctree->show_node = 1;

      /* Put this node to traverse node.  */
      if (CHECK_FLAG (nn->flags, CLI_FLAG_TRAVERSE))
        {
          if (ctree->expand_node)
            vector_set (ctree->t, nn);
        }

      /* Matching is done.  This is the last node.  */
      if (*cp == '\0')
        {
          if (ctree->mode == MODIFIER_MODE)
            ctree->modifier_node = nn;
          else
            ctree->exec_node = nn;

          if (nn->cel && current != incomplete_match)
            return CLI_PARSE_SUCCESS;
          else
            return CLI_PARSE_INCOMPLETE;
        }
    }

  return cli_parse_command (ctree, nn, cp, exec, ++depth);
}

/* Check pipe and redirection.  */
static char *
cli_parse_pipe (char *cp)
{
  int quote = 0;
  int backslash = 0;

  while (*cp != '\0')
    {
      if (backslash)
        backslash = 0;
      else
        {
          if (*cp == '\\')
            backslash = 1;
          else
            {
              if (quote)
                {
                  if (*cp == '"')
                    quote = 0;
                }
              else
                {
                  if (*cp == '"')
                    quote = 1;
                  else if (*cp == '|'
#ifndef HAVE_NO_LOCAL_FILESYSTEM
                           || *cp == '>'
#endif /* HAVE_NO_LOCAL_FILESYSTEM */
                           )
                    return cp;
                }
            }
        }
      cp++;
    }
  return NULL;
}

/* CLI parser.  */
int
cli_parse (struct cli_tree *ctree, int mode, u_char privilege, char *cp,
           int exec, int depth)
{
  int ret;
  char *pipe;
  char delimiter;
  struct cli_node *node;

  /* Set privilege.  */
  ctree->privilege = privilege;

  /* Clear pointer.  */
  ctree->exec_node = NULL;
  ctree->modifier_node = NULL;
  ctree->rem = NULL;
  ctree->pipe = NULL;

  /* Lookup mode.  */
  if (mode > MAX_MODE)
    return CLI_PARSE_NO_MODE;

  node = vector_lookup_index (ctree->modes, mode);
  if (! node)
    return CLI_PARSE_NO_MODE;

  /* Skip white spaces.  */
  while (WHITE_SPACE (*cp))
    cp++;

  /* Pipe handling check.  */
  if ((mode == EXEC_MODE || *cp == 's' || *cp == 'S')
      && (pipe = cli_parse_pipe (cp)))
    {
      delimiter = *pipe;
      *pipe = '\0';

      /* Parse command before the pipe.  */
      ret = cli_parse_command (ctree, node, cp, exec, depth);

      /* In case of ambiguous, error string should before the
         pipe.  */
      if (ret == CLI_PARSE_AMBIGUOUS)
        return ret;

      /* Restore pipe.  */
      *pipe = delimiter;

      /* If the parse failed, we should stop at here.  */
      if (ret != CLI_PARSE_SUCCESS)
        {
          /* When there is a incomplete match, we should return
             CLI_PARSE_INCOMPLETE_PIPE.  */
          if (ret == CLI_PARSE_INCOMPLETE)
            ret = CLI_PARSE_INCOMPLETE_PIPE;
          return ret;
        }

      /* The command must be show command.  */
      if (! ctree->show_node)
        return CLI_PARSE_NO_MATCH;

      /* Lookup corresponding node.  */
      node = vector_lookup_index (ctree->modes, MODIFIER_MODE);
      if (! node)
        {
#ifdef CLI_DEBUG
          ERR ("%% Mode is not configured\n");
#endif /* CLI_DEBUG */
          return CLI_PARSE_NO_MATCH;
        }

      /* Parse output modifier.  */
      ctree->mode = MODIFIER_MODE;
      ret = cli_parse_command (ctree, node, pipe, exec, depth);
      ctree->mode = EXEC_MODE;

      /* This is show_node.  */
      ctree->show_node = 1;

      /* Set pipe pointer.  */
      ctree->pipe = pipe;

      return ret;
    }
  else
    {
      /* No modifier case.  */
      ctree->mode = mode;

      return cli_parse_command (ctree, node, cp, exec, depth);
    }
}

/* CLI description routines.  When user type '?', possible command
   options are displayed.  There are two types of description, one is
   short form another one is long form.  User type '?' at the
   beginning of the line or after space, long description is used.
   User type '?' middle of the command short description is used.  */

/* Max item number in one line.  */
#define CLI_SHORT_ITEM_MAX         5

/* Short format of command description.  */
void
cli_describe_short (struct cli *cli, vector v)
{
  int i;
  int len;
  int max[CLI_SHORT_ITEM_MAX] = {0, 0, 0, 0, 0};
  struct cli_node *node;
  char *str;

  /* Check max string length.  */
  for (i = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      {
        if (node->type == cli_token_alias)
          str = node->help;
        else
          str = node->str;
        len = pal_strlen (str);
        if (max[i % CLI_SHORT_ITEM_MAX] < len)
          max[i % 5] = len;
      }

  /* Display short help.  */
  for (i = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      {
        if (node->type == cli_token_alias)
          str = node->help;
        else
          str = node->str;
        cli_out (cli, "%-*s", max[i % CLI_SHORT_ITEM_MAX] + 2, str);
        if ((i % CLI_SHORT_ITEM_MAX) == (CLI_SHORT_ITEM_MAX - 1))
          cli_out (cli, "\n");
      }

  /* Check new line is just printed out.  */
  if (((i - 1) % CLI_SHORT_ITEM_MAX) != (CLI_SHORT_ITEM_MAX - 1))
    cli_out (cli, "\n");

  cli_out (cli, "\n");
}

void
cli_describe_fold (struct cli *cli, struct cli_node *node, int max,
                   int width)
{
  char *buf, *cmd, *p;
  int pos;

  /* No width is specified.  Just output description.  */
  if (width <= 0)
    {
      cli_out (cli, "  %-*s  %s\n", max, node->str, node->help);
      return;
    }

  /* Allocate a temporally help string.  */
  width -= (max + 6);

  cmd = node->str;
  buf = XMALLOC (MTYPE_TMP, pal_strlen (node->help) + 1);

  for (p = node->help; pal_strlen (p) > width; p += pos + 1)
    {
      for (pos = width; pos > 0; pos--)
        if (p[pos] == ' ')
          break;

      if (pos == 0)
        break;

      pal_strncpy (buf, p, pos);
      buf[pos] = '\0';

      cli_out (cli, "  %-*s  %s\n", max, cmd, buf);

      cmd = "";
    }

  cli_out (cli, "  %-*s  %s\n", max, cmd, p);

  XFREE (MTYPE_TMP, buf);
}

/* Long format of command description.  */
void
cli_describe_long (struct cli *cli, vector v, u_char privilege,
                   struct cli_element *cel, int output_modifier, vector t,
                   int width)
{
  int i;
  struct cli_node *node;
  int len;
  int max = 0;

  /* Check max string length.  */
  for (i = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      if (privilege >= node->privilege
          && ! CHECK_FLAG (node->flags, CLI_FLAG_HIDDEN)
          && node->type != cli_token_alias
          && ! (CHECK_FLAG (node->flags, CLI_FLAG_TRAVERSE)
                && vector_lookup_value (t, node)))
        {
          len = pal_strlen (node->str);
          if (len > max)
            max = len;
        }

  /* Display long description.  */
  for (i = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      if (privilege >= node->privilege
          && ! CHECK_FLAG (node->flags, CLI_FLAG_HIDDEN)
          && node->type != cli_token_alias
          && ! (CHECK_FLAG (node->flags, CLI_FLAG_TRAVERSE)
                && vector_lookup_value (t, node)))
        cli_describe_fold (cli, node, max, width);

  /* When node has cel, current command line can be executed.  */
  if (cel)
    {
#ifndef VTYSH
      if (output_modifier)
        {
          cli_out (cli, "  %-*s  %s\n", max, "|", "Output modifiers");
#ifndef HAVE_NO_LOCAL_FILESYSTEM
          cli_out (cli, "  %-*s  %s\n", max, ">", "Output redirection");
#endif /* HAVE_NO_LOCAL_FILESYSTEM */
        }
#endif /* VTYSH */
      cli_out (cli, "  <cr>\n");
    }

  cli_out (cli, "\n");
}

/* Parse string using CLI tree.  */
void
cli_describe (struct cli *cli, struct cli_tree *ctree, int mode,
              u_char privilege, char *str, int width)
{
  int ret;
  struct cli_node *node;
  int output_modifier = 0;

  /* Parse all of possible tree.  */
  ret = cli_parse (ctree, mode, privilege, str, 0, 0);

  /* New line.  */
  cli_out (cli, "?\n");

  /* Check return value.  */
  switch (ret)
    {
    case CLI_PARSE_NO_MATCH:
    case CLI_PARSE_NO_MODE:
    case CLI_PARSE_ARGV_TOO_LONG:
      cli_out (cli, "%% Unrecognized command\n");
      break;

    case CLI_PARSE_EMPTY_LINE:
      cli_out (cli, "%s commands:\n", cli_mode_str (mode));
      node = vector_lookup_index (ctree->modes, mode);
      if (node)
        cli_describe_long (cli, node->keywords, privilege, NULL, 0, ctree->t,
                           width);
      break;

    case CLI_PARSE_AMBIGUOUS:
      if (ctree->expand_node)
        cli_out (cli, "%% Ambiguous command:  \"%s\"\n", str);
      else
        {
          if (ctree->advanced)
            cli_describe_long (cli, ctree->v, privilege, NULL, 0, ctree->t,
                               width);
          else
            cli_describe_short (cli, ctree->v);
        }
      break;

    case CLI_PARSE_SUCCESS:
    case CLI_PARSE_INCOMPLETE:

      if (ctree->expand_node)
        {
          if (ctree->modifier_node)
            node = ctree->modifier_node;
          else
            node = ctree->exec_node;

          if (ctree->show_node && ! ctree->pipe)
            output_modifier = 1;

          cli_describe_long (cli, node->keywords, privilege, node->cel,
                             output_modifier, ctree->t, width);
        }
      else
        {
          if (ctree->advanced)
            {
              if (CLI_PARSE_INCOMPLETE == ret)
                cli_describe_long (cli, ctree->v, privilege, NULL, 0, ctree->t,
                       width);
              else
                cli_describe_long (cli, ctree->v, privilege,
                            ctree->exec_node->cel, 0, ctree->t, width);
            }

          else
            cli_describe_short (cli, ctree->v);
        }
      break;

    case CLI_PARSE_INCOMPLETE_PIPE:
      cli_out (cli, "%% Incomplete command before pipe.");
      break;

    default:
      break;
    }
}

/* CLI completion routine.  Due to the requirement of libedit, we
   return complete string as array for the completion.  The returned
   strings are complete string including matched part.  */

/* Return matched strings array.  */
char **
cli_complete_matches (struct cli_tree *ctree, vector v)
{
  int i;
  int j;
  struct cli_node *node;
  char **matches;

  for (i = 0, j = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      if (node->type == cli_token_keyword
          && ! CHECK_FLAG (node->flags, CLI_FLAG_HIDDEN))
        if (node->privilege <= ctree->privilege)
          j++;

  if (! j)
    return NULL;

  matches = XCALLOC (MTYPE_TMP, sizeof (char *) * (j + 1));

  /* Check max string length.  */
  for (i = 0, j = 0; i < vector_max (v); i++)
    if ((node = vector_slot (v, i)) != NULL)
      if (node->type == cli_token_keyword
          && ! CHECK_FLAG (node->flags, CLI_FLAG_HIDDEN))
            if (node->privilege <= ctree->privilege)
              matches[j++] = XSTRDUP (MTYPE_TMP, (node->str));

  matches[j] = NULL;

  return matches;
}

/* Parse string using CLI tree.  */
char **
cli_complete (struct cli_tree *ctree, int mode, u_char privilege,
              char *str)
{
  int ret;
  struct cli_node *node;

  /* Parse all of possible tree.  */
  ret = cli_parse (ctree, mode, privilege, str, 0, 0);

  /* Check return value.  */
  switch (ret)
    {
    case CLI_PARSE_NO_MATCH:
    case CLI_PARSE_NO_MODE:
    case CLI_PARSE_EMPTY_LINE:
    case CLI_PARSE_ARGV_TOO_LONG:
      return NULL;

    case CLI_PARSE_AMBIGUOUS:
      if (ctree->expand_node)
        return NULL;
      else
        return cli_complete_matches (ctree, ctree->v);

    case CLI_PARSE_SUCCESS:
    case CLI_PARSE_INCOMPLETE:
      if (ctree->expand_node)
        {
          if (ctree->modifier_node)
            node = ctree->modifier_node;
          else
            node = ctree->exec_node;

          /* Let's say "show ip bgp" is only one command.  When user
             type "show ip " we complete "bgp".  If you want to
             disable the feature, please set advanced mode of struct
             cli_tree to 0.  */
          if (ctree->advanced)
            return cli_complete_matches (ctree, node->keywords);
        }
      else
        return cli_complete_matches (ctree, ctree->v);
      break;

    default:
      break;
    }
  return NULL;
}

/* Compare two node's string.  */
static int
cli_cmp_node (const void *p, const void *q)
{
  struct cli_node *a = *(struct cli_node **) p;
  struct cli_node *b = *(struct cli_node **) q;

  return pal_strcmp (a->str, b->str);
}

/* Sort CLI commands.  */
void
cli_sort_func (struct cli_node *node)
{
  int i;
  vector v;
  struct cli_node *next;

  v = node->keywords;
  pal_qsort (v->index, v->max, sizeof (void *), cli_cmp_node);

  if (CHECK_FLAG (node->flags, CLI_FLAG_TRAVERSE)
      || CHECK_FLAG (node->flags, CLI_FLAG_RECURSIVE))
    return;

  for (i = 0; i < vector_max (node->keywords); i++)
    if ((next = vector_slot (node->keywords, i)) != NULL)
      if (next != node)
        cli_sort_func (next);
}

/* Sort all mode's CLI commands.  */
void
cli_sort (struct cli_tree *ctree)
{
  int i;
  struct cli_node *node;

  for (i = 0; i < vector_max (ctree->modes); i++)
    if ((node = vector_slot (ctree->modes, i)) != NULL)
      cli_sort_func (node);
}


void
cli_set_node_flag (struct cli_tree *ctree, int mode, char *str, u_int16_t flag)
{
  int i;
  struct cli_node *parent;
  struct cli_node *node;

  if (mode == EXEC_PRIV_MODE)
    {
      mode = EXEC_MODE;
    }

  /* Lookup root node.  */
  parent = vector_lookup_index (ctree->modes, mode);
  if (! parent)
    return;

  /* Lookup node.  */
  for (i = 0; i < vector_max (parent->keywords); i++)
    if ((node = vector_slot (parent->keywords, i)) != NULL)
      if (pal_strcmp (node->str, str) == 0)
        SET_FLAG (node->flags, flag);
}

void
cli_free_arguments (struct cli_tree *ctree)
{
  int i;

  /* Free arguments. */
  for (i = 0; i < ctree->argc; i++)
    {
      if (ctree->argv[i])
        XFREE (MTYPE_CLI_ARGUMENT, ctree->argv[i]);
      ctree->argv[i] = NULL;
    }
  ctree->argc = 0;

  /* Free output modifier arguments.  */
  for (i = 0; i < ctree->argc_modifier; i++)
    {
      XFREE (MTYPE_CLI_ARGUMENT, ctree->argv_modifier[i]);
      ctree->argv_modifier[i] = NULL;
    }
  ctree->argc_modifier = 0;

  ctree->rem = NULL;
}

/* This must be removed, interface mapping is not a matter of CLI.  */
char *
cli_interface_resolve (char *buf, int bufsiz, char *iftype, char *ifnum)
{
  if (! pal_strncmp (iftype, "f", 1))
    zsnprintf (buf, bufsiz, "eth%s", ifnum);
  else if (! pal_strncmp (iftype, "l", 1))
    zsnprintf (buf, bufsiz, "lo%s", ifnum);
  else if (! pal_strncmp (iftype, "n", 1))
    zsnprintf (buf, bufsiz, "null%s", ifnum);
  else if (! pal_strncmp (iftype, "s", 1))
    zsnprintf (buf, bufsiz, "serial%s", ifnum);

  return buf;
}

/* Utility function to concatenate argv argument into a single string
   with inserting ' ' character between each argument.  */
char *
argv_concat (char **argv, int argc, int shift)
{
  int i;
  int len;
  int index;
  char *str;

  str = NULL;
  index = 0;

  for (i = shift; i < argc; i++)
    {
      len = pal_strlen (argv[i]);

      if (i == shift)
        {
          str = XSTRDUP (MTYPE_TMP, argv[i]);
          index = len;
        }
      else
        {
          str = XREALLOC (MTYPE_TMP, str, (index + len + 2));
          str[index++] = ' ';
          pal_mem_cpy (str + index, argv[i], len);
          index += len;
          str[index] = '\0';
        }
    }
  return str;
}
/* Help display function for all node. */
CLI (cli_help,
     cli_help_cli,
     "help",
     "Description of the interactive help system")
{
  cli_out (cli,
           "BGP-SDN CLI provides advanced help feature.  When you need help,\n\
anytime at the command line please press '?'.\n\
\n\
If nothing matches, the help list will be empty and you must backup\n\
until entering a '?' shows the available options.\n\
Two styles of help are provided:\n\
1. Full help is available when you are ready to enter a\n\
   command argument (e.g. 'show ?') and describes each possible\n\
   argument.\n\
2. Partial help is provided when an abbreviated argument is entered\n\
   and you want to know what arguments match the input\n\
   (e.g. 'show ve?'.)\n\n");

  return CLI_SUCCESS;
}

/* Show command list.  */
CLI (cli_show_list,
     cli_show_list_cli,
     "show list",
     CLI_SHOW_STR,
     "Show command lists")
{
  cli_command_dump (cli, cli->ctree, cli->mode, cli->privilege);
  return CLI_SUCCESS;
}

/* Show command tree.  */
CLI (cli_show_tree,
     cli_show_tree_cli,
     "show cli",
     "Show running system information",
     "Show CLI tree of current mode")
{
  cli_tree_dump (cli, cli->ctree, cli->mode, cli->privilege);
  return CLI_SUCCESS;
}

/* Generic "end" command.  */
CLI (cli_config_end,
     cli_config_end_cli,
     "end",
     "End current mode and change to EXEC mode")
{
  if (cli->vr->host)
    host_config_unlock (cli->vr->host, cli);

  if (cli->mode != EXEC_MODE)
    cli->mode = EXEC_MODE;
  return CLI_SUCCESS;
}

/* "exit" function.  */
void
cli_mode_exit (struct cli *cli)
{
  switch (cli->mode)
    {
    case EXEC_MODE:
      if (CHECK_FLAG (cli->flags, CLI_FROM_PVR))
        {
          cli->vr = ipi_vr_get_privileged (cli->zg);
          cli->privilege = PRIVILEGE_PVR_MAX;
          UNSET_FLAG (cli->flags, CLI_FROM_PVR);
        }
      else
        cli->status = CLI_CLOSE;
      break;
    case CONFIG_MODE:
      cli->mode = EXEC_MODE;
      if (cli->vr->host)
        host_config_unlock (cli->vr->host, cli);
      break;
    case KEYCHAIN_KEY_MODE:
      cli->mode = KEYCHAIN_MODE;
      break;
    default:
      cli->mode = CONFIG_MODE;
      break;
    }
}

/* Generic "exit" command. */
CLI (cli_config_exit,
     cli_config_exit_cli,
     "exit",
     "End current mode and down to previous mode")
{
  cli_mode_exit (cli);
  return CLI_SUCCESS;
}

/* "quit" alias for EXEC MODE.  */
ALI (cli_config_exit,
     cli_config_quit_cli,
     "quit",
     "Exit current mode and down to previous mode");

/* Common functions for each mode.  */
void
cli_install_default (struct cli_tree *ctree, int mode)
{
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_help_cli);
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_show_list_cli);
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_show_tree_cli);

  /* IMI shell send exit to IMI.  For protocol module, this is same as
     cli_install().  */
  cli_install_imi (ctree, mode, PM_EMPTY, PRIVILEGE_NORMAL, 0,
                   &cli_config_exit_cli);

  /* "quit" is only for EXEC MODE.  "end" should not be installed in
     EXEC MODE.  */
  if (mode == EXEC_MODE)
    cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_config_quit_cli);
  else
    {
      cli_install_imi (ctree, mode, PM_EMPTY, PRIVILEGE_NORMAL,
                       CLI_FLAG_HIDDEN, &cli_config_quit_cli);
      cli_install_imi (ctree, mode, PM_EMPTY, PRIVILEGE_NORMAL,
                       CLI_FLAG_HIDDEN, &cli_config_end_cli);
    }
}

/* Common functions for each mode.  */
void
cli_install_default_family (struct cli_tree *ctree, int mode)
{
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_help_cli);
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_show_list_cli);
  cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_show_tree_cli);

  /* "exit" should not be installed.  */

  /* "quit" is only for EXEC MODE.  "end" should not be installed in
     EXEC MODE.  */
  if (mode == EXEC_MODE)
    cli_install_gen (ctree, mode, PRIVILEGE_NORMAL, 0, &cli_config_quit_cli);
  else
    {
      cli_install_imi (ctree, mode, PM_EMPTY, PRIVILEGE_NORMAL,
                       CLI_FLAG_HIDDEN, &cli_config_quit_cli);
      cli_install_imi (ctree, mode, PM_EMPTY, PRIVILEGE_NORMAL,
                       CLI_FLAG_HIDDEN, &cli_config_end_cli);
    }
}


