/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include <bgp_incl.h>

/* Character `_' has special mean.  It represents [,{}() ] and the
   beginning of the line(^) and the end of the line ($).

   (^|[,{}() ]|$) */

pal_regex_t *
bgp_regcomp (char *regstr)
{
  /* Convert _ character to generic regular expression. */
  int i, j;
  int len;
  int magic = 0;
  char *magic_str;
  int magic_str_len;
  char magic_regexp[] = "(^|[,{}() ]|$)";
  int ret;
  pal_regex_t *regex;

  len = pal_strlen (regstr);
  for (i = 0; i < len; i++)
    if (regstr[i] == '_')
      magic++;

  magic_str_len = len + (14 * magic) + 1;
  magic_str = XMALLOC (MTYPE_TMP, magic_str_len);
  regex = XMALLOC (MTYPE_TMP, sizeof (pal_regex_t));

  for (i = 0, j = 0; i < len; i++)
    {

      if (regstr[i] == '_')
        {
          pal_mem_cpy (magic_str + j, magic_regexp, pal_strlen (magic_regexp));
          j += pal_strlen (magic_regexp);
        }
      else
        magic_str[j++] = regstr[i];
    }
  magic_str[j] = '\0';

  ret = pal_regcomp (regex, magic_str, REG_EXTENDED);

  XFREE (MTYPE_TMP, magic_str);

  if (ret != 0)
    {
      XFREE (MTYPE_TMP, regex);
      return NULL;
    }

  return regex;
}

int
bgp_regexec (pal_regex_t *regex, struct aspath *aspath)
{
  return pal_regexec (regex, aspath->str, 0, NULL, 0);
}

#ifdef HAVE_EXT_CAP_ASN
int
bgp_regexec_aspath4B (pal_regex_t *regex, struct as4path *aspath4B)
{
  return pal_regexec (regex, aspath4B->str, 0, NULL, 0);
}
#endif /* HAVE_EXT_CAP_ASN */

void
bgp_regex_free (pal_regex_t *regex)
{
  pal_regfree (regex);
  XFREE (MTYPE_TMP, regex);
}
