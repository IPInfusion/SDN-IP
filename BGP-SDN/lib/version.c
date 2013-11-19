/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"
#include "bgpsdn_version.h"
#include "copyright.h"
#include "snprintf.h"

/*
** host_name is a string containing the manufacturer's platform description.
** HOST_NAME is defined by the platform.
*/
const char *host_name = HOST_NAME;

/* BGP-SDN Version. */
const char *
bgpsdn_version (char *buf, int len)
{
  char *curr = CURR_RELEASE;

  if (CURR_VERSION_IS_FCS (curr))
    curr = NULL;

  zsnprintf (buf, len, "%s.%s.%s%s%s",
             BGPSDN_MAJOR_RELEASE,
             BGPSDN_MINOR_RELEASE,
             BGPSDN_POINT_RELEASE,
             curr && pal_strlen (curr) ? "." : "",
             curr ? curr : "");
  return buf;
}

/* BGP-SDN BUILDNO. */
const char *
bgpsdn_buildno (char *buf, int len)
{
  char *curr = CURR_RELEASE;
  char *acr = PLATFORM_ACRONYM;

  if (CURR_VERSION_IS_FCS (curr))
    curr = NULL;

  zsnprintf (buf, len, "BGP-SDN-%s-%s-%s%s%s%s%s",
             BGPSDN_MAJOR_RELEASE,
             BGPSDN_MINOR_RELEASE,
             BGPSDN_POINT_RELEASE,
             curr && pal_strlen (curr) ? "-" : "",
             curr ? curr : "",
             pal_strlen (acr) ? "-" : "",
             acr);
  return buf;
}

/* Utility function to print out version for main() for PMs. */
void
print_version (char *progname_l)
{
  char buf[50];

  printf ("%s version %s (%s)\n", progname_l, bgpsdn_version (buf, 50),
          host_name);
}
