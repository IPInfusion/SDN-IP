
/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "pal.h"

#define PAL_SYSCTL_CMD_LEN 160
#define PAL_SYSCTL_TMP_FNAME_LEN 64
#define PAL_SYSCTL_INP_LEN PAL_SYSCTL_CMD_LEN
#define PAL_SYSCTL_SIZE(x) sizeof(x)/sizeof(x[0])

#undef HAVE_SYSCTL 

result_t
pal_sysctl_set_int_val_by_param (int sysctl_param[], int val)
{
  int params_size;
  int ret;
  int error;
  int len;

  params_size = PAL_SYSCTL_SIZE(sysctl_param);

  len = sizeof (val);


  error = sysctl (sysctl_param, params_size, NULL /*(void *)oldval */, 0/*&len*/,
         (void *) &val, len);

  if (error)
      ret = RESULT_ERROR;
  else
      ret = RESULT_OK;

  return ret;
}

result_t
pal_sysctl_get_int_val_by_param (int sysctl_param[], int *val)
{
  int params_size;
  int ret;
  int error;
  size_t len;

  params_size = PAL_SYSCTL_SIZE(sysctl_param);

  len = sizeof (int);

  error = sysctl (sysctl_param, params_size, (void *)val /*oldval*/, &len /*len */,
                    NULL /*newval*/, 0 /*newvlen*/);
   if (error)
       ret = RESULT_ERROR;
   else
       ret = RESULT_OK;
      
  return ret;
}

result_t
pal_sysctl_set_int_val_by_path (char *kpath, char *vname, int val)
{
  char cmd[PAL_SYSCTL_CMD_LEN];

  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "echo %d > /proc/sys/%s/%s", val, kpath, vname);
  return (system (cmd) != 0 ? RESULT_ERROR : RESULT_OK);
}

result_t
pal_sysctl_get_int_val_by_path (char *kpath, char *vname, int *val)
{
  char tmp_fn[PAL_SYSCTL_TMP_FNAME_LEN];
  char cmd[PAL_SYSCTL_CMD_LEN];

  /* Create name of tmp file. */
  pal_snprintf (tmp_fn, PAL_SYSCTL_TMP_FNAME_LEN, "/tmp/bgpsdn_%s", vname);

  /* Copy value to tmp file. */
  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "cat /proc/sys/%s/%s > %s", kpath, vname, tmp_fn);

  if (system (cmd) != 0)
    return RESULT_ERROR;
  else
    {
      FILE *fp = NULL;
      char *sp= &cmd[0];     /* Reusing the command buffer. */
  
      fp = fopen (tmp_fn, "r");
      if (fp == NULL)
        return RESULT_ERROR;
      
      if (fgets (sp, PAL_SYSCTL_CMD_LEN, fp) == sp)
        {
          /* We expect exactly 1 value. */
          if (sscanf (sp, "%d", val) == 1)
            { 
              fclose (fp);
              return RESULT_OK;
            }
        }
      fclose (fp);
      return RESULT_ERROR;
    }
}

#ifdef HAVE_SYSCTL

result_t
pal_sysctl_set_int_val(char *kpath, char *vname, int val)
{
  char cmd[PAL_SYSCTL_CMD_LEN];

  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "sysctl -w %s/%s=%d", kpath, vname, val);
  return (system (cmd) != 0 ? RESULT_ERROR : RESULT_OK);
}

result_t
pal_sysctl_get_int_val(char *kpath, char *vname, int *val)
{
  char tmp_fn[PAL_SYSCTL_TMP_FNAME_LEN];
  char cmd[PAL_SYSCTL_CMD_LEN];

  /* Create name of tmp file. */
  pal_snprintf (tmp_fn, PAL_SYSCTL_TMP_FNAME_LEN, "/tmp/bgpsdn_%s", vname);

  /* Copy value to tmp file. */
  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "sysctl -n %s/%s > %s", kpath, vname, tmp_fn);

  if (system (cmd) != 0)
    return RESULT_ERROR;
  else
    {
      FILE *fp = NULL;
      char *sp= &cmd[0];     /* Reusing the command buffer. */

      fp = fopen (tmp_fn, "r");
      if (fp == NULL)
        return RESULT_ERROR;

      if (fgets (sp, PAL_SYSCTL_CMD_LEN, fp) == sp)
        {
          /* We expect exactly 1 value. */
          if (sscanf (sp, "%d", val) == 1)
            {
              fclose (fp);
              return RESULT_OK;
            }
        }
      fclose (fp);
      return RESULT_ERROR;
    }
}

#else
  /* In case the sysctl command is not available. */

result_t
pal_sysctl_set_int_val(char *kpath, char *vname, int val)
{
  char cmd[PAL_SYSCTL_CMD_LEN];

  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "echo %d > /proc/sys/%s/%s", val, kpath, vname);
  return (system (cmd) != 0 ? RESULT_ERROR : RESULT_OK);
}

result_t
pal_sysctl_get_int_val(char *kpath, char *vname, int *val)
{
  char tmp_fn[PAL_SYSCTL_TMP_FNAME_LEN];
  char cmd[PAL_SYSCTL_CMD_LEN];

  /* Create name of tmp file. */
  pal_snprintf (tmp_fn, PAL_SYSCTL_TMP_FNAME_LEN, "/tmp/bgpsdn_%s", vname);

  /* Copy value to tmp file. */
  pal_snprintf (cmd, PAL_SYSCTL_CMD_LEN, "cat /proc/sys/%s/%s > %s", kpath, vname, tmp_fn);

  if (system (cmd) != 0)
    return RESULT_ERROR;
  else
    {
      FILE *fp = NULL;
      char *sp= &cmd[0];     /* Reusing the command buffer. */

      fp = fopen (tmp_fn, "r");
      if (fp == NULL)
        return RESULT_ERROR;

      if (fgets (sp, PAL_SYSCTL_CMD_LEN, fp) == sp)
        {
          /* We expect exactly 1 value. */
          if (sscanf (sp, "%d", val) == 1)
            {
              fclose (fp);
              return RESULT_OK;
            }
        }
      fclose (fp);
      return RESULT_ERROR;
    }
}

#endif

