/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

#include "pal.h"
#include "modbmap.h"

/*********************************************************************/
/* FILE       : modbmap.c                                            */
/* PURPOSE    : This file contains 'Module bitmap'                   */
/*              related function definitions.                        */
/* NAME-TAG   : 'modbmap_'                                           */
/*********************************************************************/

modbmap_t PM_EMPTY;
modbmap_t PM_UCAST;
modbmap_t PM_BGP;
modbmap_t PM_IMI;

modbmap_t PM_ALL;

modbmap_t PM_VR;
modbmap_t PM_VRF;
modbmap_t PM_ACCESS;
modbmap_t PM_PREFIX;
modbmap_t PM_RMAP;
modbmap_t PM_LOG;
modbmap_t PM_SNMP_DBG;
/*
   Name: modbmap_id2bit

   Description:
   Initialize Module bitmap : allocate memory & sets the Module bitmap

   Parameters:
   bit_num - Protocol number

   Returns:
   module bitmap
*/
modbmap_t
modbmap_id2bit (u_int8_t bit_num)
{
  modbmap_t res_mbm = PM_EMPTY;

  MODBMAP_SET (res_mbm, bit_num);

  return (res_mbm);
}

/*
   Name: modbmap_vor

   Description:
   Performs logical-OR operation on "cnt" number of Module bitmaps.

   Parameters:
   *mbm1 - Address of Module bitmap
   cnt   - Count of the number of Module bitmaps sent as parameters

   Returns:
   Module bitmap
*/
modbmap_t
modbmap_vor (u_int8_t cnt, modbmap_t *mbm, ...)
{
  va_list va;
  modbmap_t res_mbm = *mbm;
  modbmap_t nxt_mbm = PM_EMPTY;

  va_start (va, mbm);

  while (cnt-- > 1)
  {
    nxt_mbm = *(va_arg (va, modbmap_t *));
    res_mbm = modbmap_or (res_mbm, nxt_mbm);
  }
  va_end (va);
  return(res_mbm);
}

/*
   Name: modbmap_check

   Description:
   Considering only one bit is getting set in second parameter modbmap_t mbm2.
   Checks whether the bit is set or not in the module bitmap mbm1.

   Parameters:
   mbm1 - Module bitmap
   mbm2 - Module bitmap

   Returns:
   PAL_TRUE  - if SET
   PAL_FALSE - if not SET
*/
bool_t
modbmap_check (modbmap_t mbm1, modbmap_t mbm2)
{
  int cnt;

  for(cnt = 0; cnt < MODBMAP_MAX_WORDS; cnt++)
    if(mbm2.mbm_arr[cnt] != 0)
      if(((mbm1.mbm_arr[cnt]) & (mbm2.mbm_arr[cnt]))!= 0)
        return PAL_TRUE;

  return PAL_FALSE;
}

/* Performs logical-AND operation on Module bitmaps and returns a Module bitmap. */
modbmap_t
modbmap_and (modbmap_t mbm1, modbmap_t mbm2)
{
  int cnt;
  modbmap_t temp = PM_EMPTY;

  for(cnt = 0; cnt < MODBMAP_MAX_WORDS; cnt++)
    temp.mbm_arr[cnt] = ((mbm1.mbm_arr[cnt]) & (mbm2.mbm_arr[cnt]));

  return temp;
}

/* Performs logical-OR operation on Module bitmaps and returns a Module bitmap. */
modbmap_t
modbmap_or (modbmap_t mbm1, modbmap_t mbm2)
{
  int cnt;
  modbmap_t temp = PM_EMPTY;

  for(cnt = 0; cnt < MODBMAP_MAX_WORDS; cnt++)
    temp.mbm_arr[cnt] = mbm1.mbm_arr[cnt] | mbm2.mbm_arr[cnt];

  return temp;
}

/* Performs Subtraction on Module bitmaps and returns a Module bitmap. */
modbmap_t
modbmap_sub (modbmap_t mbm1, modbmap_t mbm2)
{
  int cnt;
  modbmap_t temp = PM_EMPTY;

  for(cnt = 0; cnt < MODBMAP_MAX_WORDS; cnt++)
    temp.mbm_arr[cnt] = ((mbm1.mbm_arr[cnt]) & (~(mbm2.mbm_arr[cnt])));

  return temp;
}

/*
   Name: modbmap_isempty

   Description:
   Function to check whether a Module bitmap is NULL or not

   Parameters:
   mbm1 - Module bitmap

   Returns:
   PAL_TRUE  - if NULL
   PAL_FALSE - if not NULL
*/
bool_t
modbmap_isempty (modbmap_t mbm)
{
  int cnt;

  for(cnt = 0; cnt < MODBMAP_MAX_WORDS; cnt++)
    if(mbm.mbm_arr[cnt])
      return PAL_FALSE;

  return PAL_TRUE;
}

/* Function to print out the value of Module bitmap. */
void
modbmap_printvalue (modbmap_t mbm)
{
  int cnt;

  printf("\nMod: ");
  for(cnt = MODBMAP_MAX_WORDS - 1; cnt >= 0; cnt--)
    printf("%x ", mbm.mbm_arr[cnt]);

  printf("\n");
}

/* Function to return the protocol number from the input parameter module bitmap. */
u_int8_t
modbmap_bit2id (modbmap_t mbm)
{
  u_int8_t pos = 0;
  u_int8_t mask_size= 32, wix;
  u_int32_t x, mask= 0xFFFFFFFF;

  for (wix = 0; wix < MODBMAP_MAX_WORDS; wix++)
  {
    if ((x = mbm.mbm_arr[wix]) == 0)
    {
      pos += 32;
    }
    else
    {
      do
      {
        mask_size /= 2;
        mask >>= mask_size;

        if ((x & mask) != 0)
        {
          x = x & mask;
        }
        else
        {
          x = x >> mask_size;
          pos += mask_size;
        }
      } while (mask_size != 1);
      break;
    }
  }
  if (pos <= IPI_PROTO_UNSPEC || pos >= IPI_PROTO_MAX)
  {
    pos = IPI_PROTO_UNSPEC;
  }
  return (pos);
}

/* Initializes all the global predefined Module bit maps. */
void
modbmap_init_all ()
{
  pal_mem_set (&PM_EMPTY, 0, sizeof (PM_EMPTY));

  PM_BGP      = modbmap_id2bit (IPI_PROTO_BGP);
  PM_IMI      = modbmap_id2bit (IPI_PROTO_IMI);

  PM_UCAST     = modbmap_vor (1, &PM_BGP);

  PM_ALL       = modbmap_vor (1, &PM_BGP);

  PM_VR        = modbmap_vor (2, &PM_BGP, &PM_IMI);
  PM_VRF       = modbmap_vor (1, &PM_BGP);

  PM_ACCESS    = modbmap_vor (1, &PM_BGP);
  PM_PREFIX    = modbmap_vor (1, &PM_BGP);

  PM_RMAP      = modbmap_vor (1, &PM_BGP);
  PM_LOG       = PM_ALL;

#ifdef HAVE_SNMP
  PM_SNMP_DBG    = modbmap_vor (1, &PM_BGP);
#endif /* HAVE_SNMP */
}
