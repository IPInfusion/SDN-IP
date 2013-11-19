/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#include "imi_confses.h"

/* #define _CONFSES_DEBUG */

/* Create config sessions database.
*/
int
imi_confses_db_init(struct imi_confses_db *confses_db)
{
  if ((confses_db->v = vector_init (IMI_CONFSES_DEF_SESSIONS)) != NULL)
    return 0;
  else
    return -1;
}

/* Delete all config sessions info at the time the IMI is killed
*/
int
imi_confses_db_empty (struct imi_confses_db *confses_db)
{
  struct imi_confses *confses=NULL;
  int vix;

  if (confses_db == NULL) {
    return -1;
  }
#ifdef _CONFSES_DEBUG
  printf("\nimi_confses_db_empty(db:%p) ENTRY: count:%d \n",
         confses_db, vector_count(confses_db->v));
#endif

  for (vix=0; vix < vector_max(confses_db->v); vix++) {
    confses = vector_lookup_index(confses_db->v, vix);
    if (confses == NULL)
      continue;

    vector_unset(confses_db->v, vix);
    XFREE(MTYPE_IMI_CLIENT, confses);
  }
#ifdef _CONFSES_DEBUG
  printf("\nimi_confses_db_empty(db:%p) EXIT : count:%d \n",
         confses_db, vector_count(confses_db->v));
#endif
  return 0;
}

/* Delete the database at the time the IMI client daemon is being killed
*/
void
imi_confses_db_delete(struct imi_confses_db *confses_db)
{
  if (! imi_confses_db_empty(confses_db)) {
    vector_free(confses_db->v);
    confses_db->v = NULL;
  }
}

/* Get existing config session state or create a new one
*/
struct imi_confses *
imi_confses_get (struct imi_confses_db *confses_db,
                 u_int32_t sid,
                 u_int32_t vrid)
{
  struct imi_confses *confses = NULL;

  u_int32_t vix;

  if (confses_db == NULL) {
    return NULL;
  }
#ifdef _CONFSES_DEBUG
  printf("\nimi_confses_get(db:%p sid:%d vrid:%d) count:%d \n",
         confses_db, sid, vrid, vector_count(confses_db->v));
#endif

  /* Concurrent config sessions */
  for (vix=0; vix < vector_max(confses_db->v); vix++)
  {
    confses = vector_lookup_index(confses_db->v, vix);
    if (confses == NULL)
      continue;

    if (confses->imi_confses_sid==sid) {
      return confses;
    }
  }
  if (vix >= vector_max(confses_db->v))
  {
    confses = XCALLOC(MTYPE_IMI_CLIENT, sizeof(* confses));
    if (confses == NULL) {
      return NULL;
    }
  }
  confses->imi_confses_sid  = sid;
  confses->imi_confses_vrid = vrid;

  /* We assume this is the start of session so:
   *  - index and sub_index will be NULL
   */
  confses->imi_confses_vix = vector_set(confses_db->v, confses);
  return confses;
}

/* The state has already been saved in the confses object.
   If the "index" is zero, we assume the application does not preserve any context,
   therefore we will remove the confses from the database.
   If the index is not zero and we have another entry in the db with the same index,
   we will return error code just to prevent this sessionfrom interfering
   with another session.
   -1 - problems with database or data integrity
   -2 - interfering with another session
*/
int
imi_confses_save (struct imi_confses_db *confses_db,
                  struct imi_confses *confses,
                  u_int32_t *sid)
{
#ifdef _CONFSES_DEBUG
  printf("\nimi_confses_save: db:%p sid:%d ix:%p s_ix:%p count:%d\n",
         confses_db, confses->imi_confses_sid, confses->imi_confses_index,
         confses->imi_confses_index_sub,vector_count(confses_db->v));
#endif

  if (confses_db==NULL || confses==NULL)
  {
    pal_assert(0);
    return -1;
  }
  if (confses->imi_confses_vix >= vector_max(confses_db->v))
  {
    pal_assert(0);
    return -1;
  }
  if (vector_lookup_index(confses_db->v, confses->imi_confses_vix) !=
      confses)
  {
    pal_assert(0);
    return -1;
  }
  /* If the index is NULL remove the entry from the database. */
  if (confses->imi_confses_index == NULL)
  {
    vector_unset(confses_db->v, confses->imi_confses_vix);
    XFREE(MTYPE_IMI_CLIENT, confses);
  }
  else
  {
    int vix;
    struct imi_confses *cs;
    /* If there is any other confses with the same index, return an error. */
    for (vix=0; vix < vector_max(confses_db->v); vix++) {
      cs = vector_lookup_index(confses_db->v, vix);
      if (cs == NULL) continue;
      if (cs != confses && cs->imi_confses_index==confses->imi_confses_index &&
          cs->imi_confses_mode != INTERFACE_MODE) {
        *sid = cs->imi_confses_sid;
        vector_unset(confses_db->v, confses->imi_confses_vix);
        XFREE(MTYPE_IMI_CLIENT, confses);
        return -2;
      }
    }
  }
  return 0;
}

/* Delete a single config session state (if recorded here).
*/
void
imi_confses_del (struct imi_confses_db *confses_db, u_int32_t sid)
{
  struct imi_confses *confses=NULL;
  int       vix;

  if (confses_db == NULL) {
    return;
  }
#ifdef _CONFSES_DEBUG
  printf("\nimi_confses_del(db:%x sid:%d) ENTRY: count:%d \n",
         confses_db, sid, vector_count(confses_db->v));
#endif

  for (vix=0; vix < vector_max(confses_db->v); vix++) {
    confses = vector_lookup_index(confses_db->v, vix);
    if (confses == NULL)
      continue;

    if (confses->imi_confses_sid==sid) {
      vector_unset(confses_db->v, vix);
      XFREE(MTYPE_IMI_CLIENT, confses);

#ifdef _CONFSES_DEBUG
      printf("\nimi_confses_del(db:%p sid:%d) EXIT : count:%d \n",
             confses_db, sid, vector_count(confses_db->v));
#endif
      return;
    }
  }
}


/* Returns session id of any session currently configuring the daemon.
   This is used to prevent execution of "no " on the object in use.
*/
int
imi_confses_check (struct imi_confses_db *confses_db,
                   u_int32_t sid,
                   u_int32_t vrid)
{
  int vix;
  struct imi_confses *cs;
  if (confses_db==NULL)
  {
    pal_assert(0);
    return -1;
  }
  /* If there is any other confses with the same index, return an error. */
  for (vix=0; vix < vector_max(confses_db->v); vix++) {
    cs = vector_lookup_index(confses_db->v, vix);
    if (cs != NULL &&
        cs->imi_confses_sid != sid &&
        cs->imi_confses_vrid==vrid) return (int)cs->imi_confses_sid;
  }
  return 0;
}


