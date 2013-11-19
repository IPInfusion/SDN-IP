/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _IMI_CONFSES_H
#define _IMI_CONFSES_H

#include "pal.h"
#include "pal_types.h"

#define IMI_CONFSES_DEF_SESSIONS  4

/* IMI config sessions states container - keeps states throughout config session.
   Each IMISH that has sent a config command to IMI client has an entry here.
   Multiple IMISH can configure the same IMI client at the same time.

   This functionality belongs to the IMI client. Only protocol daemons are making
   use of this facility - the IMISH itself does not make use of it.
   - A configuration session state is added to this database when PM daemon handles
     first command from a given IMISH.
   - Before dispatching a "line" message to the local CLI handler we retrieve
     the user CLI state and copy it to the "cli" structure.
   - Upon the return from the user's CLI handler we store the new state
     in the user's imi_confses.
   - The imi_confses object is deleted in two cases:
      - termination of the IMISH - the IMI daemon detects the IMISH departure and
        notifies all connected IMI clients
      - termination of the IMI daemon - the IMI client detects lost connectivity
        to the IMI daemon and deletes all imi_confsys objects.
*/

/* imi_confses - IMI configuration session state
*
*  imi_confses_vix        - the vector index of this node
*  imi_confses_index      - saved user specific pointer
*  imi_confses_sub_index  - another user specific pointer
*  imi_confses_sid        - session id: it can be the IMISH process id
*                           or socket id in case of the VTY
*  imi_confses_vrid       - VR context of connecting session
*/
struct imi_confses
{
  int        imi_confses_vix;
  void      *imi_confses_index;
  void      *imi_confses_index_sub;
  u_int32_t  imi_confses_sid;
  u_int32_t  imi_confses_mode;
  u_int32_t  imi_confses_vrid;
};

/* The container of configuration sessions states */
struct imi_confses_db
{
  vector v;
};

#define IMI_CONFSES_SET_INDEX(confses, ix)     (confses)->imi_confses_index=(ix)
#define IMI_CONFSES_SET_INDEX_SUB(confses, ix) (confses)->imi_confses_index_sub=(ix)
#define IMI_CONFSES_GET_INDEX(confses)         (confses)->imi_confses_index
#define IMI_CONFSES_GET_INDEX_SUB(confses)     (confses)->imi_confses_index_sub
#define IMI_CONFSES_SET_MODE(confses,mode)     (confses)->imi_confses_mode=(mode)
#define IMI_CONFSES_SET_VRID(confses,vrid)     (confses)->imi_confses_vrid=(vrid)

int
imi_confses_db_init(struct imi_confses_db *confses_db);

void
imi_confses_db_delete(struct imi_confses_db *confses_db);

int
imi_confses_db_empty(struct imi_confses_db *confses_db);

struct imi_confses *
imi_confses_get (struct imi_confses_db *confses_db, u_int32_t sid, u_int32_t vrid);

void
imi_confses_del (struct imi_confses_db *confses_db, u_int32_t sid);

int
imi_confses_save (struct imi_confses_db *confses_db,
                  struct imi_confses *confses,
                  u_int32_t *sid);

int
imi_confses_check (struct imi_confses_db *confses_db, u_int32_t sid, u_int32_t vrid);


#endif

