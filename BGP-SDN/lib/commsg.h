/*--------------------------------------------------------
 * Common message interface to the NSM messaging subsystem.
 * Can be used by either the NSM client or the NSM itself.
 *---------------------------------------------------------
 */
#ifndef _COMMSG_H_
#define _COMMSG_H_

#include "pal.h"

typedef enum _COMMSG_TYPE
{
  COMMSG_TYPE_NONE,
  COMMSG_TYPE_CAL_SNDR_REQ,
  COMMSG_TYPE_CAL_RCVR_RDY,
  COMMSG_TYPE_CAL_SEND_FIN,
  COMMSG_TYPE_MAX
} COMMSG_TYPE;

typedef void *COMMSG_HAN;

/*----------------------------------------------------------
 * commsg_recv_cb_t - 
 *
 *  This prototype must be implemented by application.
 *  It will allow to receive encoded COMMSG message.
 *----------------------------------------------------------
 */
typedef int (* commsg_recv_cb_t)(struct lib_globals *zg,
                                 module_id_t  src_mod_id,
                                 u_int16_t    msg_type, 
                                 u_char      *msg_buf, 
                                 u_int16_t    msg_len);

/*----------------------------------------------------------
 * commsg_send_fp_t - 
 *
 *  This prototype must be implemented separately by NSM client
 *  and server. The application must register proper 
 *  implementation when calling commsg_init().
 *  NOTE: The service provider message type is not 
 *        known to COMMSG.
 *----------------------------------------------------------
 */
typedef int (* commsg_send_fp_t)(void        *tp_ref,
                                 module_id_t  dst_mod_id,
                                 u_char      *msg_buf, 
                                 u_int16_t    msg_len);

/*----------------------------------------------------------
 * commsg_getbuf_fp_t - 
 *
 *  This prototype must be implemented separately by the NSM client
 *  and server. 
 *  The implementation must retrieve buffer for a given NSM 
 *  connection reserve space for the NSM header and return the 
 *  pointer where COMMSG can write its header.
 *----------------------------------------------------------
 */
typedef u_int8_t *(* commsg_getbuf_fp_t)(void       *tp_ref,
                                         module_id_t remmod_id, 
                                         u_int16_t   size);


typedef struct _commsg
{
  struct lib_globals  *cms_zg;
  u_int16_t            cms_mod_id;
  commsg_getbuf_fp_t   cms_getbuf_fp;
  commsg_send_fp_t     cms_send_fp;
  void                *cms_tp_ref;
  commsg_recv_cb_t     cms_recv_cb[COMMSG_TYPE_MAX];
} COMMSG;

/*----------------------------------------------------------
 * commsg_recv - 
 * 
 *  API used by client or server to call with 
 *  received message. It must be installed by the application 
 *  in which context it is called.
 *-----------------------------------------------------------
 */
void commsg_recv(void      *tp_ref,
                u_int16_t  src_mod_id, 
                u_char    *buf, 
                u_int16_t  len);

/*----------------------------------------------------------
 * commsg_getbuf - 
 * 
 *  API used by the application to obtain a buffer from the 
 *  service provider.
 *-----------------------------------------------------------
 */
u_char *commsg_getbuf(COMMSG_HAN   tp_han,
                      module_id_t  dst_mod_id, 
                      u_int16_t    len);

/*----------------------------------------------------------
 * commsg_send - 
 * 
 *  API used by the application to send a message to the remote
 *  destination.
 *  Message must be encoded already. 
 *-----------------------------------------------------------
 */
int commsg_send(COMMSG_HAN   tp_han,
                COMMSG_TYPE  msg_type,
                module_id_t  dest_mod_id,
                u_char      *buf,
                u_int16_t    len);

/*----------------------------------------------------------
 * commsg_reg_msg - 
 * 
 *  API used by the application to register a mapping between 
 *  message type, the receive callback.
 *-----------------------------------------------------------
 */
int commsg_reg_msg(COMMSG_HAN       tp_han,
                   COMMSG_TYPE      msg_type,
                   commsg_recv_cb_t recv_cb);

/*----------------------------------------------------------
 * commsg_reg_tp - 
 * 
 *  API used by the application to init the COMMSG facility.
 *  send_fp - A function implemented by the client or 
 *            server, which will forward the given 
 *            message to remote destination.
 *  lgb     - Application lib_globals structure
 *  getbuf_fp- 
 *-----------------------------------------------------------
 */
COMMSG_HAN
commsg_reg_tp(struct lib_globals *lgb, 
               void               *tp_ref,
               commsg_getbuf_fp_t  getbuf_fp,
               commsg_send_fp_t    send_fp);

#endif

