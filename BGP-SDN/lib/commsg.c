/*--------------------------------------------------------
 * Common message interface to the NSM messaging subsystem.
 * Can be used by either the NSM client or the NSM itself.
 *---------------------------------------------------------
 */
#include "pal.h"
#include "commsg.h"
#include "tlv.h"


#define COMMSG_HDR_LEN 4
/* #define COMMSG_DEBUG */

typedef struct _commsg_hdr
{
  u_int16_t cmh_type;
  u_char    cmh_dst_mod_id;
  u_char    cmh_src_mod_id;
} COMMSG_HDR;

void
commsg_encode_header (u_char **pnt, u_int16_t *size,
                      COMMSG_HDR *hdr)
{
  TLV_ENCODE_PUTW(hdr->cmh_type);
  TLV_ENCODE_PUTC(hdr->cmh_dst_mod_id);
  TLV_ENCODE_PUTC(hdr->cmh_src_mod_id);
}

void
commsg_decode_header (u_char **pnt, u_int16_t *size,
                      COMMSG_HDR *hdr)
{
  TLV_DECODE_GETW(hdr->cmh_type);
  TLV_DECODE_GETC(hdr->cmh_dst_mod_id);
  TLV_DECODE_GETC(hdr->cmh_src_mod_id);
}

/*----------------------------------------------------------
 * commsg_recv - 
 * 
 *  API used by client or server transport to call with 
 *  received message. It must be installed by the application 
 *  in which context it is called.
 *-----------------------------------------------------------
 */

void commsg_recv(void     *cm_ref,
                u_int16_t src_mod_id, 
                u_char   *buf, 
                u_int16_t len)
{
  COMMSG_HDR hdr;
  u_char *pnt = buf;
  u_int16_t *size = &len;
  COMMSG *cmgb = (COMMSG *)cm_ref;

#ifdef COMMSG_DEBUG
  printf("commsg_recv: %x %d %x %d\n", cmgb, src_mod_id, buf, len);
#endif
  if (len < COMMSG_HDR_LEN) {
    return;
  }
  commsg_decode_header(&pnt,&len,&hdr);

  if (hdr.cmh_type<= COMMSG_TYPE_NONE || hdr.cmh_type>= COMMSG_TYPE_MAX) {
    return;
  }
  if (cmgb->cms_recv_cb[hdr.cmh_type] != NULL) {
    cmgb->cms_recv_cb[hdr.cmh_type](cmgb->cms_zg, 
                                    hdr.cmh_type, 
                                    src_mod_id, 
                                    pnt, *size);
  }
#ifdef COMMSG_DEBUG
  printf("commsg_recv: recv_cb returned\n");
#endif
}

/*----------------------------------------------------------
 * commsg_getbuf - 
 * 
 *  API used by the application to obtain a networ buffer 
 *  for the message to send.
 *-----------------------------------------------------------
 */
u_char *commsg_getbuf(COMMSG_HAN   cm_han,
                      module_id_t  dst_mod_id, 
                      u_int16_t    size)
{
  u_char  *buf=NULL;
  COMMSG *cmgb = (COMMSG *)cm_han;

  if (cmgb == NULL) {
    return NULL;
  }
#ifdef COMMSG_DEBUG
  printf("commsg_getbuf: %p %d %d\n", cmgb, dst_mod_id, size);
#endif
  if (cmgb->cms_getbuf_fp == NULL) {
    return NULL; 
  }
  /* Get the buffer from the service provider. */
  buf = cmgb->cms_getbuf_fp(cmgb->cms_tp_ref, 
                           dst_mod_id, 
                           size+COMMSG_HDR_LEN);
  if (buf==NULL) {
    return NULL;
  }
  /* Put a marker to verify the buffer came from the service layer. */
  *((unsigned long *)buf)=(unsigned long)buf;

  buf  += COMMSG_HDR_LEN;
#ifdef COMMSG_DEBUG
  printf("commsg_getbuf: OK\n");
#endif
  return buf;
}

/*----------------------------------------------------------
 * commsg_send - 
 * 
 *  API used by the application to send a message to the remote
 *  destination.
 *  Message must be encoded already. 
 *-----------------------------------------------------------
 */

int commsg_send(COMMSG_HAN     cm_han,
                COMMSG_TYPE    msg_type,
                module_id_t    dst_mod_id,
                u_char        *buf,
                u_int16_t      len)
{
  COMMSG_HDR hdr;
  u_char    *pnt;
  u_int16_t hdr_len=COMMSG_HDR_LEN;
  int ret;
  COMMSG *cmgb = (COMMSG *)cm_han;

  if (cmgb == NULL) {
    return -1;
  }

#ifdef COMMSG_DEBUG
  printf("commsg_send: %p %d %d %x %d\n", cmgb, msg_type, dst_mod_id, buf, len);
#endif
  /* Move back the buffer pointer to get the COMMSG header. */
  buf -= COMMSG_HDR_LEN;
  if (*((unsigned long *)buf) != (unsigned long)buf) {
    return -1;
  }
  hdr.cmh_type       = msg_type;
  hdr.cmh_dst_mod_id = dst_mod_id;
  hdr.cmh_src_mod_id = cmgb->cms_mod_id;

  pnt = buf;
  commsg_encode_header(&pnt, &hdr_len, &hdr);

  /* Call the service provider method. */
  ret = cmgb->cms_send_fp(cmgb->cms_tp_ref,
                          dst_mod_id,
                          buf,
                          len+COMMSG_HDR_LEN);
#ifdef COMMSG_DEBUG
  printf("commsg_send: sent to transport ret:%d\n", ret);
#endif
  return ret;
}


/*----------------------------------------------------------
 * commsg_register - 
 * 
 *  API used by the application to register a mapping between 
 *  message type, the receive callback.
 *-----------------------------------------------------------
 */
int commsg_reg_msg(COMMSG_HAN       cm_han,
                   COMMSG_TYPE      msg_type,
                   commsg_recv_cb_t recv_cb)
{
  COMMSG *cmgb = (COMMSG *)cm_han;

  if (cmgb == NULL) {
    return -1;
  }
  if (msg_type <= COMMSG_TYPE_NONE || msg_type >= COMMSG_TYPE_MAX) {
    return -1;
  }
  cmgb->cms_recv_cb[msg_type] = recv_cb;

  return 0;
}

/*----------------------------------------------------------
 * commsg_reg_tp
 * 
 *  API used by the application to register specific message 
 *  transport and the hosting module id.
 *  lgb      - Application lib_globals structure
 *  tp_ref   - A reference to underlying message transport entity.
 *             E.g. nsm_client or nsm_server objects.
 *             This is an opaque value at the PM - COMMSG interface,
 *             but for underlying transport it will represent 
 *             the right communication end point.
 *  getbuf_fp- 
 *  send_fp  - A function implemented by the client or 
 *             server, which will forward the given 
 *             message to remote destination.
 *  Returns:
 *   A handle to be used in all subsequent communcications to the
 *   selected transport.
 *-----------------------------------------------------------
 */

COMMSG_HAN 
commsg_reg_tp(struct lib_globals *zg, 
              void               *tp_ref,
              commsg_getbuf_fp_t  getbuf_fp,
              commsg_send_fp_t    send_fp)
{
  COMMSG *cmgb = (COMMSG *)XCALLOC(MTYPE_COMMSG, sizeof(COMMSG));
  if (cmgb == NULL) {
    return 0;
  }
  zg->commsg          = cmgb;
  cmgb->cms_zg        = zg;
  cmgb->cms_mod_id    = zg->protocol;
  cmgb->cms_tp_ref    = tp_ref;
  cmgb->cms_getbuf_fp = getbuf_fp;
  cmgb->cms_send_fp   = send_fp;

  return (COMMSG_HAN)cmgb;
}

