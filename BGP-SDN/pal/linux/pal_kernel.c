/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

/*
** pal_kernel.c -- BGP-SDN PAL kernel forwarding and interface control defs
**                 for Linux
*/

#include "pal.h"

#include "pal_kernel.h"
#include "pal_memory.h"

extern result_t kernel_init ();
extern void kernel_uninit ();
#ifdef HAVE_IPNET
extern int kernel_fib_create (fib_id_t fib, bool_t new_vr, char *fib_name);
extern int kernel_fib_delete (fib_id_t fib);
#endif /* HAVE_IPNET */

/*
** Start the kernel control manager.  This sets up any needed variables and
** hooks into the OS, and prepares the kernel for transactions, as appropriate.
** It is only called during startup.  The handle returned is stored in the
** library globals.  If this is called multiple times without an intervening
** stop, it must return the same handle.
**
** Parameters
**   none
**
** Results
**   A nonzero handle for success
**   NULL for failure
*/
result_t
pal_kernel_start (void)
{
  result_t ret;

  /* Initialize rt_netlink socket */
  ret = kernel_init ();
  if (ret < 0)
    return ret;

#ifndef HAVE_HYBRID_HAL_PAL_MODE
  ret = pal_kernel_if_scan ();
  if (ret < 0)
    return ret;

#ifdef HAVE_L3
  ret = pal_kernel_route_scan (0);
  if (ret < 0)
    return ret;
#endif /* HAVE_L3 */
#endif /* HAVE_HYBRID_HAL_PAL_MODE */

  return RESULT_OK;
}

/*!
** Stop the kernel control manager.  This finishes any pending transactions
** and shuts down the kernel control manager, breaking any previously
** created connections to the kernel or OS.  It also frees any resources
** allocated by the kernel control manager.  It is only called during the
** shutdown process.  The stops and starts must be balanced, so stop must be
** called the same number of times as start before the stop is committed.
**
** Parameters
**   none
**
** Results
**   RESULT_OK for success, else the error which occurred.
*/
result_t
pal_kernel_stop (void)
{
  kernel_uninit ();

  return RESULT_OK;
}

#ifdef HAVE_VRRP
/*
** Initialize the platform data for VRRP.
**
** Parameters
**
**
** Results
**  RESULT_Ok on success, else the error which occurred.
**
*/
result_t
pal_kernel_vrrp_start (struct lib_globals *lib_node)
{
  return plat_vrrp_init (lib_node);
}

/*
** Shutdown VRRP PAL.
**
** Parameters
**
** Results
**   RESULT_OK on success, else the error which occurred.
**
*/
result_t
pal_kernel_vrrp_stop (struct lib_globals *lib_node)
{
  return plat_vrrp_deinit (lib_node);
}

/*
** Send the provided gratuitous ARP message out the specified interface.
**
** Parameters:
**    IO struct lib_globals *lib_node   : Global variables
**    IO struct stream *s               : Gratuitous ARP message
**    IO struct interface *ifp          : Interface pointer
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_gratuitous_arp_send (struct lib_globals *lib_node,
                                struct stream *ap,
                                struct interface *ifp)
{
  return plat_vrrp_send_garp (lib_node, ap, ifp);
}

 
/*
** Send the application provided complete VRRP advertisement packet over
** specified interface.
**
** Parameters:
**    IO struct lib_globals *lib_node   : Global variables
**    IO struct stream *ap              : VRRP advert message
**    IO struct interface *ifp          : Interface pointer
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_vrrp_advert_send (struct lib_globals *lib_node,
                             struct stream *ap,
                             struct interface *ifp,
                             u_int8_t  af_type)
{
  return plat_vrrp_send_advert (lib_node, ap, ifp, af_type);
}


/*
** Register the VIP address to respond to ARP requests in promisc mode.
**
** Parameters:
**    IO struct pal_in4_addr *vip       : Virtual IP address
**    IO struct interface *ifp          : Interface pointer
**    IO bool_t owner                   : Owner status of this address
**    IO u_int8_t vrid                  : VRRP Virutal Router ID
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_virtual_ipv4_add (struct lib_globals *lib_node,
                             struct pal_in4_addr *vip,
                             struct interface *ifp,
                             bool_t owner,
                             u_int8_t vrid)
{
  result_t ret = RESULT_OK;
  ret = plat_vrrp_set_vip (lib_node, vip, ifp, vrid);

  return ret;
}

/*
** Deregister the VIP address.
**
** Parameters:
**    IO struct pal_in4_addr *vip       : Virtual IP address
**    IO struct interface *ifp          : Interface pointer
**    IO bool_t owner                   : Owner status of this address
**    IO u_int8_t vrid                  : VRRP Virutal Router ID
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_virtual_ipv4_delete (struct lib_globals *lib_node,
                                struct pal_in4_addr *vip,
                                struct interface *ifp,
                                bool_t owner,
                                u_int8_t vrid)
{
  result_t ret = RESULT_OK;
 
  ret = plat_vrrp_unset_vip (lib_node, vip, ifp, vrid);

  return ret;
}

result_t
pal_kernel_virtual_mac_add (struct lib_globals *zg,
                            u_int8_t vrid,
                            struct interface *ifp,
			    u_int8_t af_type)
{
  u_int8_t vmac[6];

  /* Setup the Virtual Mac Address */
  vmac[0] = (unsigned char) 0x00;
  vmac[1] = (unsigned char) 0x00;
  vmac[2] = (unsigned char) 0x5e;
  vmac[3] = (unsigned char) 0x00;
  vmac[4] = (unsigned char) 0x01;
#ifdef HAVE_IPV6
if (af_type == AF_INET6)
  vmac[4] = (unsigned char) 0x02;
#endif /* HAVE_IPV6 */
  vmac[5] = (unsigned char) vrid;

  return (plat_vrrp_add_vmac (zg, ifp, vmac, ifp->hw_addr_len));
}


result_t
pal_kernel_virtual_mac_delete (struct lib_globals *zg,
			       u_int8_t vrid,
			       struct interface *ifp,
			       u_int8_t af_type)
{
  u_int8_t vmac[6];

  /* Setup the Virtual Mac Address */
  vmac[0] = (unsigned char) 0x00;
  vmac[1] = (unsigned char) 0x00;
  vmac[2] = (unsigned char) 0x5e;
  vmac[3] = (unsigned char) 0x00;
  vmac[4] = (unsigned char) 0x01;
#ifdef HAVE_IPV6
if (af_type == AF_INET6)
  vmac[4] = (unsigned char) 0x02;
#endif /* HAVE_IPV6 */
  vmac[5] = (unsigned char) vrid;

  return (plat_vrrp_del_vmac (zg, ifp, vmac, ifp->hw_addr_len));
}



#ifdef HAVE_IPV6

result_t
pal_kernel_nd_nbadvt_send (struct lib_globals *lib_node,
                           struct stream *ap,
                           struct interface *ifp)
{
  return plat_vrrp_PF_send_neigh_advt (lib_node, ap, ifp);
}

/*
** A virtual IPV6 address has been added to the specified interface.
**
** Parameters:
**    IO struct pal_in6_addr *vip6      : Virtual IPV6 address
**    IO struct interface *ifp          : Interface pointer
**    IO bool_t owner                   : Owner status of this address
**    IO u_int8_t vrid                  : VRRP Virutal Router ID
**
** Results:
**    RESULT_OK for success, else error
*/

result_t
pal_kernel_virtual_ipv6_add (struct lib_globals *lib_node,
                             struct pal_in6_addr *vip6,
                             struct interface *ifp,
                             bool_t owner,
                             u_int8_t vrid)
{
  result_t ret = RESULT_OK;

  /* Add the IPV6 address to the interface iff NOT owner; else already there */
  if (owner == PAL_FALSE) {
    ret = plat_vrrp_set_vip6 (lib_node, vip6, ifp, vrid);
  }

  return ret;
}


/*
** A virtual IPV6 address has been deleted from the specified interface.
**
** Parameters:
**    IO struct pal_in6_addr *vip6      : Virtual IPV6 address
**    IO struct interface *ifp          : Interface pointer
**    IO bool_t owner                   : Owner status of this address
**    IO u_int8_t vrid                  : VRRP Virutal Router ID
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_virtual_ipv6_delete (struct lib_globals *lib_node,
                                struct pal_in6_addr *vip6,
                                struct interface *ifp,
                                bool_t owner,
                                u_int8_t vrid)
{
  result_t ret = RESULT_OK;

  /* Only remove IP addr if not owner */
  if (owner == PAL_FALSE) {
    ret = plat_vrrp_unset_vip6 (lib_node, vip6, ifp, vrid);
  }

  return ret;
}

#endif /* HAVE_IPV6 */



result_t
pal_kernel_get_vmac_status (struct lib_globals *lib_node)
{
  return plat_vrrp_get_vmac_status (lib_node);
}

result_t
pal_kernel_set_vmac_status (struct lib_globals *lib_node, int status)
{
  return plat_vrrp_set_vmac_status (lib_node, status);
}

#endif /* HAVE_VRRP */

/*
** This function is called to create a FIB in the forwarding plane for
** the provided fib-id.
**
** Parameters:
**    IO fib_id_t fib                   : ID for FIB to be created
**    IO bool_t new_vr                  : Flag to indicate if new VR is being created
**    IO char *fib_name                 : Name of the FIB
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_fib_create (fib_id_t fib, bool_t new_vr, char *fib_name)
{
#ifdef HAVE_MULTIPLE_FIB
  int sock, ret;

  PAL_UNREFERENCED_PARAMETER (new_vr);
  PAL_UNREFERENCED_PARAMETER (fib_name);
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return RESULT_ERROR;

  ret = ioctl (sock, SIOCADDVRF, fib);
  close (sock);

  if (ret < 0)
    return ret;
  else
    return RESULT_OK;
#endif /* HAVE_MULTIPLE_FIB */

#ifdef HAVE_IPNET
  return kernel_fib_create (fib, new_vr, fib_name);
#endif /* HAVE_IPNET */

  return RESULT_OK;
}

/*
** This function is called to delete a FIB in the forwarding plane for
** the provided fib-id.
**
** Parameters:
**    IO fib_id_t fib                   : ID for FIB to be deleted
**
** Results:
**    RESULT_OK for success, else error
*/
result_t
pal_kernel_fib_delete (fib_id_t fib)
{
#ifdef HAVE_MULTIPLE_FIB
  int sock, ret;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return RESULT_ERROR;

  ret = ioctl (sock, SIOCDELVRF, fib);
  close (sock);
  if (ret < 0)
    return ret;
  else
    return RESULT_OK;
#endif /* HAVE_MULTIPLE_FIB */

#ifdef HAVE_IPNET
  return kernel_fib_delete (fib);
#endif /* HAVE_IPNET */

  return RESULT_OK;
}

#ifdef HAVE_LSI
result_t pal_kernel_init (void)
{
  result_t ret;

  /* initialize rt_netlink socket */
  ret = kernel_init ();
  if (ret < 0)
    return ret;

  /* Enable forwarding in the native stack */
  ret = kernel_enable_fwd ();
  if (ret < 0)
    return ret;

  return RESULT_OK;
}
#endif
