/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved. */

#ifndef _BGPSDN_HOST_H
#define _BGPSDN_HOST_H

/* Max hostname length. */
#define MAX_HOSTNAME_LEN          64

/* Max enable password length */
#define HOST_MAX_PASSWD_LEN        8

/* Host Name set Successfully */
#define HOST_NAME_SUCCESS          0

/* Host Name Not found Error */
#define HOST_NAME_NOT_FOUND        3

/* Host Name Not Configured */
#define HOST_NAME_NOT_CONFIGURED   4

struct host;

/* Host callback function typedef. */
typedef int (*HOST_CALLBACK) (struct ipi_vr *);

/* Host structure to accumulate host information.  */
struct host
{
  /* Pointer to VR. */
  struct ipi_vr *vr;

  /* Hostname.  */
  char *name;

  /* Flags. */
  u_char flags;
#define HOST_PASSWORD_ENCRYPT           (1 << 0)
#define HOST_LOGIN                      (1 << 1)
#define HOST_LOGIN_LOCAL                (1 << 2)
#define HOST_ADVANCED_VTY               (1 << 3)
#define HOST_ADVANCED_VTYSH             (1 << 4)
#define HOST_CONFIG_READ_DONE           (1 << 5)

  /* System wide terminal lines. */
  int lines;

  /* Configuration file name.  */
  char *config_file;

  /* Configuration locking mechanism.  */
  void *config_lock;

  /* Password for VTY interface.  Not used by "line".  */
  char *password;
  char *password_encrypt;

  /* Enable password */
  char *enable;
  char *enable_encrypt;

  /* Banner configuration. */
  char *motd;

  /* Exec timeout. */
  u_int32_t timeout;

  /* IPv4 ACL for access-class. */
  char *aclass_ipv4;

#ifdef HAVE_IPV6
  /* IPv6 ACL for access-class. */
  char *aclass_ipv6;
#endif /* HAVE_IPV6 */

  /* User list. */
  struct list *users;

  /* Hostname callback function. */
  HOST_CALLBACK hostname_callback;

#ifdef HAVE_VRX
  int localifindex;
#endif /* HAVE_VRX */
};

struct host_user
{
  /* Username. */
  char *name;

  /* Flags. */
  u_char flags;
#define HOST_USER_FLAG_PRIVILEGED        (1 << 0)

  /* User privilege. */
  u_char privilege;

  /* User Login password. */
  char *password;

  /* User Login encrypto password. */
  char *password_encrypt;
};

enum user_callback_type
{
  USER_CALLBACK_UPDATE,
  USER_CALLBACK_DELETE,
  USER_CALLBACK_MAX
};


/* Host configuration macros.  */
#ifdef HAVE_CUSTOM1
#define HOST_CONFIG_READ_DELAY          0
#else /* HAVE_CUSTOM1 */
#define HOST_CONFIG_READ_DELAY          2
#endif /* HAVE_CUSTOM1 */

#define HOST_CONFIG_SET_READ_DONE(H)  SET_FLAG((H)->flags, HOST_CONFIG_READ_DONE)
#define HOST_CONFIG_READ_IS_DONE(H)   CHECK_FLAG((H)->flags, HOST_CONFIG_READ_DONE) != 0


#ifdef HAVE_IMI

#define HOST_CONFIG_START(Z, F, P)                                            \
    do {                                                                      \
      if ((Z)->protocol != IPI_PROTO_IMI)                                     \
        {                                                                     \
           ipi_vr_add_callback ((Z), VR_CALLBACK_CONFIG_READ,                 \
                                imi_client_send_config_request);              \
                                                                              \
           imi_client_create (Z, 0);                                          \
        }                                                                     \
    } while (0)

#define HOST_CONFIG_STOP(Z)                                                   \
    do {                                                                      \
      if ((Z)->protocol != IPI_PROTO_IMI)                                     \
        imi_client_delete (Z);                                                \
    } while (0)

#define HOST_CONFIG_VR_START(V)                                               \
    do {                                                                      \
        if ((V)->zg->protocol != IPI_PROTO_IMI)                               \
          {                                                                   \
            ipi_vr_add_callback ((V)->zg, VR_CALLBACK_CONFIG_READ,            \
                imi_client_send_config_request);                              \
                                                                              \
            THREAD_TIMER_ON ((V)->zg, (V)->t_config, host_config_read_event,  \
                (V), HOST_CONFIG_READ_DELAY);                                 \
          }                                                                   \
    } while (0)

#else /* HAVE_IMI */

#define HOST_CONFIG_START(Z, F, P)                                            \
    do {                                                                      \
      struct ipi_vr *_vr = ipi_vr_get_privileged (Z);                         \
                                                                              \
      host_startup_config_file_set (_vr, F);                                  \
                                                                              \
      vty_serv_sock (Z, P);                                                   \
                                                                              \
      ipi_vr_add_callback ((Z), VR_CALLBACK_CONFIG_READ, host_config_read);   \
                                                                              \
      THREAD_TIMER_ON ((Z), _vr->t_config, host_config_read_event,            \
                        _vr, HOST_CONFIG_READ_DELAY);                         \
    } while (0)

#define HOST_CONFIG_STOP(Z)

#define HOST_CONFIG_VR_START(V)                                               \
    do {                                                                      \
      host_startup_config_file_set (V, NULL);                                 \
                                                                              \
      ipi_vr_add_callback ((V)->zg, VR_CALLBACK_CONFIG_READ,                  \
                           host_config_read);                                 \
                                                                              \
      THREAD_TIMER_ON ((V)->zg, (V)->t_config, host_config_read_event,        \
                       (V), HOST_CONFIG_READ_DELAY);                          \
    } while (0)

#endif /* HAVE_IMI */



/* Prototypes.  */
struct host *host_new (struct ipi_vr *);
void host_free (struct host *);

int host_config_lock (struct host *, void *);
int host_config_unlock (struct host *, void *);

void host_config_file_set (struct ipi_vr *);
void host_startup_config_file_set (struct ipi_vr *, char *);
int host_config_read (struct ipi_vr *);
int host_config_read_event (struct thread *);

char *host_prompt (struct host *, struct cli *);

struct host_user *host_user_lookup (struct host *, char *);
struct host_user *host_user_get (struct host *, char *);
void host_user_delete (struct host *, char *);
void host_user_update (struct host *, char *, int, char *, char *);

int host_hostname_set (struct ipi_vr *, char *);
int host_hostname_unset (struct ipi_vr *, char *);
int host_hostname_set_callback (struct ipi_vr *, HOST_CALLBACK);

void host_default_cli_init (struct cli_tree *);
void host_cli_init (struct lib_globals *, struct cli_tree *);
void host_user_cli_init (struct cli_tree *);
#ifdef HAVE_VR
void host_vr_cli_init (struct cli_tree *);
int host_config_write_user_all_vr (struct cli *, struct host *);
int host_config_encode_user_all_vr (struct host *, cfg_vect_t *cv);
#endif /* HAVE_VR */
void host_init (struct ipi_vr *);
void host_vty_init (struct lib_globals *);
void host_vtysh_cli_init (struct cli_tree *);
int host_password_check (char *, char *, char *);

int host_service_write (struct cli *);
int host_service_encode (struct host *, cfg_vect_t *cv);
int host_config_write (struct cli *);
int host_config_encode (struct host *, cfg_vect_t *cv);

int host_config_start (struct lib_globals *, char *, u_int16_t);

void host_user_add_callback (struct lib_globals *, enum user_callback_type,
                             int (*func) (struct ipi_vr *,
                                          struct host_user *));

#endif /* _BGPSDN_HOST_H */
