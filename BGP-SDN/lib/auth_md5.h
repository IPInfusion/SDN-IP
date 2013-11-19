/* Copyright (C) 2013 IP Infusion, Inc. All Rights Reserved.  */

/*
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All rights
 * reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 */

#ifndef _BGPSDN_AUTH_MD5_H
#define _BGPSDN_AUTH_MD5_H

typedef struct
{
  u_int32_t state[4];
  u_int32_t count[2];
  unsigned char buffer[64];
} AUTH_MD5_CTX;

void auth_md5_init (AUTH_MD5_CTX *);
void auth_md5_update (AUTH_MD5_CTX *, const void *, unsigned int);
void auth_md5_final (u_char *, AUTH_MD5_CTX *);

void auth_md5_authenticator (u_char *);
void auth_hmac_md5 (u_char *, int, u_char *, int, u_char *);

#endif /* _BGPSDN_AUTH_MD5_H */
