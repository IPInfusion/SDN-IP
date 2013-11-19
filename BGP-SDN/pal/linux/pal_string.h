/*  Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */

/* pal_string.h -- BGP-SDN PAL definitions for string management */

#ifndef _PAL_STRING_H
#define _PAL_STRING_H

struct lib_globals;

/* API definition.  */
#include "pal_string.def"

#undef pal_snprintf
#define pal_snprintf snprintf

#undef pal_vsnprintf
#define pal_vsnprintf vsnprintf

#undef pal_sprintf
#define pal_sprintf sprintf

#undef pal_sscanf
#define pal_sscanf sscanf

#undef pal_strcpy
#define pal_strcpy strcpy

#undef pal_strncpy
#define pal_strncpy strncpy

/* pal_strdup implementation is in the pal_memory.c file */

#undef pal_strcat
#define pal_strcat strcat

#undef pal_strncat
#define pal_strncat strncat

#undef pal_strcmp
#define pal_strcmp strcmp

#undef pal_strncmp
#define pal_strncmp strncmp

#undef pal_strcasecmp
#define pal_strcasecmp strcasecmp

#undef pal_strncasecmp
#define pal_strncasecmp strncasecmp

#undef pal_strlen
#define pal_strlen strlen

#undef pal_strto32
#define pal_strtos32(x,y,z) strtol((char*)x,(char**)y,z)

#undef pal_strtou32
#define pal_strtou32(x,y,z) strtoul((char*)x,(char**)y,z)

#undef pal_strchr
#define pal_strchr strchr

#undef pal_strstr
#define pal_strstr strstr

#undef pal_strrchr
#define pal_strrchr strrchr

#undef pal_strspn
#define pal_strspn strspn

#undef pal_strerror
#define pal_strerror strerror

#undef pal_strtok
#define pal_strtok strtok

#undef pal_strtok_r
#define pal_strtok_r strtok_r

#undef pal_char_tolower
#undef pal_char_toupper
#define pal_char_tolower tolower
#define pal_char_toupper toupper

#undef pal_char_isspace
#undef pal_char_isdigit
#undef pal_char_isxdigit
#undef pal_char_isalpha
#undef pal_char_isalnum
#undef pal_char_isupper
#undef pal_char_islower
#define pal_char_isspace isspace
#define pal_char_isdigit isdigit
#define pal_char_isxdigit isxdigit
#define pal_char_isalpha isalpha
#define pal_char_isalnum isalnum
#define pal_char_isupper isupper
#define pal_char_islower islower
#define pal_char_isprint isprint

#undef pal_gai_strerror
#define pal_gai_strerror gai_strerror


#endif /* _PAL_STRING_H */
