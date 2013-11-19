/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

/* pal_assert.h -- assert.  */
#ifndef _PAL_ASSERT_H
#define _PAL_ASSERT_H

#include <assert.h>

#include "pal_assert.def"

#undef pal_assert
#define pal_assert      assert

#endif /* _PAL_POSIX_H */
