/*
	Onion HTTP server library
	Copyright (C) 2010 David Moreno Montero

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 3.0 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not see <http://www.gnu.org/licenses/>.
	*/

#ifndef __ONION_HANDLER_OPACK__
#define __ONION_HANDLER_OPACK__

#include <onion/types.h>

#ifdef __cplusplus
extern "C"{
#endif

typedef void (*onion_opack_renderer)(onion_response *res);

/// Creates a opak handler.
onion_handler *onion_handler_opack(const char *path, onion_opack_renderer opack, unsigned int length);

#ifdef __cplusplus
}
#endif

#endif
