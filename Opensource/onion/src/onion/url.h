/*
	Onion HTTP server library
	Copyright (C) 2010-2011 David Moreno Montero

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

#ifndef __ONION_URL__
#define __ONION_URL__

#include "types.h"

#ifdef __cplusplus
extern "C"{
#endif

/// Creates an handler that checks that crrent path matches the current regexp, and passes to next.
onion_url *onion_url_new();
/// Frees the url data
void onion_url_free(onion_url *url);

/// Adds a simple handler, with no custom data
int onion_url_add(onion_url *url, const char *regexp, void *handler_f);
/// Adds a handler, with custom data
int onion_url_add_with_data(onion_url *url, const char *regexp, void *handler_f, void *data, void *datafree);
/// Adds a handler, using handler methods
int onion_url_add_handler(onion_url *url, const char *regexp, onion_handler *handler);
/// Addsa another url on this regexp
int onion_url_add_url(onion_url *url, const char *regexp, onion_url *handler);
/// Adds a simple handler, it has static data and a default return code
int onion_url_add_static(onion_url *url, const char *regexp, const char *text, int http_code);

/// Returns the related handler for this url
onion_handler *onion_url_to_handler(onion_url *url);

#ifdef __cplusplus
}
#endif

#endif
