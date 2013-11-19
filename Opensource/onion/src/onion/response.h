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

#ifndef __ONION_RESPONSE__
#define __ONION_RESPONSE__

#include "types.h"
#include <stdlib.h>

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @short This is a list of standard response codes.
 * 
 * Not all resposne codes are listed, as some of them may not have sense here.
 * Check other sources for complete listings.
 */
enum onion_response_codes_e{
	// OK codes
	HTTP_OK=200,
	HTTP_CREATED=201,
	HTTP_PARTIAL_CONTENT=206,
	HTTP_MULTI_STATUS=207,
	
	// Redirects
	HTTP_MOVED=301,
	HTTP_REDIRECT=302,
	HTTP_SEE_OTHER=303,
	HTTP_NOT_MODIFIED=304,
	HTTP_TEMPORARY_REDIRECT=307,
	
	// Not allowed to access
	HTTP_BAD_REQUEST=400,
	HTTP_UNAUTHORIZED=401,
	HTTP_FORBIDDEN=403,
	HTTP_NOT_FOUND=404,
	HTTP_METHOD_NOT_ALLOWED=405,
	
	// Error codes
	HTTP_INTERNAL_ERROR=500,
	HTTP_NOT_IMPLEMENTED=501,
	HTTP_BAD_GATEWAY=502,
	HTTP_SERVICE_UNAVALIABLE=503,
};


typedef enum onion_response_codes_e onion_response_codes;


/**
 * @short Possible flags.
 * 
 * These flags are used internally by the resposnes, but they can be the responses themselves of the handler when appropiate.
 */
enum onion_response_flags_e{
	OR_KEEP_ALIVE=4, 				/// Return when want to keep alive. Please also set the proper headers, specifically set the length. Otherwise it will block server side until client closes connection.
	OR_LENGTH_SET=2,				/// Response has set the length, so we may keep alive.
	OR_CLOSE_CONNECTION=1,	/// The connection will be closed when processing finishes.
	OR_SKIP_CONTENT=8,			/// This is set when the method is HEAD. @see onion_response_write_headers
	OR_CHUNKED=32,					/// The data is to be sent using chunk encoding. Its on if no lenght is set.
  OR_HEADER_SENT=0x0200,  /// The header has already been written. Its done automatically on first user write. Same id as OR_HEADER_SENT from onion_response_flags.
};

typedef enum onion_response_flags_e onion_response_flags;

/// Generates a new response object
onion_response *onion_response_new(onion_request *req);
/// Frees the memory consumed by this object. Returns keep_alive status.
int onion_response_free(onion_response *res);
/// Adds a header to the response object
void onion_response_set_header(onion_response *res, const char *key, const char *value);
/// Sets the header length. Normally it should be through set_header, but as its very common and needs some procesing here is a shortcut
void onion_response_set_length(onion_response *res, size_t length);
/// Sets the return code
void onion_response_set_code(onion_response *res, int code);
/// Gets the headers dictionary
onion_dict *onion_response_get_headers(onion_response *res);

/// @{ @name Write functions 
/// Writes all the header to the given fd
int onion_response_write_headers(onion_response *res);
/// Writes some data to the response
ssize_t onion_response_write(onion_response *res, const char *data, size_t length);
/// Writes some data to the response. \0 ended string
ssize_t onion_response_write0(onion_response *res, const char *data);
/// Writes some data to the response. Using sprintf format strings.
ssize_t onion_response_printf(onion_response *res, const char *fmt, ...);
/// @}

/// Sets the writer to use on this response
void onion_response_set_writer(onion_response *res, onion_write write, void *socket);

/// Returns the write object.
onion_write onion_response_get_writer(onion_response *res);
/// Returns the writing handler, also known as socket object.
void *onion_response_get_socket(onion_response *res);

#ifdef __cplusplus
}
#endif

#endif
