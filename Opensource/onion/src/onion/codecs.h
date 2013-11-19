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

#ifndef __ONION_CODECS__
#define __ONION_CODECS__


#ifdef __cplusplus
extern "C"{
#endif

/// Decodes a base64 into a new char* (must be freed later).
char *onion_base64_decode(const char *orig, int *length);

/// Encodes a byte array to a base64 into a new char* (must be freed later).
char *onion_base64_encode(const char *orig, int length);

/// Performs URL unquoting
void onion_unquote_inplace(char *str);

/// Performs URL quoting, memory is allocated and has to be freed.
char *onion_quote_new(const char *str);

/// Performs URL quoting, uses auxiliary res, with maxlength size. If more, do up to where I can, and cut it with \0.
int onion_quote(const char *str, char *res, int maxlength);

/// Performs C quotation: changes " for \". Usefull when sending data to be interpreted as JSON.
char *onion_c_quote_new(const char *str);

/// Performs the C quotation on the ret str. Max length is l.
char *onion_c_quote(const char *str, char *ret, int l);

#ifdef __cplusplus
}
#endif

#endif
