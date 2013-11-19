/*
	Onion HTTP server library
	Copyright (C) 2010 David Moreno Montero

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	*/

#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <onion/dict.h>
#include <onion/server.h>
#include <onion/request.h>
#include <onion/response.h>
#include <onion/handler.h>
#include <onion/log.h>
#include <onion/handlers/static.h>
#include <onion/handlers/path.h>

#include "../ctest.h"
#include <onion/url.h>

ssize_t mstrncat(char *a, const char *b, size_t l){
	strncat(a,b,l);
	return strlen(a);
}


void t00_server_empty(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	
	onion_request *req=onion_request_new(server, buffer, NULL);
	onion_server_write_to_request(server, req, "GET ",4);
	onion_server_write_to_request(server, req, "/",1);
	onion_server_write_to_request(server, req, " HTTP/1.1\r\n",11);
	onion_server_write_to_request(server, req, "\r\n",2);
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer,"404");
	
	onion_request_free(req);
	onion_server_free(server);
	
	END_LOCAL();
}

void t01_server_min(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_server_set_root_handler(server, onion_handler_static("Succedded", 200));
	
	onion_request *req=onion_request_new(server, buffer, NULL);
	onion_request_write(req, "GET ",4);
	onion_request_write(req, "/",1);
	onion_request_write(req, " HTTP/1.1\r\n",11);
	
	onion_request_write(req, "\r\n",2);
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 200 OK\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "\r\nContent-Length: 9\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");
	FAIL_IF_NOT_STRSTR(buffer, "\r\n\r\nSuccedded");
	
	onion_request_free(req);
	onion_server_free(server);
	
	END_LOCAL();
}

void t02_server_full(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_server_set_root_handler(server, onion_handler_static("Succedded", 200));
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1\r\nHeader-1: This is header1\r\nHeader-2: This is header 2\r\n"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 200 OK\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "\r\nContent-Length: 9\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");
	FAIL_IF_NOT_STRSTR(buffer, "\r\n\r\nSuccedded");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

void t03_server_no_overflow(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_server_set_root_handler(server, onion_handler_static("Succedded", 200));
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\nHeader-1: This is header1\nHeader-2: This is header 2\n"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.

	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 200 OK\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "\r\nContent-Length: 9\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");
	FAIL_IF_NOT_STRSTR(buffer, "\r\n\r\nSuccedded");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

void t04_server_overflow(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_server_set_root_handler(server, onion_handler_static("Succedded", 200));
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1\nHeader-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2 n Header-1: This is header1 n Header-2: This is header 2\n"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs. The last \n was not processed, as was overflowing.
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 200 OK\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "\r\nContent-Length: 9\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");
	FAIL_IF_NOT_STRSTR(buffer, "\r\n\r\nSuccedded");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}


int write_p(int *p, const char *data, unsigned length){
	return write(*p, data,length);
}

void t05_server_with_pipes(){
	INIT_LOCAL();
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)write_p);
	onion_server_set_root_handler(server, onion_handler_static("Works with pipes", 200));
	
	int p[2];
	int error=pipe(p);
	if (error){
		FAIL("Could not create pipe.");
		END_LOCAL();
	}
	
	onion_request *req=onion_request_new(server, &p[1], NULL);
#define S "GET / HTTP/1.1\n\n"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	
	close(p[1]);
	
	//fcntl(p[0],F_SETFL, O_NONBLOCK);
	
	// read from the pipe
	char buffer[1024];
	memset(buffer,0,sizeof(buffer)); // better clean it, because if this does not work, it might get an old value
	int r=read(p[0], buffer, sizeof(buffer));
	if (r<0){
		ONION_DEBUG("Read %d bytes",r);
		perror("Error");
	}
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer,"HTTP/1.1 200 OK\r\n");
	FAIL_IF_NOT_STRSTR(buffer,"Content-Length: 16\r\n");
	FAIL_IF_NOT_STRSTR(buffer,"\r\n\r\nWorks with pipes");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

onion_connection_status error_500(void *_, onion_request *req, onion_response *res){
	return OCS_INTERNAL_ERROR;
}

void t06_server_with_error_500(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_url *urls=onion_url_new();
	onion_server_set_root_handler(server, onion_url_to_handler(urls));
	onion_url_add(urls, "", error_500);
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs. The last \n was not processed, as was overflowing.
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 500 INTERNAL ERROR\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

onion_connection_status error_501(void *_, onion_request *req, onion_response *res){
	return OCS_NOT_IMPLEMENTED;
}

void t07_server_with_error_501(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	onion_url *urls=onion_url_new();
	onion_server_set_root_handler(server, onion_url_to_handler(urls));
	onion_url_add(urls, "", error_501);
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs. The last \n was not processed, as was overflowing.
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 501 NOT IMPLEMENTED");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

void t08_server_with_error_404(){
	INIT_LOCAL();
	char buffer[4096];
	memset(buffer,0,sizeof(buffer));
	
	onion_server *server=onion_server_new();
	onion_server_set_write(server, (onion_write)mstrncat);
	
	onion_request *req=onion_request_new(server, buffer, NULL);
#define S "GET / HTTP/1.1"
	onion_request_write(req, S,sizeof(S)-1); // send it all, but the final 0.
#undef S
	FAIL_IF_NOT_EQUAL_STR(buffer,"");
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs.
	onion_request_write(req, "\n",1); // finish this request. no \n\n before to check possible bugs. The last \n was not processed, as was overflowing.
	
	FAIL_IF_EQUAL_STR(buffer,"");
	FAIL_IF_NOT_STRSTR(buffer, "HTTP/1.1 404 NOT FOUND\r\n");
	FAIL_IF_NOT_STRSTR(buffer, "libonion");

	onion_request_free(req);
	onion_server_free(server);

	END_LOCAL();
}

int main(int argc, char **argv){
	t00_server_empty();
	t01_server_min();
	t02_server_full();
	t03_server_no_overflow();
	t04_server_overflow();
	t05_server_with_pipes();
	t06_server_with_error_500();
	t07_server_with_error_501();
	t08_server_with_error_404();
  
	END();
}

