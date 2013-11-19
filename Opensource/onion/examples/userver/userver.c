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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <onion/onion.h>
#include <onion/handler.h>
#include <onion/log.h>

#include <onion/handlers/exportlocal.h>
#include <onion/handlers/static.h>

onion *o=NULL;

void free_onion(){
	ONION_INFO("Closing connections");
	onion_free(o);
	exit(0);
}

int req_handler(void *p, onion_request *req, onion_response *res)
{
	const char *path;

  	printf ("Receiving the request\n");

	if ((onion_request_get_flags(req) & OR_METHODS) == OR_GET) {
		printf ("GET: ");
    	}
  	else if ((onion_request_get_flags(req) & OR_METHODS) == OR_POST) {
		printf ("POST: ");
    	}
  	else if ((onion_request_get_flags(req) & OR_METHODS) == OR_DELETE) {
		printf ("DELETE: ");
    	} else {
		printf ("Unknown: ");
	}

	path = onion_request_get_path(req);

	printf ("%s\n", path);

	return OCS_PROCESSED;
}

int main(int argc, char **argv){
	int i;
  	onion_url *urls;
	char *port="8070";

	if (argc != 3) {
		printf("Usage: userver -p <port>\n");
		return 0;
	}

	for (i=1;i<argc;i++){
		if (strcmp(argv[i],"-p")==0){
			port=argv[++i];
		}
	}

	o=onion_new(O_THREADED|O_DETACH_LISTEN|O_SYSTEMD);
	
	onion_set_port(o, port);
	
	signal(SIGINT, free_onion);

	urls = onion_root_url(o);
        onion_url_add(urls, "^wm", req_handler);

	int error=onion_listen(o);
	if (error){
		perror("Cant create the server");
	}
	ONION_INFO("Detached. Printing a message every 120 seconds.");
	i=0;
	while(1){
		i++;
		ONION_INFO("Still alive. Count %d.",i);
		sleep(120);
	}
	
	onion_free(o);
	
	return 0;
}
