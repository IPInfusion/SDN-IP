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

#include <onion/codecs.h>

#include "../ctest.h"

void t01_codecs_base64_decode(){
	INIT_LOCAL();
	{
	/// Text from wikipedia. Leviathan by Hobbes.
	char *orig ="dGVzdDphYWE=";
	char *realtext="test:aaa";
	
	char *res=onion_base64_decode(orig, NULL);
	FAIL_IF_NOT_EQUAL_STR(res,realtext);
	free(res);
	}
	{
	/// Text from wikipedia. Leviathan by Hobbes.
	char *orig ="TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\n"
							"IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\n"
							"dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu\n"
							"dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\n"
							"ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=\n";
	char *realtext="Man is distinguished, not only by his reason, but by this singular passion from other animals,"
								 " which is a lust of the mind, that by a perseverance of delight in the continued and"
								 " indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
	
	int l;
	char *res=onion_base64_decode(orig, &l);
	//fprintf(stderr,"l %d len %ld\n",l,strlen(realtext));
	FAIL_IF_NOT_EQUAL(l,strlen(realtext));
	FAIL_IF_NOT_EQUAL_STR(res,realtext);
	free(res);
	}
	END_LOCAL();
}

void t02_codecs_base64_encode(){
	INIT_LOCAL();
	/// Text from wikipedia. Leviathan by Hobbes.
	char *orig ="TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\n"
							"IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\n"
							"dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu\n"
							"dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\n"
							"ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=\n";
	char *realtext="Man is distinguished, not only by his reason, but by this singular passion from other animals,"
								 " which is a lust of the mind, that by a perseverance of delight in the continued and"
								 " indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
		
	int l=strlen(realtext);
	char *res=onion_base64_encode(realtext, l);
	FAIL_IF_NOT_EQUAL(strlen(res),strlen(orig));
	FAIL_IF_NOT_EQUAL_STR(res,orig);
	free(res);

	END_LOCAL();
}

void t03_codecs_base64_encode_decode_10(){
	INIT_LOCAL();

	char text[11];
	int i,j;
	int l;
	for (i=0;i<10;i++){
		//memset(text,0,sizeof(text));
		for (j=0;j<i;j++)
			text[j]='1'+j;
		text[j]='\0';
		
		char *enc=onion_base64_encode(text, i);
		char *res=onion_base64_decode(enc, &l);
		//fprintf(stderr, "%s:%d Encoded '%s', is '%s', decoded as '%s'\n",__FILE__,__LINE__,text, enc, res);
		FAIL_IF_NOT_EQUAL(l,i);
		FAIL_IF( memcmp(res,text, l)!=0 );
		free(res);
		free(enc);
	}
	
	END_LOCAL();
}

void t04_codecs_base64_encode_decode(){
	INIT_LOCAL();

	char text[1025];
	int tlength=0;
	int i,j;
	int l;
	for (i=0;i<100;i++){
		tlength=1024*(rand()/((double)RAND_MAX));
		for (j=0;j<tlength;j++)
			text[j]=rand()&0x0FF;
		text[j]=0;
		char *enc=onion_base64_encode(text, tlength);
		char *res=onion_base64_decode(enc, &l);
		FAIL_IF_NOT_EQUAL(l,tlength);
		FAIL_IF( memcmp(res,text, l)!=0 );
		free(res);
		free(enc);
	}
	
	END_LOCAL();
}

// Just dont segfault
void t05_codecs_base64_decode_trash(){
	INIT_LOCAL();

	char text[1024];
	int tlength=0;
	int i,j;
	int l;
	for (i=0;i<100;i++){
		tlength=1024*(rand()/((double)RAND_MAX));
		for (j=0;j<tlength;j++)
			text[j]=rand()&0x0FF;
		text[j]=0;
		char *res=onion_base64_decode(text, &l);
		free(res);
	}
	
	END_LOCAL();
}

void t06_codecs_c_unicode(){
	INIT_LOCAL();
	
	const char *text="\302Hola!";
	char *res=onion_c_quote_new(text);
	
	FAIL_IF_NOT_STRSTR(res,"\\302");
	FAIL_IF_NOT_STRSTR(res,"\\302Hola!");
	
	free(res);
	
	text="€";
	res=onion_c_quote_new(text);
	
	FAIL_IF_NOT_STRSTR(text,"€");
	FAIL_IF_NOT_EQUAL_STR(res,"\"\\342\\202\\254\"");
	
	free(res);

	text="\377";
	res=onion_c_quote_new(text);
	
	FAIL_IF_NOT_EQUAL_STR(res,"\"\\377\"");
	
	free(res);

	END_LOCAL();
}


int main(int argc, char **argv){
	t01_codecs_base64_decode();
	t02_codecs_base64_encode();
	t03_codecs_base64_encode_decode_10();
	t04_codecs_base64_encode_decode();
	t05_codecs_base64_decode_trash();
	t06_codecs_c_unicode();
	
	END();
}

