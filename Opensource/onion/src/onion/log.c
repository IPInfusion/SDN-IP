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

#include <stdio.h>
#include <stdarg.h>
#include <libgen.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#ifdef HAVE_PTHREADS
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#endif

#include "log.h"

static int onion_log_flags=0;
#ifdef HAVE_PTHREADS
static pthread_mutex_t onion_log_mutex=PTHREAD_MUTEX_INITIALIZER;
#endif


void onion_log_syslog(onion_log_level level, const char *filename, int lineno, const char *fmt, ...);
void onion_log_stderr(onion_log_level level, const char *filename, int lineno, const char *fmt, ...);

/**
 * @short Logs a message to the log facility.
 * 
 * Normally to stderr, but can be set to your own logger or to use syslog.
 * 
 * It is actually a variable which you can set to any other log facility. By default it is to 
 * onion_log_stderr, but also available is onion_log_syslog.
 * 
 * @param level Level of log. 
 * @param filename File where the message appeared. Usefull on debug level, but available on all.
 * @param lineno Line where the message was produced.
 * @param fmt printf-like format string and parameters.
 */
void (*onion_log)(onion_log_level level, const char *filename, int lineno, const char *fmt, ...)=onion_log_stderr;

enum onion_log_flags_e{
	OF_INIT=1,
	OF_NOCOLOR=2,
	OF_NODEBUG0=4,
	OF_SYSLOGINIT=8,
};

/**
 * @short Logs to stderr.
 * 
 * It can be affected also by the environment variable ONION_LOG, with one or several of:
 * 
 * - "nocolor"  -- then output will be without colors.
 * - "syslog"   -- Switchs the logging to syslog. 
 * 
 * Also for DEBUG0 level, it must be explictly set with the environmental variable ONION_DEBUG0, set
 * to the names of the files to allow DEBUG0 debug info. For example:
 * 
 *   export ONION_DEBUG0="onion.c url.c"
 * 
 * It is thread safe.
 * 
 * When compiled in release mode (no __DEBUG__ defined), DEBUG and DEBUG0 are not compiled so they do
 * not incurr in any performance penalty.
 */
void onion_log_stderr(onion_log_level level, const char *filename, int lineno, const char *fmt, ...){
#ifdef HAVE_PTHREADS
	pthread_mutex_lock(&onion_log_mutex);
#endif
	if (!onion_log_flags){
		onion_log_flags=OF_INIT;
		const char *ol=getenv("ONION_LOG");
		if (ol){
			if (strstr("nocolor", ol))
				onion_log_flags|=OF_NOCOLOR;
			if (strstr("nodebug0", ol))
				onion_log_flags|=OF_NODEBUG0;
			if (strstr("syslog", ol)){ // Switch to syslog
				onion_log=onion_log_syslog;
				char tmp[256];
				
				va_list ap;
				va_start(ap, fmt);
				vsnprintf(tmp,sizeof(tmp),fmt, ap);
				va_end(ap);
				onion_log(level, filename, lineno, tmp);
				return;
			}
		}
	}
	
	filename=basename((char*)filename);
	
#ifdef __DEBUG__
	const char *debug0=getenv("ONION_DEBUG0");
	if ( (level==O_DEBUG0) && (!debug0 || !strstr(debug0, filename)) ){
		#ifdef HAVE_PTHREADS
			pthread_mutex_unlock(&onion_log_mutex);
		#endif
		return;
	}
#endif

	const char *levelstr[]={ "DEBUG0", "DEBUG", "INFO", "WARNING", "ERROR", "UNKNOWN" };
	const char *levelcolor[]={ "\033[34m", "\033[01;34m", "\033[0m", "\033[01;33m", "\033[31m", "\033[01;31m" };
	
	if (level>(sizeof(levelstr)/sizeof(levelstr[0]))-1)
		level=(sizeof(levelstr)/sizeof(levelstr[0]))-1;

#ifdef HAVE_PTHREADS
  int pid=(int)syscall(SYS_gettid);
  if (!(onion_log_flags&OF_NOCOLOR))
    fprintf(stderr, "\033[%dm[%06d]%s ",30 + (pid%7)+1, pid, levelcolor[level]);
  else
    fprintf(stderr, "[%06d] ", pid);
#else
  if (!(onion_log_flags&OF_NOCOLOR))
    fprintf(stderr,"%s",levelcolor[level]);


#endif
	char datetime[32];
	time_t t;
	t = time(NULL);
	strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", localtime(&t));
	
	fprintf(stderr, "[%s] [%s %s:%d] ", datetime, levelstr[level],  
					filename, lineno); // I dont know why basename is char *. Please somebody tell me.
	
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (!(onion_log_flags&OF_NOCOLOR))
		fprintf(stderr, "\033[0m\n");
	else
		fprintf(stderr, "\n");
	#ifdef HAVE_PTHREADS
		pthread_mutex_unlock(&onion_log_mutex);
	#endif
}


/**
 * @short Performs the log to the syslog
 */
void onion_log_syslog(onion_log_level level, const char *filename, int lineno, const char *fmt, ...){
	char pri[]={LOG_DEBUG, LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR};

	if (level>sizeof(pri) || level <0)
		return;
	
	va_list ap;
	va_start(ap, fmt);
	vsyslog(pri[level], fmt, ap);
	va_end(ap);
}
