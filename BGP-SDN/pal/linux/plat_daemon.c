/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved.*/

#include "pal.h"
#include "sys/resource.h"

/*
** Daemonize a process
**
** Parameters:
**   u_int16_t dont_change_dir
**   u_int16_t dont_close_files
**
** Results:
**   RESULT_OK for success, -ve for error
*/
result_t
pal_daemonize (u_int16_t nochdir, u_int16_t noclose)
{
  pid_t pid;

  pid = fork ();

  /* In case of fork is error. */
  if (pid < 0)
    {
      perror ("fork");
      return -1;
    }

  /* In case of this is parent process. */
  if (pid != 0)
    exit (0);

  /* Become session leader and get pid. */
  pid = setsid();

  if (pid < -1)
    {
      perror ("setsid");
      return -1;
    }

  /* Change directory to root. */
  if (! nochdir)
    (void) chdir ("/");

  /* File descriptor close. */
  if (! noclose)
    {
      int fd;

      fd = open ("/dev/null", O_RDWR, 0);
      if (fd != -1)
        {
          dup2 (fd, STDIN_FILENO);
          //dup2 (fd, STDOUT_FILENO);
          dup2 (fd, STDERR_FILENO);
          if (fd > 2)
            close (fd);
        }
    }

  umask (0027);

  return 0;
}

/*
** Spawn a program as a daemon process from a running process.
** To be used in cases where daemons are spawned from a ever-lasting process.
**
** Parameters:
**   char *program_name
**   char **argv (List of arguments to the program. Last argument has to
**                to be null).
**
** Results:
**   RESULT_OK for success, -ve for error
*/
result_t
pal_daemonize_program (char *program, 
                       char **argv, 
                       u_int16_t nochdir, 
                       u_int16_t noclose)
{
  pid_t pid1, pid2;
  int status;
  int fd;

  if (( pid1 = fork()) < 0)
    return -1;
  else if (pid1 != 0)
    {
      do 
        {
          if (waitpid (pid1, &status, 0) == -1)
            return -1;
          else
            return RESULT_OK;
        }while(1);
    }
  else
    {
      struct rlimit res;
      int ret;

      if (!noclose)
        {
          res.rlim_max = 0;
          ret = getrlimit (RLIMIT_NOFILE, &res);
          if (ret < 0)
            {
              perror("getrlimit() failed\n");
              exit(1);
            }
          
          for (fd = 0; fd < res.rlim_max; fd++)
            close (fd);
        }

      /* Become the session leader. */
      setsid();

      if ((pid2 = fork()) < 0)
        return -1;
      else if (pid2 != 0)
        exit(0);

      /* Set umask. */
      umask(0027);

      /* Change root directory. */
      if (!nochdir)
        (void) chdir("/");

      /* File descriptor close. */
      if (! noclose)
        {
          int fd;
          
          fd = open ("/dev/null", O_RDWR, 0);
          if (fd != -1)
            {
              dup2 (fd, STDIN_FILENO);
              //dup2 (fd, STDOUT_FILENO);
              dup2 (fd, STDERR_FILENO);
              if (fd > 2)
                close (fd);
            }
        }
      
      execv (program, argv);
    }
  
  return RESULT_OK;
}

/* Bind process to vrf. */
int
pal_vrf_pid_set (fib_id_t fib_id, pid_t pid)
{
#ifdef HAVE_MULTIPLE_FIB
  unsigned int pid_vrf[2] = {pid, fib_id};
  int fd, ret;

  /* Open socket. */
  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    return -1;

  ret = ioctl (fd, SIOCSPIDVRF, pid_vrf);
  if (ret < 0)
    return -1;
#endif /* HAVE_MULTIPLE_FIB */

  return 0;
}

