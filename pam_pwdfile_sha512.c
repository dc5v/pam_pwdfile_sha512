#ifdef USE_CRYPT_R
#define _GNU_SOURCE
#include <crypt.h>
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "sha512_crypt.h"

static int lock_fd(int fd)
{
  int delay;

  for (delay = 5; delay <= 40; delay *= 2)
  {
    if (flock(fd, LOCK_SH | LOCK_NB) == -1)
    {
      /* throw exception - failed */
      if (errno != EWOULDBLOCK)
      {
        goto failed;
      }

      sleep(delay);
    }
    else
    {
      return 0;
    }
  }

  if (flock(fd, LOCK_SH | LOCK_NB) != -1)
  {
    return 0;
  }

failed:
  return -1;
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i;
  const char *name;
  const char *password;
  const char *pwdfilename = NULL;
  const char *stored_crypted_password = NULL;
  char *crypted_password;
  FILE *pwdfile;
  int use_flock = 0;
  int use_delay = 1;
  int debug = 0;
  char *linebuf = NULL;
  size_t linebuflen;

#ifdef USE_CRYPT_R
  struct crypt_data crypt_buf;
#endif

  for (i = 0; i < argc; ++i)
  {
    if (!strcmp(argv[i], "pwdfile") && i + 1 < argc)
    {
      pwdfilename = argv[++i];
    }
    else if (!strncmp(argv[i], "pwdfile=", strlen("pwdfile=")))
    {
      pwdfilename = argv[i] + strlen("pwdfile=");
    }
    else if (!strcmp(argv[i], "flock"))
    {
      use_flock = 1;
    }
    else if (!strcmp(argv[i], "noflock"))
    {
      use_flock = 0;
    }
    else if (!strcmp(argv[i], "nodelay"))
    {
      use_delay = 0;
    }
    else if (!strcmp(argv[i], "debug"))
    {
      debug = 1;
    }
  }

#ifdef HAVE_PAM_FAIL_DELAY
  if (use_delay)
  {
    if (debug)
    {
      pam_syslog(pamh, LOG_DEBUG, "Setting delay");
    }

    (void)pam_fail_delay(pamh, 2000000); /* 2 sec */
  }
#endif

  if (!pwdfilename)
  {
    pam_syslog(pamh, LOG_ERR, "Passphrase filename not specified");

    return PAM_AUTHINFO_UNAVAIL;
  }

  if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "Can not get username from PAM stack");

    return PAM_AUTH_ERR;
  }

  if (debug)
  {
    pam_syslog(pamh, LOG_DEBUG, "Username : %s", name);
  }

  if (!(pwdfile = fopen(pwdfilename, "r")))
  {
    pam_syslog(pamh, LOG_ALERT, "Can not open passphrase file : %s", pwdfilename);

    return PAM_AUTHINFO_UNAVAIL;
  }

  if (use_flock && lock_fd(fileno(pwdfile)) == -1)
  {
    pam_syslog(pamh, LOG_ALERT, "Failed to lock passphrase file : %s", pwdfilename);

    fclose(pwdfile);
    return PAM_AUTHINFO_UNAVAIL;
  }

  while (getline(&linebuf, &linebuflen, pwdfile) > 0)
  {
    char *nexttok = linebuf;

    char *curtok = strsep(&nexttok, ":");

    if (strcmp(curtok, name))
    {
      continue;
    }

    if ((curtok = strsep(&nexttok, ":\n")))
    {
      stored_crypted_password = curtok;
      break;
    }
  }

  fclose(pwdfile);

  if (!stored_crypted_password)
  {
    if (debug)
    {
      pam_syslog(pamh, LOG_ERR, "User not found in passphrase file");
    }

    free(linebuf);
    return PAM_USER_UNKNOWN;
  }

  if (stored_crypted_password && !strlen(stored_crypted_password))
  {
    if (debug)
    {
      pam_syslog(pamh, LOG_DEBUG, "User passphrase not set : %s", name);
    }

    free(linebuf);
    return flags & PAM_DISALLOW_NULL_AUTHTOK ? PAM_AUTH_ERR : PAM_SUCCESS;
  }

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS)
  {
    pam_syslog(pamh, LOG_ERR, "Couldn't get password from PAM stack");

    free(linebuf);
    return PAM_AUTH_ERR;
  }

  if (!stored_crypted_password)
  {
    free(linebuf);
    return PAM_USER_UNKNOWN;
  }

  if (debug)
  {
    pam_syslog(pamh, LOG_DEBUG, "Crypted password : '%s'", stored_crypted_password);
  }

#ifdef USE_CRYPT_R
  crypt_buf.initialized = 0;

  if (!(crypted_password = crypt_r(password, stored_crypted_password, &crypt_buf)))
#else
  if (!(crypted_password = crypt(password, stored_crypted_password)))
#endif
  {
    pam_syslog(pamh, LOG_ERR, "crypt() failed");

    free(linebuf);
    return PAM_AUTH_ERR;
  }

  if (strcmp(crypted_password, stored_crypted_password))
  {
    pam_syslog(pamh, LOG_NOTICE, "Wrong passphrase : %s", name);

    free(linebuf);
    return PAM_AUTH_ERR;
  }

  if (debug)
  {
    pam_syslog(pamh, LOG_DEBUG, "Hello : %s", name);
  }

  free(linebuf);

  return PAM_SUCCESS;
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
    "pam_pwdfile",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
