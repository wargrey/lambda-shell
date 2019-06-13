#include <stdlib.h>

#ifdef __windows__
#include <stdio.h>
#include <windows.h> /* ld:library: (Advapi32 Ole32) */
#include <ShlObj.h>  /* ld:library: (Shell32) */
#include <Knownfolders.h>
#else
#include <sys/types.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#endif

#ifndef __windows__
static char* user_fill_passwd(const char* name, struct passwd* pwd) {
    struct passwd* result = NULL;
    char* pool = NULL;
    long psize = 0L;
    int retcode = 0;
    
    if ((psize = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
        psize = 1024L;
    }

    do {
        if (pool != NULL) {
            free(pool);
            psize = psize * 2L;
        }

        pool = (char*)malloc(psize);

        if ((name != NULL) && (strlen(name) > 0)) {
            retcode = getpwnam_r(name, pwd, pool, psize, &result);
        } else {
            retcode = getpwuid_r(geteuid(), pwd, pool, psize, &result);
        }
    } while (retcode == ERANGE);

    if (result == NULL) {
        free(pool);
        pool = NULL;
    }

    return pool;
}
#endif

F_LAMBDA size_t user_home_dir(const char* name, char* pool, size_t psize) {
	size_t dirsize = 0;

#ifdef __windows__
	HANDLE user = NULL;
	PWSTR homedir = NULL;
	BOOL user_ok = TRUE;
	
	if ((name != NULL) && (strlen(name) > 0)) {
		user_ok = LogonUserA(name, ".", NULL, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &user);
	}

	if (user_ok == TRUE) {
		HRESULT retcode = SHGetKnownFolderPath(&FOLDERID_Profile, KF_FLAG_DEFAULT, user, &homedir);

		if (retcode == S_OK) {
			dirsize = snprintf(pool, psize, "%S", homedir);

			if (dirsize >= psize) {
				dirsize = psize - 1;
			}

			CoTaskMemFree(homedir);
		} else {
			printf("%s: HRESULT: %d\n", name, retcode);
		}
	} else {
		printf("%s: errno: %ld\n", name, GetLastError());
	}
#else
    struct passwd pwd;
    char* buffer = user_fill_passwd(name, &pwd);
        
    if (buffer != NULL) {
        dirsize = strnlen(pwd.pw_dir, psize);
        strncpy(pool, pwd.pw_dir, dirsize);

        free(buffer);
    }
#endif

    return dirsize;
}
