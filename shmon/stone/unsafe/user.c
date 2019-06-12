#include <string.h>

#ifndef __windows__
#include <pwd.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#endif

#ifndef __windows__
static char* user_fill_passwd_by_name(const char* name, struct passwd* pwd) {
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
        retcode = getpwnam_r(name, pwd, pool, psize, &result);
    } while (retcode == ERANGE);

        
    if (result == NULL) {
        free(pool);
        pool = NULL;
    }

    return pool;
}
#endif

size_t user_home_dir(const char* name, char* pool, size_t psize) {
    size_t dirsize = 0;

    if (name != NULL) {
#ifndef __windows__
        struct passwd pwd;
        char* buffer = user_fill_passwd_by_name(name, &pwd);
        
        if (buffer != NULL) {
            dirsize = strnlen(pwd.pw_dir, psize);
            strncpy(pool, pwd.pw_dir, dirsize);

            free(buffer);
        }
#endif
    }

    return dirsize;
}

