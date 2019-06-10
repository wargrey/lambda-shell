#include <stdio.h>
#include <string.h>

#define BASE 65521 /* largest prime smaller than 65536 */

unsigned long adler32_base() {
    return BASE;
}

unsigned long update_adler32(unsigned long adler, char *buf, int len) {
    unsigned long s1 = adler & 0xffff;
    unsigned long s2 = (adler >> 16) & 0xffff;
    int n;

    for(n = 0; n < len; n++) {
       s1 = (s1 + buf[n]) % BASE;
       s2 = (s2 + s1)     % BASE;
    }
    return (s2 << 16) + s1; /* the adler32 of the bytes buf[0..len-1] */
}

unsigned long adler32(char *buf, int len) {
    return update_adler32(1L, buf, len);
}
