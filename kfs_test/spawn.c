#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>

#define PROCS 3
#define LEVELS 2

void sig_handler(int signum)
{
	printf("Received signal %d\n", signum);
	exit(signum);
}

int spawn_procs(int level)
{
	pid_t childpid[PROCS];
	int i = 0;
	if(level >= LEVELS-1)
	{
		return 0;
	}
		

	for(i=0;i < PROCS;i++)
	{
		childpid[i] = fork();
		
		if(childpid[i] >= 0)
		{
			if(childpid[i] == 0)
			{
				spawn_procs(level + 1);
			}
		}
		else
		{
			printf("Fork failed!!!\n");
			return 1;
		}
	}	
	return 0;
}

int main(void)
{

	signal(SIGINT, sig_handler);
	if(spawn_procs(0))
		return -1;

	while(1)
	{
		sleep(2);
	}

	return 0;
}