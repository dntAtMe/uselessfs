#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

typedef struct {
    char *path;
    size_t pathlen;
    int disabled;
    int priority;
} replica_t;

struct uselessfs_config {
    char *mountpoint;
    replica_t *replicas;
};

int main() {
    int fd = open("config/template.cfg", O_RDONLY);
    int code;
    char buffer[20];
    memset(buffer, 0x00, 20);
    while (1){
        code = read(fd, &buffer, 1); 
	if (!code)
		break;
	printf("code: %d ", code);
	printf("%s\n", buffer);
    	sleep(1);
    }

    return 0;
}
