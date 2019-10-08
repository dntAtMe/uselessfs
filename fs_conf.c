#include <sys/stat.h>
#include <time.h>


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
