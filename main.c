#define FUSE_USE_VERSION 31

#include <dirent.h>
#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

char *xlate(const char *fname, char *rpath)
{
	char *rname;
	int   rlen, flen;

	if (!rpath || !fname) {
		return NULL;
	}

	rlen = strlen(rpath);
	flen = strlen(fname);
	rname = malloc(1 + rlen + flen);
	if (rname) {
		strcpy(rname, rpath);
		strcpy(rname + rlen, fname);
	}
	printf("xlate %s\n", rname);
	return rname;
}

static int do_getattr( const char *path, struct stat *st ) {
	printf("[getattr] Running\n");
	printf("[getattr] Requested  path:%s\n", path);
	
/*
	st->st_uid = getuid();	
	st->st_gid = getgid();
	st->st_atime = time( NULL );
	st->st_mtime = time( NULL );

	if ( strcmp(path, "/") == 0 ) {
		printf("[getattr] Directory found");
		st->st_mode = __S_IFDIR | 0755;
		st->st_nlink = 2;
	} else {
		printf("[getattr] File found\n");
		st->st_mode = __S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;	
	}
*/	
	int res;
    	char* fpath;
	fpath = xlate(path, "/home/dntAtMe/code/fuse/uselessfs/test");
	printf("[getattr] Full path: %s\n", fpath);
	
    res = lstat(fpath, st);
	if (res == -1) {
		printf("[getattr] -1, Ending\n");
		return -errno;
	}
	
	printf("[getattr] End\n");
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct file_fuse_info *fi) {	
	DIR *dp = NULL;
	struct dirent *de;
	
	printf("[readdir] Running\n");
	printf("[readdir] Requested path: %s\n", path);
	
	char* fpath = xlate(path, "/home/dntAtMe/code/fuse/uselessfs/test");

	printf("[readdir] Full path: %s\n", fpath);

	dp = opendir(fpath);
	if (!dp) 
	{
        return -1;
	}

    seekdir(dp, offset);
    while ((de = readdir(dp)) != NULL)
    {
        if (filler(buffer, de->d_name, NULL, 0))
            break;
    }
    closedir(dp);

	//filler(buffer, ".", NULL, 0);
	//filler(buffer, "..", NULL, 0);
	//if(strcmp(path, "/") == 0) {
	//	filler(buffer, "file54", NULL, 0);
	//	filler(buffer, "file49", NULL, 0);
	//}

	return 0;
}

static int do_open(const char *path, struct fuse_file_info *fi)
{
    int fd = open(path, fi->flags);
    fi->fh = fd;
    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct file_fuse_info *fi) {
	printf("[read] Running\n");
	
	char file54text[] = "file54";
	char file49text[] = "\n\nfile49";	

	if( strcmp(path, "/file53") == 0 ) {
		memcpy(buffer, file54text + offset, size);
		return strlen(file54text) - offset;
	} else if( strcmp(path, "/file49") == 0 ) {
		memcpy(buffer, file49text + offset, size);
		return strlen(file49text) - offset;
	} else 
		return -1;
}

static int do_write(const char *path, const char *buf, size_t size,
		    off_t offset, struct fuse_file_info *fi)
{
    printf("[do_write] Running ");
    printf("[do_write] %s %d", path, fi->fh);

    return 0;
}



static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,
};

int main(int argc, char* argv[]) {
	return fuse_main(argc, argv, &operations, NULL);
}






