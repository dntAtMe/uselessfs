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

#include "log.h"

char *src1 =  "/home/dntAtMe/code/fuse/uselessfs/test";
char *src2 =  "/home/dntAtMe/code/fuse/uselessfs/test2";

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
	log_debug("xlate %s", rname);
	return rname;
}

static int do_getattr( const char *path, struct stat *st ) {
	log_debug("[getattr] Running");
	log_debug("[getattr] Requested  path:%s", path);
	
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
	fpath = xlate(path, src1);
	log_debug("[getattr] Full path: %s", fpath);
	
    res = lstat(fpath, st);
	if (res == -1) {
		printf("[getattr] -1, Ending");
		return -errno;
	}
	
	log_debug("[getattr] End");
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct file_fuse_info *fi) {	
	DIR *dp = NULL;
	struct dirent *de;
	
	log_debug("[readdir] Running");
	log_debug("[readdir] Requested path: %s", path);
	
	char* fpath = xlate(path, src1);

	log_debug("[readdir] Full path: %s", fpath);

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
    char *fpath = xlate(path, src1);

    int fd = open(fpath, fi->flags);
    fi->fh = fd;
    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
	log_debug("[read] Running");
	log_debug("[read] Path: %s", path);
    
    char *fpath = xlate(path, src1);
    log_debug("[read] Full path: %s", fpath);
    log_debug("[read] fi->fh: %d", fi->fh);

    return pread(fi->fh, buffer, size, offset);    
//	char file54text[] = "file54";
//	char file49text[] = "\n\nfile49";	
//
//	if( strcmp(path, "/file53") == 0 ) {
//		memcpy(buffer, file54text + offset, size);
//		return strlen(file54text) - offset;
//	} else if( strcmp(path, "/file49") == 0 ) {
//		memcpy(buffer, file49text + offset, size);
//		return strlen(file49text) - offset;
//	} else 
//		return -1;
}

static int do_chmod(const char *path, mode_t mode)
{
    char *fpath;

    fpath = xlate(path, src1);
    return chmod(fpath, mode);
}

static int do_chown(const char *path, uid_t uid, gid_t gid)
{
    char *fpath;
    
    fpath = xlate(path, src1);
    return chown(fpath, uid, gid);
}

static int do_truncate(const char *path, off_t size)
{
    char *fpath;

    fpath = xlate(path, src1);
    return truncate(fpath, size);

}

static int do_release(const char *path, struct fuse_file_info *fi)
{
    log_debug("[release] Starting");
    close(fi->fh);
    return 0;
}

static int do_write(const char *path, const char *buf, size_t size,
		    off_t offset, struct fuse_file_info *fi)
{
    log_debug("[do_write] Running ");
    log_debug("[do_write] %s %d", path, fi->fh);

    pwrite(fi->fh, buf, size, offset);

    return 0;
}



static struct fuse_operations operations = {
	.getattr = do_getattr,
	.readdir = do_readdir,
	.read = do_read,

    .open = do_open,
    .write = do_write,
    .truncate = do_truncate,
    .chown = do_chown,
    .chmod = do_chmod,
    .flush = NULL,
    .release = do_release
};

int main(int argc, char* argv[]) {
	return fuse_main(argc, argv, &operations, NULL);
}
