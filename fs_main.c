#define FUSE_USE_VERSION 32

#include <dirent.h>
#include "./include/fuse3/fuse.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <math.h>

#include "log.h"

char* calc_parity(unsigned char* parity_buf, off_t pos, char current_byte);

char src1[]="/home/kwik/Code/uselessfs/workspace/replica1";
char src2[]="/home/kwik/Code/uselessfs/workspace/replica2";
int file_handlers[2];

const char* sources[] = {
    "/home/kwik/Code/uselessfs/workspace/replica1",
    "/home/kwik/Code/uselessfs/workspace/replica2",
};

char *xlate(const char *fname, const char *rpath)
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
	char *fpaths[] = {"", ""};

    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
    {
       char *tmp_path = xlate(path, sources[i]);
       fpaths[i] = (char*) malloc(strlen(tmp_path)+1);
       strcpy(fpaths[i],tmp_path); 
    }
    
	log_debug("[getattr] Full path: %s, %s", fpaths[0], fpaths[1]);

    struct stat *st1;
    struct stat st2;

    res = lstat(fpaths[0], st);
    res = lstat(fpaths[1], &st2);
    st->st_size+=st2.st_size;
	if (res == -1) {
		printf("[getattr] -1, Ending");
		return -errno;
	}
	
	log_debug("[getattr] End");
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {	
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
        if (filler(buffer, de->d_name, NULL, 0, FUSE_FILL_DIR_PLUS))
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

int testvar = 0;
static int do_open(const char *path, struct fuse_file_info *fi)
{
    char *fpaths[] = {"", ""};

    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
    {
       char *tmp_path = xlate(path, sources[i]);
       fpaths[i] = (char*) malloc(strlen(tmp_path)+1);
       strcpy(fpaths[i],tmp_path); 
    }
    
    file_handlers[0] = open(fpaths[0], fi->flags);
    file_handlers[1] = open(fpaths[1], fi->flags);
    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) 
{
	log_debug("[read] Running");
	log_debug("[read] Path: %s", path);
    
    log_debug("[read] size: %d offset: %d fh1: %d fh2: %d", size, offset, file_handlers[0], file_handlers[1]);
    int a2 = pread(file_handlers[0], buffer, size, offset);
    int a1 = pread(file_handlers[1], buffer + a2, size, offset);
    log_debug("[read] buffer: %s end a1: %d a2: %d", buffer, a1, a2);

    for (int i = 0; i < a2; i++)
    {
        unsigned char current_byte = buffer[i];
        unsigned char calculated_parity = 0x00;
        unsigned char proper_parity =( *(buffer+a2+i/2) >> (4 * ((i+1)%2) )) & 0x0f;

        calc_parity(&calculated_parity, 0, current_byte); 
        log_debug("[read] CALCULATED PARITY: %x", calculated_parity & 0x0f);
        log_debug("[read] PROPER PARITY: %x", proper_parity);
        
        unsigned char xored = (calculated_parity ^ proper_parity) & 0x0f;
        log_debug("[read] XORED: %x", xored);
        if (xored)
        {
            log_debug("[read] PROPER CHAR: %x", (int) current_byte + (int) pow(2.0, (double)xored - 1.0));
        }
    }
    return a1+a2;
}
// zapisywac na koniec parzystosc wtedy stat bez niej i link nawet powinien dzialc
static int do_chmod(const char *path,  mode_t mode)
{
    char *fpath;
    fpath = xlate(path, src1);
    
    log_debug("[chmod] Full path: %s", fpath);
    return chmod(fpath, mode);
}

static int do_chown(const char *path, uid_t uid, gid_t gid)
{
    char *fpath;
    fpath = xlate(path, src1);
    log_debug("[chown] Full path: %s", fpath);
    
    return chown(fpath, uid, gid);
}

static int do_truncate(const char *path, off_t size)
{
    char *fpath;
    fpath = xlate(path, src1);
    log_debug("[truncate] Full path: %s", fpath);
    
    return truncate(fpath, size);

}

static int do_release(const char *path, struct fuse_file_info *fi)
{
    log_debug("[release] Starting");
    close(fi->fh);
    return 0;
}


char getBit(char byte, int bit)
{
    return (byte >> bit) % 2;
}

/* 
 * Might need to make it compatible for greater Hamming code size later on
 *
 */
char* calc_parity(unsigned char* parity_buf, off_t pos, char current_byte)
{
        char p0, p1, p2, p3;
        p0 = getBit(current_byte, 0) ^ getBit(current_byte, 1) ^ getBit(current_byte, 3) ^ getBit(current_byte, 4) ^ getBit(current_byte, 6);
        p1 = getBit(current_byte, 0) ^ getBit(current_byte, 2) ^ getBit(current_byte, 3) ^ getBit(current_byte, 5) ^ getBit(current_byte, 6);
        p2 = getBit(current_byte, 1) ^ getBit(current_byte, 2) ^ getBit(current_byte, 3) ^ getBit(current_byte, 7);
        p3 = getBit(current_byte, 4) ^ getBit(current_byte, 5) ^ getBit(current_byte, 6) ^ getBit(current_byte, 7);

        parity_buf[pos/2] <<= 1;
        parity_buf[pos/2] |= p3;
        parity_buf[pos/2] <<= 1;
        parity_buf[pos/2] |= p2;
        parity_buf[pos/2] <<= 1;
        parity_buf[pos/2] |= p1;
        parity_buf[pos/2] <<= 1;
        parity_buf[pos/2] |= p0;
    
    return 0; 
}

static int do_write(const char *path, const char *buf, size_t size,
		    off_t offset, struct fuse_file_info *fi)
{
    log_debug("[do_write] Running ");
    log_debug("[do_write] %s %d", path,file_handlers[0]);
    
    unsigned char* parity_buf = (unsigned char*) calloc(size, 1);
    
    for (int i=0;i<size;i++)
    {
        char current_byte = buf[i];
        //P0 = D0 + D1 + D3 + D4 + D6
        //P1 = D0 + D2 + D3 + D5 + D6
        //P2 = D1 + D2 + D3 + D7
        //P3 = D4 + D5 + D6 + D7
        calc_parity(parity_buf, i, current_byte);  
       
        pwrite(file_handlers[0], buf + i, 1, offset + i);
        pwrite(file_handlers[1], parity_buf + i / 2, 1, offset + i / 2);
 
    }
    
   /*
     * foreach byte in bytes
     *  calculateHamming
     *  attachToBuffer
     * writeFromBuffer
     */
    log_debug("buf: %s parity_buf: %s", buf, parity_buf);
    return size*3/2;
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
