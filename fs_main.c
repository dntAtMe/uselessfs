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
#include <errno.h>
#include "log.h"
#include "hash.c"
#include "md5.c"
#include <openssl/md5.h>

enum replica_status_t {CLEAN, DIRTY, INACTIVE};
enum replica_type_t {BLOCK, MIRROR};

typedef struct replica_config_t
{
    char **paths;
    size_t paths_size;
    enum replica_status_t status;
    enum replica_type_t type;
    uint8_t flags;
    uint8_t priority;
} replica_config_t;

replica_config_t *configs = NULL;

#define FLAG_USE_HAMMING 1
#define FLAG_USE_HAMMING_EXTRA_BIT 2
#define FLAG_USE_PARITY 4
#define FLAG_USE_CHECKSUM 8
#define FLAG_CORRECT_ERRORS 16 // not really needed as there are bits set for specific ECCs
#define FLAG_ATTACH_REDUNDANT 32
#define FLAG_RESTRICT_BLOCKS 64

unsigned short should_use_hamming(replica_config_t config)
{
    return config.flags & (FLAG_USE_HAMMING | FLAG_USE_HAMMING_EXTRA_BIT);
}

unsigned short should_attach_redundant(replica_config_t config)
{
    return config.flags & FLAG_ATTACH_REDUNDANT;
}

unsigned short should_restrict_blocksize(replica_config_t config)
{
    return config.flags & FLAG_RESTRICT_BLOCKS;
}

unsigned short should_correct_errors(replica_config_t config)
{
    return config.flags & FLAG_CORRECT_ERRORS;
} 

size_t calculate_hamming(unsigned char* parity_buf, off_t pos, char current_byte);

char getBit(char byte, int bit)
{
    return (byte >> bit) % 2;
}

hash_t *h;

char src1[]="/home/kpieniaz/private/uselessfs/test2";
char src2[]="/home/kpieniaz/private/uselessfs/test";
int replicas_cnt;

char* sources[] = {"/home/kpieniaz/private/uselessfs/test", "/home/kpieniaz/private/uselessfs/test2"};

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

	return 0;
}

/*
* Returns amount of files opened
*/
int block_replica_open(const char *path, struct fuse_file_info *fi, replica_config_t config, int *file_handlers, size_t number)
{
    for (int path_idx = 0; path_idx < config.paths_size; path_idx++)
    {
        char *full_path = xlate(path, config.paths[path_idx]);
    
        int val = open(full_path, fi->flags);
        if (val == -1)
            return val;
        file_handlers[number + path_idx] = val;
    }
    return config.paths_size;
}

/*
* Returns amount of files opened
*/
int mirror_replica_open(const char *path, struct fuse_file_info *fi, replica_config_t config, int *file_handlers, size_t number)
{
    char *full_path = xlate(path, config.paths[0]);
    
    int val = open(full_path, fi->flags);
    if (val == -1)
        return val;
    file_handlers[number] = val;
    return 1;
}

// TODO: fix freezes when hashmap filled, increase its' size to max opened file descriptors per process
static int do_open(const char *path, struct fuse_file_info *fi)
{
    // TODO: SET file_handlers size properly
    int *file_handlers = malloc(sizeof(int) * 100);
    int next_free_fh = 0;

    for (size_t i = 0; i < replicas_cnt; i++)
    {   
        int ret = 0;
        switch (configs[i].type)
        {
            case BLOCK:
            log_debug("[open] Block replica");
            ret = block_replica_open(path, fi, configs[i], file_handlers, next_free_fh);
            break;
            case MIRROR:
            log_debug("[open] Mirror replica");
            ret = mirror_replica_open(path, fi, configs[i], file_handlers, next_free_fh);
            break;
        }
        log_debug("[open] handler: %d", file_handlers[i]);
        if (ret == -1)
        {
            // Read error
        } else
        {
            next_free_fh += ret;
        }
    }
     
    uint64_t stamp = (uint64_t) time( NULL );
    hash_insert(h, stamp, file_handlers);
    fi->fh = stamp;
    log_debug("[open] file_handler: %d",*(hash_lookup(h, fi->fh)));
    return 0;
}


/* 
* TODO: different sizes
*/
int decode_hamming(char *buf, size_t size, char *parity_buf, int *damaged_buf, replica_config_t config)
{
    int c = 0;

    //P0 = D0 + D1 + D3 + D4 + D6
    //P1 = D0 + D2 + D3 + D5 + D6
    //P2 = D1 + D2 + D3 + D7
    //P3 = D4 + D5 + D6 + D7
    for (int i = 0; i < size; i++)
    {
        if (buf[i] == 0)
        {
            break;
        }
        char cur_byte = buf[i];
        char cur_shift = (i % 2 ? 4 : 0);
        char cur_parity = parity_buf[i/2] >> cur_shift;
        int c = 0;

        calculate_hamming(parity_buf, i, cur_byte);
        printf("par: %d cur_par %d\n", (parity_buf[i/2]), parity_buf[i/2] >> cur_shift);
        c |= (1 * getBit(cur_parity, 0)) ^ (parity_buf[i/2] & 0b0001);
        c |= (2 * getBit(cur_parity, 1)) ^ (parity_buf[i/2] & 0b0010);
        c |= (4 * getBit(cur_parity, 2)) ^ (parity_buf[i/2] & 0b0100);
        c |= (8 * getBit(cur_parity, 3)) ^ (parity_buf[i/2] & 0b1000);
        printf("c %d size %d %d \n", c, size, buf[i]);
    
        if (should_correct_errors(config) && c)
        { 
            int powered = 1;
            for (int pow = 0; pow <=  4; pow++)
            {
                if (powered == c)
                {
                    c ^= powered;
                    break;
                } else
                if (powered > c)
                {
                    buf[i] ^= 1 << (pow-2);
                    break;
                }
                powered *= 2;
            }
        }
        printf("c %d size %d %d \n", c, size, buf[i]);
    }
    
    return 0;
}

int block_replica_read(const char *path, char *buffer, size_t *size, off_t offset, struct fuse_file_info *fi, replica_config_t config, size_t number)
{
    // Read depending on our options
    int block_size = 4;
    int start_block = offset / block_size;
    int end_block = should_attach_redundant(config) ? config.paths_size - 1 : config.paths_size;
    int diff = offset % block_size;
    int total_read_bytes = 0;
    int total_size = *size;
    int ret = 0;

    for (int current_block = start_block; current_block < end_block; current_block++)
    {   
        printf("TEST\n");
        int i = current_block - start_block;
        if (current_block == start_block)
        {
            ret = pread(*(hash_lookup(h, fi->fh)+number + current_block), buffer + total_read_bytes, (block_size - diff), diff);
            *size -= (block_size - diff);
        } else 
        {
            int size_to_read = (*size > block_size ? block_size : *size);
            ret = pread(*(hash_lookup(h, fi->fh)+number + current_block), buffer + total_read_bytes, size_to_read, diff + (block_size * (i-1)));    
            *size -= size_to_read;
        }
        if (ret == -1)
        {
            // ERROR
        } else
        {
            total_read_bytes += ret;
        }
    }

    // Redundancy
    if (should_attach_redundant(config))
    {
        char *parity_buf = calloc(total_size, 1);
        //char *corrected_buf = calloc(total_size, 1);
        int *damaged_blocks = calloc(config.paths_size, sizeof(int));
        ret = pread(*(hash_lookup(h, fi->fh)+number + end_block), parity_buf, total_size, 0);
        if (ret == -1)
        {
            // Error
        }
        if (should_use_hamming(config))
        {
            ret = decode_hamming(buffer, total_size, parity_buf, damaged_blocks, config);
        }
        if (ret == -1)
        {
            // Errors detected
        } else if (ret == 0)
        {
            // Errors corrected
        }
    }

    return end_block - start_block;
}

int mirror_replica_read(const char *path, char *buffer, size_t *size, off_t offset, struct fuse_file_info *fi, replica_config_t config, size_t number)
{
    log_debug("[mirror_replica_read] Running");
	// Read all
    int ret = pread(*(hash_lookup(h, fi->fh)+number), buffer, *size, offset);
    // Check  if we read properly
    if (ret == -1)
    {
        // Error
    }
    *size -= ret;
    // Seperate data from redundant bytes
    // OR
    // read file from second tree for redundant bytes

    // Check if data matches redundant information (ecc, parity, checksums) 

    // If ok, return amount file handlers used (might be up to 2?)
    return 1;
}

// If read completely fails, mark replica as INACTIVE
// begin_size - size in the end contains amount of bytes read 
static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) 
{
	log_debug("[read] Running");
	log_debug("[read] Path: %s", path);
    //auto begin_size = size

    // Choose replica
    // Read
    // Handle errors
    // Return amount of read bytes
    log_debug("[read] size: %d offset: %d fh1: %d fh2: %d", size, offset, *(hash_lookup(h, fi->fh)), *(hash_lookup(h, fi->fh)+1));
    size_t size_to_read = size;
    int ret = 0;
    for (int i = 0; i < replicas_cnt; i++)
    {
        switch (configs[i].type)
        {
            case BLOCK:
                log_debug("[read] Reading block replica");
                ret = block_replica_read(path, buffer, &size_to_read, offset, fi, configs[i], i);
            break;
            case MIRROR:
                log_debug("[read] Reading mirror replica");
                ret = mirror_replica_read(path, buffer, &size_to_read, offset, fi, configs[i], i);
            break;
        }
        
        switch (ret)
        {
            // Read failed, check errno
            case -1:
                log_debug("[read] Error when reading -1");
            break;
            // Found damaged data
            case -2:
                log_debug("[read] Error when reading -2");
            break;
            case -3:
                log_debug("[read] Error when reading -3");
            break;
            // All ok, returns amount of bytes read
            default:
                log_debug("[read] Reading done");
                return size - size_to_read;
            break;
        }
    }

    // Return whole size but parts we didnt read
    return size - size_to_read;
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
    int *fhs = hash_lookup(h, fi->fh);
    for (int i = 0; i < replicas_cnt; i++)
    {
        int val = close(fhs[i]);
        if (val == -1)
        {
            // Error
        }
    }
    hash_delete(h, fi->fh);
    log_debug("[release] %d", fhs[0]);
    free(fhs);
    log_debug("[release] %d", fhs[0]);
    return 0;
}

/* 
 * TODO: greater Hamming code sizes
 */
size_t calculate_hamming(unsigned char* parity_buf, off_t pos, char current_byte)
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
    
    return 4; 
}

int calc_md5(char *path, char *buffer)
{
    buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));

    FILE *in_file = fopen(path, "rb");
    MD5_CTX md_context;
    int bytes;
    unsigned char data[1024];
    if (in_file == NULL)
    {
        printf("%s can't be opened.\n", path);
        return 0;
    }

    MD5_Init(&md_context);
     while ((bytes = fread (data, 1, 1024, in_file)) != 0)
        MD5_Update (&md_context, data, bytes);
    MD5_Final (buffer,&md_context);
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", buffer[i]);
    printf (" %s\n", path);
    fclose (in_file);
    return 0;
}

/*
* 0000 ABCD
* A - when set, write redundant bytes to last block 
*     when not set, attach redundant bytes to buf
* D - when set, use Hamming code for correction
*/
int block_replica_write(const char *path, const char *buf, size_t *size,
		    off_t offset, struct fuse_file_info *fi, replica_config_t config, int curnumber)
{
    // Calculate redundancy
    unsigned char* parity_buf = (unsigned char*) calloc(*size, 1);
    size_t parity_size = 0;
    if (should_use_hamming(config))
    { 
        for (int i=0;i<*size;i++)
        {
            char current_byte = buf[i];
            parity_size += calculate_hamming(parity_buf, i, current_byte);  
        }
    }
    
    // Write depending on our options
    int block_size = 4;
    int start_block = offset / block_size;
    int end_block = should_attach_redundant(config) ? config.paths_size - 1 : config.paths_size;
    int diff = offset % block_size;
    
    int total_written_bytes = 0;
    int ret = 0;

    for (int current_block = start_block; current_block < end_block; current_block++)
    {   
        printf("TEST\n");
        int i = current_block - start_block;
        if (current_block == start_block)
        {
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + current_block), buf + total_written_bytes, (block_size - diff), diff);
            *size -= (block_size - diff);
        } else 
        {
            int size_to_write = (*size > block_size ? block_size : *size);
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + current_block), buf + total_written_bytes, size_to_write, diff + (block_size * (i-1)));    
            *size -= size_to_write;
        }

        if (ret == -1)
        {
            // ERROR
        } else
        {
            total_written_bytes += ret;
        }
    }

    // Attach redundant information
    if (should_attach_redundant(config))
    {
        ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + end_block), parity_buf, parity_size, 0);

    }

    return end_block - start_block;
}
/*
* Calculate redundant bytes
* Save buffer to file(s)
*/
int mirror_replica_write(const char *path, const char *buf, size_t *size,
		    off_t offset, struct fuse_file_info *fi, replica_config_t config, int curnumber)
{
    unsigned char* parity_buf = (unsigned char*) calloc(*size, 1);
    for (int i=0;i<*size;i++)
    {
        char current_byte = buf[i];
        //P0 = D0 + D1 + D3 + D4 + D6
        //P1 = D0 + D2 + D3 + D5 + D6
        //P2 = D1 + D2 + D3 + D7
        //P3 = D4 + D5 + D6 + D7
        calculate_hamming(parity_buf, i, current_byte);  
       
    }
    int ret;
    ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber), buf, *size, offset);
    if (ret == -1)
    {
        return -1;
    }
    ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber), parity_buf, *size/2, offset + *size); 
    if (ret == -1)
    {
        return -1;
    }
    log_debug("buf: %s parity_buf: %s", buf, parity_buf);

    char *hash_buffer;
    calc_md5(xlate(path, config.paths[0]), hash_buffer);

    return 0;
}

static int do_write(const char *path, const char *buf, size_t size,
		    off_t offset, struct fuse_file_info *fi)
{
    /*
     * 1. Iterate over all replicas
     * 2. Change buffer depending on replica type
     * 3. Write to replica
     * 4. On error, mark as dirty
     */
    log_debug("[do_write] Running ");
    // Stores return value of writing function
    int val;
    size_t returned_size = size;
    for(int i = 0; i < replicas_cnt; i++)
    {
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_write] Mirror replica ");
                // Write to replica if usable 
                val = mirror_replica_write(path, buf, &returned_size, offset, fi, configs[i], i);      
            break;
            case BLOCK:
                log_debug("[do_write] Block replica ");
                // Write to replica if usable 
                val = block_replica_write(path, buf, &returned_size, offset, fi, configs[i], i);
            break;
        }
        // If failed, take action depending on value of errno (see man write(2))
        if (val == -1)
        {
            switch(errno)
            {
                case EBADF:
                        
                        break;
            }
        }
        // Mark replica as dirty
        configs[i].status = DIRTY;
    }
   
    return size - returned_size;
}

int block_replica_create(const char *path, mode_t mode, struct fuse_file_info *fi, replica_config_t config, size_t number)
{
    
}

int mirror_replica_create(const char *path, mode_t mode, struct fuse_file_info *fi, replica_config_t config, size_t number)
{
    
}

// Create and open
static int do_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    log_debug("[do_create] Running ");
    // Stores return value of writing function
    int val;
    for(int i = 0; i < replicas_cnt; i++)
    {
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_write] Mirror replica ");
                val = mirror_replica_create(path, mode, fi, configs[i], i);      
            break;
            case BLOCK:
                log_debug("[do_write] Block replica ");
                val = block_replica_create(path, mode, fi, configs[i], i);
            break;
        }
        if (val == -1)
        {
            switch(errno)
            {
                case EBADF:
                        
                        break;
            }
        }
    }
}


static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .read = do_read,
    .create = do_create,

    .open = do_open,
    .write = do_write,
    .truncate = do_truncate,
    .chown = do_chown,
    .chmod = do_chmod,
    .flush = NULL,
    .release = do_release
};

int main(int argc, char* argv[]) {
    h = hash_new(15);
    char** fuse_argv = calloc(argc, sizeof(char*)); 
    int fuse_argv_c = 1;
    int replica_configs_c = 0;
    fuse_argv[0] = argv[0];
    if (argc < 2)
    {
        printf("Need arguments \n");
    }
    for (int curarg = 1; curarg < argc; curarg++)
    {
        printf("%s\n", argv[curarg]);
        if (!strcmp(argv[curarg], "--number") )
        {
            printf(  "ENTER %s\n", argv[curarg]);
            replicas_cnt = (int) strtol(argv[curarg+1], (char**) NULL, 10);
            configs = calloc(replicas_cnt, sizeof(replica_config_t));
            curarg++;
            continue;
        } else if (!strcmp(argv[curarg], "--block-replica") )
        {
            int blocks_cnt = (int) strtol(argv[curarg+1], (char**) NULL, 10);
            int flags = (int) strtol(argv[curarg+2], (char**) NULL, 2);
            configs[replica_configs_c].paths = calloc(blocks_cnt, sizeof(char*));
            configs[replica_configs_c].paths_size = blocks_cnt;
            
            for (int i = 0; i < blocks_cnt; i++)
            {
                char *curpath = argv[curarg+3+i];
                if (curpath[0] != '/')
                {
                    char *envpath = getenv("PWD");
                    strncat(envpath, "/", 1);
                    curpath = xlate(curpath, envpath);
                }
                configs[replica_configs_c].paths[i] = curpath;
                printf("Replica %d: %s\n", i, configs[replica_configs_c].paths[i]);
            }
            configs[replica_configs_c].status = CLEAN;
            configs[replica_configs_c].type = BLOCK;
            configs[replica_configs_c].flags = flags;
            configs[replica_configs_c].priority = 0;
            printf("Replica: %s\n", argv[4]);
            replica_configs_c++;
            curarg+= 2 + blocks_cnt;
            continue;
        } else if (!strcmp(argv[curarg], "--mirror-replica") )
        {
            char* curpath = argv[curarg+1];
            // Absolute path
            if (curpath[0] != '/')
            {
                char *envpath = getenv("PWD");
                strncat(envpath, "/", 1);
                curpath = xlate(curpath, envpath);
            }
            configs[replica_configs_c].paths = calloc(1, sizeof(char*));
            configs[replica_configs_c].paths[0] = curpath;
            configs[replica_configs_c].paths_size = 1;
            
            configs[replica_configs_c].status = CLEAN;
            configs[replica_configs_c].type = MIRROR;
            configs[replica_configs_c].flags = 0b00000001;
            configs[replica_configs_c].priority = 0;
            printf("Replica: %s\n", configs[replica_configs_c].paths[0]);
            printf("Replica: %s\n", argv[4]);
            replica_configs_c++;
            curarg++;
            continue;
        }
        else
        {
            fuse_argv[fuse_argv_c++] = argv[curarg];
        }

    }

	return fuse_main(fuse_argv_c, fuse_argv, &operations, NULL);
}
