#define _DEFAULT_SOURCE
#define FUSE_USE_VERSION 32

#include <dirent.h>
#include "./include/fuse3/fuse.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <math.h>
#include <errno.h>
#include "log.h"
#include <string.h>
#include "hash.c"
#include <fcntl.h>
#include <openssl/md5.h>

int do_mkdir (const char *path, mode_t mode);
int calculate_parity_byte(char c, char *buf);

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

#define FLAG_CORRECT_ERRORS 1
#define FLAG_USE_HAMMING_EXTRA_BIT 2
#define FLAG_USE_CHECKSUM 4
#define FLAG_ATTACH_REDUNDANCY 8 // 0 parity, 1 hamming
#define FLAG_ATTACH_TO_NEW 16
#define FLAG_INTERLACE_REDUNDANCY 32 // 0 parity, 1 hamming
#define FLAG_RESTRICT_BLOCKS 64
#define FLAG_USE_INTERLACING 128

unsigned short should_correct_errors(replica_config_t *config)
{
    return config->flags & FLAG_CORRECT_ERRORS;
}

unsigned short should_interlace(replica_config_t *config)
{
    return config->flags & FLAG_USE_INTERLACING;
}

unsigned short should_attach_to_new(replica_config_t *config)
{
    return config->flags & FLAG_ATTACH_TO_NEW;
}

unsigned short should_use_checksum(replica_config_t *config)
{
    return config->flags & FLAG_USE_CHECKSUM;
}

unsigned short should_use_hamming(replica_config_t *config)
{
    return config->flags & FLAG_ATTACH_REDUNDANCY || config->flags & FLAG_INTERLACE_REDUNDANCY;
}

unsigned short interlace_redundancy_method(replica_config_t *config)
{
    return config->flags & FLAG_INTERLACE_REDUNDANCY;
}

unsigned short should_restrict_blocksize(replica_config_t *config)
{
    return config->flags & FLAG_RESTRICT_BLOCKS;
}

unsigned short attach_redundancy_method(replica_config_t *config)
{
    return config->flags & FLAG_ATTACH_REDUNDANCY;
} 

size_t calculate_hamming(unsigned char* parity_buf, off_t pos, char current_byte);

char getBit(char byte, int bit)
{
    return (byte >> bit) % 2;
}

hash_t *h;
char *recovery_dir="/tmp";

int replicas_cnt;

/*
* Create an absolute path to a file
* @fname - File path in mountpoint
* @rpath - Path to replica
*/
char *xlate(const char *fname, const char *rpath, replica_config_t *config, int path_num)
{
    char *ptr;
    struct stat sb;
    char *tmpfolder; 
    
	if (!rpath || !fname) {
		return NULL;
	}


    if (stat(rpath, &sb) == 0) {
    } else {
        ptr = strrchr(rpath, '/');
        tmpfolder = malloc(4 + strlen(rpath));
        strcpy(tmpfolder, recovery_dir);
        strcpy(tmpfolder + 4, ptr);
        printf("[xlate] Replica doesn't exist anymore, switching to %s\n", tmpfolder);

        mkdir(tmpfolder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        config->paths[path_num] = strdup(tmpfolder);
        return tmpfolder;
    }

	int rlen = strlen(rpath);
	int flen = strlen(fname);
        
	char *rname = malloc(200);
    
    strcpy(rname, rpath);
    strcat(rname, fname);
    
	return rname;
}


int calc_md5(char *path, unsigned char *buffer, short skip_hash, int is_regular_file)
{
    if (!is_regular_file)
        return 1;
    FILE *in_file = fopen(path, "rb");
    MD5_CTX md_context;
    int bytes;
    unsigned char *data = calloc(1024, 1);
    if (in_file == NULL)
    {
        printf("%s can't be opened.\n", path);
        return -1;
    }

    MD5_Init(&md_context);
    if (skip_hash)
    {
        fread(data, 1, MD5_DIGEST_LENGTH, in_file);
    }
     while ((bytes = fread (data, 1, 1024, in_file)) != 0)
        MD5_Update (&md_context, data, bytes);
    MD5_Final (buffer,&md_context);
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", buffer[i]);
    printf (" %s\n", path);
    fclose (in_file);
    return 0;
}

int get_md5(char *path, unsigned char* md5, int is_regular_file)
{
    if (!is_regular_file)
        return 1;
    FILE *in_file = fopen(path, "rb");
    int bytes;
    if (in_file == NULL)
    {
        printf("%s can't be opened.\n", path);
        return -1;
    }

    fread (md5, 1, MD5_DIGEST_LENGTH, in_file);
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", md5[i]);

    fclose (in_file);
    return 0;
}

int write_new_block(char *path, unsigned char *checksum, char* buffer, size_t size, replica_config_t *config, int block)
{
    int ret;
    if (block == config->paths_size - 1 && attach_redundancy_method == 0) // Last parity block
    {
        FILE *fh = fopen(xlate(path, config->paths[block], config, block), "w");
        if (fh == NULL)
        {
            printf("%s can't be opened.\n", path);
            return 0;
        }
        for (int chk = 0; chk < MD5_DIGEST_LENGTH; chk++) fputc(checksum[chk], fh);
        
        for (int i = 0; i < size; i++)
        {
            if (!buffer[i])
            {
                break;
            }
            fputc(buffer[i], fh);
            if (ret == -1)
            {
                // Error
                return -errno;
            }
        }
        fclose(fh);
    } else // Any other block
    {
        unsigned char* parity_buf = (unsigned char*) calloc(size, 1);
        size_t parity_size = 0;
        if (should_use_hamming(config))
        { 
            for (int i=0;i<size;i++)
            {
                char current_byte = buffer[i];
                parity_size += calculate_hamming(parity_buf, i, current_byte);  
            }
        }

        FILE *fh = fopen(xlate(path, config->paths[block], config, block), "w");
        if (fh == NULL)
        {
            printf("%s can't be opened.\n", path);
            return 0;
        }
        for (int chk = 0; chk < MD5_DIGEST_LENGTH; chk++) fputc(checksum[chk], fh);
        
        for (int i = 0; i < size; i++)
        {
            if (should_interlace(config))
            {
                if (!buffer[i])
                {
                    break;
                }
                ret = fputc(buffer[i], fh);
                if (ret == -1)
                {
                    // Error
                    return -errno;
                }
                ret = fputc(parity_buf[i], fh);
                if (ret == -1)
                {
                    // Error
                    return -errno;
                }
            }
        }
        fclose(fh);
        return 0;
    }

    unsigned char *md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
    ret = calc_md5(xlate(path, config->paths[block], config, block), md5_buffer, 1, 1);
    if (ret)
    {
        free (md5_buffer);
        return ret;
    }
    ret = change_checksum(md5_buffer, xlate(path, config->paths[block], config, block)); 
    if (ret)
    {
        free (md5_buffer);
        return ret;
    }
    free (md5_buffer);
    return 0;
}

int write_new_file(char *path, unsigned char *checksum, char *data_buffer, size_t size, replica_config_t *config)
{
    if (config->type == BLOCK)
    {
            // Calculate redundancy
        unsigned char* parity_buf = (unsigned char*) calloc(size, 1);
        unsigned char* attach_parity_buf = (unsigned char*) calloc(size, 1);

        if (should_interlace(config)) // Use interlacing
        {
            if (config->flags & FLAG_INTERLACE_REDUNDANCY) // Interlace Hamming
            { 
                for (int i=0;i<size;i++)
                {
                    char current_byte = data_buffer[i];
                    calculate_hamming(parity_buf, i, current_byte);  
                }
            } else // Interlace parity
            {
                for (int i = 0; i < size; i++)
                {
                    calculate_parity_byte(data_buffer[i], parity_buf + i);
                }
            }
        }
        
        // Write depending on our options
        int block_size = 4;
        int last_block = attach_redundancy_method(config) ? config->paths_size : config->paths_size - 1;
        int start_block = 0;
        int current_block = start_block;
        int size_to_write = size;

        int total_written_bytes = 0;
        int ret = 0;

        FILE *fhs[config->paths_size];
        for (int i = 0; i < config->paths_size; i++)
        {
            fhs[i] = fopen(xlate(path, config->paths[i], config, i), "w");
            for (int chk = 0; chk < MD5_DIGEST_LENGTH; chk++) fputc(checksum[chk], fhs[i]);
            if (fhs[i] == NULL)
            {
                printf("%s can't be opened.\n", path);
                return 0;
            }
        }

        for (int i = 0; i < size_to_write; i++)
        {
            if (should_interlace(config))
            {
                if (!data_buffer[i])
                {
                    break;
                }
                ret = fputc(data_buffer[i], fhs[current_block]);
                if (ret == -1)
                {
                    // Error
                    return -errno;
                }
                ret = fputc(parity_buf[i], fhs[current_block]);
                if (ret == -1)
                {
                    // Error
                    return -errno;
                }
            }
            else
            {
                if (!data_buffer[i])
                {
                    break;
                }
                ret = fputc(data_buffer[i], fhs[current_block]);
                if (ret == -1)
                {
                    // Error
                    return -errno;
                }   
            }
            
            current_block++;
            current_block %= last_block;
        }

        if (attach_redundancy_method(config)) // Attach Hamming
        {

        } else // Attach parity
        {
            for (int i = 0; i < (size_to_write / last_block) - 1; i++)
            {
                attach_parity_buf[i] = 0x00;
                for (int j = 0; j < last_block; j++)
                {
                    attach_parity_buf[i] ^= data_buffer[last_block * i + j];

                }
            }
            for (int s = 0; s < size_to_write; s++)
            {
                if (!attach_parity_buf[s])
                    break;
                fputc(attach_parity_buf[s], fhs[config->paths_size - 1]);
            }
        }

        
        for (int i = 0; i < config->paths_size; i++)
        {
            fclose(fhs[i]);
        }

        for (int i = 0; i < config->paths_size; i++)
        {
            unsigned char *md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
            ret = calc_md5(xlate(path, config->paths[i], config, i), md5_buffer, 1, 1);
            if (ret)
            {
                return ret;
            }
            ret = change_checksum(md5_buffer, xlate(path, config->paths[i], config, i)); 
            if (ret)
            {
                return ret;
            }
        }

    } else
    if (config->type == MIRROR)
    {
        int ret;
        int size_to_write = size;

        char *fullpath = xlate(path, config->paths[0], config, 0);
        FILE *fh = fopen(fullpath, "w");
        for (int chk = 0; chk < MD5_DIGEST_LENGTH; chk++) fputc(checksum[chk], fh);

        unsigned char parity_buf = 0x00;

        for (int i=0;i<size_to_write;i++)
        {
            if (!data_buffer[i])
            {
                break;
            }
            if (should_interlace(config))
            {
                char current_byte = data_buffer[i];
                if (interlace_redundancy_method(config) == 1)
                {
                    calculate_hamming(&parity_buf, 0, current_byte);
                }
                else
                {
                    calculate_parity_byte(current_byte, &parity_buf);
                }
                ret = fputc(data_buffer[i], fh);
                if (ret == -1)
                {
                    free (fullpath);
                    return -1;
                }
                ret = fputc(parity_buf, fh); 
                if (ret == -1)
                {
                    free (fullpath);
                    return -1;
                }
            }
            else
            {
                ret = fputc(data_buffer[i], fh);
                if (ret == -1)
                {
                    free (fullpath);
                    return -1;
                }
            }
        }

        fclose(fh);

        unsigned char *md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
        ret = calc_md5(fullpath, md5_buffer, 1, 1);
        if (ret)
        {
            free (fullpath);
            free (md5_buffer);
            return ret;
        }
        ret = change_checksum(md5_buffer, xlate(path, config->paths[0], config, 0)); 
        if (ret)
        {
            free (fullpath);
            free (md5_buffer);
            return -1;
        }

        free (fullpath);
        free (md5_buffer);
        return 0;

    }
    
    return 0;
}

int correct_file(char *path, unsigned char* checksum,  char *buffer, unsigned char *parity_buffer, size_t size, replica_config_t *config)
{
        FILE *in_file = fopen(path, "r+");
        char ch;
        int i = 0;

        if (in_file == NULL)
        {
            printf("%s can't be opened.\n", path);
            return 0;
        }

        if (checksum)
        {
            while ((ch = fgetc(in_file)) != EOF && i < MD5_DIGEST_LENGTH)
            {
                fseek(in_file, -1, SEEK_CUR);
                fputc(checksum[i++],in_file);
                fseek(in_file, 0, SEEK_CUR);
            }
        }
        else 
        {
            fseek(in_file, MD5_DIGEST_LENGTH, SEEK_CUR);
        
            if (interlace_redundancy_method(config))
            {
                while ((ch = fgetc(in_file)) != EOF && i <= size)
                {
                    
-                   fseek(in_file, -1, SEEK_CUR);
                    fputc(buffer[i], in_file);
                    fputc(parity_buffer[i], in_file);
                    fseek(in_file, 0, SEEK_CUR);  
                    i++;
                }
            }
            fclose (in_file);
        }
    
    return 0;
}


int file_data_read(char *path, char *data_buf, size_t size, off_t offset, replica_config_t *config, int should_read_single_block)
{
    char ch;
    int ch_cnt = 0;

    if (config->type == BLOCK)
    {
        int p_size = attach_redundancy_method(config) ? config->paths_size : config->paths_size - 1;

        FILE *files[config->paths_size];

        for (int i = 0; i < config->paths_size; i++)
        {
            if (should_read_single_block != -1 && i != should_read_single_block)
                continue;
            char *fpath = xlate(path, config->paths[i], config, i);
            files[i] = fopen(fpath, "r+");
            printf("%s is being opened.\n", fpath);

            if (files[i] == NULL)
            {
                printf("%s can't be opened.\n", fpath);
                return 0; 
            }
            free(fpath);
            
            if (should_use_checksum(config))
            {
                // Skip checksum
                fseek(files[i], MD5_DIGEST_LENGTH, SEEK_CUR);
            }
        }

        if (should_read_single_block == config->paths_size - 1 && attach_redundancy_method(config) == 0)
        {
            while ((ch = fgetc(files[config->paths_size - 1])) != EOF)
            {
                data_buf[ch_cnt] = ch;
                ch_cnt++;    
            }
        } else
        {
            // Read data, depending on redundancy method
            if (should_interlace(config))
            {
                if (should_read_single_block == -1)
                {
                    while ((ch = fgetc(files[ch_cnt % p_size])) != EOF)
                    {
                        fgetc(files[ch_cnt % p_size]);
                        data_buf[ch_cnt] = ch;
                        ch_cnt++;
                    }
                } else
                {
                    while ((ch = fgetc(files[should_read_single_block])) != EOF)
                    {
                        fgetc(files[should_read_single_block]);
                        data_buf[ch_cnt] = ch;
                        ch_cnt++;
                    }
                }
            }
        }

        for (int i = 0; i < config->paths_size; i++)
        {
            if (should_read_single_block != -1 && i != should_read_single_block)
                continue;
            fclose(files[i]);
        }
    } else
    if (config->type == MIRROR)
    {
        char *fpath = xlate(path, config->paths[0], config, 0);
        FILE *fh = fopen(fpath, "r+");

        if (should_use_checksum(config)) // Skip checksum
        {
            fseek(fh, MD5_DIGEST_LENGTH, SEEK_CUR);
        }

        if (should_interlace(config))
        {
            while ((ch = fgetc(fh)) != EOF)
            {
                fgetc(fh);
                data_buf[ch_cnt] = ch;
                ch_cnt++;
            }
        } else
        {
            while ((ch = fgetc(fh)) != EOF)
            {
                data_buf[ch_cnt] = ch;
                ch_cnt++;
            }
        }
    }

    return 0;
}


int block_replica_getattr(const char *path, replica_config_t *config, int number, struct stat *st)
{
    int res = 0;
    struct stat *tmp_stat;
    // ENOENT - missing file
    int8_t errors_at[config->paths_size];
    struct stat stats[config->paths_size];
    size_t errors_cnt = 0;
    size_t missing_blocks = 0;
    unsigned int last_missing_block = 0;
    int is_regular_file;

    st->st_size = 0;

    for (int i = 0; i < config->paths_size; i++)
    {

        char *fpath = xlate(path, config->paths[i], config, i);

        res = lstat(fpath, stats + i);
        if (res == -1) 
        {
            free(fpath);
            printf("[getattr] ERROR CODE: -1, ERRNO: %d\n", errno);
                errors_at[i] = errno;
                errors_cnt++;
            if (errno == ENOENT)
            {
                last_missing_block = i;
                missing_blocks++;
            }
            continue;
        }
        is_regular_file = S_ISREG(stats[i].st_mode);
        unsigned char *gmd5 = calloc(MD5_DIGEST_LENGTH, 1);
        unsigned char *cmd5 = calloc(MD5_DIGEST_LENGTH, 1);
        get_md5(fpath, gmd5, is_regular_file);
        calc_md5(fpath, cmd5, 1, is_regular_file);
        free(fpath);
        if (strcmp(gmd5, cmd5))
        {
            printf("[getattr] !DIFFERENT CHECKSUMS!\n", errno);
            // Various checksums, file content unexpectedly changed
            errors_at[i] = -1;
            errors_cnt++;
        }  
    }
    
    if (errors_cnt && !is_regular_file)
    {
        st->st_mode = __S_IFDIR;
        return -ENOENT;
    }
    // If errors found, try to fix
    if (missing_blocks == config->paths_size)
    {
        // File is not here at all
        return -ENOENT;
    } else
    if (errors_cnt == 1 && missing_blocks == 1)
    {
        printf("! FIXING MISSING BLOCK USING PARITY %d !\n", stats[last_missing_block == 0 ? 1 : 0].st_size);
        char *parity_buf = malloc(stats[last_missing_block == 0 ? 1 : 0].st_size);
        for (int c = 0; c < stats[last_missing_block == 0 ? 1 : 0].st_size; c++) parity_buf[c] = 0x00;
        // Only one block missing and it's fixable with parity
        if (attach_redundancy_method(config) == 0)
        {
            for (int cnt = 0; cnt < config->paths_size; cnt++)
            {
                if (cnt == last_missing_block)
                {
                    continue;
                }
                char *current_buf = malloc(stats[cnt].st_size);

                file_data_read(path, current_buf, stats[cnt].st_size, 0, config, cnt);

                for (int c = 0; c < stats[cnt].st_size; c++)
                {
                    parity_buf[c] ^= current_buf[c];
                }
                free (current_buf);
            }

            char *empty = malloc(MD5_DIGEST_LENGTH);
            res = write_new_block(path, empty, parity_buf, stats[last_missing_block == 0 ? 1 : 0].st_size, config, last_missing_block);
            free (empty);
            free (parity_buf);
            if (res)
            {
                printf("! FAILED TO FIX MISSING BLOCK USING PARITY %d!\n", stats[last_missing_block == 0 ? 1 : 0].st_size);
                return -2;
            }
            printf("! FIXED MISSING BLOCK USING PARITY !\n");
            res = lstat(xlate(path, config->paths[last_missing_block], config, last_missing_block), stats + last_missing_block);
            if (res == -1) 
            {
                return -2;
            }
        }
        else
        {
            return -2;
        }
    } else
    if (errors_cnt > 1 || errors_cnt == 1 && !should_correct_errors(config))
    {
        // Not fixable on its own
        return -2;
    }

    // Try to fill out stat for fixed files

    // If failed again, replica inactive
    
    st->st_dev = stats[0].st_dev;
    st->st_gid = stats[0].st_dev;
    st->st_ino = stats[0].st_dev;
    st->st_mode = stats[0].st_mode;
    st->st_nlink = stats[0].st_nlink;
    st->st_rdev = stats[0].st_rdev;
    st->st_uid = stats[0].st_uid;
    st->st_blocks = stats[0].st_blocks;
    st->st_blksize = stats[0].st_blksize;

    for (int i = 0; i < config->paths_size; i++)
    {
        st->st_size += stats[i].st_size;
    }

    // Checksum in the beginning of a file
    if (should_use_checksum(config))
    {
        st->st_size -= config->paths_size * MD5_DIGEST_LENGTH;
    }
    // Attach Hamming
    if (attach_redundancy_method(config))
    {
        
    } else
    // Attach parity
    {
        //st->st_size -= stats[config->paths_size-1].st_size;
    }
    // Interlace every other bit
    if (should_interlace(config))
    {
        st->st_size /= 2;
    }

    return 0;
}

int mirror_replica_getattr(const char *path, replica_config_t *config, int number, struct stat *st)
{
    int res = 0;
    int is_regular_file;

    char *fpath = xlate(path, config->paths[0], config, 0);
    res = lstat(fpath, st);
    if (res == -1) {
        printf("[getattr] -1, Ending\n");
        return -errno;
    }
    is_regular_file = S_ISREG(st->st_mode);

    unsigned char gmd5[MD5_DIGEST_LENGTH];
    unsigned char cmd5[MD5_DIGEST_LENGTH];
    get_md5(fpath, gmd5, is_regular_file);
    calc_md5(fpath, cmd5, 1, is_regular_file);               


    if (is_regular_file)
    {
        st->st_size -= MD5_DIGEST_LENGTH; 
        if (should_interlace(config))
            st->st_size /=2;
    }


    return 0;
}

// 1 - missing blocks in replica
// -2 - missing file in a replica

// TODO: If we got blocks 1,3 ok on one replica and block 2 ok on another replica,
// it is possible to merge them together

// TODO: Take care of directories
static int do_getattr( const char *path, struct stat *st ) {
	log_debug("[getattr] Running");
	log_debug("[getattr] Requested  path:%s", path);

	int res = 0;
    size_t i;
    int8_t errors_at[replicas_cnt];
    size_t missing_file = 0;
	
    for (i = 0; i < replicas_cnt; i++)
    {   
        // Stat file
        if (configs[i].status != CLEAN)
        {
            errors_at[i] = 3;
            log_debug("[read] Replica %d is inactive");
            continue;
        }
        int ret = 0;
        switch (configs[i].type)
        {
            case BLOCK:
                log_debug("[getattr] Block replica");
                ret = block_replica_getattr(path, &configs[i],i, st);
            break;
            case MIRROR:
                log_debug("[getattr] Mirror replica");
                ret = mirror_replica_getattr(path, &configs[i], i, st);
            break;
        }

        errors_at[i] = ret;
        if (!ret)
        {
            // Success
            break;
        }
        if (ret == -2)
        {
            missing_file++;
        }
    }

    if (missing_file == replicas_cnt)
    {
        // Failed everywhere
	    log_debug("[getattr] ! MISSING FILE IN ALL REPLICAS !");
        return -2;
    }

    if (i == replicas_cnt)
    {
        // Failed everywhere
	    log_debug("[getattr] ! ALL REPLICAS FAILED !");
        return -2;
    }

    if (i == 0)
    {
        // No errors
        log_debug("[getattr] ! NO ERRORS FOUND !");
        return 0;
    }

    char *data_buf = calloc(st->st_size, 1);
    log_debug("[getattr] ! FILE READ %d %d !", st->st_size, i);

    file_data_read(path, data_buf, st->st_size, 0, &configs[i], -1);

    for (int cnt = 0; cnt < replicas_cnt; cnt++)
    {
        log_debug("[getattr] ! FIXING %d REPLICA: ERROR %d !", cnt, errors_at[cnt]);

        // Some errors
        if (errors_at[cnt] == 1 || errors_at[cnt] == -2)
        {
            // Failed blocks
            // Supported: Either missing block, or wrong block (checksum difference)
            // TODO: Replace only missing blocks, right now fixes whole files


            // if directory, no need to write
            if (S_ISDIR(st->st_mode))
            {
                fprintf(stderr, "[!] Invalid or missing blocks for directory %s on replica %d\n", path, cnt);
                int ret = do_mkdir(path, st->st_mode);
                fprintf(stderr, "[+] Fixed directory %s on replica %d\n", path, cnt);
                continue;
            }
            else // if regular file
            {
                // read file
                printf("[!] Invalid or missing blocks\n%s\n", path);
                printf("[!] Perhaps content in replica %d should be: \n%s\n[!] Suggestion ends\n----------------\n", cnt, data_buf);
                if (errors_at[cnt] == 1 && attach_redundancy_method(&configs[cnt]))
                {
                    char *empty = calloc(MD5_DIGEST_LENGTH, 1);
                    write_new_file(path, empty, data_buf, st->st_size, &configs[cnt]);
                }
            }

        }
        if (errors_at[cnt] == -2)
        {
            char *empty = calloc(MD5_DIGEST_LENGTH, 1);
            write_new_file(path, empty, data_buf, st->st_size, &configs[cnt]);
            free(empty);
         } else
        if (errors_at[cnt] == 0)
        {
            // All done
            break;
        } else
        {
            printf("[!] Failed with %d for %s\n", errors_at[cnt], path);
        }
    }
    
	log_debug("[getattr] End");
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {	
	DIR *dp = NULL;
	struct dirent *de;
	log_debug("[readdir] Running");
	log_debug("[readdir] Requested path: %s", path);
    int rets[replicas_cnt];
    int sum = 0;

    struct dirent **namelist[replicas_cnt];


    for (int i = 0; i < replicas_cnt; i++)
    {
        if (configs[i].status != CLEAN)
        {
            continue;
        }
        char* fpath = xlate(path, configs[i].paths[0], &configs[i], 0);
        int val = i == 0 ? 0 : rets[i-1];
        rets[i] = scandir(fpath, &namelist[i], NULL, alphasort);
        free(fpath);
        sum += rets[i];
        if (rets[i] == -1)
        {
            fprintf(stderr, "Reading dir %s on replica %d failed\n", path, i);
            continue;
        }
    }

    char **full_namelist = malloc (sum * sizeof(char *));
    char **full_namelist2 = malloc (sum * sizeof(char *));
    int k = 0;
    int j = 0;
    for (int i = 0; i < sum; i++)
    {;

        if (j >= rets[k])
        {
            k++;
            j = 0;
        }
        fprintf(stderr, "Going through %s\n", namelist[k][j]->d_name);
        full_namelist[i] = namelist[k][j++]->d_name;
    }

    int count = 0;
    int c, d;
    for (c = 0; c < sum; c++)
    {
        for (d = 0; d < count; d++)
        {
            if(!strcmp(full_namelist[c], full_namelist2[d]))
                break;
        }
        if (d == count)
        {
            fprintf(stderr, "Print %s\n", full_namelist[c]);

            full_namelist2[count] = strdup(full_namelist[c]);
            filler(buffer, full_namelist[c], NULL, 0, FUSE_FILL_DIR_PLUS);
            count++;
        }
    }

    free(full_namelist2);
    free(full_namelist);
    
	return 0;
}

/*
* Returns amount of files opened
*/
int block_replica_open(const char *path, struct fuse_file_info *fi, replica_config_t *config, int *file_handlers, size_t number)
{
    for (int path_idx = 0; path_idx < config->paths_size; path_idx++)
    {
        char *full_path = xlate(path, config->paths[path_idx], config, path_idx);
    
        int val = open(full_path, fi->flags);
        //if (val == -1)
        //    return val;
        free(full_path);
        file_handlers[number + path_idx] = val;
    }
    return config->paths_size;
}

/*
* Returns amount of files opened
*/
int mirror_replica_open(const char *path, struct fuse_file_info *fi, replica_config_t *config, int *file_handlers, size_t number)
{
    char *full_path = xlate(path, config->paths[0], config, 0);
    
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
    int *file_handlers = malloc(sizeof(int) * 1000);
    int next_free_fh = 0;

    for (size_t i = 0; i < replicas_cnt; i++)
    {   
        int ret = 0;
        switch (configs[i].type)
        {
            case BLOCK:
            log_debug("[open] Block replica");
            ret = block_replica_open(path, fi, &configs[i], file_handlers, next_free_fh);
            break;
            case MIRROR:
            log_debug("[open] Mirror replica");
            ret = mirror_replica_open(path, fi, &configs[i], file_handlers, next_free_fh);
            break;
        }
        if (ret == -1)
        {
            // Read error
            printf("! OPENING FAILED !\n");
            next_free_fh += ret;

        } else
        {
            next_free_fh += ret;
        }

    }
     
    uint64_t stamp = (uint64_t) time( NULL );
    hash_insert(h, stamp, file_handlers);
    fi->fh = stamp;
    return 0;
}


/* 
* TODO: different sizes
*/
int decode_hamming(char *buf, size_t size, unsigned char *parity_buf, int *damaged_buf, replica_config_t *config, short should_correct)
{
    unsigned int c = 0;

    //P0 = D0 + D1 + D3 + D4 + D6
    //P1 = D0 + D2 + D3 + D5 + D6
    //P2 = D1 + D2 + D3 + D7
    //P3 = D4 + D5 + D6 + D7
    unsigned char *calculated_parity = calloc(size, 1);
    for (int i = 0; i < size; i++)
    {
        if (buf[i] == 0)
        {
            break;
        }
        unsigned char cur_byte = buf[i];
        //char cur_shift = (i % 2 ? 0 : 4);
        unsigned char cur_parity = parity_buf[i];
        int c = 0;

        calculate_hamming(calculated_parity, i, cur_byte);
        printf("par: %d cur_par %d\n", (calculated_parity[i] & 0x0f), cur_parity & 0x0f);
        c |= (1 * getBit(cur_parity, 0)) ^ (calculated_parity[i] & 0b0001);
        c |= (2 * getBit(cur_parity, 1)) ^ (calculated_parity[i] & 0b0010);
        c |= (4 * getBit(cur_parity, 2)) ^ (calculated_parity[i] & 0b0100);
        c |= (8 * getBit(cur_parity, 3)) ^ (calculated_parity[i] & 0b1000);
        printf("c %d size %d %d \n", c, size, buf[i]);
        if ( c )
        { 
            if (should_correct) 
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
                printf("c %d size %d %d \n", c, size, buf[i]);
            } else
            {
                free (calculated_parity);
                printf("[!] DESYNC ON %c", buf[i]);
                return -2;
            }
        }
    }
    
    free (calculated_parity);
    return 0;
}

int block_replica_read(const char *path, char *buffer, size_t *size, off_t offset, struct fuse_file_info *fi, replica_config_t *config, size_t number)
{
    // Read depending on our options
    int block_size = 4;
    
    int last_block = attach_redundancy_method(config) ? config->paths_size : config->paths_size - 1;
    int hash_offset = should_use_checksum(config) ? MD5_DIGEST_LENGTH : 0;

    int start_block = offset % last_block;
    int current_block = start_block;
    int total_read_bytes = 0;
    int total_size = *size;
    int bytes_read = 0;
    int ret = 0;

    unsigned char *parity_buf = calloc(total_size, 1);
    char parity_char = 0x00;

    unsigned char *stored_md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
    unsigned char *calculated_md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));

    for (int i = 0; i < total_size; i++)
    {
        if (should_interlace(config)) // Interlace parity data
        {
            //printf("READING BLOCK %d ON %d SIZE %d\n", current_block, ((offset + i) / last_block) * 2, total_size);
            ret = pread(*(hash_lookup(h, fi->fh)+number+current_block), buffer + i, 1, ((offset + i) / last_block) * 2 + hash_offset);
            if (ret == -1)
            {
                // Error
                return errno;
            }
            if (ret == 0)
            {
                break;
            }
            *size -= 1;
            bytes_read += 1;

            ret = pread(*(hash_lookup(h, fi->fh)+number+current_block), parity_buf + i, 1, ((offset + i) / last_block) * 2 + 1 + hash_offset);
            if (ret == -1)
            {
                // Error
                return errno;
            }
        }
        else // Only data, no interlacing
        {
            //printf("READING BLOCK %d ON %d SIZE %d\n", current_block, (offset + i) / last_block, total_size);
            ret = pread(*(hash_lookup(h, fi->fh)+number+current_block), buffer + i, 1, ((offset + i) / last_block) + hash_offset);
            if (ret == -1)
            {
                // Error
                return errno;
            }
            if (ret == 0)
            {
                break;
            }
            *size -= 1;
            bytes_read += 1;
        }

        current_block++;
        current_block %= last_block;
    }

    
    // Redundancy
    if (should_interlace(config)) // Interlacing
    {
        if (interlace_redundancy_method(config)) // Interlace Hamming
        {
            ret = decode_hamming(buffer, bytes_read, parity_buf, NULL, config, should_correct_errors(config));
            if (should_correct_errors(config))
            {
                for (int cnt = 0; cnt < config->paths_size; cnt++)
                {
                    char *filepath = xlate(path, config->paths[cnt], config, cnt);
                    
                    char *current_data_buffer = malloc(bytes_read / last_block);
                    char *current_parity_buffer = malloc(bytes_read / last_block);
                    for (int c = 0; c < (bytes_read / last_block) + 1 ; c++)
                    {
                        current_data_buffer[c] = buffer[c * last_block + cnt];
                        current_parity_buffer[c] = parity_buf[c * last_block + cnt];
                    }
                    correct_file(filepath, NULL, current_data_buffer, current_parity_buffer, bytes_read, config);
                    free(current_data_buffer);
                    free(current_parity_buffer);

                    ret = calc_md5(xlate(path, config->paths[cnt], config, cnt), calculated_md5_buffer, 1, 1);
                    if (ret == -1)
                    {
                        free (parity_buf);
                        free (stored_md5_buffer);
                        free (calculated_md5_buffer);
                        free (filepath);
                        return -1;
                    }
                    correct_file(filepath, calculated_md5_buffer, NULL, NULL, NULL, config);
                    free(filepath);    
                }
            } else
            {
                if (ret == -2)
                {
                    free (parity_buf);
                    free (stored_md5_buffer);
                    free (calculated_md5_buffer);
                    printf("HAMMING CODE DOESN'T MATCH\n");
                    return -2;
                }
            }
        } else // Interlace parity
        {
            for (int i = 0; i < bytes_read; i++)
            {
                char parity_bit;
                calculate_parity_byte(buffer[i], &parity_bit);
                if (parity_bit & 1 != parity_buf[i] & 1) // Wrong parity
                {

                    free (parity_buf);
                    free (stored_md5_buffer);
                    free (calculated_md5_buffer);
                    printf("PARITY DOESN'T MATCH\n");
                    return -2;
                }
            }

        }
        
        if (ret == -1)
        {
            // Errors detected
        } else if (ret == 0)
        {
            // Errors corrected
        }
    }

    if(should_use_checksum(config))
    {
        for (int cur = 0; cur < config->paths_size; cur++)
        {
            ret = pread(*(hash_lookup(h, fi->fh)+number+cur), stored_md5_buffer, MD5_DIGEST_LENGTH, 0);
            if (ret == -1)
            {
                // Error
                free (parity_buf);
                free (stored_md5_buffer);
                free (calculated_md5_buffer);
                return errno;
            }
            char *fp = xlate(path, config->paths[cur], config, cur);
            ret = calc_md5(fp, calculated_md5_buffer, 1, 1);
            free(fp);
            if (ret == -1)
            {
                free (parity_buf);
                free (stored_md5_buffer);
                free (calculated_md5_buffer);
                return -1;
            }
            // for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", stored_md5_buffer[i]);
            if (strcmp(stored_md5_buffer, calculated_md5_buffer))
            {
                log_debug("[block_replica_read] ! Different checksums !");
                return -2;
            } else
            {
            }
        }
    }

    free (parity_buf);
    free (stored_md5_buffer);
    free (calculated_md5_buffer);

    return 0;
}

int mirror_replica_read(const char *path, char *buffer, size_t *size, off_t offset, struct fuse_file_info *fi, replica_config_t *config, size_t number)
{
    log_debug("[mirror_replica_read] Running");
    unsigned char *stored_md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
    unsigned char *calculated_md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
    char *total_buffer;
    char *parity_buf;
    char *data_buf;
    int buf_size = *size;
    int bytes_read = 0;
    int ret;
	// Read all

        total_buffer = calloc((*size) * 2, 1);
        parity_buf = calloc((*size), 1);
        data_buf = calloc((*size), 1);

        ret = pread(*(hash_lookup(h, fi->fh)+number), stored_md5_buffer, MD5_DIGEST_LENGTH, 0);
        if (ret == -1)
        {
            return -1;
        }
        if (should_interlace(config))
        {
            ret = pread(*(hash_lookup(h, fi->fh)+number), total_buffer, (*size) * 2, offset + MD5_DIGEST_LENGTH);
            *size = ret / 2;
            bytes_read = ret / 2;
            for (int i = 0; i < bytes_read; i++)
            {
                data_buf[i] = total_buffer[2*i];
                parity_buf[i] = total_buffer[2*i + 1];
            }
        } else
        {
            ret = pread(*(hash_lookup(h, fi->fh)+number), data_buf, (*size), offset + MD5_DIGEST_LENGTH);
            *size = ret;
            bytes_read = ret;
        }
        if (ret == -1)
        {
            return -1;
        }

    strcpy(buffer, data_buf);

    if (should_interlace(config))
    {
        if (interlace_redundancy_method(config) == 1)
        {
            ret = decode_hamming(buffer, *size, parity_buf, NULL, config, should_correct_errors(config));
            if (should_correct_errors(config))
            {
                char *filepath = xlate(path, config->paths[0], config, 0);
                correct_file(filepath, NULL, buffer, parity_buf, bytes_read, config);
                ret = calc_md5(filepath, calculated_md5_buffer, 1, 1);
                if (ret == -1)
                {
                    free(filepath);
                    return -1;
                }
                correct_file(filepath, calculated_md5_buffer, NULL, NULL, NULL, config);
                free(filepath);
            } else
            {
                if (ret == -2)
                {
                    printf("! DESYNC ON HAMMING CODE !\n");
                    return -2;
                }
            }
        } else
        {
            for (int i = 0; i < bytes_read; i++)
            {
                char parity_bit;
                calculate_parity_byte(buffer[i], &parity_bit);
                if (parity_bit & 1 != parity_buf[i] & 1) // Wrong parity
                {
                    printf("! DESYNC ON PARITY BIT !\n");
                    return -2;
                }
            }
        }
    }
    if (ret == -1)
    {
        // Errors detected
    } else if (ret == 0)
    {
        // Errors corrected
    }

    char *fp = xlate(path, config->paths[0], config, 0);
    ret = calc_md5(fp, calculated_md5_buffer, 1, 1);
    free(fp);
    if (ret == -1)
    {
        return -1;
    }
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", stored_md5_buffer[i]);

    if (strcmp(stored_md5_buffer, calculated_md5_buffer))
    {
        log_debug("[mirror_replica_read] Different checksums");
        return -2;
    } else
    {
    }

    // If ok, return amount file handlers used (might be up to 2?)
    return 0;
}

// If read completely fails, mark replica as INACTIVE
// begin_size - size in the end contains amount of bytes read 
// TODO: Find errors on replicas after succesful reading and fix them
static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) 
{
	log_debug("[read] Running");
	log_debug("[read] Path: %s", path);
    //auto begin_size = size

    // Choose replica
    // Read
    // Handle errors
    // Return amount of read bytes
    size_t size_to_read = size;
    int ret = 0;
    int next_free_fh = 0;

    size_t i = 0;
    size_t success_i = 0;
    int8_t errors_at[replicas_cnt];
    size_t missing_file = 0;
    size_t error = 0;
    char *backup_buffer = malloc(size);
    int did_success = 0;

    for (i = 0; i < replicas_cnt; i++)
    { 
        size_to_read = size;
        if (!configs[i].status == CLEAN)
        {
            log_debug("[read] Replica %d is inactive");
            next_free_fh += configs[i].paths_size;
            continue;
        }
        switch (configs[i].type)
        {
            case BLOCK:
                log_debug("[read] Reading block replica");
                ret = block_replica_read(path, did_success ? backup_buffer : buffer, &size_to_read, offset, fi, &configs[i], next_free_fh);
            break;
            case MIRROR:
                log_debug("[read] Reading mirror replica");
                ret = mirror_replica_read(path, did_success ? backup_buffer : buffer, &size_to_read, offset, fi, &configs[i], next_free_fh);
            break;
        }
        next_free_fh += configs[i].paths_size;
 
        errors_at[i] = ret;
        if (!ret)
        {
            // Success
            did_success = 1;
            success_i = i;
            break;
        }
        if (ret == 2)
        {
            missing_file++;
        }
        error++;
    }

    free(backup_buffer);

    if (missing_file == replicas_cnt)
    {
        // Failed everywhere
	    log_debug("[read] ! MISSING FILE IN ALL REPLICAS !");
        return -2;
    }
    if (error == replicas_cnt)
    {
        // Failed everywhere
        log_debug("[read] ! ALL REPLICAS FAILED !");
        return -2;
        
    }
    if (error == 0)
    {
        // No errors
        log_debug("[read] ! NO ERRORS FOUND !");
        return size - size_to_read;
    }

    char *data_buf = calloc(size, 1);
    char *check_buf = calloc(size, 1);

    next_free_fh = 0;
    int check_size = size;

    file_data_read(path, data_buf, size, 0, &configs[success_i], -1);

    for (int cnt = 0; cnt < replicas_cnt; cnt++)
    {
        log_debug("[read] ! FIXING %d REPLICA: ERROR %d !", cnt, errors_at[cnt]);
        if (errors_at[cnt] == -1) // Random read error
        {
            printf("[!] Error when reading file %s\n", path);
            printf("[-] Perhaps content in replica %d should be: \n%s\n[!] Suggestion ends\n\n", cnt, data_buf);
            char *empty = calloc(MD5_DIGEST_LENGTH, 1);
            write_new_file(path, empty, data_buf, size, &configs[cnt]);
            printf("[+] Fixed content in replica %d for %s\n", cnt, path);    
        } else
        if (errors_at[cnt] == -2) // Desynced file
        {
            printf("[!] Desynchronized file %s\n", path);
            printf("[-] Perhaps content in replica %d should be: \n%s\n[!] Suggestion ends\n\n", cnt, data_buf);
            char *empty = calloc(MD5_DIGEST_LENGTH, 1);
            write_new_file(path, empty, data_buf, size, &configs[cnt]);
            printf("[+] Fixed content in replica %d for %s\n", cnt, path);

        } else
        if (errors_at[cnt] == 2 || errors_at[cnt] == 9 ) // Missing file or Bad file number
        {
            printf("[!] Missing file %s\n", path);
            printf("[-] Perhaps content in replica %d should be: \n%s\n[!] Suggestion ends\n\n", cnt, data_buf);
            char *empty = calloc(MD5_DIGEST_LENGTH, 1);
            write_new_file(path, empty, data_buf, size, &configs[cnt]);
            printf("[+] Fixed content in replica %d for %s\n", cnt, path);

        } else
        if (errors_at[cnt] == 0) // All good
        {
            next_free_fh += configs[cnt].paths_size;
            continue;
        }
        else // Other errors
        {
            printf("[!] Error %d for %s\n", errors_at[cnt], path);
        }

        if (configs[cnt].type == BLOCK)
        {
            ret = block_replica_read(path, check_buf, &check_size, offset, fi, &configs[cnt], next_free_fh);
            if (ret)
            {
                printf("[!] Failed again for replica %d with %d\n", cnt, ret);
                printf("[!] Set replica %d as [INACTIVE]\n", cnt);
                configs[cnt].status = INACTIVE;
            } else
            {
                printf("[!] Reading again replica %d: Success\n", cnt);
            }
        }
        else
        {
            ret = mirror_replica_read(path, check_buf, &check_size, offset, fi, &configs[cnt], next_free_fh);
            if (ret)
            {
                printf("[!] Failed again for replica %d with %d\n", cnt, ret);
                printf("[!] Set replica %d as [INACTIVE]\n", cnt);
                configs[cnt].status = INACTIVE;
                
            } else
            {
                printf("[!] Reading again replica %d: Success\n", cnt);
            } 
        }
        next_free_fh += configs[cnt].paths_size;
    }

    free(data_buf);
    free(check_buf);
    // Return whole size but parts we didnt read
    return size - size_to_read;
}
// zapisywac na koniec parzystosc wtedy stat bez niej i link nawet powinien dzialc
static int do_chmod(const char *path,  mode_t mode)
{
    char *fpath;
    int ret;
    fpath = xlate(path, configs[0].paths[0], &configs[0], 0);
    
    log_debug("[chmod] Full path: %s", fpath);
    
    ret = chmod(fpath, mode);
    free (fpath);
    return ret;
}

static int do_chown(const char *path, uid_t uid, gid_t gid)
{
    char *fpath;
    int ret;
    fpath = xlate(path, configs[0].paths[0], &configs[0], 0);
    log_debug("[chown] Full path: %s", fpath);
    ret = chown(fpath, uid, gid);
    free (fpath);
    return ret;
}

static int do_truncate(const char *path, off_t size)
{
    char *fpath;
    int ret;
    fpath = xlate(path, configs[0].paths[0], &configs[0], 0);
    log_debug("[truncate] Full path: %s", fpath);
    ret =truncate(fpath, size);
    free (fpath);
    return ret;
}

static int do_release(const char *path, struct fuse_file_info *fi)
{
    log_debug("[release] Starting");
    int *fhs = hash_lookup(h, fi->fh);
    for (int i = 0; i < replicas_cnt; i++)
    {
        if (fhs[i])
        {
            int val = close(fhs[i]);
            if (val == -1)
            {
                // Error
            }
        }
        
    }
    hash_delete(h, fi->fh);
    free(fhs);
    return 0;
}

int change_checksum(unsigned char *new_checksum, char *path)
{
    FILE *ft;
    int ch = 0;
    ft = fopen(path, "r+");
    if (ft == NULL)
    {
        printf("cannot open target file %s\n", path);
        return 1;
    }
    int i = 0;
    while ((ch = fgetc(ft)) != EOF && i < MD5_DIGEST_LENGTH)
    {
        fseek(ft, -1, SEEK_CUR);
        fputc(new_checksum[i++],ft);
        fseek(ft, 0, SEEK_CUR);

    }

    if (i == 0)
    {
       fwrite(new_checksum, 1, MD5_DIGEST_LENGTH, ft);
    }
    fclose(ft);
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

        char c = 0x00;
        c |= p3;
        c <<= 1;
        c |= p2;
        c <<= 1;
        c |= p1;
        c <<= 1;
        c |= p0;

        parity_buf[pos] |= c;
        //if (!(pos % 2)) parity_buf[pos/2] <<= 4;
    
    return 4; 
}

int calculate_parity_byte(char c, char *buf)
{
    char xored_bit = 0x00;
    for (int b = 0; b < 8; b++)
    {
        xored_bit ^= (c & 1);
        c >>= 1;
    }
    buf[0] = xored_bit;
    return 0;
}


/*
* 0000 ABCD
* A - when set, write redundant bytes to last block 
*     when not set, attach redundant bytes to buf
* D - when set, use Hamming code for correction
*/
int block_replica_write(const char *path, const char *buf, size_t *size,
		    off_t offset, struct fuse_file_info *fi, replica_config_t *config, int curnumber)
{
    int hash_offset = should_use_checksum(config) ? MD5_DIGEST_LENGTH : 0;

    // Calculate redundancy
    unsigned char* parity_buf = (unsigned char*) calloc(*size, 1);
    unsigned char* attach_parity_buf = (unsigned char*) calloc(*size, 1);
    size_t parity_size = 0;
    
    if (should_interlace(config)) // Use interlacing
    {
        if (config->flags & FLAG_INTERLACE_REDUNDANCY) // Interlace Hamming
        { 
            for (int i=0;i<*size;i++)
            {
                char current_byte = buf[i];
                parity_size += calculate_hamming(parity_buf, i, current_byte);  
            }
        } else // Interlace parity
        {
            for (int i = 0; i < *size; i++)
            {
                calculate_parity_byte(buf[i], parity_buf + i);
            }
        }
    }
    
    // Write depending on our options
    int block_size = 4;
    int last_block = attach_redundancy_method(config) ? config->paths_size : config->paths_size - 1;
    int start_block = offset % last_block;
    int current_block = start_block;
    int size_to_write = *size;

    int total_written_bytes = 0;
    int ret = 0;

    for (int i = 0; i < size_to_write; i++)
    {
        if (should_interlace(config))
        {
            //printf("WRITING BLOCK %d WITH %c ON %d\n", current_block, buf[i], ((offset + i) / last_block) * 2);
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + current_block), buf + i, 1, ((offset + i) / last_block) * 2 + hash_offset);
            if (ret == -1)
            {
                // Error
                return -errno;
            }
            *size -= 1;
 
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + current_block), parity_buf + i, 1, ((offset + i) / last_block) * 2 + 1 + hash_offset);
            if (ret == -1)
            {
                // Error
                return -errno;
            }
        }
        else
        {
            //printf("WRITING BLOCK %d WITH %c ON %d\n", current_block, buf[i], ((offset + i) / last_block));
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + current_block), buf + i, 1, ((offset + i) / last_block) + hash_offset);
            if (ret == -1)
            {
                // Error
                return -errno;
            }
            *size -= 1;
        }
        current_block++;
        current_block %= last_block;
    }

    if (attach_redundancy_method(config)) // Attach Hamming
    {

    } else // Attach parity
    {
        for (int i = 0; i < (size_to_write / last_block); i++)
        {
            attach_parity_buf[i] = 0x00;
            for (int j = 0; j < last_block; j++)
            {
                attach_parity_buf[i] ^= buf[last_block * i + j];
            }
        }
        ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber + config->paths_size - 1), attach_parity_buf, size_to_write / last_block, offset + hash_offset);
        if (ret == -1)
        {
            // Error
            return -errno;
        }
    }


    for (int i = 0; i < config->paths_size; i++)
    {
        unsigned char *md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
        char *fp = xlate(path, config->paths[i], config, i);
        ret = calc_md5(fp, md5_buffer, 1, 1);
        if (ret)
        {
            free(fp);
            return ret;
        }
        ret = change_checksum(md5_buffer, fp); 
        if (ret)
        {
            free(fp);
            return ret;
        }
        free(fp);
    }
    return 0;
}


        //P0 = D0 + D1 + D3 + D4 + D6
        //P1 = D0 + D2 + D3 + D5 + D6
        //P2 = D1 + D2 + D3 + D7
        //P3 = D4 + D5 + D6 + D7

/*
* Calculate redundant bytes
* Save buffer to file(s)
*/
int mirror_replica_write(const char *path, const char *buf, size_t *size,
		    off_t offset, struct fuse_file_info *fi, replica_config_t *config, int curnumber)
{
    int ret;
    int size_to_write = *size;

    char *fullpath = xlate(path, config->paths[0], config, 0);
    unsigned char parity_buf = 0x00;

    for (int i=0;i<size_to_write;i++)
    {
        if (should_interlace(config))
        {
            char current_byte = buf[i];
            if (interlace_redundancy_method(config) == 1)
            {
                calculate_hamming(&parity_buf, 0, current_byte);
            }
            else
            {
                calculate_parity_byte(current_byte, &parity_buf);
            }
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber), buf + i, 1, offset + MD5_DIGEST_LENGTH + 2 * i );
            *size -= 1;
            if (ret == -1)
            {
                free (fullpath);
                return -1;
            }
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber), &parity_buf, 1, offset + MD5_DIGEST_LENGTH  + 2 * i + 1); 
            if (ret == -1)
            {
                free (fullpath);
                return -1;
            }
        }
        else
        {
            ret = pwrite(*(hash_lookup(h, fi->fh)+curnumber), buf + i, 1, offset + MD5_DIGEST_LENGTH + i );
            *size -= 1;
            if (ret == -1)
            {
                free (fullpath);
                return -1;
            }
        }
    }

    unsigned char *md5_buffer = calloc(MD5_DIGEST_LENGTH, sizeof(char));
    ret = calc_md5(fullpath, md5_buffer, 1, 1);
    if (ret)
    {
        free (fullpath);
        free (md5_buffer);
        return ret;
    }
    ret = change_checksum(md5_buffer, xlate(path, config->paths[0], config, 0)); 
    if (ret)
    {
        free (fullpath);
        free (md5_buffer);
        return -1;
    }

    free (fullpath);
    free (md5_buffer);
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

    /* Writing structure in one file
     * 1. Constant-sized hash
     * 2. Actual data
     * 3. ECC, size can be predicted
     * Parts 2. and 3. can interlace
     */
    log_debug("[do_write] Running ");
    uint8_t outcomes[replicas_cnt];

    // Stores return value of writing function
    int val;
    size_t returned_size = size;
    int next_free_fh = 0;

    for(int i = 0; i < replicas_cnt; i++)
    {
        returned_size = size;
        if (configs[i].status == INACTIVE)
        {
            log_debug("[read] Replica %d is inactive");
            continue;
        }
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_write] Mirror replica ");
                // Write to replica if usable 
                val = mirror_replica_write(path, buf, &returned_size, offset, fi, &configs[i], next_free_fh);      
            break;
            case BLOCK:
                log_debug("[do_write] Block replica ");
                // Write to replica if usable 
                val = block_replica_write(path, buf, &returned_size, offset, fi, &configs[i], next_free_fh);
            break;
        }
        // If failed, take action depending on value of errno (see man write(2))
        if (val == -1)
        {
            switch(errno)
            {
                case EBADF:
                        log_debug("[do_write] BADF error");
                        break;
            }
            // Mark replica as dirty
            outcomes[i] = 1;
            configs[i].status = DIRTY;
        }

        next_free_fh += configs[i].paths_size;
    }
   
    return size - returned_size;
}

int block_replica_mknod(const char *path, mode_t mode, dev_t dev, replica_config_t *config)
{
    int ret;
    FILE *ft;
    char *buf = calloc(MD5_DIGEST_LENGTH, 1);

    for (int i = 0; i < config->paths_size; i++)
    {
        char *fullpath = xlate(path, config->paths[i], config, i);
        ret = mknod(fullpath, mode, dev);
        if (ret)
        {
            free (fullpath);
            free (buf);
            return ret;
        }
        
        if (should_use_checksum(config))
        {
            ft = fopen(fullpath, "w");
            if (ft == NULL)
            {
                free (fullpath);
                free (buf);
                return -1;
            }
            calc_md5(fullpath, buf, 1, 1);
            fwrite(buf, 1, MD5_DIGEST_LENGTH, ft);
            fclose(ft);
        }
        free (fullpath);
    }
    free (buf);
    return 0;
}

// TODO: if one of file, .file exists, whole thing fails
int mirror_replica_mknod(const char *path, mode_t mode, dev_t dev, replica_config_t *config)
{
    int ret;
    char *fullpath = xlate(path, config->paths[0], config, 0);
/*
    char *hiddenpath = malloc(strlen(path)+1);
    strcpy(hiddenpath+1, path);
    hiddenpath[0] = '/';
    hiddenpath[1] = '.';
    char *hiddenpath_parity = xlate(hiddenpath, config->paths[0], config, 0);
*/  
    FILE *ft;
    char empty[MD5_DIGEST_LENGTH];

    if (interlace_redundancy_method(config))
    {
        ret = mknod(fullpath, mode, dev);
        if (ret)
        {
            return ret;
        }
        char empty[MD5_DIGEST_LENGTH];
        ft = fopen(fullpath, "w");
        if (ft == NULL)
        {
            return -1;
        }
        fwrite(empty, 1, MD5_DIGEST_LENGTH, ft);
        fclose(ft);

        return 0;
    }
    // Else

    ret = mknod(fullpath, mode, dev);
    if (ret)
    {
        return ret;
    }

    ft = fopen(fullpath, "w");
    if (ft == NULL)
    {
        return -1;
    }
    fwrite(empty, 1, MD5_DIGEST_LENGTH, ft);
    fclose(ft);

    return 0;
}

// Create and open
static int do_mknod(const char *path, mode_t mode, dev_t dev)
{
    log_debug("[do_mknod] Running ");
    // Stores return value of writing function
    int val;
    for(int i = 0; i < replicas_cnt; i++)
    {
        if (configs[i].status == INACTIVE)
        {
            log_debug("[mknod] Replica %d is inactive");
            continue;
        }
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_mknod] Mirror replica ");
                val = mirror_replica_mknod(path, mode, dev, &configs[i]);      
            break;
            case BLOCK:
                log_debug("[do_mknod] Block replica ");
                val = block_replica_mknod(path, mode, dev, &configs[i]);
            break;
        }
        if (val)
        {
            switch(errno)
            {
                case EBADF:
                        
                        break;
            }
        }
    }

    return 0;
}

int block_replica_mkdir(const char *path, mode_t mode, replica_config_t *config)
{
    int ret;
    int exists = 0;

    for (int i = 0; i < config->paths_size; i++)
    {
        char *fpath = xlate(path, config->paths[i],config, i);
        ret = mkdir(fpath, mode);
        if (ret == -1)
        {
            if (errno == EEXIST)
            {
                exists++;
                continue;
            }
            free (fpath);
            return errno;
        }
        free (fpath);
    }

    if (exists == config->paths_size) return EEXIST;

    return 0;
}

int mirror_replica_mkdir(const char *path, mode_t mode, replica_config_t *config)
{
    int ret;
    int exists = 0;

    char *fpath = xlate(path, config->paths[0],config, 0);
    ret = mkdir(fpath, mode);
    if (ret == -1)
    {
        free (fpath);
        if (errno == EEXIST)
        {        
            return EEXIST;
        }
        return errno;
    }
    free (fpath);

    return 0;
}

int do_mkdir (const char *path, mode_t mode)
{
    log_debug("[do_mkdir] Running ");
    // Stores return value of writing function
    int val;
    for(int i = 0; i < replicas_cnt; i++)
    {
        if (configs[i].status == INACTIVE)
        {
            log_debug("[do_mkdir] Replica %d is inactive");
            continue;
        }
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_mkdir] Mirror replica ");
                val = mirror_replica_mkdir(path, mode, &configs[i]);      
            break;
            case BLOCK:
                log_debug("[do_mkdir] Block replica ");
                val = block_replica_mkdir(path, mode, &configs[i]);
            break;
        }
        if (val)
        {
            printf ("Returned error %d\n", val);
            switch(errno)
            {
                case EBADF:
                        
                        break;
            }
        }
    }

    return 0;
}

int block_replica_unlink(const char *path, replica_config_t *config)
{
    int ret;
    int exists = 0;

    for (int i = 0; i < config->paths_size; i++)
    {
        char *fpath = xlate(path, config->paths[i],config, i);
        ret = unlink(fpath);
        if (ret == -1)
        {
            
        }
        free (fpath);
    }

    return 0;
}

int mirror_replica_unlink(const char *path, replica_config_t *config)
{
    int ret;
    int exists = 0;

    char *fpath = xlate(path, config->paths[0],config, 0);
    ret = unlink(fpath);
    if (ret == -1)
    {
        
    }
    free (fpath);

    return 0;
}

int do_unlink(const char *path)
{
  log_debug("[do_unlink] Running ");
    // Stores return value of writing function
    int val;
    for(int i = 0; i < replicas_cnt; i++)
    {
        if (configs[i].status == INACTIVE)
        {
            log_debug("[do_unlink] Replica %d is inactive");
            continue;
        }
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_unlink] Mirror replica ");
                val = mirror_replica_unlink(path, &configs[i]);      
            break;
            case BLOCK:
                log_debug("[do_unlink] Block replica ");
                val = block_replica_unlink(path, &configs[i]);
            break;
        }
        if (val)
        {
            printf ("Returned error %d\n", val);
            switch(errno)
            {
                case EBADF:          
                        break;
            }
        }
    }
    return 0;
}


int block_replica_rmdir(const char *path, replica_config_t *config)
{
    int ret;
    int exists = 0;

    for (int i = 0; i < config->paths_size; i++)
    {
        char *fpath = xlate(path, config->paths[i],config, i);
        ret = rmdir(fpath);
        if (ret == -1)
        {
            
        }
        free (fpath);
    }

    return 0;
}

int mirror_replica_rmdir(const char *path, replica_config_t *config)
{
    int ret;
    int exists = 0;

    char *fpath = xlate(path, config->paths[0],config, 0);
    ret = rmdir(fpath);
    if (ret == -1)
    {
        
    }
    free (fpath);

    return 0;
}

int do_rmdir(const char *path)
{
  log_debug("[do_rmdir] Running ");
    // Stores return value of writing function
    int val;
    for(int i = 0; i < replicas_cnt; i++)
    {
        if (configs[i].status == INACTIVE)
        {
            log_debug("[do_rmdir] Replica %d is inactive");
            continue;
        }
        switch (configs[i].type)
        {
            case MIRROR:
                log_debug("[do_rmdir] Mirror replica ");
                val = mirror_replica_rmdir(path, &configs[i]);      
            break;
            case BLOCK:
                log_debug("[do_rmdir] Block replica ");
                val = block_replica_rmdir(path, &configs[i]);
            break;
        }
        if (val)
        {
            printf ("Returned error %d\n", val);
            switch(errno)
            {
                case EBADF:          
                        break;
            }
        }
    }
    return 0;
}



static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .read = do_read,
    .mknod = do_mknod,
    .mkdir = do_mkdir,
    .unlink = do_unlink,
    .rmdir = do_rmdir,

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
        printf("uselessFS\n\n");

        printf("Launch:\n");
        printf("Recommended: @<config file> <fuse args> (Example: ./uselessfs @config/1-example.cfg -d path/to/mountpoint) \n");
        printf("<args> \n\n");
        
        printf("Important: With -d option when mounting you'll get to see printed logs\n");
        printf("Try proposed configurations, adjust paths before using them\n\n");
        printf("Note: Not all options and combinations of flags work yet!\n");
        printf("This filesystem is considered WIP, so any configurations other than ones already delivered might fail to work properly\n");
        printf("\nAll functionalities presented are to be treated as experimental.\n");
        return 0;
    }
    if (argv[1][0] == '@')
    {
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        uint8_t cur_replica = 0;

        fp = fopen((argv[1])+1, "r");
        if (fp == NULL)
            exit(EXIT_FAILURE);

        while ((read = getline(&line, &len, fp)) != -1) 
        {
            if(len && line[len-1] == '\n')
                line[len-1] = 0;

            char *tokenized = strtok(line, " \n");
            if (tokenized == NULL)
            {
                continue;
            }
            if (!strcmp(tokenized, "--number") )
            {
                //printf(  "ENTER %s\n", tokenized);
                replicas_cnt = (int) strtol(strtok(NULL, " "), (char**) NULL, 10);
                configs = calloc(replicas_cnt, sizeof(replica_config_t));
                continue;
            } else if (!strcmp(tokenized, "--block-replica") )
            {
                int blocks_cnt = (int) strtol(strtok(NULL, " "), (char**) NULL, 10);
                int flags = (int) strtol(strtok(NULL, " "), (char**) NULL, 2);
                configs[replica_configs_c].paths = calloc(blocks_cnt, sizeof(char*));
                configs[replica_configs_c].paths_size = blocks_cnt;
                
                for (int i = 0; i < blocks_cnt; i++)
                {
                    char *curpath = strtok(NULL, " ");
                    if (curpath[0] != '/')
                    {
                        char *envpath = getenv("PWD");
                        strncat(envpath, "/", 1);
                        curpath = xlate(curpath, envpath, &configs[0], 0);
                    }
                    configs[replica_configs_c].paths[i] = curpath;
                    //printf("Replica %d: %s\n", i, configs[replica_configs_c].paths[i]);
                }
                configs[replica_configs_c].status = CLEAN;
                configs[replica_configs_c].type = BLOCK;
                configs[replica_configs_c].flags = flags;
                configs[replica_configs_c].priority = 0;
                //printf("Replica: %s\n", tokenized);
                replica_configs_c++;
                continue;
            } else if (!strcmp(tokenized, "--mirror-replica"))
            {
                char* curpath = strtok(NULL, " ");
                int flags = (int) strtol(strtok(NULL, " "), (char**) NULL, 2);

                // Absolute path
                if (curpath[0] != '/')
                {
                    char *envpath = getenv("PWD");
                    strncat(envpath, "/", 1);
                    curpath = xlate(curpath, envpath, &configs[0], 0);
                }
                configs[replica_configs_c].paths = calloc(1, sizeof(char*));
                configs[replica_configs_c].paths[0] = curpath;
                configs[replica_configs_c].paths_size = 1;
                
                configs[replica_configs_c].status = CLEAN;
                configs[replica_configs_c].type = MIRROR;
                configs[replica_configs_c].flags = flags;
                configs[replica_configs_c].priority = 0;
                //printf("Replica: %s\n", configs[replica_configs_c].paths[0]);
                //printf("Replica: %s\n", argv[4]);
                replica_configs_c++;
                continue;
            } else if (!strcmp(tokenized, "--recovery-dir"))
            {
                recovery_dir = strtok(NULL, " ");
                //printf("RECOVERY %s\n", recovery_dir);
            }

        }

        for (int curarg = 2; curarg < argc; curarg++)
        {
            fuse_argv[fuse_argv_c++] = argv[curarg];
            
        }
        fclose(fp);

    }

	return fuse_main(fuse_argv_c, fuse_argv, &operations, NULL);
}
