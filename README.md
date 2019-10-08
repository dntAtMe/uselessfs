# Useless Filesystem


Useless filesystem is just one of many useless filesystems, i guess.

### Mounting
```
$ gcc main.c log.c -o uselessfs -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -lfuse -pthread
./uselessfs [-d] [mountdir]
```
-d debugging option
