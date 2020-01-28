gcc fs_main.c log.c -w -o uselessfs -D_FILE_OFFSET_BITS=64 -Iinclude/ -lfuse3 -pthread -lm -lssl -lcrypto

rm -rf workspace/
mkdir workspace/
cd workspace/
mkdir mountpoint/
mkdir 0-mirror/
mkdir 1-block/ 1-block/0 1-block/1 1-block/2
mkdir 2-block/ 2-block/0 2-block/1 2-block/2
cd - > /dev/null
echo "Workspace prepared under ./workspace/ directory"
echo ""
echo "You can mount filesystem with"
echo "$ ./uselessfs @config/1-two-block-replicas.cfg -d workspace/mountpoint"
echo "-d option is highly recommended, as it provides some debugging logs"
echo "For more informations, call './uselessfs' with no arguments"
echo "You can also try other example configurations"
echo ""
echo "Important: It is NOT recommended to try you own configurations, as not all options are fully working at the moment"