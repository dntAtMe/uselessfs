MNT="workspace/mountpoint"

echo "[-] Clearing replicas"
rm -rf workspace/r1 workspace/r2 workspace/r3 workspace/r4 workspace/r5 workspace/r6
mkdir workspace/r1 workspace/r2 workspace/r3 workspace/r4 workspace/r5 workspace/r6
echo "[+] Cleared replicas"

./uselessfs @config/1-example.cfg ${MNT} 2>&1 >/dev/null

touch ${MNT}/testfile
echo "New file" > ${MNT}/testfile
echo "And another line" >> ${MNT}/testfile
echo -n "And one more\nAnd last one\n" >> ${MNT}/testfile

echo -n "\n\nDirectory: "
ls -al ${MNT}
echo -n "\n\n"

echo -n "\n[-] Removing block 1 from replica 1\n"
rm workspace/r1/testfile
echo "[+] Removed block 1 from replica 1"

echo ""
echo "File content:"
cat ${MNT}/testfile

echo "[+] Restored block 1 from replica 1"

# THIS CRASHES, PROBABLY CANT HANDLE 2 REPLICAS FAILING FUCK
echo -n "\n[-] Removing block 1 from replica 1\n"
rm workspace/r1/testfile
echo "[+] Removed block 1 from replica 1"
echo -n "\n[-] Removing block 2 from replica 1\n"
rm workspace/r2/testfile
echo "[+] Removed block 2 from replica 1"


sleep 1
fusermount3 -u ${MNT}
