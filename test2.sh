MNT="workspace/mountpoint"

echo "[-] Clearing replicas"
./prepare_env.sh > /dev/null
echo "[+] Cleared replicas"

./uselessfs @config/3-two-block-replicas.cfg ${MNT} 
echo ""
echo "Write/read test with missing blocks"
echo ""

echo "Writing '1st line' on line 0"
echo "1st line" > ${MNT}/testfile
echo "Writing '2nd line' on line 1"
echo "2nd line" >> ${MNT}/testfile
echo "Writing '3rd line...' on line 2"
echo -n "3rd line..." >> ${MNT}/testfile
echo "Writing ' ...continued' on line 2"
echo " ...continued" >> ${MNT}/testfile
echo ""

echo "[-] Removing block 1 from replica 1"
#rm workspace/r1/testfile
echo "[+] Removed block 1 from replica 1"

echo ""
echo "File content:"
cat ${MNT}/testfile

echo "[-] Does file exist in block 1 of replica 1?"
(stat workspace/1-block/0/testfile > /dev/null && echo "[+] Yes") || echo "[x] No"

echo ""
# THIS CRASHES, PROBABLY CANT HANDLE 2 REPLICAS FAILING FUCK
echo "[-] Removing block 1 from replica 1"
#rm workspace/r1/testfile
echo "[+] Removed block 1 from replica 1"
echo ""
echo "[-] Removing block 2 from replica 1"
#rm workspace/r2/testfile
echo "[+] Removed block 2 from replica 1"
echo ""
echo "File content:"
cat ${MNT}/testfile

echo "[-] Does file exist in block 1 of replica 1?"
(stat workspace/1-block/0/testfile > /dev/null && echo "[+] Yes") || echo "[x] No"

echo "[-] Does file exist in block 2 of replica 1?"
(stat workspace/1-block/1/testfile > /dev/null && echo "[+] Yes") || echo "[x] No"

fusermount3 -u ${MNT}
