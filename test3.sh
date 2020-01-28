MNT="workspace/mountpoint"

./prepare_env.sh > /dev/null

./uselessfs @config/3-two-block-replicas.cfg ${MNT}

echo ""
echo "Recovery of a missing replica"
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

echo "[+] Removing 1st replica directory"
rm -rf workspace/r1

echo "Mounted directory listed: "
ls ${MNT}
echo ""

echo "File content:"
cat ${MNT}/testfile
echo ""

echo "[+] New recovery path for 1st replica:"
echo "/tmp/r1"
echo ""

rm -rf /tmp/r1
echo "Unmounting"
fusermount3 -u ${MNT}

cd -