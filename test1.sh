MNT="workspace/mountpoint"

./prepare_env.sh > /dev/null
./uselessfs @config/1-two-block-replicas.cfg ${MNT}

echo ""
echo "Write/read test"
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

echo "Directory: "
ls -al ${MNT}
echo ""
echo ""

echo "File content:"
cat ${MNT}/testfile
echo ""
echo ""
fusermount3 -u ${MNT}

cd -