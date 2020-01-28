MNT="workspace/mountpoint"

echo "[-] Clearing replicas"
./prepare_env.sh > /dev/null
echo "[+] Cleared replicas"

./uselessfs @config/3-two-block-replicas.cfg ${MNT} 
echo ""
echo "Write/read test with Hamming code correction"
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

echo "Swapping 't' for 'u':"
sed -e "s/t/u/g" "${MNT}"/testfile
echo ""
echo "File content:"
cat ${MNT}/testfile

fusermount3 -u ${MNT}
