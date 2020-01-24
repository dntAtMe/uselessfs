MNT="workspace/mountpoint"

./uselessfs @config/1-example.cfg ${MNT}

rm -rf r*/
mkdir r1 r2 r3 r4 r5 r6
echo "New file" > ${MNT}/testfile
echo "And another line" >> ${MNT}/testfile
echo -n "And one more\nAnd last one\n" >> ${MNT}/testfile

echo -n"\n\nDirectory: "
ls -al ${MNT}
echo -n "\n\n"

echo -n "File content:\n"
cat ${MNT}/testfile

fusermount3 -u ${MNT}

cd -