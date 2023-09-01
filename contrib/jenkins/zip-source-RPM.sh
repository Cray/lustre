#! /bin/bash

# Copyright 2023 Hewlett Packard Enterprise Development LP

umask 022
SHA=${GIT_COMMIT:0:6}
zipFile=lustre-${JP_BRANCH}.B${BUILD_NUMBER}.g${SHA}.zip
logFile=git-log-${JP_BRANCH#cray-}.txt

sha1sum rpmbuild/lustre-*.src.rpm > rpmbuild/SHA1SUM.txt
sha256sum rpmbuild/lustre-*.src.rpm > rpmbuild/SHA256SUM.txt
zip -r $zipFile rpmbuild/lustre-*.src.rpm
zip -g $zipFile rpmbuild/SHA1SUM.txt
zip -g $zipFile rpmbuild/SHA256SUM.txt
zip -g $zipFile $logFile

echo "Complet creation of lustre source zip"

storDir=/releng/iso/build/neo/lustre-sourcefiles/$JP_BRANCH
mkdir -p $storDir

cp $WORKSPACE/$zipFile $storDir
echo "Copied lustre sourcefiles to releng-serv1."

echo "[DESC] ftp://releng-serv1.hpc.amslabs.hpecorp.net/images/build/neo/lustre-sourcefiles/${JP_BRANCH}/$zipFile [END DESC]"

