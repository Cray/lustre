#! /bin/bash

# Copyright 2023 Hewlett Packard Enterprise Development LP

umask 022

SHA=${GIT_COMMIT:0:6}
zipFile=lustre-${JP_BRANCH}.B${BUILD_NUMBER}.g${SHA}.zip
logFile=git-log-${JP_BRANCH#cray-}.txt


# CSRE-1331:
BNUM=$(printf "B%02d" $BUILD_NUMBER)
git tag -a -m "CSRE-1331" ${JP_BRANCH}.${BNUM} ${GIT_COMMIT}
git config remote.origin.url git@github.hpe.com:hpe/hpc-lus-filesystem.git

if [ "$JP_PUSH_TAG" = "yes" ]; then
   git push --tags
fi

# CSRE-1141
git log --oneline > $logFile

# CSRE-897:
sh ./autogen.sh 
./configure --enable-dist

make srpm

if [ ! -f lustre-*.src.rpm ]; then
   echo "SRPM not found"
   exit 1
fi

mkdir rpmbuild
cp lustre-*.src.rpm rpmbuild/

echo "Completed copying rpm to rpmbuild/"
