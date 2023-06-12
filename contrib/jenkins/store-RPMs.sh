#! /bin/bash

# Copyright 2023 Hewlett Packard Enterprise Development LP
# Store RPMs and SRPMs in /build/results

REPO=${JP_REPO}

umask 022
mkdir -p /build/repos/${REPO}

LATEST_REPO=/build/repos/${REPO}/latest_${JOB_NAME##*/}
YYYY=`date +%Y`
MM=`date +%m`
DD=`date +%d`
RESULTS_BASE=/build/results/${YYYY}/m${MM}/d${DD}
RESULTS=${RESULTS_BASE}/${JOB_NAME##*/}.B${BUILD_NUMBER}

mkdir -p ${RESULTS_BASE}
mkdir ${RESULTS}

# Store RPMs
cp ${WORKSPACE}/rpmbuild/RPMS/* ${RESULTS}
if [ "${JP_PACKAGE_NAME}" != "lustre_opa" ] ; then
  cp ${WORKSPACE}/rpmbuild/SRPMS/* ${RESULTS}
fi

# Setup new yum repo
createrepo ${RESULTS}

[ -L $LATEST_REPO ] && unlink $LATEST_REPO
ln -s ${RESULTS} $LATEST_REPO

# Store source repository data with result
/build/bin/get_srcrepodata.sh > ${RESULTS}/srcrepodata

# Save artifact manifest and location
sha1sum $(ls ${RESULTS}/*.rpm 2>/dev/null) > packages.txt

echo "Complete Storage"
