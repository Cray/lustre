#!/bin/bash -xv

# Modify Spec file

[ $# -ne 7 ] && echo "Usage: " && exit 1

name=$1
version=$2
url=$3
repo_dir=$4
RPMBLDDIR=$5
BUILD_NUMBER=$6
SRCSPECFILE=$7

SRCSPECFILE=${SRCSPECFILE:-${repo_dir}/${name}.spec}
RPMSPECFILE=${RPMBLDDIR}/SPECS/${name}.spec

sed -e '/#xyr build defines/,/#xyr end defines/d'  ${SRCSPECFILE} > ${RPMSPECFILE}.in

echo "#xyr build defines" > ${RPMSPECFILE}
echo "%define _xyr_package_name     ${name}" >> ${RPMSPECFILE}
echo "%define _xyr_package_source   ${name}.tgz" >>  ${RPMSPECFILE}
echo "%define _xyr_package_version  ${version}" >>  ${RPMSPECFILE}
echo "%define _xyr_build_number     ${BUILD_NUMBER}" >>  ${RPMSPECFILE}

if [ ! -z "${url}" ] ; then
     echo "%define _xyr_pkg_url          ${url}" >> ${RPMSPECFILE}
fi
if [ -d ${repo_dir}/.git ] ; then
    svn_ver=$(git rev-list --max-count=1 HEAD | cut -c1-8)
fi
if [ -d ${repo_dir}/.svn ] ; then
    svn_ver=$(svn info ${repo_dir} 2>/dev/null | grep "Revision:" | cut -f2 -d" ")
fi

if [ ! -z "${svn_ver}" ] ; then
   echo "%define _xyr_svn_version      ${svn_ver}" >> ${RPMSPECFILE}
fi

echo "#xyr end defines" >> ${RPMSPECFILE}

cat ${RPMSPECFILE}.in >> ${RPMSPECFILE}
rm ${RPMSPECFILE}.in

