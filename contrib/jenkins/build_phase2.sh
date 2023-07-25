#!/bin/bash

umask 022

# Default parameters from Jenkins
JP_NEO_RELEASE=${JP_NEO_RELEASE:-NEO3.X}
JP_SCM_URL=${JP_SCM_URL:-ssh://es-gerrit.hpc.amslabs.hpecorp.net:29418/lustre-wc-rel}
JP_BUILD_MODE=${JP_BUILD_MODE:-full}
JP_VERSION=${JP_VERSION:-2.11}  # never used
JP_VERS_TAG=${JP_VERS_TAG:-x3.1} #never used
JP_NEO_ID=${JP_NEO_ID:-$JP_VERS_TAG} #never used
JP_REPO=${JP_REPO:-lustre} #never used
JP_CLIENT_KERNEL=${JP_CLIENT_KERNEL}
JP_BUILD_OPTIONS=${JP_BUILD_OPTIONS}
JP_TARGET_ARCH=${JP_TARGET_ARCH:-x86_64}
JP_INKERNEL_MOFED=${JP_INKERNEL_MOFED:-no}
JP_CLIENT_DKMS=${JP_INKERNEL_MOFED:-no}

JP_KFI=${JP_KFI}
JP_TARGET_KERNEL=${JP_TARGET_KERNEL}

JP_NEO_LABEL=${JP_NEO_LABEL:-devel}
JP_FS_BACKEND=${JP_FS_BACKEND:-ldiskfs}
SVN_URL=${JP_SCM_URL}
JP_MOFED_VERSION=${JP_MOFED_VERSION}

ADD_REPOS=

BUILD_NUMBER=${BUILD_NUMBER:-1}
RPM_RELEASE=${JP_RPM_RELEASE:-$BUILD_NUMBER}

#
# Lustre Specific parameters
#
# lustre_ib, lustre_opa, lustre

case ${JP_NEO_RELEASE} in
    NEO2.X*|changeling|aero) JP_PACKAGE_NAME=${JP_PACKAGE_NAME:-lustre} ;;
    *) JP_PACKAGE_NAME=${JP_PACKAGE_NAME:-lustre_ib} ;;
esac

[[ ${JP_BUILD_TYPE} == "debug" ]] && BUILD_TYPE="-debug"
[[ -z $JP_MOCK_CFG ]] || JP_NEO_LABEL=custom

JP_OBSOLETES=${JP_OBSOLETES:-2.7.19.8.x8-248_3.10}

#
# These are stock Jenkins variables
#
_PWD=$(pwd)
WORKSPACE=${WORKSPACE:-$_PWD}
BUILD_NUMBER=${BUILD_NUMBER:-3}  #never used

# ---------------------------------
RPMBUILD_DIR=$WORKSPACE

build_iem() {
    PACKAGE=lustre-iem
    VERSION=${JP_VERSION}
    # if [ -d ${WORKSPACE}/contrib/IEM/ ] ; then
    if false; then
        IEM_DIR=${WORKSPACE}/contrib/IEM/
    else
        cd ${WORKSPACE}
        git clone https://csint-ghe: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@github.hpe.com/hpe/hpc-neo-cs_iem_filter.git cs_iem_filter
        ( cd cs_iem_filter && git checkout ${JP_IEM_BRANCH} )
        rc=$?
        if [ $rc != 0 ]; then
            echo "ERROR: missing IEM branch ${JP_IEM_BRANCH}"
            return $rc
        fi
        IEM_DIR=${WORKSPACE}/cs_iem_filter/lustre/IEM
    fi

    SPEC_FILE=${IEM_DIR}/lustre_iem.spec

    RPMVER=${VERSION}.${JP_VERS_TAG}
    RPMREL=${BUILD_NUMBER}

    if [ -d ${WORKSPACE}/.git ] ; then
        SCM_VER=$(git rev-list --max-count=1 HEAD | cut -c1-8)
    fi
    if [ -d ${WORKSPACE}/.svn ] ; then
        SCM_VER=$(svn info ${repo_dir} 2>/dev/null | grep "Revision:" | cut -f2 -d" ")
    fi
    if [ ! -z "${SCM_VER}" ] ; then
       RPMREL=${RPMREL}.${SCM_VER}
    fi
    RPMDIR=${WORKSPACE}/rpmbuild
    mkdir -p ${RPMDIR}/SOURCE
    mkdir -p ${RPMDIR}/SPECS

    if [ ! -f ${SPEC_FILE} ] ; then
        echo "ERROR:  This is not a Seagate source branch -- missing IEM."
        return 0
    fi
    SCRIPT_DIR=`dirname "$(readlink -f "$0")"`

    sh -x ${SCRIPT_DIR}/spec_update.sh ${PACKAGE} ${RPMVER} ${SVN_URL} ${WORKSPACE} ${RPMDIR} ${RPMREL} ${SPEC_FILE}

    #### dja STEP 4: create tarball.
    cd ${IEM_DIR}
    git archive --format=tar HEAD . | gzip > ${RPMDIR}/SOURCE/lustre-iem.tgz
    #### dja STEP 5: create SRPM.  Note: If KVER is used as RPM name
    #### this step can only be done after manually populating mock env.
    mock --buildsrpm -r ${MOCK_CONFIG} --spec ${RPMDIR}/SPECS/${PACKAGE}.spec --sources ${RPMDIR}/SOURCE --resultdir ${RPMDIR} --no-clean --no-cleanup-after

    ####  dja STEP 6: build RPM(s) from SRPM.
    mock --rebuild -r ${MOCK_CONFIG} --no-clean --no-cleanup-after --rebuild ${RPMDIR}/${PACKAGE}*.src.rpm --resultdir ${RPMDIR}

    #
    # Allow Lustre build script to be in IEM repo
    #
    if [ -d ${WORKSPACE}/cs_iem_filter/jenkins ] ; then
      mv ${WORKSPACE}/cs_iem_filter/jenkins  ${WORKSPACE}/
    fi
}

#
# NOTE: Since this is in iem repo instead of lustre repo Jenkins
# already ran in-built copy of IEM build.  This allows manual run
# by copying jenkins directory to lustre repo.
#

# Fix bug from 88ae427ab69c49
sed -i.orig -e '/EXTRA_DIST += @SYMVERFILE@/d' ${WORKSPACE}/autoMakefile.am

# RTP-1910 -- trinity-meta-oem will not install.
sed -i.orig -e '/Obsoletes: *lustre-ldiskfs/a Provides: lustre-ldiskfs' lustre.spec.in

sed -i '/BuildRequires: openmpi/d' lustre.spec.in

# RTP-3731 Also need to fix "Provides"
sed -i -e '/Provides: lustre-lite/a  Provides: lustre' \
    -e '/%package modules/a  Provides: lustre-modules' \
    -e '/%package osd-ldiskfs-mount/a Provides: lustre-osd-ldiskfs-mount' \
    -e '/%package tests/a  Provides: lustre-tests' \
lustre.spec.in

# RTP-3959 Add obsoletes for base packages.
if [ "$JP_PACKAGE_NAME" = "lustre_ib" ] && [ -n "$JP_OBSOLETES" ] ; then

  sed -i -e "/Provides: lustre-lite/a  Obsoletes: lustre < ${JP_OBSOLETES}" \
         -e "/%package modules/a  Obsoletes: lustre-modules < ${JP_OBSOLETES}" \
         -e "/%package osd-ldiskfs-mount/a Obsoletes: lustre-osd-ldiskfs-mount < ${JP_OBSOLETES}" \
         -e "/%package osd-ldiskfs$/a Obsoletes: lustre-osd-ldiskfs < ${JP_OBSOLETES}" \
         -e "/%package tests/a  Obsoletes: lustre-tests < ${JP_OBSOLETES}" \
  lustre.spec.in

fi

# LU-14439 remove hardcoded wc dependency
sed -i 's/ldiskfsprogs >= \(.*\).wc1/ldiskfsprogs >= \1/' lustre.spec.in

RPMBUILD_ARGS='--define "_topdir '${RPMBUILD_DIR}\"' --define "myrelease 1" --define "_srcrpmdir ." --define "kversion 1.2.3"'

sed -i.bak -e 's/eval rpmbuild/rpmbuild/' build/autoMakefile.am.toplevel
sed -i.bak -e "s#\$\$RPMARGS -ta#$RPMBUILD_ARGS -ts#" build/autoMakefile.am.toplevel

! grep -q 'EXTRA_DIST += configs/ads.conf' lustre/utils/Makefile.am  &&
grep -q 'ads.conf' lustre/utils/Makefile.am && \
sed -i.bak -e '/EXTRA_DIST/a EXTRA_DIST += configs/ads.conf' lustre/utils/Makefile.am

# 2.x
sed -i.bak -e "s#@RPMBUILD_SOURCE_ARGS@#$RPMBUILD_ARGS#" autoMakefile.am

# moduledir fix
sed -i .bak -e "s/IN_KERNEL=\"\${PACKAGE}\"/IN_KERNEL=\"$JP_PACKAGE_NAME\"/" config/lustre-build-linux.m4

if [ -f LUSTRE-VERSION-GEN ]
then
    #Remove _dirty suffix
    sed -i.bak -e 's/VN-dirty/VN/g' LUSTRE-VERSION-GEN
    ./LUSTRE-VERSION-GEN
fi

LUSTRE_DEVEL="openldap-devel gcc libyaml-devel lsof pciutils procps module-init-tools zlib-devel libtool git swig libblkid-devel flex bison"
EL7_DEVEL=python-devel
EL8_DEVEL=
EL9_DEVEL=

ZFS7_DEVEL="zfs libzfs2-devel libzpool2 libzfs2 kmod-zfs-devel kmod-zfs libselinux-devel net-snmp-devel libyaml-devel python-docutils"
ZFS8_DEVEL="zfs libzfs5-devel libzpool5 libzfs5 kmod-zfs-devel kmod-zfs libselinux-devel net-snmp-devel libyaml-devel python2-docutils"
ZFS9_DEVEL="zfs libzfs5-devel libzpool5 libzfs5 kmod-zfs-devel kmod-zfs libselinux-devel net-snmp-devel libyaml-devel python2-docutils"

if [ ! -z "$JP_KFI" ]
then
    o_opt="${o_opt} --with-kfi=$JP_KFI"
    LUSTRE_DEVEL="$LUSTRE_DEVEL cray-kfabric-devel"
fi

[[ ${JP_NEO_RELEASE:3} = "4.X" ]] || [[ ${JP_NEO_RELEASE:3} > "4.3" ]] &&
    ZFS7_DEVEL="zfs libzfs5-devel libzpool5 libzfs5 kmod-zfs-devel kmod-zfs libselinux-devel net-snmp-devel libyaml-devel python-docutils"


[[ "${JP_BUILD_TYPE}" == "debug" ]] && DOTDEBUG="*debug"


if [ -z $JP_CLIENT_TARGET ]
then
    DISTRO=$(echo ${JP_CLIENT_KERNEL} | sed 's/.*el//' | tr '_' '.')
else
    DISTRO=${JP_CLIENT_TARGET#el}
fi

DISTRO=${DISTRO:-8}
[[ $JP_NEO_RELEASE =~ ORNL.* ]] && ORNL=${$JP_NEO_RELEASE#ORNL}


case $JP_BUILD_MODE in
    full)
        MOCK_CONFIG=${JP_MOCK_CFG:-mock_${JP_NEO_RELEASE}}
        DISTRO=8
        [[ $JP_NEO_RELEASE =~ CSL3.*|NEO3.*|NEO4.*|CSL4.* ]] && DISTRO=7
        REPO_OPTS="--enablerepo=kernel_${JP_NEO_LABEL} --enablerepo=drivers_${JP_NEO_LABEL} --enablerepo=devvm_${JP_NEO_LABEL}"
        if [ ! -z ${JP_TARGET_KERNEL} ] && [[ $JP_NEO_RELEASE =~ ORNL.* ]]
        then
            REPOBASE=http://appdev-vm.hpc.amslabs.hpecorp.net/yum/build/results/projects/ORNL${ORNL}/
            ADD_REPOS="-a http://debuginfo.centos.org/8/x86_64/ \
                        -a ${REPOBASE}/ORNL${ORNL}_cassini_driver/latest/${JP_TARGET_KERNEL} \
                        -a ${REPOBASE}/ORNL${ORNL}_vendor_modules/latest/${JP_TARGET_KERNEL} \
                        -a ${REPOBASE}/ORNL${ORNL}_kernel/${JP_TARGET_KERNEL}"
        fi
        # RTP-3731 Add support for variable lustre name.
        sed -i -e "$(eval echo '/@RPMBUILD_BINARY_ARGS@/i\\\\t\\t --define \"lustre_name ${JP_PACKAGE_NAME}\" \\\\')" ${WORKSPACE}/autoMakefile.am
        JP_CLIENT_KERNEL=${JP_TARGET_KERNEL:+-$JP_TARGET_KERNEL}
        if [ "${JP_PACKAGE_NAME}" != "lustre_opa" ] && [[ ! $JP_INKERNEL_MOFED =~ true|yes|^1$ ]] ; then
            # include OFED if this is a IB or IB/Ethernet build
            LUSTRE_DEVEL+=" mlnx-ofa_kernel-devel"
        fi
    ;;
    client)
        MOCK_CONFIG="epel-${DISTRO}-${JP_TARGET_ARCH}"
##        c_opt=$c_opt' --with lnet_dlc --define "_with_lnet_dlc lnet_dlc"'
        c_opt="${c_opt} --without servers"
        JP_PACKAGE_NAME=lustre-client
        [ -z ${JP_CLIENT_KERNEL} ] || JP_CLIENT_KERNEL="-${JP_CLIENT_KERNEL}"
    ;;
    patchless)
        DEFAULT_MOCK="epel-${DISTRO}-${JP_TARGET_ARCH}"
        MOCK_CONFIG=${JP_MOCK_CFG:-$DEFAULT_MOCK}
        [ -z ${JP_CLIENT_KERNEL} ] || JP_CLIENT_KERNEL="-${JP_CLIENT_KERNEL}"
    ;;
esac

RPMDIR=${WORKSPACE}/rpmbuild
PID=$$
MOCK_CMD="/usr/bin/mock -r ${MOCK_CONFIG} $ADD_REPOS --resultdir=${RPMDIR} ${REPO_OPTS} --uniqueext ${PID}"
[ -n "$JP_ADD_REPOS" ] && MOCK_CMD="$MOCK_CMD $(for repo in $JP_ADD_REPOS; do echo -n " -a $repo"; done)"

# Note: Increment base for each new project so that versions is always greater than previous release.
VERS_TAG=${JP_VERS_TAG} #never used

# Create output directory
rm -rf ${RPMDIR}
mkdir ${RPMDIR}
rm -f build_failed

# Select mock config for the kernel we are building with
PROJECT=${JP_NEO_RELEASE}

if [ -z "$JP_NO_IEM" ] ; then
    build_iem
    [ $? != 0 ] && echo "cannot build IEM" > build_failed
fi


GITHASH=$(git rev-parse HEAD | cut -c1-8)
GITHASH=${GITHASH:+_g${GITHASH}}
[[ ${JP_NEO_RELEASE} =~ CSL3.0 ]] && RPM_SUFFIX=${GITHASH}
ROOT=$(${MOCK_CMD}  -p)

${MOCK_CMD} --init
${MOCK_CMD} $REPO_OPTS --install kernel${BUILD_TYPE}-devel${JP_CLIENT_KERNEL} kernel${BUILD_TYPE}${JP_CLIENT_KERNEL}

rval=$?
if [ "$rval" != "0" ] ; then
  touch build_failed
fi

[ "$JP_BUILD_MODE" != "full" ] && [ -z $JP_CLIENT_KERNEL ] && \
    JP_CLIENT_KERNEL=-$(${MOCK_CMD}  --chroot "rpm -q --qf '%{VERSION}-%{RELEASE}' kernel${BUILD_TYPE}-devel 2>/dev/null")

if [[ $JP_BUILD_MODE == patchless ]] || ([[ $JP_BUILD_MODE == full ]] && [[ $JP_NEO_RELEASE =~ ORNL.*|CSL6.*|NEO6.*|TST6.* ]])
then
    LUSTRE_DEVEL+=" kernel-debuginfo${JP_CLIENT_KERNEL} kernel-debuginfo-common-${JP_TARGET_ARCH}${JP_CLIENT_KERNEL}"
fi

ADD_PKG=EL${DISTRO/.*/}_DEVEL
${MOCK_CMD} --install ${LUSTRE_DEVEL} ${!ADD_PKG}
rval=$?
if [ "$rval" != "0" ] ; then
  touch build_failed
fi

# Install MOFED
# JP_MOFED_VERSION variable should look like "4.7-el7.6"
if [ "$JP_BUILD_MODE" == "client" ] && [ ! -z ${JP_MOFED_VERSION} ]
then
    MOFED_PKGS="mlnx-ofa_kernel mlnx-ofa_kernel-devel kmod-mlnx-ofa_kernel"
    [ "$JP_MOFED_VERSION" != "external" ] && MOFED_OPTS="--enablerepo=mofed-${JP_MOFED_VERSION}"
    mkdir ${WORKSPACE}/mofed
    ${MOCK_CMD} ${MOFED_OPTS} --install $MOFED_PKGS
    [ "$?" != "0" ] && echo "cannot install mofed-${JP_MOFED_VERSION}" > build_failed

    ${MOCK_CMD} ${MOFED_OPTS} --dnf-cmd download $MOFED_PKGS --destdir ${WORKSPACE}/mofed
fi

# mpich-devel installation will fail on el6-targeted releases since they don't
# have mpich in their repos
${MOCK_CMD} --install mpich-devel || true

# make mpich binaries visible for configure script
# that's a hack, but mpiselect doesn't work with mpich for some reason
${MOCK_CMD} --chroot " [ -d /usr/lib64/mpich ]   && ln -sf /usr/lib64/mpich/bin/* /usr/bin/"
${MOCK_CMD} --chroot " [ -d /usr/lib64/mpich-* ] && ln -sf /usr/lib64/mpich-*/bin/* /usr/bin/"

c_opt="$c_opt --with lnet_dlc"

ZFS_DEV_NAME=ZFS${DISTRO/.*/}_DEVEL
ZFS_DEVEL=${!ZFS_DEV_NAME}

if [ "$JP_BUILD_MODE" == "full" ]
then
case ${JP_FS_BACKEND} in
    ldiskfs)
    b_opt="--without zfs"
    ;;
    zfs)
    b_opt="--without ldiskfs --with zfs"
    ${MOCK_CMD}  --install ${ZFS_DEVEL}
    rval=$?
    if [ "$rval" != "0" ] ; then
        touch build_failed
    fi
    ;;
    both)
    b_opt="--with ldiskfs --with zfs"
    ${MOCK_CMD}  --install ${ZFS_DEVEL}
    rval=$?
    if [ "$rval" != "0" ] ; then
        touch build_failed
    fi
    ;;
esac
fi

${MOCK_CMD} --chroot "test -d /usr/src/ofa_kernel/default"
rc=$?
if [ $rc == 0 ]; then
    o_opt="$o_opt --with-o2ib=/usr/src/ofa_kernel/default"
else
    o_opt="$o_opt --with-o2ib"
fi

rm -f ${WORKSPACE}/*.src.rpm
${MOCK_CMD} --chroot  "rm -rf /build/lustre"
${MOCK_CMD} --copyin ${WORKSPACE} /build/lustre
${MOCK_CMD} --cwd /build/lustre/ --chroot "sh autogen.sh"
${MOCK_CMD} --cwd /build/lustre/ --chroot "touch META"
${MOCK_CMD} --cwd /build/lustre/ --chroot "sh ./configure --enable-dist"
${MOCK_CMD} --cwd /build/lustre/ --chroot "make srpm"
${MOCK_CMD} --copyout /build/lustre/*.src.rpm ${WORKSPACE}
srpm=$(ls ${WORKSPACE}/*.src.rpm)

if [ -z ${JP_ENABLE_GSS+x} ]
then
  WITH_GSS_KEYRING=WITHOUT_gss_keyring
else
  WITH_GSS_KEYRING=with_gss_keyring
fi

KERNEL=$(rpm -r $ROOT -q --qf '%{VERSION}-%{RELEASE}'  kernel${BUILD_TYPE}-devel)
K_ARCH=$JP_TARGET_ARCH
release=$(echo "${KERNEL}" | tr "-" "_")
${MOCK_CMD}  --no-clean --rebuild ${srpm} --define "myrelease ${release}${GITHASH}" --define "configure_args ${o_opt} ${JP_BUILD_OPTIONS}" \
    --define "kver ${KERNEL}${DOTDEBUG}" --define "kversion ${KERNEL}.${K_ARCH}${DOTDEBUG}" --define "kdir /usr/src/kernels/${KERNEL}.${K_ARCH}${DOTDEBUG}" \
    --define "lustre_name ${JP_PACKAGE_NAME}"  \
    --define "mpi_name mpich" \
    --define "$WITH_GSS_KEYRING 1" \
    --define "rpm_rel ${RPM_RELEASE}" \
    --define "_rpmfilename %%{NAME}-%%{VERSION}_${release}${RPM_SUFFIX}.%%{ARCH}.rpm" \
    --rpmbuild-opts="${c_opt} ${b_opt}"

rval=$?
if [ "$rval" != "0" ] ; then
  rejects=$(find $ROOT -name *.rej)
  echo $rejects
  [ ! -z $rejects ] && cp $rejects ${RPMDIR}
  touch build_failed
fi

# RTP-3731 / LUS-5946  Do not include src.rpm or iokit for lustre_opa build since they have
# identical names to the lustre_ib results.
if [ "${JP_PACKAGE_NAME}" == "lustre_opa" ] ; then
  rm -rf ${RPMDIR}/RPMS/lustre-iokit* || true
  rm -rf ${RPMDIR}/SRPMS/lustre*.src.rpm || true
fi

mkdir -p $RPMDIR/RPMS $RPMDIR/SRPMS
mv $RPMDIR/*.src.rpm $RPMDIR/SRPMS
mv $RPMDIR/*.rpm $RPMDIR/RPMS
[ -e ${WORKSPACE}/mofed ] && mv ${WORKSPACE}/mofed/*  $RPMDIR/RPMS
${MOCK_CMD} --scrub=bootstrap --clean

if [ -f build_failed ] ; then
    echo "RPM Build(s) failed"
    exit -3
else
    echo "Complete Build"
    exit 0
fi
