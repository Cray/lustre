%define vendor_name lustre
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define flavor cray_gem_s
%define namespace_flavor %{namespace}_%{flavor}
%define intranamespace_name %{vendor_name}-%{flavor}
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}
%define branch trunk
%define pc_files cray-lustre-api-devel.pc cray-lustre-ptlctl-devel.pc cray-lustre-cfsutil-devel.pc cray-lnet.pc

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: cray-krca-devel
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: module-init-tools
BuildRequires: ofed-devel
BuildRequires: pkgconfig
BuildRequires: sles-release
BuildRequires: -post-build-checks
BuildRequires: libtool
BuildRequires: libyaml-devel zlib-devel
Requires: cray-lustre-utils >= %{branch}-1.0000.18191.0
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %{release}
Requires: %{switch_requires}
Summary: Lustre File System for Gemini Service Nodes
Version: %{_version}_%{kernel_version}
Source0: %{source_name}.tar.bz2
Source1: %{vendor_namespace}-%{vendor_name}-switch-%{_version}.tar.bz2
Source99: cray-lustre-rpmlintrc
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%package lnet
Group: System/Filesystems
License: GPL
Summary: Lustre networking for Gemini Service Nodes

%description
Userspace tools and files for the Lustre file system on XT SIO nodes.
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%description lnet
Userspace tools and files for Lustre networking on XT SIO nodes.
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%package -n cray-lustre-cray_gem_s-devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Header files

%description -n cray-lustre-cray_gem_s-devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{source_name} -a 1

%build
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{_version}-%{branch}-%{release}-%{build_user}-%{version_path}-%{date}

# Sets internal kgnilnd build version
export SVN_CODE_REV=%{lustre_version}

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
        chmod +x autogen.sh
        ./autogen.sh
fi

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca`
if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=no
fi

syms="$(pkg-config --variable=symversdir cray-gni)/cray_ari_s/Module.symvers"
syms="$syms $(pkg-config --variable=symversdir cray-krca)/cray_ari_s/Module.symvers"

export KBUILD_EXTRA_SYMBOLS=${syms}

CFLAGS="%{optflags} -Werror -fno-stack-protector"

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --enable-gni \
           --disable-server \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-o2ib=${O2IBPATH} \
           --with-obd-buffer-size=16384
fi
%{__make} %_smp_mflags

#
# make switching file
#
pushd switch

%CRAYconfigure -- --with-module=%{_release_modulefile}

%{__make} %_smp_mflags

popd

%install
# Sets internal kgnilnd build version
export SVN_CODE_REV=%{lustre_version}

%makeinstall

cp -var %{buildroot}/usr/include/* %{buildroot}%{_includedir}

#
# Make all files from lustre switchable
#
pushd %{buildroot}

SWITCH_ROOTS="lib sbin"

# etc does not exists in the buildroot in all versions
if [ -e etc ]
then
    SWITCH_ROOTS="${SWITCH_ROOTS} etc"
    for f in lustre lhbadm ldev haconfig; do
        %{__rm} -f etc/init.d/${f}
    done
    %{__rm} -rf etc/ha.d etc/sysconfig etc/ldev.conf
fi

man_path="opt/cray/lustre-cray_gem_s/%{version}-%{release}/man"
if [ -e ${man_path} ]; then
    %{__rm} -rf ${man_path}/man5 ${man_path}/man8/lhbadm.8 ${man_path}/man8/ldev.8
fi

SWITCH_DIRS=`find ${SWITCH_ROOTS} -type d -printf "%%p "`
SWITCH_FILES=`find ${SWITCH_ROOTS} -type f -printf "%%p "`

for header in libiam.h lustreapi.h liblustreapi.h ll_fiemap.h ; do
    found=`find %{buildroot} -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            install -D -m 0644 ${each} %{buildroot}/usr/include/`echo $each | sed 's/^.*include\///'`
        done
    fi
done

for file in libcfsutil.a libiam.a liblustre.a liblustre.so liblustreapi.a liblustreapi.so libptlctl.a
do
    found=`find %{buildroot} -name $file`
    [ -n "${found}" ] && install -D -m 0644 ${found} %{buildroot}/usr/lib64/${file}
done

### Include files.
### ----------------------------------------------------------------------------

for header in api.h lib-lnet.h lib-types.h
do
    found=`find %{_builddir}/cray-lustre-%{_version}/lnet/include/lnet -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            incl=$(echo ${each} | sed 's:^.*/BUILD/::' | cut -d'/' -f4-)
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/${incl}
        done
    fi
done

for header in libcfs_debug.h lnetctl.h lnetst.h libcfs_ioctl.h lnet-dlc.h \
	      lnet-types.h nidstr.h
do
    found=`find %{_builddir}/cray-lustre-%{_version}/lnet/include/uapi -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            incl=$(echo ${each} | sed 's:^.*/BUILD/::' | cut -d'/' -f4-)
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/${incl}
        done
    fi
done

for header in bitmap.h curproc.h libcfs_cpu.h libcfs_debug.h \
	      libcfs_fail.h  libcfs.h libcfs_hash.h libcfs_heap.h \
	      libcfs_prim.h libcfs_private.h libcfs_string.h  \
	      libcfs_workitem.h range_lock.h linux-cpu.h linux-crypto.h \
	      linux-fs.h linux-mem.h linux-misc.h linux-time.h
do
    found=`find %{_builddir}/cray-lustre-%{_version}/libcfs/include/libcfs -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            incl=$(echo ${each} | sed 's:^.*/BUILD/::' | cut -d'/' -f5-)
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/libcfs/${incl}
        done
    fi
done

for header in  hash.h ioctl.h list.h param.h parser.h string.h
do
    found=`find %{_builddir}/cray-lustre-%{_version}/libcfs/include/libcfs/util -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            incl=$(echo ${each} | sed 's:^.*/BUILD/::' | cut -d'/' -f5-)
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/libcfs/${incl}
        done
    fi
done


## 

for header in linux-fs.h linux-mem.h linux-time.h linux-cpu.h linux-crypto.h \
	      linux-misc.h
do
    found=`find %{_builddir}/cray-lustre-%{_version}/libcfs/include/libcfs/linux -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            incl=$(echo ${each} | sed 's:^.*/BUILD/::' | cut -d'/' -f4-)
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/${incl}
        done
    fi
done

for header in interval_tree.h
do
    found=`find %{_builddir} -name $header`
    if [ -n "${found}" ]; then
        for each in ${found}; do
            install -D -m 0644 ${each} %{buildroot}%{_includedir}/${header}
        done
    fi
done

install -D -m 0644 %{_builddir}/cray-lustre-%{_version}/config.h %{buildroot}%{_includedir}/lustre/%{flavor}/config.h
install -D -m 0644 %{_builddir}/cray-lustre-%{_version}/Module.symvers %{buildroot}/opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/symvers/%{flavor}/Module.symvers

popd


# file for switching in post/preun scriptlets
%{__mkdir_p} %{buildroot}/%{_sysconfdir}

rm -f %{buildroot}/%{_sysconfdir}/switch.files
for file in ${SWITCH_FILES}
do
    echo "${file}" >> %{buildroot}/%{_sysconfdir}/switch.files
    install -D %{buildroot}/${file} %{buildroot}/%{_prefix}/${file}
    %{__rm} -f %{buildroot}/${file}
done

#-------------------------------------------------------------------------------

for seekf in %{pc_files} ; do
    f=`find %{_builddir} -name ${seekf}`
    if [ -n "${f}" ] ; then
        eval "sed -i 's/flavor/%{flavor}/g' ${f}"
        eval "sed -i 's,@PACKAGE_VERSION@,%{_version},' ${f}"
        eval "sed -i 's,@includedir@,%{_includedir},' ${f}"
        eval "sed -i 's,@libdir@,%{_libdir},' ${f}"
        eval "sed -i 's,@symversdir@,/opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/symvers/%{flavor},' ${f}"
        eval "sed -i 's,@cfgdir@,%{_includedir}/lustre/%{flavor},' ${f}"
        install -D -m 0644 ${f} %{buildroot}/opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/pkgconfig/${seekf}
    fi
done

mkdir -p %{buildroot}/etc/ld.so.conf.d
touch %{buildroot}/etc/ld.so.conf.d/cray-lustre.conf
f=`find %{_builddir} -name cray-lustre.conf`
if [ -n "${f}" ] ; then
    eval "sed -i 's/flavor/%{flavor}/g' ${f}"
    install -D -m 0644 ${f} %{buildroot}/etc/ld.so.conf.d/cray-lustre.conf
fi

grep 'net/lustre' %{buildroot}/%{_sysconfdir}/switch.files > %{buildroot}/%{_sysconfdir}/switch.files.lnet

# clear switch.directories so incremental builds of different flavors don't
# both append to the same file
rm -f switch.directories
rm -f switch.directories.lraw
for directory in ${SWITCH_DIRS}
do
    echo "%dir /${directory}" >> switch.directories
    echo "%dir /${directory}" >> switch.directories.lraw
    echo "%{_release_prefix}/${directory}" >> switch.directories.lraw
done
grep 'net/lustre' switch.directories.lraw > switch.directories.lnet

#
# install switching files
#
pushd switch

%makeinstall

popd

%files -f switch.directories
%defattr(-,root,root)
%prefixdirs
%switch_files
%{_prefix}
%dir /etc
%dir /etc/ld.so.conf.d
/etc/ld.so.conf.d/cray-lustre.conf
%exclude %{_sysconfdir}/lustre/perm.conf
%exclude /etc/lustre

%files lnet -f switch.directories.lnet
%defattr(-,root,root)
%prefixdirs
%dir %{_mandir}
%dir %{_mandir}/man8
%dir %{_sbindir}
%dir %{_sysconfdir}
%{_sbindir}/lctl
%{_sbindir}/routerstat
%switch_files
%{_sysconfdir}/switch.files.lnet
%{_mandir}/man8/lctl.8
%{_mandir}/man8/lst.8

%files -n cray-lustre-cray_gem_s-devel
%defattr(-,root,root)
/usr/lib64/*
%dir /opt
%dir /opt/cray
%dir /opt/cray/lustre-%{flavor}
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs/linux
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs/util
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/linux/lnet
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/linux/lustre
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lnet
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lustre/
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/uapi
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/uapi/linux
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/uapi/linux/lnet
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lustre/%{flavor}
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/pkgconfig
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/symvers
%dir /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/symvers/%{flavor}
/opt/cray/lustre-cray_gem_s/%{version}-%{release}/lib64/pkgconfig/*.pc
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/interval_tree.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs/linux/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/libcfs/util/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/linux/lnet/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/linux/lustre/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lnet/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lustre/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/lustre/%{flavor}/config.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/include/uapi/linux/lnet/*.h
/opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/symvers/%{flavor}/Module.symvers
%exclude /usr/include/linux/lnet/libcfs_debug.h
%exclude /usr/include/linux/lnet/libcfs_ioctl.h
%exclude /usr/include/linux/lnet/lnet-dlc.h
%exclude /usr/include/linux/lnet/lnet-types.h
%exclude /usr/include/linux/lnet/lnetctl.h
%exclude /usr/include/linux/lnet/lnetst.h
%exclude /usr/include/linux/lnet/nidstr.h
%exclude /usr/include/linux/lnet/socklnd.h
%exclude /usr/include/linux/lustre/lustre_cfg.h
%exclude /usr/include/linux/lustre/lustre_fid.h
%exclude /usr/include/linux/lustre/lustre_fiemap.h
%exclude /usr/include/linux/lustre/lustre_idl.h
%exclude /usr/include/linux/lustre/lustre_ioctl.h
%exclude /usr/include/linux/lustre/lustre_kernelcomm.h
%exclude /usr/include/linux/lustre/lustre_ostid.h
%exclude /usr/include/linux/lustre/lustre_param.h
%exclude /usr/include/linux/lustre/lustre_user.h
%exclude /usr/include/linux/lustre/lustre_ver.h
%exclude /usr/include/lustre/liblustreapi.h
%exclude /usr/include/lustre/ll_fiemap.h
%exclude /usr/include/lustre/lustreapi.h

%post
%{__ln_s} -f %{_sbindir}/ko2iblnd-probe /usr/sbin
%{__ln_s} -f %{_prefix}/sbin/lctl /usr/sbin

/sbin/ldconfig

%install_switch
for file in `cat %{_sysconfdir}/switch.files`
do
    %switchable_link ${file}
done

switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
        switch_extra="-r ${RELEASE_UPDATE}"
fi

/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -l %{version}-%{release} ${switch_extra}

%preun
%{__rm} -f /usr/sbin/lctl
%{__rm} -f /usr/sbin/ko2iblnd-probe

for file in `cat %{_sysconfdir}/switch.files`
do
    %switchable_unlink ${file}
done

%remove_switch

%postun
if [ "$1" = "0" ]; then
    for f in %{pc_files}
    do
        [ -L /usr/lib64/pkgconfig/${f} && %{__rm} -f /usr/lib64/pkgconfig/${f}
    done
fi
/sbin/ldconfig

switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
        switch_extra="-r ${RELEASE_UPDATE}"
fi
/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -u ${switch_extra}

%post lnet
%install_switch
for file in `cat %{_sysconfdir}/switch.files.lnet`
do
    %switchable_link ${file}
done

switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
        switch_extra="-r ${RELEASE_UPDATE}"
fi

/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -l %{version}-%{release} ${switch_extra}

%preun lnet
for file in `cat %{_sysconfdir}/switch.files.lnet`
do
    %switchable_unlink ${file}
done

%remove_switch

%postun lnet
switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
        switch_extra="-r ${RELEASE_UPDATE}"
fi
/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -u ${switch_extra}

%post devel
mkdir -p /usr/include/libcfs/linux
mkdir -p /usr/include/libcfs/util
mkdir -p /usr/include/linux/lnet
mkdir -p /usr/include/linux/lustre
mkdir -p /usr/include/lnet
mkdir -p /usr/include/lustre/%{flavor}

%{__ln_s} -f %{_includedir}/*.h /usr/include
for d in libcfs libcfs/linux libcfs/util linux linux/lnet linux/lustre lnet lustre lustre/%{flavor}
do
     %{__ln_s} -f %{_includedir}/${d}/*.h /usr/include/${d}
done

mkdir -p /usr/lib64/pkgconfig
for f in %{pc_files}
do
    %{__ln_s} -f /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/pkgconfig/${f} /usr/lib64/pkgconfig/${f}
done

%postun devel


%clean
%clean_build_root
