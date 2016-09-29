%define vendor_name lustre
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define flavor cray_gem_s
%define namespace_flavor %{namespace}_%{flavor}
%define intranamespace_name %{vendor_name}-%{flavor}
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}
%define branch trunk
%define pc_files cray-lustre-api-devel.pc cray-lustre-cfsutil-devel.pc cray-lustre-ptlctl-devel.pc

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
Requires: cray-lustre-utils >= %{branch}-1.0000.18191.0
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %{release}
Requires: %{switch_requires}
Summary: Lustre File System for Gemini Service Nodes
Version: %{_version}_%{kernel_version}_%{kernel_release}
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

%description lnet
Userspace tools and files for Lustre networking on XT SIO nodes.

%package -n cray-lustre-cray_gem_s-devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Header files

%description -n cray-lustre-cray_gem_s-devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{source_name} -a 1

%build
# LUSTRE_VERS used in ko versioning.
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{_version}-${LUSTRE_VERS}

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
%makeinstall

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

for header in  libiam.h lustreapi.h liblustreapi.h ll_fiemap.h lustre_idl.h lustre_user.h; do
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
for f in %{pc_files}
do
    eval "sed -i 's/flavor/%{flavor}/g' %{_sourcedir}/${f}"
    install -D -m 0644  %{_sourcedir}/${f} %{buildroot}/%{_pkgconfigdir}/${f}
    %{__rm} -f %{_sourcedir}/${f}
done
eval "sed -i 's/flavor/%{flavor}/g' %{_sourcedir}/cray-lustre.conf"
install -D -m 0644 %{_sourcedir}/cray-lustre.conf %{buildroot}/etc/ld.so.conf.d/cray-lustre.conf
%{__rm} -f %{_sourcedir}/cray-lustre.conf

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
%dir /opt
%dir /opt/cray
%dir /opt/cray/lustre-cray_gem_s
%dir /opt/cray/lustre-cray_gem_s/%{version}-%{release}
%dir /opt/cray/lustre-cray_gem_s/%{version}-%{release}/lib64
%dir /opt/cray/lustre-cray_gem_s/%{version}-%{release}/lib64/pkgconfig/
/opt/cray/lustre-cray_gem_s/%{version}-%{release}/lib64/pkgconfig/*.pc

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
%dir /usr/include/lustre
/usr/include/lustre/*.h
/usr/lib64/*

%post
%{__ln_s} %{_sbindir}/ko2iblnd-probe /usr/sbin

for f in %{pc_files}
do
    %{__ln_s} -f /opt/cray/lustre-%{flavor}/default/lib64/pkgconfig/${f} /usr/lib64/pkgconfig/${f}
done
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

%clean
%clean_build_root
