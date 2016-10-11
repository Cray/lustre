%define vendor_name lustre
%define vendor_version 2.7.1.10
%define flavor cray_ari_s
%define intranamespace_name %{vendor_name}-%{flavor}_rhine
%define flavorless_name %{namespace}-%{vendor_name}
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk
%define pc_files cray-lustre-api-devel.pc cray-lustre-cfsutil-devel.pc cray-lustre-ptlctl-devel.pc

# Override _prefix to avoid installing into Cray locations under /opt/cray/
%define _prefix    /
%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)
%define cray_kernel_version %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease) 
%define lnet_ko_path lib/modules/%{cray_kernel_version}/updates/kernel/net/lustre

# Override the _mandir so man pages don't end up in /man
%define _mandir /usr/share/man
%define _includedir /usr/include

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
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %{release}
Requires: module-init-tools
Summary: Lustre File System for Aries Service Nodes running CLE Rhine
Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source0: %{source_name}.tar.gz
Source1: %{flavorless_name}-switch-%{branch}.tar.gz
Source99: cray-lustre-rpmlintrc
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%package lnet
Group: System/Filesystems
License: GPL
Requires: module-init-tools
Summary: Lustre networking for Gemini Service Nodes

%description
Kernel modules and userspace tools needed for a Lustre client on XC SLES-based
service nodes running the CLE Rhine release.

%description lnet
Userspace tools and files for Lustre networking on XT SIO nodes.

%package -n cray-lustre-cray_ari_s-devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Header files

%description -n cray-lustre-cray_ari_s-devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name} -a 1

%build
# LUSTRE_VERS used in ko versioning.
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

%{__sed} -e 's/@VERSION@/%{version}-%{release}/g' version.in > .version

export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
        chmod +x autogen.sh
        ./autogen.sh
fi

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca lsb-cray-hss`
if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=no
fi

HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --enable-gni \
           --disable-server \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-o2ib=${O2IBPATH} \
           --with-obd-buffer-size=16384
fi
%{__make} %_smp_mflags

%install
# LUSTRE_VERS used in ko versioning.
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

# don't use %makeinstall for Rhine RPMS - it needlessly puts things into 
# /opt/cray/...

make DESTDIR=${RPM_BUILD_ROOT} install 

pushd %{buildroot}

# etc does not exists in the buildroot in all versions
if [ -e etc ]
then
    for f in lustre lhbadm ldev haconfig; do
        %{__rm} -f etc/init.d/${f}
    done
    %{__rm} -rf etc/ha.d etc/sysconfig etc/ldev.conf
fi

man_path="opt/cray/lustre-cray_ari_s/%{version}-%{release}/man"
if [ -e ${man_path} ]; then
    %{__rm} -rf ${man_path}/man5 ${man_path}/man8/lhbadm.8 ${man_path}/man8/ldev.8
fi

for file in libcfsutil.a libiam.a liblustre.a liblustre.so liblustreapi.a liblustreapi.so libptlctl.a
do
    found=`find %{buildroot} -name $file`
    [ -n "${found}" ] && install -D -m 0644 ${found} %{buildroot}/usr/lib64/${file}
done

popd

for f in %{pc_files}
do
    eval "sed -i 's,^prefix=.*$,prefix=/usr,' %{_sourcedir}/${f}"
    install -D -m 0644  %{_sourcedir}/${f} %{buildroot}/%{_pkgconfigdir}/${f}
    %{__rm} -f %{_sourcedir}/${f}
done
eval "sed -i 's/flavor/%{flavor}/g' %{_sourcedir}/cray-lustre.conf"
install -D -m 0644 %{_sourcedir}/cray-lustre.conf %{buildroot}/etc/ld.so.conf.d/cray-lustre.conf
%{__rm} -f %{_sourcedir}/cray-lustre.conf

# Install module directories and files
%{__install} -D -m 0644 .version %{buildroot}/%{_name_modulefiles_prefix}/.version
%{__install} -D -m 0644 module %{buildroot}/%{_release_modulefile}

%files
%defattr(-,root,root)
%{_prefix}
%dir /etc
%dir /etc/ld.so.conf.d
/etc/ld.so.conf.d/cray-lustre.conf

%files lnet
%defattr(-,root,root)
%dir /%{lnet_ko_path}
/%{lnet_ko_path}
%dir %{_mandir}
%dir %{_mandir}/man8/
%{_mandir}/man8/lctl.8*
%{_mandir}/man8/lst.8*
%{_mandir}/man8/routerstat.8*
%dir %{_sbindir}
%{_sbindir}/lctl
%{_sbindir}/lst
%{_sbindir}/routerstat

%files -n cray-lustre-cray_ari_s-devel
%defattr(-,root,root)
%dir /usr/include/lustre
/usr/include/lustre/*.h
/usr/lib64/*

%post
%{__ln_s} %{_sbindir}/ko2iblnd-probe /usr/sbin

/sbin/ldconfig

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%preun
%{__rm} -f /usr/sbin/ko2iblnd-probe

%postun
if [ "$1" = "0" ]; then
    for f in %{pc_files}
    do
        [ -L /usr/lib64/pkgconfig/${f} ] && %{__rm} -f /usr/lib64/pkgconfig/${f}
    done
fi
/sbin/ldconfig

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%post lnet

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%postun lnet

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%clean
%clean_build_root
