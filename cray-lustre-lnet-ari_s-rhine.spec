%define vendor_name lustre
%define vendor_version 2.7.1.12
%define flavor cray_ari_s
%define namespace_flavor %{namespace}_%{flavor}
%define intranamespace_name %{vendor_name}-%{flavor}_rhine
%define flavorless_name %{namespace}-%{vendor_name}
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk

# Override _prefix to avoid installing into Cray locations under /opt/cray/
%define _prefix    /

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)
%define cray_kernel_version %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease) 
%define lnet_ko_path lib/modules/%{cray_kernel_version}/updates/kernel/net/lustre
# Override the _mandir so man pages don't end up in /man
%define _mandir /usr/share/man

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: module-init-tools
BuildRequires: ofed-devel
BuildRequires: sles-release
BuildRequires: -post-build-checks
BuildRequires: libtool
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}-lnet
Release: %{release}
Requires: module-init-tools
Summary: Lustre networking for Aries Service Nodes running CLE Rhine
Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source0: %{source_name}.tar.gz
Source1: %{flavorless_name}-switch-%{branch}.tar.gz
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Kernel modules and user-space tools for Lustre networking on XC SLES-based
service nodes running the CLE Rhine release.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name} -a 1

%build
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

# only keep lnet related directories
sed -i '/^SUBDIRS/,/config contrib/d' autoMakefile.am
sed -i '1iSUBDIRS := . @LIBCFS_SUBDIR@ lnet \nDIST_SUBDIRS := @LIBCFS_SUBDIR@ lnet' autoMakefile.am 

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

# build lustre/utils/lctl
lustre_build_header="./lustre/include/lustre/lustre_build_version.h"
%{__cp} ./devel/lctl-makefile ./lustre/utils/Makefile.am
build_release=$(grep ^RELEASE ./lustre/autoMakefile | awk '{ print $3}')
echo "#define BUILD_VERSION \"%{lustre_version}\"" > ${lustre_build_header}
echo "#define LUSTRE_RELEASE \"$build_release\"" >> ${lustre_build_header}

pushd ./lustre/utils
%{__make} %_smp_mflags
%{__mkdir_p} %{buildroot}/sbin
%{__cp} lctl %{buildroot}/sbin
popd

%install
# %makeinstall
# don't use %makeinstall for Rhine RPMS - it needlessly puts things into 
# /opt/cray/...
# 
make DESTDIR=${RPM_BUILD_ROOT} install 

# copy the man pages
%{__mkdir_p} %{buildroot}/%{_mandir}/man8
%{__cp} ./lustre/doc/lctl.8 %{buildroot}/%{_mandir}/man8/
%{__cp} ./lustre/doc/lst.8 %{buildroot}/%{_mandir}/man8/
%{__cp} ./lustre/doc/routerstat.8 %{buildroot}/%{_mandir}/man8/

# remove all unwanted files and directories
%{__rm} -rf %{buildroot}/include %{buildroot}/lib64 %{buildroot}/etc
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$|/routerstat$|/lst$' | xargs rm -fv

%files
%defattr(-,root,root)
%dir %{_sbindir}
%{_sbindir}/lctl
%{_sbindir}/lst
%{_sbindir}/routerstat
%dir /%{lnet_ko_path}
/%{lnet_ko_path}
%dir %{_mandir}
%dir %{_mandir}/man8
%{_mandir}/man8

%post

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%postun

DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%clean
%clean_build_root
