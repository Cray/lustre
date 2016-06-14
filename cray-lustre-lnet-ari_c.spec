%define vendor_name lustre
%define vendor_version 2.7.1.1
%define flavor cray_ari_c
%define intranamespace_name %{vendor_name}-%{flavor}
%define flavorless_name %{namespace}-%{vendor_name}
%define branch trunk
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define rel_path opt/%{namespace}/%{vendor_name}-%{flavor}/%{version}-%{release}

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)
%define KERNELRELEASE  %(rpm -q --qf "%{VERSION}-%{RELEASE}" kernel-source | sed 's/\.[0-9][0-9]*\.[0-9][0-9]*$//')

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: cray-krca-devel
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: module-init-tools
BuildRequires: pkgconfig
BuildRequires: libtool
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}-lnet
Release: %release
Summary: Lustre networking for Gemini Compute Nodes

Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source: %{source_name}.tar.gz
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /

%description
Userspace tools and files for Lustre networking on XT compute nodes.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name}

%build
# LUSTRE_VERS used in ko versioning.
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

# only keep lnet related directories
sed -i '/^SUBDIRS/,/config contrib/d' autoMakefile.am
sed -i '1iSUBDIRS := . @LIBCFS_SUBDIR@ lnet \nDIST_SUBDIRS := @LIBCFS_SUBDIR@ lnet' autoMakefile.am 

[ -f Makefile.in ] && sed -i '/lustre/d' Makefile.in 
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
    chmod +x autogen.sh
    ./autogen.sh
fi

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca lsb-cray-hss`

HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --disable-doc \
           --disable-server \
           --with-o2ib=no \
           --enable-gni \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
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
# LUSTRE_VERS used in ko versioning.
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

# don't use %makeinstall for compute node RPMS - it needlessly puts things into 
#  /opt/cray/,.....

make DESTDIR=${RPM_BUILD_ROOT} install 

# Remove all the extras not needed for CNL
%{__rm} -fr %{buildroot}/etc
for dir in %{_libdir} %{_mandir} %{_bindir} %{_includedir} %{_datadir}; do
    find %{buildroot}$dir -type f | xargs rm -fv
    rm -frv %{buildroot}$dir
done

# all of _prefix/sbin but lctl
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$' | xargs rm -fv

%files
%defattr(-,root,root)
%dir /lib/modules/%{KERNELRELEASE}-%{flavor}
%dir /lib/modules/%{KERNELRELEASE}-%{flavor}/updates
%dir /lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel
%dir /lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel/net
%dir /lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel/net/lustre
/lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel/net/lustre
/sbin/lctl

%clean
%clean_build_root
