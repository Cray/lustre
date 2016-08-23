%define vendor_name lustre
%define vendor_version 2.7.1.5
%if %{with athena}
%define flavor cray_ari_athena_c_cos
%else
%define flavor cray_ari_c
%endif
%define intranamespace_name %{vendor_name}-%{flavor}
%define flavorless_name %{namespace}-%{vendor_name}
%define branch trunk
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}

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
BuildRequires: pkgconfig
BuildRequires: udev
BuildRequires: libtool
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for CNL
Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source: %{source_name}.tar.gz
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%package lnet
Group: System/Filesystems
License: GPL
Summary: Lustre networking for Gemini Compute Nodes

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /

%description
Userspace tools and files for the Lustre file system on XT compute nodes.

%description lnet
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

%install
# LUSTRE_VERS used in ko versioning.
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

# don't use %makeinstall for compute node RPMS - it needlessly puts things into 
#  /opt/cray/,.....

make DESTDIR=${RPM_BUILD_ROOT} install 

for dir in init.d sysconfig ha.d; do
    %{__rm} -fr %{buildroot}/etc/$dir
done
%{__rm} -f %{buildroot}/etc/ldev.conf
%{__rm} -f %{buildroot}/etc/modprobe.d/ko2iblnd.conf
%{__rm} -f %{buildroot}/lib/lustre/haconfig
%{__rm} -f %{buildroot}/lib/lustre/lc_common

# Remove all the extras not needed for CNL
for dir in %{_libdir} %{_mandir} %{_bindir} %{_includedir} %{_datadir}; do
    find %{buildroot}$dir -type f | xargs rm -fv
    rm -frv %{buildroot}$dir
done

# all of _prefix/sbin but lctl
find %{buildroot}%{_sbindir} -print > install_files
find %{buildroot}%{_sbindir} -print | egrep -v '/lctl$' > install_files2
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$|/mount.lustre$' > install_files3
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$|/mount.lustre$' | xargs rm -fv

%files 
%defattr(-,root,root)
/lib/modules/*
/sbin/mount.lustre
/sbin/lctl
%config /etc/udev/rules.d/99-lustre.rules

%files lnet
%defattr(-,root,root)
%if %{with athena}
/lib/modules/*/extra/kernel/net/lustre
%else
/lib/modules/*/updates/kernel/net/lustre
%endif
/sbin/lctl

%clean
%clean_build_root
