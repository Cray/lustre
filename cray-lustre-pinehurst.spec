%define vendor_name lustre
%define vendor_version 2.7.1.0
%define flavor default

%define intranamespace_name %{vendor_name}-%{flavor}
%define flavorless_name %{namespace}-%{vendor_name}
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk

%define clean_build_root %{nil}

%define local_kernel_version %(rpm -q --qf '%{VERSION}' kernel-cray-devel)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-cray-devel)

BuildRequires: kernel-cray-devel
BuildRequires: redhat-rpm-config
BuildRequires: libselinux-devel
BuildRequires: pkgconfig
BuildRequires: -post-build-checks
BuildRequires: module-init-tools
BuildRequires: python-docutils
Group: System/Filesystems
License: GPLv2
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for CLFS CentOS Nodes
Version: %{vendor_version}_%{local_kernel_version}_%{kernel_release}
Source: %{source_name}.tar.gz
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Provides: liblustreapi.so()(64bit)

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /usr

%description
Userspace tools and files for the Lustre file system on Apollo CentOS nodes.

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

if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=no
fi

CFLAGS="%{optflags} -Werror"
%define ksrc /usr/src/kernels/%{local_kernel_version}-%{kernel_release}.%{_target_cpu}

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ]; then
        %configure --disable-checksum \
           --with-linux=%{ksrc} \
           --enable-ldiskfs
fi
%{__make} %_smp_mflags

%install
# LUSTRE_VERS used in ko versioning.
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

# don't use %makeinstall for CentOS RPMS - it needlessly puts things into 
#  /opt/cray/,.....

make DESTDIR=${RPM_BUILD_ROOT} install 

for dir in var man/man5 etc/sysconfig etc/ha.d; do
    %{__rm} -fr %{buildroot}/$dir
done
%{__rm} -f %{buildroot}/etc/lustre %{buildroot}/etc/ldev.conf

%{__install} -D Module.symvers ${RPM_BUILD_ROOT}/%{_libdir}/symvers/Module.symvers

%post
/sbin/depmod -a

%postun
/sbin/depmod -a

%files
%defattr(-,root,root)
/lib/modules
%exclude %dir /lib/modules
/sbin/mount.lustre
/etc/udev/rules.d
/etc/init.d/*
/etc/modprobe.d/ko2iblnd.conf
%{_bindir}
%exclude %dir %{_bindir}
%{_includedir}
%exclude %dir %{_includedir}
%{_libdir}
%exclude %dir %{_libdir}
%{_libexecdir}
%exclude %dir %{_libexecdir}
%{_mandir}
%exclude %dir %{_mandir}
%{_sbindir}
%exclude %dir %{_sbindir}
%{_datadir}
%exclude %dir %{_datadir} 

%clean
%clean_build_root
