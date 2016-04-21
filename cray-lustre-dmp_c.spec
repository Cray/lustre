%define vendor_name lustre
%define vendor_version 2.7
%define flavor default

%define intranamespace_name %{vendor_name}-%{flavor}
%define flavorless_name %{namespace}-%{vendor_name}

# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)
%define kernel_release_major %(rpm -q --qf "%{RELEASE}" kernel-source |  awk -F . '{print $1}')

%define cray_kernel_version %{kernel_version}-%{kernel_release_major}-%{flavor}
# Override the _mandir so man pages don't end up in /man
%define _mandir /usr/share/man

BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: pkgconfig
BuildRequires: -post-build-checks
BuildRequires: module-init-tools
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %{release}
Summary: Lustre File System for CLFS SLES-based Nodes
Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source0: %{source_name}.tar.gz
Source1: %{flavorless_name}-switch-%{branch}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# Override _prefix to avoid installing into Cray locations under /opt/cray/
%define _prefix    /
%define _includedir /usr/include

%description
Kernel modules and userspace tools needed for a Lustre client on CLFS SLES-based
service nodes.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name} -a 1

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

CFLAGS="%{optflags} -Werror"

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --disable-server \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
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

if [ -e etc ]
then
    for f in lustre lhbadm ldev haconfig; do
        %{__rm} -f etc/init.d/${f}
    done
    %{__rm} -rf etc/ha.d etc/sysconfig etc/ldev.conf
fi

popd

# set l_getidentity to the default location
%{__mkdir_p} %{buildroot}/usr/sbin
%{__ln_s} -f /sbin/l_getidentity %{buildroot}/usr/sbin/l_getidentity

%post
DEPMOD_OPTS=""
if [ -f /boot/System.map-%{cray_kernel_version} ]; then
    DEPMOD_OPTS="-F /boot/System.map-%{cray_kernel_version}"
fi

depmod -a ${DEPMOD_OPTS} %{cray_kernel_version}

%files
%defattr(-,root,root)
%{_prefix}

%clean
%clean_build_root
