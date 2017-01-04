%define vendor_name lustre
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define flavor cray_gem_s_cos
%define intranamespace_name %{vendor_name}-%{flavor}
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}
%define branch trunk

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: cray-krca-devel
BuildRequires: ofed-devel
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: pkgconfig
BuildRequires: -post-build-checks
BuildRequires: module-init-tools
BuildRequires: python-docutils
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for Gemini CentOS Nodes
Version: %{_version}_%{kernel_version}_%{kernel_release}
Source: %{source_name}.tar.bz2
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /

%description
Userspace tools and files for the Lustre file system on Baker CentOS nodes.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{source_name}

%build
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE
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
           --enable-cray-xt3 \
           --enable-gni \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-obd-buffer-size=16384
fi
%{__make} %_smp_mflags

%install
# don't use %makeinstall for CentOS RPMS - it needlessly puts things into 
#  /opt/cray/,.....

make DESTDIR=${RPM_BUILD_ROOT} install 

for dir in var man/man5 etc/init.d etc/sysconfig etc/ha.d; do
    %{__rm} -fr %{buildroot}/$dir
done
%{__rm} -f %{buildroot}/etc/lustre %{buildroot}/etc/ldev.conf

# set l_getidentity to the default location
%{__mkdir_p} %{buildroot}/usr/sbin
%{__ln_s} -f /sbin/l_getidentity %{buildroot}/usr/sbin/l_getidentity

%files 
%defattr(-,root,root)
%{_prefix}

%clean
%clean_build_root
