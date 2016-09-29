%define vendor_name lustre
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define flavor default

%define intranamespace_name %{vendor_name}-server-%{flavor}
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}
%define branch trunk

%define clean_build_root %{nil}

%define local_kernel_version %(rpm -q --qf '%{VERSION}' kernel-devel)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-devel)

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: kernel-devel
BuildRequires: redhat-rpm-config
BuildRequires: ofed-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: pkgconfig
BuildRequires: -post-build-checks
BuildRequires: module-init-tools
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for Apollo Aries CentOS Nodes
Version: %{_version}_%{local_kernel_version}_%{kernel_release}
Source: %{source_name}.tar.bz2
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /

%description
Userspace tools and files for the Lustre file system on Apollo CentOS nodes.

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

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers lsb-cray-hss`
%define ksrc /usr/src/kernels/%{kernel_version}

if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=no
fi

HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS -DCRAY_APOLLO -DCONFIG_CRAY_ARIES"
gni_symvers=`pkg-config --variable=symversdir cray-gni`/default/Module.symvers

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ]; then
        %configure --disable-checksum \
           --enable-gni \
           --with-symvers=$gni_symvers \
           --with-o2ib=$O2IBPATH \
           --with-linux-obj=%{ksrc} \
           --with-linux=%{ksrc} \
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

%{__install} -D Module.symvers ${RPM_BUILD_ROOT}/%{_libdir}/symvers/Module.symvers

%files 
%defattr(-,root,root)
%{_prefix}
%exclude %{_sysconfdir}/lustre/perm.conf

%clean
%clean_build_root
