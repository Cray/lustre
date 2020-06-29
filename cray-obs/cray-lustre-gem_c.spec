%define vendor_name lustre
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define flavor cray_gem_c
%define intranamespace_name %{vendor_name}-%{flavor}
%define branch trunk
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}
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
BuildRequires: pkgconfig
BuildRequires: udev
BuildRequires: libtool
BuildRequires: libyaml-devel zlib-devel
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for CNL
Version: %{_version}_%{kernel_version}
Source: %{source_name}.tar.bz2
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
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%description lnet
Userspace tools and files for Lustre networking on XT compute nodes.
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%package devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Header files

%description devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.
kernel_version: %{kernel_version}
kernel_release: %{kernel_release}

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{source_name}

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

CFLAGS="%{optflags} -Werror -fno-stack-protector"

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
# Sets internal kgnilnd build version
export SVN_CODE_REV=%{lustre_version}

# don't use %makeinstall for compute node RPMS - it needlessly puts things into 
#  /opt/cray/,.....

f=`find %{_builddir} -name ldev.conf`
if [ -n "${f}" ] ; then
    install -D -m 0644 ${f} %{buildroot}/%{_sysconfdir}/ldev.conf
fi

for seekf in %{pc_files} ; do
    f=`find %{_builddir} -name ${seekf}`
    if [ -n "${f}" ] ; then
        eval "sed -i 's/flavor/%{flavor}/g' ${f}"
        eval "sed -i 's,@includedir@,%{_includedir},' ${f}"
        eval "sed -i 's,@libdir@,%{_libdir},' ${f}"
        eval "sed -i 's,@symversdir@,%{_datadir}/symvers,' ${f}"
        eval "sed -i 's,@PACKAGE_VERSION@,%{_version},' ${f}"
        eval "sed -i 's,@cfgdir@,%{_includedir}/lustre/%{flavor},' ${f}"
        echo install -D -m 0644 ${f} %{buildroot}/usr/lib64/pkgconfig/${seekf}
        install -D -m 0644 ${f} %{buildroot}/usr/lib64/pkgconfig/${seekf}
    fi
done


make DESTDIR=${RPM_BUILD_ROOT} install 

# We only want lctl and mount.lustre from _sbindir
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$|/mount.lustre$' | xargs rm -fv

%files 
%defattr(-,root,root)
/lib/modules/*
%{_sbindir}/mount.lustre
%{_sbindir}/lctl
%config /etc/udev/rules.d/99-lustre.rules
%{_libdir}/*
%exclude %{_mandir}/*
%exclude %{_bindir}/*
%exclude %{_includedir}/*
%{_datadir}/*
%exclude %{_sysconfdir}/lustre/perm.conf
%exclude %{_sysconfdir}/lustre
%exclude %{_sysconfdir}/ldev.conf
%exclude %{_sysconfdir}/modprobe.d/ko2iblnd.conf

%files lnet
%defattr(-,root,root)
/lib/modules/*/updates/kernel/net/lustre
%{_sbindir}/lctl
%config %{_sysconfdir}/lnet.conf
%config %{_sysconfdir}/lnet_routes.conf

%files devel
%defattr(-,root,root)
/usr/include/linux/lnet/*.h
/usr/include/linux/lustre/*.h
/usr/lib64/pkgconfig/*.pc
/usr/lib64/*


%post
%{__ln_s} -f /sbin/lctl /usr/sbin

%preun
%{__rm} -f /usr/sbin/lctl

%post devel
mkdir -p /usr/lib64/pkgconfig
for f in %{pc_files}
do
    %{__ln_s} -f /opt/cray/lustre-%{flavor}/%{version}-%{release}/lib64/pkgconfig/${f} /usr/lib64/pkgconfig/${f}
done

%preun devel
for f in %{pc_files}
do
    %{__rm} -f /usr/lib64/pkgconfig/${f}
done

%clean
%clean_build_root
