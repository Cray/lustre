%global kfabric_version %(rpm -q --qf '%{VERSION}-%{RELEASE}' cray-kfabric-devel)

%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define _lnet_version %(echo "%{_version}" | awk -F . '{printf("%s.%s", $1, $2)}')

%define intranamespace_name %{name}
%{expand:%%global OBS_prefix %{_prefix}}
%define prefix /usr
%define _sysconfdir /etc

%global lustre_name cray-lustre-client-ofed

Name: %{lustre_name}
Summary: Cray Lustre Filesystem
Version: %{_version}
Release: %{release}
License: GPL
Group: System/Filesystems
Source: cray-lustre-%{_version}.tar.bz2
Source1: kmp-lustre.preamble
Source2: kmp-lustre.files
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: %kernel_module_package_buildreqs
BuildRequires: libtool libyaml-devel zlib-devel
BuildRequires: systemd
BuildRequires: libnl3-devel
BuildRequires: keyutils-devel
BuildRequires: libmount-devel
BuildRequires: cray-kfabric-devel
BuildRequires: flex
BuildRequires: bison
Requires: (cray-kfabric-udev or cray-kfabric-dkms)

# Vendor specific requires/defines/etc.
%if %{_vendor}=="redhat"
%global kversion %(make -s -C /usr/src/kernels/* kernelversion)
%global _with_linux --with-linux=/usr/src/kernels/%{kversion}
%global requires_kmod_name kmod-%{lustre_name}
%global requires_kmod_version %{version}
Requires: (kmod-cray-kfabric or cray-kfabric-dkms)
BuildRequires: redhat-rpm-config
%else
%global kversion %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease)
%global _with_linux --with-linux=/usr/src/linux
%global _with_linux_obj --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor}
%global requires_kmod_name %{lustre_name}-kmp
%global krequires %(echo %{kversion} | sed -e 's/\.x86_64$//' -e 's/\.i[3456]86$//' -e 's/-smp$//' -e 's/-bigsmp$//' -e 's/[-.]ppc64$//' -e 's/\.aarch64$//' -e 's/-default$//' -e 's/-%{flavor}//')
%global requires_kmod_version %{version}_k%(echo %{krequires} | sed -r 'y/-/_/; s/^(2\.6\.[0-9]+)_/\\1.0_/;')
Requires: (cray-kfabric-kmp or cray-kfabric-dkms)
%endif

Requires: (%{requires_kmod_name} = %{requires_kmod_version} or cray-lustre-client-dkms)

# Disable post-build-checks; See LUS-1345
# Note: build checks can be run manually by first doing an incremental build
# and then doing a second incremental build with post-build-checks enabled.
#!BuildIgnore: post-build-checks

%description
Userspace tools and files for the Lustre filesystem.
Compiled for kernel: %{kversion}
ko2iblnd compiled against: In-kernel drivers
kkfilnd compiled against: cray-kfabric-devel-%{kfabric_version} or cray-kfabric-dkms

%package devel
Group: Development/Libraries
Requires: %{lustre_name} = %{version}
Requires: (%{requires_kmod_name} = %{requires_kmod_version} or cray-lustre-client-dkms)
License: GPL
Summary: Cray Lustre Header files

%description devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.
Compiled for kernel: %{kversion}
ko2iblnd compiled against: In-kernel drivers
kkfilnd compiled against: cray-kfabric-devel-%{kfabric_version}

%package lnet-headers
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Network Header files

%description lnet-headers
Cray Lustre Network Header files
Compiled for kernel: %{kversion}
ko2iblnd compiled against: In-kernel drivers
kkfilnd compiled against: cray-kfabric-devel-%{kfabric_version}

%package %{flavor}-lnet-devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Network kernel flavor specific devel files

%description %{flavor}-lnet-devel
Kernel flavor specific development files for building against Lustre
Network (LNet)
Compiled for kernel: %{kversion}
ko2iblnd compiled against: In-kernel drivers
kkfilnd compiled against: cray-kfabric-devel-%{kfabric_version}

%if %{undefined kmoddir}
	%if %{defined kernel_module_package_moddir}
		%global kmoddir %{kernel_module_package_moddir}
	%else
		%if %{defined suse_kernel_module_package}
			%global kmoddir updates
		%else
			%global kmoddir extra
		%endif
	%endif
%endif

%global modules_fs_path /lib/modules/%{kversion}/%{kmoddir}

%kernel_module_package -n %{name} -p %SOURCE1 -f %SOURCE2 %{flavor}

%prep
%if %{undefined flavor}
%{error:"flavor is undefined"}
exit 1
%endif

%incremental_setup -q -n cray-lustre-%{_version}

# Need '-f' here for incremental builds
ln -f lustre/ChangeLog ChangeLog-lustre
ln -f lnet/ChangeLog ChangeLog-lnet

%build
echo "LUSTRE_VERSION = %{_version}" > LUSTRE-VERSION-FILE

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{name}-%{version}/configure ];then
	chmod +x autogen.sh
	./autogen.sh
fi

O2IBPATH=yes
if [ -d /usr/src/ofa_kernel/%{flavor} ]; then
	O2IBPATH=/usr/src/ofa_kernel/%{flavor}
elif [ -d /usr/src/ofa_kernel/default ]; then
	O2IBPATH=/usr/src/ofa_kernel/default
fi

WITH_KFI=""
if [ -d /usr/src/kfabric/%{flavor} ]; then
	WITH_KFI="--with-kfi=/usr/src/kfabric/%{flavor}"
fi

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{name}-%{version}/Makefile ];then
	%configure \
		--disable-server \
		--enable-client \
		--with-kmp-moddir=%{kmoddir}/%{name} \
		--with-o2ib=${O2IBPATH} ${WITH_KFI} \
		%{_with_linux} %{?_with_linux_obj}
fi
%{__make} %_smp_mflags

%install
make DESTDIR=${RPM_BUILD_ROOT} install

for fname in $(find lnet/include -type f -name \*.h)
do
	target=$(echo ${fname} | sed 's:^lnet/include/::g')
	%{__install} -D -m 0644 ${fname} %{buildroot}/%{_includedir}/${target}
done

for fname in $(find libcfs/include/libcfs -type f -name \*.h)
do
	target=$(echo ${fname} | sed -e 's:^libcfs/include/::g')
	%{__install} -D -m 0644 ${fname} %{buildroot}/%{_includedir}/${target}
done

%{__install} -D -m 0644 lustre/include/interval_tree.h %{buildroot}/%{_includedir}/interval_tree.h

%define cfgdir %{_includedir}/lustre/%{flavor}
for f in cray-lustre-api-devel.pc cray-lnet.pc
do
	eval "sed -i 's,@includedir@,%{_includedir},' cray-obs/${f}"
	eval "sed -i 's,@libdir@,%{_libdir},' cray-obs/${f}"
	eval "sed -i 's,@symversdir@,%{_datadir}/symvers,' cray-obs/${f}"
	eval "sed -i 's,@PACKAGE_VERSION@,%{_version},' cray-obs/${f}"
	eval "sed -i 's,@cfgdir@,%{cfgdir},' cray-obs/${f}"
	install -D -m 0644 cray-obs/${f} $RPM_BUILD_ROOT%{_pkgconfigdir}/${f}
done

if [[ -e %{buildroot}/%{_sysconfdir}/modprobe.d/ko2iblnd.conf ]]; then
	%{__sed} -i -e 's/^\(install ko2iblnd .*\)/\#\1/' %{buildroot}/%{_sysconfdir}/modprobe.d/ko2iblnd.conf
fi

# Install Module.symvers and config.h for the lnet devel package
%{__install} -D -m 0644 ${PWD}/Module.symvers %{buildroot}/%{_datadir}/symvers/%{_arch}/%{flavor}/Module.symvers
%{__install} -D -m 0644 config.h %{buildroot}/%{cfgdir}/config.h

# Install module directories and files
%{__sed} -e 's/@VERSION@/%{version}-%{release}/g' cray-obs/version.in > .version
%{__sed} -e 's,@pkgconfigdir@,%{_pkgconfigdir},g' cray-obs/module.in > module
%{__install} -D -m 0644 .version %{buildroot}/%{_name_modulefiles_prefix}/.version
%{__install} -D -m 0644 module %{buildroot}/%{_release_modulefile}

rm -f $RPM_BUILD_ROOT%{_libdir}/liblustreapi.la
rm -f $RPM_BUILD_ROOT%{_libdir}/liblnetconfig.la

%files
%defattr(-,root,root)
/sbin/mount.lustre
%{_sysconfdir}/lustre
%{_sysconfdir}/lnet.conf
%{_sysconfdir}/lnet_routes.conf
%{_sysconfdir}/modprobe.d
%{_sysconfdir}/udev
%config(noreplace) /etc/sysconfig/dkms-lustre
%{_sbindir}/*
%{_bindir}/*
%{_mandir}
%{_unitdir}/lnet.service
%dir %{_libdir}/lustre
%{_libdir}/lustre/tests
# The versioned shared library files for liblnetconfig are needed for
# lnetctl, so they are included in the base package
%{_libdir}/liblnetconfig.so.*
%{_libdir}/liblustreapi.so*
%{_datadir}/bash-completion/completions/*
%exclude %{_pkgconfigdir}/lustre.pc

%files devel
%defattr(-,root,root)
%dir %{_includedir}/lustre
%{_includedir}/lustre
%dir %{_includedir}/linux/lustre
%dir %{_includedir}/linux/lnet
%{_includedir}/linux/lnet
%{_includedir}/linux/lustre
%{_libdir}/liblustreapi.a
%{_libdir}/liblustreapi.so
%{_libdir}/liblnetconfig.a
%{_libdir}/liblnetconfig.so
%{_pkgconfigdir}/cray-lustre-api-devel.pc
%{_modulefiles_prefix}
%exclude %{cfgdir}

%files %{flavor}-lnet-devel
%dir %{_datadir}/symvers
%dir %{_datadir}/symvers/%{_arch}
%dir %{_datadir}/symvers/%{_arch}/%{flavor}
%attr (644,root,root) %{_datadir}/symvers/%{_arch}/%{flavor}/Module.symvers
%{cfgdir}

%files lnet-headers
%{_includedir}/lnet
%{_includedir}/linux
%{_includedir}/uapi
%{_includedir}/libcfs
%{_includedir}/interval_tree.h
%{_pkgconfigdir}/cray-lnet.pc

%post
/sbin/ldconfig
%systemd_post lnet.service

%preun
%systemd_preun lnet.service

%postun
/sbin/ldconfig
%systemd_postun_with_restart lnet.service

%post devel
/sbin/ldconfig

%postun devel
/sbin/ldconfig

%clean
%clean_build_root
