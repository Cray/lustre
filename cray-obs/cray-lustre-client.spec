%ifarch x86_64
%global mofed_version %(rpm -q --qf '%{VERSION}-%{RELEASE}' mlnx-ofa_kernel-devel)
%endif

%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define _lnet_version %(echo "%{_version}" | awk -F . '{printf("%s.%s", $1, $2)}')

%define intranamespace_name %{name}
%{expand:%%global OBS_prefix %{_prefix}}
%define prefix /usr
%define _sysconfdir /etc

%global lustre_name cray-lustre-client
%define module %{lustre_name}
%define mkconf lustre/scripts/dkms.mkconf

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
%ifarch x86_64
BuildRequires: mlnx-ofa_kernel-devel
%endif
BuildRequires: flex
BuildRequires: bison

# Vendor specific requires/defines/etc.
%if %{_vendor}=="redhat"
%global kversion %(make -s -C /usr/src/kernels/* kernelversion)
%global _with_linux --with-linux=/usr/src/kernels/%{kversion}
%global requires_kmod_name kmod-%{lustre_name}
%global requires_kmod_version %{version}
%ifarch x86_64
Requires: (kmod-mlnx-ofa_kernel or mlnx-ofa_kernel-dkms)
%endif
BuildRequires: redhat-rpm-config
%define mkconf_options %{nil}
%else
%global kversion %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease)
%global _with_linux --with-linux=/usr/src/linux
%global _with_linux_obj --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor}
%global requires_kmod_name %{lustre_name}-kmp
%global krequires %(echo %{kversion} | sed -e 's/\.x86_64$//' -e 's/\.i[3456]86$//' -e 's/-smp$//' -e 's/-bigsmp$//' -e 's/[-.]ppc64$//' -e 's/\.aarch64$//' -e 's/-default$//' -e 's/-%{flavor}//')
%global requires_kmod_version %{version}_k%(echo %{krequires} | sed -r 'y/-/_/; s/^(2\.6\.[0-9]+)_/\\1.0_/;')
%ifarch x86_64
Requires: (mlnx-ofa_kernel-kmp or mlnx-ofa_kernel-dkms)
%endif
%define mkconf_options -k updates
%endif

Requires: %{requires_kmod_name} = %{requires_kmod_version}

# Disable post-build-checks; See LUS-1345
# Note: build checks can be run manually by first doing an incremental build
# and then doing a second incremental build with post-build-checks enabled.
#!BuildIgnore: post-build-checks

%description
Userspace tools and files for the Lustre filesystem.
Compiled for kernel: %{kversion}
%ifarch x86_64
ko2iblnd compiled against: mlnx-ofa_kernel-devel-%{mofed_version}
%endif

%package devel
Group: Development/Libraries
Requires: %{lustre_name} = %{version}
Requires: %{requires_kmod_name} = %{requires_kmod_version}
License: GPL
Summary: Cray Lustre Header files

%description devel
Development files for building against Lustre library.
Includes headers, dynamic, and static libraries.
Compiled for kernel: %{kversion}
%ifarch x86_64
ko2iblnd compiled against: mlnx-ofa_kernel-devel-%{mofed_version}
%endif

%package lnet-headers
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Network Header files

%description lnet-headers
Cray Lustre Network Header files
Compiled for kernel: %{kversion}
%ifarch x86_64
ko2iblnd compiled against: mlnx-ofa_kernel-devel-%{mofed_version}
%endif

%package %{flavor}-lnet-devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre Network kernel flavor specific devel files

%description %{flavor}-lnet-devel
Kernel flavor specific development files for building against Lustre
Network (LNet)
Compiled for kernel: %{kversion}
%ifarch x86_64
ko2iblnd compiled against: mlnx-ofa_kernel-devel-%{mofed_version}
%endif

%package dkms
Group: System/Filesystems
License: GPL
Summary: Cray Lustre Filesystem DKMS
URL: %url
BuildArch: noarch
Requires: dkms >= 2.2.0.3-28.git.7c3e7c5
Requires: gcc, make, perl
Requires: libtool libyaml-devel zlib-devel
Requires: libnl3-devel keyutils-devel
Requires: automake
Requires: pkg-config
Requires: kernel-devel
Requires: autoconf
Requires: bash-completion bash-completion-devel
Requires: libmount-devel
# NOTE: mlnx-ofa_kernel-devel appears to be optional
Requires: flex
Requires: bison
Provides: %{lustre_name} = %{version}
Conflicts:  kmod-%{lustre_name}
Conflicts:  %{lustre_name}-kmp

%description dkms
This package contains the dkms Lustre kernel modules.
and userspace tools and files for the Lustre filesystem.
Compiled for kernel: %{kversion}

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

# DKMS
%{mkconf} -n %{module} -v %{version} -f dkms.conf %{mkconf_options}
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi
mkdir -p $RPM_BUILD_ROOT/usr/src
cp -rfp ${RPM_BUILD_DIR}/cray-lustre-%{version} $RPM_BUILD_ROOT/usr/src/
mv $RPM_BUILD_ROOT/usr/src/cray-lustre-%{version} $RPM_BUILD_ROOT/usr/src/%{module}-%{version}
# end DKMS

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{name}-%{version}/configure ];then
	chmod +x autogen.sh
	./autogen.sh
fi

if [ -d /usr/src/ofa_kernel/%{flavor} ]; then
	O2IBPATH=/usr/src/ofa_kernel/%{flavor}
elif [ -d /usr/src/ofa_kernel/default ]; then
	O2IBPATH=/usr/src/ofa_kernel/default
else
	O2IBPATH=yes
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
# DKMS
install -D -m 0644 cray-obs/cray-lnet.pc $RPM_BUILD_ROOT%{_pkgconfigdir}/cray-lnet-dkms.pc

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

%files dkms
%defattr(-,root,root)
/usr/src/%{module}-%{version}
%{_pkgconfigdir}/cray-lnet-dkms.pc

%post
/sbin/ldconfig
%systemd_post lnet.service

%post dkms
if [ ! -f %{_pkgconfigdir}/cray-lnet.pc ] ; then
    ln -s %{_pkgconfigdir}/cray-lnet-dkms.pc %{_pkgconfigdir}/cray-lnet.pc
fi

COMMON_POSTINT=/usr/libexec/dkms/common.postinst
if [ ! -f ${COMMON_POSTINT} ] ; then
    if [ -f /usr/lib/dkms/common.postinst ] ; then
        COMMON_POSTINT=/usr/lib/dkms/common.postinst
    fi
fi
for POSTINST in ${COMMON_POSTINT}; do
    if [ -f $POSTINST ]; then
        $POSTINST %{module} %{version}
        exit $?
    fi
    echo "WARNING: $POSTINST does not exist."
done
echo -e "ERROR: DKMS version is too old and %{module} was not"
echo -e "built with legacy DKMS support."
echo -e "You must either rebuild %{module} with legacy postinst"
echo -e "support or upgrade DKMS to a more current version."
exit 1

%preun
%systemd_preun lnet.service

%preun dkms
if [ -L %{_pkgconfigdir}/cray-lnet.pc ] ; then
    rm %{_pkgconfigdir}/cray-lnet.pc
fi
dkms remove -m %{module} -v %{version} --all --rpm_safe_upgrade
exit 0

%postun
/sbin/ldconfig
%systemd_postun_with_restart lnet.service

%post devel
/sbin/ldconfig

%postun devel
/sbin/ldconfig

%clean
%clean_build_root
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi
