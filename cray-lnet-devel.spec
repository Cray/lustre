%define intranamespace_name lnet
%ifarch k1om
%define flavor cray_ari_m
%else
%if %{with athena}
%define flavor cray_ari_athena_s_cos
%else
%define flavor cray_ari_s
%endif
%endif

%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define branch trunk

# This package is a build requirement for DVS. Changing the name of this package
# requires a corresponding change to the DVS package.
%define lnet_version 2.7
%define pkgbase %{namespace}-%{intranamespace_name}
%define pkgname %{pkgbase}-%{lnet_version}-devel

%define srcbase %{namespace}-lustre-%{_version}
%define pkgsrcbase %{pkgbase}-devel-%{_version}

Group: Development/Libraries/C and C++
License: GPL
Name: %{pkgname}
Release: %release
Requires: %{switch_requires}
BuildRequires: update-alternatives
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: module-init-tools
BuildRequires: pkgconfig
BuildRequires: libtool
BuildConflicts: post-build-checks
Summary: The lnet development package
Vendor: Cray Inc.
Version: %{_version}
Source0: %{srcbase}.tar.bz2
Source1: %{pkgsrcbase}.tar.bz2
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Header files for lnet.

%prep
%incremental_setup -q -n %{srcbase} -a 1

%build
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE
if [ "%reconfigure" == "1" -o ! -x %_builddir/%{srcbase}/configure ];then
        chmod +x autogen.sh
        ./autogen.sh
fi
if [ "%reconfigure" == "1" -o ! -f %_builddir/%{srcbase}/Makefile ];then
        %configure --disable-checksum \
           --disable-server \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-o2ib=no \
           --with-obd-buffer-size=16384
fi
pushd %{pkgsrcbase}
%CRAYconfigure -- --with-module=%{_release_modulefile}

%{__make} %_smp_mflags

%install
%{__install} -D -m 0644 config.h %{buildroot}/%{_includedir}/lustre/config.h
install -D -m 0644  %{pkgsrcbase}/%{pkgbase}-devel.pc %{buildroot}/%{_pkgconfigdir}/%{pkgbase}.pc
install -D -m 0644  %{pkgsrcbase}/module %{buildroot}/%{_release_modulefile}
install -D -m 0644  %{pkgsrcbase}/.version %{buildroot}/%{_release_prefix}/etc/.version

for header in api.h lib-dlc.h lib-lnet.h lib-types.h lnetctl.h lnet.h lnetst.h \
              nidstr.h socklnd.h types.h
do
    %{__install} -D -m 0644 lnet/include/lnet/${header} \
                            %{buildroot}/%{_includedir}/lnet/${header}
done
for header in libcfs.h list.h curproc.h bitmap.h byteorder.h err.h \
              libcfs_debug.h libcfs_private.h libcfs_cpu.h libcfs_ioctl.h \
              libcfs_prim.h libcfs_time.h libcfs_string.h libcfs_kernelcomm.h \
              libcfs_workitem.h libcfs_hash.h libcfs_heap.h libcfs_fail.h \
              linux/kp30.h linux/libcfs.h linux/linux-fs.h linux/linux-lock.h \
              linux/linux-mem.h linux/linux-prim.h linux/linux-time.h \
              linux/linux-cpu.h linux/linux-crypto.h
do
    %{__install} -D -m 0644 libcfs/include/libcfs/${header} \
                            %{buildroot}/%{_includedir}/libcfs/${header}
done

%files
%defattr(-,root,root)
%prefixdirs
%if %{without lustre}
%dir %{_namespace_modulefiles_network_prefix}
%endif
%dir %{_modulefiles_prefix}
%dir %{_modulefiles_prefix}/lnet
%dir %{_sysconfdir}
%dir %{_libdir}
%{_includedir}
%{_pkgconfigdir}
%{_release_modulefile}
%{_sysconfdir}
%exclude %{_sysconfdir}/lustre/perm.conf

%post
/usr/sbin/update-alternatives --install %{_default_prefix} %{pkgbase} %{_release_prefix} %{release_priority}
%{__ln_s} -f %{_default_sysconfdir}/.version %{_name_modulefiles_prefix}/.version
%link_pkg_config -n %{pkgbase}

%preun
%{__rm} -f %{_name_modulefiles_prefix}/.version
/usr/sbin/update-alternatives --remove %{pkgbase} %{_release_prefix}
%remove_pkg_config -n %{pkgbase}
