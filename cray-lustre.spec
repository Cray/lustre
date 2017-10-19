%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define _tag %(if test -s "%_sourcedir/_tag"; then cat "%_sourcedir/_tag"; else echo "UNKNOWN"; fi)

# Override prefix to avoid isntalling under /opt/cray
%define _prefix /usr

%if %{with server}
%define _config_server --enable-server
%if %{with ari}
%define lustre_name service
%else
%define lustre_name server
%endif # with ari
%else  # client build
%define _config_server --disable-server
%if %{with ari}
%define lustre_name compute
%else
%if %{with clevm}
%define lustre_name client
%else
%define lustre_name elogin
%endif # with clevm
%endif # with ari
%endif # with server

%if %{with ari}
%if %{with server}
%define flavor cray_ari_s
%else
%define flavor cray_ari_c
%endif
%else
%define flavor default
%endif

%define vendor_name lustre
%define intranamespace_name %{vendor_name}-%{flavor}
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}

%define kver %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelversion)
%define krel %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease) 

%if %{with ari}
BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: cray-krca-devel
BuildRequires: lsb-cray-hss-devel
%endif

BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: module-init-tools
BuildRequires: pkgconfig
BuildRequires: libtool
BuildRequires: libyaml-devel
BuildRequires: systemd
# Disable post-build-checks; See LUS-1345
# Note: build checks can be run manually by first doing an incremental build
# and then doing a second incremental build with post-build-checks enabled.
BuildConflicts: post-build-checks
Group: System/Filesystems
License: GPL
Name: cray-lustre-%{lustre_name}
Release: %{release}
Requires: module-init-tools
Summary: Cray Lustre File System
Version: %{_version}_%{kver}
Source: %{source_name}.tar.bz2
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# Reconstruct the version assigned to the kmp package
%global requires_kmod_version %{_version}_%(echo %{krel} | sed -e 's/-%{flavor}$//' -e 'y/-/_/')
Requires: cray-lustre-kmp-%{flavor} = %{requires_kmod_version}-%{release}

%description
Kernel modules and userspace tools needed for Lustre client
Compiled for kernel: %{krel}

%package devel
Group: Development/Libraries
License: GPL
Summary: Cray Lustre API Headers and Libraries
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
Development files for building against Lustre API.
Includes headers and shared and dynamic libraries.

# We use major.minor version in the lnet devel package Provides
# This provides some backward compatibility
%define lnet_version %(echo "%{_version}" | awk -F . '{printf("%s.%s", $1, $2)}')
%package lnet-devel
Group: Development/Libraries
License: GPL
Summary: Cray LNet Header files
Provides: cray-lustre-%{flavor}-%{lnet_version}-devel

%description lnet-devel
Development files for building against LNet

# Override the default package name - See LUS-276
# Override the default version since we don't need the kernel version
# string included twice.
%if %{with ari}
%cray_kernel_module_package -n cray-lustre -x %{flavor} -v %{_version}
%else
%kernel_module_package -n cray-lustre %{flavor} -v %{_version}
%endif

%prep
%incremental_setup -n %{source_name}

# Need '-f' here for incremental builds
ln -f lustre/ChangeLog ChangeLog-lustre
ln -f lnet/ChangeLog ChangeLog-lnet

%build
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE
%define version_path %(basename %url)
%define kgnilnd_version %{_version}-%{release}-%{build_user}-%{version_path}

%if %{with ari}
# Sets internal kgnilnd build version
export SVN_CODE_REV=%{kgnilnd_version}
%endif

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
    sh ./autogen.sh
fi

%if %{with ari}
%define _enable_gni --enable-gni
syms="$(pkg-config --variable=symversdir cray-gni)/%{flavor}/Module.symvers"
syms="$syms $(pkg-config --variable=symversdir cray-krca)/%{flavor}/Module.symvers"

export GNICPPFLAGS=$(pkg-config --cflags cray-gni cray-gni-headers cray-krca lsb-cray-hss)

HSS_FLAGS=$(pkg-config --cflags lsb-cray-hss)
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"
%endif

%if %{without server} && %{with ari}
# Skip building o2iblnd for aries compute clients
%define _config_o2ib --with-o2ib=no
%else
%define _config_o2ib --with-o2ib=yes
%endif

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
    %configure -C \
               --disable-checksum \
               %{_config_server} \
               %{_config_o2ib} \
               --enable-dlc \
               --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
               --with-systemdsystemunitdir=%{_unitdir} \
               --with-extra-symbols="$syms" %{?_enable_gni}
fi
%{__make} %_smp_mflags

%install
%if %{with ari}
# Sets internal kgnilnd build version
export SVN_CODE_REV=%{kgnilnd_version}
%endif

make DESTDIR=${RPM_BUILD_ROOT} install

%define lnetincludedir /usr/src/lustre-%{_tag}-headers
for f in cray-lustre-api-devel.pc cray-lustre-cfsutil-devel.pc \
         cray-lustre-ptlctl-devel.pc cray-lnet.pc
do
    eval "sed -i 's,@includedir@,%{_includedir},' %{_sourcedir}/${f}"
    eval "sed -i 's,@libdir@,%{_libdir},' %{_sourcedir}/${f}"
    eval "sed -i 's,@symversdir@,%{lnetincludedir},' %{_sourcedir}/${f}"
    eval "sed -i 's,@lnetincludedir@,%{lnetincludedir},' %{_sourcedir}/${f}"
    eval "sed -i 's,@PACKAGE_VERSION@,%{_version},' %{_sourcedir}/${f}"
    install -D -m 0644  %{_sourcedir}/${f} $RPM_BUILD_ROOT%{_pkgconfigdir}/${f}
done

# Install module directories and files
sed -e 's/@VERSION@/%{version}-%{release}/g' version.in > .version
%{__install} -D -m 0644 .version $RPM_BUILD_ROOT%{_name_modulefiles_prefix}/.version
%{__install} -D -m 0644 module $RPM_BUILD_ROOT%{_release_modulefile}

# Module.symvers and config.h are for the DVS build
%{__install} -D -m 0644 ${PWD}/Module.symvers $RPM_BUILD_ROOT%{lnetincludedir}/%{_arch}/%{flavor}/Module.symvers
%{__install} -D -m 0644 config.h $RPM_BUILD_ROOT%{lnetincludedir}/%{_arch}/%{flavor}/config.h

rm -f $RPM_BUILD_ROOT%{_libdir}/liblnetconfig.la
rm -f $RPM_BUILD_ROOT%{_libdir}/lustre/mount_osd_ldiskfs.la

%if %{without server} && %{with ari}
%define ari_client_files -f lustre.files
:> lustre.files
# Many things are excluded from compute node packages to save space in
# the compute node image. Here we generate '%exclude' directives for
# everything that should be left out of the package.
## '-H' needed in find commands for incremental builds
## '%%%' needed because bash turns the first '%%' into '%'

# %exclude everything in _sbindir except lctl, mount.lustre, lustre_rmmod
# and lnetctl
find -H $RPM_BUILD_ROOT%{_sbindir} -type f -print | \
    awk -F '/' '{printf("%%%exclude %%{_sbindir}/%s\n", $NF)}' |
    egrep -v '/lctl$|/mount.lustre$|/lustre_rmmod$|/lnetctl$' >> lustre.files

# %exclude everything in _bindir except lfs and lfs_migrate
find -H $RPM_BUILD_ROOT%{_bindir} -type f -print | \
    awk -F '/' '{printf("%%%exclude %%{_bindir}/%s\n", $NF)}' |
    egrep -v '/lfs$|/lfs_migrate$' >> lustre.files

# %exclude all man pages, documentation, and tests
echo '%exclude %{_mandir}' >> lustre.files
echo '%exclude %{_docdir}' >> lustre.files
echo '%exclude %{_libdir}/lustre/tests' >> lustre.files
%else
%define ari_client_files %{nil}
%endif

%if %{with server} && %{with ari}
%define lnet_devel_files -f lnet-devel.files
:> lnet-devel.files
# Install headers needed for lnet-devel subpackage
add_hdr_file() {
    declare srcfile=$1

    install -D -m 0644 ${srcfile} $RPM_BUILD_ROOT%{lnetincludedir}/${srcfile}
    echo "%attr(-, root, root) %{lnetincludedir}/${srcfile}"
}

for header in api.h lib-dlc.h lib-lnet.h lib-types.h lnetctl.h lnet.h \
              lnetst.h nidstr.h socklnd.h types.h
do
    add_hdr_file lnet/include/lnet/${header} >> lnet-devel.files
done

for header in libcfs.h curproc.h bitmap.h libcfs_debug.h libcfs_private.h \
              libcfs_cpu.h libcfs_ioctl.h libcfs_prim.h libcfs_time.h \
              libcfs_string.h libcfs_workitem.h libcfs_hash.h libcfs_heap.h \
              libcfs_fail.h linux/libcfs.h linux/linux-fs.h linux/linux-mem.h \
              linux/linux-time.h linux/linux-cpu.h linux/linux-crypto.h \
              linux/linux-misc.h
do
    add_hdr_file libcfs/include/libcfs/${header} >> lnet-devel.files
done
%else
%define lnet_devel_files %{nil}
%endif

# Exclude directives take precedence over everything else. Thus, many
# of the files listed below are not actually included in compute node
# packages
%files %{ari_client_files}
%defattr(-,root,root)
/sbin/mount.lustre
/etc/udev
%{_sbindir}/*
%{_bindir}/*
%{_mandir}
%{_unitdir}/lnet.service
%dir %{_libdir}/lustre
%{_libdir}/lustre/tests
# The versioned shared library files for liblnetconfig are needed for
# lnetctl, so they are included in the base package
%{_libdir}/liblnetconfig.so.*
%if %{with server}
%{_libdir}/lustre/mount_osd_ldiskfs.so
%{_libexecdir}/lustre
%exclude /etc/ha.d/resource.d/Lustre.ha_v2
%endif
%exclude %{_pkgconfigdir}/cray-lnet.pc
%exclude /etc/ldev.conf
%exclude /etc/lnet.conf
%exclude /etc/lnet_routes.conf
%exclude /etc/modprobe.d/ko2iblnd.conf
%exclude %{_mandir}/man5
%exclude %{_mandir}/man8/lhbadm.8.gz

%files devel
%defattr(-,root,root)
%if %{with server}
%{_libdir}/libiam.a
%endif
%{_libdir}/libptlctl.a
%{_libdir}/libcfsutil.a
%{_libdir}/liblustreapi.a
%{_libdir}/liblustreapi.so
%{_libdir}/liblnetconfig.a
%{_libdir}/liblnetconfig.so
%{_includedir}/lustre
%{_pkgconfigdir}/cray-lustre-api-devel.pc
%{_pkgconfigdir}/cray-lustre-cfsutil-devel.pc
%{_pkgconfigdir}/cray-lustre-ptlctl-devel.pc
%if %{without server} && %{with ari}
%exclude %{_name_modulefiles_prefix}/.version
%exclude %{_release_modulefile}
%else
%{_modulefiles_prefix}
%endif

%files lnet-devel %{lnet_devel_files}
%defattr(-,root,root)
%{lnetincludedir}
%if %{with server} && %{with ari}
%{_pkgconfigdir}/cray-lnet.pc
%else
%exclude %{_pkgconfigdir}/cray-lnet.pc
%endif

%post devel
/sbin/ldconfig

%postun devel
/sbin/ldconfig

%clean
%clean_build_root
