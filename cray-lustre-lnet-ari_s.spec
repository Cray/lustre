%define vendor_name lustre
%define vendor_version 2.7.2
%define flavor cray_ari_s
%define namespace_flavor %{namespace}_%{flavor}
%define intranamespace_name %{vendor_name}-%{flavor}
%define flavorless_name %{namespace}-%{vendor_name}
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)
%define KERNELRELEASE  %(rpm -q --qf "%{VERSION}-%{RELEASE}" kernel-source | sed 's/\.[0-9][0-9]*\.[0-9][0-9]*$//')
%define lust_ko_path lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel/fs/lustre
%define lnet_ko_path lib/modules/%{KERNELRELEASE}-%{flavor}/updates/kernel/net/lustre
%define rel_path opt/%{namespace}/%{vendor_name}-%{flavor}/%{version}-%{release}
%define inst_path /%{rel_path}/%{lnet_ko_path}
%define man_path %{rel_path}/man/man8

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: module-init-tools
BuildRequires: ofed-devel
BuildRequires: sles-release
BuildRequires: -post-build-checks
BuildRequires: libtool
Requires: cray-lustre-utils >= %{branch}-1.0000.18191.0
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}-lnet
Release: %{release}
Requires: %{switch_requires}
Summary: Lustre networking for Aries Service Nodes

Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source0: %{source_name}.tar.gz
Source1: %{flavorless_name}-switch-%{branch}.tar.gz
URL: %url
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Userspace tools and files for Lustre networking on XT SIO nodes.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name} -a 1

%build
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

# only keep lnet related directories
sed -i '/^SUBDIRS/,/config contrib/d' autoMakefile.am
sed -i '1iSUBDIRS := . @LIBCFS_SUBDIR@ lnet \nDIST_SUBDIRS := @LIBCFS_SUBDIR@ lnet' autoMakefile.am 

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
    chmod +x autogen.sh
    ./autogen.sh
fi

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca lsb-cray-hss`

if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=no
fi

HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --enable-gni \
           --disable-server \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-o2ib=${O2IBPATH} \
           --with-obd-buffer-size=16384
fi
%{__make} %_smp_mflags

# build lustre/utils/lctl
lustre_build_header="./lustre/include/lustre/lustre_build_version.h"
%{__cp} ./devel/lctl-makefile ./lustre/utils/Makefile.am
build_release=$(grep ^RELEASE ./lustre/autoMakefile | awk '{ print $3}')
echo "#define BUILD_VERSION \"%{lustre_version}\"" > ${lustre_build_header}
echo "#define LUSTRE_RELEASE \"$build_release\"" >> ${lustre_build_header}

pushd ./lustre/utils
%{__make} %_smp_mflags
%{__mkdir_p} %{buildroot}/%{rel_path}/sbin
%{__cp} lctl %{buildroot}/%{rel_path}/sbin
popd

# make switching file
pushd switch
%CRAYconfigure -- --with-module=%{_release_modulefile}
%{__make} %_smp_mflags
popd

%install
%makeinstall

# copy the man pages
%{__mkdir_p} %{buildroot}/%{man_path}
%{__cp} ./lustre/doc/lctl.8 %{buildroot}/%{man_path}
%{__cp} ./lustre/doc/lst.8 %{buildroot}/%{man_path}

# Make all files from lustre switchable
pushd %{buildroot}
SWITCH_FILES=`find lib -type f -printf "%%p "`
# remove all unwanted files and directories
%{__rm} -rf %{rel_path}/include %{rel_path}/lib64 %{rel_path}/etc
find %{buildroot}%{_sbindir} -type f -print | egrep -v '/lctl$|/routerstat$' | xargs rm -fv
popd

# file for switching in post/preun scriptlets
%{__mkdir_p} %{buildroot}/%{_sysconfdir}

# install switching files
pushd switch
%makeinstall
popd

for file in $(ls %{buildroot}/%{lnet_ko_path}); do
    echo $file >> %{buildroot}/%{_sysconfdir}/switch.files.lnet
done

for file in ${SWITCH_FILES}; do
    install -D %{buildroot}/${file} %{buildroot}/%{_prefix}/${file}
    %{__rm} -f %{buildroot}/${file}
done

%files
%defattr(-,root,root)
%prefixdirs
%dir %{_mandir}
%dir %{_mandir}/man8
%dir %{_sbindir}
%dir %{_sysconfdir}
%{_sbindir}/lctl
%{_sbindir}/routerstat
%{_sysconfdir}/switch.files.lnet
%dir %{inst_path}
%dir /%{lnet_ko_path}
%{inst_path}
/opt/%{namespace}/modulefiles/%{vendor_name}-%{flavor}/%{version}-%{release}
/%{rel_path}/etc/.version
%{_mandir}/man8/lctl.8
%{_mandir}/man8/lst.8

%post
%install_switch

switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
    switch_extra="-r ${RELEASE_UPDATE}"
fi

/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -l %{version}-%{release} ${switch_extra}

%preun
%remove_switch

%postun
switch_extra=""
if [ -n "${RELEASE_UPDATE}" ]; then 
    switch_extra="-r ${RELEASE_UPDATE}"
fi
/opt/cray/lustre-utils/default/bin/lustrerelswitch -p lustre-%{flavor} -u ${switch_extra}

%clean
%clean_build_root
