BuildRequires: pkgconfig
BuildRequires: module-init-tools
BuildRequires: libtool

%if %{with clfs}
BuildRequires: kernel-debug-headers
BuildRequires: kernel-devel
BuildRequires: libselinux-devel
BuildRequires: redhat-rpm-config
BuildRequires: ofed-devel
%endif

%if  %{with compute} || %{with dal} || %{with service}
BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: cray-krca-devel
BuildRequires: lsb-cray-hss-devel
%endif

%if %{with compute} || %{with dal} || %{with service} || %{with elogin}
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: libselinux-devel
%endif

%if %{with compute} || %{with service}
BuildRequires: libtool
%endif

%if %{with clfs} || %{with dal} || %{with service} || %{with elogin}
BuildRequires: -post-build-checks
%endif

%if %{with clfs} || %{with xedal}
BuildRequires: python-docutils
%endif

%if %{with service} || %{with compute}
BuildRequires: sles-release
%endif

%if %{with compute}
BuildRequires: udev
%endif

BuildConflicts: post-build-checks

%if %{with clfs} || %{with elogin}
%define flavor default
%endif

%if %{with xccompute}
%define flavor cray_ari_c
%endif

%if %{with xecompute}
%define flavor cray_gem_c
%endif

%if %{with xcdal}
%define flavor cray_ari_s_cos
%endif

%if %{with xedal}
%define flavor cray_gem_s_cos
%endif

%if %{with xcservice}
%define flavor cray_ari_s
%endif

%if %{with xeservice}
%define flavor cray_gem_s
%endif

%define _prefix    /
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}
%define branch trunk
%define vendor_name lustre
%define pc_files cray-lustre-api-devel.pc cray-lustre-cfsutil-devel.pc cray-lustre-ptlctl-devel.pc
%if %{with SLES12}
%define intranamespace_name %{vendor_name}-%{flavor}_rhine
%else
%define intranamespace_name %{vendor_name}-%{flavor}
%endif
%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define source_name %{vendor_namespace}-%{vendor_name}-%{_version}

Requires: liblustreapi.so()(64bit) 

%if %{without elogin}
%define gni --enable-gni 
%else
%define gni %{nil} 
%endif

%if %{with service} || %{with compute} || %{with elogin}
%define disable_server --disable-server --enable-client 
%else
%define disable_server %{nil}
%endif

%if %{with clfs}
%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-devel)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-devel)
%define config_args --with-linux=/usr/src/kernels/%{kernel_version}-%{kernel_release}.%{_target_cpu} --enable-ldiskfs
%else
%define config_args --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} %{gni} %{disable_server}
%endif

%define node_type %(echo %{distribution} | awk '{print $1}' | awk -F: '{print $NF}')

Name:       cray-lustre-%{node_type}-module 
Version:    %{_version}
Release:    %{release}
Source:     %{source_name}.tar.bz2
Summary:    Lustre module file and pc files
Group:      System/Filesystems
License:    Cray Software License Agreement
Packager:   sps@cray.com
URL:        %url
BuildRoot:  %{_tmppath}/%{name}-%{version}-root 

%description
A package that contains pc files and a lustre module file. 
 
%prep
%setup -n %{source_name}
 
%build
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE
sed -i '1i%%define _prefix /' lustre.spec.in
sed -i '1i%%define _includedir /usr/include' lustre.spec.in
sed -i '/Requires: kernel = %{krequires}/d' lustre.spec.in
sed -i '/Release.*/c\Release: %{release}' lustre.spec.in
%if %{with service} || %{with compute} || %{with dal}
sed -i 's/kernel_module_package /cray_kernel_module_package /g' lustre.spec.in
%endif

%{__sed} -e 's/@VERSION@/%{version}-%{release}/g' version.in > .version

export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{_version}-${LUSTRE_VERS}

%if %{with xc} || %{with xedal}
export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca lsb-cray-hss`
%endif

%if %{with xeservice} || %{with xecompute}
export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers cray-krca`
%endif

%if %{with xc}
HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"
%endif
%if %{with clfs} || %{with elogin}
CFLAGS="%{optflags} -Werror"
%endif

%if %{with xe}
CFLAGS="%{optflags} -Werror -fno-stack-protector"
%endif

%if %{without compute}
if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=yes
fi
%else
O2IBPATH=no
%endif


sh autogen.sh
%configure --includedir=/usr/include --with-rpmsubname=%{node_type} --with-o2ib=${O2IBPATH} %{config_args}
%{__make} %_smp_mflags rpms 

%if %{with SLES11} 
%{__cp} *x86_64.rpm /usr/src/packages/RPMS/x86_64/
%{__cp} *src.rpm /usr/src/packages/SRPMS/

%if %{with compute}
%{__rm} -f /usr/src/packages/RPMS/x86_64/*ari_s*
%endif
%if %{with service}
%{__rm} -f /usr/src/packages/RPMS/x86_64/*ari_c*
%endif
%if %{with xe}
%{__rm} -f /usr/src/packages/RPMS/x86_64/*ari*
%endif
%endif


%if %{with CENTOS65} || %{with CENTOS66} || %{with SLES12}
%{__cp} *x86_64.rpm /home/abuild/rpmbuild/RPMS/x86_64/
%{__cp} *src.rpm /home/abuild/rpmbuild/SRPMS

%if %{with xc}
%{__rm} -f /home/abuild/rpmbuild/RPMS/x86_64/*gem*
%endif
%if %{with xe}
%{__rm} -f /home/abuild/rpmbuild/RPMS/x86_64/*ari*
%endif
%if %{with dal}
%{__rm} -f /home/abuild/rpmbuild/RPMS/x86_64/*athena*
%endif
%if %{with compute}
%{__rm} -f /home/abuild/rpmbuild/RPMS/x86_64/*ari_s*
%endif
%if %{with service}
%{__rm} -f /home/abuild/rpmbuild/RPMS/x86_64/*ari_c*
%endif
%endif

%install
for f in %{pc_files}
do
    eval "sed -i 's,^prefix=.*$,prefix=/usr,' %{_sourcedir}/${f}"
    install -D -m 0644  %{_sourcedir}/${f} %{buildroot}/%{_pkgconfigdir}/${f}
    %{__rm} -f %{_sourcedir}/${f}
done

%{__install} -D -m 0644 .version %{buildroot}/%{_name_modulefiles_prefix}/.version
%{__install} -D -m 0644 module %{buildroot}/%{_release_modulefile}
 
%files
%defattr(-, root, root)
/

%post
%{__ln_s} %{_sbindir}/ko2iblnd-probe /usr/sbin
