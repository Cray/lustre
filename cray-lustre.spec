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

%define _prefix          /usr
%define _pkgconfigdir    %{_prefix}/lib64/pkgconfig/%{flavor}
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}
%define branch trunk
%define vendor_name lustre
%define pc_files cray-lustre-api-devel.pc cray-lustre-cfsutil-devel.pc cray-lustre-ptlctl-devel.pc
%define intranamespace_name %{vendor_name}-%{flavor}
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
## Set the version of the lustre build to the git tag
echo "LUSTRE_VERSION = %{_tag}" > LUSTRE-VERSION-FILE

## Set the sysconfig dir to /etc. It is set by default to %{_prefix}/etc which means
## that in this case it would be /usr/etc which is not waht we want.
%{__sed} -i '1i%%define _sysconfdir /etc' lustre.spec.in

## Set the overall prefix to /usr.
%{__sed} -i '1i%%define _prefix /usr' lustre.spec.in

## Set the release version of the lustre rpms to the release version of the metaspec build.
## If this is not done the versions between the lustre rpms and the metaspec rpms will differ.
%{__sed} -i '/Release.*/c\Release: %{release}' lustre.spec.in

## This is a sles quirk which did not carry over to our cray sles kernel. Thus it must be changed
## for the build to work. When the sles kernel went from version 11 to 12 they decided to add this
## "k" to the beginning of the release string. Our version of the kernel doesnt do that.
%{__sed} -i 's/{version}_k/{version}_/g' lustre.spec.in

## Set the version of the lustre rpms to the version of the metaspec rpm.
%{__sed} -i 's/%%{version}/%{version}/g' lustre.spec.in

## This is required because we want the lustre version in the config.h file to contain
## the githash of the build whereas we dont want the version of the lustre rpm to contain
## the githash. This is because the githash is included in the release and we dont want it
## in there twice.
%{__sed} -i 's/lustre-%{version}/lustre-%{_tag}/g' lustre.spec.in

## This allows the Module.symvers file to be packaged in the way that DVS expects
%if %{with service} || %{with compute}
%{__sed} -i 's,destfil=usr/src/lustre-%{_tag}-headers/Module.symvers,destfil=usr/src/lustre-%{_tag}-headers/Module.symvers; %%{__install} -D -m 0644 $f %{buildroot}/usr/src/lustre-%{_tag}-headers/%{_target_cpu}/%{flavor}/Module.symvers,g' lustre.spec.in
%endif

## This is necessary because our centos kernel is "SLESified" which means that it contains
## some of the versioning characteristics of the sles kernels.
%if %{with dal}
%{__sed} -i '/%%global requires_kmod_name kmod-%%{lustre_name}/c\%%global requires_kmod_name %%{lustre_name}-kmp' lustre.spec.in
%{__sed} -i "/%%global requires_kmod_version %{version}$/c\%%global requires_kmod_version %{version}_%%(echo %%{krequires} | sed -r 'y\/-\/_\/;')" lustre.spec.in
%endif

## We want to use our cray_kernel_module_package macro instead of the upstream
## kernel_module_package macro.
%if %{with service} || %{with compute} || %{with dal}
%{__sed} -i 's/kernel_module_package /cray_kernel_module_package /g' lustre.spec.in
%endif

## A hack to set the correct version in the .version file for the lustre modulefile.
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

%if %{with compute} || %{with service}
syms="$(pkg-config --variable=symversdir cray-gni)/%{flavor}/Module.symvers"
syms="$syms $(pkg-config --variable=symversdir cray-krca)/%{flavor}/Module.symvers"
%endif

%if %{without compute}
if [ -d /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}
    syms="$syms /usr/src/kernel-modules-ofed/%{_target_cpu}/%{flavor}/Modules.symvers"
elif [ -d /usr/src/ofed/%{_target_cpu}/%{flavor} ]; then
    O2IBPATH=/usr/src/ofed/%{_target_cpu}/%{flavor}
else
    O2IBPATH=yes
fi
%else
O2IBPATH=no
%endif

cat << EOF > cray-lnet.pc
includedir=/usr/src/lustre-%{_tag}-headers
symversdir=/usr/src/lustre-%{_tag}-headers

Cflags: \
-I\${includedir}/libcfs/include \
-I\${includedir}/lnet/include \
-I\${includedir}/lustre/include

Description: Lustre Lnet
Name: cray-lnet
Version: %{_tag}
EOF

sh autogen.sh
%configure --with-rpmsubname=%{node_type} --with-extra-symbols="$syms" --with-pkgconfigdir=%{_pkgconfigdir} --with-o2ib=${O2IBPATH} %{config_args}
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
    eval "sed -i 's,^includedir=.*$,includedir=/usr/src/lustre-%{_tag}-headers,' %{_sourcedir}/${f}"
    install -D -m 0644  %{_sourcedir}/${f} %{buildroot}/%{_pkgconfigdir}/${f}
    %{__rm} -f %{_sourcedir}/${f}
done

%{__install} -D -m 0644 cray-lnet.pc %{buildroot}/%{_pkgconfigdir}/cray-lnet.pc
%{__install} -D -m 0644 config.h %{buildroot}/usr/src/lustre-%{_tag}-headers/%{_arch}/%{flavor}/config.h

%{__install} -D -m 0644 .version %{buildroot}/%{_name_modulefiles_prefix}/.version
%{__install} -D -m 0644 module %{buildroot}/%{_release_modulefile}

%files
%defattr(-, root, root)
%{_pkgconfigdir}/*
/opt/cray/modulefiles/*
/usr/src/lustre-%{_tag}-headers/%{_arch}/%{flavor}/config.h
%if %{with service} || %{with compute}
%attr(0755, root, root) /usr/src/lustre-%{_tag}-headers/%{_target_cpu}/%{flavor}/Module.symvers
%endif

%post
%{__ln_s} -f %{_sbindir}/ko2iblnd-probe /usr/sbin
