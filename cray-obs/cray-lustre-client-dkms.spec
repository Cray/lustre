# LUTF Turn off brp-python-precompile script as we don't want the python files
# to be compiled on installation
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

%define _version %(if test -s "%_sourcedir/_version"; then cat "%_sourcedir/_version"; else echo "UNKNOWN"; fi)
%define _lnet_version %(echo "%{_version}" | awk -F . '{printf("%s.%s", $1, $2)}')

%define intranamespace_name %{name}
%{expand:%%global OBS_prefix %{_prefix}}
%define prefix /usr
%define _sysconfdir /etc

%global lustre_name cray-lustre-client
%define module %{lustre_name}

%define buildid 1
%define mkconf  lustre/scripts/dkms.mkconf

%bcond_with ofed

%if 0%{with ofed}
%define use_ofed 1
%endif

%if "%{_vendor}" == "redhat"
%global kversion %(make -s -C /usr/src/kernels/* kernelversion)
%global _with_linux --with-linux=/usr/src/kernels/%{kversion}
%global requires_kmod_name kmod-%{lustre_name}
%global requires_kmod_version %{version}
%define mkconf_options %{nil}
%define ofed_module_pkg kmod-mlnx-ofa_kernel
%else
%global kversion %(make -s -C /usr/src/linux-obj/%{_target_cpu}/%{flavor} kernelrelease)
%global _with_linux --with-linux=/usr/src/linux
%global _with_linux_obj --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor}
%global requires_kmod_name %{lustre_name}-kmp
%global krequires %(echo %{kversion} | sed -e 's/\.x86_64$//' -e 's/\.i[3456]86$//' -e 's/-smp$//' -e 's/-bigsmp$//' -e 's/[-.]ppc64$//' -e 's/\.aarch64$//' -e 's/-default$//' -e 's/-%{flavor}//')
%global requires_kmod_version %{version}_k%(echo %{krequires} | sed -r 'y/-/_/; s/^(2\.6\.[0-9]+)_/\\1.0_/;')
%define mkconf_options -k updates
%define ofed_module_pkg mlnx-ofa_kernel-kmp-%{flavor}
%endif

Name: %{module}-dkms
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
BuildArch: noarch

# Vendor specific requires/defines/etc.
%if "%{_vendor}" == "redhat"
BuildRequires: redhat-rpm-config
%endif

%if 0%{?use_ofed}
BuildRequires: mlnx-ofa_kernel-devel
Requires: %{ofed_module_pkg}
%else
Requires: cray-gni-devel
Requires: cray-gni-headers
Requires: cray-gni-headers-private
Requires: cray-krca-devel
Requires: %{namespace}-krca-devel
%endif

Requires: dkms >= 2.2.0.3-28.git.7c3e7c5
Requires: gcc, make, perl
Requires: libtool libyaml-devel zlib-devel
Requires: libnl3-devel keyutils-devel
Requires: cray-kfabric-devel
Requires: automake
Requires: pkg-config
Requires: kernel-devel
Requires: autoconf
Requires: bash-completion bash-completion-devel
Requires: libmount-devel

BuildRequires: %kernel_module_package_buildreqs
BuildRequires: libtool libyaml-devel zlib-devel
BuildRequires: systemd
BuildRequires: libnl3-devel
BuildRequires: keyutils-devel
BuildRequires: flex
BuildRequires: bison

Provides: %{lustre_name} = %{version}
Provides: %{requires_kmod_name} = %{requires_kmod_version}

# Disable post-build-checks; See LUS-1345
# Note: build checks can be run manually by first doing an incremental build
# and then doing a second incremental build with post-build-checks enabled.
#!BuildIgnore: post-build-checks

%description
This package contains the dkms Lustre kernel modules.
and userspace tools and files for the Lustre filesystem.
Compiled for kernel: %{kversion}

%prep
%setup -q -n cray-lustre-%{version}

%build
echo "LUSTRE_VERSION = %{_version}" > LUSTRE-VERSION-FILE
%{mkconf} -n %{module} -v %{version} -f dkms.conf %{mkconf_options}

%install
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi
mkdir -p $RPM_BUILD_ROOT/usr/src/
cp -rfp ${RPM_BUILD_DIR}/cray-lustre-%{version} $RPM_BUILD_ROOT/usr/src/
mv $RPM_BUILD_ROOT/usr/src/cray-lustre-%{version} $RPM_BUILD_ROOT/usr/src/%{module}-%{version}

%clean
if [ "$RPM_BUILD_ROOT" != "/" ]; then
    rm -rf $RPM_BUILD_ROOT
fi

%files
%defattr(-,root,root)
/usr/src/%{module}-%{version}

%post
for POSTINST in /usr/lib/dkms/common.postinst \
		/usr/libexec/dkms/common.postinst; do
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
dkms remove -m %{module} -v %{version} --all --rpm_safe_upgrade
exit 0
