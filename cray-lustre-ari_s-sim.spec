%define vendor_name lustre
%define vendor_version 2.4
%define flavor cray_ari_s
%define intranamespace_name %{vendor_name}-%{flavor}-sim
%define flavorless_name %{namespace}-%{vendor_name}
# use non-customized version so source doesn't need to be repackaged for custom versions.
%define source_name %{flavorless_name}
%define branch trunk

%define kernel_version %(rpm -q --qf '%{VERSION}' kernel-source)
%define kernel_release %(rpm -q --qf '%{RELEASE}' kernel-source)

BuildRequires: cray-gni-devel
BuildRequires: cray-gni-headers
BuildRequires: cray-gni-headers-private
BuildRequires: kernel-source
BuildRequires: kernel-syms
BuildRequires: %{namespace}-krca-devel
BuildRequires: lsb-cray-hss-devel
BuildRequires: pkgconfig
BuildRequires: -post-build-checks
BuildRequires: module-init-tools
Group: System/Filesystems
License: GPL
Name: %{namespace}-%{intranamespace_name}
Release: %release
Summary: Lustre File System for Aries Sim Nodes
Version: %{vendor_version}_%{kernel_version}_%{kernel_release}
Source: %{source_name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root

# override OBS _prefix to allow us to munge things 
%{expand:%%global OBS_prefix %{_prefix}}
%define _prefix    /

%description
Userspace tools and files for the Lustre file system on Baker SimNow nodes.

%prep
# using source_name here results in too deep of a macro stack, so use
# definition of source_name directly
%incremental_setup -q -n %{flavorless_name}

%build
# LUSTRE_VERS used in ko versioning.
%define version_path %(basename %url)
%define date %(date +%%F-%%R)
%define lustre_version %{branch}-%{release}-%{build_user}-%{version_path}-%{date}

export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

if [ "%reconfigure" == "1" -o ! -x %_builddir/%{source_name}/configure ];then
        chmod +x autogen.sh
        ./autogen.sh
fi

export GNICPPFLAGS=`pkg-config --cflags cray-gni cray-gni-headers lsb-cray-hss`

HSS_FLAGS=`pkg-config --cflags lsb-cray-hss`
CFLAGS="%{optflags} -Werror -fno-stack-protector $HSS_FLAGS"

case "%{kernel_version}" in
  3.0.*)
    VERSION_CONFIGURE_OPTIONS=--disable-server
    ;;
  *)
    VERSION_CONFIGURE_OPTIONS=
    ;;
esac

if [ "%reconfigure" == "1" -o ! -f %_builddir/%{source_name}/Makefile ];then
        %configure --disable-checksum \
           --disable-liblustre \
           --enable-cray-xt3 \
           --enable-gni \
           $VERSION_CONFIGURE_OPTIONS \
           --with-linux-obj=/usr/src/linux-obj/%{_target_cpu}/%{flavor} \
           --with-obd-buffer-size=16384 \
           --without-sysio
fi
%{__make}

%install
# LUSTRE_VERS used in ko versioning.
export LUSTRE_VERS=%{lustre_version}
export SVN_CODE_REV=%{vendor_version}-${LUSTRE_VERS}

# don't use %makeinstall for simulator RPMS - it needlessly puts things into 
#  /opt/cray/,.....

make DESTDIR=${RPM_BUILD_ROOT} install 

%files 
%defattr(-,root,root)
%{_prefix}

%clean
%clean_build_root
