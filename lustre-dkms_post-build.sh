#!/bin/bash
# $1 : $module
# $2 : $module_version
# $3 : $kernelver
# $4 : $kernel_source_dir
# $5 : $arch
# $6 : $source_tree
# $7 : $dkms_tree
#
# This script ensure that ALL Lustre kernel modules that have been built
# during DKMS build step of lustre[-client]-dkms module will be moved in
# DKMS vault/repository, and this before the build directory content will be
# trashed.
# This is required because dkms.conf file is only sourced at the very
# beginning of the DKMS build step when its content has to be on-target
# customized during pre_build script. This can lead to incomplete list
# of built Lustre kernel modules then to be saved for next DKMS install step.

# Use this place to also save config.log that has been generated during
# pre_build.
# $7/$1/$2/$3/$5/log repository should have already been created to save
# make.log and $kernel_config
mkdir -p "$7/$1/$2/$3/$5/log"
cp -f "$7/$1/$2/build/config.log" "$7/$1/$2/$3/$5/log/config.log" 2>/dev/null
cp -f "$7/$1/$2/build/config.h" \
    "$7/$1/$2/build/Module.symvers" \
    "$7/$1/$2/$3/$5/" 2> /dev/null

case $1 in
    cray-lustre-client)
	flavor=$(echo $3 | tr '-' '\n' | tail -1)

	# $flavor-lnet-devel
	mkdir -p /usr/include/lustre/$flavor
	cp -vf $7/$1/$2/$3/$5/config.h /usr/include/lustre/$flavor
	mkdir -p /usr/share/symvers/$5/$flavor
	cp -vf $7/$1/$2/$3/$5/Module.symvers /usr/share/symvers/$5/$flavor

	# LNet headers:
	for fname in $(find lnet/include -type f -name \*.h)
	do
	    target=$(echo ${fname} | sed -e 's:^lnet/include/::g')
	    if [[ ${target} == uapi/* ]]; then
	        header=$(echo ${fname} | sed -e 's:^uapi/linux/lnet/::g')
	        install -D -m 0644 ${fname} /usr/include/uapi/linux/lnet/${header}
	        install -D -m 0644 ${fname} /usr/include/linux/lnet/${header}
	    else
	        install -D -m 0644 $fname} /usr/include/${target}
	    fi
	done

	## Lustre headers:
	for fname in $(find libcfs/include/libcfs -type f -name \*.h)
	do
	    target=$(echo ${fname} | sed -e 's:^libcfs/:/usr/:g')
	    install -D -m 0644 ${fname} ${target}
	done

	install -D -m 0644 lustre/include/interval_tree.h /usr/include/interval_tree.h

	cfgdir=/usr/include/lustre/${flavor}
	_version=$2
	_libdir=/usr/lib64
	_includedir=/usr/include
	_datadir=/usr/share

	for f in cray-lustre-api-devel.pc cray-lnet.pc
	do
	    eval "sed -i 's,@includedir@,${_includedir},' cray-obs/${f}"
	    eval "sed -i 's,@libdir@,${_libdir},' cray-obs/${f}"
	    eval "sed -i 's,@symversdir@,${_datadir}/symvers,' cray-obs/${f}"
	    eval "sed -i 's,@PACKAGE_VERSION@,${_version},' cray-obs/${f}"
	    eval "sed -i 's,@cfgdir@,${cfgdir},' cray-obs/${f}"
	    install -D -m 0644 cray-obs/${f} /usr/lib64/pkgconfig/${f}
	done
	;;
esac
