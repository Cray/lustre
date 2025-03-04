dnl #
dnl # Supported configure options.  When no options are specified support
dnl # for ZFS OSDs will be autodetected assuming server support is enabled.
dnl # If the ZFS OSD cannot be built support for it is disabled and a
dnl # warning is issued but the configure process is allowed to continue.
dnl #
dnl # --without-zfs   - Disable zfs support.
dnl # --with-zfs=no
dnl #
dnl # --with-zfs      - Enable zfs support and attempt to autodetect the zfs
dnl # --with-zfs=yes    headers in one of the following places.  Because zfs
dnl #                   support was explicitly required if the headers cannot
dnl #                   be located it is treated as a fatal error.
dnl #
dnl #                       * /var/lib/dkms/zfs/${VERSION}/source
dnl #                       * /usr/src/zfs-${VERSION}/${LINUXRELEASE}
dnl #                       * /usr/src/zfs-${VERSION}
dnl #                       * ../zfs/
dnl #                       * $LINUX/zfs
dnl #
dnl # --with-zfs-devel=path
dnl #                 - User provided directory where zfs development headers
dnl #                   are located. This option is typically used when user
dnl #                   uses rpm2cpio to unpack src rpm.
dnl #                   Assumes layout of:
dnl #                     ${zfs-devel-path}/usr/include/libzfs
dnl #                     ${zfs-devel-path}/usr/include/libspl
dnl #                     ${zfs-devel-path}/lib64/libzfs.so.* or
dnl #                     ${zfs-devel-path}/lib/libzfs.so.*
dnl #
dnl # --with-zfs=path - Enable zfs support and use the zfs headers in the
dnl #                   provided path.  No autodetection is performed and
dnl #                   if no headers are found this is a fatal error.
dnl #
dnl # --with-zfs-obj  - When zfs support is enabled the object directory
dnl #                   will be based on the --with-zfs directory.  If this
dnl #                   is detected incorrectly it can be explicitly
dnl #                   specified using this option.
dnl #
dnl # --without-spl   - Disable spl support.
dnl # --with-spl=no
dnl #
dnl # --with-spl      - Enable spl support and attempt to autodetect the spl
dnl # --with-spl=yes    headers in one of the following places in this order:
dnl #                   * /var/lib/dkms/spl/${VERSION}/source
dnl #                   * /usr/src/spl-${VERSION}/${LINUXRELEASE}
dnl #                   * /usr/src/spl-${VERSION}
dnl #                   * ../spl/
dnl #                   * $LINUX/spl
dnl #
dnl # --with-spl=path - Enable spl support and use the spl headers in the
dnl #                   provided path.  No autodetection is performed.
dnl #
dnl # --with-spl-obj  - When spl support is enabled the object directory
dnl #                   will be based on the --with-spl directory.  If this
dnl #                   is detected incorrectly it can be explicitly
dnl #                   specified using this option.
dnl #
AC_DEFUN([LB_SPL], [
	AC_ARG_WITH([spl],
		AS_HELP_STRING([--with-spl=PATH],
		[Path to spl source]),
		[splsrc="$withval"])

	AC_ARG_WITH([spl-obj],
		AS_HELP_STRING([--with-spl-obj=PATH],
		[Path to spl build objects]),
		[splobj="$withval"])

	dnl #
	dnl # The existence of spl.release[.in] is used to identify a valid
	dnl # source directory.  In order of preference:
	dnl #
	splver=$(ls -1 /usr/src/ | grep ^spl- | cut -f2 -d'-' |
		 sort -V | head -n1)
	spldkms="/var/lib/dkms/spl/${splver}"
	splsrc1="/usr/src/spl-${splver}/${LINUXRELEASE}"
	splsrc2="/usr/src/spl-${splver}"
	splsrc3="../spl/"
	splsrc4="$LINUX/spl"

	AC_MSG_CHECKING([spl source directory])
	AS_IF([test -z "${splsrc}"], [
		AS_IF([test -e "${spldkms}/source/spl.release.in"], [
			splsrc=${spldkms}/source
		], [test -e "${splsrc1}/spl.release.in"], [
			splsrc=${splsrc1}
		], [test -e "${splsrc2}/spl.release.in"], [
			splsrc=${splsrc2}
		], [test -e "${splsrc3}/spl.release.in"], [
			splsrc=$(readlink -f "${splsrc3}")
		], [test -e "${splsrc4}/spl.release.in"], [
			splsrc=${splsrc4}
		], [
			splsrc="[Not found]"
		])
	])
	AC_MSG_RESULT([$splsrc])

	AS_IF([test ! -e "$splsrc/spl.release" &&
	    test ! -e "$splsrc/spl.release.in"], [
		enable_zfs=no
	])

	dnl #
	dnl # The existence of the spl_config.h is used to identify a valid
	dnl # spl object directory.  In many cases the object and source
	dnl # directory are the same, however the objects may also reside
	dnl # is a subdirectory named after the kernel version.  When
	dnl # weak modules are used, the kernel version may not be the
	dnl # same as the LINUXRELEASE against which we are building lustre.
	dnl #
	AC_MSG_CHECKING([spl build directory])
	AS_IF([test -z "$splobj"], [
		last_spl_obj_dir=$(ls -d ${splsrc}/[[0-9]]*/  2> /dev/null | tail -n 1 | sed 's|/$||')
		AS_IF([test "${splsrc}" = "${spldkms}/source"], [
			AS_IF([test -e "${spldkms}/${LINUXRELEASE}/${target_cpu}/spl_config.h"], [
				splobj=${spldkms}/${LINUXRELEASE}/${target_cpu}
			], [
				splobj="[Not found]"
			])
		],[test -e "${splsrc}/${LINUXRELEASE}/spl_config.h"], [
			splobj="${splsrc}/${LINUXRELEASE}"
		], [test -e "${splsrc}/spl_config.h"], [
			splobj="${splsrc}"
		], [test -e "${last_spl_obj_dir}/spl_config.h"], [
			splobj="${last_spl_obj_dir}"
		], [
			splobj="[Not found]"
		])
	])
	AC_MSG_RESULT([$splobj])

	AS_IF([test ! -e "$splobj/spl_config.h"], [
		enable_zfs=no
	])

	dnl #
	dnl # Verify the source version using SPL_META_VERSION in spl_config.h
	dnl #
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([spl source version])
		AS_IF([fgrep -q SPL_META_VERSION $splobj/spl_config.h], [
			splver=$((echo "#include <spl_config.h>";
			    echo "splver=SPL_META_VERSION-SPL_META_RELEASE") |
			    cpp -I $splobj |
			    grep "^splver=" | tr -d \" | cut -d= -f2)
		], [
			splver="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$splver])
	])

	dnl #
	dnl # Verify the modules systems exist by the expect name.
	dnl #
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([spl file name for module symbols])
		AS_IF([test -r $splobj/$SYMVERFILE], [
			splsym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $splobj/$SYMVERFILE"
		], [test -r $splobj/module/$SYMVERFILE], [
			splsym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $splobj/module/$SYMVERFILE"
		], [
			splsym="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$splsym])
	])

	AS_IF([test x$enable_zfs = xyes], [
		SPL=${splsrc}
		SPL_OBJ=${splobj}
		SPL_VERSION=${splver}

		AC_SUBST(SPL)
		AC_SUBST(SPL_OBJ)
		AC_SUBST(SPL_VERSION)
		AC_SUBST(EXTRA_SYMBOLS)
	])

])

AC_DEFUN([LB_ZFS], [
	AC_ARG_WITH([zfs-obj],
		AS_HELP_STRING([--with-zfs-obj=PATH],
		[Path to zfs build objects]),
		[zfsobj="$withval"])

	dnl #
	dnl # The existence of zfs.release[.in] is used to identify a valid
	dnl # source directory.  In order of preference:
	dnl #
	zfsver=$(ls -1 /usr/src/ | grep ^zfs- | cut -f2 -d'-' |
		 sort -V | head -n1)
	zfsdkms="/var/lib/dkms/zfs/${zfsver}"
	zfssrc1="/usr/src/zfs-${zfsver}/${LINUXRELEASE}"
	zfssrc2="/usr/src/zfs-${zfsver}"
	zfssrc3="../zfs/"
	zfssrc4="$LINUX/zfs"

	AC_MSG_CHECKING([zfs source directory])
	AS_IF([test -z "${zfssrc}"], [
		AS_IF([test -e "${zfsdkms}/source/zfs.release.in"], [
			zfssrc=${zfsdkms}/source
		], [test -e "${zfssrc1}/zfs.release.in"], [
			zfssrc=${zfssrc1}
		], [test -e "${zfssrc2}/zfs.release.in"], [
			zfssrc=${zfssrc2}
		], [test -e "${zfssrc3}/zfs.release.in"], [
			zfssrc=$(readlink -f "${zfssrc3}")
		], [test -e "${zfssrc4}/zfs.release.in"], [
			zfssrc=${zfssrc4}
		], [
			zfssrc="[Not found]"
		])
	])
	AC_MSG_RESULT([$zfssrc])

	AS_IF([test ! -e "$zfssrc/zfs.release.in" &&
	    test ! -e "$zfssrc/zfs.release"], [
		enable_zfs=no
	])

	dnl #
	dnl # The existence of the zfs_config.h is used to identify a valid
	dnl # zfs object directory.  In many cases the object and source
	dnl # directory are the same, however the objects may also reside
	dnl # is a subdirectory named after the kernel version.  When
	dnl # weak modules are used, the kernel version may not be the
	dnl # same as the LINUXRELEASE against which we are building lustre.
	dnl #
	AC_MSG_CHECKING([zfs build directory])
	AS_IF([test -z "$zfsobj"], [
		last_zfs_obj_dir=$(ls -d ${zfssrc}/[[0-9]]*/ 2> /dev/null | tail -n 1 | sed 's|/$||')
		AS_IF([test "${zfssrc}" = "${zfsdkms}/source"], [
			AS_IF([test -e "${zfsdkms}/${LINUXRELEASE}/${target_cpu}/zfs_config.h"], [
				zfsobj=${zfsdkms}/${LINUXRELEASE}/${target_cpu}
			], [
				zfsobj="[Not found]"
			])
		], [test -e "${zfssrc}/${LINUXRELEASE}/zfs_config.h"], [
			zfsobj="${zfssrc}/${LINUXRELEASE}"
		], [test -e "${zfssrc}/zfs_config.h"], [
			zfsobj="${zfssrc}"
		], [test -e "${last_zfs_obj_dir}/zfs_config.h"], [
			zfsobj="${last_zfs_obj_dir}"
		], [
			zfsobj="[Not found]"
		])
	])

	AC_MSG_RESULT([$zfsobj])
	AS_IF([test ! -e "$zfsobj/zfs_config.h"], [
		enable_zfs=no
	])

	dnl #
	dnl # Verify the source version using SPL_META_VERSION in spl_config.h
	dnl #
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([zfs source version])
		AS_IF([fgrep -q ZFS_META_VERSION $zfsobj/zfs_config.h], [
			zfsver=$((echo "#include <zfs_config.h>";
			    echo "zfsver=ZFS_META_VERSION-ZFS_META_RELEASE") |
			    cpp -I $zfsobj |
			    grep "^zfsver=" | tr -d \" | cut -d= -f2)
		],[
			zfsver="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$zfsver])
	])

	dnl #
	dnl # Verify the modules systems exist by the expect name.
	dnl #
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([zfs file name for module symbols])
		AS_IF([test -r $zfsobj/$SYMVERFILE], [
			zfssym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $zfsobj/$SYMVERFILE"
		], [test -r $zfsobj/module/$SYMVERFILE], [
			zfssym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $zfsobj/module/$SYMVERFILE"
		], [
			zfssym="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$zfssym])
	])

	AS_IF([test x$enable_zfs = xyes], [
		ZFS=${zfssrc}
		ZFS_OBJ=${zfsobj}
		ZFS_VERSION=${zfsver}

		AC_SUBST(ZFS)
		AC_SUBST(ZFS_OBJ)
		AC_SUBST(ZFS_VERSION)
		AC_SUBST(EXTRA_SYMBOLS)
	])

])

AC_DEFUN([LB_ZFS_DEVEL], [
	AC_ARG_WITH([zfs-devel],
		[AS_HELP_STRING([--with-zfs-devel=PATH],
		[Path to zfs development headers])],
		[zfsdevel="$withval"])

	AC_MSG_CHECKING([user provided zfs devel headers])
	AS_IF([test ! -z "${zfsdevel}"], [
		AS_IF([test -d "${zfsdevel}/usr/include/libspl" && test -d "${zfsdevel}/usr/include/libzfs"], [
			zfsinc="-I $zfsdevel/usr/include/libspl -I $zfsdevel/usr/include/libzfs"
			zfslib="-L$zfsdevel/usr/lib64 -L$zfsdevel/usr/lib -L$zfsdevel/lib64 -L$zfsdevel/lib"
		], [
			AC_MSG_ERROR([Path to development headers directory does not exist])
		])
	])
	AC_MSG_RESULT([$zfsinc])
])

AC_DEFUN([LB_ZFS_USER], [
	dnl #
	dnl # Detect user space zfs development headers.
	dnl #
	AC_MSG_CHECKING([zfs devel headers])
	AS_IF([test -z "${zfsinc}"], [
        	AS_IF([test -e "${zfssrc}/include/libzfs.h" && test -e "${zfssrc}/lib/libspl/include"], [
			zfsinc="-I $zfssrc/lib/libspl/include -I $zfssrc/lib/libspl/include/os/linux -I $zfssrc/include"
			zfslib="-L$zfssrc/lib/libzfs/.libs/ -L$zfssrc/lib/libnvpair/.libs/ -L$zfssrc/lib/libzpool/.libs/"
		], [test -d /usr/include/libzfs && test -d /usr/include/libspl], [
			zfsinc="-I/usr/include/libspl -I /usr/include/libzfs"
			zfslib=""
		], [
			zfsinc="[Not Found]"
			zfslib=""
			enable_zfs=no
		])
	])
	AC_MSG_RESULT([$zfsinc])

	ZFS_LIBZFS_INCLUDE=${zfsinc}
	ZFS_LIBZFS_LDFLAGS=${zfslib}
	ZFS_LIBZFS_LIBS="-lzfs -lnvpair -lzpool"
	AC_SUBST(ZFS_LIBZFS_INCLUDE)
	AC_SUBST(ZFS_LIBZFS_LDFLAGS)
	AC_SUBST(ZFS_LIBZFS_LIBS)
])

AC_DEFUN([LB_CONFIG_ZFS], [
	AC_ARG_WITH([zfs],
		[AS_HELP_STRING([--with-zfs=PATH], [Path to zfs source])],
		[
			AS_IF([test x$withval = xno], [
				enable_spl=no
				enable_zfs=no
				require_zfs=no
			], [test x$withval = xyes], [
				enable_spl=yes
				enable_zfs=yes
				require_zfs=yes
			], [
				enable_spl=yes
				enable_zfs=yes
				require_zfs=yes
				zfssrc="$withval"
			])
		], [
			AS_IF([test x$enable_server != xno], [
				enable_spl=yes
				require_zfs=no
				enable_zfs=yes
			], [
				enable_spl=no
				require_zfs=no
				enable_zfs=no
			])
		])

	AC_MSG_CHECKING([whether to enable zfs])
	AC_MSG_RESULT([$enable_zfs])

	AS_IF([test x$enable_zfs = xyes], [
		AS_IF([test x$enable_modules = xyes], [
			LB_ZFS
		])
		LB_ZFS_DEVEL
		LB_ZFS_USER

		dnl #
		dnl # Define zfs source code version
		dnl #
		ZFS_MAJOR=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\1/'])
		ZFS_MINOR=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\2/'])
		ZFS_PATCH=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\3/'])
		ZFS_FIX=$(echo $zfsver   | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\5/'])
		AS_IF([test -z "$ZFS_FIX"], [ZFS_FIX="0"])

		AC_DEFINE_UNQUOTED([ZFS_MAJOR], [$ZFS_MAJOR], [zfs major version])
		AC_DEFINE_UNQUOTED([ZFS_MINOR], [$ZFS_MINOR], [zfs minor version])
		AC_DEFINE_UNQUOTED([ZFS_PATCH], [$ZFS_PATCH], [zfs patch version])
		AC_DEFINE_UNQUOTED([ZFS_FIX],   [$ZFS_FIX],   [zfs fix version])

		dnl #
		dnl # SPL is only needed if ZFS is prior to 0.8.0
		dnl #
		AS_IF([test x$enable_modules = xyes && test -n "$ZFS_MAJOR" &&
			    test $ZFS_MAJOR -eq 0 && test $ZFS_MINOR -lt 8], [
			LB_SPL
		],[
			enable_spl=no
		])

		dnl #
		dnl # enable_zfs will be set to no in LB_SPL or LB_ZFS if
		dnl # one of more of the build requirements is not met.
		dnl #
		AS_IF([test x$enable_zfs = xyes], [
			AC_DEFINE(HAVE_ZFS_OSD, 1, Enable zfs osd)
		],[
			AS_IF([test x$require_zfs = xyes], [
				AC_MSG_ERROR([

Required zfs osd cannot be built due to missing zfs development headers.

Support for zfs can be enabled by downloading the required packages for your
distribution.  See http://zfsonlinux.org/ to determine is zfs is supported by
your distribution.
				])
			], [
				AC_MSG_WARN([

Disabling optional zfs osd due to missing development headers.

Support for zfs can be enabled by downloading the required packages for your
distribution.  See http://zfsonlinux.org/ to determine is zfs is supported by
your distribution.
				])
			])
		])
	])


	AS_IF([test "x$enable_zfs" = xyes], [
		LB_CHECK_COMPILE([if zfs defines dsl_pool_config_enter/exit],
		dsl_pool_config_enter, [
			#include <sys/dsl_pool.h>
		],[
			dsl_pool_config_enter(NULL, FTAG);
		],[
			AC_DEFINE(HAVE_DSL_POOL_CONFIG, 1,
				[Have dsl_pool_config_enter/exit in ZFS])
		],[
			AC_MSG_ERROR([dsl_pool_config_enter/exit do not exist])
		])
		LB_CHECK_COMPILE([if zfs defines zio_buf_alloc/free],
		zio_buf_alloc, [
			#include <sys/zio.h>
		],[
			void *ptr = zio_buf_alloc(1024);

			(void)ptr;
		],[
			AC_DEFINE(HAVE_ZIO_BUF_ALLOC, 1,
				[Have zio_buf_alloc/free in ZFS])
		],[
			AC_MSG_ERROR([zio_buf_alloc/free do not exist])
		])
		LB_CHECK_COMPILE([if zfs defines spa_maxblocksize],
		spa_maxblocksize, [
			#include <sys/spa.h>
		],[
			spa_t *spa = NULL;
			int size = spa_maxblocksize(spa);

			(void)size;
		],[
			AC_DEFINE(HAVE_SPA_MAXBLOCKSIZE, 1,
				[Have spa_maxblocksize in ZFS])
		],[
			AC_MSG_ERROR([spa_maxblocksize does not exist])
		])

		dnl #
		dnl # ZFS 0.7.x adds support for large dnodes.  This
		dnl # allows Lustre to optionally specify the size of a
		dnl # dnode which ZFS will then use to store metadata such
		dnl # as xattrs. The default dnode size specified by the
		dnl # 'dnodesize' dataset property will be used unless a
		dnl # specific value is provided.
		dnl #
		LB_CHECK_COMPILE([if zfs defines dmu_object_alloc_dnsize],
		dmu_object_alloc_dnsize, [
			#include <sys/dmu.h>
			#include <sys/dnode.h>
		],[
			objset_t *os = NULL;
			dmu_object_type_t objtype = DMU_OT_NONE;
			int blocksize = 0;
			dmu_object_type_t bonustype = DMU_OT_SA;
			int dnodesize = DNODE_MIN_SIZE;
			dmu_tx_t *tx = NULL;
			uint64_t id;

			id = dmu_object_alloc_dnsize(os, objtype, blocksize,
						     bonustype,
						     DN_BONUS_SIZE(dnodesize),
						     dnodesize, tx);
		],[
			AC_DEFINE(HAVE_DMU_OBJECT_ALLOC_DNSIZE, 1,
				[Have dmu_object_alloc_dnsize in ZFS])
		],[
			AC_MSG_ERROR([dmu_object_alloc_dnsize does not exist])
		])

		dnl #
		dnl # ZFS 0.7.x extended dmu_prefetch() to take an additional
		dnl # 'level' and 'priority' argument.  Use a level of 0 and a
		dnl # priority of ZIO_PRIORITY_SYNC_READ to replicate the
		dnl # behavior of the four argument version.
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_prefetch' with 6 args],
		dmu_prefetch, [
			#include <sys/dmu.h>
		],[
			objset_t *os = NULL;
			uint64_t object = 0;
			int64_t level = 0;
			uint64_t offset = 0;
			uint64_t len = 0;
			enum zio_priority pri = ZIO_PRIORITY_SYNC_READ;

			dmu_prefetch(os, object, level, offset, len, pri);
		],[
			AC_DEFINE(HAVE_DMU_PREFETCH_6ARG, 1,
				[Have 6 argument dmu_pretch in ZFS])
		],[
			AC_MSG_ERROR([6 argument dmu_pretch does not exist])
		])
		dnl #
		dnl # ZFS 0.7.0 feature: SPA_FEATURE_USEROBJ_ACCOUNTING
		dnl #
		LB_CHECK_COMPILE([if ZFS has native dnode accounting supported],
		dmu_objset_userobjused_enabled, [
			#include <sys/dmu_objset.h>
		],[
			dmu_objset_userobjused_enabled(NULL);
		],[
			AC_DEFINE(HAVE_DMU_USEROBJ_ACCOUNTING, 1,
				[Have native dnode accounting in ZFS])
		],[
			AC_MSG_ERROR([native dnode accounting does not exist])
		])
		dnl #
		dnl # ZFS 0.7.0 feature: MULTIHOST
		dnl #
		LB_CHECK_COMPILE([if ZFS has multihost protection],
		spa_multihost, [
			#include <sys/fs/zfs.h>
		],[
			zpool_prop_t prop = ZPOOL_PROP_MULTIHOST;

			(void)prop;
		],[
			AC_DEFINE(HAVE_ZFS_MULTIHOST, 1,
				[Have multihost protection in ZFS])
		],[
			AC_MSG_ERROR([multihost protection does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method zap_lookup_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'zap_lookup_by_dnode'],
		zap_lookup_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			zap_lookup_by_dnode(dn, NULL, 1, 1, NULL);
		],[
			AC_DEFINE(HAVE_ZAP_LOOKUP_BY_DNODE, 1,
				[Have zap_lookup_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([zap_lookup_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method zap_add_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'zap_add_by_dnode'],
		zap_add_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			zap_add_by_dnode(dn, NULL, 1, 1, NULL, NULL);
		],[
			AC_DEFINE(HAVE_ZAP_ADD_BY_DNODE, 1,
				[Have zap_add_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([zap_add_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method zap_remove_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'zap_remove_by_dnode'],
		zap_remove_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			zap_remove_by_dnode(dn, NULL, NULL);
		],[
			AC_DEFINE(HAVE_ZAP_REMOVE_ADD_BY_DNODE, 1,
				[Have zap_remove_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([zap_remove_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method dmu_tx_hold_zap_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_tx_hold_zap_by_dnode'],
		dmu_tx_hold_zap_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			dmu_tx_hold_zap_by_dnode(NULL, dn, TRUE, NULL);
		],[
			AC_DEFINE(HAVE_DMU_TX_HOLD_ZAP_BY_DNODE, 1,
				[Have dmu_tx_hold_zap_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([dmu_tx_hold_zap_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method dmu_tx_hold_write_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_tx_hold_write_by_dnode'],
		dmu_tx_hold_write_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			dmu_tx_hold_write_by_dnode(NULL, dn, 0, 0);
		],[
			AC_DEFINE(HAVE_DMU_TX_HOLD_WRITE_BY_DNODE, 1,
				[Have dmu_tx_hold_write_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([dmu_tx_hold_write_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method dmu_write_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_write_by_dnode'],
		dmu_write_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			dmu_write_by_dnode(dn, 0, 0, NULL, NULL);
		],[
			AC_DEFINE(HAVE_DMU_WRITE_BY_DNODE, 1,
				[Have dmu_write_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([dmu_write_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.x adds new method dmu_read_by_dnode
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_read_by_dnode'],
		dmu_read_by_dnode, [
			#include <sys/zap.h>
			#include <sys/dnode.h>
		],[
			dnode_t *dn = NULL;
			dmu_read_by_dnode(dn, 0, 0, NULL, 0);
		],[
			AC_DEFINE(HAVE_DMU_READ_BY_DNODE, 1,
				[Have dmu_read_by_dnode() in ZFS])
		],[
			AC_MSG_ERROR([dmu_read_by_dnode does not exist])
		])
		dnl #
		dnl # ZFS 0.7.2 adds new method dmu_tx_mark_netfree
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_tx_mark_netfree'],
		dmu_tx_mark_netfree, [
			#include <sys/dmu.h>
		],[
			dmu_tx_t *tx = NULL;
			dmu_tx_mark_netfree(tx);
		],[
			AC_DEFINE(HAVE_DMU_TX_MARK_NETFREE, 1,
				[Have dmu_tx_mark_netfree])
		])
		dnl #
		dnl # ZFS 0.7.10 changes timestruc_t to inode_timespec_t
		dnl #
		LB_CHECK_COMPILE([if SPL has 'inode_timespec_t'],
		zfs_have_inode_timespec, [
			#include <sys/fs/zfs.h>
		],[
			inode_timespec_t now;
			gethrestime(&now);
		],[
			AC_DEFINE(HAVE_ZFS_INODE_TIMESPEC, 1,
				[Have inode_timespec_t])
		])
		dnl # ZFS 0.7.12/0.8.x uses zfs_refcount_add() instead of
		dnl # refcount_add().  ZFS 2.0 renamed sys/refcount.h to
		dnl # sys/zfs_refcount.h, rather the add another check to
		dnl # determine the correct header name include it
		dnl # indirectly through sys/dnode.h.
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'zfs_refcount_add'],
		zfs_refcount_add, [
			#include <sys/dnode.h>
		],[
			zfs_refcount_add((zfs_refcount_t *) NULL, NULL);
		],[
			AC_DEFINE(HAVE_ZFS_REFCOUNT_ADD, 1,
				[Have zfs_refcount_add])
		])
		dnl #
		dnl # ZFS 0.8.x changes dmu_objset_own for encryption
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_objset_own' with 6 args],
		dmu_objset_own, [
			#include <sys/dmu_objset.h>
		],[
			objset_t *os = NULL;
			dmu_objset_type_t type = DMU_OST_ANY;
			dmu_objset_own(NULL, type, B_FALSE, B_TRUE, FTAG, &os);
		],[
			AC_DEFINE(HAVE_DMU_OBJSET_OWN_6ARG, 1,
				[Have dmu_objset_own() with 6 args])
		])
		dnl #
		dnl # ZFS 0.8.x changes dmu_objset_disown for encryption
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'dmu_objset_disown' with 3 args],
		dmu_objset_disown, [
			#include <sys/dmu_objset.h>
		],[
			objset_t *os = NULL;
			dmu_objset_disown(os, B_TRUE, FTAG);
		],[
			AC_DEFINE(HAVE_DMU_OBJSET_DISOWN_3ARG, 1,
				[Have dmu_objset_disown() with 3 args])
		])
		dnl #
		dnl # ZFS exports dmu_offet_next
		dnl #
		AC_CACHE_CHECK([if ZFS exports 'dmu_offset_next'],
		[lb_cv_dmu_offset_next], [
		lb_cv_dmu_offset_next="no"
		AS_IF([grep -q -E "EXPORT_SYMBOL.*\(dmu_offset_next\)" "$zfssrc/module/zfs/dmu.c" 2>/dev/null],
			[lb_cv_dmu_offset_next="yes"])
		])
		AS_IF([test "x$lb_cv_dmu_offset_next" = "xyes"], [
			AC_DEFINE(HAVE_DMU_OFFSET_NEXT, 1,
				[Have dmu_offset_next() exported])
		])
		dnl #
		dnl # ZFS 2.0 replaced .db_last_dirty / .dr_next with a list_t
		dnl # and list_node_t named .db_dirty_records / .dr_dbuf_node.
		dnl #
		LB_CHECK_COMPILE([if ZFS has 'db_dirty_records' list_t],
		db_dirty_records, [
			#include <sys/dbuf.h>
		],[
			dmu_buf_impl_t db;
			dbuf_dirty_record_t *dr;
			dr = list_head(&db.db_dirty_records);
		],[
			AC_DEFINE(HAVE_DB_DIRTY_RECORDS_LIST, 1,
				[Have db_dirty_records list_t])
		])
		dnl #
		dnl # ZFS 2.0 renamed sys/refcount.h to zfs_refcount.h
		dnl # This build issue shows up with ZFS 2.0.7 and Lustre 2.12 LTS
		dnl #
		LB_CHECK_COMPILE([if ZFS renamed sys/refcount to zfs_refcount.h],
		zfs_zfs_refcount, [
			#include <sys/zfs_refcount.h>
		],[
			zfs_refcount_add((zfs_refcount_t *) NULL, NULL);
		],[
			AC_DEFINE(HAVE_ZFS_REFCOUNT_HEADER, 1,
				[Have zfs_refcount.h])
		])
		old_EXTRA_KCFLAGS=$EXTRA_KCFLAGS
		EXTRA_KCFLAGS+=" -Werror"
		dnl #
		dnl # ZFS 2.2.0 nvpair now returns and expects constant args
		dnl #
		LB_CHECK_COMPILE([if ZFS nvlist interfaces require const],
		zfs_nvpair_const, [
			#include <sys/nvpair.h>
		], [
			nvpair_t *nvp = NULL;
			nvlist_t *nvl = NULL;
			const char *name = nvpair_name(nvp);
			nvlist_lookup_string(nvl, name, &name);
			nvlist_lookup_nvlist(nvl, name, &nvl);
		], [
			AC_DEFINE(HAVE_ZFS_NVLIST_CONST_INTERFACES, 1,
			    [ZFS nvlist interfaces require const])
		])
		dnl #
		dnl # ZFS 2.2.1 arc_prune_func_t now uses uint64_t for the
		dnl # first parameter
		dnl #
		LB_CHECK_COMPILE([if ZFS arc_prune_func_t uses uint64_t],
		zfs_arc_prune_func_uint64, [
			#include <sys/arc.h>
		], [
			void arc_prune_func(uint64_t bytes, void *priv) {}
			arc_prune_t *arc_p __attribute__ ((unused)) =
				arc_add_prune_callback(arc_prune_func, NULL);
		], [
			AC_DEFINE(HAVE_ZFS_ARC_PRUNE_FUNC_UINT64, 1,
				[ZFS arc_prune_func_t uses uint64_t])
		])
		EXTRA_KCFLAGS=$old_EXTRA_KCFLAGS
	])

	AS_IF([test "x$enable_zfs" = xyes], [
		AC_SUBST(ENABLE_ZFS, yes)
	], [
		AC_SUBST(ENABLE_ZFS, no)
	])
	AM_CONDITIONAL(ZFS_ENABLED, [test "x$enable_zfs" = xyes])
	AM_CONDITIONAL(SPL_ENABLED, [test "x$enable_spl" = xyes])
])
