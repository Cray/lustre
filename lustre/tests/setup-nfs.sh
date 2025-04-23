#!/bin/bash
#set -x
EXPORT_OPTS=${EXPORT_OPTS:-"rw,async,no_root_squash"}

nfslock_service() {
	do_nodes $1 "systemctl list-unit-files |\
		grep -q nfslock"
}

setup_nfs() {
	local NFS_VER=${1}
	local MNTPNT=${2}
	local LUSTRE_CLIENT=${3}
	local NFS_CLIENTS=${4}
	local nfs_climntpt=${5:-$MNTPNT}

    local export_opts_v=$EXPORT_OPTS

    echo "Exporting Lustre filesystem..."

    if [ "$NFS_VER" = "4" ]; then
        export_opts_v="$EXPORT_OPTS,fsid=0"
        do_nodes $LUSTRE_CLIENT "mkdir -p /var/lib/nfs/v4recovery"
    fi

    do_nodes $LUSTRE_CLIENT,$NFS_CLIENTS "grep -q rpc_pipefs' ' /proc/mounts ||\
        { mkdir -p /var/lib/nfs/rpc_pipefs && \
        mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs; }" || return 1
    sleep 5

	# get rid of old $MNTPNT entries in /etc/exports
	do_nodes $LUSTRE_CLIENT "sed -i '/${MNTPNT##*/}/d' /etc/exports &&
			echo $MNTPNT *\($export_opts_v\) >> /etc/exports" ||
			return 1

	# restart nfs server according to distro
	do_nodes $LUSTRE_CLIENT "service nfsserver restart ||
				 service nfs restart ||
				 service nfs-server restart" || return 1

	if nfslock_service $LUSTRE_CLIENT; then
		do_nodes $LUSTRE_CLIENT "service nfslock restart" ||
			return 1
	else
		echo "No nfslock service"
	fi

	do_nodes $NFS_CLIENTS "chkconfig --list rpcidmapd 2>/dev/null |
			       grep -q rpcidmapd && service rpcidmapd restart ||
			       true"

	echo -e "\nMounting NFS clients (version $NFS_VER)..."

	do_nodes $NFS_CLIENTS "mkdir -p $nfs_climntpt" || return 1
	if [ "$NFS_VER" = "4" ]; then
		do_nodes $NFS_CLIENTS \
			"mount -t nfs$NFS_VER -o async \
			$LUSTRE_CLIENT:/ $nfs_climntpt" || return 1
	else
		do_nodes $NFS_CLIENTS \
			"mount -t nfs -o nfsvers=$NFS_VER,async \
			$LUSTRE_CLIENT:$MNTPNT $nfs_climntpt" || return 1
	fi
	return 0
}

cleanup_nfs() {
	local MNTPNT=${1}
	local LUSTRE_CLIENT=${2}
	local NFS_CLIENTS=${3}

	echo -e "\nUnmounting NFS clients..."
	zconf_umount_clients "$NFS_CLIENTS" $MNTPNT -f || return 1

	echo -e "\nUnexporting Lustre filesystem..."
	do_nodes $NFS_CLIENTS "chkconfig --list rpcidmapd 2>/dev/null |
			       grep -q rpcidmapd && service rpcidmapd stop ||
			       true"

	do_nodes $LUSTRE_CLIENT "service nfsserver stop ||
				 service nfs stop ||
				 service nfs-server stop" || return 1

	if nfslock_service $LUSTRE_CLIENT; then
		do_nodes $LUSTRE_CLIENT "service nfslock stop" ||
			return 1
	fi
	do_nodes $LUSTRE_CLIENT "sed -i '/${MNTPNT##*/}/d' /etc/exports" || return 1

	do_nodes $LUSTRE_CLIENT "exportfs -v"
}
