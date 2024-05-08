#!/bin/bash

NFSVERSION=${1:-"3"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
# only call init_test_env if this script is called directly
if [[ -z "$TESTSUITE" || "$TESTSUITE" = "$(basename $0 .sh)" ]]; then
	init_test_env $@
else
	. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

fi

init_logging

racer=$LUSTRE/tests/racer/racer.sh
. $LUSTRE/tests/setup-nfs.sh

# lustre client used as nfs server (default is mds node)
LUSTRE_CLIENT_NFSSRV=${LUSTRE_CLIENT_NFSSRV:-$(facet_active_host $SINGLEMDS)}
NFS_SRVMNTPT=${NFS_SRVMNTPT:-$MOUNT}
NFS_CLIENTS=${NFS_CLIENTS:-$CLIENTS}
NFS_CLIENTS=$(exclude_items_from_list $NFS_CLIENTS $LUSTRE_CLIENT_NFSSRV)
NFS_CLIMNTPT=${NFS_CLIMNTPT:-$MOUNT}

[ -z "$NFS_CLIENTS" ] &&
	skip_env "need at least two nodes: nfs server and nfs client"

[ "$NFSVERSION" = "4" ] && cl_mnt_opt="${MOUNT_OPTS:+$MOUNT_OPTS,}32bitapi" ||
	cl_mnt_opt=""

check_and_setup_lustre
$LFS df
TESTDIR=$NFS_CLIMNTPT/d0.$(basename $0 .sh)
mkdir -p $TESTDIR
$LFS setstripe -c -1 $TESTDIR

# first unmount all the lustre clients
cleanup_mount $MOUNT

cleanup_exit () {
	trap 0
	cleanup
	check_and_cleanup_lustre
	exit
}

cleanup () {
	cleanup_nfs "$NFS_CLIMNTPT" "$LUSTRE_CLIENT_NFSSRV" "$NFS_CLIENTS" ||
		error_noexit false "failed to cleanup nfs"
	zconf_umount $LUSTRE_CLIENT_NFSSRV $NFS_SRVMNTPT force ||
		error_noexit false "failed to umount lustre on"\
			"$LUSTRE_CLIENT_NFSSRV"
	# restore lustre mount
	restore_mount $MOUNT ||
		error_noexit false "failed to mount lustre"
}

trap cleanup_exit EXIT SIGHUP SIGINT

zconf_mount $LUSTRE_CLIENT_NFSSRV $NFS_SRVMNTPT "$cl_mnt_opt" ||
	error "mount lustre on $LUSTRE_CLIENT_NFSSRV failed"

# setup the nfs
setup_nfs "$NFSVERSION" "$NFS_SRVMNTPT" "$LUSTRE_CLIENT_NFSSRV" \
		"$NFS_CLIENTS" "$NFS_CLIMNTPT" ||
	error false "setup nfs failed!"

NFSCLIENT=true
FAIL_ON_ERROR=false

# common setup
clients=${NFS_CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE ||
	error "Failed to generate machine file"
num_clients=$(get_node_count ${clients//,/ })

# compilbench
# Run short iteration in nfs mode
cbench_IDIRS=${cbench_IDIRS:-2}
cbench_RUNS=${cbench_RUNS:-2}

# metabench
# Run quick in nfs mode
mbench_NFILES=${mbench_NFILES:-10000}

# connectathon
[ "$SLOW" = "no" ] && cnt_NRUN=2

# IOR
ior_DURATION=${ior_DURATION:-30}

# source the common file after all parameters are set to take affect
. $LUSTRE/tests/functions.sh

build_test_filter

get_mpiuser_id $MPI_USER
MPI_RUNAS=${MPI_RUNAS:-"runas -u $MPI_USER_UID -g $MPI_USER_GID"}
$GSS_KRB5 && refresh_krb5_tgt $MPI_USER_UID $MPI_USER_GID $MPI_RUNAS

test_compilebench() {
	run_compilebench $TESTDIR
}
run_test compilebench "compilebench"

test_metabench() {
	run_metabench $TESTDIR $NFS_CLIMNTPT
}
run_test metabench "metabench"

test_connectathon() {
	run_connectathon $TESTDIR
}
run_test connectathon "connectathon"

test_iorssf() {
	run_ior "ssf" $TESTDIR $NFS_SRVMNTPT
}
run_test iorssf "iorssf"

test_iorfpp() {
	run_ior "fpp" $TESTDIR $NFS_SRVMNTPT
}
run_test iorfpp "iorfpp"

test_racer_on_nfs() {
	local racer_params=${RACER_ON_NFS_PARAMS:-"LCTL=$LCTL \
		RACER_ENABLE_PFL=false RACER_ENABLE_DOM=false \
		RACER_ENABLE_FLR=false RACER_ENABLE_SEL=false \
		RACER_ENABLE_OVERSTRIPE=false RACER_STRIPECOUNT=0 \
		RACER_PROGS=dir_create,file_chmod,file_chown,file_concat,\
file_create,file_delxattr,file_exec,file_getxattr,file_link,file_list,file_mknod,\
file_rename,file_rm,file_setxattr,file_symlink,file_truncate"}

	do_nodes $CLIENTS "$racer_params $racer $TESTDIR"
}
run_test racer_on_nfs "racer on NFS client"

complete $SECONDS
exit_status
