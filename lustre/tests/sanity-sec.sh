#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

init_logging

ALWAYS_EXCEPT="$SANITY_SEC_EXCEPT "

[[ "$SLOW" == "no" ]] && EXCEPT_SLOW="26"

NODEMAP_TESTS=$(seq 7 26)

if ! check_versions; then
	echo "It is NOT necessary to test nodemap under interoperation mode"
	EXCEPT="$EXCEPT $NODEMAP_TESTS"
fi

build_test_filter

RUNAS_CMD=${RUNAS_CMD:-runas}

WTL=${WTL:-"$LUSTRE/tests/write_time_limit"}

CONFDIR=/etc/lustre
PERM_CONF=$CONFDIR/perm.conf
FAIL_ON_ERROR=false
HOSTNAME_CHECKSUM=$(hostname | sum | awk '{ print $1 }')
SUBNET_CHECKSUM=$(expr $HOSTNAME_CHECKSUM % 250 + 1)

require_dsh_mds || exit 0
require_dsh_ost || exit 0

clients=${CLIENTS//,/ }
num_clients=$(get_node_count ${clients})
clients_arr=($clients)

echo "was USER0=$(getent passwd | grep :${ID0:-500}:)"
echo "was USER1=$(getent passwd | grep :${ID1:-501}:)"

ID0=$(id -u $USER0)
ID1=$(id -u $USER1)

echo "now USER0=$USER0=$ID0:$(id -g $USER0), USER1=$USER1=$ID1:$(id -g $USER1)"

if [ "$SLOW" == "yes" ]; then
	NODEMAP_COUNT=16
	NODEMAP_RANGE_COUNT=3
	NODEMAP_IPADDR_LIST="1 10 64 128 200 250"
	NODEMAP_ID_COUNT=10
else
	NODEMAP_COUNT=3
	NODEMAP_RANGE_COUNT=2
	NODEMAP_IPADDR_LIST="1 250"
	NODEMAP_ID_COUNT=3
fi
NODEMAP_MAX_ID=$((ID0 + NODEMAP_ID_COUNT))

[ -z "$USER0" ] &&
	skip "need to add user0 ($ID0:$ID0)" && exit 0

[ -z "$USER1" ] &&
	skip "need to add user1 ($ID1:$ID1)" && exit 0

IDBASE=${IDBASE:-60000}

# changes to mappings must be reflected in test 23
FOPS_IDMAPS=(
	[0]="$((IDBASE+3)):$((IDBASE+0)) $((IDBASE+4)):$((IDBASE+2))"
	[1]="$((IDBASE+5)):$((IDBASE+1)) $((IDBASE+6)):$((IDBASE+2))"
	)

check_and_setup_lustre

assert_DIR

# for GSS_SUP
GSS_REF=$(lsmod | grep ^ptlrpc_gss | awk '{print $3}')
if [ ! -z "$GSS_REF" -a "$GSS_REF" != "0" ]; then
	GSS_SUP=1
	echo "with GSS support"
else
	GSS_SUP=0
	echo "without GSS support"
fi

MDT=$(mdtname_from_index 0 $MOUNT)
[[ -z "$MDT" ]] && error "fail to get MDT0000 device name" && exit 1
do_facet $SINGLEMDS "mkdir -p $CONFDIR"
IDENTITY_FLUSH=mdt.$MDT.identity_flush

SAVE_PWD=$PWD

if (( $MDS1_VERSION >= $(version_code 2.16.51) )); then
	nodemap_activate="nodemap activate"
	nodemap_add="nodemap add"
	nodemap_del="nodemap del"
	nodemap_info="nodemap info"
	nodemap_modify="nodemap modify"
	nodemap_add_range="nodemap add_range"
	nodemap_del_range="nodemap del_range"
	nodemap_add_idmap="nodemap add_idmap"
	nodemap_del_idmap="nodemap del_idmap"
	nodemap_test_nid="nodemap test_nid"
	nodemap_test_id="nodemap test_id"
	nodemap_set_fileset="nodemap set_fileset"
	nodemap_set_sepol="nodemap set_sepol"
else
	nodemap_activate="nodemap_activate"
	nodemap_add="nodemap_add"
	nodemap_del="nodemap_del"
	nodemap_info="nodemap_info"
	nodemap_modify="nodemap_modify"
	nodemap_add_range="nodemap_add_range"
	nodemap_del_range="nodemap_del_range"
	nodemap_add_idmap="nodemap_add_idmap"
	nodemap_del_idmap="nodemap_del_idmap"
	nodemap_test_nid="nodemap_test_nid"
	nodemap_test_id="nodemap_test_id"
	nodemap_set_fileset="nodemap_set_fileset"
	nodemap_set_sepol="nodemap_set_sepol"
fi

sec_login() {
	local user=$1
	local group=$2

	$GSS_KRB5 || return
	if ! $RUNAS_CMD -u $user krb5_login.sh; then
		error "$user login kerberos failed."
		exit 1
	fi

	if ! $RUNAS_CMD -u $user -g $group ls $DIR > /dev/null 2>&1; then
		$RUNAS_CMD -u $user lfs flushctx -k
		$RUNAS_CMD -u $user krb5_login.sh
		if ! $RUNAS_CMD -u$user -g$group ls $DIR > /dev/null 2>&1; then
			error "init $user $group failed."
			exit 2
		fi
	fi
}

declare -a identity_old

wait_ssk() {
	# wait for SSK flavor to be applied if necessary
	if $GSS_SK; then
		if $SK_S2S; then
			wait_flavor all2all $SK_FLAVOR
		else
			wait_flavor cli2mdt $SK_FLAVOR
			wait_flavor cli2ost $SK_FLAVOR
		fi
	fi
}

sec_setup() {
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		switch_identity $num true || identity_old[$num]=$?
	done

	if ! $RUNAS_CMD -u $ID0 ls $DIR > /dev/null 2>&1; then
		sec_login $USER0 $USER0
	fi

	if ! $RUNAS_CMD -u $ID1 ls $DIR > /dev/null 2>&1; then
		sec_login $USER1 $USER1
	fi
	wait_ssk
}
sec_setup

# run as different user
test_0() {
	umask 0022

	chmod 0755 $DIR || error "chmod (1) Failed"
	rm -rf $DIR/$tdir || error "rm (1) Failed"
	mkdir -p $DIR/$tdir || error "mkdir (1) Failed"

	# $DIR/$tdir owner changed to USER0(sanityusr)
	chown $USER0 $DIR/$tdir || error "chown (2) Failed"
	chmod 0755 $DIR/$tdir || error "chmod (2) Failed"

	# Run as ID0 cmd must pass
	$RUNAS_CMD -u $ID0 ls -ali $DIR || error "ls (1) Failed"
	# Remove non-existing file f0
	rm -f $DIR/f0 || error "rm (2) Failed"

	# It is expected that this cmd should fail
	# $DIR has only r-x rights for group and other
	$RUNAS_CMD -u $ID0 touch $DIR/f0
	(( $? == 0 )) && error "touch (1) should not pass"

	# This must pass. $DIR/$tdir/ is owned by ID0/USER0
	$RUNAS_CMD -u $ID0 touch $DIR/$tdir/f1 || error "touch (2) Failed"

	# It is expected that this cmd should fail
	# $tdir has rwxr-xr-x rights for $ID0
	$RUNAS_CMD -u $ID1 touch $DIR/$tdir/f2
	(( $? == 0 )) && error "touch (3) should not pass"

	touch $DIR/$tdir/f3 || error "touch (4) Failed"
	chown root $DIR/$tdir || error "chown (3) Failed"
	chgrp $USER0 $DIR/$tdir || error "chgrp (1) Failed"
	chmod 0775 $DIR/$tdir || error "chmod (3) Failed"

	# Owner is root and group is USER0
	$RUNAS_CMD -u $USER0 -g $USER0 touch $DIR/$tdir/f4 ||
		error "touch (5) Failed"

	# It is expected that this cmd should fail
	# $tdir has rwxrwxr-x rights for group sanityusr/ID0, ID1 will fail
	$RUNAS_CMD -u $ID1 -g $ID1 touch $DIR/$tdir/f5
	(( $? == 0 )) && error "touch (6) should not pass"

	touch $DIR/$tdir/f6 || error "touch (7) Failed"
	rm -rf $DIR/$tdir || error "rm (3) Failed"
}
run_test 0 "uid permission ============================="

# setuid/gid
test_1() {
	[ $GSS_SUP = 0 ] && skip "without GSS support." && return

	rm -rf $DIR/$tdir
	mkdir_on_mdt0 $DIR/$tdir

	chown $USER0 $DIR/$tdir || error "chown (1)"
	$RUNAS_CMD -u $ID1 -v $ID0 touch $DIR/$tdir/f0 && error "touch (2)"
	echo "enable uid $ID1 setuid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid' >> $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -v $ID0 touch $DIR/$tdir/f1 || error "touch (3)"

	chown root $DIR/$tdir || error "chown (4)"
	chgrp $USER0 $DIR/$tdir || error "chgrp (5)"
	chmod 0770 $DIR/$tdir || error "chmod (6)"
	$RUNAS_CMD -u $ID1 -g $ID1 touch $DIR/$tdir/f2 && error "touch (7)"
	$RUNAS_CMD -u$ID1 -g$ID1 -j$ID0 touch $DIR/$tdir/f3 && error "touch (8)"
	echo "enable uid $ID1 setuid,setgid"
	do_facet $SINGLEMDS "echo '* $ID1 setuid,setgid' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -g $ID1 -j $ID0 touch $DIR/$tdir/f4 ||
		error "touch (9)"
	$RUNAS_CMD -u $ID1 -v $ID0 -g $ID1 -j $ID0 touch $DIR/$tdir/f5 ||
		error "touch (10)"

	rm -rf $DIR/$tdir

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 1 "setuid/gid ============================="

# bug 3285 - supplementary group should always succeed.
# NB: the supplementary groups are set for local client only,
# as for remote client, the groups of the specified uid on MDT
# will be obtained by upcall /usr/sbin/l_getidentity and used.
test_4() {
	[[ "$MDS1_VERSION" -ge $(version_code 2.6.93) ]] ||
	[[ "$MDS1_VERSION" -ge $(version_code 2.5.35) &&
	   "$MDS1_VERSION" -lt $(version_code 2.5.50) ]] ||
		skip "Need MDS version at least 2.6.93 or 2.5.35"

	rm -rf $DIR/$tdir
	mkdir_on_mdt0 -p $DIR/$tdir
	chmod 0771 $DIR/$tdir
	chgrp $ID0 $DIR/$tdir
	$RUNAS_CMD -u $ID0 ls $DIR/$tdir || error "setgroups (1)"
	do_facet $SINGLEMDS "echo '* $ID1 setgrp' > $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
	$RUNAS_CMD -u $ID1 -G1,2,$ID0 ls $DIR/$tdir ||
		error "setgroups (2)"
	$RUNAS_CMD -u $ID1 -G1,2 ls $DIR/$tdir && error "setgroups (3)"
	rm -rf $DIR/$tdir

	do_facet $SINGLEMDS "rm -f $PERM_CONF"
	do_facet $SINGLEMDS "lctl set_param -n $IDENTITY_FLUSH=-1"
}
run_test 4 "set supplementary group ==============="

create_nodemaps() {
	local i
	local rc

	squash_id default ${NOBODY_UID:-65534} 0
	wait_nm_sync default squash_uid '' inactive
	squash_id default ${NOBODY_UID:-65534} 1
	wait_nm_sync default squash_gid '' inactive
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		do_facet mgs $LCTL $nodemap_add $csum
		rc=$?
		if [ $rc -ne 0 ]; then
			echo "$nodemap_add $csum failed with $rc"
			return $rc
		fi

		wait_update_facet --verbose mgs \
			"$LCTL get_param nodemap.$csum.id 2>/dev/null | \
			grep -c $csum || true" 1 30 ||
		    return 1
	done
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		wait_nm_sync $csum id '' inactive
	done
	return 0
}

delete_nodemaps() {
	local i

	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL $nodemap_del $csum; then
			error "$nodemap_del $csum failed with $?"
			return 3
		fi

		wait_update_facet --verbose mgs \
			"$LCTL get_param nodemap.$csum.id 2>/dev/null | \
			grep -c $csum || true" 0 30 ||
		    return 1
	done
	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		wait_nm_sync $csum id '' inactive
	done
	return 0
}

add_range() {
	local j
	local cmd="$LCTL $nodemap_add_range"
	local range
	local rc=0

	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		range="$SUBNET_CHECKSUM.${2}.${j}.[1-253]@tcp"
		if ! do_facet mgs $cmd --name $1 --range $range; then
			rc=$((rc + 1))
		fi
	done
	return $rc
}

delete_range() {
	local j
	local cmd="$LCTL $nodemap_del_range"
	local range
	local rc=0

	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		range="$SUBNET_CHECKSUM.${2}.${j}.[1-253]@tcp"
		if ! do_facet mgs $cmd --name $1 --range $range; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

add_idmaps() {
	local i
	local cmd="$LCTL $nodemap_add_idmap"
	local do_proj=true
	local rc=0

	(( $MDS1_VERSION >= $(version_code 2.14.52) )) || do_proj=false

	echo "Start to add idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = $ID0; j < NODEMAP_MAX_ID; j++)); do
			local csum=${HOSTNAME_CHECKSUM}_${i}
			local client_id=$j
			local fs_id=$((j + 1))

			if ! do_facet mgs $cmd --name $csum --idtype uid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if ! do_facet mgs $cmd --name $csum --idtype gid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if $do_proj; then
				if ! do_facet mgs $cmd --name $csum \
				     --idtype projid --idmap \
				     $client_id:$fs_id; then
					rc=$((rc + 1))
				fi
			fi
		done
	done

	return $rc
}

add_root_idmaps() {
	local i
	local cmd="$LCTL $nodemap_add_idmap"
	local rc=0

	echo "Start to add root idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $cmd --name $csum --idtype uid \
		     --idmap 0:1; then
			rc=$((rc + 1))
		fi
		if ! do_facet mgs $cmd --name $csum --idtype gid \
		     --idmap 0:1; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

update_idmaps() { #LU-10040
	[ "$MGS_VERSION" -lt $(version_code 2.10.55) ] &&
		skip "Need MGS >= 2.10.55"

	local csum=${HOSTNAME_CHECKSUM}_0
	local old_id_client=$ID0
	local old_id_fs=$((ID0 + 1))
	local new_id=$((ID0 + 100))
	local tmp_id
	local cmd
	local rc=0

	echo "Start to update idmaps ..."

	#Inserting an existed idmap should return error
	cmd="$LCTL $nodemap_add_idmap --name $csum --idtype uid"
	if do_facet mgs \
		$cmd --idmap $old_id_client:$old_id_fs 2>/dev/null; then
		error "insert idmap {$old_id_client:$old_id_fs} " \
			"should return error"
		rc=$((rc + 1))
		return rc
	fi

	#Update id_fs and check it
	if ! do_facet mgs $cmd --idmap $old_id_client:$new_id; then
		error "$cmd --idmap $old_id_client:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi
	tmp_id=$(do_facet mgs $LCTL get_param -n nodemap.$csum.idmap |
		awk '{ print $7 }' | sed -n '2p')
	[ $tmp_id != $new_id ] && { error "new id_fs $tmp_id != $new_id"; \
		rc=$((rc + 1)); return $rc; }

	#Update id_client and check it
	if ! do_facet mgs $cmd --idmap $new_id:$new_id; then
		error "$cmd --idmap $new_id:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi
	tmp_id=$(do_facet mgs $LCTL get_param -n nodemap.$csum.idmap |
		awk '{ print $5 }' | sed -n "$((NODEMAP_ID_COUNT + 1)) p")
	tmp_id=$(echo ${tmp_id%,*}) #e.g. "501,"->"501"
	[ $tmp_id != $new_id ] && { error "new id_client $tmp_id != $new_id"; \
		rc=$((rc + 1)); return $rc; }

	#Delete above updated idmap
	cmd="$LCTL $nodemap_del_idmap --name $csum --idtype uid"
	if ! do_facet mgs $cmd --idmap $new_id:$new_id; then
		error "$cmd --idmap $new_id:$new_id failed"
		rc=$((rc + 1))
		return $rc
	fi

	#restore the idmaps to make delete_idmaps work well
	cmd="$LCTL $nodemap_add_idmap --name $csum --idtype uid"
	if ! do_facet mgs $cmd --idmap $old_id_client:$old_id_fs; then
		error "$cmd --idmap $old_id_client:$old_id_fs failed"
		rc=$((rc + 1))
		return $rc
	fi

	return $rc
}

delete_idmaps() {
	local i
	local cmd="$LCTL $nodemap_del_idmap"
	local do_proj=true
	local rc=0

	(( $MDS1_VERSION >= $(version_code 2.14.52) )) || do_proj=false

	echo "Start to delete idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local j

		for ((j = $ID0; j < NODEMAP_MAX_ID; j++)); do
			local csum=${HOSTNAME_CHECKSUM}_${i}
			local client_id=$j
			local fs_id=$((j + 1))

			if ! do_facet mgs $cmd --name $csum --idtype uid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if ! do_facet mgs $cmd --name $csum --idtype gid \
			     --idmap $client_id:$fs_id; then
				rc=$((rc + 1))
			fi
			if $do_proj; then
				if ! do_facet mgs $cmd --name $csum \
				     --idtype projid --idmap \
				     $client_id:$fs_id; then
					rc=$((rc + 1))
				fi
			fi
		done
	done

	return $rc
}

delete_root_idmaps() {
	local i
	local cmd="$LCTL $nodemap_del_idmap"
	local rc=0

	echo "Start to delete root idmaps ..."
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $cmd --name $csum --idtype uid \
		     --idmap 0:1; then
			rc=$((rc + 1))
		fi
		if ! do_facet mgs $cmd --name $csum --idtype gid \
		     --idmap 0:1; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

modify_flags() {
	local i
	local proc
	local option
	local cmd="$LCTL $nodemap_modify"
	local rc=0

	proc[0]="admin_nodemap"
	proc[1]="trusted_nodemap"
	option[0]="admin"
	option[1]="trusted"

	for ((idx = 0; idx < 2; idx++)); do
		if ! do_facet mgs $cmd --name $1 --property ${option[$idx]} \
		     --value 1; then
			rc=$((rc + 1))
		fi

		if ! do_facet mgs $cmd --name $1 --property ${option[$idx]} \
		     --value 0; then
			rc=$((rc + 1))
		fi
	done

	return $rc
}

squash_id() {
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	local cmd

	cmd[0]="$LCTL $nodemap_modify --property squash_uid"
	cmd[1]="$LCTL $nodemap_modify --property squash_gid"
	cmd[2]="$LCTL $nodemap_modify --property squash_projid"

	if ! do_facet mgs ${cmd[$3]} --name $1 --value $2; then
		return 1
	fi
}

# ensure that the squash defaults are the expected defaults
squash_id default ${NOBODY_UID:-65534} 0
wait_nm_sync default squash_uid '' inactive
squash_id default ${NOBODY_UID:-65534} 1
wait_nm_sync default squash_gid '' inactive
if [ "$MDS1_VERSION" -ge $(version_code 2.14.50) ]; then
	squash_id default ${NOBODY_UID:-65534} 2
	wait_nm_sync default squash_projid '' inactive
fi

test_nid() {
	local cmd

	cmd="$LCTL $nodemap_test_nid"

	nid=$(do_facet mgs $cmd $1)

	if [ $nid == $2 ]; then
		return 0
	fi

	return 1
}

cleanup_active() {
	# restore activation state
	do_facet mgs $LCTL $nodemap_activate 0
	wait_nm_sync active
}

test_idmap() {
	local i
	local cmd="$LCTL $nodemap_test_id"
	local do_root_idmap=true
	local rc=0

	(( $MDS1_VERSION >= $(version_code 2.15.60) )) || do_root_idmap=false

	echo "Start to test idmaps ..."
	## nodemap deactivated
	if ! do_facet mgs $LCTL $nodemap_activate 0; then
		return 1
	fi
	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
		local j

		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			local nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			local fs_id=$(do_facet mgs $cmd --nid $nid	\
				      --idtype uid --id $id)
			if [ $fs_id != $id ]; then
				echo "expected $id, got $fs_id"
				rc=$((rc + 1))
			fi
		done
	done

	## nodemap activated
	if ! do_facet mgs $LCTL $nodemap_activate 1; then
		return 2
	fi

	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			expected_id=$((id + 1))
			if [ $fs_id != $expected_id ]; then
				echo "expected $expected_id, got $fs_id"
				rc=$((rc + 1))
			fi
		done
	done

	## trust client ids
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL $nodemap_modify --name $csum \
		     --property trusted --value 1; then
			error "$nodemap_modify $csum failed with $?"
			return 3
		fi
	done

	for ((id = $ID0; id < NODEMAP_MAX_ID; id++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id $id)
			if [ $fs_id != $id ]; then
				echo "expected $id, got $fs_id"
				rc=$((rc + 1))
			fi
		done
	done

	## ensure allow_root_access is enabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL $nodemap_modify --name $csum	\
		     --property admin --value 1; then
			error "$nodemap_modify $csum failed with $?"
			return 3
		fi
	done

	## check that root allowed
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		if [ $fs_id != 0 ]; then
			echo "root allowed expected 0, got $fs_id"
			rc=$((rc + 1))
		fi
	done

	if $do_root_idmap; then
		## add mapping for root
		add_root_idmaps

		## check that root allowed
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid \
				--idtype uid --id 0)
			if [ $fs_id != 0 ]; then
				echo "root allowed expected 0, got $fs_id"
				rc=$((rc + 1))
			fi
		done

		## delete mapping for root
		delete_root_idmaps
	fi

	## ensure allow_root_access is disabled
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL $nodemap_modify --name $csum	\
				--property admin --value 0; then
			error "$nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	## check that root is mapped to NOBODY_UID
	for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
		nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
		fs_id=$(do_facet mgs $cmd --nid $nid --idtype uid --id 0)
		if [ $fs_id != ${NOBODY_UID:-65534} ]; then
		      error "root squash expect ${NOBODY_UID:-65534} got $fs_id"
		      rc=$((rc + 1))
		fi
	done

	if $do_root_idmap; then
		## add mapping for root
		add_root_idmaps

		## check root is mapped
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			nid="$SUBNET_CHECKSUM.0.${j}.100@tcp"
			fs_id=$(do_facet mgs $cmd --nid $nid	\
				--idtype uid --id 0)
			expected_id=1
			if [ $fs_id != $expected_id ]; then
				echo "expected $expected_id, got $fs_id"
				rc=$((rc + 1))
			fi
		done

		## delete mapping for root
		delete_root_idmaps
	fi

	## reset client trust to 0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! do_facet mgs $LCTL $nodemap_modify		\
			--name ${HOSTNAME_CHECKSUM}_${i}	\
			--property trusted --value 0; then
			error "$nodemap_modify ${HOSTNAME_CHECKSUM}_${i} "
				"failed with $rc"
			return 3
		fi
	done

	return $rc
}

test_7() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc"

	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc"

	return 0
}
run_test 7 "nodemap create and delete"

test_8() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	# Set up nodemaps

	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	# Try duplicates

	create_nodemaps
	rc=$?
	[[ $rc == 0 ]] && error "duplicate nodemap_add allowed with $rc" &&
	return 2

	# Clean up
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 3

	return 0
}
run_test 8 "nodemap reject duplicates"

test_9() {
	local i
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! delete_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_del_range failed with $rc" && return 4

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 9 "nodemap range add"

test_10a() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc == 0 ]] && error "nodemap_add_range duplicate add with $rc" &&
		return 2


	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! delete_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_del_range failed with $rc" && return 4

	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 5

	return 0
}
run_test 10a "nodemap reject duplicate ranges"

test_10b() {
	[ "$MGS_VERSION" -lt $(version_code 2.10.53) ] &&
		skip "Need MGS >= 2.10.53"

	local nm1="nodemap1"
	local nm2="nodemap2"
	local nids="192.168.19.[0-255]@o2ib20"

	do_facet mgs $LCTL nodemap_del $nm1 2>/dev/null
	do_facet mgs $LCTL nodemap_del $nm2 2>/dev/null

	do_facet mgs $LCTL nodemap_add $nm1 || error "Add $nm1 failed"
	do_facet mgs $LCTL nodemap_add $nm2 || error "Add $nm2 failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm1 --range $nids ||
		error "Add range $nids to $nm1 failed"
	[ -n "$(do_facet mgs $LCTL get_param nodemap.$nm1.* |
		grep start_nid)" ] || error "No range was found"
	do_facet mgs $LCTL nodemap_del_range --name $nm2 --range $nids &&
		error "Deleting range $nids from $nm2 should fail"
	[ -n "$(do_facet mgs $LCTL get_param nodemap.$nm1.* |
		grep start_nid)" ] || error "Range $nids should be there"

	do_facet mgs $LCTL nodemap_del $nm1 || error "Delete $nm1 failed"
	do_facet mgs $LCTL nodemap_del $nm2 || error "Delete $nm2 failed"
	return 0
}
run_test 10b "delete range from the correct nodemap"

test_10c() { #LU-8912
	[ "$MGS_VERSION" -lt $(version_code 2.10.57) ] &&
		skip "Need MGS >= 2.10.57"

	local nm="nodemap_lu8912"
	local nid_range="10.210.[32-47].[0-255]@o2ib3"
	local start_nid="10.210.32.0@o2ib3"
	local end_nid="10.210.47.255@o2ib3"
	local start_nid_found
	local end_nid_found

	do_facet mgs $LCTL nodemap_del $nm 2>/dev/null
	do_facet mgs $LCTL nodemap_add $nm || error "Add $nm failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm --range $nid_range ||
		error "Add range $nid_range to $nm failed"

	start_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /start_nid/'{ print $9 }')
	[ "$start_nid" == "$start_nid_found" ] ||
		error "start_nid: $start_nid_found != $start_nid"
	end_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /end_nid/'{ print $13 }')
	[ "$end_nid" == "$end_nid_found" ] ||
		error "end_nid: $end_nid_found != $end_nid"

	do_facet mgs $LCTL nodemap_del $nm || error "Delete $nm failed"
	return 0
}
run_test 10c "verfify contiguous range support"

test_10d() { #LU-8913
	[ "$MGS_VERSION" -lt $(version_code 2.10.59) ] &&
		skip "Need MGS >= 2.10.59"

	local nm="nodemap_lu8913"
	local nid_range="*@o2ib3"
	local start_nid="0.0.0.0@o2ib3"
	local end_nid="255.255.255.255@o2ib3"
	local start_nid_found
	local end_nid_found

	do_facet mgs $LCTL nodemap_del $nm 2>/dev/null
	do_facet mgs $LCTL nodemap_add $nm || error "Add $nm failed"
	do_facet mgs $LCTL nodemap_add_range --name $nm --range $nid_range ||
		error "Add range $nid_range to $nm failed"

	start_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /start_nid/'{ print $9 }')
	[ "$start_nid" == "$start_nid_found" ] ||
		error "start_nid: $start_nid_found != $start_nid"
	end_nid_found=$(do_facet mgs $LCTL get_param nodemap.$nm.* |
		awk -F '[,: ]' /end_nid/'{ print $13 }')
	[ "$end_nid" == "$end_nid_found" ] ||
		error "end_nid: $end_nid_found != $end_nid"

	do_facet mgs $LCTL nodemap_del $nm || error "Delete $nm failed"
	return 0
}
run_test 10d "verfify nodemap range format '*@<net>' support"

test_11() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! modify_flags ${HOSTNAME_CHECKSUM}_${i}; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_modify with $rc" && return 2

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 3

	return 0
}
run_test 11 "nodemap modify"

test_12() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! squash_id ${HOSTNAME_CHECKSUM}_${i} 88 0; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap squash_uid with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! squash_id ${HOSTNAME_CHECKSUM}_${i} 88 1; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap squash_gid with $rc" && return 3

	rc=0
	if (( $MDS1_VERSION >= $(version_code 2.14.52) )); then
		for ((i = 0; i < NODEMAP_COUNT; i++)); do
			if ! squash_id ${HOSTNAME_CHECKSUM}_${i} 88 2; then
				rc=$((rc + 1))
			fi
		done
	fi
	[[ $rc != 0 ]] && error "nodemap squash_projid with $rc" && return 5

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 12 "nodemap set squash ids"

test_13() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			for k in $NODEMAP_IPADDR_LIST; do
				if ! test_nid $SUBNET_CHECKSUM.$i.$j.$k	\
				       ${HOSTNAME_CHECKSUM}_${i}; then
					rc=$((rc + 1))
				fi
			done
		done
	done
	[[ $rc != 0 ]] && error "nodemap_test_nid failed with $rc" && return 3

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 13 "test nids"

test_14() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		for ((j = 0; j < NODEMAP_RANGE_COUNT; j++)); do
			for k in $NODEMAP_IPADDR_LIST; do
				if ! test_nid $SUBNET_CHECKSUM.$i.$j.$k \
					default; then
					rc=$((rc + 1))
				fi
			done
		done
	done
	[[ $rc != 0 ]] && error "nodemap_test_nid failed with $rc" && return 3

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del failed with $rc" && return 4

	return 0
}
run_test 14 "test default nodemap nid lookup"

test_15() {
	local rc

	remote_mgs_nodsh && skip "remote MGS with nodsh"
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53"

	rc=0
	create_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add failed with $rc" && return 1

	for (( i = 0; i < NODEMAP_COUNT; i++ )); do
		local csum=${HOSTNAME_CHECKSUM}_${i}

		if ! do_facet mgs $LCTL nodemap_modify --name $csum \
				--property admin --value 0; then
			rc=$((rc + 1))
		fi
		if ! do_facet mgs $LCTL nodemap_modify --name $csum \
				--property trusted --value 0; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_modify failed with $rc" && return 1

	rc=0
	for ((i = 0; i < NODEMAP_COUNT; i++)); do
		if ! add_range ${HOSTNAME_CHECKSUM}_${i} $i; then
			rc=$((rc + 1))
		fi
	done
	[[ $rc != 0 ]] && error "nodemap_add_range failed with $rc" && return 2

	rc=0
	add_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_add_idmap failed with $rc" && return 3

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)
	if [[ "$activedefault" != "1" ]]; then
		stack_trap cleanup_active EXIT
	fi

	rc=0
	test_idmap
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_test_id failed with $rc" && return 4

	rc=0
	update_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "update_idmaps failed with $rc" && return 5

	rc=0
	delete_idmaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_del_idmap failed with $rc" && return 6

	rc=0
	delete_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "nodemap_delete failed with $rc" && return 7

	return 0
}
run_test 15 "test id mapping"

create_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		local client_ip=$(host_nids_address $client $NETTYPE)
		local client_nid=$(h2nettype $client_ip)

		do_facet mgs $LCTL nodemap_add c${i} || return 1
		do_facet mgs $LCTL nodemap_add_range 	\
			--name c${i} --range $client_nid || {
			do_facet mgs $LCTL nodemap_del c${i}
			return 1
		}
		for map in ${FOPS_IDMAPS[i]}; do
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype uid --idmap ${map} || return 1
			do_facet mgs $LCTL nodemap_add_idmap --name c${i} \
				--idtype gid --idmap ${map} || return 1
		done

		wait_nm_sync c$i idmap

		i=$((i + 1))
	done
	return 0
}

delete_fops_nodemaps() {
	local i=0
	local client
	for client in $clients; do
		do_facet mgs $LCTL nodemap_del c${i} || return 1
		i=$((i + 1))
	done
	return 0
}

fops_mds_index=0
nm_test_mkdir() {
	if [ $MDSCOUNT -le 1 ]; then
		do_node ${clients_arr[0]} mkdir -p $DIR/$tdir
	else
		# round-robin MDTs to test DNE nodemap support
		[ ! -d $DIR ] && do_node ${clients_arr[0]} mkdir -p $DIR
		do_node ${clients_arr[0]} $LFS setdirstripe -c 1 -i \
			$((fops_mds_index % MDSCOUNT)) $DIR/$tdir
		((fops_mds_index++))
	fi
}

# acl test directory needs to be initialized on a privileged client
fops_test_setup() {
	local admin=$(do_facet mgs $LCTL get_param -n nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chown $user $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap
}

# fileset test directory needs to be initialized on a privileged client
fileset_test_setup() {
	local nm=$1
	local modify_val=""

	# exercise new nodemap_modify syntax if available
	(( $MGS_VERSION >= $(version_code 2.16.51) )) ||
		modify_val=" --value"

	if [[ -n $FILESET && -z $SKIP_FILESET ]]; then
		cleanup_mount $MOUNT
		FILESET="" zconf_mount_clients $CLIENTS $MOUNT
	fi

	local admin=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property admin${modify_val}=1
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property trusted${modify_val}=1

	wait_nm_sync $nm trusted_nodemap

	# create directory and populate it for subdir mount
	do_node ${clients_arr[0]} mkdir $MOUNT/$subdir ||
		error "unable to create dir $MOUNT/$subdir"
	do_node ${clients_arr[0]} touch $MOUNT/$subdir/this_is_$subdir ||
		error "unable to create file $MOUNT/$subdir/this_is_$subdir"
	do_node ${clients_arr[0]} mkdir $MOUNT/$subdir/$subsubdir ||
		error "unable to create dir $MOUNT/$subdir/$subsubdir"
	do_node ${clients_arr[0]} touch \
			$MOUNT/$subdir/$subsubdir/this_is_$subsubdir ||
		error "unable to create file \
			$MOUNT/$subdir/$subsubdir/this_is_$subsubdir"

	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property admin${modify_val}=$admin
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property trusted${modify_val}=$trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync $nm trusted_nodemap
}

# fileset test directory needs to be initialized on a privileged client
fileset_test_cleanup() {
	local nm=$1
	local admin=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		nodemap.${nm}.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name $nm --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name $nm --property trusted \
		--value 1

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap

	# cleanup directory created for subdir mount
	do_node ${clients_arr[0]} rm -rf $MOUNT/$subdir ||
		error "unable to remove dir $MOUNT/$subdir"

	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property trusted --value $trust

	# flush MDT locks to make sure they are reacquired before test
	do_node ${clients_arr[0]} $LCTL set_param \
		ldlm.namespaces.$FSNAME-MDT*.lru_size=clear

	wait_nm_sync $nm admin_nodemap
	wait_nm_sync $nm trusted_nodemap
	if [ -n "$FILESET" -a -z "$SKIP_FILESET" ]; then
		cleanup_mount $MOUNT
		zconf_mount_clients $CLIENTS $MOUNT
	fi
}

do_create_delete() {
	local run_u=$1
	local key=$2
	local testfile=$DIR/$tdir/$tfile
	local rc=0
	local c=0 d=0
	local qused_new
	if $run_u touch $testfile >& /dev/null; then
		c=1
		$run_u rm $testfile && d=1
	fi >& /dev/null

	local res="$c $d"
	local expected=$(get_cr_del_expected $key)
	[ "$res" != "$expected" ] &&
		error "test $key, wanted $expected, got $res" && rc=$((rc + 1))
	return $rc
}

nodemap_check_quota() {
	local run_u="$1"
	$run_u lfs quota -q $DIR | awk '{ print $2; exit; }'
}

do_fops_quota_test() {
	local run_u=$1
	# fuzz quota used to account for possible indirect blocks, etc
	local quota_fuzz=$(fs_log_size)
	local qused_orig=$(nodemap_check_quota "$run_u")
	local qused_high=$((qused_orig + quota_fuzz))
	local qused_low=$((qused_orig - quota_fuzz))
	local testfile=$DIR/$tdir/$tfile
	$run_u dd if=/dev/zero of=$testfile oflag=sync bs=1M count=1 \
		>& /dev/null || error "unable to write quota test file"
	sync; sync_all_data || true

	local qused_new=$(nodemap_check_quota "$run_u")
	[ $((qused_new)) -lt $((qused_low + 1024)) -o \
	  $((qused_new)) -gt $((qused_high + 1024)) ] &&
		error "$qused_new != $qused_orig + 1M after write, " \
		      "fuzz is $quota_fuzz"
	$run_u rm $testfile || error "unable to remove quota test file"
	wait_delete_completed_mds

	qused_new=$(nodemap_check_quota "$run_u")
	[ $((qused_new)) -lt $((qused_low)) \
		-o $((qused_new)) -gt $((qused_high)) ] &&
		error "quota not reclaimed, expect $qused_orig, " \
		      "got $qused_new, fuzz $quota_fuzz"
}

get_fops_mapped_user() {
	local cli_user=$1

	for ((i=0; i < ${#FOPS_IDMAPS[@]}; i++)); do
		for map in ${FOPS_IDMAPS[i]}; do
			if [ $(cut -d: -f1 <<< "$map") == $cli_user ]; then
				cut -d: -f2 <<< "$map"
				return
			fi
		done
	done
	echo -1
}

get_cr_del_expected() {
	local -a key
	IFS=":" read -a key <<< "$1"
	local mapmode="${key[0]}"
	local mds_user="${key[1]}"
	local cluster="${key[2]}"
	local cli_user="${key[3]}"
	local mode="0${key[4]}"
	local SUCCESS="1 1"
	local FAILURE="0 0"
	local noadmin=0
	local mapped=0
	local other=0

	[[ $mapmode == *mapped* ]] && mapped=1
	# only c1 is mapped in these test cases
	[[ $mapmode == mapped_trusted* ]] && [ "$cluster" == "c0" ] && mapped=0
	[[ $mapmode == *noadmin* ]] && noadmin=1

	# o+wx works as long as the user isn't mapped
	if [ $((mode & 3)) -eq 3 ]; then
		other=1
	fi

	# if client user is root, check if root is squashed
	if [ "$cli_user" == "0" ]; then
		# squash root succeed, if other bit is on
		case $noadmin in
			0) echo $SUCCESS;;
			1) [ "$other" == "1" ] && echo $SUCCESS
			   [ "$other" == "0" ] && echo $FAILURE;;
		esac
		return
	fi
	if [ "$mapped" == "0" ]; then
		[ "$other" == "1" ] && echo $SUCCESS
		[ "$other" == "0" ] && echo $FAILURE
		return
	fi

	# if mapped user is mds user, check for u+wx
	mapped_user=$(get_fops_mapped_user $cli_user)
	[ "$mapped_user" == "-1" ] &&
		error "unable to find mapping for client user $cli_user"

	if [ "$mapped_user" == "$mds_user" -a \
	     $(((mode & 0300) == 0300)) -eq 1 ]; then
		echo $SUCCESS
		return
	fi
	if [ "$mapped_user" != "$mds_user" -a "$other" == "1" ]; then
		echo $SUCCESS
		return
	fi
	echo $FAILURE
}

test_fops_admin_cli_i=""
test_fops_chmod_dir() {
	local current_cli_i=$1
	local perm_bits=$2
	local dir_to_chmod=$3
	local new_admin_cli_i=""

	# do we need to set up a new admin client?
	[ "$current_cli_i" == "0" ] && [ "$test_fops_admin_cli_i" != "1" ] &&
		new_admin_cli_i=1
	[ "$current_cli_i" != "0" ] && [ "$test_fops_admin_cli_i" != "0" ] &&
		new_admin_cli_i=0

	# if only one client, and non-admin, need to flip admin everytime
	if [ "$num_clients" == "1" ]; then
		test_fops_admin_client=$clients
		test_fops_admin_val=$(do_facet mgs $LCTL get_param -n \
			nodemap.c0.admin_nodemap)
		if [ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c0 \
				--property admin \
				--value 1
			wait_nm_sync c0 admin_nodemap
		fi
	elif [ "$new_admin_cli_i" != "" ]; then
		# restore admin val to old admin client
		if [ "$test_fops_admin_cli_i" != "" ] &&
				[ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c${test_fops_admin_cli_i} \
				--property admin \
				--value $test_fops_admin_val
			wait_nm_sync c${test_fops_admin_cli_i} admin_nodemap
		fi

		test_fops_admin_cli_i=$new_admin_cli_i
		test_fops_admin_client=${clients_arr[$new_admin_cli_i]}
		test_fops_admin_val=$(do_facet mgs $LCTL get_param -n \
			nodemap.c${new_admin_cli_i}.admin_nodemap)

		if [ "$test_fops_admin_val" != "1" ]; then
			do_facet mgs $LCTL nodemap_modify \
				--name c${new_admin_cli_i} \
				--property admin \
				--value 1
			wait_nm_sync c${new_admin_cli_i} admin_nodemap
		fi
	fi

	do_node $test_fops_admin_client chmod $perm_bits $DIR/$tdir || return 1

	# remove admin for single client if originally non-admin
	if [ "$num_clients" == "1" ] && [ "$test_fops_admin_val" != "1" ]; then
		do_facet mgs $LCTL nodemap_modify --name c0 --property admin \
			--value 0
		wait_nm_sync c0 admin_nodemap
	fi

	return 0
}

test_fops() {
	local mapmode="$1"
	local single_client="$2"
	local client_user_list=([0]="0 $((IDBASE+3))"
				[1]="0 $((IDBASE+5))")
	local mds_users="-1 0"
	local mds_i
	local rc=0
	local perm_bit_list="3 $((0300))"
	# SLOW tests 000-007, 010-070, 100-700 (octal modes)
	if [ "$SLOW" == "yes" ]; then
		perm_bit_list="0 $(seq 1 7) $(seq 8 8 63) $(seq 64 64 511) \
			       $((0303))"
		client_user_list=([0]="0 $((IDBASE+3)) $((IDBASE+4))"
				  [1]="0 $((IDBASE+5)) $((IDBASE+6))")
		mds_users="-1 0 1 2"
	fi

	# force single_client to speed up test
	[ "$SLOW" == "yes" ] ||
		single_client=1
	# step through mds users. -1 means root
	for mds_i in $mds_users; do
		local user=$((mds_i + IDBASE))
		local client
		local x

		[ "$mds_i" == "-1" ] && user=0

		echo mkdir -p $DIR/$tdir
		fops_test_setup
		local cli_i=0
		for client in $clients; do
			local u
			for u in ${client_user_list[$cli_i]}; do
				local run_u="do_node $client \
					     $RUNAS_CMD -u$u -g$u -G$u"
				for perm_bits in $perm_bit_list; do
					local mode=$(printf %03o $perm_bits)
					local key
					key="$mapmode:$user:c$cli_i:$u:$mode"
					test_fops_chmod_dir $cli_i $mode \
						$DIR/$tdir ||
							error cannot chmod $key
					do_create_delete "$run_u" "$key"
				done

				# check quota
				test_fops_chmod_dir $cli_i 777 $DIR/$tdir ||
					error cannot chmod $key
				do_fops_quota_test "$run_u"
			done

			cli_i=$((cli_i + 1))
			[ "$single_client" == "1" ] && break
		done
		rm -rf $DIR/$tdir
	done
	return $rc
}

nodemap_version_check () {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return 1
	[ "$MGS_VERSION" -lt $(version_code 2.5.53) ] &&
		skip "No nodemap on $MGS_VERSION MGS < 2.5.53" &&
		return 1
	return 0
}

nodemap_test_setup() {
	local rc
	local active_nodemap=1

	[ "$1" == "0" ] && active_nodemap=0

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	rc=0
	create_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "adding fops nodemaps failed $rc"

	do_facet mgs $LCTL nodemap_activate $active_nodemap
	wait_nm_sync active

	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	wait_nm_sync default admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	wait_nm_sync default trusted_nodemap
}

nodemap_test_cleanup() {
	trap 0
	delete_fops_nodemaps
	rc=$?
	[[ $rc != 0 ]] && error "removing fops nodemaps failed $rc"

	do_facet mgs $LCTL nodemap_modify --name default \
		 --property admin --value 0
	wait_nm_sync default admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name default \
		 --property trusted --value 0
	wait_nm_sync default trusted_nodemap

	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active 0

	export SK_UNIQUE_NM=false
	return 0
}

nodemap_clients_admin_trusted() {
	local admin=$1
	local tr=$2
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property admin --value $admin
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property trusted --value $tr
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) admin_nodemap
	wait_nm_sync c$((i - 1)) trusted_nodemap
}

test_16() {
	nodemap_version_check || return 0
	nodemap_test_setup 0

	trap nodemap_test_cleanup EXIT
	test_fops all_off
	nodemap_test_cleanup
}
run_test 16 "test nodemap all_off fileops"

test_17() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi
	local check_proj=true

	(( $MDS1_VERSION >= $(version_code 2.14.52) )) || check_proj=false

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 1
	test_fops trusted_noadmin 1
	if $check_proj; then
		do_facet mgs $LCTL nodemap_modify --name c0 \
			--property map_mode --value projid
		wait_nm_sync c0 map_mode
	fi
	test_fops trusted_noadmin 1
	nodemap_test_cleanup
}
run_test 17 "test nodemap trusted_noadmin fileops"

test_18() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 0 0
	test_fops mapped_noadmin 1
	nodemap_test_cleanup
}
run_test 18 "test nodemap mapped_noadmin fileops"

test_19() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 1
	test_fops trusted_admin 1
	nodemap_test_cleanup
}
run_test 19 "test nodemap trusted_admin fileops"

test_20() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	nodemap_clients_admin_trusted 1 0
	test_fops mapped_admin 1
	nodemap_test_cleanup
}
run_test 20 "test nodemap mapped_admin fileops"

test_21() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	local x=1
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 0
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value $x
		x=0
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

	test_fops mapped_trusted_noadmin
	nodemap_test_cleanup
}
run_test 21 "test nodemap mapped_trusted_noadmin fileops"

test_22() {
	if $SHARED_KEY &&
	[ "$MDS1_VERSION" -lt $(version_code 2.11.55) ]; then
		skip "Need MDS >= 2.11.55"
	fi

	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	local x=1
	local i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value $x
		x=0
		i=$((i + 1))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

	test_fops mapped_trusted_admin
	nodemap_test_cleanup
}
run_test 22 "test nodemap mapped_trusted_admin fileops"

# acl test directory needs to be initialized on a privileged client
nodemap_acl_test_setup() {
	local admin=$(do_facet mgs $LCTL get_param -n \
		      nodemap.c0.admin_nodemap)
	local trust=$(do_facet mgs $LCTL get_param -n \
		      nodemap.c0.trusted_nodemap)

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1

	wait_nm_sync c0 admin_nodemap
	wait_nm_sync c0 trusted_nodemap

	do_node ${clients_arr[0]} rm -rf $DIR/$tdir
	nm_test_mkdir
	do_node ${clients_arr[0]} chmod a+rwx $DIR/$tdir ||
		error unable to chmod a+rwx test dir $DIR/$tdir

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property admin --value $admin
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property trusted --value $trust

	wait_nm_sync c0 trusted_nodemap
}

# returns 0 if the number of ACLs does not change on the second (mapped) client
# after being set on the first client
nodemap_acl_test() {
	local user="$1"
	local set_client="$2"
	local get_client="$3"
	local check_setfacl="$4"
	local setfacl_error=0
	local testfile=$DIR/$tdir/$tfile
	local RUNAS_USER="$RUNAS_CMD -u $user"
	local acl_count=0
	local acl_count_post=0

	nodemap_acl_test_setup
	sleep 5

	do_node $set_client $RUNAS_USER touch $testfile
	# remove from cache, otherwise ACLs will not be fetched from server
	do_rpc_nodes $set_client cancel_lru_locks
	do_node $set_client "sync ; echo 3 > /proc/sys/vm/drop_caches"

	# ACL masks aren't filtered by nodemap code, so we ignore them
	acl_count=$(do_node $get_client getfacl $testfile | grep -v mask |
		wc -l)
	# remove from cache, otherwise ACLs will not be fetched from server
	do_rpc_nodes $get_client cancel_lru_locks
	do_node $get_client "sync ; echo 3 > /proc/sys/vm/drop_caches"
	do_node $set_client $RUNAS_USER setfacl -m $user:rwx $testfile ||
		setfacl_error=1
	# remove from cache, otherwise ACLs will not be fetched from server
	do_rpc_nodes $set_client cancel_lru_locks
	do_node $set_client "sync ; echo 3 > /proc/sys/vm/drop_caches"

	# if check setfacl is set to 1, then it's supposed to error
	if [ "$check_setfacl" == "1" ]; then
		[ "$setfacl_error" != "1" ] && return 1
		return 0
	fi
	[ "$setfacl_error" == "1" ] && echo "WARNING: unable to setfacl"

	acl_count_post=$(do_node $get_client getfacl $testfile | grep -v mask |
		wc -l)
	# remove from cache, otherwise ACLs will not be fetched from server
	do_rpc_nodes $get_client cancel_lru_locks
	do_node $get_client "sync ; echo 3 > /proc/sys/vm/drop_caches"
	[ $acl_count -eq $acl_count_post ] && return 0
	return 1
}

test_23a() {
	[ $num_clients -lt 2 ] && skip "Need 2 clients at least" && return
	nodemap_version_check || return 0
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	# 1 trusted cluster, 1 mapped cluster
	local unmapped_fs=$((IDBASE+0))
	local unmapped_c1=$((IDBASE+5))
	local mapped_fs=$((IDBASE+2))
	local mapped_c0=$((IDBASE+4))
	local mapped_c1=$((IDBASE+6))

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 1

	do_facet mgs $LCTL nodemap_modify --name c1 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c1 --property trusted --value 0

	wait_nm_sync c1 trusted_nodemap

	# setfacl on trusted cluster to unmapped user, verify it's not seen
	nodemap_acl_test $unmapped_fs ${clients_arr[0]} ${clients_arr[1]} ||
		error "acl count (1)"

	# setfacl on trusted cluster to mapped user, verify it's seen
	nodemap_acl_test $mapped_fs ${clients_arr[0]} ${clients_arr[1]} &&
		error "acl count (2)"

	# setfacl on mapped cluster to mapped user, verify it's seen
	nodemap_acl_test $mapped_c1 ${clients_arr[1]} ${clients_arr[0]} &&
		error "acl count (3)"

	# setfacl on mapped cluster to unmapped user, verify error
	nodemap_acl_test $unmapped_fs ${clients_arr[1]} ${clients_arr[0]} 1 ||
		error "acl count (4)"

	# 2 mapped clusters
	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name c0 --property trusted --value 0

	wait_nm_sync c0 trusted_nodemap

	# setfacl to mapped user on c1, also mapped to c0, verify it's seen
	nodemap_acl_test $mapped_c1 ${clients_arr[1]} ${clients_arr[0]} &&
		error "acl count (5)"

	# setfacl to mapped user on c1, not mapped to c0, verify not seen
	nodemap_acl_test $unmapped_c1 ${clients_arr[1]} ${clients_arr[0]} ||
		error "acl count (6)"

	nodemap_test_cleanup
}
run_test 23a "test mapped regular ACLs"

test_23b() { #LU-9929
	(( num_clients >= 2 )) || skip "Need 2 clients at least"
	(( $MGS_VERSION >= $(version_code 2.10.53) )) ||
		skip "Need MGS >= 2.10.53"

	stack_trap "export SK_UNIQUE_NM=$SK_UNIQUE_NM"
	export SK_UNIQUE_NM=true
	nodemap_test_setup
	stack_trap nodemap_test_cleanup EXIT

	local testdir=$DIR/$tdir
	local fs_id=$((IDBASE+10))
	local unmapped_id
	local mapped_id
	local fs_user

	do_facet mgs $LCTL nodemap_modify --name c0 --property admin --value 1
	wait_nm_sync c0 admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name c1 --property admin --value 1
	wait_nm_sync c1 admin_nodemap
	do_facet mgs $LCTL nodemap_modify --name c1 --property trusted --value 1
	wait_nm_sync c1 trusted_nodemap

	# Add idmap $ID0:$fs_id (500:60010)
	do_facet mgs $LCTL nodemap_add_idmap --name c0 --idtype gid \
		--idmap $ID0:$fs_id ||
		error "add idmap $ID0:$fs_id to nodemap c0 failed"
	wait_nm_sync c0 idmap

	# set/getfacl default acl on client 1 (unmapped gid=500)
	do_node ${clients_arr[0]} rm -rf $testdir
	do_node ${clients_arr[0]} mkdir -p $testdir
	echo "$testdir ACLs after mkdir:"
	do_node ${clients_arr[0]} getfacl $testdir
	# Here, USER0=$(getent passwd | grep :$ID0:$ID0: | cut -d: -f1)
	do_node ${clients_arr[0]} setfacl -R -d -m group:$USER0:rwx $testdir ||
		error "setfacl $testdir on ${clients_arr[0]} failed"
	do_node ${clients_arr[0]} "sync && stat $testdir > /dev/null"
	do_node ${clients_arr[0]} \
		$LCTL set_param -t4 -n "ldlm.namespaces.*.lru_size=clear"
	echo "$testdir ACLs after setfacl, on ${clients_arr[0]}:"
	do_node ${clients_arr[0]} getfacl $testdir
	unmapped_id=$(do_node ${clients_arr[0]} getfacl $testdir |
			grep -E "default:group:.+:rwx" | awk -F: '{print $3}')
	echo unmapped_id=$unmapped_id
	(( unmapped_id == USER0 )) ||
		error "gid=$ID0 was not unmapped correctly on ${clients_arr[0]}"

	# getfacl default acl on client 2 (mapped gid=60010)
	do_node ${clients_arr[1]} \
		$LCTL set_param -t4 -n "ldlm.namespaces.*.lru_size=clear"
	do_node ${clients_arr[1]} "sync && stat $testdir > /dev/null"
	echo "$testdir ACLs after setfacl, on ${clients_arr[1]}:"
	do_node ${clients_arr[1]} getfacl $testdir
	mapped_id=$(do_node ${clients_arr[1]} getfacl $testdir |
			grep -E "default:group:.+:rwx" | awk -F: '{print $3}')
	echo mapped_id=$mapped_id
	[[ -n "$mapped_id" ]] || error "mapped_id empty"
	fs_user=$(do_node ${clients_arr[1]} getent passwd |
			grep :$fs_id:$fs_id: | cut -d: -f1)
	[[ -n "$fs_user" ]] || fs_user=$fs_id
	echo fs_user=$fs_user
	(( mapped_id == fs_id || mapped_id == fs_user )) ||
		error "Should return user $fs_user id $fs_id on client2"
}
run_test 23b "test mapped default ACLs"

test_24() {
	nodemap_test_setup

	trap nodemap_test_cleanup EXIT
	do_nodes $(comma_list $(all_server_nodes)) $LCTL get_param -R nodemap

	nodemap_test_cleanup
}
run_test 24 "check nodemap proc files for LBUGs and Oopses"

test_25() {
	local tmpfile=$(mktemp)
	local tmpfile2=$(mktemp)
	local tmpfile3=$(mktemp)
	local tmpfile4=$(mktemp)
	local subdir=c0dir
	local client

	nodemap_version_check || return 0

	# stop clients for this test
	zconf_umount_clients $CLIENTS $MOUNT ||
	    error "unable to umount clients $CLIENTS"

	export SK_UNIQUE_NM=true
	nodemap_test_setup

	# enable trusted/admin for setquota call in cleanup_and_setup_lustre()
	i=0
	for client in $clients; do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			--property trusted --value 1
		((i++))
	done
	wait_nm_sync c$((i - 1)) trusted_nodemap

	trap nodemap_test_cleanup EXIT

	# create a new, empty nodemap, and add fileset info to it
	do_facet mgs $LCTL nodemap_add test25 ||
		error "unable to create nodemap $testname"
	do_facet mgs $LCTL set_param -P nodemap.$testname.fileset=/$subdir ||
		error "unable to add fileset info to nodemap test25"

	wait_nm_sync test25 id

	do_facet mgs $LCTL $nodemap_info > $tmpfile
	do_facet mds $LCTL $nodemap_info > $tmpfile2

	if ! $SHARED_KEY; then
		# will conflict with SK's nodemaps
		cleanup_and_setup_lustre
	fi
	# stop clients for this test
	zconf_umount_clients $CLIENTS $MOUNT ||
	    error "unable to umount clients $CLIENTS"

	do_facet mgs $LCTL $nodemap_info > $tmpfile3
	diff -q $tmpfile3 $tmpfile >& /dev/null ||
		error "$nodemap_info diff on MGS after remount"

	do_facet mds $LCTL $nodemap_info > $tmpfile4
	diff -q $tmpfile4 $tmpfile2 >& /dev/null ||
		error "$nodemap_info diff on MDS after remount"

	# cleanup nodemap
	do_facet mgs $LCTL nodemap_del test25 ||
	    error "cannot delete nodemap test25 from config"
	nodemap_test_cleanup
	# restart clients previously stopped
	zconf_mount_clients $CLIENTS $MOUNT ||
	    error "unable to mount clients $CLIENTS"

	rm -f $tmpfile $tmpfile2
	export SK_UNIQUE_NM=false
}
run_test 25 "test save and reload nodemap config"

test_25a() {
	local nm="c0"
	local info_dump=$(mktemp)
	local param_dump=$(mktemp)

	(( $MGS_VERSION >= $(version_code 2.16.52) )) ||
		skip "Need MGS >= 2.16.52 for updated nodemap_info"

	nodemap_test_setup
	stack_trap nodemap_test_cleanup EXIT

	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
	fi

	# fill some more values on nodemap
	# We test only local here, so no wait_nm_sync required
	do_facet mgs $LCTL nodemap_add_offset --name $nm \
		--offset 1000000 --limit 100000 ||
		error "cannot set offset $nm"
	do_facet mgs $LCTL nodemap_set_fileset --name $nm \
		--fileset "/somedir" ||
		error "unable to add fileset info"

	# full nodemap dump
	do_facet mgs $LCTL $nodemap_info > $info_dump ||
		error "$nodemap_info failed"
	stack_trap "rm -f $info_dump" EXIT
	do_facet mgs $LCTL get_param -R nodemap > $param_dump
	stack_trap "rm -f $param_dump" EXIT

	diff -q $info_dump $param_dump >& /dev/null ||
		error "$nodemap_info differs from get_param output"

	# nodemap dump for $nm
	do_facet mgs $LCTL $nodemap_info --name $nm > $info_dump ||
		error "$nodemap_info failed"
	do_facet mgs $LCTL get_param -R nodemap.$nm > $param_dump

	diff -q $info_dump $param_dump >& /dev/null ||
		error "$nodemap_info differs from get_param output"

	# nodemap dump for $nm and property fileset
	do_facet mgs $LCTL $nodemap_info --name $nm \
		--property fileset > $info_dump ||
		error "$nodemap_info failed"
	do_facet mgs $LCTL get_param nodemap.$nm.fileset > $param_dump

	diff -q $info_dump $param_dump >& /dev/null ||
		error "$nodemap_info differs from get_param output"

	# cross nodemap dump for property ranges
	do_facet mgs $LCTL $nodemap_info --property ranges > $info_dump ||
		error "$nodemap_info failed"
	do_facet mgs $LCTL get_param -R nodemap.*.ranges > $param_dump

	# back to non-nodemap setup
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=false
	fi
}
run_test 25a "test nodemap info values"

test_26() {
	nodemap_version_check || return 0

	local large_i=32000

	do_facet mgs "seq -f 'c%g' $large_i | xargs -n1 $LCTL nodemap_add"
	wait_nm_sync c$large_i admin_nodemap

	do_facet mgs "seq -f 'c%g' $large_i | xargs -n1 $LCTL nodemap_del"
	wait_nm_sync c$large_i admin_nodemap
}
run_test 26 "test transferring very large nodemap"

nodemap_exercise_fileset_cleanup() {
	# Already mounted clients are skipped in zconf_mount_clients()
	for client in "${clients_arr[@]}"; do
		zconf_mount_clients $client $MOUNT $MOUNT_OPTS ||
			error "unable to mount client $client"
	done
}

nodemap_exercise_fileset() {
	local have_persistent_fset_cmd
	local check_proj=true
	local loop=0
	local nm="$1"
	local subdir="subdir_${nm}"
	local subsubdir="subsubdir_${nm}"

	(( $MDS1_VERSION >= $(version_code 2.14.52) )) || check_proj=false

	# when "have_persistent_fset_cmd" is true, "lctl nodemap_set_fileset"
	# is persistent, otherwise "lctl set_param -P" must be used
	have_persistent_fset_cmd=false
	if (( $MGS_VERSION >= $(version_code 2.16.51) )); then
		have_persistent_fset_cmd=true
		subdir="thisisaverylongsubdirtotestlongfilesetsandtotestmultiplefilesetfragmentsonthenodemapiam_${nm}"
	fi

	# setup
	if [[ "$nm" == "default" ]]; then
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
		do_facet mgs $LCTL nodemap_modify --name default \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name default \
			--property trusted --value 1
		wait_nm_sync default trusted_nodemap
		check_proj=false
	else
		nodemap_test_setup
	fi
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
	else
		# will conflict with SK's nodemaps
		trap "fileset_test_cleanup $nm" EXIT
	fi
	fileset_test_setup "$nm"

	# add fileset info to $nm nodemap
	if $have_persistent_fset_cmd; then
		do_facet mgs $LCTL nodemap_set_fileset --name $nm \
			--fileset "/${subdir}" ||
			error "can't set fileset to $nm nodemap on MGS"
		# check fileset is set on local mgs node
		wait_update_facet mgs "$LCTL get_param nodemap.${nm}.fileset" \
				"nodemap.${nm}.fileset=/${subdir}" ||
			error "fileset /${subdir} not set on $nm nodemap"
	else
		if ! combined_mgs_mds; then
			do_facet mgs $LCTL set_param \
				nodemap.${nm}.fileset=/${subdir} ||
				error "can't set fileset /${subdir} to $nm nodemap on MGS"
		fi
		do_facet mgs $LCTL set_param -P \
			nodemap.${nm}.fileset=/${subdir} ||
			error "can't set fileset /${subdir} to $nm nodemap on servers"
	fi

	# check fileset is set on remote nodes
	wait_nm_sync $nm fileset "nodemap.${nm}.fileset=/${subdir}"

	if $check_proj; then
		do_facet mgs $LCTL nodemap_modify --name $nm \
			 --property admin --value 1
		wait_nm_sync $nm admin_nodemap
		do_facet mgs $LCTL nodemap_modify --name $nm \
			 --property trusted --value 0
		wait_nm_sync $nm trusted_nodemap
		do_facet mgs $LCTL nodemap_modify --name $nm \
			 --property map_mode --value projid
		wait_nm_sync $nm map_mode
		do_facet mgs $LCTL nodemap_add_idmap --name $nm \
			 --idtype projid --idmap 1:1
		do_facet mgs $LCTL nodemap_modify --name $nm \
			 --property deny_unknown --value 1
		wait_nm_sync $nm deny_unknown
	fi

	# re-start all components to verify persistence of fileset after restart
	stopall || error "unable to stop"
	# Unload modules to fully reload nodemap IAM
	LOAD_MODULES_REMOTE=true unload_modules ||
		error "unable to unload modules"
	LOAD_MODULES_REMOTE=true load_modules ||
		error "unable to load modules"
	mountmgs || error "unable to start mgs"
	mountmds || error "unable to start mds"
	mountoss || error "unable to start oss"

	stack_trap nodemap_exercise_fileset_cleanup EXIT

	# mount a single client for fileset testing and remount
	# the remaining clients later.
	# set some generic fileset to trigger SSK code
	export FILESET=/
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"
	unset FILESET

	# test mount point content
	do_node ${clients_arr[0]} test -f $MOUNT/this_is_$subdir ||
		error "fileset not taken into account"

	if $check_proj; then
		do_node ${clients_arr[0]} $LFS setquota -p 1 -b 10000 -B 11000 \
			-i 0 -I 0 $MOUNT || error "setquota -p 1 failed"
		do_node ${clients_arr[0]} $LFS setquota -p 2 -b 10000 -B 11000 \
			-i 0 -I 0 $MOUNT && error "setquota -p 2 should fail"
	fi

	# re-mount client with sub-subdir
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	export FILESET=/$subsubdir
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"
	unset FILESET

	# test mount point content
	do_node ${clients_arr[0]} test -f $MOUNT/this_is_$subsubdir ||
		error "subdir of fileset not taken into account"

	# remove fileset info from nodemap
	do_facet mgs $LCTL nodemap_set_fileset --name $nm --fileset clear ||
		error "unable to delete fileset info on $nm nodemap"
	# check whether fileset was removed on mgs
	wait_update_facet mgs "$LCTL get_param nodemap.${nm}.fileset" \
			  "nodemap.${nm}.fileset=" ||
		error "fileset info still not cleared on $nm nodemap"
	if ! $have_persistent_fset_cmd; then
		do_facet mgs $LCTL set_param -P nodemap.${nm}.fileset=clear ||
		error "unable to reset fileset info on $nm nodemap"
	fi

	# check whether fileset was removed on remote nodes
	wait_nm_sync $nm fileset "nodemap.${nm}.fileset="
	if ! $have_persistent_fset_cmd; then
		do_facet mgs $LCTL set_param -P -d nodemap.${nm}.fileset ||
			error "unable to remove fileset rule on $nm nodemap"
	fi

	# re-mount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount client ${clients_arr[0]}"
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "unable to remount client ${clients_arr[0]}"

	# test mount point content
	if ! $(do_node ${clients_arr[0]} test -d $MOUNT/$subdir); then
		ls $MOUNT
		error "fileset not cleared on $nm nodemap"
	fi

	# back to non-nodemap setup
	if $SHARED_KEY; then
		export SK_UNIQUE_NM=false
		zconf_umount_clients ${clients_arr[0]} $MOUNT ||
			error "unable to umount client ${clients_arr[0]}"
	fi
	fileset_test_cleanup "$nm"
	if [[ "$nm" == "default" ]]; then
		do_facet mgs $LCTL nodemap_modify --name default \
			 --property admin --value 0
		do_facet mgs $LCTL nodemap_modify --name default \
			 --property trusted --value 0
		wait_nm_sync default trusted_nodemap
		do_facet mgs $LCTL nodemap_activate 0
		wait_nm_sync active 0
		trap 0
		export SK_UNIQUE_NM=false
	else
		nodemap_test_cleanup
	fi
	# The fileset cleanup trap is reset during nodemap clean up.
	# Call fileset cleanup to restart all shut down clients
	nodemap_exercise_fileset_cleanup
}

test_27a() {
	(( $MDS1_VERSION < $(version_code 2.11.50) )) &&
		skip "Need MDS >= 2.11.50"

	# if servers run on the same node, it is impossible to tell if they get
	# synced with the mgs, so this test needs to be skipped
	if [[ $(facet_active_host mgs) == $(facet_active_host mds) ]] &&
	   [[ $(facet_active_host mgs) == $(facet_active_host ost1) ]]; then
		skip "local mode not supported"
	fi

	for nm in "default" "c0"; do
		if [[ "$nm" == "default" && "$SHARED_KEY" == "true" ]]; then
			echo "Skipping nodemap $nm with SHARED_KEY"
			continue
		fi

		echo "Exercising fileset for nodemap $nm"
		nodemap_exercise_fileset "$nm"
	done
}
run_test 27a "test fileset in various nodemaps"

test_27aa() { #LU-17922
	local idmap
	local id=500

	(( $MDS1_VERSION >= $(version_code v2_15_64-86-g8445f7b92f) )) ||
		skip "need MDS >= 2.15.64.86 for nodemap range"

	do_facet mgs $LCTL nodemap_add Test17922 ||
		error "unable to add Test17922 as nodemap"
	stack_trap "do_facet mgs $LCTL nodemap_del Test17922 || true"

	do_facet mgs $LCTL nodemap_add_idmap --name Test17922 \
		 --idtype uid --idmap 500-509:10000-10009 ||
		 error "unable to add idmap range 500-509:10000-10009"

	idmap=$(do_facet mgs $LCTL get_param nodemap.Test17922.idmap | grep idtype)
	while IFS= read -r idmap; do
		if (( $id <= 509 )); then
			[[ "$idmap" == *"client_id: $id"* ]] ||
				error "could not find 'client_id: ${id}' inside of ${idmap}"
		fi
		((id++))
	done < <(echo "$idmap")

	do_facet mgs $LCTL nodemap_del_idmap --name Test17922 \
		 --idtype uid --idmap 505-509:10005 ||
			error "cannot delete idmap range 505-509:10005"

	id=500
	idmap=$(do_facet mgs $LCTL get_param nodemap.Test17922.idmap | grep idtype)
	while IFS= read -r idmap; do
		if (( $id <= 504 )); then
			[[ "$idmap" == *"client_id: $id"* ]] ||
				error "could not find 'client_id: ${id}' inside of ${idmap}"
		else
			[[ "$idmap" =~ "client_id: $id" ]] &&
				error "found 'client_id: $id' in $idmap"
		fi
		((id++))
	done < <(echo "$idmap")

	do_facet mgs $LCTL nodemap_del_idmap --name Test17922 \
		 --idtype uid --idmap 500-504:10000

	#expected error, invalid secondary range supplied
	do_facet mgs $LCTL nodemap_add --name Test17922 \
		 --idtype uid --idmap 500-509:10000-10010 &&
		 error "Invalid range 10000-10010 was added"

	(( $(do_facet mgs $LCTL get_param nodemap.Test17922.idmap |
		grep -c idtype) == 0 )) ||
		error "invalid range 10000-10010 supplied and passed"

	do_facet mgs $LCTL nodemap_del Test17922 ||
		error "failed to remove nodemap Test17922"
}
run_test 27aa "test nodemap idmap range"

test_27ab() { #LU-18109
	local offset_start=100000
	local offset_limit=200000
	local nid=1.1.1.1@tcp777
	local activedefault
	local nm1=Test18109
	local nm2=OffsetTest
	local squash=65534
	local id_start=500
	local expected
	local id=500
	local idmap
	local offset

	(( MDS1_VERSION > $(version_code 2.16.50.170) )) ||
		skip "need MDS > 2.16.50.170 for nodemap range offset"

	do_facet mgs $LCTL nodemap_add $nm1 ||
		error "unable to add $nm1 as nodemap"
	stack_trap "do_facet mgs $LCTL nodemap_del $nm1 || true"

	do_facet mgs $LCTL nodemap_add $nm2 ||
		error "unable to add $nm2 as nodemap"
	stack_trap "do_facet mgs $LCTL nodemap_del $nm2 || true"

	do_facet mgs $LCTL nodemap_add_offset --name $nm1 \
		--offset $offset_start --limit $offset_limit ||
			error "cannot set offset $offset_start-$((offset_start+offset_limit-1)) for $nm1"

	#expected error, invalid offset range supplied
	do_facet mgs $LCTL nodemap_add_offset --name $nm2 \
		--offset $((offset_start+50000)) --limit 100000 &&
			error "setting offset $((offset_start+50000))-249999 on $nm2 should fail"

	do_facet mgs $LCTL nodemap_add_idmap --name $nm1 \
		 --idtype uid --idmap 500-509:0-9 ||
		 error "unable to add idmap range 500-509:0-9"

	idmap=$(do_facet mgs $LCTL get_param nodemap.$nm1.idmap |
		grep idtype)
	while IFS= read -r idmap; do
		if (( $id <= 509 )); then
			[[ "$idmap" == *"client_id: $id"* ]] ||
				error "could not find 'client_id: ${id}' inside of ${idmap}"
		fi
		((id++))
	done < <(echo "$idmap")

	do_facet mgs $LCTL nodemap_add_range --name $nm1 --range $nid ||
		error "Add range $nid to $nm1 failed"
	do_facet mgs $LCTL nodemap_modify --name $nm1 \
		--property admin --value 1 ||
		error "Setting admin=1 on $nm1 failed"
	do_facet mgs $LCTL nodemap_modify --name $nm1 \
		--property trusted --value 1 ||
		error "Setting trusted=1 on $nm1 failed"
	do_facet mgs $LCTL nodemap_modify --name $nm1 \
		--property squash_uid --value $squash ||
		error "Setting squash_uid=$squash on $nm1 failed"
	do_facet mgs $LCTL nodemap_modify --name $nm1 \
		--property squash_gid --value $squash ||
		error "Setting squash_gid=$squash on $nm1 failed"

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)
	if ((activedefault != 1)); then
		do_facet mgs $LCTL nodemap_modify --name default \
			--property trusted --value 1
		do_facet mgs $LCTL nodemap_modify --name default \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
		stack_trap cleanup_active EXIT
	fi

	if (( MDS1_VERSION >= $(version_code 2.16.51.45) )); then
		# with admin=1, we expect root to be offset
		id=0
		expected=$offset_start
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"
		# with trusted=1, we expect ids to be offset
		id=$((id_start+1))
		expected=$((offset_start+id_start+1))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"

		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property trusted --value 0 ||
			error "Setting trusted=0 on $nm1 failed"

		# with trusted=0, we expect uid to be mapped+offset,
		# gid to be squashed+offset
		expected=$((offset_start+1))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		expected=$((offset_start+squash))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"

		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property admin --value 0 ||
			error "Setting admin=0 on $nm1 failed"

		# with admin=0, we expect root to be squashed+offset
		id=0
		expected=$((offset_start+squash))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"

		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property admin --value 1 ||
			error "Setting admin=1 on $nm1 failed"
		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property trusted --value 1 ||
			error "Setting trusted=1 on $nm1 failed"
	fi

	do_facet mgs $LCTL nodemap_del_idmap --name $nm1 \
		 --idtype uid --idmap 500-509:0 ||
			error "cannot delete idmap range 500-509:0"

	#expected error, invalid secondary range supplied
	do_facet mgs $LCTL nodemap_add_idmap --name $nm1 \
		 --idtype uid --idmap 500-509:200000-200010 &&
		 error "Invalid range 200000-200010 was supplied"

	(( $(do_facet mgs $LCTL get_param nodemap.$nm1.idmap |
		grep -c idtype) == 0 )) ||
		error "invalid range 200000-200010 supplied and passed"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep start_uid)
	[[ "$offset" == *"start_uid: $offset_start"* ]] ||
		error "expected start_uid of $offset_start not found before remounting"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep limit_uid)
	[[ "$offset" == *"limit_uid: $offset_limit"* ]] ||
		error "expected limit_uid of $offset_limit not found before remounting"

	if (( MDS1_VERSION >= $(version_code 2.16.51.45) )); then
		# with admin=1, we expect root to be offset
		id=0
		expected=$offset_start
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"
		# with trusted=1, we expect ids to be offset
		id=$((id_start+1))
		expected=$((offset_start+id_start+1))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"

		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property trusted --value 0 ||
			error "Setting trusted=0 on $nm1 failed"

		# with trusted=0, we expect uid to be squashed+offset
		expected=$((offset_start+squash))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"

		do_facet mgs $LCTL nodemap_modify --name $nm1 \
			--property admin --value 0 ||
			error "Setting admin=0 on $nm1 failed"

		# with admin=0, we expect root to be squashed+offset
		id=0
		expected=$((offset_start+squash))
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype uid --id $id)
		((idmap == expected)) ||
			error "uid $id should be mapped to $expected"
		idmap=$(do_facet mgs $LCTL nodemap_test_id --nid $nid \
			--idtype gid --id $id)
		((idmap == expected)) ||
			error "gid $id should be mapped to $expected"
	fi

	stopall || error "failed to unmount servers"
	setupall || error "failed to remount servers"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep start_uid)
	[[ "$offset" == *"start_uid: $offset_start"* ]] ||
		error "expected start_uid of $offset_start not found after remounting"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep limit_uid)
	[[ "$offset" == *"limit_uid: $offset_limit"* ]] ||
		error "expected limit_uid of $offset_limit not found after remounting"

	do_facet mgs $LCTL nodemap_del_offset --name $nm1 ||
		error "cannot del offset from $nm1"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep start_uid)
	[[ "$offset" == *"start_uid: 0"* ]] ||
		error "expected start_uid 0, found $offset"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep limit_uid)
	[[ "$offset" == *"limit_uid: 0"* ]] ||
		error "expected limit_uid 0, found $offset"

	stopall || error "failed to unmount servers"
	setupall || error "failed to remount servers"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep start_uid)
	[[ "$offset" == *"start_uid: 0"* ]] ||
		error "expected start_uid 0, found $offset after remounting"

	offset=$(do_facet mgs $LCTL get_param nodemap.$nm1.offset |
		 grep limit_uid)
	[[ "$offset" == *"limit_uid: 0"* ]] ||
		error "expected limit_uid 0, found $offset after remounting"

	do_facet mgs $LCTL nodemap_del $nm1 ||
		error "failed to remove nodemap $nm1"

	do_facet mgs $LCTL nodemap_del $nm2 ||
		error "failed to remove nodemap $nm2"
}
run_test 27ab "test nodemap idmap offset"

test_27b() { #LU-10703
	[ "$MDS1_VERSION" -lt $(version_code 2.11.50) ] &&
		skip "Need MDS >= 2.11.50"
	[[ $MDSCOUNT -lt 2 ]] && skip "needs >= 2 MDTs"

	# if servers run on the same node, it is impossible to tell if they get
	# synced with the mgs, so this test needs to be skipped
	if [ $(facet_active_host mgs) == $(facet_active_host mds) ] &&
	   [ $(facet_active_host mgs) == $(facet_active_host ost1) ]; then
		skip "local mode not supported"
	fi

	nodemap_test_setup
	trap nodemap_test_cleanup EXIT

	# Add the nodemaps and set their filesets
	for i in $(seq 1 $MDSCOUNT); do
		do_facet mgs $LCTL nodemap_del nm$i 2>/dev/null
		do_facet mgs $LCTL nodemap_add nm$i ||
			error "add nodemap nm$i failed"
		wait_nm_sync nm$i "" "" "-N"

		if ! combined_mgs_mds; then
			do_facet mgs \
				$LCTL set_param nodemap.nm$i.fileset=/dir$i ||
				error "set nm$i.fileset=/dir$i failed on MGS"
		fi
		do_facet mgs $LCTL set_param -P nodemap.nm$i.fileset=/dir$i ||
			error "set nm$i.fileset=/dir$i failed on servers"
		wait_nm_sync nm$i fileset "nodemap.nm$i.fileset=/dir$i"
	done

	# Check if all the filesets are correct
	for i in $(seq 1 $MDSCOUNT); do
		fileset=$(do_facet mds$i \
			  $LCTL get_param -n nodemap.nm$i.fileset)
		[ "$fileset" = "/dir$i" ] ||
			error "nm$i.fileset $fileset != /dir$i on mds$i"
		do_facet mgs $LCTL set_param -P -d nodemap.nm$i.fileset ||
			error "unable to remove fileset rule for nm$i nodemap"
		do_facet mgs $LCTL nodemap_del nm$i ||
			error "delete nodemap nm$i failed"
	done

	nodemap_test_cleanup
}
run_test 27b "The new nodemap won't clear the old nodemap's fileset"

test_28() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	mkdir -p $DIR/$tdir || error "mkdir failed"
	touch $DIR/$tdir/$tdir.out || error "touch failed"
	if [ ! -f $DIR/$tdir/$tdir.out ]; then
		error "read before rotation failed"
	fi
	# check srpc_contexts is valid YAML
	$LCTL get_param -n *.*.srpc_contexts 2>/dev/null | verify_yaml ||
		error "srpc_contexts is not valid YAML"
	# store top key identity to ensure rotation has occurred
	SK_IDENTITY_OLD=$($LCTL get_param -n *.*.srpc_contexts 2>/dev/null |
		       head -n 1 | awk 'BEGIN{RS=", "} $1=="expire:"{print $2}')
	do_facet $SINGLEMDS lfs flushctx ||
		 error "could not run flushctx on $SINGLEMDS"
	sleep 5
	lfs flushctx || error "could not run flushctx on client"
	sleep 5
	# verify new key is in place
	SK_IDENTITY_NEW=$($LCTL get_param -n *.*.srpc_contexts 2>/dev/null |
		       head -n 1 | awk 'BEGIN{RS=", "} $1=="expire:"{print $2}')
	if [ $SK_IDENTITY_OLD == $SK_IDENTITY_NEW ]; then
		error "key did not rotate correctly"
	fi
	if [ ! -f $DIR/$tdir/$tdir.out ]; then
		error "read after rotation failed"
	fi
}
run_test 28 "check shared key rotation method"

test_29() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	if [ $SK_FLAVOR != "ski" ] && [ $SK_FLAVOR != "skpi" ]; then
		skip "test only valid if integrity is active"
	fi
	rm -r $DIR/$tdir
	mkdir $DIR/$tdir || error "mkdir"
	touch $DIR/$tdir/$tfile || error "touch"
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=/dev/null
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		export SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "ls $DIR/$tdir/$tfile"
		if [ $? -eq 0 ]; then
			error "able to mount and read without key"
		else
			error "able to mount without key"
		fi
	else
		export SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "keyctl show |
			awk '/lustre/ { print \\\$1 }' |
			xargs -IX keyctl unlink X"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to mount clients"
}
run_test 29 "check for missing shared key"

test_30() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test" && return
	fi
	if [ $SK_FLAVOR != "ski" ] && [ $SK_FLAVOR != "skpi" ]; then
		skip "test only valid if integrity is active"
	fi
	mkdir -p $DIR/$tdir || error "mkdir failed"
	touch $DIR/$tdir/$tdir.out || error "touch failed"
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	# unload keys from ring
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	# generate key with bogus filesystem name
	do_node ${clients_arr[0]} "$LGSS_SK -w $SK_PATH/$FSNAME-bogus.key \
		-f $FSNAME.bogus -t client -d /dev/urandom" ||
		error "lgss_sk failed (1)"
	do_facet $SINGLEMDS lfs flushctx || error "could not run flushctx"
	OLD_SK_PATH=$SK_PATH
	export SK_PATH=$SK_PATH/$FSNAME-bogus.key
	if zconf_mount_clients ${clients_arr[0]} $MOUNT; then
		SK_PATH=$OLD_SK_PATH
		do_node ${clients_arr[0]} "ls $DIR/$tdir/$tdir.out"
		if [ $? -eq 0 ]; then
			error "mount and read file with invalid key"
		else
			error "mount with invalid key"
		fi
	fi
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to umount clients"
	# unload keys from ring
	do_node ${clients_arr[0]} "keyctl show |
		awk '/lustre/ { print \\\$1 }' | xargs -IX keyctl unlink X"
	rm -f $SK_PATH
	SK_PATH=$OLD_SK_PATH
	zconf_mount_clients ${clients_arr[0]} $MOUNT ||
		error "unable to mount clients"
}
run_test 30 "check for invalid shared key"

basic_ios() {
	local flvr=$1

	mkdir -p $DIR/$tdir/dir0 || error "mkdir $flvr"
	touch $DIR/$tdir/dir0/f0 || error "touch $flvr"
	ls $DIR/$tdir/dir0 || error "ls $flvr"
	dd if=/dev/zero of=$DIR/$tdir/dir0/f0 conv=fsync bs=1M count=10 \
		>& /dev/null || error "dd $flvr"
	rm -f $DIR/$tdir/dir0/f0 || error "rm $flvr"
	rmdir $DIR/$tdir/dir0 || error "rmdir $flvr"

	sync ; sync
	echo 3 > /proc/sys/vm/drop_caches
}

cleanup_30b() {
	# restore clients' idle_timeout
	for c in ${clients//,/ }; do
		param=IDLETIME_$(echo $c | cut -d'.' -f1 | sed s+-+_+g)
		do_node $c "lctl set_param osc.*.idle_timeout=${!param}"
	done
}

test_30b() {
	local save_flvr=$SK_FLAVOR

	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	# save clients' idle_timeout, and set all to 0 for this test,
	# as we do not want connections to go idle
	for c in ${clients//,/ }; do
		param=IDLETIME_$(echo $c | cut -d'.' -f1 | sed s+-+_+g)
		idle=$(do_node $c lctl get_param -n osc.*.idle_timeout |
			head -n1)
		eval export $param=\$idle
		do_node $c lctl set_param osc.*.idle_timeout=0
	done

	stack_trap cleanup_30b EXIT
	stack_trap restore_to_default_flavor EXIT

	lfs mkdir -i 0 -c 1 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	lfs setstripe -c -1 $DIR/$tdir/fileA ||
		error "setstripe $DIR/$tdir/fileA failed"
	echo 30b > $DIR/$tdir/fileA ||
		error "wrtie to $DIR/$tdir/fileA failed"

	for flvr in skn ska ski skpi; do
		# set flavor
		SK_FLAVOR=$flvr
		restore_to_default_flavor || error "cannot set $flvr flavor"
		SK_FLAVOR=$save_flvr

		basic_ios $flvr
	done
}
run_test 30b "basic test of all different SSK flavors"

cleanup_31() {
	local failover_mds1=$1

	# unmount client
	zconf_umount $HOSTNAME $MOUNT || error "unable to umount client"

	# necessary to do writeconf in order to de-register
	# @${NETTYPE}999 nid for targets
	KZPOOL=$KEEP_ZPOOL
	export KEEP_ZPOOL="true"
	stopall
	LOAD_MODULES_REMOTE=true unload_modules
	LOAD_MODULES_REMOTE=true load_modules

	# restore mgsnid on targets
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		do_facet mds$num $TUNEFS --erase-param mgsnode \
			$(mdsdevname $num)
		do_facet mds$num $TUNEFS --mgsnode=$MGSNID $(mdsdevname $num)
	done
	for ((num = 1; num <= $OSTCOUNT; num++)); do
		do_facet ost$num $TUNEFS --erase-param mgsnode \
			$(ostdevname $num)
		do_facet ost$num $TUNEFS --mgsnode=$MGSNID $(ostdevname $num)
	done

	do_facet mds1 $TUNEFS --erase-param failover.node $(mdsdevname 1)
	if [ -n "$failover_mds1" ]; then
		do_facet mds1 $TUNEFS \
			--servicenode=$failover_mds1 $(mdsdevname 1)
	else
		# If no service node previously existed, setting one in test_31
		# added the no_primnode flag to the target. To remove everything
		# and clear the flag, add a meaningless failnode and remove it.
		do_facet mds1 $TUNEFS \
			--failnode=$(do_facet mds1 $LCTL list_nids | head -1) \
			$(mdsdevname 1)
		do_facet mds1 $TUNEFS \
			--erase-param failover.node $(mdsdevname 1)
	fi

	export SK_MOUNTED=false
	writeconf_all
	setupall || echo 1
	export KEEP_ZPOOL="$KZPOOL"
}

test_31() {
	local nid=$(lctl list_nids | grep ${NETTYPE} | head -n1)
	local addr=${nid%@*}
	local net=${nid#*@}
	local net2=${NETTYPE}999
	local mdsnid=$(do_facet mds1 $LCTL list_nids | head -1)
	local addr1=${mdsnid%@*}
	local nid2=${addr}@$net2
	local addr2 failover_mds1
	local all=$(comma_list $(all_nodes))

	export LNETCTL=$(which lnetctl 2> /dev/null)

	(( $MDS1_VERSION >= $(version_code 2.15.0) )) ||
		skip "Need MDS >= 2.15.0"
	[ -z "$LNETCTL" ] && skip "without lnetctl support." && return
	local_mode && skip "in local mode."

	if $SHARED_KEY; then
		skip "Conflicting test with SSK"
	fi

	if [[ $addr1 =~ ^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$ ]]; then
		local tmp=$(printf "%x" $(((0x${addr1##*:} + 11) % 65536)))

		addr2=${addr1%:*}:${tmp}
	elif [[ $addr1 =~ ^([0-9]{1,3}\.){3,3}[0-9]{1,3}$ ]]; then
		addr2=${addr1%.*}.$(((${addr1##*.} + 11) % 256))
	elif [[ $addr1 =~ ^[0-9]+$ ]]; then
		addr2=$((addr1 + 11))
	fi

	# build list of interface on nodes
	for node in ${all//,/ }; do
		infname=inf_$(echo $node | cut -d'.' -f1 | sed s+-+_+g)
		itf=$(do_node $node $LNETCTL net show --net $net |
		      awk 'BEGIN{inf=0} \
		      {if (inf==1) { print $2; exit; } fi} /interfaces/{inf=1}')
		eval $infname=\$itf
	done

	# backup MGSNID
	local mgsnid_orig=$MGSNID
	# compute new MGSNID
	local mgsnid_new=${MGSNID%@*}@$net2
	local tgts=$(tgts_nodes)

	# save mds failover nids for restore at cleanup
	failover_mds1=$(do_facet mds1 $TUNEFS --dryrun $(mdsdevname 1))
	if [ -n "$failover_mds1" ]; then
		failover_mds1=${failover_mds1##*Parameters:}
		failover_mds1=${failover_mds1%%exiting*}
		failover_mds1=$(echo $failover_mds1 | tr ' ' '\n' |
				grep failover.node | cut -d'=' -f2-)
	fi
	stack_trap "cleanup_31 $failover_mds1" EXIT

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	do_facet mgs "$LCTL set_param mgs.MGS.exports.clear=clear"
	do_nodes $tgts "$LCTL set_param *.${FSNAME}*.exports.clear=clear"

	# check exports on servers are empty for client
	wait_update_facet_cond mgs \
		"$LCTL get_param -N mgs.MGS.exports.* | grep $nid |
		cut -d'.' -f4-" '!=' $nid
	for node in ${tgts//,/ }; do
		wait_update_cond $node \
			"$LCTL get_param -N *.${FSNAME}*.exports.* | grep $nid |
			cut -d'.' -f4-" '!=' $nid
	done
	do_facet mgs "$LCTL get_param *.MGS*.exports.*.export"
	do_facet mgs "$LCTL get_param -n *.MGS*.exports.'$nid'.uuid 2>/dev/null|
		      grep -q -" && error "export on MGS should be empty"
	do_nodes $tgts "$LCTL get_param -n *.${FSNAME}*.exports.'$nid'.uuid \
			 2>/dev/null | grep -q -" &&
		error "export on servers should be empty"

	KZPOOL=$KEEP_ZPOOL
	export KEEP_ZPOOL="true"
	stopall || error "stopall failed"
	LOAD_MODULES_REMOTE=true unload_modules ||
		error "Failed to unload modules"

	# add network $net2 on all nodes
	do_rpc_nodes $all load_modules || error "unable to load modules on $all"
	for node in ${all//,/ }; do
		do_node $node "$LNETCTL set discovery 0" ||
			error "Failed to disable discovery on $node"
		do_node $node "$LNETCTL lnet configure" ||
			error "unable to configure lnet on node $node"
		infname=inf_$(echo $node | cut -d'.' -f1 | sed s+-+_+g)
		do_node $node "$LNETCTL net add --if ${!infname} --net $net2" ||
			error "unable to configure NID on $net2 for node $node"
	done

	LOAD_MODULES_REMOTE=true load_modules || error "failed to load modules"

	# update MGSNID
	MGSNID=$mgsnid_orig,$mgsnid_new
	stack_trap "MGSNID=$mgsnid_orig" EXIT

	# add mgsnid on @$net2 to targets
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		do_facet mds$num $TUNEFS --erase-param mgsnode \
			$(mdsdevname $num)
		do_facet mds$num $TUNEFS --mgsnode=$MGSNID $(mdsdevname $num)
	done
	for ((num = 1; num <= $OSTCOUNT; num++)); do
		do_facet ost$num $TUNEFS --erase-param mgsnode \
			$(ostdevname $num)
		do_facet ost$num $TUNEFS --mgsnode=$MGSNID $(ostdevname $num)
	done

	# necessary to do writeconf in order to register
	# new @$net2 nid for targets
	export SK_MOUNTED=false
	writeconf_all || error "writeconf failed"

	nids="${addr1}@$net,${addr1}@$net2:${addr2}@$net,${addr2}@$net2"
	do_facet mds1 "$TUNEFS --servicenode="$nids" $(mdsdevname 1)" ||
		error "tunefs failed"

	setupall server_only || error "setupall failed"
	export KEEP_ZPOOL="$KZPOOL"

	# on client, reconfigure LNet and turn LNet Dynamic Discovery off
	$LUSTRE_RMMOD || error "$LUSTRE_RMMOD failed (1)"
	load_modules || error "Failed to load modules"
	$LNETCTL set discovery 0 || error "Failed to disable discovery"
	$LNETCTL lnet configure ||
		error "unable to configure lnet on client"
	infname=inf_$(echo $(hostname -s) | sed s+-+_+g)
	$LNETCTL net add --if ${!infname} --net $net2 ||
		error "unable to configure NID on $net2 on client (1)"

	# mount client with -o network=$net2 option
	mount_client $MOUNT ${MOUNT_OPTS},network=$net2 ||
		error "unable to remount client"

	# check export on MGS
	do_facet mgs "$LCTL get_param *.MGS*.exports.*.export"
	do_facet mgs "$LCTL get_param -n *.MGS*.exports.'$nid'.uuid 2>/dev/null|
		      grep -" &&
		error "export for $nid on MGS should not exist"

	do_facet mgs "$LCTL get_param -n *.MGS*.exports.'$nid2'.uuid"|grep - ||
		error "export for $nid2 on MGS should exist"

	# check {mdc,osc} imports
	$LCTL get_param mdc.${FSNAME}-*.import | grep current_connection |
		grep $net2 ||
		error "import for mdc should use ${addr1}@$net2"
	$LCTL get_param osc.${FSNAME}-*.import | grep current_connection |
		grep $net2 ||
		error "import for osc should use ${addr1}@$net2"

	# no NIDs on other networks should be listed
	$LCTL get_param mdc.${FSNAME}-*.import | grep failover_nids |
	    grep -w ".*@$net" &&
		error "MDC import shouldn't have failnids at @$net"

	# failover NIDs on net999 should be listed
	$LCTL get_param mdc.${FSNAME}-*.import | grep failover_nids |
	    grep ${addr2}@$net2 ||
		error "MDC import should have failnid ${addr2}@$net2"

	# unmount client
	zconf_umount $HOSTNAME $MOUNT || error "unable to umount client"

	do_facet mgs "$LCTL set_param mgs.MGS.exports.clear=clear"
	do_nodes $tgts "$LCTL set_param *.${FSNAME}*.exports.clear=clear"

	wait_update_facet_cond mgs \
		"$LCTL get_param -N mgs.MGS.exports.* | grep $nid2 |
		cut -d'.' -f4-" '!=' $nid2
	for node in ${tgts//,/ }; do
		wait_update_cond $node \
			"$LCTL get_param -N *.${FSNAME}*.exports.* | grep $nid2|
			cut -d'.' -f4-" '!=' $nid2
	done
	do_facet mgs "$LCTL get_param *.MGS*.exports.*.export"

	# on client, configure LNet and turn LNet Dynamic Discovery on (default)
	$LUSTRE_RMMOD || error "$LUSTRE_RMMOD failed (2)"
	load_modules || error "Failed to load modules"
	$LNETCTL lnet configure || error "unable to configure lnet on client"
	infname=inf_$(echo $(hostname -s) | sed s+-+_+g)
	$LNETCTL net add --if ${!infname} --net $net2 ||
		error "unable to configure NID on $net2 on client (2)"

	# mount client with -o network=$net2 option:
	# should fail because of LNet Dynamic Discovery
	mount_client $MOUNT ${MOUNT_OPTS},network=$net2 &&
		error "client mount with '-o network' option should be refused"

	# remount with '-o network' server side option
	(( $MDS1_VERSION >= $(version_code 2.16.51) )) || return 0

	KZPOOL=$KEEP_ZPOOL
	export KEEP_ZPOOL="true"
	stopall || error "stopall failed"
	mountmgs
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		start mds$num $(mdsdevname $num) $MDS_MOUNT_OPTS,network=$net2
	done
	for ((num = 1; num <= $OSTCOUNT; num++)); do
		start ost$num $(ostdevname $num) $OST_MOUNT_OPTS,network=$net2
	done
	export KEEP_ZPOOL="$KZPOOL"
	sleep 5

	# check exports on servers are empty for $net
	do_facet mgs "$LCTL get_param mgs.MGS.exports.*.export"
	wait_update_facet_cond mgs \
		"$LCTL get_param -N mgs.MGS.exports.*.export | \
		 grep ${net}.export | cut -d'@' -f2-" '!=' ${net}.export
	do_nodes $tgts "$LCTL get_param *.${FSNAME}*.exports.*.export"
	for node in ${tgts//,/ }; do
		wait_update_cond $node \
			"$LCTL get_param -N *.${FSNAME}*.exports.*.export | \
			grep ${net}.export | cut -d'@' -f2-" '!=' ${net}.export
	done

	return 0
}
run_test 31 "client mount option '-o network'"

cleanup_32() {
	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT

	# disable sk flavor enforcement on MGS
	set_rule _mgs any any null

	# stop gss daemon on MGS
	send_sigint $mgs_HOST lsvcgssd

	# re-start gss daemon on MDS if necessary
	if combined_mgs_mds ; then
		start_gss_daemons $mds_HOST $LSVCGSSD "-vvv -s -m -o -z"
	fi

	# restore MGS NIDs in key on MGS
	do_nodes $mgs_HOST "$LGSS_SK -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS (3)"

	# load modified key file on MGS
	do_nodes $mgs_HOST "$LGSS_SK -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS (3)"

	# restore MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "$LGSS_SK -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on client (3)"

	# re-mount client
	MOUNT_OPTS=$(add_sk_mntflag $MOUNT_OPTS)
	mountcli

	restore_to_default_flavor
}

test_32() {
	local mgsnid2=$(host_nids_address $ost1_HOST $NETTYPE)@${MGSNID#*@}
	local mgsorig=$MGSNID

	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	stack_trap cleanup_32 EXIT

	# restore to default null flavor
	save_flvr=$SK_FLAVOR
	SK_FLAVOR=null
	restore_to_default_flavor || error "cannot set null flavor"
	SK_FLAVOR=$save_flvr

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# kill daemon on MGS to start afresh
	send_sigint $mgs_HOST lsvcgssd

	# start gss daemon on MGS
	if combined_mgs_mds ; then
		start_gss_daemons $mgs_HOST $LSVCGSSD "-vvv -s -g -m -o -z"
	else
		start_gss_daemons $mgs_HOST $LSVCGSSD "-vvv -s -g"
	fi

	# add mgs key type and MGS NIDs in key on MGS
	do_nodes $mgs_HOST "$LGSS_SK -t mgs,server -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS (1)"

	# load modified key file on MGS
	do_nodes $mgs_HOST "$LGSS_SK -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS (1)"

	# add MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "$LGSS_SK -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on client (1)"

	# set perms for per-nodemap keys else permission denied
	do_nodes $(comma_list $(all_nodes)) \
		 "keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	stack_trap "MOUNT_OPTS=$save_opts" EXIT
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=skn failed"
	MOUNT_OPTS=$save_opts

	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "umount ${clients_arr[0]} failed"

	# enforce ska flavor on MGS
	set_rule _mgs any any ska

	# re-mount client without mgssec
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS &&
		error "mount ${clients_arr[0]} without mgssec should fail"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS &&
		error "mount ${clients_arr[0]} with mgssec=skn should fail"
	MOUNT_OPTS=$save_opts

	# re-mount client with mgssec=ska
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=ska"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=ska"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=ska failed"

	MGSNID=$mgsnid2:$mgsorig
	stack_trap "MGSNID=$mgsorig" EXIT

	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT ||
		error "umount ${clients_arr[0]} failed"

	# add MGS NIDs in key on MGS
	do_nodes $mgs_HOST "$LGSS_SK -g ${MGSNID//:/,} -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS (2)"

	# load modified key file on MGS
	do_nodes $mgs_HOST "$LGSS_SK -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS (2)"

	# add MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "$LGSS_SK -g ${MGSNID//:/,} -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on client (2)"

	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with alternate mgsnid failed"
}
run_test 32 "check for mgssec"

cleanup_33() {
	# disable sk flavor enforcement
	set_rule $FSNAME any cli2mdt null
	wait_flavor cli2mdt null

	# umount client
	zconf_umount_clients ${clients_arr[0]} $MOUNT

	# stop gss daemon on MGS
	send_sigint $mgs_HOST lsvcgssd

	# re-start gss daemon on MDS if necessary
	if combined_mgs_mds ; then
		start_gss_daemons $mds_HOST $LSVCGSSD "-vvv -s -m -o -z"
	fi

	# re-mount client
	MOUNT_OPTS=$(add_sk_mntflag $MOUNT_OPTS)
	mountcli

	restore_to_default_flavor
}

test_33() {
	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	stack_trap cleanup_33 EXIT

	# restore to default null flavor
	save_flvr=$SK_FLAVOR
	SK_FLAVOR=null
	restore_to_default_flavor || error "cannot set null flavor"
	SK_FLAVOR=$save_flvr

	# umount client
	if [ "$MOUNT_2" ] && $(grep -q $MOUNT2' ' /proc/mounts); then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if $(grep -q $MOUNT' ' /proc/mounts); then
	umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# kill daemon on MGS to start afresh
	send_sigint $mgs_HOST lsvcgssd

	# start gss daemon on MGS
	if combined_mgs_mds ; then
		start_gss_daemons $mgs_HOST $LSVCGSSD "-vvv -s -g -m -o -z"
	else
		start_gss_daemons $mgs_HOST $LSVCGSSD "-vvv -s -g"
	fi

	# add mgs key type and MGS NIDs in key on MGS
	do_nodes $mgs_HOST "$LGSS_SK -t mgs,server -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# load modified key file on MGS
	do_nodes $mgs_HOST "$LGSS_SK -l $SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not load keyfile on MGS"

	# add MGS NIDs in key on client
	do_nodes ${clients_arr[0]} "$LGSS_SK -g $MGSNID -m \
				$SK_PATH/$FSNAME.key >/dev/null 2>&1" ||
		error "could not modify keyfile on MGS"

	# set perms for per-nodemap keys else permission denied
	do_nodes $(comma_list $(all_nodes)) \
		 "keyctl show | grep lustre | cut -c1-11 |
				sed -e 's/ //g;' |
				xargs -IX keyctl setperm X 0x3f3f3f3f"

	# re-mount client with mgssec=skn
	save_opts=$MOUNT_OPTS
	if [ -z "$MOUNT_OPTS" ]; then
		MOUNT_OPTS="-o mgssec=skn"
	else
		MOUNT_OPTS="$MOUNT_OPTS,mgssec=skn"
	fi
	zconf_mount_clients ${clients_arr[0]} $MOUNT $MOUNT_OPTS ||
		error "mount ${clients_arr[0]} with mgssec=skn failed"
	MOUNT_OPTS=$save_opts

	# enforce ska flavor for cli2mdt
	set_rule $FSNAME any cli2mdt ska
	wait_flavor cli2mdt ska

	# check error message
	$LCTL dk | grep "faked source" &&
		error "MGS connection srpc flags incorrect"

	exit 0
}
run_test 33 "correct srpc flags for MGS connection"

cleanup_34_deny() {
	# restore deny_unknown
	do_facet mgs $LCTL nodemap_modify --name default \
			   --property deny_unknown --value $denydefault
	if [ $? -ne 0 ]; then
		error_noexit "cannot reset deny_unknown on default nodemap"
		return
	fi

	wait_nm_sync default deny_unknown
}

test_34() {
	local denynew
	local activedefault

	[ $MGS_VERSION -lt $(version_code 2.12.51) ] &&
		skip "deny_unknown on default nm not supported before 2.12.51"

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)

	if [[ "$activedefault" != "1" ]]; then
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
		stack_trap cleanup_active EXIT
	fi

	denydefault=$(do_facet mgs $LCTL get_param -n \
		      nodemap.default.deny_unknown)
	[ -z "$denydefault" ] &&
		error "cannot get deny_unknown on default nodemap"
	if [ "$denydefault" -eq 0 ]; then
		denynew=1;
	else
		denynew=0;
	fi

	do_facet mgs $LCTL nodemap_modify --name default \
			--property deny_unknown --value $denynew ||
		error "cannot set deny_unknown on default nodemap"

	[ "$(do_facet mgs $LCTL get_param -n nodemap.default.deny_unknown)" \
			-eq $denynew ] ||
		error "setting deny_unknown on default nodemap did not work"

	stack_trap cleanup_34_deny EXIT

	wait_nm_sync default deny_unknown
}
run_test 34 "deny_unknown on default nodemap"

test_35() {
	(( $MDS1_VERSION >= $(version_code 2.13.50) )) ||
		skip "Need MDS >= 2.13.50"

	# activate changelogs
	changelog_register || error "changelog_register failed"
	local cl_user="${CL_USERS[$SINGLEMDS]%% *}"
	changelog_users $SINGLEMDS | grep -q $cl_user ||
		error "User $cl_user not found in changelog_users"
	changelog_chmask ALL

	# do some IOs
	mkdir $DIR/$tdir || error "failed to mkdir $tdir"
	touch $DIR/$tdir/$tfile || error "failed to touch $tfile"

	# access changelogs with root
	changelog_dump || error "failed to dump changelogs"
	changelog_clear 0 || error "failed to clear changelogs"

	# put clients in non-admin nodemap
	nodemap_test_setup
	stack_trap nodemap_test_cleanup EXIT
	for i in $(seq 0 $((num_clients-1))); do
		do_facet mgs $LCTL nodemap_modify --name c${i} \
			 --property admin --value 0
	done
	for i in $(seq 0 $((num_clients-1))); do
		wait_nm_sync c${i} admin_nodemap
	done

	# access with mapped root
	changelog_dump && error "dump changelogs should have failed"
	changelog_clear 0 && error "clear changelogs should have failed"

	exit 0
}
run_test 35 "Check permissions when accessing changelogs"

setup_dummy_key() {
	local mode='\x00\x00\x00\x00'
	local raw="$(printf ""\\\\x%02x"" {0..63})"
	local size
	local key

	[[ $(lscpu) =~ Byte\ Order.*Little ]] && size='\x40\x00\x00\x00' ||
		size='\x00\x00\x00\x40'
	key="${mode}${raw}${size}"
	echo -n -e "${key}" | keyctl padd logon fscrypt:4242424242424242 @s
}

insert_enc_key() {
	cancel_lru_locks
	sync ; echo 3 > /proc/sys/vm/drop_caches
	setup_dummy_key
}

remove_enc_key() {
	local dummy_key

	$LCTL set_param -n ldlm.namespaces.*.lru_size=clear
	sync ; echo 3 > /proc/sys/vm/drop_caches
	dummy_key=$(keyctl show | awk '$7 ~ "^fscrypt:" {print $1}')
	if [ -n "$dummy_key" ]; then
		keyctl revoke $dummy_key
		keyctl reap
	fi
}

remount_client_normally() {
	# remount client without dummy encryption key
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi
	mount_client $MOUNT ${MOUNT_OPTS} ||
		error "remount failed"

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} ||
			error "remount failed"
	fi

	remove_enc_key
	wait_ssk
}

remount_client_dummykey() {
	insert_enc_key

	# remount client with dummy encryption key
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption ||
		error "remount failed"

	wait_ssk
}

setup_for_enc_tests() {
	# remount client with test_dummy_encryption option
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount with '-o test_dummy_encryption' failed"

	wait_ssk

	# this directory will be encrypted, because of dummy mode
	mkdir $DIR/$tdir
}

cleanup_for_enc_tests() {
	rm -rf $DIR/$tdir $*

	remount_client_normally
}

cleanup_nodemap_after_enc_tests() {
	umount_client $MOUNT || true

	if (( MGS_VERSION >= $(version_code 2.13.55) )); then
		do_facet mgs $LCTL nodemap_modify --name default \
			--property forbid_encryption --value 0
		if (( MGS_VERSION >= $(version_code 2.15.51) )); then
			do_facet mgs $LCTL nodemap_modify --name default \
				--property readonly_mount --value 0
		fi
	fi
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 0
	do_facet mgs $LCTL nodemap_activate 0

	if (( MGS_VERSION >= $(version_code 2.13.55) )); then
		wait_nm_sync default forbid_encryption '' inactive
		if (( MGS_VERSION >= $(version_code 2.15.51) )); then
			wait_nm_sync default readonly_mount '' inactive
		fi
	fi
	wait_nm_sync default trusted_nodemap '' inactive
	wait_nm_sync default admin_nodemap '' inactive
	wait_nm_sync active

	mount_client $MOUNT ${MOUNT_OPTS} || error "re-mount failed"
	wait_ssk
}

test_36() {
	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT

	# first make sure it is possible to enable encryption
	# when nodemap is not active
	setup_for_enc_tests
	rmdir $DIR/$tdir
	umount_client $MOUNT || error "umount $MOUNT failed (1)"

	# then activate nodemap, and retry
	# should succeed as encryption is not forbidden on default nodemap
	# by default
	stack_trap cleanup_nodemap_after_enc_tests EXIT
	do_facet mgs $LCTL nodemap_activate 1
	wait_nm_sync active
	forbid=$(do_facet mgs lctl get_param -n nodemap.default.forbid_encryption)
	[ $forbid -eq 0 ] || error "wrong default value for forbid_encryption"
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount '-o test_dummy_encryption' failed with default"
	umount_client $MOUNT || error "umount $MOUNT failed (2)"

	# then forbid encryption, and retry
	do_facet mgs $LCTL nodemap_modify --name default \
		--property forbid_encryption --value 1
	wait_nm_sync default forbid_encryption
	mount_client $MOUNT ${MOUNT_OPTS},test_dummy_encryption &&
		error "mount '-o test_dummy_encryption' should have failed"
	return 0
}
run_test 36 "control if clients can use encryption"

test_37() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local objdump=$TMP/objdump

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[ "$ost1_FSTYPE" = ldiskfs ] || skip "ldiskfs only test (using debugfs)"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync
	do_facet ost1 "sync; sync"

	# check that content on ost is encrypted
	local fids=($($LFS getstripe $testfile | grep 0x))
	local fid="${fids[3]}:${fids[2]}:0"
	local objpath=$(ost_fid2_objpath ost1 $fid)

	do_facet ost1 "$DEBUGFS -c -R 'cat $objpath' $(ostdevname 1)" > $objdump
	cmp -s $objdump $tmpfile &&
		error "file $testfile is not encrypted on ost"

	# check that in-memory representation of file is correct
	cmp -bl ${tmpfile} ${testfile} ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl ${tmpfile} ${testfile} ||
		error "file $testfile is corrupted on server"

	rm -f $tmpfile $objdump
}
run_test 37 "simple encrypted file"

test_38() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local blksz
	local filesz
	local bsize
	local pagesz=$(getconf PAGE_SIZE)

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# get block size on ost
	blksz=$($LCTL get_param osc.$FSNAME*.import |
		awk '/grant_block_size:/ { print $2; exit; }')
	# write a few bytes in file at offset $blksz
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$blksz \
		oflag=seek_bytes conv=fsync

	blksz=$(($blksz > $pagesz ? $blksz : $pagesz))
	# check that in-memory representation of file is correct
	bsize=$(stat --format=%B $testfile)
	filesz=$(stat --format=%b $testfile)
	filesz=$((filesz*bsize))
	[ $filesz -le $blksz ] ||
		error "file $testfile is $filesz long in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	bsize=$(stat --format=%B $testfile)
	filesz=$(stat --format=%b $testfile)
	filesz=$((filesz*bsize))
	[ $filesz -le $blksz ] ||
		error "file $testfile is $filesz long on server"

	rm -f $tmpfile
}
run_test 38 "encrypted file with hole"

test_39() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync

	# write a few more bytes in the same page
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=1024 oflag=seek_bytes \
		conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=1024 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	rm -f $tmpfile
}
run_test 39 "rewrite data in already encrypted page"

test_40() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local seek
	local filesz
	#define LUSTRE_ENCRYPTION_UNIT_SIZE   (1 << 12)
	local UNIT_SIZE=$((1 << 12))
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write a few bytes in file
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (1)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (1)"

	# write a few other bytes in same page
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=256 oflag=seek_bytes \
		conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=256 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (2)"

	rm -f $testfile $tmpfile
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at end of first page
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 4))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few other bytes at beginning of first page
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync,notrunc

	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (3)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (3)"

	rm -f $testfile $tmpfile
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at beginning of second page
	echo "abc" > $tmpfile
	$LFS setstripe -c1 -i0 $testfile
	seek=$(getconf PAGESIZE)
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few other bytes at end of first page
	seek=$((seek - 4))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (4)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (4)"

	rm -f $testfile $tmpfile $tmpfile2
	cancel_lru_locks osc ; cancel_lru_locks mdc

	# write a few bytes in file, at beginning of first stripe
	echo "abc" > $tmpfile
	$LFS setstripe -S 256k -c2 $testfile
	dd if=$tmpfile of=$testfile bs=4 count=1 conv=fsync,notrunc

	# write a few other bytes, at beginning of second stripe
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=262144 oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile of=$tmpfile bs=4 count=1 seek=262144 oflag=seek_bytes \
		conv=fsync,notrunc

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory (5)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (5)"

	filesz=$(stat --format=%s $testfile)
	filesz=$(((filesz+UNIT_SIZE-1)/UNIT_SIZE * UNIT_SIZE))

	# remount without dummy encryption key
	remount_client_normally

	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type f)
	[ $(stat --format=%s $scrambledfile) -eq $filesz ] ||
		error "file size without key should be rounded up"

	rm -f $tmpfile
}
run_test 40 "exercise size of encrypted file"

test_41() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	echo "abc" > $tmpfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 204))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync
	seek=$(getconf PAGESIZE)
	seek=$((seek + 1092))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few bytes in file
	$LFS setstripe -c1 -i0 -S 256k $testfile
	seek=$(getconf PAGESIZE)
	seek=$((seek - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync &

	sleep 5
	# write a few other bytes, at a different offset
	seek=$(getconf PAGESIZE)
	seek=$((seek + 1092))
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &
	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (1)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 41 "test race on encrypted file size (1)"

test_42() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local pagesz=$(getconf PAGESIZE)
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	mount_client $MOUNT2 ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount2 with '-o test_dummy_encryption' failed"

	# create file by writting one whole page
	$LFS setstripe -c1 -i0 -S 256k $testfile
	dd if=/dev/zero of=$testfile bs=$pagesz count=1 conv=fsync

	# read file from 2nd mount point
	cat $testfile2 > /dev/null

	echo "abc" > $tmpfile
	dd if=/dev/zero of=$tmpfile2 bs=$pagesz count=1 conv=fsync
	seek=$((2*pagesz - 204))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	seek=$((2*pagesz + 1092))
	dd if=$tmpfile of=$tmpfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc

	# write a few bytes in file from 1st mount point
	seek=$((2*pagesz - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &

	sleep 5
	# write a few other bytes, at a different offset from 2nd mount point
	seek=$((2*pagesz + 1092))
	dd if=$tmpfile of=$testfile2 bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &
	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted in memory (1)"

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile2 $testfile2 ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile2 $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 42 "test race on encrypted file size (2)"

test_43() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/abc
	local tmpfile2=$TMP/abc2
	local resfile=$TMP/res
	local pagesz=$(getconf PAGESIZE)
	local seek

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi
	mount_client $MOUNT2 ${MOUNT_OPTS},test_dummy_encryption ||
		error "mount2 with '-o test_dummy_encryption' failed"

	# create file
	tr '\0' '1' < /dev/zero |
		dd of=$tmpfile bs=1 count=$pagesz conv=fsync
	$LFS setstripe -c1 -i0 -S 256k $testfile
	cp $tmpfile $testfile

	# read file from 2nd mount point
	cat $testfile2 > /dev/null

	# write a few bytes in file from 1st mount point
	echo "abc" > $tmpfile2
	seek=$((2*pagesz - 204))
	#define OBD_FAIL_OST_WR_ATTR_DELAY	 0x250
	do_facet ost1 "$LCTL set_param fail_loc=0x250 fail_val=15"
	dd if=$tmpfile2 of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc &

	sleep 5
	# read file from 2nd mount point
	dd if=$testfile2 of=$resfile bs=$pagesz count=1 conv=fsync,notrunc
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted in memory (1)"

	wait
	do_facet ost1 "$LCTL set_param fail_loc=0x0"

	# check that in-memory representation of file is correct
	dd if=$tmpfile2 of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	cmp -bl $tmpfile $testfile2 ||
		error "file $testfile is corrupted in memory (2)"

	cancel_lru_locks osc ; cancel_lru_locks mdc

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server (1)"

	rm -f $tmpfile $tmpfile2
}
run_test 43 "test race on encrypted file size (3)"

test_44() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local resfile=$TMP/resfile
	local pagesz=$(getconf PAGESIZE)
	local respage

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	which vmtouch || skip "This test needs vmtouch utility"

	# Direct I/O is now supported on encrypted files.

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile
	dd if=/dev/urandom of=$tmpfile bs=$pagesz count=2 conv=fsync
	dd if=$tmpfile of=$testfile bs=$pagesz count=2 oflag=direct ||
		error "could not write to file with O_DIRECT (1)"

	respage=$(vmtouch $testfile | awk '/Resident Pages:/ {print $3}')
	[ "$respage" == "0/2" ] ||
		error "write to enc file fell back to buffered IO"

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=2 iflag=direct ||
		error "could not read from file with O_DIRECT (1)"

	respage=$(vmtouch $testfile | awk '/Resident Pages:/ {print $3}')
	[ "$respage" == "0/2" ] ||
		error "read from enc file fell back to buffered IO"

	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (1)"

	rm -f $resfile

	$TRUNCATE $tmpfile $pagesz
	dd if=$tmpfile of=$testfile bs=$pagesz count=1 seek=13 oflag=direct ||
		error "could not write to file with O_DIRECT (2)"

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=1 skip=13 iflag=direct ||
		error "could not read from file with O_DIRECT (2)"
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (2)"

	rm -f $testfile $resfile
	$LFS setstripe -c1 -i0 $testfile

	$TRUNCATE $tmpfile $((pagesz/2 - 5))
	cp $tmpfile $testfile

	cancel_lru_locks

	dd if=$testfile of=$resfile bs=$pagesz count=1 iflag=direct ||
		error "could not read from file with O_DIRECT (3)"
	cmp -bl $tmpfile $resfile ||
		error "file $testfile is corrupted (3)"

	rm -f $tmpfile $resfile $testfile

	if [ $OSTCOUNT -ge 2 ]; then
		dd if=/dev/urandom of=$tmpfile bs=$pagesz count=1 conv=fsync
		$LFS setstripe -S 256k -c2 $testfile

		# write in file, at beginning of first stripe, buffered IO
		dd if=$tmpfile of=$testfile bs=$pagesz count=1 \
			conv=fsync,notrunc

		# write at beginning of second stripe, direct IO
		dd if=$tmpfile of=$testfile bs=$pagesz count=1 seek=256k \
			oflag=seek_bytes,direct conv=fsync,notrunc

		cancel_lru_locks

		# read at beginning of first stripe, direct IO
		dd if=$testfile of=$resfile bs=$pagesz count=1 \
			iflag=direct conv=fsync

		cmp -bl $tmpfile $resfile ||
			error "file $testfile is corrupted (4)"

		# read at beginning of second stripe, buffered IO
		dd if=$testfile of=$resfile bs=$pagesz count=1 skip=256k \
			iflag=skip_bytes conv=fsync

		cmp -bl $tmpfile $resfile ||
			error "file $testfile is corrupted (5)"

		rm -f $tmpfile $resfile
	fi
}
run_test 44 "encrypted file access semantics: direct IO"

test_45() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/junk

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile
	dd if=/dev/zero of=$testfile bs=512K count=1
	$MULTIOP $testfile OSMRUc || error "$MULTIOP $testfile failed (1)"
	$MULTIOP $testfile OSMWUc || error "$MULTIOP $testfile failed (2)"

	dd if=/dev/zero of=$tmpfile bs=512K count=1
	$MULTIOP $tmpfile OSMWUc || error "$MULTIOP $tmpfile failed"
	$MMAP_CAT $tmpfile > ${tmpfile}2

	cancel_lru_locks

	$MULTIOP $testfile OSMRUc
	$MMAP_CAT $testfile > ${testfile}2
	cmp -bl ${tmpfile}2 ${testfile}2 ||
		error "file $testfile is corrupted"

	rm -f $tmpfile ${tmpfile}2
}
run_test 45 "encrypted file access semantics: MMAP"

test_46() {
	local testdir=$DIR/$tdir/mydir
	local testfile=$testdir/myfile
	local testdir2=$DIR/$tdir/mydirwithaveryverylongnametotestcodebehaviour0
	local testfile2=$testdir/myfilewithaveryverylongnametotestcodebehaviour0
	# testdir3, testfile3, testhl3 and testsl3 names are 255 bytes long
	local testdir3=$testdir2/dir_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012345678
	local testfile3=$testdir2/file_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567
	local testhl3=$testdir2/hl_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789
	local testsl3=$testdir2/sl_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789
	local lsfile=$TMP/lsfile
	local scrambleddir
	local scrambledfile
	local inum

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	touch $DIR/$tdir/$tfile
	mkdir $testdir
	echo test > $testfile
	echo othertest > $testfile2
	if [[ $MDSCOUNT -gt 1 ]]; then
		$LFS setdirstripe -c1 -i1 $testdir2
	else
		mkdir $testdir2
	fi
	inum=$(stat -c %i $testdir2)
	if [ "$mds1_FSTYPE" = ldiskfs ]; then
		# For now, restrict this part of the test to ldiskfs backend,
		# as osd-zfs does not support 255 byte-long encrypted names.
		mkdir $testdir3 || error "cannot mkdir $testdir3"
		touch $testfile3 || error "cannot touch $testfile3"
		ln $testfile3 $testhl3 || error "cannot ln $testhl3"
		ln -s $testfile3 $testsl3 || error "cannot ln $testsl3"
	fi
	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remount without dummy encryption key
	remount_client_normally

	# this is $testdir2
	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -inum $inum)
	stat $scrambleddir || error "stat $scrambleddir failed"
	if [ "$mds1_FSTYPE" = ldiskfs ]; then
		stat $scrambleddir/* || error "cannot stat in $scrambleddir"
		rm -rf $scrambleddir/* || error "cannot clean in $scrambleddir"
	fi
	rmdir $scrambleddir || error "rmdir $scrambleddir failed"

	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type d)
	ls -1 $scrambleddir > $lsfile || error "ls $testdir failed (1)"

	scrambledfile=$scrambleddir/$(head -n 1 $lsfile)
	stat $scrambledfile || error "stat $scrambledfile failed (1)"
	rm -f $lsfile

	cat $scrambledfile && error "cat $scrambledfile should have failed (1)"
	rm -f $scrambledfile || error "rm $scrambledfile failed (1)"

	ls -1 $scrambleddir > $lsfile || error "ls $testdir failed (2)"
	scrambledfile=$scrambleddir/$(head -n 1 $lsfile)
	stat $scrambledfile || error "stat $scrambledfile failed (2)"
	rm -f $lsfile
	cat $scrambledfile && error "cat $scrambledfile should have failed (2)"

	touch $scrambleddir/otherfile &&
		error "touch otherfile should have failed"
	ls $scrambleddir/otherfile && error "otherfile should not exist"
	mkdir $scrambleddir/otherdir &&
		error "mkdir otherdir should have failed"
	ls -d $scrambleddir/otherdir && error "otherdir should not exist"

	ls -R $DIR
	rm -f $scrambledfile || error "rm $scrambledfile failed (2)"
	rmdir $scrambleddir || error "rmdir $scrambleddir failed"
	ls -R $DIR
}
run_test 46 "encrypted file access semantics without key"

test_47() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR/$tdir/${tfile}.2
	local tmpfile=$DIR/junk
	local name_enc=1
	local scrambleddir
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	$LCTL get_param mdc.*.connect_flags | grep -q name_encryption ||
		name_enc=0

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	dd if=/dev/urandom of=$tmpfile bs=512K count=1
	mrename $tmpfile $testfile &&
		error "rename from unencrypted to encrypted dir should fail"

	ln $tmpfile $testfile &&
		error "link from encrypted to unencrypted dir should fail"

	cp $tmpfile $testfile ||
		error "cp from unencrypted to encrypted dir should succeed"
	rm -f $tmpfile

	mrename $testfile $testfile2 ||
		error "rename from within encrypted dir should succeed"

	ln $testfile2 $testfile ||
		error "link from within encrypted dir should succeed"
	cmp -bl $testfile2 $testfile ||
		error "cannot read from hard link (1.1)"
	echo a >> $testfile || error "cannot write to hard link (1)"
	cancel_lru_locks
	cmp -bl $testfile2 $testfile ||
		error "cannot read from hard link (1.2)"
	rm -f $testfile

	ln $testfile2 $tmpfile ||
		error "link from unencrypted to encrypted dir should succeed"
	cancel_lru_locks
	cmp -bl $testfile2 $tmpfile ||
		error "cannot read from hard link (2.1)"
	echo a >> $tmpfile || error "cannot write to hard link (2)"
	cancel_lru_locks
	cmp -bl $testfile2 $tmpfile ||
		error "cannot read from hard link (2.2)"
	rm -f $tmpfile

	if [ $name_enc -eq 1 ]; then
		# check we are limited in the number of hard links
		# we can create for encrypted files, to what can fit into LinkEA
		for i in $(seq 1 160); do
			ln $testfile2 ${testfile}_$i || break
		done
		[ $i -lt 160 ] || error "hard link $i should fail"
		rm -f ${testfile}_*
	fi

	mrename $testfile2 $tmpfile &&
		error "rename from encrypted to unencrypted dir should fail"
	rm -f $testfile2
	dd if=/dev/urandom of=$tmpfile bs=512K count=1

	dd if=/dev/urandom of=$testfile bs=512K count=1
	mkdir $DIR/$tdir/mydir

	ln -s $testfile ${testfile}.sym ||
		error "symlink from within encrypted dir should succeed"
	cancel_lru_locks
	cmp -bl $testfile ${testfile}.sym ||
		error "cannot read from sym link (1.1)"
	echo a >> ${testfile}.sym || error "cannot write to sym link (1)"
	cancel_lru_locks
	cmp -bl $testfile ${testfile}.sym ||
		error "cannot read from sym link (1.2)"
	[ $(stat -c %s ${testfile}.sym) -eq ${#testfile} ] ||
		error "wrong symlink size (1)"

	ln -s $tmpfile ${testfile}.sl ||
		error "symlink from encrypted to unencrypted dir should succeed"
	cancel_lru_locks
	cmp -bl $tmpfile ${testfile}.sl ||
		error "cannot read from sym link (2.1)"
	echo a >> ${testfile}.sl || error "cannot write to sym link (2)"
	cancel_lru_locks
	cmp -bl $tmpfile ${testfile}.sl ||
		error "cannot read from sym link (2.2)"
	[ $(stat -c %s ${testfile}.sl) -eq ${#tmpfile} ] ||
		error "wrong symlink size (2)"
	rm -f ${testfile}.sl

	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remount without dummy encryption key
	remount_client_normally

	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type d)
	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -type f)
	scrambledlink=$(find $DIR/$tdir/ -maxdepth 1 -type l)
	ln $scrambledfile $scrambleddir/linkfile &&
		error "ln linkfile should have failed"
	mrename $scrambledfile $DIR/onefile2 &&
		error "mrename from $scrambledfile should have failed"
	touch $DIR/onefile
	mrename $DIR/onefile $scrambleddir/otherfile &&
		error "mrename to $scrambleddir should have failed"
	readlink $scrambledlink ||
		error "link should be read without key"
	[ $(stat -c %s $scrambledlink) -eq \
			$(expr length "$(readlink $scrambledlink)") ] ||
		error "wrong symlink size without key"
	if [ $name_enc -eq 1 ]; then
		readlink -e $scrambledlink &&
			error "link should not point to anywhere useful"
	fi
	ln -s $scrambledfile ${scrambledfile}.sym &&
		error "symlink without key should fail (1)"
	ln -s $tmpfile ${scrambledfile}.sl &&
		error "symlink without key should fail (2)"

	rm -f $tmpfile $DIR/onefile
}
run_test 47 "encrypted file access semantics: rename/link"

test_48a() {
	local save="$TMP/$TESTSUITE-$TESTNAME.parameters"
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/111
	local tmpfile2=$TMP/abc
	local pagesz=$(getconf PAGESIZE)
	local sz
	local seek
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# create file, 4 x PAGE_SIZE long
	tr '\0' '1' < /dev/zero |
		dd of=$tmpfile bs=1 count=4x$pagesz conv=fsync
	$LFS setstripe -c1 -i0 $testfile
	cp $tmpfile $testfile
	echo "abc" > $tmpfile2

	# decrease size: truncate to PAGE_SIZE
	$TRUNCATE $tmpfile $pagesz
	$TRUNCATE $testfile $pagesz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (1)"

	# increase size: truncate to 2 x PAGE_SIZE
	sz=$((pagesz*2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (2)"

	# write in 2nd page
	seek=$((pagesz+100))
	dd if=$tmpfile2 of=$tmpfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	dd if=$tmpfile2 of=$testfile bs=4 count=1 seek=$seek oflag=seek_bytes \
		conv=fsync,notrunc
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (3)"

	# truncate to PAGE_SIZE / 2
	sz=$((pagesz/2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (4)"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz-7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (5)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz+18))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (6)"

	# truncate to a larger, non-multiple of PAGE_SIZE, in a different page
	sz=$((sz+pagesz+30))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	cancel_lru_locks osc ; cancel_lru_locks mdc
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (7)"

	sync ; echo 3 > /proc/sys/vm/drop_caches

	# remount without dummy encryption key
	remount_client_normally

	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -type f)
	$TRUNCATE $scrambledfile 0 &&
		error "truncate $scrambledfile should have failed without key"

	rm -f $tmpfile $tmpfile2
}
run_test 48a "encrypted file access semantics: truncate"

cleanup_for_enc_tests_othercli() {
	local othercli=$1

	# remount othercli normally
	zconf_umount $othercli $MOUNT ||
		error "umount $othercli $MOUNT failed"
	zconf_mount $othercli $MOUNT ||
		error "remount $othercli $MOUNT failed"
}

test_48b() {
	local othercli

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[ "$num_clients" -ge 2 ] || skip "Need at least 2 clients"

	if [ "$HOSTNAME" == ${clients_arr[0]} ]; then
		othercli=${clients_arr[1]}
	else
		othercli=${clients_arr[0]}
	fi

	stack_trap cleanup_for_enc_tests EXIT
	stack_trap "cleanup_for_enc_tests_othercli $othercli" EXIT
	setup_for_enc_tests
	zconf_umount $othercli $MOUNT ||
		error "umount $othercli $MOUNT failed"

	cp /bin/sleep $DIR/$tdir/
	cancel_lru_locks osc ; cancel_lru_locks mdc
	$DIR/$tdir/sleep 30 &
	# mount and IOs must be done in the same shell session, otherwise
	# encryption key in session keyring is missing
	do_node $othercli "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT && \
			   $TRUNCATE $DIR/$tdir/sleep 7"
	wait || error "wait error"
	cmp --silent /bin/sleep $DIR/$tdir/sleep ||
		error "/bin/sleep and $DIR/$tdir/sleep differ"
}
run_test 48b "encrypted file: concurrent truncate"

trace_cmd() {
	local cmd="$@"

	cancel_lru_locks
	$LCTL set_param debug=+info
	$LCTL clear

	echo $cmd
	eval $cmd
	[ $? -eq 0 ] || error "$cmd failed"

	if [ -z "$MATCHING_STRING" ]; then
		$LCTL dk | grep -E "get xattr 'encryption.c'|get xattrs"
	else
		$LCTL dk | grep -E "$MATCHING_STRING"
	fi
	[ $? -ne 0 ] || error "get xattr event was triggered"
}

test_49() {
	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	local dirname=$DIR/$tdir/subdir

	mkdir $dirname

	trace_cmd stat $dirname
	trace_cmd echo a > $dirname/f1
	sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
	trace_cmd stat $dirname/f1
	sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
	trace_cmd cat $dirname/f1
	dd if=/dev/zero of=$dirname/f1 bs=1M count=10 conv=fsync
	sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
	MATCHING_STRING="get xattr 'encryption.c'" \
		trace_cmd $TRUNCATE $dirname/f1 10240
	trace_cmd $LFS setstripe -E -1 -S 4M $dirname/f2
	sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
	trace_cmd $LFS migrate -E -1 -S 256K $dirname/f2

	if [[ $MDSCOUNT -gt 1 ]]; then
		trace_cmd $LFS setdirstripe -i 1 $dirname/d2
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		trace_cmd $LFS migrate -m 0 $dirname/d2
		echo b > $dirname/d2/subf
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		if (( "$MDS1_VERSION" > $(version_code 2.14.54.54) )); then
			# migrate a non-empty encrypted dir
			trace_cmd $LFS migrate -m 1 $dirname/d2
			sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
			[ -f $dirname/d2/subf ] || error "migrate failed (1)"
			[ $(cat $dirname/d2/subf) == "b" ] ||
				error "migrate failed (2)"
		fi

		$LFS setdirstripe -i 1 -c 1 $dirname/d3
		dirname=$dirname/d3/subdir
		mkdir $dirname
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		trace_cmd stat $dirname
		trace_cmd echo c > $dirname/f1
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		trace_cmd stat $dirname/f1
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		trace_cmd cat $dirname/f1
		dd if=/dev/zero of=$dirname/f1 bs=1M count=10 conv=fsync
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		MATCHING_STRING="get xattr 'encryption.c'" \
			trace_cmd $TRUNCATE $dirname/f1 10240
		trace_cmd $LFS setstripe -E -1 -S 4M $dirname/f2
		sync ; sync ; echo 3 > /proc/sys/vm/drop_caches
		trace_cmd $LFS migrate -E -1 -S 256K $dirname/f2
	else
		skip_noexit "2nd part needs >= 2 MDTs"
	fi
}
run_test 49 "Avoid getxattr for encryption context"

test_50() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/abc
	local pagesz=$(getconf PAGESIZE)
	local sz

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# write small file, data on MDT only
	tr '\0' '1' < /dev/zero |
	    dd of=$tmpfile bs=1 count=5000 conv=fsync
	$LFS setstripe -E 1M -L mdt -E EOF $testfile
	cp $tmpfile $testfile

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	remove_enc_key ; insert_enc_key

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	# decrease size: truncate to PAGE_SIZE
	$TRUNCATE $tmpfile $pagesz
	$TRUNCATE $testfile $pagesz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (1)"

	# increase size: truncate to 2 x PAGE_SIZE
	sz=$((pagesz*2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (2)"

	# truncate to PAGE_SIZE / 2
	sz=$((pagesz/2))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (3)"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz-7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (4)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16
	sz=$((sz+18))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (5)"

	# truncate to a larger, non-multiple of PAGE_SIZE, in a different page
	sz=$((sz+pagesz+30))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (6)"

	rm -f $testfile
	remove_enc_key ; insert_enc_key

	# write hole in file, data spread on MDT and OST
	tr '\0' '2' < /dev/zero |
	    dd of=$tmpfile bs=1 count=1539 seek=1539074 conv=fsync,notrunc
	$LFS setstripe -E 1M -L mdt -E EOF $testfile
	cp --sparse=always $tmpfile $testfile

	# check that in-memory representation of file is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted in memory"

	remove_enc_key ; insert_enc_key

	# check that file read from server is correct
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted on server"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside OST part of data
	sz=$((1024*1024+13))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (7)"

	# truncate to a smaller, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside MDT part of data
	sz=7
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (8)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside MDT part of data
	sz=$((1024*1024-13))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (9)"

	# truncate to a larger, non-multiple of PAGE_SIZE, non-multiple of 16,
	# inside OST part of data
	sz=$((1024*1024+7))
	$TRUNCATE $tmpfile $sz
	$TRUNCATE $testfile $sz
	remove_enc_key ; insert_enc_key
	cmp -bl $tmpfile $testfile ||
		error "file $testfile is corrupted (10)"

	rm -f $tmpfile
}
run_test 50 "DoM encrypted file"

test_51() {
	(( "$MDS1_VERSION" >= $(version_code v2_13_55-38-gf05edf8e2b) )) ||
		skip "Need MDS version at least 2.13.55.38"

	mkdir $DIR/$tdir || error "mkdir $tdir"
	local mdts=$(comma_list $(mdts_nodes))
	local cap_param=mdt.*.enable_cap_mask
	local nm_param=nodemap.default.enable_cap_mask
	local val

	old_cap=($(do_nodes $mdts $LCTL get_param -n $cap_param 2>/dev/null))
	if [[ -n "$old_cap" ]]; then
		local new_cap="+cap_chown+cap_fowner+cap_dac_override+cap_dac_read_search"

		(( MDS1_VERSION >= $(version_code 2.15.63.14) )) ||
		(( MDS1_VERSION < $(version_code 2.15.0) &&
		   MDS1_VERSION > $(version_code 2.14.0.135) )) ||
			new_cap=0xf
		echo "old_cap: $old_cap new_cap: $new_cap"
		do_nodes $mdts $LCTL set_param $cap_param=$new_cap
		stack_trap "do_nodes $mdts $LCTL set_param $cap_param=$old_cap"
	fi

	touch $DIR/$tdir/$tfile || error "touch $tfile as root (1)"
	cp $(which chown) $DIR/$tdir || error "cp chown"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile &&
		error "chown $tfile should fail (1)"
	setcap 'CAP_CHOWN=ep' $DIR/$tdir/chown || error "setcap CAP_CHOWN"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile ||
		error "chown $tfile as $ID0 (1)"
	rm $DIR/$tdir/$tfile || error "rm $tfile (1)"

	touch $DIR/$tdir/$tfile || error "touch $tfile as root (2)"
	cp $(which touch) $DIR/$tdir || error "cp touch"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/touch $DIR/$tdir/$tfile &&
		error "touch should fail"
	setcap 'CAP_FOWNER=ep' $DIR/$tdir/touch || error "setcap CAP_FOWNER"
	$RUNAS_CMD -u $ID0 $DIR/$tdir/touch $DIR/$tdir/$tfile ||
		error "touch $tfile"
	rm $DIR/$tdir/$tfile || error "rm $tfile (2)"

	local cap
	for cap in "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH"; do
		touch $DIR/$tdir/$tfile || error "touch $tfile as root (3)"
		chmod 600 $DIR/$tdir/$tfile || error "chmod $tfile"
		cp $(which cat) $DIR/$tdir || error "cp cat"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/cat $DIR/$tdir/$tfile &&
			error "cat should fail"
		setcap $cap=ep $DIR/$tdir/cat || error "setcap $cap"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/cat $DIR/$tdir/$tfile ||
			error "cat $tfile"
		rm $DIR/$tdir/$tfile || error "rm $tfile (3)"
	done

	if (( "$MDS1_VERSION" >= $(version_code 2.16.55) )); then
		val=$(do_facet mgs $LCTL get_param -n $nm_param)
		[[ "$val" == "off" ]] ||
			error "wrong default value $val for $nm_param"

		do_facet mgs $LCTL nodemap_modify --name default \
			--property admin --value 1
		do_facet mgs $LCTL nodemap_modify --name default \
			--property trusted --value 1
		wait_nm_sync default trusted_nodemap

		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active 1
		stack_trap cleanup_active EXIT
		stack_trap "do_facet mgs $LCTL nodemap_modify --name default \
			--property admin --value 0" EXIT
		stack_trap "do_facet mgs $LCTL nodemap_modify --name default \
			--property trusted --value 0" EXIT
		stack_trap "do_facet mgs $LCTL nodemap_set_cap \
			--name default --type off" EXIT

		# $DIR/$tdir/chown has CAP_CHOWN, so it should succeed with
		# enable_cap_mask=off on nodemap
		touch $DIR/$tdir/$tfile || error "touch $tfile as root (4)"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile ||
			error "chown $tfile as $ID0 (2)"
		rm $DIR/$tdir/$tfile || error "rm $tfile (4)"

		do_facet mgs $LCTL nodemap_set_cap --name default \
		   --type mask --caps cap_dac_read_search ||
			error "nodemap_set_cap failed (1)"
		wait_nm_sync default enable_cap_mask

		# $DIR/$tdir/chown should fail with
		# enable_cap_mask=mask:cap_dac_read_search on nodemap
		touch $DIR/$tdir/$tfile || error "touch $tfile as root (5)"
		$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile &&
			error "chown $tfile should fail (2)"
		do_facet mgs $LCTL nodemap_set_cap --name default \
		   --type mask --caps +cap_chown ||
			error "nodemap_set_cap failed (2)"
		wait_nm_sync default enable_cap_mask
		# $DIR/$tdir/chown should succeed with
		# enable_cap_mask=mask:cap_chown,cap_dac_read_search
		$RUNAS_CMD -u $ID0 $DIR/$tdir/chown $ID0 $DIR/$tdir/$tfile ||
			error "chown $tfile as $ID0 (3)"
		rm $DIR/$tdir/$tfile || error "rm $tfile (5)"

		# Test ability to raise caps on child nodemap
		do_facet mgs $LCTL nodemap_modify --name default \
		   --property child_raise_privileges --value none ||
			error "setting child_raise_privileges=none failed"
		wait_nm_sync default child_raise_privileges
		stack_trap "do_facet mgs $LCTL nodemap_modify --name default \
			    --property child_raise_privileges --value none" EXIT
		do_facet mds1 $LCTL nodemap_add -d -p default nm_51 ||
			error "cannot create nodemap nm_51 (1)"
		stack_trap "do_facet mds1 $LCTL nodemap_del nm_51" EXIT
		do_facet mds1 $LCTL nodemap_set_cap --name nm_51 \
		   --type mask --caps +cap_fowner &&
			error "nodemap_set_cap +cap_fowner should fail"
		do_facet mds1 $LCTL nodemap_set_cap --name nm_51 \
		   --type mask --caps -cap_chown ||
			error "nodemap_set_cap -cap_chown failed"
		do_facet mds1 $LCTL nodemap_set_cap --name nm_51 \
		   --type mask --caps +cap_chown ||
			error "nodemap_set_cap +cap_chown failed"
		do_facet mds1 $LCTL nodemap_del nm_51 ||
			error "cannot delete nodemap nm_51"
		do_facet mgs $LCTL nodemap_modify --name default \
		   --property child_raise_privileges --value caps ||
			error "setting child_raise_privileges=caps failed"
		wait_nm_sync default child_raise_privileges
		do_facet mds1 $LCTL nodemap_add -d -p default nm_51 ||
			error "cannot create nodemap nm_51 (2)"
		do_facet mds1 $LCTL nodemap_set_cap --name nm_51 \
		   --type mask --caps +cap_fowner ||
			error "nodemap_set_cap +cap_fowner failed"
	fi
}
run_test 51 "FS capabilities ==============="

test_52() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/$tfile
	local mirror1=$TMP/$tfile.mirror1
	local mirror2=$TMP/$tfile.mirror2

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap "cleanup_for_enc_tests $tmpfile $mirror1 $mirror2" EXIT
	setup_for_enc_tests

	dd if=/dev/urandom of=$tmpfile bs=5000 count=1 conv=fsync

	$LFS mirror create -N -i0 -N -i1 $testfile ||
		error "could not create mirror"

	dd if=$tmpfile of=$testfile bs=5000 count=1 conv=fsync ||
		error "could not write to $testfile"

	$LFS mirror resync $testfile ||
		error "could not resync mirror"

	$LFS mirror verify -v $testfile ||
		error "verify mirror failed"

	$LFS mirror read -N 1 -o $mirror1 $testfile ||
		error "could not read from mirror 1"

	cmp -bl $tmpfile $mirror1 ||
		error "mirror 1 is corrupted"

	$LFS mirror read -N 2 -o $mirror2 $testfile ||
		error "could not read from mirror 2"

	cmp -bl $tmpfile $mirror2 ||
		error "mirror 2 is corrupted"

	tr '\0' '2' < /dev/zero |
	    dd of=$tmpfile bs=1 count=9000 conv=fsync

	$LFS mirror write -N 1 -i $tmpfile $testfile ||
		error "could not write to mirror 1"

	$LFS mirror verify -v $testfile &&
		error "mirrors should be different"

	rm -f $testfile $mirror1 $mirror2

	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=9000 count=1 conv=fsync ||
		error "write to $testfile failed"
	$LFS getstripe $testfile
	cancel_lru_locks

	$LFS migrate -i1 $testfile ||
		error "migrate $testfile failed"
	$LFS getstripe $testfile
	stripe=$($LFS getstripe -i $testfile)
	[ $stripe -eq 1 ] || error "migrate file $testfile failed"

	cancel_lru_locks
	cmp -bl $tmpfile $testfile ||
		error "migrated file is corrupted"

	$LFS mirror extend -N -i0 $testfile ||
		error "mirror extend $testfile failed"
	$LFS getstripe $testfile
	mirror_count=$($LFS getstripe -N $testfile)
	[ $mirror_count -eq 2 ] ||
		error "mirror extend file $testfile failed (1)"
	stripe=$($LFS getstripe --mirror-id=1 -i $testfile)
	[ $stripe -eq 1 ] || error "mirror extend file $testfile failed (2)"
	stripe=$($LFS getstripe --mirror-id=2 -i $testfile)
	[ $stripe -eq 0 ] || error "mirror extend file $testfile failed (3)"

	cancel_lru_locks
	$LFS mirror verify -v $testfile ||
		error "mirror verify failed"
	$LFS mirror read -N 1 -o $mirror1 $testfile ||
		error "read from mirror 1 failed"
	cmp -bl $tmpfile $mirror1 ||
		error "corruption of mirror 1"
	$LFS mirror read -N 2 -o $mirror2 $testfile ||
		error "read from mirror 2 failed"
	cmp -bl $tmpfile $mirror2 ||
		error "corruption of mirror 2"

	$LFS mirror split --mirror-id 1 -f ${testfile}.mirror $testfile &&
		error "mirror split -f should fail"

	$LFS mirror split --mirror-id 1 $testfile &&
		error "mirror split without -d should fail"

	$LFS mirror split --mirror-id 1 -d $testfile ||
		error "mirror split failed"
	$LFS getstripe $testfile
	mirror_count=$($LFS getstripe -N $testfile)
	[ $mirror_count -eq 1 ] ||
		error "mirror split file $testfile failed (1)"
	stripe=$($LFS getstripe --mirror-id=1 -i $testfile)
	[ -z "$stripe" ] || error "mirror extend file $testfile failed (2)"
	stripe=$($LFS getstripe --mirror-id=2 -i $testfile)
	[ $stripe -eq 0 ] || error "mirror extend file $testfile failed (3)"

	cancel_lru_locks
	cmp -bl $tmpfile $testfile ||
		error "extended/split file is corrupted"
}
run_test 52 "Mirrored encrypted file"

test_53() {
	local testfile=$DIR/$tdir/$tfile
	local testfile2=$DIR2/$tdir/$tfile
	local tmpfile=$TMP/$tfile.tmp
	local resfile=$TMP/$tfile.res
	local pagesz
	local filemd5

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	pagesz=$(getconf PAGESIZE)
	[[ $pagesz == 65536 ]] || skip "Need 64K PAGE_SIZE client"

	do_node $mds1_HOST \
		"mount.lustre --help |& grep -q 'test_dummy_encryption:'" ||
			skip "need dummy encryption support on MDS client mount"

	# this test is probably useless now, but may turn out to be useful when
	# Lustre supports servers with PAGE_SIZE != 4KB
	pagesz=$(do_node $mds1_HOST getconf PAGESIZE)
	[[ $pagesz == 4096 ]] || skip "Need 4K PAGE_SIZE MDS client"

	stack_trap cleanup_for_enc_tests EXIT
	stack_trap "zconf_umount $mds1_HOST $MOUNT2" EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 -i0 $testfile

	# write from 1st client
	cat /dev/urandom | tr -dc 'a-zA-Z0-9' |
		dd of=$tmpfile bs=$((pagesz+3)) count=2 conv=fsync
	dd if=$tmpfile of=$testfile bs=$((pagesz+3)) count=2 conv=fsync ||
		error "could not write to $testfile (1)"

	# read from 2nd client
	# mount and IOs must be done in the same shell session, otherwise
	# encryption key in session keyring is missing
	do_node $mds1_HOST "mkdir -p $MOUNT2"
	do_node $mds1_HOST \
		"$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
		 $MGSNID:/$FSNAME $MOUNT2 && \
		 dd if=$testfile2 of=$resfile bs=$((pagesz+3)) count=2" ||
		error "could not read from $testfile2 (1)"

	# compare
	filemd5=$(do_node $mds1_HOST md5sum $resfile | awk '{print $1}')
	[ $filemd5 = $(md5sum $tmpfile | awk '{print $1}') ] ||
		error "file is corrupted (1)"
	do_node $mds1_HOST rm -f $resfile
	cancel_lru_locks

	# truncate from 2nd client
	$TRUNCATE $tmpfile $((pagesz+3))
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (1)"
	do_node $mds1_HOST "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT2 && \
			   $TRUNCATE $testfile2 $((pagesz+3))" ||
		error "could not truncate $testfile2 (1)"

	# compare
	cmp -bl $tmpfile $testfile ||
		error "file is corrupted (2)"
	rm -f $tmpfile $testfile
	cancel_lru_locks
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (2)"

	# do conversly
	do_node $mds1_HOST \
	      dd if=/dev/urandom of=$tmpfile bs=$((pagesz+3)) count=2 conv=fsync
	# write from 2nd client
	do_node $mds1_HOST \
	   "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
	    $MGSNID:/$FSNAME $MOUNT2 && \
	    dd if=$tmpfile of=$testfile2 bs=$((pagesz+3)) count=2 conv=fsync" ||
		error "could not write to $testfile2 (2)"

	# read from 1st client
	dd if=$testfile of=$resfile bs=$((pagesz+3)) count=2 ||
		error "could not read from $testfile (2)"

	# compare
	filemd5=$(do_node $mds1_HOST md5sum -b $tmpfile | awk '{print $1}')
	[ $filemd5 = $(md5sum -b $resfile | awk '{print $1}') ] ||
		error "file is corrupted (3)"
	rm -f $resfile
	cancel_lru_locks

	# truncate from 1st client
	do_node $mds1_HOST "$TRUNCATE $tmpfile $((pagesz+3))"
	$TRUNCATE $testfile $((pagesz+3)) ||
		error "could not truncate $testfile (2)"

	# compare
	zconf_umount $mds1_HOST $MOUNT2 ||
		error "umount $mds1_HOST $MOUNT2 failed (3)"
	do_node $mds1_HOST "$MOUNT_CMD -o ${MOUNT_OPTS},test_dummy_encryption \
			   $MGSNID:/$FSNAME $MOUNT2 && \
			   cmp -bl $tmpfile $testfile2" ||
		error "file is corrupted (4)"

	do_node $mds1_HOST rm -f $tmpfile
	rm -f $tmpfile
}
run_test 53 "Mixed PAGE_SIZE clients"

test_54() {
	local testdir=$DIR/$tdir/$ID0
	local testdir2=$DIR2/$tdir/$ID0
	local testfile=$testdir/$tfile
	local testfile2=$testdir/${tfile}withveryverylongnametoexercisecode
	local testfile3=$testdir/_${tfile}
	local tmpfile=$TMP/${tfile}.tmp
	local resfile=$TMP/${tfile}.res
	local nameenc=""
	local fid1
	local fid2

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	which fscrypt || skip "This test needs fscrypt userspace tool"

	yes | fscrypt setup --force --verbose ||
		error "fscrypt global setup failed"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	yes | fscrypt setup --verbose $MOUNT ||
		error "fscrypt setup $MOUNT failed"
	mkdir -p $testdir
	chown -R $ID0:$ID0 $testdir

	echo -e 'mypass\nmypass' | su - $USER0 -c "fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector $testdir" ||
		error "fscrypt encrypt failed"

	echo -e 'mypass\nmypass' | su - $USER0 -c "fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector2 $testdir" &&
		error "second fscrypt encrypt should have failed"

	mkdir -p ${testdir}2 || error "mkdir ${testdir}2 failed"
	touch ${testdir}2/f || error "mkdir ${testdir}2/f failed"
	cancel_lru_locks

	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector3 ${testdir}2 &&
		error "fscrypt encrypt on non-empty dir should have failed"

	$RUNAS dd if=/dev/urandom of=$testfile bs=127 count=1 conv=fsync ||
		error "write to encrypted file $testfile failed"
	cp $testfile $tmpfile
	$RUNAS dd if=/dev/urandom of=$testfile2 bs=127 count=1 conv=fsync ||
		error "write to encrypted file $testfile2 failed"
	$RUNAS dd if=/dev/urandom of=$testfile3 bs=127 count=1 conv=fsync ||
		error "write to encrypted file $testfile3 failed"
	$RUNAS mkdir $testdir/subdir || error "mkdir subdir failed"
	$RUNAS touch $testdir/subdir/subfile || error "mkdir subdir failed"

	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (1)"

	$RUNAS ls -R $testdir || error "ls -R $testdir failed"
	local filecount=$($RUNAS find $testdir -type f | wc -l)
	[ $filecount -eq 4 ] || error "found $filecount files"

	# check enable_filename_encryption default value
	# tunable only available for client built against embedded llcrypt
	$LCTL get_param mdc.*.connect_flags | grep -q name_encryption &&
	  nameenc=$(lctl get_param -n llite.*.enable_filename_encryption |
			head -n1)
	# If client is built against in-kernel fscrypt, it is not possible
	# to decide to encrypt file names or not: they are always encrypted.
	if [ -n "$nameenc" ]; then
		[ $nameenc -eq 0 ] ||
		       error "enable_filename_encryption should be 0 by default"

		# $testfile, $testfile2 and $testfile3 should exist because
		# names are not encrypted
		[ -f $testfile ] ||
		      error "$testfile should exist because name not encrypted"
		[ -f $testfile2 ] ||
		      error "$testfile2 should exist because name not encrypted"
		[ -f $testfile3 ] ||
		      error "$testfile3 should exist because name not encrypted"
		stat $testfile3
		[ $? -eq 0 ] || error "cannot stat $testfile3 without key"
	fi

	scrambledfiles=( $(find $testdir/ -maxdepth 1 -type f) )
	$RUNAS hexdump -C ${scrambledfiles[0]} &&
		error "reading ${scrambledfiles[0]} should fail without key"

	$RUNAS touch ${testfile}.nokey &&
		error "touch ${testfile}.nokey should have failed without key"

	echo mypass | $RUNAS fscrypt unlock --verbose $testdir ||
		error "fscrypt unlock $testdir failed (1)"

	$RUNAS cat $testfile > $resfile ||
		error "reading $testfile failed"

	cmp -bl $tmpfile $resfile || error "file read differs from file written"
	stat $testfile3
	[ $? -eq 0 ] || error "cannot stat $testfile3 with key"

	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (2)"

	$RUNAS hexdump -C ${scrambledfiles[1]} &&
		error "reading ${scrambledfiles[1]} should fail without key"

	# server local client incompatible with SSK keys installed
	if [ "$SHARED_KEY" != true ]; then
		mount_mds_client
		stack_trap umount_mds_client EXIT
		do_facet $SINGLEMDS touch $DIR2/$tdir/newfile
		mdsscrambledfile=$(do_facet $SINGLEMDS find $testdir2/ \
					-maxdepth 1 -type f | head -n1)
		[ -n "$mdsscrambledfile" ] || error "could not find file"
		do_facet $SINGLEMDS cat "$mdsscrambledfile" &&
			error "reading $mdsscrambledfile should fail on MDS"
		do_facet $SINGLEMDS "echo aaa >> \"$mdsscrambledfile\"" &&
			error "writing $mdsscrambledfile should fail on MDS"
		do_facet $SINGLEMDS $MULTIOP $testdir2/fileA m &&
			error "creating $testdir2/fileA should fail on MDS"
		do_facet $SINGLEMDS mkdir $testdir2/dirA &&
			error "mkdir $testdir2/dirA should fail on MDS"
		do_facet $SINGLEMDS ln -s $DIR2/$tdir/newfile $testdir2/sl1 &&
			error "ln -s $testdir2/sl1 should fail on MDS"
		do_facet $SINGLEMDS ln $DIR2/$tdir/newfile $testdir2/hl1 &&
			error "ln $testdir2/hl1 should fail on MDS"
		do_facet $SINGLEMDS mv "$mdsscrambledfile" $testdir2/fB &&
			error "mv $mdsscrambledfile should fail on MDS"
		do_facet $SINGLEMDS mrename "$mdsscrambledfile" $testdir2/fB &&
			error "mrename $mdsscrambledfile should fail on MDS"
		do_facet $SINGLEMDS rm -f $DIR2/$tdir/newfile
	fi

	echo mypass | $RUNAS fscrypt unlock --verbose $testdir ||
		error "fscrypt unlock $testdir failed (2)"

	rm -rf $testdir/*
	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (3)"

	rm -rf $tmpfile $resfile $testdir ${testdir}2 $MOUNT/.fscrypt

	# remount client with subdirectory mount
	umount_client $MOUNT || error "umount $MOUNT failed (1)"
	export FILESET=/$tdir
	mount_client $MOUNT ${MOUNT_OPTS} || error "remount failed (1)"
	export FILESET=""
	wait_ssk

	# setup encryption from inside this subdir mount
	# the .fscrypt directory is going to be created at the real fs root
	yes | fscrypt setup --verbose $MOUNT ||
		error "fscrypt setup $MOUNT failed (2)"
	testdir=$MOUNT/vault
	mkdir $testdir
	chown -R $ID0:$ID0 $testdir
	fid1=$(path2fid $MOUNT/.fscrypt)
	echo "With FILESET $tdir, .fscrypt FID is $fid1"

	# enable name encryption, only valid if built against embedded llcrypt
	if [ -n "$nameenc" ]; then
		do_facet mgs $LCTL set_param -P \
			llite.*.enable_filename_encryption=1
		[ $? -eq 0 ] ||
			error "set_param -P \
				llite.*.enable_filename_encryption failed"

		wait_update_facet --verbose client \
			"$LCTL get_param -n llite.*.enable_filename_encryption \
			| head -n1" 1 30 ||
			error "enable_filename_encryption not set on client"
	fi

	# encrypt 'vault' dir inside the subdir mount
	echo -e 'mypass\nmypass' | su - $USER0 -c "fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector $testdir" ||
		error "fscrypt encrypt failed"

	echo abc > $tmpfile
	chmod 666 $tmpfile
	$RUNAS cp $tmpfile $testdir/encfile

	$RUNAS fscrypt lock --verbose $testdir ||
		error "fscrypt lock $testdir failed (4)"

	# encfile should actually have its name encrypted
	if [ -n "$nameenc" ]; then
		[ -f $testdir/encfile ] &&
			error "encfile name should be encrypted"
	fi
	filecount=$(find $testdir -type f | wc -l)
	[ $filecount -eq 1 ] || error "found $filecount files instead of 1"

	# remount client with encrypted dir as subdirectory mount
	umount_client $MOUNT || error "umount $MOUNT failed (2)"
	export FILESET=/$tdir/vault
	mount_client $MOUNT ${MOUNT_OPTS} || error "remount failed (2)"
	export FILESET=""
	wait_ssk
	ls -laR $MOUNT
	fid2=$(path2fid $MOUNT/.fscrypt)
	echo "With FILESET $tdir/vault, .fscrypt FID is $fid2"
	[ "$fid1" == "$fid2" ] || error "fid1 $fid1 != fid2 $fid2 (1)"

	# all content seen by this mount is encrypted, but .fscrypt is virtually
	# presented, letting us call fscrypt lock/unlock
	echo mypass | $RUNAS fscrypt unlock --verbose $MOUNT ||
		error "fscrypt unlock $MOUNT failed (3)"

	ls -laR $MOUNT
	[ $(cat $MOUNT/encfile) == "abc" ] || error "cat encfile failed"

	# remount client without subdir mount
	umount_client $MOUNT || error "umount $MOUNT failed (3)"
	mount_client $MOUNT ${MOUNT_OPTS} || error "remount failed (3)"
	wait_ssk
	ls -laR $MOUNT
	fid2=$(path2fid $MOUNT/.fscrypt)
	echo "Without FILESET, .fscrypt FID is $fid2"
	[ "$fid1" == "$fid2" ] || error "fid1 $fid1 != fid2 $fid2 (2)"

	# because .fscrypt was actually created at the real root of the fs,
	# we can call fscrypt lock/unlock on the encrypted dir
	echo mypass | $RUNAS fscrypt unlock --verbose $DIR/$tdir/vault ||
		error "fscrypt unlock $$DIR/$tdir/vault failed (4)"

	ls -laR $MOUNT
	echo c >> $DIR/$tdir/vault/encfile || error "write to encfile failed"

	rm -rf $DIR/$tdir/vault/*
	$RUNAS fscrypt lock --verbose $DIR/$tdir/vault ||
		error "fscrypt lock $DIR/$tdir/vault failed (5)"

	# disable name encryption, only valid if built against embedded llcrypt
	if [ -n "$nameenc" ]; then
		do_facet mgs $LCTL set_param -P \
			llite.*.enable_filename_encryption=0
		[ $? -eq 0 ] ||
			error "set_param -P \
				llite.*.enable_filename_encryption failed"

		wait_update_facet --verbose client \
			"$LCTL get_param -n llite.*.enable_filename_encryption \
			| head -n1" 0 30 ||
			error "enable_filename_encryption not set back to default"
	fi

	rm -rf $tmpfile $MOUNT/.fscrypt
}
run_test 54 "Encryption policies with fscrypt"

setup_local_client_nodemap() {
	local nm_name=${1:-"c0"}
	local nm_admin_val=${2:-0}
	local nm_trusted_val=${3:-0}
	local rc

	if $SHARED_KEY; then
		export SK_UNIQUE_NM=true
		export FILESET="/"
	fi

	do_facet mgs $LCTL nodemap_del $nm_name || true
	wait_nm_sync $nm_name id ''

	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 1
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 1
	wait_nm_sync default trusted_nodemap

	client_ip=$(host_nids_address $HOSTNAME $NETTYPE)
	client_nid=$(h2nettype $client_ip)
	do_facet mgs $LCTL nodemap_add $nm_name
	do_facet mgs $LCTL nodemap_add_range \
		--name $nm_name --range $client_nid ||
		error "Add range $client_nid to $nm_name failed rc = $?"
	do_facet mgs $LCTL nodemap_modify --name $nm_name \
		--property admin --value $nm_admin_val
	do_facet mgs $LCTL nodemap_modify --name $nm_name \
		--property trusted --value $nm_trusted_val

	do_facet mgs $LCTL nodemap_activate 1
	wait_nm_sync active
}

cleanup_local_client_nodemap() {
	local nm_name=${1:-"c0"}

	do_facet mgs $LCTL nodemap_del $nm_name
	do_facet mgs $LCTL nodemap_modify --name default \
		--property admin --value 0
	do_facet mgs $LCTL nodemap_modify --name default \
		--property trusted --value 0
	wait_nm_sync default trusted_nodemap

	do_facet mgs $LCTL nodemap_activate 0
	wait_nm_sync active 0

	if $SHARED_KEY; then
		unset FILESET
		export SK_UNIQUE_NM=false
	fi
	if ! is_mounted $MOUNT; then
		mount_client $MOUNT ${MOUNT_OPTS} || error "re-mount failed"
		wait_ssk
	fi
}

cleanup_local_client_nodemap_with_mounts() {
	# unmount client
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# reset and deactivate nodemaps, remount client
	cleanup_local_client_nodemap

	# remount client on $MOUNT_2
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} || error "remount failed"
	fi
	wait_ssk
}

test_55() {
	(( $MDS1_VERSION > $(version_code 2.12.6.2) )) ||
		skip "Need MDS version at least 2.12.6.3"

	local client_ip
	local client_nid

	mkdir -p $DIR/$tdir/$USER0/testdir_groups
	chown root:$USER0 $DIR/$tdir/$USER0
	chmod 770 $DIR/$tdir/$USER0
	chmod g+s $DIR/$tdir/$USER0
	chown $USER0:$USER0 $DIR/$tdir/$USER0/testdir_groups
	chmod 770 $DIR/$tdir/$USER0/testdir_groups
	chmod g+s $DIR/$tdir/$USER0/testdir_groups

	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	stack_trap cleanup_local_client_nodemap_with_mounts EXIT

	setup_local_client_nodemap "c0" 0 1

	# remount client to take nodemap into account
	zconf_mount_clients $HOSTNAME $MOUNT $MOUNT_OPTS ||
		error "remount failed"
	unset FILESET
	wait_ssk

	euid_access $USER0 $DIR/$tdir/$USER0/testdir_groups/file
}
run_test 55 "access with seteuid"

test_56() {
	local filefrag_op=$(filefrag -l 2>&1 | grep "invalid option")
	[[ -z "$filefrag_op" ]] || skip_env "filefrag missing logical ordering"

	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setstripe -c1 $testfile
	dd if=/dev/urandom of=$testfile bs=1M count=3 conv=fsync
	filefrag -v $testfile || error "filefrag $testfile failed"
	(( $(filefrag -v $testfile | grep -c encrypted) >= 1 )) ||
		error "filefrag $testfile does not show encrypted flag"
	(( $(filefrag -v $testfile | grep -c encoded) >= 1 )) ||
		error "filefrag $testfile does not show encoded flag"
}
run_test 56 "FIEMAP on encrypted file"

test_57() {
	local testdir=$DIR/$tdir/mytestdir
	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	mkdir $DIR/$tdir
	mkdir $testdir
	setfattr -n security.c -v myval $testdir &&
		error "setting xattr on $testdir should have failed (1.1)"
	setfattr -n encryption.c -v myval $testdir &&
		error "setting xattr on $testdir should have failed (1.2)"
	touch $testfile
	setfattr -n security.c -v myval $testfile &&
		error "setting xattr on $testfile should have failed (1.1)"
	setfattr -n encryption.c -v myval $testfile &&
		error "setting xattr on $testfile should have failed (1.2)"

	rm -rf $DIR/$tdir

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	mkdir $testdir
	if [ $(getfattr -n security.c $testdir 2>&1 |
	       grep -ci "Operation not permitted") -eq 0 ]; then
		error "getting xattr on $testdir should have failed (1.1)"
	fi
	if [ $(getfattr -n encryption.c $testdir 2>&1 |
	       grep -ci "Operation not supported") -eq 0 ]; then
		error "getting xattr on $testdir should have failed (1.2)"
	fi
	getfattr -d -m - $testdir 2>&1 | grep security\.c &&
		error "listing xattrs on $testdir should not expose security.c"
	getfattr -d -m - $testdir 2>&1 | grep encryption\.c &&
	       error "listing xattrs on $testdir should not expose encryption.c"
	if [ $(setfattr -n security.c -v myval $testdir 2>&1 |
	       grep -ci "Operation not permitted") -eq 0 ]; then
		error "setting xattr on $testdir should have failed (2.1)"
	fi
	if [ $(setfattr -n encryption.c -v myval $testdir 2>&1 |
	       grep -ci "Operation not supported") -eq 0 ]; then
		error "setting xattr on $testdir should have failed (2.2)"
	fi
	touch $testfile
	if [ $(getfattr -n security.c $testfile 2>&1 |
	       grep -ci "Operation not permitted") -eq 0 ]; then
		error "getting xattr on $testfile should have failed (1.1)"
	fi
	if [ $(getfattr -n encryption.c $testfile 2>&1 |
	       grep -ci "Operation not supported") -eq 0 ]; then
		error "getting xattr on $testfile should have failed (1.2)"
	fi
	getfattr -d -m - $testfile 2>&1 | grep security\.c &&
		error "listing xattrs on $testfile should not expose security.c"
	getfattr -d -m - $testfile 2>&1 | grep encryption\.c &&
	      error "listing xattrs on $testfile should not expose encryption.c"
	if [ $(setfattr -n security.c -v myval $testfile 2>&1 |
	       grep -ci "Operation not permitted") -eq 0 ]; then
		error "setting xattr on $testfile should have failed (2.1)"
	fi
	if [ $(setfattr -n encryption.c -v myval $testfile 2>&1 |
	       grep -ci "Operation not supported") -eq 0 ]; then
		error "setting xattr on $testfile should have failed (2.2)"
	fi
	return 0
}
run_test 57 "security.c/encryption.c xattr protection"

test_58() {
	local testdir=$DIR/$tdir/mytestdir
	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	touch $DIR/$tdir/$tfile
	mkdir $DIR/$tdir/subdir

	cancel_lru_locks
	sync ; sync
	echo 3 > /proc/sys/vm/drop_caches

	ll_decode_linkea $DIR/$tdir/$tfile || error "cannot read $tfile linkea"
	ll_decode_linkea $DIR/$tdir/subdir || error "cannot read subdir linkea"

	for ((i = 0; i < 1000; i = $((i+1)))); do
		mkdir -p $DIR/$tdir/d${i}
		touch $DIR/$tdir/f${i}
		createmany -m $DIR/$tdir/d${i}/f 5 > /dev/null
	done

	cancel_lru_locks
	sync ; sync
	echo 3 > /proc/sys/vm/drop_caches

	sleep 10
	ls -ailR $DIR/$tdir > /dev/null || error "fail to ls"
}
run_test 58 "access to enc file's xattrs"

verify_mirror() {
	local mirror1=$TMP/$tfile.mirror1
	local mirror2=$TMP/$tfile.mirror2
	local testfile=$1
	local reffile=$2

	$LFS mirror verify -vvv $testfile ||
		error "verifying mirror failed (1)"
	if [ $($LFS mirror verify -v $testfile 2>&1 |
		grep -ci "only valid") -ne 0 ]; then
		error "verifying mirror failed (2)"
	fi

	$LFS mirror read -N 1 -o $mirror1 $testfile ||
		error "read from mirror 1 failed"
	cmp -bl $reffile $mirror1 ||
		error "corruption of mirror 1"
	$LFS mirror read -N 2 -o $mirror2 $testfile ||
		error "read from mirror 2 failed"
	cmp -bl $reffile $mirror2 ||
		error "corruption of mirror 2"
}

test_59a() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/$tfile
	local mirror1=$TMP/$tfile.mirror1
	local mirror2=$TMP/$tfile.mirror2
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap "cleanup_for_enc_tests $tmpfile $mirror1 $mirror2" EXIT
	setup_for_enc_tests

	dd if=/dev/urandom of=$tmpfile bs=5000 count=1 conv=fsync

	$LFS mirror create -N -i0 -N -i1 $testfile ||
		error "could not create mirror"
	dd if=$tmpfile of=$testfile bs=5000 count=1 conv=fsync ||
		error "could not write to $testfile"
	$LFS getstripe $testfile

	# remount without dummy encryption key
	remount_client_normally

	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type f)
	$LFS mirror resync $scrambledfile ||
		error "could not resync mirror"

	$LFS mirror verify -vvv $scrambledfile ||
		error "mirror verify failed (1)"
	if [ $($LFS mirror verify -v $scrambledfile 2>&1 |
		grep -ci "only valid") -ne 0 ]; then
		error "mirror verify failed (2)"
	fi

	$LFS mirror read -N 1 -o $mirror1 $scrambledfile &&
		error "read from mirror should fail"

	# now, with the key
	remount_client_dummykey
	verify_mirror $testfile $tmpfile
}
run_test 59a "mirror resync of encrypted files without key"

test_59b() {
	local testfile=$DIR/$tdir/$tfile
	local tmpfile=$TMP/$tfile
	local mirror1=$TMP/$tfile.mirror1
	local mirror2=$TMP/$tfile.mirror2
	local scrambledfile

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $OSTCOUNT -lt 2 ]] && skip_env "needs >= 2 OSTs"

	stack_trap "cleanup_for_enc_tests $tmpfile $mirror1 $mirror2" EXIT
	setup_for_enc_tests

	tr '\0' '2' < /dev/zero |
		dd of=$tmpfile bs=1 count=9000 conv=fsync

	$LFS setstripe -c1 -i0 $testfile
	dd if=$tmpfile of=$testfile bs=9000 count=1 conv=fsync ||
		error "write to $testfile failed"
	$LFS getstripe $testfile

	# remount without dummy encryption key
	remount_client_normally

	scrambledfile=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type f)
	$LFS migrate -i1 $scrambledfile ||
		error "migrate $scrambledfile failed"
	$LFS getstripe $scrambledfile
	stripe=$($LFS getstripe -i $scrambledfile)
	[ $stripe -eq 1 ] || error "migrate file $scrambledfile failed"
	cancel_lru_locks

	# now, with the key
	remount_client_dummykey
	cmp -bl $tmpfile $testfile ||
		error "migrated file is corrupted"

	# remount without dummy encryption key
	remount_client_normally

	$LFS mirror extend -N -i0 $scrambledfile ||
		error "mirror extend $scrambledfile failed (1)"
	$LFS getstripe $scrambledfile
	mirror_count=$($LFS getstripe -N $scrambledfile)
	[ $mirror_count -eq 2 ] ||
		error "mirror extend file $scrambledfile failed (2)"
	stripe=$($LFS getstripe --mirror-id=1 -i $scrambledfile)
	[ $stripe -eq 1 ] ||
		error "mirror extend file $scrambledfile failed (3)"
	stripe=$($LFS getstripe --mirror-id=2 -i $scrambledfile)
	[ $stripe -eq 0 ] ||
		error "mirror extend file $scrambledfile failed (4)"

	$LFS mirror verify -vvv $scrambledfile ||
		error "mirror verify failed (1)"
	if [ $($LFS mirror verify -v $scrambledfile 2>&1 |
		grep -ci "only valid") -ne 0 ]; then
		error "mirror verify failed (2)"
	fi

	# now, with the key
	remount_client_dummykey
	verify_mirror $testfile $tmpfile

	# remount without dummy encryption key
	remount_client_normally

	$LFS mirror split --mirror-id 1 -d $scrambledfile ||
		error "mirror split file $scrambledfile failed (1)"
	$LFS getstripe $scrambledfile
	mirror_count=$($LFS getstripe -N $scrambledfile)
	[ $mirror_count -eq 1 ] ||
		error "mirror split file $scrambledfile failed (2)"
	stripe=$($LFS getstripe --mirror-id=1 -i $scrambledfile)
	[ -z "$stripe" ] || error "mirror split file $scrambledfile failed (3)"
	stripe=$($LFS getstripe --mirror-id=2 -i $scrambledfile)
	[ $stripe -eq 0 ] || error "mirror split file $scrambledfile failed (4)"

	# now, with the key
	remount_client_dummykey
	cancel_lru_locks
	cmp -bl $tmpfile $testfile ||
		error "extended/split file is corrupted"
}
run_test 59b "migrate/extend/split of encrypted files without key"

test_59c() {
	local dirname=$DIR/$tdir/subdir
	local scrambleddir

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	[[ $MDSCOUNT -ge 2 ]] || skip_env "needs >= 2 MDTs"

	(( "$MDS1_VERSION" > $(version_code 2.14.54.54) )) ||
		skip "MDT migration not supported with older server"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	$LFS setdirstripe -i 0 $dirname
	echo b > $dirname/subf

	# remount without dummy encryption key
	remount_client_normally

	scrambleddir=$(find $DIR/$tdir/ -maxdepth 1 -mindepth 1 -type d)

	# migrate a non-empty encrypted dir
	$LFS migrate -m 1 $scrambleddir ||
		error "migrate $scrambleddir between MDTs failed (1)"

	stripe=$($LFS getdirstripe -i $scrambleddir)
	[ $stripe -eq 1 ] ||
		error "migrate $scrambleddir between MDTs failed (2)"

	# now, with the key
	insert_enc_key
	[ -f $dirname/subf ] ||
	    error "migrate $scrambleddir between MDTs failed (3)"
	[ $(cat $dirname/subf) == "b" ] ||
	    error "migrate $scrambleddir between MDTs failed (4)"
}
run_test 59c "MDT migrate of encrypted files without key"

test_60() {
	local testdir=$DIR/$tdir/mytestdir
	local testfile=$DIR/$tdir/$tfile

	(( $MDS1_VERSION > $(version_code 2.14.53) )) ||
		skip "Need MDS version at least 2.14.53"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	echo a > $DIR/$tdir/file1
	mkdir $DIR/$tdir/subdir
	echo b > $DIR/$tdir/subdir/subfile1

	remove_enc_key
	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	# remount client with subdirectory mount
	export FILESET=/$tdir
	mount_client $MOUNT ${MOUNT_OPTS} || error "remount failed"
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} || error "remount failed"
	fi
	wait_ssk

	ls -Rl $DIR || error "ls -Rl $DIR failed (1)"

	# now, with the key
	remount_client_dummykey
	export FILESET=""

	ls -Rl $DIR || error "ls -Rl $DIR failed (2)"
	cat $DIR/file1 || error "cat $DIR/$tdir/file1 failed"
	cat $DIR/subdir/subfile1 ||
		error "cat $DIR/$tdir/subdir/subfile1 failed"
}
run_test 60 "Subdirmount of encrypted dir"

test_61() {
	local testfile=$DIR/$tdir/$tfile
	local readonly

	readonly=$(do_facet mgs \
			lctl get_param -n nodemap.default.readonly_mount)
	[ -n "$readonly" ] ||
		skip "Server does not have readonly_mount nodemap flag"

	stack_trap cleanup_local_client_nodemap EXIT
	for idx in $(seq 1 $MDSCOUNT); do
		wait_recovery_complete mds$idx
	done
	umount_client $MOUNT || error "umount $MOUNT failed (1)"

	# Activate nodemap, and mount rw.
	# Should succeed as rw mount is not forbidden by default.
	setup_local_client_nodemap "c0" 1 1
	readonly=$(do_facet mgs \
			lctl get_param -n nodemap.default.readonly_mount)
	[ $readonly -eq 0 ] ||
		error "wrong default value for readonly_mount on default nodemap"
	readonly=$(do_facet mgs \
			lctl get_param -n nodemap.c0.readonly_mount)
	[ $readonly -eq 0 ] ||
		error "wrong default value for readonly_mount on nodemap c0"

	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS},rw ||
		error "mount '-o rw' failed with default"
	wait_ssk
	findmnt $MOUNT --output=options -n -f | grep -q "rw," ||
		error "should be rw mount"
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo a > $testfile || error "write $testfile failed"
	umount_client $MOUNT || error "umount $MOUNT failed (2)"

	# Now enforce read-only, and retry.
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property readonly_mount --value 1
	wait_nm_sync c0 readonly_mount

	# mount without option should turn into ro
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS} ||
		error "mount failed (1)"
	findmnt $MOUNT --output=options -n -f | grep -q "ro," ||
		error "mount should have been turned into ro"
	cat $testfile || error "read $testfile failed (1)"
	echo b > $testfile && error "write $testfile should fail (1)"
	umount_client $MOUNT || error "umount $MOUNT failed (3)"

	# mount rw should turn into ro
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS},rw ||
		error "mount '-o rw' failed"
	findmnt $MOUNT --output=options -n -f | grep -q "ro," ||
		error "mount rw should have been turned into ro"
	cat $testfile || error "read $testfile failed (2)"
	echo b > $testfile && error "write $testfile should fail (2)"
	umount_client $MOUNT || error "umount $MOUNT failed (4)"

	# mount ro should work as expected
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS},ro ||
		error "mount '-o ro' failed"
	wait_ssk
	cat $testfile || error "read $testfile failed (3)"
	echo b > $testfile && error "write $testfile should fail (3)"
	umount_client $MOUNT || error "umount $MOUNT failed (5)"

	# remount rw should not work
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS} ||
		error "mount failed (2)"
	mount_client $MOUNT remount,rw || error "remount failed"
	findmnt $MOUNT --output=options -n -f | grep -q "ro," ||
		error "remount rw should have been turned into ro"
	cat $testfile || error "read $testfile failed (4)"
	echo b > $testfile && error "write $testfile should fail (4)"
	umount_client $MOUNT || error "umount $MOUNT failed (6)"
}
run_test 61 "Nodemap enforces read-only mount"

test_62() {
	local testdir=$DIR/$tdir/mytestdir
	local testfile=$DIR/$tdir/$tfile

	[[ $(facet_fstype ost1) == zfs ]] && skip "skip ZFS backend"

	(( $MDS1_VERSION > $(version_code 2.15.51) )) ||
		skip "Need MDS version at least 2.15.51"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	lfs setstripe -c -1 $DIR/$tdir
	touch $DIR/$tdir/${tfile}_1 || error "touch ${tfile}_1 failed"
	dd if=/dev/zero of=$DIR/$tdir/${tfile}_2 bs=1 count=1 conv=fsync ||
		error "dd ${tfile}_2 failed"

	# unmount the Lustre filesystem
	stopall || error "stopping for e2fsck run"

	# run e2fsck on the MDT and OST devices
	local mds_host=$(facet_active_host $SINGLEMDS)
	local ost_host=$(facet_active_host ost1)
	local mds_dev=$(mdsdevname ${SINGLEMDS//mds/})
	local ost_dev=$(ostdevname 1)

	run_e2fsck $mds_host $mds_dev "-n"
	run_e2fsck $ost_host $ost_dev "-n"

	# mount the Lustre filesystem
	setupall || error "remounting the filesystem failed"
}
run_test 62 "e2fsck with encrypted files"

create_files() {
	local path

	for path in "${paths[@]}"; do
		touch $path
	done
}

build_fids() {
	local path

	for path in "${paths[@]}"; do
		fids+=("$(lfs path2fid $path)")
	done
}

check_fids() {
	for fid in "${fids[@]}"; do
		echo $fid
		respath=$(lfs fid2path $MOUNT $fid)
		echo -e "\t" $respath
		ls -li $respath >/dev/null
		[ $? -eq 0 ] || error "fid2path $fid failed"
	done
}

test_63() {
	declare -a fids
	declare -a paths
	local vaultdir1=$DIR/$tdir/vault1==dir
	local vaultdir2=$DIR/$tdir/vault2==dir
	local longfname1="longfilenamewitha=inthemiddletotestbehaviorregardingthedigestedform"
	local longdname="longdirectorynamewitha=inthemiddletotestbehaviorregardingthedigestedform"
	local longfname2="$longdname/${longfname1}2"

	(( $MDS1_VERSION > $(version_code 2.15.53) )) ||
		skip "Need MDS version at least 2.15.53"

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	which fscrypt || skip "This test needs fscrypt userspace tool"

	yes | fscrypt setup --force --verbose ||
		echo "fscrypt global setup already done"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	yes | fscrypt setup --verbose $MOUNT ||
		echo "fscrypt setup $MOUNT already done"

	# enable_filename_encryption tunable only available for client
	# built against embedded llcrypt. If client is built against in-kernel
	# fscrypt, file names are always encrypted.
	$LCTL get_param mdc.*.connect_flags | grep -q name_encryption &&
	  nameenc=$(lctl get_param -n llite.*.enable_filename_encryption |
			head -n1)
	if [ -n "$nameenc" ]; then
		do_facet mgs $LCTL set_param -P \
			llite.*.enable_filename_encryption=1
		[ $? -eq 0 ] ||
			error "set_param -P \
				llite.*.enable_filename_encryption=1 failed"

		wait_update_facet --verbose client \
			"$LCTL get_param -n llite.*.enable_filename_encryption \
			| head -n1" 1 30 ||
			error "enable_filename_encryption not set on client"
	fi

	mkdir -p $vaultdir1
	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector_63_1 $vaultdir1 ||
		error "fscrypt encrypt $vaultdir1 failed"

	mkdir $vaultdir1/dirA
	mkdir $vaultdir1/$longdname
	paths=("$vaultdir1/fileA")
	paths+=("$vaultdir1/dirA/fileB")
	paths+=("$vaultdir1/$longfname1")
	paths+=("$vaultdir1/$longfname2")
	create_files

	paths+=("$vaultdir1/dirA")
	paths+=("$vaultdir1/$longdname")

	build_fids
	check_fids

	fscrypt lock --verbose $vaultdir1 ||
		error "fscrypt lock $vaultdir1 failed (1)"

	check_fids

	if [ -z "$nameenc" ]; then
		echo "Rest of the test requires disabling name encryption"
		exit 0
	fi

	# disable name encryption
	do_facet mgs $LCTL set_param -P llite.*.enable_filename_encryption=0
	[ $? -eq 0 ] ||
		error "set_param -P llite.*.enable_filename_encryption=0 failed"

	wait_update_facet --verbose client \
		"$LCTL get_param -n llite.*.enable_filename_encryption \
		| head -n1" 0 30 ||
		error "enable_filename_encryption not set back to default"

	mkdir -p $vaultdir2
	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
		--source=custom_passphrase --name=protector_63_2 $vaultdir2 ||
		error "fscrypt encrypt $vaultdir2 failed"

	mkdir $vaultdir2/dirA
	mkdir $vaultdir2/$longdname
	paths=()
	fids=()
	paths=("$vaultdir2/fileA")
	paths+=("$vaultdir2/dirA/fileB")
	paths+=("$vaultdir2/$longfname1")
	paths+=("$vaultdir2/$longfname2")
	create_files

	paths+=("$vaultdir2/dirA")
	paths+=("$vaultdir2/$longdname")

	build_fids
	check_fids

	fscrypt lock --verbose $vaultdir2 ||
		error "fscrypt lock $vaultdir2 failed (2)"

	check_fids

	rm -rf $MOUNT/.fscrypt
}
run_test 63 "fid2path with encrypted files"

test_64a() {
	local testfile=$DIR/$tdir/$tfile
	local srv_uc=""
	local local_admin=""
	local rbac

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	(( MDS1_VERSION >= $(version_code 2.16.52) )) &&
		local_admin="local_admin"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	setup_local_client_nodemap "c0" 1 1

	# check default value for rbac is all
	rbac=$(do_facet mds $LCTL get_param -n nodemap.c0.rbac)
	for role in file_perms \
		    dne_ops \
		    quota_ops \
		    byfid_ops \
		    chlg_ops \
		    fscrypt_admin \
		    $srv_uc \
		    $local_admin \
		    ;
	do
		[[ "$rbac" =~ "$role" ]] ||
			error "role '$role' not in default '$rbac'"
	done

	rbac="file_perms"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac
	touch $testfile
	stack_trap "set +vx"
	set -vx
	chmod 777 $testfile || error "chmod failed"
	chown $TSTUSR:$TSTUSR $testfile || error "chown failed"
	chgrp $TSTUSR $testfile || error "chgrp failed"
	$LFS project -p 1000 $testfile || error "setting project failed"
	set +vx
	rm -f $testfile
	rbac="none"
	if [ -z "$srv_uc" ]; then
		rbac="none"
	else
		rbac="$srv_uc"
	fi
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac
	touch $testfile
	set -vx
	chmod 777 $testfile && error "chmod should fail"
	chown $TSTUSR:$TSTUSR $testfile && error "chown should fail"
	chgrp $TSTUSR $testfile && error "chgrp should fail"
	$LFS project -p 1000 $testfile && error "setting project should fail"
	set +vx
}
run_test 64a "Nodemap enforces file_perms RBAC roles"

test_64b() {
	local testdir=$DIR/$tdir/${tfile}.d
	local dir_restripe
	local srv_uc=""
	local rbac

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDSCOUNT >= 2 )) || skip "mdt count $MDSCOUNT, skipping dne_ops role"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	setup_local_client_nodemap "c0" 1 1

        dir_restripe=$(do_node $mds1_HOST \
		"$LCTL get_param -n mdt.*MDT0000.enable_dir_restripe")
	[ -n "$dir_restripe" ] || dir_restripe=0
	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.enable_dir_restripe=1 ||
			error "enabling dir_restripe failed"
	stack_trap "do_nodes $(comma_list $(all_mdts_nodes)) \
	      $LCTL set_param mdt.*.enable_dir_restripe=$dir_restripe" EXIT
	rbac="dne_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		 --value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac
	$LFS mkdir -i 0 ${testdir}_for_migr ||
		error "$LFS mkdir ${testdir}_for_migr failed (1)"
	touch ${testdir}_for_migr/file001 ||
		error "touch ${testdir}_for_migr/file001 failed (1)"
	$LFS mkdir -i 0 ${testdir}_mdt0 ||
		error "$LFS mkdir ${testdir}_mdt0 failed (1)"
	$LFS mkdir -i 1 ${testdir}_mdt1 ||
		error "$LFS mkdir ${testdir}_mdt1 failed (1)"
	set -vx
	$LFS mkdir -i 1 $testdir || error "$LFS mkdir failed (1)"
	rmdir $testdir
	$LFS mkdir -c 2 $testdir || error "$LFS mkdir failed (2)"
	rmdir $testdir
	mkdir $testdir
	$LFS setdirstripe -c 2 $testdir || error "$LFS setdirstripe failed"
	rmdir $testdir
	$LFS migrate -m 1 ${testdir}_for_migr || error "$LFS migrate failed"
	touch ${testdir}_mdt0/fileA || error "touch fileA failed (1)"
	mv ${testdir}_mdt0/fileA ${testdir}_mdt1/ || error "mv failed (1)"
	set +vx
	rm -rf ${testdir}*
	$LFS mkdir -i 0 ${testdir}_for_migr ||
		error "$LFS mkdir ${testdir}_for_migr failed (2)"
	touch ${testdir}_for_migr/file001 ||
		error "touch ${testdir}_for_migr/file001 failed (2)"
	$LFS mkdir -i 0 ${testdir}_mdt0 ||
		error "$LFS mkdir ${testdir}_mdt0 failed (2)"
	$LFS mkdir -i 1 ${testdir}_mdt1 ||
		error "$LFS mkdir ${testdir}_mdt1 failed (2)"

	rbac="none"
	if [ -z "$srv_uc" ]; then
		rbac="none"
	else
		rbac="$srv_uc"
	fi
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac
	set -vx
	$LFS mkdir -i 1 $testdir && error "$LFS mkdir should fail (1)"
	$LFS mkdir -c 2 $testdir && error "$LFS mkdir should fail (2)"
	mkdir $testdir
	$LFS setdirstripe -c 2 $testdir && error "$LFS setdirstripe should fail"
	rmdir $testdir
	$LFS migrate -m 1 ${testdir}_for_migr &&
		error "$LFS migrate should fail"
	touch ${testdir}_mdt0/fileA || error "touch fileA failed (2)"
	mv ${testdir}_mdt0/fileA ${testdir}_mdt1/ || error "mv failed (2)"
	set +vx
}
run_test 64b "Nodemap enforces dne_ops RBAC roles"

test_64c() {
	local srv_uc=""
	local rbac

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	setup_local_client_nodemap "c0" 1 1

	rbac="quota_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac
	set -vx
	$LFS setquota -u $USER0 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT ||
		error "lfs setquota -u failed"
	$LFS setquota -u $USER0 --delete $MOUNT
	$LFS setquota -g $USER0 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT ||
		error "lfs setquota -g failed"
	$LFS setquota -g $USER0 --delete $MOUNT
	$LFS setquota -p 1000 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT ||
		error "lfs setquota -p failed"
	$LFS setquota -p 1000 --delete $MOUNT

	$LFS setquota -U -b 10G -B 11G -i 100K -I 105K $MOUNT ||
		error "lfs setquota -U failed"
	$LFS setquota -U -b 0 -B 0 -i 0 -I 0 $MOUNT
	$LFS setquota -G -b 10G -B 11G -i 100K -I 105K $MOUNT ||
		error "lfs setquota -G failed"
	$LFS setquota -G -b 0 -B 0 -i 0 -I 0 $MOUNT
	$LFS setquota -P -b 10G -B 11G -i 100K -I 105K $MOUNT ||
		error "lfs setquota -P failed"
	$LFS setquota -P -b 0 -B 0 -i 0 -I 0 $MOUNT
	$LFS setquota -u $USER0 -D $MOUNT ||
		error "lfs setquota -u -D failed"
	$LFS setquota -u $USER0 --delete $MOUNT
	$LFS setquota -g $USER0 -D $MOUNT ||
		error "lfs setquota -g -D failed"
	$LFS setquota -g $USER0 --delete $MOUNT
	$LFS setquota -p 1000 -D $MOUNT ||
		error "lfs setquota -p -D failed"
	$LFS setquota -p 1000 --delete $MOUNT
	set +vx

	rbac="none"
	if [ -z "$srv_uc" ]; then
		rbac="none"
	else
		rbac="$srv_uc"
	fi
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac

	set -vx
	$LFS setquota -u $USER0 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT &&
		error "lfs setquota -u should fail"
	$LFS setquota -u $USER0 --delete $MOUNT
	$LFS setquota -g $USER0 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT &&
		error "lfs setquota -g should fail"
	$LFS setquota -g $USER0 --delete $MOUNT
	$LFS setquota -p 1000 -b 307200 -B 309200 -i 10000 -I 11000 $MOUNT &&
		error "lfs setquota -p should fail"
	$LFS setquota -p 1000 --delete $MOUNT

	$LFS setquota -U -b 10G -B 11G -i 100K -I 105K $MOUNT &&
		error "lfs setquota -U should fail"
	$LFS setquota -G -b 10G -B 11G -i 100K -I 105K $MOUNT &&
		error "lfs setquota -G should fail"
	$LFS setquota -P -b 10G -B 11G -i 100K -I 105K $MOUNT &&
		error "lfs setquota -P should fail"
	$LFS setquota -u $USER0 -D $MOUNT &&
		error "lfs setquota -u -D should fail"
	$LFS setquota -u $USER0 --delete $MOUNT
	$LFS setquota -g $USER0 -D $MOUNT &&
		error "lfs setquota -g -D should fail"
	$LFS setquota -g $USER0 --delete $MOUNT
	$LFS setquota -p 1000 -D $MOUNT &&
		error "lfs setquota -p -D should fail"
	$LFS setquota -p 1000 --delete $MOUNT
	set +vx
}
run_test 64c "Nodemap enforces quota_ops RBAC roles"

test_64d() {
	local testfile=$DIR/$tdir/$tfile
	local srv_uc=""
	local rbac
	local fid

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	setup_local_client_nodemap "c0" 1 1

	rbac="byfid_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac

	touch $testfile
	fid=$(lfs path2fid $testfile)
	set -vx
	$LFS fid2path $MOUNT $fid || error "fid2path $fid failed (1)"
	cat $MOUNT/.lustre/fid/$fid || error "cat by fid failed"
	lfs rmfid $MOUNT $fid || error "lfs rmfid failed"
	set +vx

	rbac="none"
	if [ -z "$srv_uc" ]; then
		rbac="none"
	else
		rbac="$srv_uc"
	fi
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac

	touch $testfile
	fid=$(lfs path2fid $testfile)
	set -vx
	$LFS fid2path $MOUNT $fid || error "fid2path $fid failed (2)"
	cat $MOUNT/.lustre/fid/$fid && error "cat by fid should fail"
	lfs rmfid $MOUNT $fid && error "lfs rmfid should fail"
	set +vx
	rm -f $testfile
}
run_test 64d "Nodemap enforces byfid_ops RBAC roles"

test_64e() {
	local testfile=$DIR/$tdir/$tfile
	local testdir=$DIR/$tdir/${tfile}.d
	local srv_uc=""
	local rbac

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	setup_local_client_nodemap "c0" 1 1

	# activate changelogs
	changelog_register || error "changelog_register failed"
	local cl_user="${CL_USERS[$SINGLEMDS]%% *}"
	changelog_users $SINGLEMDS | grep -q $cl_user ||
		error "User $cl_user not found in changelog_users"
	changelog_chmask ALL

	# do some IOs
	mkdir $testdir || error "failed to mkdir $testdir"
	touch $testfile || error "failed to touch $testfile"

	rbac="chlg_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac

	# access changelogs
	echo "changelogs dump"
	changelog_dump || error "failed to dump changelogs"
	echo "changelogs clear"
	changelog_clear 0 || error "failed to clear changelogs"

	rm -rf $testdir $testfile || error "rm -rf $testdir $testfile failed"

	rbac="none"
	if [ -z "$srv_uc" ]; then
		rbac="none"
	else
		rbac="$srv_uc"
	fi
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac

	# do some IOs
	mkdir $testdir || error "failed to mkdir $testdir"
	touch $testfile || error "failed to touch $testfile"

	# access changelogs
	echo "changelogs dump"
	changelog_dump && error "dump changelogs should fail"
	echo "changelogs clear"
	changelog_clear 0 && error "clear changelogs should fail"
	rm -rf $testdir $testfile

	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property rbac --value all ||
		error "setting rbac all failed (3)"
	wait_nm_sync c0 rbac
}
run_test 64e "Nodemap enforces chlg_ops RBAC roles"

test_64f() {
	local vaultdir=$DIR/$tdir/vault
	local cli_enc
	local policy
	local protector
	local srv_uc=""
	local rbac

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	cli_enc=$($LCTL get_param mdc.*.import | grep client_encryption)
	[ -n "$cli_enc" ] || skip "Need enc support, skip fscrypt_admin role"
        which fscrypt || skip "Need fscrypt, skip fscrypt_admin role"

	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	echo "setup local client nodmap c0"
	setup_local_client_nodemap "c0" 1 1

	yes | fscrypt setup --force --verbose ||
		echo "fscrypt global setup already done"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	yes | fscrypt setup --verbose $MOUNT ||
		echo "fscrypt setup $MOUNT already done"
	echo "fscrypt for mount $MOUNT is ready for use"
	stack_trap "rm -rf $MOUNT/.fscrypt"

	# file_perms is required because fscrypt uses chmod/chown
	rbac="fscrypt_admin,file_perms"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (1)"
	echo "waiting for nodemap file_perms and fscrypt to be modified"
	wait_nm_sync c0 rbac

	mkdir -p $vaultdir
	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
	     --source=custom_passphrase --name=protector_64 $vaultdir ||
		error "fscrypt encrypt $vaultdir failed"
	fscrypt lock $vaultdir || error "fscrypt lock $vaultdir failed (1)"
	echo "$vaultdir is locked away with encryption"
	policy=$(fscrypt status $vaultdir | awk '$1 == "Policy:"{print $2}')
	[ -n "$policy" ] || error "could not get enc policy"
	echo "fscrypt policy $policy is ready"
	protector=$(fscrypt status $vaultdir |
		  awk 'BEGIN {found=0} { if (found == 1) { print $1 }} \
			$1 == "PROTECTOR" {found=1}')
	[ -n "$protector" ] || error "could not get enc protector"
	set +vx

	cancel_lru_locks
	# file_perms is required because fscrypt uses chmod/chown
	rbac="file_perms"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac

	set -vx
	echo mypass | fscrypt unlock $vaultdir ||
		error "fscrypt unlock $vaultdir failed"
	fscrypt lock $vaultdir || error "fscrypt lock $vaultdir failed (2)"
	fscrypt metadata destroy --protector=$MOUNT:$protector --force &&
		error "destroy protector should fail"
	fscrypt metadata destroy --policy=$MOUNT:$policy --force &&
		error "destroy policy should fail"
	mkdir -p ${vaultdir}2
	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
		--source=custom_passphrase \
		--name=protector_64bis ${vaultdir}2 &&
			error "fscrypt encrypt ${vaultdir}2 should fail"
	set +vx

	cancel_lru_locks
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property rbac  --value all ||
		error "setting rbac all failed (3)"
	wait_nm_sync c0 rbac

	set -vx
	fscrypt metadata destroy --protector=$MOUNT:$protector --force ||
		error "destroy protector failed"
	fscrypt metadata destroy --policy=$MOUNT:$policy --force ||
		error "destroy policy failed"
	set +vx

	rm -rf ${vaultdir}*
}
run_test 64f "Nodemap enforces fscrypt_admin RBAC roles"

test_64g() {
	local testfile=$DIR/$tdir/$tfile

	(( MDS1_VERSION >= $(version_code 2.16.50) )) ||
		skip "Need MDS >= 2.16.50 for role-based controls"

	# Add groups, and client to new group, on client only.
	# Server is not aware.
	groupadd -g 5000 grptest64g1
	stack_trap "groupdel grptest64g1" EXIT
	groupadd -g 5001 grptest64g2
	stack_trap "groupdel grptest64g2" EXIT
	groupadd -g 5002 grptest64g3
	stack_trap "groupdel grptest64g3" EXIT

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 750 $DIR/$tdir
	chgrp grptest64g1 $DIR/$tdir
	echo hi > $DIR/$tdir/fileA
	chmod 640 $DIR/$tdir/fileA
	chgrp grptest64g3 $DIR/$tdir/fileA
	setfacl -m g:grptest64g2:r $DIR/$tdir/fileA
	setfacl -m g:grptest64g2:rwx $DIR/$tdir
	ls -lR $DIR/$tdir

	setup_local_client_nodemap "c0" 1 1
	stack_trap cleanup_local_client_nodemap EXIT

	# remove server_upcall from rbac roles,
	# to make this client use INTERNAL upcall
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value file_perms ||
		error "setting rbac file_perms failed"
	wait_nm_sync c0 rbac

	$RUNAS touch $DIR/$tdir/fileB &&
		error "touch $DIR/$tdir/fileB should fail"
	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_int_flush=$RUNAS_ID
	$RUNAS -G 5001 touch $DIR/$tdir/fileB ||
		error "touch $DIR/$tdir/fileB failed"
	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_int_flush=$RUNAS_ID
	$RUNAS -G 5000,5001 touch $DIR/$tdir/fileC ||
		error "touch $DIR/$tdir/fileC failed"
	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_int_flush=$RUNAS_ID
	$RUNAS cat $DIR/$tdir/fileA && error "cat $DIR/$tdir/fileA should fail"
	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_int_flush=$RUNAS_ID
	$RUNAS -G 5000,5001 cat $DIR/$tdir/fileA ||
		error "cat $DIR/$tdir/fileA failed"
}
run_test 64g "Nodemap enforces server_upcall RBAC role"

test_64h() {
	local testfile=$DIR/$tdir/$tfile
	local offset_start=100000
	local offset_limit=200000
	local projid=1001
	local srv_uc=""
	local rbac
	local fid

	(( MDS1_VERSION >= $(version_code 2.15.54) )) ||
		skip "Need MDS >= 2.15.54 for role-based controls"

	(( MDS1_VERSION >= $(version_code 2.16.50) )) &&
		srv_uc="server_upcall"

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	stack_trap \
	    "$LFS setquota -p $((projid+offset_start)) --delete $DIR/$tdir" EXIT
	stack_trap cleanup_local_client_nodemap EXIT
	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chmod 777 $DIR/$tdir
	$LFS project -p $((projid+offset_start)) -s $DIR/$tdir
	$LFS setquota -p $((projid+offset_start)) -b 1G -B 1G $DIR/$tdir
	$LFS project -d $DIR/$tdir
	$LFS quota -aph $DIR/$tdir
	setup_local_client_nodemap "c0" 1 1

	# skip test if server does not support local_admin rbac role
	rbac=$(do_facet mds $LCTL get_param -n nodemap.c0.rbac)
	[[ "$rbac" =~ "local_admin" ]] ||
		skip "server does not support 'local_admin' rbac role"

	# Let's offset ids. Even root is offset.
	do_facet mgs $LCTL nodemap_add_offset --name c0 \
		--offset $offset_start --limit $offset_limit ||
			error "cannot set offset for c0"

	rbac="file_perms,quota_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (1)"
	wait_nm_sync c0 rbac

	$RUNAS touch $testfile

	# Without local_admin, root capabilities are dropped
	chmod o+x $testfile && error "root chmod should fail (1)"
	# and setquota/lfs project is not permitted
	$LFS setquota -p $projid -b 4G -B 4G $DIR/$tdir &&
		error "setquota should fail (1)"
	$LFS project -p $((projid+1)) -s $DIR/$tdir &&
		error "setting projid should fail (1)"

	rbac="file_perms,quota_ops,local_admin"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property rbac --value $rbac ||
		error "setting rbac $rbac failed (2)"
	wait_nm_sync c0 rbac
	# squash root by setting admin=0
	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property admin --value 0
	wait_nm_sync c0 admin_nodemap

	# Even with local_admin, capabilities are dropped if root is squashed
	chmod o+x $testfile && error "root chmod should fail (2)"
	# and setquota/lfs project is not permitted
	$LFS setquota -p $projid -b 4G -B 4G $DIR/$tdir &&
		error "setquota should fail (2)"
	$LFS project -p $((projid+1)) -s $DIR/$tdir &&
		error "setting projid should fail (2)"

	do_facet mgs $LCTL nodemap_modify --name c0 \
		 --property admin --value 1
	wait_nm_sync c0 admin_nodemap

	#  with local_admin and admin=1, capabilities are kept
	chmod o+x $testfile || error "root chmod failed (1)"
	# and setquota/lfs project is permitted
	$LFS setquota -p $projid -b 4G -B 4G $DIR/$tdir ||
		error "setquota failed (1)"
	$LFS project -p $((projid+1)) -s $DIR/$tdir ||
		error "setting projid failed (1)"

	# remove offset and local_admin but keep admin, so that root
	# on client is root on file system side
	do_facet mgs $LCTL nodemap_del_offset --name c0 ||
		error "cannot del offset for c0"
	rbac="file_perms,quota_ops"
	[ -z "$srv_uc" ] || rbac="$rbac,$srv_uc"
	do_facet mgs $LCTL nodemap_modify --name c0 --property rbac \
		--value $rbac ||
		error "setting rbac $rbac failed (3)"
	wait_nm_sync c0 rbac

	#  as root, capabilities are kept even without local_admin
	chmod g+x $testfile || error "root chmod failed (2)"
	# and setquota/lfs project is permitted
	$LFS setquota -p $((projid+offset_start)) -b 3G -B 3G $DIR/$tdir ||
		error "setquota failed (2)"
	$LFS project -p $((projid+offset_start)) -s $DIR/$tdir ||
		error "setting projid failed (2)"
}
run_test 64h "Nodemap enforces local_admin RBAC roles"

look_for_files() {
	local pattern=$1
	local neg=$2
	local path=$3
	local expected=$4
	local res

	(( neg == 1 )) || neg=""
	$LFS find -type f ${neg:+"!"} --attrs $pattern $path > $TMP/res
	cat $TMP/res
	res=$(cat $TMP/res | wc -l)
	(( res == $expected )) ||
		error "Find $pattern $path: found $res, expected $expected"
}

test_65() {
	local dirbis=$DIR/${tdir}_bis
	local testfile=$DIR/$tdir/$tfile
	local res

	$LCTL get_param mdc.*.import | grep -q client_encryption ||
		skip "client encryption not supported"

	mount.lustre --help |& grep -q "test_dummy_encryption:" ||
		skip "need dummy encryption support"

	# $dirbis is not going to be encrypted, as client
	# is not mounted with -o test_dummy_encryption yet
	mkdir $dirbis
	stack_trap "rm -rf $dirbis" EXIT
	touch $dirbis/$tfile.1
	touch $dirbis/$tfile.2
	chattr +i $dirbis/$tfile.2
	stack_trap "chattr -i $dirbis/$tfile.2" EXIT

	stack_trap cleanup_for_enc_tests EXIT
	setup_for_enc_tests

	# All files/dirs under $DIR/$tdir are encrypted
	touch $testfile.1
	touch $testfile.2
	chattr +i $testfile.2
	stack_trap "chattr -i $testfile.2" EXIT

	$LFS find -printf "%p %LA\n" $dirbis/$tfile.1
	res=$($LFS find -printf "%LA" $dirbis/$tfile.1)
	[ "$res" == "---" ] ||
		error "$dirbis/$tfile.1 should have no attr, showed $res (1)"
	$LFS find -printf "%p %La\n" $dirbis/$tfile.1
	res=$($LFS find -printf "%La" $dirbis/$tfile.1)
	[ "$res" == "---" ] ||
		error "$dirbis/$tfile.1 should have no attr, showed $res (2)"
	$LFS find -printf "%p %LA\n" $dirbis/$tfile.2
	res=$($LFS find -printf "%LA" $dirbis/$tfile.2)
	[ "$res" == "Immutable" ] ||
		error "$dirbis/$tfile.2 should be Immutable, showed $res"
	$LFS find -printf "%p %La\n" $dirbis/$tfile.2
	res=$($LFS find -printf "%La" $dirbis/$tfile.2)
	[ "$res" == "i" ] ||
		error "$dirbis/$tfile.2 should be 'i', showed $res"
	$LFS find -printf "%p %LA\n" $testfile.1
	res=$($LFS find -printf "%LA" $testfile.1)
	[ "$res" == "Encrypted" ] ||
		error "$testfile.1 should be Encrypted, showed $res"
	$LFS find -printf "%p %La\n" $testfile.1
	res=$($LFS find -printf "%La" $testfile.1)
	[ "$res" == "E" ] ||
		error "$testfile.1 should be 'E', showed $res"
	$LFS find -printf "%p %LA\n" $testfile.2
	res=$($LFS find -printf "%LA" $testfile.2)
	[ "$res" == "Immutable,Encrypted" ] ||
		error "$testfile.2 should be Immutable,Encrypted, showed $res"
	$LFS find -printf "%p %La\n" $testfile.2
	res=$($LFS find -printf "%La" $testfile.2)
	[ "$res" == "iE" ] ||
		error "$testfile.2 should be 'iE', showed $res"

	echo Expecting to find 2 encrypted files
	look_for_files Encrypted 0 "$DIR/${tdir}*" 2
	echo Expecting to find 2 encrypted files
	look_for_files E 0 "$DIR/${tdir}*" 2

	echo Expecting to find 2 non-encrypted files
	look_for_files Encrypted 1 "$DIR/${tdir}*" 2
	echo Expecting to find 2 non-encrypted files
	look_for_files E 1 "$DIR/${tdir}*" 2

	echo Expecting to find 1 encrypted+immutable file
	look_for_files "Encrypted,Immutable" 0 "$DIR/${tdir}*" 1
	echo Expecting to find 1 encrypted+immutable file
	look_for_files "Ei" 0 "$DIR/${tdir}*" 1

	echo Expecting to find 1 encrypted+^immutable file
	look_for_files "Encrypted,^Immutable" 0 "$DIR/${tdir}*" 1
	echo Expecting to find 1 encrypted+^immutable file
	look_for_files "E^i" 0 "$DIR/${tdir}*" 1

	echo Expecting to find 1 ^encrypted+immutable file
	look_for_files "^Encrypted,Immutable" 0 "$DIR/${tdir}*" 1
	echo Expecting to find 1 ^encrypted+immutable file
	look_for_files "^Ei" 0 "$DIR/${tdir}*" 1

	echo Expecting to find 1 ^encrypted+^immutable file
	look_for_files "^Encrypted,^Immutable" 0 "$DIR/${tdir}*" 1
	echo Expecting to find 1 ^encrypted+^immutable file
	look_for_files "^E^i" 0 "$DIR/${tdir}*" 1
}
run_test 65 "lfs find -printf %La and --attrs support"

cleanup_68() {
	lctl set_param fail_loc=0 fail_val=0
	mount_client $MOUNT ${MOUNT_OPTS} || error "re-mount $MOUNT failed"
	if is_mounted $MOUNT2; then
		mount_client $MOUNT2 ${MOUNT_OPTS} ||
			error "re-mount $MOUNT2 failed"
	fi
}

test_68() {
	stack_trap cleanup_68 EXIT

	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	#define CFS_FAIL_ONCE|OBD_FAIL_PTLRPC_DROP_MGS    0x51d
	lctl set_param fail_loc=0x8000051d fail_val=20

	zconf_mount_clients $HOSTNAME $MOUNT $MOUNT_OPTS ||
		error "mount failed"

	umount_client $MOUNT || error "re-umount $MOUNT failed"
}
run_test 68 "all config logs are processed"

test_69() {
	local mdt="$(mdtname_from_index 0 $MOUNT)"
	local param
	local orig

	(( MDS1_VERSION >= $(version_code v2_15_61-210-g2153e86541) )) ||
		skip "need MDS >= 2.15.61.210 for upcall sanity checking"

	param="mdt.$mdt.identity_upcall"
	orig="$(do_facet mds1 "$LCTL get_param -n $param")"
	stack_trap "do_facet mds1 $LCTL set_param $param=$orig" EXIT

	# identity_upcall accepts an absolute path to an executable,
	# or NONE (case insensitive)
	do_facet mds1 $LCTL set_param $param=/path/to/prog ||
		error "set_param $param=/path/to/prog failed (1)"
	do_facet mds1 $LCTL set_param $param=prog &&
		error "set_param $param=prog should fail (1)"
	do_facet mds1 $LCTL set_param $param=NONE ||
		error "set_param $param=NONE failed (1)"
	do_facet mds1 $LCTL set_param $param=none ||
		error "set_param $param=none failed (1)"

	if $GSS; then
		param="sptlrpc.gss.rsi_upcall"
		orig="$(do_facet mds1 "$LCTL get_param -n $param")"
		stack_trap "do_facet mds1 $LCTL set_param $param=$orig" EXIT

		# rsi_upcall only accepts an absolute path to an executable
		do_facet mds1 $LCTL set_param $param=prog &&
			error "set_param $param=prog should fail (2)"
		do_facet mds1 $LCTL set_param $param=NONE &&
			error "set_param $param=NONE should fail (2)"
		do_facet mds1 $LCTL set_param $param=/path/to/prog ||
			error "set_param $param=/path/to/prog failed (2)"
	fi
}
run_test 69 "check upcall incorrect values"

test_70() {
	local param_mgs=$(mktemp $TMP/$tfile-mgs.XXXXXX)
	local param_copy=$(mktemp $TMP/$tfile-copy.XXXXXX)

	stack_trap "rm -f $param_mgs $param_copy" EXIT

	(( $MDS1_VERSION > $(version_code 2.15.61) )) ||
		skip "Need MDS version at least 2.15.61"

	if ! $SHARED_KEY; then
		skip "need shared key feature for this test"
	fi

	[[ "$ost1_FSTYPE" == ldiskfs ]] ||
		skip "ldiskfs only test (using debugfs)"

	# unmount then remount the Lustre filesystem, to make sure llogs
	# are copied locally
	export SK_NO_KEY=false
	stopall || error "stopall failed"
	init_gss
	mountmgs || error "mountmgs failed"
	mountmds || error "mountmds failed"
	mountoss || error "mountoss failed"
	mountcli || error "mountcli failed"
	lfs df -h
	unset SK_NO_KEY

	do_facet mgs "sync ; sync"
	do_facet mgs "$DEBUGFS -c -R 'ls CONFIGS/' $(mgsdevname)"
	do_facet mgs "$DEBUGFS -c -R 'dump CONFIGS/$FSNAME-sptlrpc $param_mgs' \
		$(mgsdevname)"
	do_facet mgs "llog_reader $param_mgs" | grep -vE "SKIP|marker" |
		grep "^#" > $param_mgs
	cat $param_mgs

	if ! combined_mgs_mds; then
		do_facet mds1 "sync ; sync"
		do_facet mds1 "$DEBUGFS -c -R 'ls CONFIGS/' $(mdsdevname 1)"
		do_facet mds1 "$DEBUGFS -c -R 'dump CONFIGS/$FSNAME-sptlrpc \
			$param_copy' $(mdsdevname 1)"
		do_facet mds1 "llog_reader $param_copy" |
			grep -vE "SKIP|marker" | grep "^#" > $param_copy
		cat $param_copy
		cmp -bl $param_mgs $param_copy ||
			error "sptlrpc llog differ in mds"
		rm -f $param_copy
	fi

	do_facet ost1 "sync ; sync"
	do_facet ost1 "$DEBUGFS -c -R 'ls CONFIGS/' $(ostdevname 1)"
	do_facet ost1 "$DEBUGFS -c -R 'dump CONFIGS/$FSNAME-sptlrpc \
		$param_copy' $(ostdevname 1)"
	do_facet ost1 "llog_reader $param_copy" | grep -vE "SKIP|marker" |
		grep "^#" > $param_copy
	cat -A $param_copy
	cmp -bl $param_mgs $param_copy ||
		error "sptlrpc llog differ at ost1"
	rm -f $param_copy

	do_facet ost2 "sync ; sync"
	do_facet ost2 "$DEBUGFS -c -R 'ls CONFIGS/' $(ostdevname 2)"
	do_facet ost2 "$DEBUGFS -c -R 'dump CONFIGS/$FSNAME-sptlrpc \
		$param_copy' $(ostdevname 2)"
	do_facet ost2 "llog_reader $param_copy" | grep -vE "SKIP|marker" |
		grep "^#" > $param_copy
	cat -A $param_copy
	cmp -bl $param_mgs $param_copy ||
		error "sptlrpc llog differ at ost2"
}
run_test 70 "targets have local copy of sptlrpc llog"

test_71() {
	local vaultdir=$DIR/$tdir/vault
	local projid=101
	local res

	(( $MDS1_VERSION >= $(version_code 2.15.63) )) ||
		skip "Need MDS version at least 2.15.63"

	[[ $($LCTL get_param mdc.*.import) =~ client_encryption ]] ||
		skip "need encryption support"
	which fscrypt || skip_env "Need fscrypt"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	yes | fscrypt setup --force --verbose ||
		echo "fscrypt global setup already done"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	yes | fscrypt setup --verbose $MOUNT ||
		echo "fscrypt setup $MOUNT already done"
	stack_trap "rm -rf $MOUNT/.fscrypt"

	mkdir -p $vaultdir
	stack_trap "rm -rf $vaultdir"
	$LFS project -p $projid -s $vaultdir
	$LFS project -d $vaultdir
	res=$($LFS project -d $vaultdir | awk '{print $1}')
	[[ "$res" == "$projid" ]] ||
		error "project id set to $res instead of $projid"
	res=$($LFS project -d $vaultdir | awk '{print $2}')
	[[ "$res" == "P" ]] ||
		error "project id should have inherit flag (1)"

	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
	     --source=custom_passphrase --name=protector_71 $vaultdir ||
		error "fscrypt encrypt $vaultdir failed"

	$LFS project -d $vaultdir
	res=$($LFS project -d $vaultdir | awk '{print $1}')
	[[ "$res" == "$projid" ]] ||
		error "project id changed to $res after enc"
	res=$($LFS project -d $vaultdir | awk '{print $2}')
	[[ "$res" == "P" ]] ||
		error "project id should have inherit flag (2)"

	touch $vaultdir/fileA || error "touch $vaultdir/fileA failed"
	$LFS project $vaultdir/fileA
	res=$($LFS project $vaultdir/fileA | awk '{print $1}')
	[[ "$res" == "$projid" ]] ||
		error "project id on fileA is $res after enc"

	mkdir $vaultdir/dirA || error "touch $vaultdir/dirA failed"
	$LFS project -d $vaultdir/dirA
	res=$($LFS project -d $vaultdir/dirA | awk '{print $1}')
	[[ "$res" == "$projid" ]] ||
		error "project id on dirA is $res after enc"
	res=$($LFS project -d $vaultdir/dirA | awk '{print $2}')
	[[ "$res" == "P" ]] ||
		error "project id should have inherit flag (3)"
}
run_test 71 "encryption does not remove project flag"

dyn_nm_helper() {
	local facet=$1
	local mgsnm=mgsnm
	local mgsnids=1.1.0.[1-100]@tcp
	local mgsnids2=1.0.0.[1-100]@tcp
	local mgsclid=600
	local mgsfsid=2000
	local nm=nm_test72
	local nids=1.1.1.[1-100]@tcp
	local startnid=1.1.1.1@tcp
	local endnid=1.1.1.100@tcp
	local subnids1=1.1.1.[2-50]@tcp
	local subnids2=1.1.1.[51-100]@tcp
	local subnids3=1.1.1.[2-25]@tcp
	local subnids4=1.1.1.[51-52]@tcp
	local subnids5=1.1.1.[26-60]@tcp
	local subnids6=1.1.1.[1-60]@tcp
	local clid=500
	local fsid=1000
	local properties="audit_mode deny_unknown forbid_encryption \
			  readonly_mount"
	local sepol="1:mls:31:40afb76d077c441b69af58cccaaa2ca63641ed6e21b0a887dc21a684f508b78f"
	local rbac_val
	local raise
	local val

	activedefault=$(do_facet mgs $LCTL get_param -n nodemap.active)
	if [[ "$activedefault" != "1" ]]; then
		do_facet mgs $LCTL nodemap_activate 1
		wait_nm_sync active
		stack_trap cleanup_active EXIT
	fi

	do_facet mgs $LCTL nodemap_set_fileset --name default \
		--fileset "/deffset" ||
			error "setting fileset on default failed"
	raise=$(do_facet mgs $LCTL get_param -n \
		nodemap.default.child_raise_privileges)
	if [[ -n "$raise" ]]; then
		do_facet mgs $LCTL nodemap_modify --name default \
		    --property child_raise_privileges --value all ||
		       error "modify raise_privileges for default on MGS failed"
		wait_nm_sync default child_raise_privileges
		stack_trap "do_facet mgs $LCTL nodemap_modify --name default \
			--property child_raise_privileges --value $raise" EXIT
	fi

	do_facet mgs $LCTL nodemap_add $mgsnm ||
		error "adding $mgsnm on MGS failed"
	stack_trap "do_facet mgs $LCTL nodemap_del $mgsnm" EXIT
	do_facet mgs $LCTL nodemap_add_range --name $mgsnm --range $mgsnids ||
		error "add_range for $mgsnm on MGS failed"
	do_facet mgs $LCTL nodemap_add_idmap --name $mgsnm --idtype uid \
		--idmap $mgsclid:$mgsfsid ||
		error "add_idmap for $mgsnm on MGS failed"
	wait_nm_sync $mgsnm idmap

	rbac_val=$(do_facet mgs $LCTL get_param -n nodemap.$mgsnm.rbac)

	stack_trap "do_facet $facet $LCTL nodemap_del $nm || true" EXIT
	if [[ "$(facet_active_host mgs)" != \
			"$(facet_active_host $facet)" ]]; then
		do_facet $facet $LCTL nodemap_add $nm &&
			error "static nodemap on server should fail"
	fi
	do_facet $facet $LCTL nodemap_add -d $nm &&
		error "dynamic nodemap without parent should fail"
	do_facet $facet $LCTL nodemap_add -d -p default $nm ||
		error "dynamic nodemap on server failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.id)
	if [[ -z "$val" || "$val" == "0" ]]; then
		error "dynamic nodemap wrong id $val"
	fi

	do_facet $facet $LCTL nodemap_add_range --name $nm --range $nids ||
		error "dynamic add_range on server failed"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.ranges |
		awk 'BEGIN{RS=", "} $1=="start_nid:"{print $2 ; exit}')
	[[ "$val" == "$startnid" ]] ||
		error "dynamic nodemap wrong start nid range $val"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.ranges |
		awk 'BEGIN{RS=", "} $1=="end_nid:"{print $2 ; exit}')
	[[ "$val" == "$endnid" ]] ||
		error "dynamic nodemap wrong end nid range $val"

	do_facet $facet $LCTL nodemap_add_idmap --name $nm --idtype uid \
		--idmap $clid:$fsid ||
			error "dynamic add_idmap on server failed"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.idmap |
		awk 'BEGIN{RS=", "} $1=="client_id:"{print $2 ; exit}')
	(( val == clid )) || error "dynamic nodemap wrong client id $val"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.idmap |
		awk 'BEGIN{RS=", "} $1=="fs_id:"{print $2 ; exit}')
	(( val == fsid )) || error "dynamic nodemap wrong fs id $val"

	for prop in $properties; do
		do_facet $facet $LCTL nodemap_modify --name $nm \
			--property $prop --value 1 ||
				error "dynamic modify of $prop failed"
		val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
		(( val == 1 )) || error "incorrect $prop $val"
	done
	prop=admin
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value 1 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.admin_nodemap)
	(( val == 1 )) || error "incorrect $prop $val"
	prop=trusted
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value 0 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.trusted_nodemap)
	(( val == 0 )) || error "incorrect $prop $val"
	prop=map_mode
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value uid ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	[[ "$val" == "uid" ]] || error "incorrect $prop $val"
	prop=rbac
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value file_perms ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	[[ "$val" == "file_perms" ]] || error "incorrect $prop $val"
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value all ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	[[ "$val" == "$rbac_val" ]] || error "incorrect $prop $val"
	prop=squash_uid
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value 77 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	(( val == 77 )) || error "incorrect $prop $val"
	prop=squash_gid
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value 77 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	(( val == 77 )) || error "incorrect $prop $val"
	prop=squash_projid
	do_facet $facet $LCTL nodemap_modify --name $nm \
		--property $prop --value 77 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	(( val == 77 )) || error "incorrect $prop $val"
	prop=fileset
	do_facet $facet $LCTL nodemap_set_fileset --name $nm \
		--fileset "/tmp" &&
			error "dynamic modify of $prop should fail"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	[[ "$val" == "/deffset" ]] || error "incorrect $prop $val"
	prop=sepol
	do_facet $facet $LCTL nodemap_set_sepol --name $nm \
		--sepol $sepol ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop)
	[[ "$val" == "$sepol" ]] || error "incorrect $prop $val"

	prop=offset
	do_facet $facet $LCTL nodemap_add_offset --name $nm \
		--offset 100000 --limit 200000 ||
			error "dynamic modify of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop |
		awk '$1 == "start_uid:" {print $2}' | sed s+,++)
	(( val == 100000 )) || error "incorrect $prop start_uid $val"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop |
		awk '$1 == "limit_uid:" {print $2}' | sed s+,++)
	(( val == 200000 )) || error "incorrect $prop limit_uid $val"
	do_facet $facet $LCTL nodemap_del_offset --name $nm ||
			error "dynamic del of $prop failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop |
		awk '$1 == "start_uid:" {print $2}' | sed s+,++)
	(( val == 0 )) || error "incorrect $prop start_uid $val"
	val=$(do_facet $facet $LCTL get_param -n nodemap.$nm.$prop |
		awk '$1 == "limit_uid:" {print $2}' | sed s+,++)
	(( val == 0 )) || error "incorrect $prop limit_uid $val"

	val=$(do_facet $facet $LCTL nodemap_test_id --nid $startnid \
		--idtype uid --id $clid)
	(( val == fsid )) || error "dynamic test_id on server failed"

	do_facet $facet $LCTL nodemap_del_idmap --name $nm --idtype uid \
		--idmap $clid:$fsid ||
			error "dynamic del_idmap on server failed"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.idmap |
		awk 'BEGIN{RS=", "} $1=="client_id:"{print $2 ; exit}')
	[[ -z "$val" ]] || error "idmap should be empty, got $val"

	val=$(do_facet $facet $LCTL nodemap_test_nid $startnid)
	[[ "$val" == "$nm" ]] || error "dynamic test_nid on server failed"

	do_facet $facet $LCTL nodemap_add -d -p $nm ${nm}_1 ||
		error "nodemap add ${nm}_1 on server failed"
	stack_trap "do_facet $facet $LCTL nodemap_del ${nm}_1 || true" EXIT
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_1 \
		--range $subnids1 ||
			error "add_range for ${nm}_1 failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.${nm}_1.parent)
	[[ "$val" == "$nm" ]] ||
		error "parent of ${nm}_1 should be $nm, got $val"

	do_facet $facet $LCTL nodemap_add -d -p $nm ${nm}_2 ||
		error "nodemap add ${nm}_2 on server failed"
	stack_trap "do_facet $facet $LCTL nodemap_del ${nm}_2 || true" EXIT
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_2 \
		--range $subnids2 ||
			error "add_range for ${nm}_2 failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.${nm}_2.parent)
	[[ "$val" == "$nm" ]] ||
		error "parent of ${nm}_2 should be $nm, got $val"

	do_facet $facet $LCTL nodemap_add -d -p ${nm}_1 ${nm}_3 ||
		error "nodemap add ${nm}_3 on server failed"
	stack_trap "do_facet $facet $LCTL nodemap_del ${nm}_3 || true" EXIT
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_3 \
		--range $subnids4 &&
		       error "nodemap ${nm}_3 should not accept range $subnids4"
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_3 \
		--range $subnids5 &&
		       error "nodemap ${nm}_3 should not accept range $subnids5"
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_3 \
		--range $subnids6 &&
		       error "nodemap ${nm}_3 should not accept range $subnids6"
	do_facet $facet $LCTL nodemap_add_range --name ${nm}_3 \
		--range $subnids3 ||
			error "add_range $subnids3 for ${nm}_3 failed"
	val=$(do_facet $facet $LCTL get_param -n nodemap.${nm}_3.parent)
	[[ "$val" == "${nm}_1" ]] ||
		error "parent of ${nm}_3 should be ${nm}_1, got $val"
	val=$(do_facet $facet $LCTL get_param -n nodemap.${nm}_3.squash_projid)
	(( val == 77 )) || error "squash_projid should be inherited, got $val"

	do_facet $facet $LCTL nodemap_del_range --name $nm --range $nids ||
		error "dynamic del_range on server failed"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.ranges |
		awk 'BEGIN{RS=", "} $1=="start_nid:"{print $2 ; exit}')
	[[ -z "$val" ]] || error "nid range should be empty, got $val"

	do_facet $facet $LCTL nodemap_del $nm ||
		error "dynamic nodemap del on server failed"
	val=$(do_facet $facet $LCTL get_param nodemap.$nm.id)
	[[ -z "$val" ]] || error "nodemap should be gone, got $val"

	if [[ "$(facet_active_host mgs)" != \
			"$(facet_active_host $facet)" ]]; then
		do_facet $facet $LCTL nodemap_add_range --name $mgsnm \
			--range $mgsnids2 &&
				error "add_range $mgsnm on server should fail"
		do_facet $facet $LCTL nodemap_del_range --name $mgsnm \
			--range $mgsnids &&
				error "del_range $mgsnm on server should fail"
		do_facet $facet $LCTL nodemap_add_idmap --name $mgsnm \
			--idtype gid --idmap $mgsclid:$mgsfsid &&
				error "add_idmap $mgsnm on server should fail"
		do_facet $facet $LCTL nodemap_del_idmap --name $mgsnm \
			--idtype uid --idmap $mgsclid:$mgsfsid &&
				error "del_idmap $mgsnm on server should fail"
		do_facet $facet $LCTL nodemap_modify --name $mgsnm \
			--property squash_projid --value 77 &&
				error "modify $mgsnm on server should fail"
		do_facet $facet $LCTL nodemap_del $mgsnm &&
			error "nodemap del $mgsnm on server should fail"
	fi
	do_facet $facet $LCTL get_param -R 'nodemap.*'
}

test_72a() {
	(( OST1_VERSION >= $(version_code 2.15.64) )) ||
		skip "Need MDS >= 2.15.64 dynamic nodemaps"

	[[ "$(facet_active_host mgs)" != "$(facet_active_host ost1)" ]] ||
		skip "Need servers on different hosts"

	dyn_nm_helper ost1
}
run_test 72a "dynamic nodemap properties on OSS"

test_72b() {
	(( MDS1_VERSION >= $(version_code 2.15.64) )) ||
		skip "Need MDS >= 2.15.64 dynamic nodemaps"

	dyn_nm_helper mds1
}
run_test 72b "dynamic nodemap properties on MDS"

test_72c() {
	local mgsnm=mgsnm
	local nm=nm_test72c
	local val

	(( MDS1_VERSION >= $(version_code 2.16.52) )) ||
		skip "Need MDS >= 2.16.52 dynamic nodemaps"

	do_facet mgs $LCTL nodemap_add $mgsnm ||
		error "adding $mgsnm on MGS failed"
	stack_trap "do_facet mgs $LCTL nodemap_del $mgsnm" EXIT

	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property child_raise_privileges --value trusted ||
		error "modify raise_privileges for $mgsnm on MGS failed (1)"
	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property admin --value 0 ||
		error "modify admin for $mgsnm on MGS failed"
	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property trusted --value 0 ||
		error "modify trusted for $mgsnm on MGS failed"
	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property deny_unknown --value 0 ||
		error "modify deny_unknown for $mgsnm on MGS failed"
	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property readonly_mount --value 0 ||
		error "modify readonly_mount for $mgsnm on MGS failed"
	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property rbac --value file_perms,quota_ops,byfid_ops ||
		error "modify rbac for $mgsnm on MGS failed"
	wait_nm_sync $mgsnm rbac '' inactive

	do_facet mds1 $LCTL nodemap_add -d -p $mgsnm $nm ||
		error "dynamic nodemap on server failed (1)"
	stack_trap "do_facet mds1 $LCTL nodemap_del $nm || true" EXIT
	val=$(do_facet mds1 $LCTL get_param -n nodemap.$nm.id)
	if [[ -z "$val" || "$val" == "0" ]]; then
		error "dynamic nodemap wrong id $val (1)"
	fi
	val=$(do_facet mds1 $LCTL get_param -n \
		nodemap.$nm.child_raise_privileges)
	[[ $val == "trusted" ]] ||
		error "dyn nodemap should inherit child_raise_privileges"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
		--property admin --value 1 &&
		error "modify admin for $nm on mds1 should fail"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
		--property trusted --value 1 ||
		error "modify trusted for $nm on mds1 failed"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
		--property deny_unknown --value 1 ||
		error "modify deny_unknown for $nm on mds1 failed"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
		--property readonly_mount --value 1 ||
		error "modify readonly_mount for $nm on mds1 failed"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property rbac --value file_perms,quota_ops,byfid_ops,dne_ops &&
		error "modify rbac for $nm on mds1 should fail (1)"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
		--property rbac --value file_perms ||
		error "modify rbac for $nm on mds1 failed (1)"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property child_raise_privileges \
	       --value trusted,admin &&
	    error "modify nm.child_raise_privileges for $nm on mds1 should fail"

	do_facet mds1 $LCTL nodemap_del $nm ||
		error "failed to delete dynamic nodemap $nm"

	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property child_raise_privileges --value trusted,dne_ops ||
		error "modify raise_privileges for $mgsnm on MGS failed (2)"
	wait_nm_sync $mgsnm child_raise_privileges '' inactive

	do_facet mds1 $LCTL nodemap_add -d -p $mgsnm $nm ||
		error "dynamic nodemap on server failed (2)"
	val=$(do_facet mds1 $LCTL get_param -n nodemap.$nm.id)
	if [[ -z "$val" || "$val" == "0" ]]; then
		error "dynamic nodemap wrong id $val (2)"
	fi
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property rbac --value file_perms,quota_ops,byfid_ops,dne_ops ||
		error "modify rbac for $nm on mds1 failed (2)"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property rbac --value file_perms,quota_ops,byfid_ops,chlg_ops &&
		error "modify rbac for $nm on mds1 should fail (2)"
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property child_raise_privileges \
	       --value trusted ||
	    error "modify nm.child_raise_privileges for $nm on mds1 failed (1)"

	do_facet mds1 $LCTL nodemap_del $nm ||
		error "failed to delete dynamic nodemap $nm"

	do_facet mgs $LCTL nodemap_modify --name $mgsnm \
		--property child_raise_privileges \
		--value child_raise_privs,trusted,dne_ops ||
		error "modify raise_privileges for $mgsnm on MGS failed (3)"
	wait_nm_sync $mgsnm child_raise_privileges '' inactive

	do_facet mds1 $LCTL nodemap_add -d -p $mgsnm $nm ||
		error "dynamic nodemap on server failed (3)"
	val=$(do_facet mds1 $LCTL get_param -n nodemap.$nm.id)
	if [[ -z "$val" || "$val" == "0" ]]; then
		error "dynamic nodemap wrong id $val (3)"
	fi
	do_facet mds1 $LCTL nodemap_modify --name $nm \
	       --property child_raise_privileges \
	       --value child_raise_privs,trusted,dne_ops,admin ||
	    error "modify nm.child_raise_privileges for $nm on mds1 failed (2)"

	do_facet mds1 $LCTL get_param -R nodemap.*
}
run_test 72c "child_raise_privileges nodemap property"

test_73() {
	local vaultdir1=$DIR/$tdir/vault1
	local vaultdir2=$DIR/$tdir/vault2
	local shortfname="short=a"
	local longfname="longfilenamewitha=inthemiddletotestbehaviorregardingthedigestedform"
	local fid
	local digshort1
	local digshort2
	local diglong1
	local diglong2

	(( $MDS1_VERSION >= $(version_code 2.16.50) )) ||
		skip "Need MDS version at least 2.16.50"

	[[ $($LCTL get_param mdc.*.import) =~ client_encryption ]] ||
		skip "need encryption support"
	which fscrypt || skip_env "Need fscrypt"

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	yes | fscrypt setup --force --verbose ||
		echo "fscrypt global setup already done"
	sed -i 's/\(.*\)policy_version\(.*\):\(.*\)\"[0-9]*\"\(.*\)/\1policy_version\2:\3"2"\4/' \
		/etc/fscrypt.conf
	yes | fscrypt setup --verbose $MOUNT ||
		echo "fscrypt setup $MOUNT already done"
	stack_trap "rm -rf $MOUNT/.fscrypt"

	# enable_filename_encryption tunable only available for client
	# built against embedded llcrypt. If client is built against in-kernel
	# fscrypt, file names are always encrypted.
	$LCTL get_param mdc.*.connect_flags | grep -q name_encryption &&
	  nameenc=$(lctl get_param -n llite.*.enable_filename_encryption |
			head -n1)

	# begin with non-encrypted names
	if [ -n "$nameenc" ] && (( nameenc != 0 )); then
	        $LCTL set_param llite.*.enable_filename_encryption=0
		[ $? -eq 0 ] ||
			error "set_param \
			       llite.*.enable_filename_encryption=1 failed"
	fi

	mkdir -p $vaultdir1
	stack_trap "rm -rf $vaultdir1"

	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
	     --source=custom_passphrase --name=protector_73a $vaultdir1 ||
		error "fscrypt encrypt $vaultdir1 failed"

	# activate changelogs
	changelog_register || error "changelog_register failed"
	local cl_user="${CL_USERS[$SINGLEMDS]%% *}"
	changelog_users $SINGLEMDS | grep -q $cl_user ||
		error "User $cl_user not found in changelog_users"
	changelog_chmask ALL

	touch $vaultdir1/$shortfname ||
		error "touch $vaultdir1/$shortfname failed"
	fid=$($LFS path2fid $vaultdir1/$shortfname)
	fid="${fid:1:-1}"
	fscrypt lock $vaultdir1 || error "fscrypt lock $vaultdir1 failed"
	digshort1=$($LFS fid2path $MOUNT $fid)
	digshort1=$(basename $digshort1)
	echo mypass | fscrypt unlock $vaultdir1 ||
		error "fscrypt unlock $vaultdir1 failed"
	mrename $vaultdir1/$shortfname $vaultdir1/$longfname ||
		error "mrename $vaultdir1/$shortfname failed"
	fscrypt lock $vaultdir1 || error "fscrypt lock $vaultdir1 failed"
	diglong1=$($LFS fid2path $MOUNT $fid)
	diglong1=$(basename $diglong1)

	# access changelogs
	echo "changelogs dump"
	changelog_dump || error "failed to dump changelogs"
	digshort2=$(changelog_find -type CREAT -target-fid $fid |
			awk '{print $12}')
	[[ $digshort1 == $digshort2 ]] ||
		error "name $digshort2 in CREAT is not $digshort1"
	digshort2=$(changelog_find -type RENME -source-fid $fid |
			awk '{print $15}')
	[[ $digshort1 == $digshort2 ]] ||
		error "name $digshort2 in RENME is not $digshort1"
	diglong2=$(changelog_find -type RENME -source-fid $fid |
			awk '{print $12}')
	[[ $diglong1 == $diglong2 ]] ||
		error "name $diglong2 in RENME is not $diglong1"

	echo "changelogs clear"
	changelog_clear 0 || error "failed to clear changelogs"

	# now switch to encrypted names
	if [ -n "$nameenc" ] && (( nameenc != 1 )); then
	        $LCTL set_param llite.*.enable_filename_encryption=1
		[ $? -eq 0 ] ||
			error "set_param \
			       llite.*.enable_filename_encryption=1 failed"
		stack_trap \
			"$LCTL set_param llite.*.enable_filename_encryption=0"
	fi

	$LFS mkdir -c1 -i $((MDSCOUNT-1)) $vaultdir2
	stack_trap "rm -rf $vaultdir2"

	echo -e 'mypass\nmypass' | fscrypt encrypt --verbose \
	     --source=custom_passphrase --name=protector_73b $vaultdir2 ||
		error "fscrypt encrypt $vaultdir2 failed"

	touch $vaultdir2/$shortfname ||
		error "touch $vaultdir2/$shortfname failed"
	fid=$($LFS path2fid $vaultdir2/$shortfname)
	fid="${fid:1:-1}"
	fscrypt lock $vaultdir2 || error "fscrypt lock $vaultdir2 failed"
	digshort1=$($LFS fid2path $MOUNT $fid)
	digshort1=$(basename $digshort1)
	echo mypass | fscrypt unlock $vaultdir2 ||
		error "fscrypt unlock $vaultdir2 failed"
	mrename $vaultdir2/$shortfname $vaultdir2/$longfname ||
		error "mrename $vaultdir2/$shortfname failed"
	fscrypt lock $vaultdir2 || error "fscrypt lock $vaultdir2 failed"
	diglong1=$($LFS fid2path $MOUNT $fid)
	diglong1=$(basename $diglong1)

	# access changelogs
	echo "changelogs dump"
	changelog_dump || error "failed to dump changelogs"
	digshort2=$(changelog_find -type CREAT -target-fid $fid |
			awk '{print $12}')
	[[ $digshort1 == $digshort2 ]] ||
		error "name $digshort2 in CREAT is not $digshort1"
	digshort2=$(changelog_find -type RENME -source-fid $fid |
			awk '{print $15}')
	[[ $digshort1 == $digshort2 ]] ||
		error "name $digshort2 in RENME is not $digshort1"
	diglong2=$(changelog_find -type RENME -source-fid $fid |
			awk '{print $12}')
	[[ $diglong1 == $diglong2 ]] ||
		error "name $diglong2 in RENME is not $diglong1"
}
run_test 73 "encrypted names in changelogs"

test_74() {
	local testfile="${DIR}/${tdir}/$tfile"
	local deny_mount

	# check that deny_mount flag exists
	deny_mount=$(do_facet mgs \
			$LCTL get_param -n nodemap.default.deny_mount)
	[[ -n "$deny_mount" ]] ||
		skip "Server does not have the deny_mount nodemap flag"

	stack_trap cleanup_local_client_nodemap EXIT

	umount_client $MOUNT || error "umount $MOUNT failed (1)"

	# setup privileged nodemap for c0
	setup_local_client_nodemap "c0" 1 1

	# check default deny_mount flags
	(( $deny_mount == 0 )) ||
		error "wrong default for deny_mount flag on default nodemap"
	deny_mount=$(do_facet mgs \
			$LCTL get_param -n nodemap.c0.deny_mount)
	(( $deny_mount == 0 )) ||
		error "wrong default value for deny_mount on nodemap c0"

	# mount client with active nodemap
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS} ||
		error "re-mount failed (1)"
	wait_ssk

	# simple access test
	$LFS mkdir -c 1 "${DIR}/$tdir" || error "mkdir ${DIR}/$tdir failed"
	$LFS setstripe -c 1 $testfile || error "setstripe $testfile failed"
	echo -n "a" > $testfile || error "(1) write $testfile failed"

	# set deny_mount flag. Access should still work for existing clients
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property deny_mount --value 1
	wait_nm_sync c0 deny_mount
	echo -n "b" >> $testfile || error "(2) write $testfile failed"
	cat $testfile > /dev/null || error "read $testfile failed"
	# unmount client
	umount_client $MOUNT || error "umount $MOUNT failed (2)"

	# mount client should fail (nodemap is deny_mount)
	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS} &&
		error "mount should have failed. deny_mount flag is not honored"

	# set active flag for c0. Access should work again
	do_facet mgs $LCTL nodemap_modify --name c0 \
		--property deny_mount --value 0
	wait_nm_sync c0 deny_mount

	zconf_mount_clients $HOSTNAME $MOUNT ${MOUNT_OPTS} ||
		error "re-mount failed (2)"
	wait_ssk

	# check access
	echo -n "c" >> $testfile || error "(3) write $testfile failed"
	[[ $(cat $testfile) == "abc" ]] ||
		error "read access test for $testfile failed"
}
run_test 74 "Set nodemap deny_mount flag"

check_ost_object_ids() {
	local file=$1
	local expected_uid=$2
	local expected_gid=$3
	local expected_projid=$4
	local objdump=$DIR/$tdir/objdump

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# Get the OST object path. We assume the file has one stripe on ost1
	local fids=($($LFS getstripe $file | grep 0x))
	local fid="${fids[3]}:${fids[2]}:0"
	local objpath=$(ost_fid2_objpath ost1 $fid)

	do_facet ost1 "$DEBUGFS -c -R 'stat $objpath' $(ostdevname 1)" |
		grep "Project" > $objdump
	local obj_uid=$(awk '{print $2}' $objdump)
	local obj_gid=$(awk '{print $4}' $objdump)
	local obj_projid=$(awk '{print $6}' $objdump)
	echo "OST object ids and size for file '$file': $(cat $objdump)"

	[[ "$obj_uid" == "$expected_uid" ]] ||
		error "uid is not set to expected value $expected_uid"
	[[ "$obj_gid" == "$expected_gid" ]] ||
		error "gid is not set to expected value $expected_gid"
	[[ "$obj_projid" == "$expected_projid" ]] ||
		error "projid is not set to expected value $expected_projid"
}

check_mdt_inode_ids() {
	local file=${1#${MOUNT}}
	local expected_uid=$2
	local expected_gid=$3
	local expected_projid=$4
	local objdump=$DIR/$tdir/objdump

	if (( $MDSCOUNT != 1 )); then
		echo "DNE not supported; checking IDs on MDT assumes a single MDT only"
		return 0
	fi

	mkdir -p $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	do_facet mds1 "$DEBUGFS -c -R 'stat ROOT${file}' $(mdsdevname 1)" |
		grep "Project" > $objdump

	local obj_uid=$(awk '{print $2}' $objdump)
	local obj_gid=$(awk '{print $4}' $objdump)
	local obj_projid=$(awk '{print $6}' $objdump)
	echo "MDT inode ids and size for file '$file': $(cat $objdump)"

	[[ "$obj_uid" == "$expected_uid" ]] ||
		error "uid is not set to expected value $expected_uid"
	[[ "$obj_gid" == "$expected_gid" ]] ||
		error "gid is not set to expected value $expected_gid"
	[[ "$obj_projid" == "$expected_projid" ]] ||
		error "projid is not set to expected value $expected_projid"
}

check_ids_sync() {
	sync
	# wait for asynchronous MDS-OST sync and force flush to OST
	sync_all_data
	wait_mds_ost_sync || error "wait_mds_ost_sync failed"
	# drop_caches to flush inode cache so ID updates from chown or
	# lfs project are visible through debugfs on the OST objects
	do_facet ost1 "sync; sync; echo 3 > /proc/sys/vm/drop_caches"
	# drop_caches to flush dentry cache so namespace updates from "mv"
	# operations are visible through debugfs on the MDT
	do_facet mds "sync; sync; echo 3 > /proc/sys/vm/drop_caches"
}

test_75() {
	local testdir="${DIR}/${tdir}"
	local projdir="${testdir}/projdir"
	local tfile_write=${projdir}/${tfile}_write
	local tfile_trunc=${projdir}/${tfile}_trunc
	local tfile_creat=${projdir}/${tfile}_creat
	local tfile_falloc=${projdir}/${tfile}_falloc
	local tfile_write2=${testdir}/${tfile}_write2
	local testdir_projid=42
	local testfile_projid=43
	local have_ost_punch_ids=false

	# prior to 2.16.53 OST_PUNCH did not set OST IDs
	(( $OST1_VERSION >= $(version_code 2.16.53) &&
		$CLIENT_VERSION >= $(version_code 2.16.53) )) &&
		have_ost_punch_ids=true

	[[ "$ost1_FSTYPE" == ldiskfs ]] ||
		skip "ldiskfs only test (using debugfs)"

	# setup
	mkdir -p $projdir || error "mkdir $projdir failed"
	stack_trap "rm -rf $DIR/$tdir" EXIT

	$LFS project -s -p $testdir_projid $projdir ||
		error "lfs project failed"
	chown -R $USER0 $DIR/$tdir || error "chown Failed"

	# setstripe is primarily used to force data being created on ost1

	# OST_WRITE RPC (dd) - in projdir
	$RUNAS_CMD -u $ID0 $LFS setstripe -c 1 -i 0 $tfile_write ||
		error "setstripe for file $tfile_write failed"
	$RUNAS_CMD -u $ID0 dd if=/dev/urandom of=$tfile_write bs=1M count=1 ||
		error "dd for file $tfile_write failed"

	# OST_WRITE RPC (dd) - not in projdir
	$RUNAS_CMD -u $ID0 $LFS setstripe -c 1 -i 0 $tfile_write2 ||
		error "setstripe for file $tfile_write2 failed"
	$RUNAS_CMD -u $ID0 \
		dd if=/dev/urandom of=$tfile_write2 bs=1M count=1 ||
		error "dd for file $tfile_write2 failed"

	if $have_ost_punch_ids; then
		# OST_PUNCH RPC (truncate)
		$RUNAS_CMD -u $ID0 $LFS setstripe -c 1 -i 0 $tfile_trunc ||
			error "setstripe for file $tfile_trunc failed"
		$RUNAS_CMD -u $ID0 $TRUNCATE $tfile_trunc 1048576 ||
			error "truncate for file $tfile_trunc failed"
	fi

	# LDLM_ENQUEUE RPC (IT_CREAT intent) (setstripe)
	$RUNAS_CMD -u $ID0 $LFS setstripe -c 1 -i 0 $tfile_creat ||
		error "setstripe for file $tfile_creat failed"

	# OST_FALLOCATE RPC (fallocate)
	$RUNAS_CMD -u $ID0 $LFS setstripe -c 1 -i 0 $tfile_falloc ||
		error "setstripe for file $tfile_falloc failed"
	$RUNAS_CMD -u $ID0 fallocate -l 1M $tfile_falloc ||
		error "fallocate for file $tfile_falloc failed"

	check_ids_sync

	# check IDs are set correctly
	check_mdt_inode_ids $tfile_write $ID0 $ID0 $testdir_projid
	check_ost_object_ids $tfile_write $ID0 $ID0 $testdir_projid

	check_mdt_inode_ids $tfile_write2 $ID0 $ID0 0
	check_ost_object_ids $tfile_write2 $ID0 $ID0 0

	if $have_ost_punch_ids; then
		check_mdt_inode_ids $tfile_trunc $ID0 $ID0 $testdir_projid
		check_ost_object_ids $tfile_trunc $ID0 $ID0 $testdir_projid
	fi

	check_mdt_inode_ids $tfile_falloc $ID0 $ID0 $testdir_projid
	check_ost_object_ids $tfile_falloc $ID0 $ID0 $testdir_projid

	check_mdt_inode_ids $tfile_creat $ID0 $ID0 $testdir_projid

	# move file to projdir should set PROJID from directory
	# MDS_REINT RPC Client->MDS; OST_SETATTR RPC MDS->OST
	mv $tfile_write ${testdir}/ || error "mv $tfile_write failed"
	tfile_write=$testdir/${tfile}_write

	# set explicit PROJID outside of projdir
	# MDS_REINT RPC Client->MDS; OST_SETATTR RPC MDS->OST
	$LFS project -p $testfile_projid $tfile_write2 ||
		error "lfs project failed"

	check_ids_sync

	check_mdt_inode_ids $tfile_write $ID0 $ID0 $testdir_projid
	check_ost_object_ids $tfile_write $ID0 $ID0 $testdir_projid

	check_mdt_inode_ids $tfile_write2 $ID0 $ID0 $testfile_projid
	check_ost_object_ids $tfile_write2 $ID0 $ID0 $testfile_projid

	# move file to projdir should set new PROJID from directory
	# MDS_REINT RPC Client->MDS; OST_SETATTR RPC MDS->OST
	mv $tfile_write2 $projdir || error "mv $tfile_write2 failed"
	tfile_write2=$projdir/${tfile}_write2

	# chown should set new UID/GID
	# MDS_REINT RPC Client->MDS; OST_SETATTR RPC MDS->OST
	chown $ID1:$ID1 $tfile_write || error "chown $tfile_write failed"

	check_ids_sync

	check_mdt_inode_ids $tfile_write2 $ID0 $ID0 $testdir_projid
	check_ost_object_ids $tfile_write2 $ID0 $ID0 $testdir_projid

	check_mdt_inode_ids $tfile_write $ID1 $ID1 $testdir_projid
	check_ost_object_ids $tfile_write $ID1 $ID1 $testdir_projid
}
run_test 75 "check uid/gid/projid are set on OST and MDT for various RPCs"

setup_75a() {
	# Assumes that variables from test_75a are set
	# Setup c0 (trusted) and c1 (tenant) nodemaps used by the clients
	nodemap_test_setup
	trap cleanup_75a EXIT

	# configure tentant nodemap
	do_facet mgs $LCTL nodemap_set_fileset --name $nm_tenant \
		--fileset "/$fileset_nm" || error "Setting fileset failed"
	do_facet mgs $LCTL nodemap_add_offset --name $nm_tenant \
		--offset $offset_start --limit $offset_limit ||
		error "cannot set offset for $nm_tenant"
	do_facet mgs $LCTL nodemap_modify --name $nm_tenant \
		--property map_mode=projid ||
		error "cannot set offset for $nm_tenant"

	# configure trusted nodemap
	do_facet mgs $LCTL nodemap_modify --name $nm_trusted \
		--property admin --value 1 || error "Setting admin=1 failed"
	do_facet mgs $LCTL nodemap_modify --name $nm_trusted \
		--property trusted --value 1 || error "Setting trusted=1 failed"

	wait_nm_sync $nm_trusted trusted_nodemap

	# create and set ownership for fileset dir of "nm_tenant"
	$run_as_trusted mkdir -p $fileset_subdir ||
		error "mkdir $fileset_subdir failed"
	$run_as_trusted chown $((offset_start+ID0)) $fileset_subdir

	# remount clients for nodemap changes to take effect.
	# This mounts the trusted nodemap (c0) and tenant nodemap (c1)
	export FILESET=/
	for client in "${clients_arr[@]}"; do
		zconf_umount_clients $client $MOUNT ||
			error "unable to umount client ${clients_arr[0]}"
		zconf_mount_clients $client $MOUNT $MOUNT_OPTS ||
			error "unable to umount client ${clients_arr[0]}"
	done
	unset FILESET
	wait_ssk
}

setup_namespace_75a() {
	# Assumes that variables from test_75a are set
	setup_tfiles_75a() {
		local tenant_file=$1
		local tenant_dir=$2
		local offset=$3
		$run_as_trusted "echo \"abc\" > ${fileset_subdir}/$tenant_file" ||
			error "echo $tenant_file failed"
		$run_as_trusted mkdir -p ${fileset_subdir}/$tenant_dir ||
			error "mkdir $tenant_dir failed"
		$run_as_trusted chmod 777 ${fileset_subdir}/$tenant_file \
			${fileset_subdir}/$tenant_dir ||
			error "chmod 777 $tenant_file and $tenant_dir failed"
		$run_as_trusted chown \
			$((offset+ID0)):$((offset+ID0)) \
			${fileset_subdir}/$tenant_file \
			${fileset_subdir}/$tenant_dir ||
			error "chown $tenant_file and $tenant_dir failed"
	}

	# setup testfiles and testdirectories. *_trusted files/dirs are
	# world-accessible, but become inaccessible once the id_check is enabled
	$run_as_trusted "echo \"abc\" > ${fileset_subdir}/$tfile_trusted" ||
		error "echo $tfile_trusted failed"
	$run_as_trusted mkdir ${fileset_subdir}/$tdir_trusted ||
		error "mkdir $tdir_trusted failed"
	$run_as_trusted chmod 777 ${fileset_subdir}/$tdir_trusted \
		${fileset_subdir}/$tfile_trusted ||
		error "chmod 777 $tdir_trusted failed"

	setup_tfiles_75a $tfile_tl $tdir_tl 100000
	setup_tfiles_75a $tfile_tenant $tdir_tenant $offset_start
	setup_tfiles_75a $tfile_tr $tdir_tr 300000

	# DoM files
	$run_as_trusted $LFS setstripe -E 1M -L mdt \
		 ${fileset_subdir}/${tfile_trusted}_dom ||
		error "setstripe ${tfile_trusted}_dom failed"
	$run_as_trusted chmod 777 ${fileset_subdir}/${tfile_trusted}_dom ||
			error "chmod 777 ${tfile_trusted}_dom failed"
	$run_as_trusted $LFS setstripe -E 1M -L mdt \
		 ${fileset_subdir}/${tfile_tenant}_dom ||
		error "setstripe ${tfile_tenant}_dom failed"
	$run_as_trusted chown \
			$((offset_start+ID0)):$((offset_start+ID0)) \
			${fileset_subdir}/${tfile_tenant}_dom ||
			error "chown ${tfile_tenant}_dom failed"

	# create a file used in write tests
	$run_as_trusted "echo \"def\" > ${fileset_subdir}/$tf_write" ||
		error "echo  $tf_write failed"
	$run_as_trusted chown \
		$((offset_start+ID0)):$((offset_start+ID0)) \
		${fileset_subdir}/$tf_write ||
		error "chown $tf_write failed"
}

cleanup_75a() {
	do_nodes $(all_mdts_nodes) \
		$LCTL set_param mdt.*.enable_resource_id_check=0 ||
			error "disabling resource id check on MDTs failed"

	do_nodes $(all_osts_nodes) \
		$LCTL set_param obdfilter.*.enable_resource_id_check=0 ||
			error "disabling resource id check on OSTs failed"

	nodemap_test_cleanup

	for client in "${clients_arr[@]}"; do
		zconf_umount_clients $client $MOUNT ||
			error "unable to umount client $client"
		zconf_mount_clients $client $MOUNT $MOUNT_OPTS ||
			error "unable to umount client $client"
	done
	wait_ssk
}

test_75a() {
	local offset_start=200000
	local offset_limit=100000
	local nm_trusted="c0"
	local nm_tenant="c1"
	local fileset_nm="${tdir}/${nm_tenant}_dir"
	local fileset_subdir="${DIR}/${fileset_nm}"
	local tfile_trusted="testfile_trusted"
	local tfile_tenant="testfile_tenant"
	local tdir_trusted="testdir_trusted"
	local tdir_tenant="testdir_tenant"
	# *_tl and *_tr files/dirs are set up such that their fs_ids are to the
	# left and right of the tenant's offset range, respectively. This is to
	# exercise both cases of nodemap_map_id() when mapping FS to client IDs.
	local tfile_tl="testfile_tenant_left"
	local tdir_tl="testdir_tenant_left"
	local tfile_tr="testfile_tenant_right"
	local tdir_tr="testdir_tenant_right"
	local tf_write="testf_write"
	local tf="testfile"
	local client_trusted
	local run_as_tenant
	local out

	# This test checks that the enable_resource_id_check flag works
	# correctly by having a tenant accessing squashed files.
	# Without this check, tenants are able to access such files
	# that have world-accessible permissions.
	# With the flag enabled, this is no longer possible.

	# check that enable_resource_id_check flag exists
	do_facet mds $LCTL get_param -n mdt.*.enable_resource_id_check ||
		skip "MDS does not have the enable_resource_id_check flag"
	do_facet ost $LCTL get_param -n obdfilter.*.enable_resource_id_check ||
		skip "OSS does not have the enable_resource_id_check flag"

	# need two clients to continue
	(( $CLIENTCOUNT >= 2 )) || skip "need at least two clients"

	if $SHARED_KEY; then
		skip "need non-shared key for this test"
	fi

	# assign clients and helper routines
	client_trusted=${clients_arr[0]}
	client_tenant=${clients_arr[1]}
	run_as_tenant="do_node $client_tenant $RUNAS_CMD -u $ID0"
	run_as_trusted="do_node $client_trusted"

	setup_75a

	do_nodes $(all_mdts_nodes) \
		$LCTL set_param mdt.*.enable_resource_id_check=0 ||
			error "disabling resource id check on MDTs failed"

	do_nodes $(all_osts_nodes) \
		$LCTL set_param obdfilter.*.enable_resource_id_check=0 ||
			error "disabling resource id check on OSTs failed"

	report_client_view_75a() {
		echo "Trusted view:"
		$run_as_trusted ls -al $fileset_subdir
		echo "------------------------------"
		echo "Tenant view:"
		$run_as_tenant ls -al $MOUNT
	}

	75a_drop_tenant_cache() {
		do_node $client_tenant \
			"sync ; echo 3 > /proc/sys/vm/drop_caches"
	}

	75a_op_test() {
		local test_cmd="$run_as_tenant $1"
		local test_success=${2:-true}
		if $test_success; then
			$test_cmd || error "$1 failed"
		else
			$test_cmd && error "$1 should've failed"
		fi
	}

	75a_read_test() {
		local test_cmd="$run_as_tenant $1"
		local test_success=${2:-true}
		local expected=${3:-"def"}
		local out
		if $test_success; then
			out=$($test_cmd) || error "$1 failed"
			echo $out
			[[ $out == $expected ]] ||
				error "read $expected for $1 incorrect"
		else
			$test_cmd && error "$1 should've failed"
		fi
	}

	75a_getxattr_test() {
		local test_cmd="$run_as_tenant getfattr -n user.abc $1"
		local test_success=${2:-true}
		local expected=${3:-"\"def\""}
		local out
		if $test_success; then
			out=$($test_cmd | awk -F'=' '/user.abc/ {print $2}') ||
				error "$1 failed"
			echo $out
			[[ $out == $expected ]] ||
				error "getxattr $expected for $1 incorrect"
		else
			$test_cmd && error "$1 should've failed"
		fi
	}

	# Setup testrun 1
	setup_namespace_75a
	report_client_view_75a
	# Testrun 1 begins (check disabled)
	# 1. write to files
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_trusted" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tl" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tenant" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tr" true
	75a_drop_tenant_cache
	# 2. read from files
	75a_read_test "cat ${MOUNT}/$tfile_trusted" true
	75a_read_test "cat ${MOUNT}/$tfile_tl" true
	75a_read_test "cat ${MOUNT}/$tfile_tenant" true
	75a_read_test "cat ${MOUNT}/$tfile_tr" true
	75a_drop_tenant_cache
	# 3. create files in various dirs
	75a_op_test "touch ${MOUNT}/${tdir_trusted}/$tf" true
	75a_op_test "touch ${MOUNT}/${tdir_tl}/$tf" true
	75a_op_test "touch ${MOUNT}/${tdir_tenant}/$tf" true
	75a_op_test "touch ${MOUNT}/${tdir_tr}/$tf" true
	# 4. soft and hard links
	75a_op_test "ln ${MOUNT}/$tfile_trusted \
		${MOUNT}/${tfile_trusted}_hlink" true
	75a_op_test "ln -s ${MOUNT}/$tfile_trusted \
		${MOUNT}/${tfile_trusted}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tl \
		${MOUNT}/${tfile_tl}_hlink" true
	75a_op_test "ln -s ${MOUNT}/$tfile_tl \
		${MOUNT}/${tfile_tl}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tenant \
		${MOUNT}/${tfile_tenant}_hlink" true
	75a_op_test "ln -s ${MOUNT}/$tfile_tenant \
		${MOUNT}/${tfile_tenant}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tr \
		${MOUNT}/${tfile_tr}_hlink" true
	75a_op_test "ln -s ${MOUNT}/$tfile_tr \
		${MOUNT}/${tfile_tr}_slink" true
	75a_read_test "cat ${MOUNT}/${tfile_trusted}_hlink" true
	75a_read_test "cat ${MOUNT}/${tfile_trusted}_slink" true
	75a_read_test "cat ${MOUNT}/${tfile_tl}_hlink" true
	75a_read_test "cat ${MOUNT}/${tfile_tl}_slink" true
	75a_read_test "cat ${MOUNT}/${tfile_tenant}_hlink" true
	75a_read_test "cat ${MOUNT}/${tfile_tenant}_slink" true
	75a_read_test "cat ${MOUNT}/${tfile_tr}_hlink" true
	75a_read_test "cat ${MOUNT}/${tfile_tr}_slink" true
	75a_op_test "rm ${MOUNT}/*_hlink" true
	75a_op_test "rm ${MOUNT}/*_slink" true
	# 5. fallocate (zfs does not support pre-allocation via fallocate(2))
	if [[ "$ost1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_trusted" true
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tl" true
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tenant" true
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tr" true
	fi
	# 6. truncate
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_trusted 524288" true
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tl 524288" true
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tenant 524288" true
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tr 524288" true
	# 7. rename files (and back)
	75a_op_test "mv ${MOUNT}/$tfile_trusted ${MOUNT}/${tfile_trusted}_" true
	75a_op_test "mv ${MOUNT}/${tfile_trusted}_ ${MOUNT}/$tfile_trusted" true
	75a_op_test "mv ${MOUNT}/$tfile_tl ${MOUNT}/${tfile_tl}_" true
	75a_op_test "mv ${MOUNT}/${tfile_tl}_ ${MOUNT}/$tfile_tl" true
	75a_op_test "mv ${MOUNT}/$tfile_tenant ${MOUNT}/${tfile_tenant}_" true
	75a_op_test "mv ${MOUNT}/${tfile_tenant}_ ${MOUNT}/$tfile_tenant" true
	75a_op_test "mv ${MOUNT}/$tfile_tr ${MOUNT}/${tfile_tr}_" true
	75a_op_test "mv ${MOUNT}/${tfile_tr}_ ${MOUNT}/$tfile_tr" true
	# 8. trigger setattr operation with "touch" (timestamp update)
	75a_op_test "touch ${MOUNT}/$tfile_trusted" true
	75a_op_test "touch ${MOUNT}/$tfile_tl" true
	75a_op_test "touch ${MOUNT}/$tfile_tenant" true
	75a_op_test "touch ${MOUNT}/$tfile_tr" true
	# 9. xattr, set and get
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_trusted" true
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tl" true
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tenant" true
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tr" true
	75a_getxattr_test ${MOUNT}/$tfile_trusted true
	75a_getxattr_test ${MOUNT}/$tfile_tl true
	75a_getxattr_test ${MOUNT}/$tfile_tenant true
	75a_getxattr_test ${MOUNT}/$tfile_tr true
	# 10. remove create files from tenant dirs
	75a_op_test "rm ${MOUNT}/${tdir_trusted}/$tf" true
	75a_op_test "rm ${MOUNT}/${tdir_tl}/$tf" true
	75a_op_test "rm ${MOUNT}/${tdir_tenant}/$tf" true
	75a_op_test "rm ${MOUNT}/${tdir_tr}/$tf" true
	# 11. remove all tenant dirs
	75a_op_test "rmdir ${MOUNT}/$tdir_trusted" true
	75a_op_test "rmdir ${MOUNT}/$tdir_tl" true
	75a_op_test "rmdir ${MOUNT}/$tdir_tenant" true
	75a_op_test "rmdir ${MOUNT}/$tdir_tr" true
	# 12. remove remaining tenant files from root
	75a_op_test "rm ${MOUNT}/$tfile_trusted" true
	75a_op_test "rm ${MOUNT}/$tfile_tl" true
	75a_op_test "rm ${MOUNT}/$tfile_tenant" true
	75a_op_test "rm ${MOUNT}/$tfile_tr" true
	# 13. Data on MDT cases
	if [[ "$mds1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/${tfile_trusted}_dom" true
	fi
	75a_op_test "$TRUNCATE ${MOUNT}/${tfile_trusted}_dom 524288" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/${tfile_trusted}_dom" true
	75a_drop_tenant_cache
	75a_read_test "cat ${MOUNT}/${tfile_trusted}_dom" true
	75a_op_test "rm ${MOUNT}/${tfile_trusted}_dom" true

	if [[ "$mds1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/${tfile_tenant}_dom" true
	fi
	75a_op_test "$TRUNCATE ${MOUNT}/${tfile_tenant}_dom 524288" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/${tfile_tenant}_dom" true
	75a_drop_tenant_cache
	75a_read_test "cat ${MOUNT}/${tfile_tenant}_dom" true
	75a_op_test "rm ${MOUNT}/${tfile_tenant}_dom" true

	report_client_view_75a

	do_nodes $(all_mdts_nodes) \
		$LCTL set_param mdt.*.enable_resource_id_check=1 ||
			error "enabling resource id check on MDTs failed"

	do_nodes $(all_osts_nodes) \
		$LCTL set_param obdfilter.*.enable_resource_id_check=1 ||
			error "enabling resource id check on OSTs failed"

	# Setup testrun 2
	setup_namespace_75a
	report_client_view_75a

	# Testrun 2 begins (check enabled)
	# 1. write to files
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_trusted" false
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tl" false
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tenant" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/$tfile_tr" false
	75a_drop_tenant_cache
	# 2. read from files
	75a_read_test "cat ${MOUNT}/$tfile_trusted" false
	75a_read_test "cat ${MOUNT}/$tfile_tl" false
	75a_read_test "cat ${MOUNT}/$tfile_tenant" true
	75a_read_test "cat ${MOUNT}/$tfile_tr" false
	75a_drop_tenant_cache
	# 3. create files
	75a_op_test "touch ${MOUNT}/${tdir_trusted}/$tf" false
	75a_op_test "touch ${MOUNT}/${tdir_tl}/$tf" false
	75a_op_test "touch ${MOUNT}/${tdir_tenant}/$tf" true
	75a_op_test "touch ${MOUNT}/${tdir_tr}/$tf" false
	# 4. soft and hard links (cannot create hard links but soft links)
	75a_op_test "ln ${MOUNT}/$tfile_trusted \
		${MOUNT}/${tfile_trusted}_hlink" false
	75a_op_test "ln -s ${MOUNT}/$tfile_trusted \
		${MOUNT}/${tfile_trusted}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tl \
		${MOUNT}/${tfile_tl}_hlink" false
	75a_op_test "ln -s ${MOUNT}/$tfile_tl \
		${MOUNT}/${tfile_tl}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tenant \
		${MOUNT}/${tfile_tenant}_hlink" true
	75a_op_test "ln -s ${MOUNT}/$tfile_tenant \
		${MOUNT}/${tfile_tenant}_slink" true
	75a_op_test "ln ${MOUNT}/$tfile_tr \
		${MOUNT}/${tfile_tr}_hlink" false
	75a_op_test "ln -s ${MOUNT}/$tfile_tr \
		${MOUNT}/${tfile_tr}_slink" true
	# can only read soft-links pointing to permitted files
	75a_read_test "cat ${MOUNT}/${tfile_trusted}_slink" false
	75a_read_test "cat ${MOUNT}/${tfile_tl}_slink" false
	75a_read_test "cat ${MOUNT}/${tfile_tenant}_slink" true
	75a_read_test "cat ${MOUNT}/${tfile_tr}_slink" false
	# can remove all links created by tenant
	75a_op_test "rm ${MOUNT}/${tfile_trusted}_slink" true
	75a_op_test "rm ${MOUNT}/${tfile_tl}_slink" true
	75a_op_test "rm ${MOUNT}/${tfile_tenant}_slink" true
	75a_op_test "rm ${MOUNT}/${tfile_tr}_slink" true
	75a_op_test "rm ${MOUNT}/${tfile_tenant}_hlink" true
	# 5. fallocate (only on ldiskfs, zfs does not support pre-allocation)
	if [[ "$ost1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_trusted" false
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tl" false
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tenant" true
		75a_op_test "fallocate -l 1M ${MOUNT}/$tfile_tr" false
	fi
	# 6. truncate
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_trusted 524288" false
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tl 524288" false
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tenant 524288" true
	75a_op_test "$TRUNCATE ${MOUNT}/$tfile_tr 524288" false
	# 7. rename files (and back)
	75a_op_test "mv ${MOUNT}/$tfile_trusted \
		${MOUNT}/${tfile_trusted}_" false
	75a_op_test "mv ${MOUNT}/$tfile_tl ${MOUNT}/${tfile_tl}_" false
	75a_op_test "mv ${MOUNT}/$tfile_tenant ${MOUNT}/${tfile_tenant}_" true
	75a_op_test "mv ${MOUNT}/${tfile_tenant}_ ${MOUNT}/$tfile_tenant" true
	75a_op_test "mv ${MOUNT}/$tfile_tr ${MOUNT}/${tfile_tr}_" false
	# 8. trigger setattr operation with "touch" (timestamp update)
	75a_op_test "touch ${MOUNT}/$tfile_trusted" false
	75a_op_test "touch ${MOUNT}/$tfile_tl" false
	75a_op_test "touch ${MOUNT}/$tfile_tenant" true
	75a_op_test "touch ${MOUNT}/$tfile_tr" false
	# 9. xattr, set and get
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_trusted" false
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tl" false
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tenant" true
	75a_op_test "setfattr -n user.abc -v def ${MOUNT}/$tfile_tr" false
	75a_getxattr_test ${MOUNT}/$tfile_trusted false
	75a_getxattr_test ${MOUNT}/$tfile_tl false
	75a_getxattr_test ${MOUNT}/$tfile_tenant true
	75a_getxattr_test ${MOUNT}/$tfile_tr false
	# 10. remove create files from tenant dirs
	75a_op_test "rm ${MOUNT}/${tdir_tenant}/$tf" true
	# 11. attempt to remove all tenant dirs
	75a_op_test "rmdir ${MOUNT}/$tdir_trusted" false
	75a_op_test "rmdir ${MOUNT}/$tdir_tl" false
	75a_op_test "rmdir ${MOUNT}/$tdir_tenant" true
	75a_op_test "rmdir ${MOUNT}/$tdir_tr" false
	# 12. attempt to remove remaining tenant files from root
	75a_op_test "rm ${MOUNT}/$tfile_trusted" false
	75a_op_test "rm ${MOUNT}/$tfile_tl" false
	75a_op_test "rm ${MOUNT}/$tfile_tenant" true
	75a_op_test "rm ${MOUNT}/$tfile_tr" false
	# 13. Data on MDT cases
	if [[ "$mds1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/${tfile_trusted}_dom" \
			false
	fi
	75a_op_test "$TRUNCATE ${MOUNT}/${tfile_trusted}_dom 524288" false
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/${tfile_trusted}_dom" false
	75a_read_test "cat ${MOUNT}/${tfile_trusted}_dom" false
	75a_op_test "rm ${MOUNT}/${tfile_trusted}_dom" false

	if [[ "$mds1_FSTYPE" == "ldiskfs" ]]; then
		75a_op_test "fallocate -l 1M ${MOUNT}/${tfile_tenant}_dom" true
	fi
	75a_op_test "$TRUNCATE ${MOUNT}/${tfile_tenant}_dom 524288" true
	75a_op_test "cp ${MOUNT}/$tf_write ${MOUNT}/${tfile_tenant}_dom" true
	75a_drop_tenant_cache
	75a_read_test "cat ${MOUNT}/${tfile_tenant}_dom" true
	75a_op_test "rm ${MOUNT}/${tfile_tenant}_dom" true

	report_client_view_75a
}
run_test 75a "test resource fs IDs against nodemap offset"

cleanup_76() {
	# unmount client
	if is_mounted $MOUNT; then
		umount_client $MOUNT || error "umount $MOUNT failed"
	fi

	# reset and deactivate nodemaps, remount client
	cleanup_local_client_nodemap

	# remount client on $MOUNT_2
	if [ "$MOUNT_2" ]; then
		mount_client $MOUNT2 ${MOUNT_OPTS} || error "remount failed"
	fi
	wait_ssk
}

test_76() {
	local user=$(getent passwd $RUNAS_ID | cut -d: -f1)
	local grp=grptest76
	local grpid=5000
	local nm=c0

	(( $MDS1_VERSION >= $(version_code 2.16.53) )) ||
		skip "need MDS >= 2.16.53 for suppgroup mapping"

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	# create a specific group and add it as a supplementary group for $USER0
	groupadd -g $grpid $grp
	stack_trap "groupdel $grp" EXIT
	usermod -aG $grp $user
	stack_trap "gpasswd -d $user $grp" EXIT

	stack_trap cleanup_76 EXIT

	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	# setup nodemap with offset
	setup_local_client_nodemap $nm 1 1
	do_facet mgs $LCTL nodemap_add_offset --name $nm \
		--offset 100000 --limit 200000 ||
			error "nodemap_add_offset failed"
	wait_nm_sync $nm offset

	# remount client to take nodemap into account
	zconf_mount_clients $HOSTNAME $MOUNT $MOUNT_OPTS ||
		error "remount failed"
	wait_ssk

	# Create directory from client part of the nodemap, as root,
	# and set its group membership to $grpid.
	# This is going to be mapped on server side.
	$LFS mkdir -i 0 -c 1 $DIR/$tdir || error "mkdir $DIR/$tdir failed"
	chgrp -v $grp $DIR/$tdir || error "chgrp $DIR/$tdir failed"
	chmod -v 0770 $DIR/$tdir || error "chmod $DIR/$tdir failed"
	ls -ld $DIR/$tdir
	cancel_lru_locks

	# access as $USER0, should work because it has $grpid as a supp group
	# and it is properly mapped on server side
	$RUNAS -G$grpid ls -l $DIR/$tdir ||
		error "ls -l $DIR/$tdir as $user failed"
	$RUNAS -G$grpid touch $DIR/$tdir/fileA ||
		error "touch $DIR/$tdir/fileA as $user failed"
}
run_test 76 "suppgroups and gid mapping"

test_77() {
	local squash=100
	local nm=c0

	(( $MDS1_VERSION >= $(version_code 2.16.54) )) ||
		skip "Need MDS version >= 2.16.54 for proper root offsetting"

	do_nodes $(comma_list $(all_mdts_nodes)) \
		$LCTL set_param mdt.*.identity_upcall=NONE

	stack_trap cleanup_local_client_nodemap_with_mounts EXIT

	# create dir before nodemap create
	$LFS mkdir -i 0 -c 1 $DIR/$tdir || error "mkdir $DIR/$tdir failed"

	# unmount client completely
	umount_client $MOUNT || error "umount $MOUNT failed"
	if is_mounted $MOUNT2; then
		umount_client $MOUNT2 || error "umount $MOUNT2 failed"
	fi

	# setup nodemap with offset
	setup_local_client_nodemap $nm 1 0
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property squash_uid --value $squash ||
		error "Setting squash_uid=$squash on $nm failed"
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property squash_gid --value $squash ||
		error "Setting squash_gid=$squash on $nm failed"
	do_facet mgs $LCTL nodemap_modify --name $nm \
		--property squash_projid --value $squash ||
		error "Setting squash_projid=$squash on $nm failed"
	do_facet mgs $LCTL nodemap_add_offset --name $nm \
		--offset 100000 --limit 200000 ||
			error "nodemap_add_offset failed"
	wait_nm_sync $nm offset

	# remount client to take nodemap into account
	zconf_mount_clients $HOSTNAME $MOUNT $MOUNT_OPTS ||
		error "remount failed"
	wait_ssk

	# create a file as root...
	touch $DIR/$tdir/fileA
	# the owner:group ids read back should be 0:0
	ls -ln $DIR/$tdir/fileA
	[[ $(stat -c "%u:%g" $DIR/$tdir/fileA) == "0:0" ]] ||
		error "bad owner/group for root file"
}
run_test 77 "root offsetting"

test_79() {
	# reserve test_79
	skip "not implemented yet"
}
#run_test 79 "ssk for nodemap identification"

log "cleanup: ======================================================"

sec_unsetup() {
	for ((num = 1; num <= $MDSCOUNT; num++)); do
		if [[ "${identity_old[$num]}" == 1 ]]; then
			switch_identity $num false || identity_old[$num]=$?
		fi
	done

	$RUNAS_CMD -u $ID0 ls $DIR
	$RUNAS_CMD -u $ID1 ls $DIR
}
sec_unsetup

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
