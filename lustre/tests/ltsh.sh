#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Subtest files
#
# Subtests can be kept in $LUSTRE/tests/$TESTSUITE.d/*.ltsh files, each
# with a YAML header, instead of in $TESTSUITE.sh.  build_test_filter()
# reads the headers, run_test() runs the file subtests in order between
# the subtests of $TESTSUITE.sh, and complete_test() runs any left over.
# See README-ltsh.md for the file format and header fields.
#
declare -gA LTSH_META		# "subtest:key" and "file:ids" metadata
declare -gA LTSH_SOURCED	# files that have been sourced
LTSH_QUEUE=()			# subtests from files, in run order
LTSH_NEXT=0			# index of the next subtest in $LTSH_QUEUE
LTSH_INIT=false
LTSH_STATE=unknown		# filesystem state, see ltsh_state_change()
LTSH_REASON=""			# why the current subtest cannot run
LTSH_ACTIONS=""			# setup for the current subtest
LTSH_LAST=""			# last run_test in $TESTSUITE.sh
LTSH_RESTORE=""			# mount or setup before the next subtest
				# of $TESTSUITE.sh, see ltsh_finish()
# header lists that the subtests add to those for the whole file
LTSH_LISTS="keywords modifies observes"
# shared state that a subtest changes, or reads and so needs unchanged,
# described in README-ltsh.md
LTSH_MODIFIES="fail_loc tunables config mount format pools layout quota "
LTSH_MODIFIES+="changelog hsm nodemap lnet debug"
LTSH_OBSERVES="stats grant free_space free_inodes changelog debug_log "
LTSH_OBSERVES+="console locks"

# Print the sort key of subtest $1 into variable $2: the subtest number
# zero-padded, then the suffix with its case inverted so that "a-z" sort
# before "A-Z" in the C locale.  Names without a number sort last.
ltsh_sort_key() {
	local num=${1%%[!0-9]*}
	local suffix=${1#"$num"}

	if [[ -z "$num" ]]; then
		printf -v "$2" "~%s" "$1"
	else
		printf -v "$2" "%010d%s" $((10#$num)) "${suffix~~}"
	fi
}

# Return success if sort key $1 comes before sort key $2
ltsh_key_before() {
	local LC_ALL=C

	[[ "$1" < "$2" ]]
}

# Read the header of subtest file $1 into LTSH_META
ltsh_load() {
	local file=$1
	local short=${file#"$LUSTRE/tests/"}
	local known=" summary description jira commit keywords duration "
	known+="requires start end fsck expect slow always_except modifies "
	known+="observes "
	local -A defaults=()
	local -A meta=()
	local -A keys=()
	local -a ids=()
	local errors=""
	local path value id key

	while IFS=$'\t' read -r path value; do
		value=${value//\\n/$'\n'}
		case "$path" in
		_error*)
			errors+="$short: $value; "
			;;
		subtests.*)
			id=${path#subtests.}
			key=summary
			[[ "$id" != *.* ]] || key=${id#*.}
			id=${id%%.*}
			if [[ ! -v keys[$id] ]]; then
				ids+=($id)
				keys[$id]=""
			fi
			meta[$id:$key]=$value
			keys[$id]+=" $key"
			;;
		*)
			defaults[$path]=$value
			;;
		esac
	done < <(awk -f $LUSTRE/tests/ltsh.awk "$file")

	# every test_*() is a subtest, so helpers need other names
	local -a funcs=()
	local -a helpers=()
	local func

	for func in $(awk -F'[ (]' '/^test_[A-Za-z0-9_]+ *\(\)/ {
			print substr($1, 6) }' "$file"); do
		[[ "$func" =~ ^[0-9]+[A-Za-z]*$ ]] && funcs+=($func) ||
			helpers+=(test_$func)
	done

	# without "subtests:", the header is for the only subtest in the file
	if (( ${#ids[@]} == 0 && ${#funcs[@]} == 1 )); then
		ids=(${funcs[0]})
		keys[${funcs[0]}]=""
	elif (( ${#ids[@]} == 0 && ${#funcs[@]} > 1 )); then
		errors+="$short: several test_NNN() need subtests: in header; "
	elif (( ${#ids[@]} == 0 )); then
		errors+="$short: no subtests; "
	fi
	(( ${#helpers[@]} == 0 )) ||
		errors+="$short: rename ${helpers[*]}, e.g. sub_test_NNN; "
	[[ -z "$errors" ]] || log "$errors"

	# report subtests missing from the header as failures
	for id in "${funcs[@]}"; do
		[[ ! -v keys[$id] ]] || continue
		ids+=($id)
		meta[$id:summary]="from $short"
		keys[$id]=" summary"
		[[ -n "$errors" ]] ||
			meta[$id:invalid]="test_$id not in $short header; "
	done

	for id in "${ids[@]}"; do
		local invalid=$errors${meta[$id:invalid]}

		if ! [[ "$id" =~ ^[A-Za-z0-9_]+$ ]]; then
			log "$short: bad subtest name '$id', ignored"
			continue
		fi
		if [[ -v LTSH_META[$id:file] ]]; then
			local first=${LTSH_META[$id:file]#"$LUSTRE/tests/"}

			log "$short: $id also in $first, ignored"
			LTSH_META[$id:invalid]+="also in $short; "
			continue
		fi
		LTSH_META[$id:file]=$file
		LTSH_META[$file:ids]+=" $id"

		for key in ${keys[$id]}; do
			LTSH_META[$id:$key]=${meta[$id:$key]}
		done
		for key in "${!defaults[@]}"; do
			if [[ " ${keys[$id]} " != *" $key "* ]]; then
				LTSH_META[$id:$key]=${defaults[$key]}
				keys[$id]+=" $key"
			elif [[ " $LTSH_LISTS " == *" $key "* ]]; then
				# lists of the file add to those of the subtest
				LTSH_META[$id:$key]+=" ${defaults[$key]}"
			fi
		done
		LTSH_META[$id:keys]=${keys[$id]}

		for key in ${keys[$id]}; do
			[[ "$known" == *" ${key%%.*} "* ]] ||
				invalid+="unknown key '$key'; "
		done
		[[ -n "${LTSH_META[$id:summary]}" ]] ||
			invalid+="no summary; "
		# banner() runs the summary through "bash -c" on every node
		[[ "${LTSH_META[$id:summary]}" != *[\`\$]* ]] ||
			invalid+="\` or \$ in summary; "
		value=${LTSH_META[$id:fsck]}
		[[ "$value" =~ ^(each|last)?$ ]] ||
			invalid+="bad fsck '$value'; "
		local states="mounted|unmounted|stopped|formatted"

		for key in start end; do
			value=${LTSH_META[$id:$key]}
			[[ "$value" =~ ^($states)?$ ]] ||
				invalid+="bad $key '$value'; "
		done

		# subtests start mounted and leave things as they found them,
		# but do not reformat again at the end after "start: formatted"
		value=${LTSH_META[$id:start]:-mounted}
		LTSH_META[$id:start]=$value
		[[ "$value" != formatted ]] || value=stopped
		LTSH_META[$id:end]=${LTSH_META[$id:end]:-$value}
		# a state change remounts, and a reformat changes all state
		if [[ "${LTSH_META[$id:start]} ${LTSH_META[$id:end]}" != \
		      "mounted mounted" ]]; then
			[[ " ${keys[$id]} " == *" modifies "* ]] ||
				keys[$id]+=" modifies"
			LTSH_META[$id:modifies]+=" mount"
		fi
		[[ "${LTSH_META[$id:start]} ${LTSH_META[$id:end]}" != \
		   *formatted* ]] || LTSH_META[$id:modifies]+=" format"
		LTSH_META[$id:keys]=${keys[$id]}
		for value in ${LTSH_META[$id:keywords]}; do
			[[ "$value" =~ ^[a-z0-9][a-z0-9_-]{1,19}$ ]] ||
				invalid+="bad keyword '$value'; "
		done
		for value in ${LTSH_META[$id:modifies]}; do
			[[ " $LTSH_MODIFIES " == *" $value "* ]] ||
				invalid+="bad modifies '$value'; "
		done
		for value in ${LTSH_META[$id:observes]}; do
			[[ " $LTSH_OBSERVES " == *" $value "* ]] ||
				invalid+="bad observes '$value'; "
		done
		value=${LTSH_META[$id:duration]}
		[[ "$value" =~ ^([1-9][0-9]*)?$ ]] ||
			invalid+="bad duration '$value'; "
		value=${LTSH_META[$id:expect]}
		[[ "$value" =~ ^(pass|must_fail|should_fail)?$ ]] ||
			invalid+="bad expect '$value'; "

		value=${LTSH_META[$id:always_except]}
		if [[ "$value" =~ ^[[:upper:]]+-[[:digit:]]+$ ]]; then
			always_except $value $id
		elif [[ -n "$value" ]]; then
			invalid+="bad always_except '$value'; "
		fi
		[[ "$SLOW" == "no" &&
		   "${LTSH_META[$id:slow]}" =~ ^(true|yes)$ ]] &&
			EXCEPT_SLOW+=" $id"

		LTSH_META[$id:invalid]=$invalid
		ltsh_sort_key $id key
		LTSH_META[$id:sortkey]=$key
		LTSH_QUEUE+=($id)
	done
}

# Find the subtest files of $TESTSUITE and put their subtests in run order
ltsh_init() {
	local dir=${LTSH_DIR:-$LUSTRE/tests/$TESTSUITE.d}
	local file

	$LTSH_INIT && return 0
	LTSH_INIT=true
	[[ -d "$dir" ]] || return 0
	local script=$LUSTRE/tests/$TESTSUITE.sh

	[[ ! -f $script ]] ||
		LTSH_LAST=$(awk '/^run_test(_must_fail|_should_fail)? / {
					n = $2 } END { print n }' \
			    $script)

	for file in $(LC_ALL=C ls "$dir"/*.ltsh 2>/dev/null); do
		ltsh_load $file
	done
	(( ${#LTSH_QUEUE[@]} > 0 )) || return 0

	local id

	LTSH_QUEUE=($(for id in ${LTSH_QUEUE[*]}; do
			echo "${LTSH_META[$id:sortkey]} $id"
		done | LC_ALL=C sort | awk '{ print $2 }'))
	# the last subtest of each file, for "fsck: last"
	for id in ${LTSH_QUEUE[*]}; do
		LTSH_META[${LTSH_META[$id:file]}:last]=$id
	done
	log "subtests in $dir: ${LTSH_QUEUE[*]}"
}

# Read subtest names from stdin and print them with those from subtest
# files added in run order
ltsh_merge_list() {
	local id key

	if (( ${#LTSH_QUEUE[@]} == 0 )); then
		cat
		return 0
	fi

	local next=0
	while read -r id; do
		# helpers like test_renamefs() are not subtests
		if [[ ! "$id" =~ ^[0-9] ]]; then
			echo $id
			continue
		fi
		ltsh_sort_key $id key
		while (( next < ${#LTSH_QUEUE[@]} )) &&
		      ltsh_key_before \
			${LTSH_META[${LTSH_QUEUE[next]}:sortkey]} $key; do
			echo ${LTSH_QUEUE[next++]}
		done
		echo $id
	done
	while (( next < ${#LTSH_QUEUE[@]} )); do
		echo ${LTSH_QUEUE[next++]}
	done
}

# Run the subtests from subtest files that sort before subtest $1, or all
# that are left if no subtest is given.  The locals are visible to the
# subtests, so they have names that subtests are unlikely to use.
ltsh_run_before() {
	local ltsh_key
	local LTSH_RUNNING=true
	# not the run_test_must_fail() of the subtest being run from the suite
	local ERROR_TYPE=

	[[ -z "$1" ]] || ltsh_sort_key $1 ltsh_key
	while (( LTSH_NEXT < ${#LTSH_QUEUE[@]} )); do
		local ltsh_id=${LTSH_QUEUE[LTSH_NEXT]}
		local ltsh_runner=run_test
		local ltsh_expect=${LTSH_META[$ltsh_id:expect]}

		[[ -z "$1" ]] ||
			ltsh_key_before ${LTSH_META[$ltsh_id:sortkey]} \
				$ltsh_key || break
		LTSH_NEXT=$((LTSH_NEXT + 1))

		[[ ! "$ltsh_expect" =~ ^(must|should)_fail$ ]] ||
			ltsh_runner=run_test_$ltsh_expect
		local ltsh_msg=${LTSH_META[$ltsh_id:summary]}
		local ltsh_jira=${LTSH_META[$ltsh_id:jira]}
		local ltsh_re='\("([A-Z]+-[0-9]+) '

		# or the ticket of the first commit that added the subtest
		[[ -n "$ltsh_jira" ||
		   ! "${LTSH_META[$ltsh_id:commit]}" =~ $ltsh_re ]] ||
			ltsh_jira=${BASH_REMATCH[1]}
		[[ -z "$ltsh_jira" ]] || ltsh_msg+=" ($ltsh_jira)"
		$ltsh_runner $ltsh_id "$ltsh_msg"
	done
}

# Source the subtest file that holds subtest $1, if not done already.  Code
# at the top level of the file sees the locals, hence their names.
ltsh_source() {
	local ltsh_file=${LTSH_META[$1:file]}
	local ltsh_short=${ltsh_file#"$LUSTRE/tests/"}
	local ltsh_id ltsh_func

	[[ -v LTSH_SOURCED[$ltsh_file] ]] && return 0
	LTSH_SOURCED[$ltsh_file]=true

	for ltsh_id in ${LTSH_META[$ltsh_file:ids]}; do
		declare -F test_$ltsh_id > /dev/null || continue
		LTSH_META[$ltsh_id:invalid]+="also in $TESTSUITE.sh; "
	done
	for ltsh_func in $(awk -F'[ (]' '/^[A-Za-z_][A-Za-z0-9_]* *\(\)/ {
			print $1 }' $ltsh_file); do
		[[ "$ltsh_func" == test_* ]] ||
			! declare -F $ltsh_func > /dev/null ||
			log "$ltsh_short: replaces $ltsh_func()"
	done

	. $ltsh_file || log "$ltsh_short: returned $?"

	for ltsh_id in ${LTSH_META[$ltsh_file:ids]}; do
		declare -F test_$ltsh_id > /dev/null ||
			LTSH_META[$ltsh_id:invalid]+="test_$ltsh_id() missing; "
	done
}

# Check requirement $1 with value $2 from a subtest file header.  Return
# success if the test configuration meets it, else print the reason as
# "skip|skip_env|error: reason".
ltsh_check_require() {
	local req=$1
	local value=${2//$'\n'/ }

	case "$req" in
	mdtcount|ostcount|clientcount|mdsnodes|ossnodes)
		local have what

		[[ "$value" =~ ^[0-9]+$ ]] || {
			echo "error: bad $req '$value'"
			return 1
		}
		case "$req" in
		mdtcount) have=$MDSCOUNT; what=MDTs ;;
		ostcount) have=$OSTCOUNT; what=OSTs ;;
		clientcount) have=$CLIENTCOUNT; what=clients ;;
		mdsnodes) have=$(mdts_nodes); what="MDS nodes" ;;
		ossnodes) have=$(osts_nodes); what="OSS nodes" ;;
		esac
		# the node lists are comma-separated host names
		[[ "$req" != *nodes ]] || have=$(tr , '\n' <<< "$have" | wc -l)
		(( ${have:-1} >= value )) && return 0
		echo "skip: needs >= $value $what"
		;;
	*_version)
		local facet=${req%_version}
		local var=${facet^^}_VERSION
		local ops="<=|>=|==|!=|<|>"
		local op=">="
		local ver=$value

		[[ "$facet" =~ ^(mds1|ost1|mgs|client)$ && -n "${!var}" ]] || {
			echo "error: unknown $req"
			return 1
		}
		if [[ "$value" =~ ^($ops)[[:space:]]*([[:alnum:]].*)$ ]]; then
			op=${BASH_REMATCH[1]}
			ver=${BASH_REMATCH[2]}
		fi
		# v2_17_52-72-g0631c80b8986 is 2.17.52.72, with the commit
		# count limited to the 8 bits that version_code() has for it,
		# and so is v2_17_52_0-72-g0631c80b8986 from an old "_0" tag
		local re="^v?([0-9]+)[._]([0-9]+)([._]([0-9]+))?([._]([0-9]+))?"

		re+="(-([0-9]+)-g[0-9a-f]+)?$"
		[[ "$ver" =~ $re ]] || {
			echo "error: bad $req '$value'"
			return 1
		}
		local fix=${BASH_REMATCH[8]:-${BASH_REMATCH[6]}}
		local dotted=${BASH_REMATCH[1]}.${BASH_REMATCH[2]}
		dotted+=.${BASH_REMATCH[4]:-0}

		(( ${fix:-0} <= 255 )) || fix=255
		dotted+=${fix:+.$fix}
		(( ${!var} $op $(version_code $dotted) )) && return 0
		echo "skip: need ${facet^^} $op $dotted"
		;;
	fstype|*_fstype)
		local facets=${req%_fstype}
		local facet

		[[ "$req" == fstype ]] && facets="mds1 ost1"
		for facet in $facets; do
			local have=$(facet_fstype $facet)

			[[ " $value " == *" $have "* ]] && continue
			echo "skip: $facet is $have, need $value"
			return 1
		done
		return 0
		;;
	mgs)
		case "$value" in
		separate) combined_mgs_mds || return 0 ;;
		combined) ! combined_mgs_mds || return 0 ;;
		*) echo "error: bad $req '$value'"; return 1 ;;
		esac
		echo "skip: needs $value MGS"
		;;
	tools)
		local tool

		for tool in $value; do
			command -v $tool > /dev/null && continue
			echo "skip_env: $tool not installed"
			return 1
		done
		return 0
		;;
	free_space|free_inodes|mdt_free_*|ost_free_*)
		# checked by ltsh_check_space() when the subtest starts
		[[ "$req" =~ ^((mdt|ost)_)?free_(space|inodes)$ ]] && return 0
		echo "error: unknown $req"
		;;
	*)
		echo "error: unknown $req"
		;;
	esac
	return 1
}

# Print why subtest $1 cannot run in this test configuration as
# "skip|skip_env|error: reason", or nothing if it can run
ltsh_check_static() {
	local id=$1
	local invalid=${LTSH_META[$id:invalid]}
	local key

	if [[ -n "$invalid" ]]; then
		echo "error: ${invalid%; }"
		return 0
	fi
	# run beside other subtests only if known to change and read nothing
	# that they share
	if [[ "$PARALLEL" == "yes" ]] &&
	   [[ " ${LTSH_META[$id:keys]} " != *" modifies "* ||
	      " ${LTSH_META[$id:keys]} " != *" observes "* ||
	      -n "${LTSH_META[$id:modifies]// }" ||
	      -n "${LTSH_META[$id:observes]// }" ]]; then
		echo "skip: skip parallel run"
		return 0
	fi
	local reason=${LTSH_META[$id:requires.reason]}
	local msg

	for key in ${LTSH_META[$id:keys]}; do
		[[ "$key" == requires.* && "$key" != requires.reason ]] ||
			continue
		msg=$(ltsh_check_require ${key#requires.} \
		      "${LTSH_META[$id:$key]}") && continue
		[[ "$msg" != skip* || -z "$reason" ]] || msg+=" for $reason"
		echo "$msg"
		return 0
	done
}

# Convert value $1 with optional K/M/G/T suffix into a number: KiB for
# space, which has no suffix in "lfs df" output, and units for inodes
ltsh_number() {
	local value=${1^^}
	local inodes=$2
	local num=${value%%[!0-9]*}
	local suffix=${value#"$num"}
	local shift=0

	suffix=${suffix%B}
	case "${suffix%I}" in
	"")	shift=0 ;;
	K)	shift=10 ;;
	M)	shift=20 ;;
	G)	shift=30 ;;
	T)	shift=40 ;;
	*)	return 1 ;;
	esac
	[[ -n "$num" ]] || return 1
	$inodes || shift=$((shift > 10 ? shift - 10 : 0))
	echo $((10#$num << shift))
}

# Skip subtest $1 if the filesystem has less free space or inodes than
# its header requires
ltsh_check_space() {
	local id=$1
	local key

	for key in ${LTSH_META[$id:keys]}; do
		[[ "$key" =~ ^requires\.((mdt|ost)_)?free_(space|inodes)$ ]] ||
			continue

		local value=${LTSH_META[$id:$key]}
		local which=--${BASH_REMATCH[2]:-only-summary}
		local field=avail
		local inodes=false
		local need have

		[[ "${BASH_REMATCH[3]}" == inodes ]] && inodes=true
		$inodes && field=iavail
		need=$(ltsh_number "$value" $inodes) ||
			error "bad $key '$value'"
		is_mounted $MOUNT || error "${key#*.} needs $MOUNT mounted"

		# the filesystem total, or the least free MDT or OST
		have=$($LFS df --output=$field --no-header $which $MOUNT |
		       sort -n | head -n 1)
		local why=${LTSH_META[$id:requires.reason]:+" for "}

		why+=${LTSH_META[$id:requires.reason]}
		(( ${have:-0} >= need )) ||
			skip "need ${key#*.} $value, have ${have:-0}$why"
	done
}

# Redo the setup of the mounted filesystem that check_and_setup_lustre()
# did at the start of the suite, such as the root layout and pools.  It
# runs in the subshell of a subtest, so drop the EXIT traps that it adds
# to undo the setup again at the end, as the suite's own traps do that.
ltsh_suite_setup() {
	REFORMAT=no do_check_and_setup_lustre
	trap - EXIT
}

# Reformat the filesystem for "start: formatted" or "end: formatted"
ltsh_format() {
	echo "reformat for $TESTNAME with ${LTSH_FORMAT:-formatall}"
	${LTSH_FORMAT:-formatall} || error "${LTSH_FORMAT:-formatall} failed"
}

# Check the ldiskfs MDTs and OSTs with "e2fsck -n" for a "fsck:" header,
# which leaves the filesystem stopped.  Any problem found is an error.
# Not after a subtest that failed, which may have left problems of its
# own, or was skipped.
ltsh_fsck() {
	local facets=$(get_facets MDS OST)
	local facet dev

	[[ ! -f $LOGDIR/err && ! -f $LOGDIR/skip ]] || return 0
	ltsh_do ${LTSH_CLEANUP:-stopall}
	for facet in ${facets//,/ }; do
		[[ "$(facet_fstype $facet)" == ldiskfs ]] || continue
		case $facet in
		mds*) dev=$(mdsdevname ${facet#mds}) ;;
		ost*) dev=$(ostdevname ${facet#ost}) ;;
		esac
		FSCK_MAX_ERR=0 run_e2fsck $(facet_active_host $facet) $dev -n
	done
}

# Run command $1 (with arguments) to change the filesystem state
ltsh_do() {
	echo "$TESTNAME: $*"
	"$@" || error "$* failed"
}

# Change the filesystem from state $1 to state $2 for a "start:" header.
# States are mounted (servers and client), unmounted (servers only),
# stopped, formatted (stopped after a reformat), and unknown, which is
# checked only with the local client mount.
ltsh_state_change() {
	local from=$1
	local to=$2
	local clients=${CLIENTS:-$HOSTNAME}
	local mount="zconf_mount_clients $clients $MOUNT"
	local umount="zconf_umount_clients $clients $MOUNT"

	[[ "$from" != "$to" ]] || return 0
	if [[ "$from" == unknown ]]; then
		is_mounted $MOUNT && from=mounted
		[[ "$from" != "$to" ]] || return 0
	fi
	[[ "$from" != formatted ]] || from=stopped
	[[ "$from" != "$to" ]] || return 0

	case "$to" in
	mounted)
		if [[ "$from" == unmounted ]]; then
			ltsh_do ${LTSH_MOUNT:-$mount}
		else
			ltsh_do ${LTSH_SETUP:-setupall}
		fi
		;;
	unmounted)
		[[ "$from" == mounted ]] ||
			ltsh_do ${LTSH_SERVERS:-setupall server_only}
		! is_mounted $MOUNT ||
			ltsh_do ${LTSH_UMOUNT:-$umount}
		;;
	stopped)
		ltsh_do ${LTSH_CLEANUP:-stopall}
		;;
	formatted)
		ltsh_format
		;;
	esac
}

# Called in the subshell of subtest $1 before test_$1() runs, so that a
# failure to set up the filesystem fails only this subtest.  Run the
# setup that ltsh_prepare() chose, then check free space and inodes.
ltsh_check() {
	local id=$1
	local reason=$LTSH_REASON
	local action

	# The EXIT traps of the suite, e.g. restore_layout from
	# check_and_setup_lustre(), are listed but not run in this subshell.
	# Drop them, or stack_trap below would run them at the end of the
	# subtest, with the filesystem maybe stopped.
	[[ -z "$LTSH_ACTIONS" ]] || trap - EXIT
	# until the setup is done, see ltsh_finish()
	touch $LOGDIR/ltsh_setup
	[[ -z "$reason" ]] || ${reason%%: *} "${reason#*: }"

	for action in $LTSH_ACTIONS; do
		case $action in
		format_end) stack_trap "ltsh_cleanup ltsh_format" ;;
		fsck) stack_trap "ltsh_cleanup ltsh_fsck" ;;
		mount) ltsh_state_change $LTSH_STATE mounted ;;
		setup) ltsh_state_change $LTSH_STATE mounted
		       ltsh_do ltsh_suite_setup ;;
		start=*) ltsh_state_change $LTSH_STATE ${action#start=} ;;
		esac
	done
	# a pending end reformat clears it only if it is done, since an error
	# in an earlier stack_trap of the subtest skips the rest of them
	[[ " $LTSH_ACTIONS " == *" format_end "* ]] || rm -f $LOGDIR/ltsh_setup
	[[ ! -v LTSH_META[$id:file] ]] || ltsh_check_space $id
}

# Run cleanup command $1 for a subtest header at the end of the subtest,
# leaving $LOGDIR/ltsh_setup if it fails, as ltsh_check() does
ltsh_cleanup() {
	touch $LOGDIR/ltsh_setup
	"$@"
	rm -f $LOGDIR/ltsh_setup
}

# Choose how to set up the filesystem for subtest $1 as its header
# declares, before each repetition, and put it in $LTSH_ACTIONS for
# ltsh_check().  A subtest from $TESTSUITE.sh gets the client mounted
# again, or the suite setup redone, as ltsh_finish() found needed.
ltsh_prepare() {
	local id=$1

	LTSH_REASON=""
	LTSH_ACTIONS=""
	if [[ ! -v LTSH_META[$id:file] ]]; then
		[[ -n "$LTSH_RESTORE" ||
		   ! "$LTSH_STATE" =~ ^(unmounted|stopped|formatted)$ ]] ||
			LTSH_RESTORE=" mount"
		${LTSH_RESTORE_MOUNT:-true} && LTSH_ACTIONS=$LTSH_RESTORE
		LTSH_RESTORE=""
		return 0
	fi

	ltsh_source $id
	LTSH_REASON=$(ltsh_check_static $id)
	[[ -z "$LTSH_REASON" ]] || return 0

	local fsck=${LTSH_META[$id:fsck]}
	local file=${LTSH_META[$id:file]}

	# the end reformat and fsck are a stack_trap, so they also run if
	# test_$id fails, and fsck is not needed before a reformat
	if [[ "${LTSH_META[$id:end]}" == formatted ]]; then
		LTSH_ACTIONS+=" format_end"
	elif [[ "$fsck" == each ||
		"$fsck" == last && "${LTSH_META[$file:last]}" == "$id" ]]; then
		LTSH_ACTIONS+=" fsck"
	fi
	LTSH_ACTIONS+=" start=${LTSH_META[$id:start]}"
}

# Record the filesystem state after each repetition of subtest $1 with
# exit status $2, from its "end:" header, without checking it.  It is
# unknown after a subtest from $TESTSUITE.sh, or one that did not pass,
# unless it ends formatted.
ltsh_finish() {
	local id=$1
	local rc=$2
	local end=${LTSH_META[$id:end]}
	local setup_failed=false

	# the reformat at the end may not be done after a failed setup or
	# cleanup, which is still an expected failure for "expect:"
	if [[ -f $LOGDIR/ltsh_setup ]]; then
		rm -f $LOGDIR/ltsh_setup
		setup_failed=true
	fi
	# a subtest skipped by its header did not change the filesystem
	[[ -z "$LTSH_REASON" ]] || return 0
	LTSH_STATE=unknown
	[[ -v LTSH_META[$id:file] ]] || return 0

	# formatall loses the root layout and pools that the suite set up
	[[ -n "$LTSH_FORMAT" ||
	   "${LTSH_META[$id:start]} $end" != *formatted* ]] ||
		LTSH_RESTORE=" setup"

	# fsck leaves the filesystem stopped
	[[ " $LTSH_ACTIONS " != *" fsck "* ]] || end=stopped
	# the end reformat runs even if the subtest failed
	if [[ "$end" == formatted ]]; then
		$setup_failed || LTSH_STATE=$end
	elif (( rc == 0 )) && [[ ! -f $LOGDIR/err && ! -f $LOGDIR/skip ]]; then
		LTSH_STATE=$end
	fi
	# a failed subtest may have left the client unmounted
	[[ "$LTSH_STATE" != unknown || "$LTSH_RESTORE" == *setup* ]] ||
		LTSH_RESTORE=" mount"
}

# Run the subtests from subtest files that sort after the last subtest in
# $TESTSUITE.sh once it has run, before the suite's own cleanup
ltsh_run_after() {
	[[ -z "$LTSH_RUNNING" && "$1" == "$LTSH_LAST" ]] || return 0
	ltsh_run_before
}
