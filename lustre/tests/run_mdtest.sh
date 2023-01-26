#!/bin/bash

TMP=${TMP:-/tmp}

TESTLOG_PREFIX=${TESTLOG_PREFIX:-$TMP/recovery-mds-scale}
TESTNAME=${TESTNAME:-""}
[ -n "$TESTNAME" ] && TESTLOG_PREFIX=$TESTLOG_PREFIX.$TESTNAME

LOG=$TESTLOG_PREFIX.$(basename $0 .sh)_stdout.$(hostname -s).log
DEBUGLOG=$(echo $LOG | sed 's/\(.*\)stdout/\1debug/')

error () {
	echo "$@"
	exit 17
}
ENOSPC_IGNORE=${ENOSPC_IGNORE:-false}
DEBUG_SPACE=${DEBUG_SPACE:-false}
mkdir -p ${LOG%/*}

rm -f $LOG $DEBUGLOG
exec 2>$DEBUGLOG
set -x

. $(dirname $0)/functions.sh

MDTEST=${MDTEST:=$(which mdtest 2> /dev/null || true)}

assert_env MOUNT END_RUN_FILE LOAD_PID_FILE MDTEST

trap signaled TERM

# if MACHINEFILE set and exists -- use it
if [ -z $MACHINEFILE ] || [ ! -e $MACHINEFILE ]; then
    MACHINEFILE=$TMP/$(basename $0)-$(hostname).machines
    echo $(hostname) >$MACHINEFILE
fi

THREADS_PER_CLIENT=${THREADS_PER_CLIENT:-3}
NUM_CLIENTS=$(cat $MACHINEFILE | wc -l)

# recovery-*-scale scripts use this to signal the client loads to die
echo $$ >$LOAD_PID_FILE

TESTDIR=${TESTDIR:-$MOUNT/d0.mdtest-$(hostname)}

while [ ! -e "$END_RUN_FILE" ]; do
	echoerr "$(date +'%F %H:%M:%S'): mdtest run starting"
	rm -rf $TESTDIR
	client_load_mkdir $TESTDIR
	if [ $? -ne 0 ]; then
		echoerr "$(date +'%F %H:%M:%S'): failed to create $TESTDIR"
		echo $(hostname) >> $END_RUN_FILE
		break
	fi

	# need this only if TESTDIR is not default
	chmod -R 777 $TESTDIR

	sync
	if $DEBUG_SPACE; then
		lfs df 1>>$LOG
		lfs df -i 1>>$LOG
	fi
	run_mdtest fpp $TESTDIR  1>>$LOG &

	load_pid=$!
	wait $load_pid
	if [ ${PIPESTATUS[0]} -eq 0 ]; then
        	echoerr "$(date +'%F %H:%M:%S'): mdtest succeeded"
        	cd $TMP
	else
		if enospc_detected $LOG; then
			if $ENOSPC_IGNORE; then
				echoerr "$(date +'%F %H:%M:%S'): mdtest ENOSPC, ignored" &&
				continue
			fi
			echoerr "$(date +'%F %H:%M:%S'): mdtest ENOSPC, ignore=$ENOSPC_IGNORE"
			lfs df 1>>$LOG
			lfs df -i 1>>$LOG
		fi

		echoerr "$(date +'%F %H:%M:%S'): mdtest failed"
		if [ -z "$ERRORS_OK" ]; then
			echo $(hostname) >> $END_RUN_FILE
		fi
	fi
done

echoerr "$(date +'%F %H:%M:%S'): mdtest run exiting"
