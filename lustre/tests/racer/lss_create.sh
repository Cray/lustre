#!/bin/bash

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/../..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
trap - ERR
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

while /bin/true; do
	lsnapshot_create -n lss_$RANDOM || true
	sleep $((RANDOM % 9 + 11))
done
