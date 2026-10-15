#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Test the running of subtests from .ltsh files (README-ltsh.md).  Most of
# the subtests are in sanity-ltsh.d/; those here check what the framework
# does before a subtest of the suite script.
set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

ALWAYS_EXCEPT="$SANITY_LTSH_EXCEPT "
build_test_filter

FAIL_ON_ERROR=false
# a root layout to check that the suite setup is redone after a reformat
sanity_ltsh_STRIPEPARAMS=${sanity_ltsh_STRIPEPARAMS:-"-S 3M"}

check_and_setup_lustre

test_6b() {
	is_mounted $MOUNT || error "$MOUNT not mounted again after 6a failed"
}
run_test 6b "client mounted again after a failed file subtest"

# check that the root layout is that of sanity_ltsh_STRIPEPARAMS
check_root_layout_7() {
	${do_setup:-true} || skip "suite setup disabled"
	[[ "$sanity_ltsh_STRIPEPARAMS" == "-S 3M" ]] ||
		skip "sanity_ltsh_STRIPEPARAMS is '$sanity_ltsh_STRIPEPARAMS'"

	local size=$($LFS getstripe -d -S $MOUNT)

	(( size == 3 * 1024 * 1024 )) ||
		error "root stripe size $size after 7a reformat, not 3M"
}

test_7b() {
	is_mounted $MOUNT || error "$MOUNT not mounted again after 7a"
	check_root_layout_7
}
run_test 7b "root layout restored after a file subtest reformat"

test_7c() {
	check_root_layout_7
}
run_test 7c "root layout still restored in the next subtest"

complete_test $SECONDS
check_and_cleanup_lustre
exit_status
