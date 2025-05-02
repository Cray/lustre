// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2014, 2015 Cray Inc, all rights reserved.
 * Copyright (c) 2015, Intel Corporation.
 * Copyright (c) 2025, DataDirect Networks, Inc. All rights reserved.
 */

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <lustre/lustreapi.h>
#include "llapi_test_utils.h"

static bool is_bitmap;		/* use old bitmap interface */
static char lustre_dir[PATH_MAX - 5];	/* Lustre test directory */

static void usage(char *prog)
{
	printf("Usage: %s [-d LUSTRE_DIR] [-s SKIP[,SKIP...]] [-t ONLY[,ONLY...]\n",
	       prog);
	exit(0);
}

#define T1_DESC		"Register/unregister copytool 2000x to check for leaks"
static void test1(void)
{
	int i;
	int rc;
	struct hsm_copytool_private *ctdata;

	for (i = 0; i < 2000; i++) {
		rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
						 0, NULL, 0);
		ASSERTF(rc == 0,
			"llapi_hsm_copytool_register failed: %s, loop=%d",
			strerror(-rc), i);

		rc = llapi_hsm_copytool_unregister(&ctdata);
		ASSERTF(rc == 0,
			"llapi_hsm_copytool_unregister failed: %s, loop=%d",
			strerror(-rc), i);
	}
}

#define T2_DESC		"Re/un-register copytool multiple times without error"
static void test2(void)
{
	int rc;
	struct hsm_copytool_private *ctdata1;
	struct hsm_copytool_private *ctdata2;

	rc = llapi_hsm_copytool_register(&ctdata1, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata2, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata2);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata1);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));
}

#define T3_DESC		"Pass bad parameters to llapi_hsm_copytool_register()"
static void test3(void)
{
	int rc;
	struct hsm_copytool_private *ctdata;
	int archives[33];
	int count = sizeof(archives) / sizeof(*archives);

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 1, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, count, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	if (is_bitmap) {
		int i;

		for (i = 0; i < count; i++)
			archives[i] = i + 1;
		rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
						 count, archives, 0);
		ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
			strerror(-rc));
	}

#if 0
	/* BUG? Should that fail or not? */
	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, -1, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));
#endif

	memset(archives, -1, sizeof(archives));
	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 1, archives, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata, "/tmp", 0, NULL, 0);
	ASSERTF(rc == -ENOENT, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));
}

#define T4_DESC		"Bad parameters to llapi_hsm_copytool_unregister()"
static void test4(void)
{
	int rc;

	rc = llapi_hsm_copytool_unregister(NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_unregister error: %s",
		strerror(-rc));
}

#define T5_DESC		"Test llapi_hsm_copytool_recv() in non-blocking mode"
static void test5(void)
{
	int rc;
	int i;
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list	*hal;
	int msgsize;

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, O_NONBLOCK);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	/* Hopefully there is nothing lingering */
	for (i = 0; i < 1000; i++) {
		rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
		ASSERTF(rc == -EAGAIN, "llapi_hsm_copytool_recv error: %s",
			strerror(-rc));
	}

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));
}

#define T6_DESC		"Test llapi_hsm_copytool_recv() with bogus parameters"
static void test6(void)
{
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list *hal;
	int rc;
	int msgsize;

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(NULL, &hal, &msgsize);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, NULL, &msgsize);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, &hal, NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, NULL, NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));
}

#define T7_DESC		"Test event polling (without actual traffic)"
static void test7(void)
{
	int rc;
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list	*hal;
	int msgsize;
	int fd;
	struct pollfd fds[1];

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, O_NONBLOCK);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	fd = llapi_hsm_copytool_get_fd(ctdata);
	ASSERTF(fd >= 0, "llapi_hsm_copytool_get_fd failed: %s",
		strerror(-rc));

	/* Ensure it's read-only */
	rc = write(fd, &rc, 1);
	ASSERTF(rc == -1 && errno == EBADF, "write error: %d, %s",
		rc, strerror(errno));

	rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
	ASSERTF(rc == -EAGAIN, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	rc = poll(fds, 1, 10);
	ASSERTF(rc == 0, "poll failed: %d, %s",
		rc, strerror(errno)); /* no event */

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));
}

/* Create the testfile of a given length. It returns a valid file descriptor. */
static char testfile[PATH_MAX];
static int create_testfile(size_t length)
{
	int rc;
	int fd;

	rc = snprintf(testfile, sizeof(testfile), "%s/hsm_check_test",
		      lustre_dir);
	ASSERTF((rc > 0 && rc < sizeof(testfile)), "invalid name for testfile");

	/* Remove old test file, if any. */
	unlink(testfile);

	/* Use truncate so we can create a file (almost) as big as we
	 * want, while taking 0 bytes of data.
	 */
	fd = creat(testfile, 0700);
	ASSERTF(fd >= 0, "create failed for '%s': %s",
		testfile, strerror(errno));

	rc = ftruncate(fd, length);
	ASSERTF(rc == 0, "ftruncate failed for '%s': %s",
		testfile, strerror(errno));

	return fd;
}

#define T50_DESC		"Test llapi_hsm_state_get()/get_fd()"
static void test50(void)
{
	struct hsm_user_state hus;
	int rc;
	int fd;

	fd = create_testfile(100);

	/* With fd variant */
	rc = llapi_hsm_state_get_fd(fd, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get_fd failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);

	rc = llapi_hsm_state_get_fd(fd, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_state_get_fd error: %s",
		strerror(-rc));

	rc = close(fd);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));

	/* Without fd */
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);

	rc = llapi_hsm_state_get(testfile, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_state_get error: %s",
		strerror(-rc));

	memset(&hus, 0xaa, sizeof(hus));
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);
	ASSERTF(hus.hus_archive_id == 0, "archive_id=%u", hus.hus_archive_id);
	ASSERTF(hus.hus_in_progress_state == 0, "hus_in_progress_state=%u",
		hus.hus_in_progress_state);
	ASSERTF(hus.hus_in_progress_action == 0, "hus_in_progress_action=%u",
		hus.hus_in_progress_action);
}

#define T51_DESC	"Test llapi_hsm_state_set_fd()"
static void test51(void)
{
	int rc;
	int fd;
	int i;
	int test_count;
	struct hsm_user_state hus;

	fd = create_testfile(100);

	rc = llapi_hsm_state_set_fd(fd, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	/* Set archive id */
	if (is_bitmap)
		test_count = 32;
	else
		test_count = 48;
	for (i = 0; i <= test_count; i++) {
		rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, i);
		ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s",
			strerror(-rc));

		rc = llapi_hsm_state_get_fd(fd, &hus);
		ASSERTF(rc == 0, "llapi_hsm_state_get_fd failed: %s",
			strerror(-rc));
		ASSERTF(hus.hus_states == HS_EXISTS, "state=%u",
			hus.hus_states);
		ASSERTF(hus.hus_archive_id == i, "archive_id=%u, i=%d",
			hus.hus_archive_id, i);
	}

	if (is_bitmap) {
		/* Invalid archive numbers */
		rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, 33);
		ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd: %s",
			strerror(-rc));

		rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, 151);
		ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd: %s",
			strerror(-rc));

		rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, -1789);
		ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd: %s",
			strerror(-rc));
	}

	/* Settable flags, with respect of the HSM file state transition rules:
	 *	DIRTY without EXISTS: no dirty if no archive was created
	 *	DIRTY and RELEASED: a dirty file could not be released
	 *	RELEASED without ARCHIVED: do not release a non-archived file
	 *	LOST without ARCHIVED: cannot lost a non-archived file.
	 */
	rc = llapi_hsm_state_set_fd(fd, HS_DIRTY, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_EXISTS, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_DIRTY, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_EXISTS, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_DIRTY, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_RELEASED, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_LOST, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_ARCHIVED, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_RELEASED, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_LOST, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_DIRTY|HS_EXISTS, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_RELEASED, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_DIRTY|HS_EXISTS, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_ARCHIVED, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd failed: %s",
		strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_LOST, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_ARCHIVED, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_NORELEASE, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_NORELEASE, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_NOARCHIVE, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_NOARCHIVE, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	/* Bogus flags for good measure. */
	rc = llapi_hsm_state_set_fd(fd, 0x00080000, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0x80000000, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_state_set_fd: %s", strerror(-rc));

	close(fd);
}

#define T52_DESC	"Test llapi_hsm_current_action()"
static void test52(void)
{
	int rc;
	int fd;
	struct hsm_current_action hca;

	/* No fd equivalent, so close it. */
	fd = create_testfile(100);
	close(fd);

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s", strerror(-rc));
	ASSERTF(hca.hca_state, "hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action, "hca_state=%u", hca.hca_action);

	rc = llapi_hsm_current_action(testfile, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
}

/* Helper to simulate archiving a file. No actual data movement happens. */
static void helper_archiving(void (*progress)
		      (struct hsm_copyaction_private *hcp, size_t length),
		      const size_t length)
{
	int rc;
	int fd;
	struct hsm_copytool_private *ctdata;
	struct hsm_user_request	*hur;
	struct hsm_action_list	*hal;
	struct hsm_action_item	*hai;
	int			 msgsize;
	struct hsm_copyaction_private *hcp;
	struct hsm_user_state hus;

	fd = create_testfile(length);

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	/* Create and send the archive request. */
	hur = llapi_hsm_user_request_alloc(1, 0);
	ASSERTF(hur != NULL, "llapi_hsm_user_request_alloc returned NULL");

	hur->hur_request.hr_action = HUA_ARCHIVE;
	hur->hur_request.hr_archive_id = 1;
	hur->hur_request.hr_flags = 0;
	hur->hur_request.hr_itemcount = 1;
	hur->hur_request.hr_data_len = 0;
	hur->hur_user_item[0].hui_extent.offset = 0;
	hur->hur_user_item[0].hui_extent.length = -1;

	rc = llapi_fd2fid(fd, &hur->hur_user_item[0].hui_fid);
	ASSERTF(rc == 0, "llapi_fd2fid failed: %s", strerror(-rc));

	close(fd);

	rc = llapi_hsm_request(testfile, hur);
	ASSERTF(rc == 0, "llapi_hsm_request failed: %s", strerror(-rc));

	free(hur);

	/* Read the request */
	rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
	ASSERTF(rc == 0, "llapi_hsm_copytool_recv failed: %s", strerror(-rc));
	ASSERTF(hal->hal_count == 1, "hal_count=%d", hal->hal_count);

	hai = hai_first(hal);
	ASSERTF(hai != NULL, "hai_first returned NULL");
	ASSERTF(hai->hai_action == HSMA_ARCHIVE,
		"hai_action=%d", hai->hai_action);

	/* "Begin" archiving */
	hcp = NULL;
	rc = llapi_hsm_action_begin(&hcp, ctdata, hai, -1, 0, false);
	ASSERTF(rc == 0, "llapi_hsm_action_begin failed: %s", strerror(-rc));
	ASSERTF(hcp != NULL, "hcp is NULL");

	if (progress)
		progress(hcp, length);

	/* Done archiving */
	rc = llapi_hsm_action_end(&hcp, &hai->hai_extent, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_end failed: %s", strerror(-rc));
	ASSERTF(hcp == NULL, "hcp is NULL");

	/* Close HSM client */
	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	/* Final check */
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == (HS_EXISTS | HS_ARCHIVED),
		"state=%u", hus.hus_states);
}

#define T100_DESC	"Simple archive creation with no progress reported."
static void test100(void)
{
	const size_t length = 100;

	helper_archiving(NULL, length);
}

#define T101_DESC	"Simple archive creation with progress every byte."
static void test101_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int i;
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	/* Report progress. 1 byte at a time :) */
	for (i = 0; i < length; i++) {
		he.offset = i;
		he.length = 1;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));
	}

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test101(void)
{
	const size_t length = 1000;

	helper_archiving(test101_progress, length);
}

#define T102_DESC	"Archive creation with progress every byte, backwards"
static void test102_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int i;
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	/* Report progress. 1 byte at a time :) */
	for (i = length-1; i >= 0; i--) {
		he.offset = i;
		he.length = 1;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));
	}

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test102(void)
{
	const size_t length = 1000;

	helper_archiving(test102_progress, length);
}

#define T103_DESC	"Archive creation with a single progress report"
static void test103_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = 0;
	he.length = length;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test103(void)
{
	const size_t length = 1000;

	helper_archiving(test103_progress, length);
}

#define T104_DESC	"Archive creation with two progress reports"
static void test104_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = 0;
	he.length = length/2;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	he.offset = length/2;
	he.length = length/2;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test104(void)
{
	const size_t length = 1000;

	helper_archiving(test104_progress, length);
}

#define T105_DESC	"Archive creation with one bogus progress report"
static void test105_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = 2*length;
	he.length = 10*length;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);

	/* BUG - offset should be 2*length, or length should be 8*length */
	ASSERTF(hca.hca_location.length == 10*length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test105(void)
{
	const size_t length = 1000;

	helper_archiving(test105_progress, length);
}

#define T106_DESC	"Archive creation with one empty progress report"
static void test106_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = 0;
	he.length = 0;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == 0,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test106(void)
{
	const size_t length = 1000;

	helper_archiving(test106_progress, length);
}

#define T107_DESC	"Archive creation with one bogus progress report"
static void test107_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = -1;
	he.length = 10;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_action_progress error: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == 0,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test107(void)
{
	const size_t length = 1000;

	helper_archiving(test107_progress, length);
}

#define T108_DESC	"Archive creation with same progress report each time"
static void test108_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	int i;
	struct hsm_current_action hca;

	for (i = 0; i < 1000; i++) {
		he.offset = 0;
		he.length = length;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));
	}

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == length,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test108(void)
{
	const size_t length = 1000;

	helper_archiving(test108_progress, length);
}

#define T109_DESC	"Archive creation with one report, with large number"
static void test109_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	struct hsm_extent he;
	struct hsm_current_action hca;

	he.offset = 0;
	he.length = 0xffffffffffffffffULL;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
		strerror(-rc));

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
	ASSERTF(hca.hca_state == HPS_RUNNING,
		"hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action == HUA_ARCHIVE,
		"hca_state=%u", hca.hca_action);
	ASSERTF(hca.hca_location.length == 0xffffffffffffffffULL,
		"length=%llu", (unsigned long long)hca.hca_location.length);
}

static void test109(void)
{
	const size_t length = 1000;

	helper_archiving(test109_progress, length);
}

#define T110_DESC	"Archive with 10 progress reports, checking progress"
static void test110_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	int i;
	struct hsm_extent he;
	struct hsm_current_action hca;

	for (i = 0; i < 10; i++) {
		he.offset = i*length/10;
		he.length = length/10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == (i+1)*length/10,
			"i=%d, length=%llu",
			i, (unsigned long long)hca.hca_location.length);
	}
}

static void test110(void)
{
	const size_t length = 1000;

	helper_archiving(test110_progress, length);
}

#define T111_DESC	"Archive with 10 reports in reverse, checking progress"
static void test111_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	int i;
	struct hsm_extent he;
	struct hsm_current_action hca;

	for (i = 0; i < 10; i++) {
		he.offset = (9-i)*length/10;
		he.length = length/10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == (i+1)*length/10,
			"i=%d, length=%llu",
			i, (unsigned long long)hca.hca_location.length);
	}
}

static void test111(void)
{
	const size_t length = 1000;

	helper_archiving(test111_progress, length);
}

#define T112_DESC	"Archive with 10 reports, duplicated, check progress"
static void test112_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	int i;
	struct hsm_extent he;
	struct hsm_current_action hca;

	for (i = 0; i < 10; i++) {
		he.offset = i*length/10;
		he.length = length/10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == (i+1)*length/10,
			"i=%d, length=%llu",
			i, (unsigned long long)hca.hca_location.length);
	}

	for (i = 0; i < 10; i++) {
		he.offset = i*length/10;
		he.length = length/10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"i=%d, length=%llu",
			i, (unsigned long long)hca.hca_location.length);
	}
}

static void test112(void)
{
	const size_t length = 1000;

	helper_archiving(test112_progress, length);
}

#define T113_DESC	"Archive with 9 reports, with 20% overlapping coverage"
static void test113_progress(struct hsm_copyaction_private *hcp, size_t length)
{
	int rc;
	int i;
	struct hsm_extent he;
	struct hsm_current_action hca;

	for (i = 0; i < 9; i++) {
		he.offset = i*length/10;
		he.length = 2*length/10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == (i+2)*length/10,
			"i=%d, length=%llu",
			i, (unsigned long long)hca.hca_location.length);
	}
}

static void test113(void)
{
	const size_t length = 1000;

	helper_archiving(test113_progress, length);
}

static struct test_tbl_entry test_tbl[] = {
	TEST_REGISTER(1),
	TEST_REGISTER(2),
	TEST_REGISTER(3),
	TEST_REGISTER(4),
	TEST_REGISTER(5),
	TEST_REGISTER(6),
	TEST_REGISTER(7),
	TEST_REGISTER(50),
	TEST_REGISTER(51),
	TEST_REGISTER(52),
	TEST_REGISTER(100),
	TEST_REGISTER(101),
	TEST_REGISTER(102),
	TEST_REGISTER(103),
	TEST_REGISTER(104),
	TEST_REGISTER(105),
	TEST_REGISTER(106),
	TEST_REGISTER(107),
	TEST_REGISTER(108),
	TEST_REGISTER(109),
	TEST_REGISTER(110),
	TEST_REGISTER(111),
	TEST_REGISTER(112),
	TEST_REGISTER(113),
	TEST_REGISTER_END
};

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "bd:s:t:")) != -1) {
		switch (c) {
		case 'b':
			is_bitmap = true;
		case 'd':
			if (snprintf(lustre_dir, sizeof(lustre_dir), "%s",
				     optarg) >= sizeof(lustre_dir))
				DIE("Error: test directory name too long\n");
			break;
		case 's':
			set_tests_to_skip(optarg, test_tbl);
			break;
		case 't':
			set_tests_to_run(optarg, test_tbl);
			break;
		case '?':
		default:
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(argv[0]);
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	process_args(argc, argv);

	return run_tests(lustre_dir, test_tbl);
}
