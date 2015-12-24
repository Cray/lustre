/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */

/*
 * Copyright 2015 Cray Inc. All rights reserved.
 * Authors: Patrick Farrell, Frank Zago
 *
 * A few portions are extracted from llapi_layout_test.c
 *
 * The purpose of this test is to exercise the lock ahead ioctl.
 *
 * The program will exit as soon as a test fails.
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>

#include <lustre/lustreapi.h>
#include <lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__);

#define DIE(fmt, ...)				\
	do {					\
		ERROR(fmt, ## __VA_ARGS__);	\
		exit(EXIT_FAILURE);		\
	} while (0)

#define ASSERTF(cond, fmt, ...)						\
	do {								\
		if (!(cond))						\
			DIE("assertion '%s' failed: "fmt,		\
			    #cond, ## __VA_ARGS__);			\
	} while (0)

#define PERFORM(testfn) \
	do {								\
		cleanup();						\
		fprintf(stderr, "Starting test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		cleanup();						\
	} while (0)

/* Name of file/directory. Will be set once and will not change. */
static char mainpath[PATH_MAX];
static const char *maindir = "locak_ahead_test_name_65436563";

static char fsmountdir[PATH_MAX];	/* Lustre mountpoint */
static char *lustre_dir;		/* Test directory inside Lustre */

/* Cleanup our test file. */
static void cleanup(void)
{
	unlink(mainpath);
}

/* Test valid single lock ahead request */
static void test10(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	lla = alloc_lla(count, WRITE_USER, 0);

	lla->lla_extents[0].end = write_size - 1;
	lla->lla_extents[0].result = 345678;

	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == 0,
		"cannot lock ahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(lla->lla_extents[0].result == 0, "unexpected extent result: %d",
		lla->lla_extents[0].result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	free(lla);

	close(fd);
}

/* Get lock, wait until lock is taken */
static void test11(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	lla = alloc_lla(count, WRITE_USER, 0);

	lla->lla_extents[0].end = write_size - 1;
	lla->lla_extents[0].result = 345678;

	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == 0,
		"cannot lock ahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(lla->lla_extents[0].result == 0, "unexpected extent result: %d",
		lla->lla_extents[0].result);

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */

		lla->lla_extents[0].result = 456789;
		rc = llapi_lock_ahead(fd, lla);
		ASSERTF(rc == 0, "cannot lock ahead '%s': %s",
			mainpath, strerror(errno));

		if (lla->lla_extents[0].result > 0)
			break;
	}

	printf("exited wait loop after %f seconds\n", i * 0.1);

	ASSERTF(lla->lla_extents[0].result > 0,
		"unexpected extent result: %d",
		lla->lla_extents[0].result);

	/* Again. This time it is always there. */
	for (i = 0; i < 100; i++) {
		lla->lla_extents[0].result = 456789;
		rc = llapi_lock_ahead(fd, lla);
		ASSERTF(rc == 0, "cannot lock ahead '%s': %s",
			mainpath, strerror(errno));
		ASSERTF(lla->lla_extents[0].result > 0,
			"unexpected extent result: %d",
			lla->lla_extents[0].result);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	free(lla);

	close(fd);
}

/* Test with several times the same extent */
static void test12(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 10;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	lla = alloc_lla(count, WRITE_USER, 0);

	for (i = 0; i < count; i++) {
		lla->lla_extents[i].end = write_size - 1;
		lla->lla_extents[i].result = 98674;
	}

	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == 0,
		"cannot lock ahead '%s': %s", mainpath, strerror(errno));
	for (i = 0; i < count; i++) {
		ASSERTF(lla->lla_extents[i].result >= 0,
			"unexpected extent result for extent %d: %d",
			i, lla->lla_extents[i].result);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	free(lla);

	close(fd);
}

/* Grow a lock forward */
static void test13(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	for (i = 0; i < 100; i++) {

		lla = alloc_lla(count, WRITE_USER, 0);

		lla->lla_extents[0].end = i * write_size - 1;
		lla->lla_extents[0].result = 98674;

		rc = llapi_lock_ahead(fd, lla);
		ASSERTF(rc == 0, "cannot lock ahead '%s' at offset %llu: %s",
			mainpath,
			lla->lla_extents[0].end,
			strerror(errno));

		ASSERTF(lla->lla_extents[0].result >= 0,
			"unexpected extent result for extent %d: %d",
			i, lla->lla_extents[0].result);

		free(lla);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);
}

/* Grow a lock backward */
static void test14(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	const int num_blocks = 100;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	for (i = 0; i < num_blocks; i++) {

		lla = alloc_lla(count, WRITE_USER, 0);

		lla->lla_extents[0].start = (num_blocks - i - 1) * write_size;
		lla->lla_extents[0].end = (num_blocks) * write_size - 1;
		lla->lla_extents[0].result = 98674;

		rc = llapi_lock_ahead(fd, lla);
		ASSERTF(rc == 0, "cannot lock ahead '%s' at offset %llu: %s",
			mainpath,
			lla->lla_extents[0].end,
			strerror(errno));

		ASSERTF(lla->lla_extents[0].result >= 0,
			"unexpected extent result for extent %d: %d",
			i, lla->lla_extents[0].result);

		free(lla);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);
}

/* Request many locks at 10MiB intervals */
static void test15(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	lla = alloc_lla(count, WRITE_USER, 0);

	for (i = 0; i < 20000; i++) {
		lla->lla_extents[0].start = i * 1024 * 1024 * 10;
		lla->lla_extents[0].end = lla->lla_extents[0].start + 1;

		lla->lla_extents[0].result = 345678;
		rc = llapi_lock_ahead(fd, lla);
		ASSERTF(rc == 0, "cannot lock ahead '%s': %s",
			mainpath, strerror(errno));
		ASSERTF(lla->lla_extents[0].result >= 0,
			"unexpected extent result: %d",
			lla->lla_extents[0].result);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	free(lla);

	close(fd);
}

/* Test llapi_lock_ahead_one function */
static void test16(void)
{
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	rc = llapi_lock_ahead_one(fd, 0, write_size - 1, WRITE_USER, 0);
	ASSERTF(rc == 0,
		"cannot lock ahead '%s': %s", mainpath, strerror(errno));

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);
}

/* Test invalid single lock ahead request */
static void test20(void)
{
	struct llapi_lock_ahead_arg *lla;
	const int count = 1;
	int fd;
	int rc;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* A valid request first */
	lla = alloc_lla(count, WRITE_USER, 0);
	lla->lla_extents[0].end = 1024 * 1024;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == 0, "cannot lock ahead '%s': %s",
		mainpath, strerror(errno));
	free(lla);

	/* No actual block */
	lla = alloc_lla(count, WRITE_USER, 0);
	lla->lla_extents[0].end = 0;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for no block lock: %d %s",
		rc, strerror(errno));
	free(lla);

	/* end before start */
	lla = alloc_lla(count, WRITE_USER, 0);
	lla->lla_extents[0].start = 1024 * 1024;
	lla->lla_extents[0].end = 0;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for reversed block: %d %s",
		rc, strerror(errno));
	free(lla);

	/* bogus lock mode - 0x65464 */
	lla = alloc_lla(count, 0x65464, 0);
	lla->lla_extents[0].end = 1024 * 1024;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus lock mode: %d %s",
		rc, strerror(errno));
	free(lla);

	/* bogus version */
	lla = alloc_lla(count, WRITE_USER, 0);
	lla->lla_extents[0].end = 1024 * 1024;
	lla->lla_version = 0;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus version: %d %s",
		rc, strerror(errno));
	free(lla);

	/* bogus version (2) */
	lla = alloc_lla(count, WRITE_USER, 0);
	lla->lla_extents[0].end = 1024 * 1024;
	lla->lla_version = 2;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus version (2): %d %s",
		rc, strerror(errno));
	free(lla);

	/* bogus flags, 0x80 */
	lla = alloc_lla(count, WRITE_USER, 0x80);
	lla->lla_extents[0].end = 1024 * 1024;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		lla->lla_flags,
		rc, strerror(errno));
	free(lla);

	/* bogus flags, 0xff - CEF_MASK */
	lla = alloc_lla(count, WRITE_USER, 0xff);
	lla->lla_extents[0].end = 1024 * 1024;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		lla->lla_flags,
		rc, strerror(errno));
	free(lla);

	/* bogus flags, 0xffffffff */
	lla = alloc_lla(count, WRITE_USER, 0xffffffff);
	lla->lla_extents[0].end = 1024 * 1024;
	rc = llapi_lock_ahead(fd, lla);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		lla->lla_flags,
		rc, strerror(errno));
	free(lla);

	close(fd);
}

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-d lustre_dir]\n", prog);
	exit(EXIT_FAILURE);
}

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:")) != -1) {
		switch (c) {
		case 'd':
			lustre_dir = optarg;
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
	char fsname[8];
	int rc;

	process_args(argc, argv);
	if (lustre_dir == NULL)
		lustre_dir = "/mnt/lustre";

	rc = llapi_search_mounts(lustre_dir, 0, fsmountdir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: '%s': not a Lustre filesystem\n",
			lustre_dir);
		return EXIT_FAILURE;
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* Create a test filename and reuse it. Remove possibly old files. */
	rc = snprintf(mainpath, sizeof(mainpath), "%s/%s", lustre_dir, maindir);
	ASSERTF(rc > 0 && rc < sizeof(mainpath), "invalid name for mainpath");
	cleanup();

	atexit(cleanup);

	PERFORM(test10);
	PERFORM(test11);
	PERFORM(test12);
	PERFORM(test13);
	PERFORM(test14);
	PERFORM(test15);
	PERFORM(test16);
	PERFORM(test20);

	return EXIT_SUCCESS;
}
