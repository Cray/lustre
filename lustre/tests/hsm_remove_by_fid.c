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

/* Copyright 2015 Intel Corporation. */
/* Some portions are extracted from llapi_layout_test.c */

/* The purpose of this cmd is to allow submitting of hsm_remove request
 * with the FID as a parameter.
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>

#include <lustre/lustreapi.h>

int main(int argc, char *argv[])
{
	int rc;
	int c;
	int fid_count;
	int i;
	unsigned int archive_id = 0;
	char *mntpath = NULL;
	char fullpath[PATH_MAX];
	struct hsm_user_request	*hur;

	/* process args */
	while ((c = getopt(argc, argv, "a:m:")) != -1) {
		switch (c) {
		case 'a':
			archive_id = atoi(optarg);
			break;
		case 'm':
			mntpath = optarg;
			if (realpath(mntpath, fullpath) == NULL) {
				fprintf(stderr, "Cannot find path '%s': %s\n",
					mntpath, strerror(errno));
				return EXIT_FAILURE;
			}
			break;
		case '?':
		default:
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			fprintf(stderr, "Usage: %s -m mount-point "
					"[-a <archive_id>] FID(s)\n", argv[0]);
			return EXIT_FAILURE;
			break;
		}
	}

	if (mntpath == NULL) {
		fprintf(stderr, "A Lustre mount-point is required\n");
		return EXIT_FAILURE;
	}

	/* all remaining args should be FIDs */
	fid_count = argc - optind;

	if (fid_count == 0) {
		fprintf(stderr, "No FIDs provided\n");
		fprintf(stderr, "Usage: %s -m mount-point [-a <archive_id>] "
				"FID(s)\n", argv[0]);
		return EXIT_FAILURE;
	}
	/* Create and send the remove request. */
	hur = llapi_hsm_user_request_alloc(fid_count, 0);
	if (hur == NULL) {
		fprintf(stderr, "cannot allocate HSM user request: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	hur->hur_request.hr_action = HUA_REMOVE;
	hur->hur_request.hr_archive_id = archive_id;
	hur->hur_request.hr_flags = 0;
	hur->hur_request.hr_itemcount = fid_count;
	hur->hur_request.hr_data_len = 0;

	for (i = 0; i < fid_count; i++) {
		rc = sscanf(argv[optind + i], "0x%llx:0x%x:0x%x",
			    &hur->hur_user_item[i].hui_fid.f_seq,
			    &hur->hur_user_item[i].hui_fid.f_oid,
			    &hur->hur_user_item[i].hui_fid.f_ver);
		if (rc != 3) {
			fprintf(stderr, "hsm: '%s' is not a valid FID\n",
				argv[optind + i]);
			return EXIT_FAILURE;
		}
		hur->hur_user_item[i].hui_extent.length = -1;
	}

	rc = llapi_hsm_request(fullpath, hur);
	if (rc != 0) {
		fprintf(stderr, "llapi_hsm_request failed: %s", strerror(-rc));
		return EXIT_FAILURE;
	}

	free(hur);

	return EXIT_SUCCESS;
}
