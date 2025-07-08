// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

static void usage(char *prog)
{
	printf("usage: %s owner filenamefmt count\n", prog);
	printf("       %s owner filenamefmt start count\n", prog);
}

int main(int argc, char **argv)
{
	int i, rc = 0, mask = 0;
	char format[4096], *fmt;
	char filename[4096];
	long start, last;
	long begin = 0, count;

	if (argc < 4 || argc > 5) {
		usage(argv[0]);
		return 1;
	}

	mask = strtol(argv[1], NULL, 0);

	if (strlen(argv[2]) > 4080) {
		printf("name too long\n");
		return 1;
	}

	start = last = time(0);

	if (argc == 4) {
		count = strtol(argv[3], NULL, 0);
		if (count < 1) {
			printf("count must be at least one\n");
			return 1;
		}
	} else {
		begin = strtol(argv[3], NULL, 0);
		count = strtol(argv[4], NULL, 0);
	}

	if (strchr(argv[2], '%')) {
		fmt = argv[2];
	} else {
		sprintf(format, "%s%%d", argv[2]);
		fmt = format;
	}
	for (i = 0; i < count; i++, begin++) {
		sprintf(filename, fmt, begin);
		rc = chown(filename, mask, -1);
		if (rc) {
			printf("chown (%s) error: %s\n",
			       filename, strerror(errno));
			rc = errno;
			break;
		}
		if ((i % 10000) == 0) {
			printf(" - chowned %d (time %ld ; total %ld ; last %ld)\n", i, time(0), time(0) - start,
			       time(0) - last);
			last = time(0);
		}
	}
	printf("total: %d chowns in %ld seconds: %f chowns/second\n", i,
	       time(0) - start, ((float)i / (time(0) - start)));

	return rc;
}
