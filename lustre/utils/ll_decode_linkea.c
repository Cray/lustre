// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016, DDN Storage Corporation.
 */
/*
 * lustre/utils/ll_decode_linkea.c
 *
 * Tool for printing the MDT link_ea structure on the objects
 * in human readable form.
 *
 * Author: Li Xi <lixi@ddn.com>
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/lustre/lustre_fid.h>

#define BUFFER_SIZE 65536

static void print_name(const char *cp, int len)
{
	unsigned char ch;

	while (len--) {
		ch = *cp++;
		if (!isprint(ch) || ch == '\\')
			printf("\\x%02x", ch);
		else
			putchar(ch);
	}
}

static int decode_linkea(const char *fname)
{
	char buf[BUFFER_SIZE];
	struct link_ea_header *leh;
	ssize_t size;
	struct link_ea_entry *lee;
	int i;
	__u64 length;
	int reclen;
	struct lu_fid pfid;

	size = getxattr(fname, "trusted.link", buf, BUFFER_SIZE);
	if (size < 0) {
		if (errno == ERANGE) {
			fprintf(stderr, "%s: failed to read trusted.link "
				"xattr, the buffer size %u might be too "
				"small\n", fname, BUFFER_SIZE);
		} else {
			fprintf(stderr,
				"%s: failed to read trusted.link xattr: %s\n",
				fname, strerror(errno));
		}
		return -1;
	}

	leh = (struct link_ea_header *)buf;
	if (leh->leh_magic == __swab32(LINK_EA_MAGIC)) {
		leh->leh_magic = LINK_EA_MAGIC;
		leh->leh_reccount = __swab32(leh->leh_reccount);
		leh->leh_len = __swab64(leh->leh_len);
	}
	if (leh->leh_magic != LINK_EA_MAGIC) {
		fprintf(stderr,
			"%s: magic mismatch, expected 0x%lx, got 0x%x\n",
			fname, LINK_EA_MAGIC, leh->leh_magic);
		return -1;
	}
	if (leh->leh_reccount == 0) {
		fprintf(stderr, "%s: empty record count\n", fname);
		return -1;
	}
	if (leh->leh_len > size) {
		fprintf(stderr,
			"%s: invalid length %llu, should smaller than %zd\n",
			fname, (unsigned long long)leh->leh_len, size);
		return -1;
	}

	length = sizeof(struct link_ea_header);
	lee = (struct link_ea_entry *)(leh + 1);
	printf("%s: count %u\n", fname, leh->leh_reccount);
	for (i = 0; i < leh->leh_reccount; i++) {
		reclen = (lee->lee_reclen[0] << 8) | lee->lee_reclen[1];
		length += reclen;
		if (length > leh->leh_len) {
			fprintf(stderr,
				"%s: length exceeded, expected %llu, got %llu\n",
				fname, (unsigned long long)leh->leh_len,
				(unsigned long long)length);
			return -1;
		}
		memcpy(&pfid, &lee->lee_parent_fid, sizeof(pfid));
		fid_be_to_cpu(&pfid, &pfid);

		printf("    %d: pfid "DFID", name '", i, PFID(&pfid));
		print_name(lee->lee_name, reclen - (int)sizeof(*lee));
		printf("'\n");
		lee = (struct link_ea_entry *)((char *)lee + reclen);
	}

	if (length != leh->leh_len) {
		fprintf(stderr,
			"%s: length mismatch, expected %llu, got %llu\n",
			fname,
			(unsigned long long)leh->leh_len,
			(unsigned long long)length);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int	rc = 0;
	int	rc2;
	int	i;

	for (i = 1; i < argc; i++) {
		rc2 = decode_linkea(argv[i]);
		if (rc2 != 0)
			rc = rc2;
	}

	return rc;
}
