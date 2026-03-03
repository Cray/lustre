#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <byteswap.h>

#include <linux/lustre/lustre_idl.h>

void usage(void)
{
	fprintf(stderr, "Usage: %s -d <dirname>\n",
		program_invocation_short_name);
}

int main(int argc, char **argv)
{
	int c, i;
	char *dname = NULL;
	size_t len, len2;
	struct lmv_foreign_md *lfm;

	while ((c = getopt(argc, argv, "d:h")) != -1) {
		switch (c) {
		case 'd':
			dname = optarg;
			break;
		case 'h':
			usage();
			exit(0);
		}
	}
	if (dname == NULL) {
		if (argc > 1) {
			dname = argv[1];
		} else {
			usage();
			exit(1);
		}
	}

	len = getxattr(dname, "trusted.lmv", NULL, 0);
	if (len == -1) {
		fprintf(stderr, "error: NULL getxattr(\"%s\") failed: %s\n",
			dname, strerror(errno));
		exit(1);
	}
	if (len > XATTR_SIZE_MAX || len <= 0) {
		fprintf(stderr, "invalid LMV EA length %zu "
			"(must be 0 < len < "
			"XATTR_SIZE_MAX(%u))\n", len,
			XATTR_SIZE_MAX);
		exit(1);
	}

	lfm = malloc(len);
	if (lfm == NULL) {
		fprintf(stderr, "error: malloc(%zu) failed: %s\n",
			len, strerror(errno));
		exit(1);
	}

	len2 = getxattr(dname, "trusted.lmv", lfm, len);
	if (len2 == -1) {
		fprintf(stderr, "error: dir getxattr(\"%s\") failed: %s\n",
			dname, strerror(errno));
		exit(1);
	}

	if (len != len2)
		fprintf(stderr, "trusted.lmv xattr size changed, %zu->%zu\n",
			len, len2);

	if (len2 < offsetof(struct lmv_foreign_md, lfm_value)) {
		fprintf(stderr, "trusted.lov size=%zu too small\n", len2);
		fprintf(stderr, "printing its content in hex anyway:\n");
		for (i = 0; i < len2; i++) {
			fprintf(stderr, "%02x", *((char *)lfm + i));
			if (i % 16 == 15)
				fprintf(stderr, "\n");
			else if (i % 4 == 3)
				fprintf(stderr, " ");
		}
		fprintf(stderr, "\n");
		exit(1);
	}


	if (lfm->lfm_magic != LMV_MAGIC_FOREIGN) {
		if (lfm->lfm_magic == bswap_32(LMV_MAGIC_FOREIGN))
			fprintf(stderr, "magic is swapped\n");
		else
			fprintf(stderr, "wrong magic=%#x\n", lfm->lfm_magic);
	}

	if (lfm->lfm_length != len2 - offsetof(typeof(*lfm), lfm_value)) {
		if (bswap_32(lfm->lfm_length) == len2 - offsetof(typeof(*lfm),
		    lfm_value))
			fprintf(stderr, "length is swapped\n");
		else
			fprintf(stderr,
				"wrong internal length=%u/%#x != xattr=%zu\n",
				lfm->lfm_length, lfm->lfm_length, len2);
	}

	if (lfm->lfm_magic == bswap_32(LMV_MAGIC_FOREIGN)) {
		lfm->lfm_magic = bswap_32(lfm->lfm_magic);
		lfm->lfm_length = bswap_32(lfm->lfm_length);
		lfm->lfm_type = bswap_32(lfm->lfm_type);
		lfm->lfm_flags = bswap_32(lfm->lfm_flags);
	}

	fprintf(stdout, "lmv_xattr_size: %zu\n", len2);
	fprintf(stdout, "lmv_foreign_magic: %#x\n", lfm->lfm_magic);
	fprintf(stdout, "lmv_foreign_size: %u\n", lfm->lfm_length);
	fprintf(stdout, "lmv_foreign_type: %#x\n", lfm->lfm_type);
	fprintf(stdout, "lmv_foreign_flags: %#x\n", lfm->lfm_flags);
	fprintf(stdout, "lmv_foreign_value: 0x");
	for (i = 0; i < len2 - offsetof(typeof(*lfm), lfm_value); i++)
		fprintf(stdout, "%02x", lfm->lfm_value[i]);

	fprintf(stdout, "\n");

	return 0;
}
