// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <lustre/lustreapi.h>

#include <linux/lustre/lustre_user.h>
#include <lustre/lustreapi.h>

static void usage(const char *prog)
{
	printf(
	       "usage: %s {-o [-k] [-x <size>]|-m|-d|-l<tgt>} [-u[<unlinkfmt>]] [-i mdt_index] [-t seconds] filenamefmt [[start] count]\n",
	       prog);
	printf("\t-i\tMDT to create the directories on\n"
	       "\t-l\tlink files to existing <tgt> file\n"
	       "\t-m\tmknod regular files (don't create OST objects)\n"
	       "\t-o\topen+create files with path and printf format\n"
	       "\t-k\t    keep files open until all files are opened\n"
	       "\t-x\t    set an xattr with <size> length on the files\n"
	       "\t-u\tunlink file/dir (with optional <unlinkfmt>)\n");
	printf("\t-d\tuse directories instead of regular files\n"
	       "\t-t\tstop creating files after <seconds> have elapsed\n");
	printf("\t-S\tthe file size\n"
	       "\t-W\tthe file will be written to the specified size\n"
	       "\t-U\tthe start User ID of the file\n"
	       "\t-G\tthe start Group ID of the file\n"
	       "\t-P\tthe start Project ID of the file\n");

	exit(EXIT_FAILURE);
}

static char *get_file_name(const char *fmt, long n, int has_fmt_spec)
{
	static char filename[4096];
	int bytes;

	bytes = has_fmt_spec ? snprintf(filename, 4095, fmt, n) :
		snprintf(filename, 4095, "%s%ld", fmt, n);
	if (bytes >= 4095) {
		printf("file name too long\n");
		exit(EXIT_FAILURE);
	}
	return filename;
}

static double now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

int main(int argc, char **argv)
{
	bool do_open = false, do_keep = false, do_link = false;
	bool do_unlink = false, do_mknod = false, do_mkdir = false;
	bool do_setsize = false, do_chuid = false, do_chgid = false;
	bool do_write = false;
	bool do_chprj = false;
	bool do_rmdir = false;
	bool do_xattr = false;
	int stripe_pattern = LMV_HASH_TYPE_FNV_1A_64;
	int stripe_offset = -1, stripe_count = 1;
	size_t xattr_size = 0;
	char *xattr_buf = NULL;
	char *filename, *progname;
	char *fmt = NULL, *fmt_unlink = NULL, *tgt = NULL;
	char *endp = NULL;
	double start, last_t, end;
	long begin = 0, count = ~0UL >> 1;
	int has_fmt_spec = 0, unlink_has_fmt_spec = 0;
	long i, total, last_i = 0;
	int c, last_fd = -1, stderr_fd;
	int fd_urandom;
	unsigned int uid = 0, gid = 0, pid = 0;
	int size = 0;
	int rc = 0;

	/* Handle the deprecated positional last argument "-seconds" */
	if (argc > 1 && argv[argc - 1][0] == '-' &&
	    (end = strtol(argv[argc - 1] + 1, &endp, 0)) && *endp == '\0') {
		fprintf(stderr,
			"warning: '-runtime' deprecated, use '-t runtime' instead\n");
		argv[--argc] = NULL;
	} else {
		/* Not '-number', let regular argument parsing handle it. */
		end = ~0U >> 1;
	}

	if ((endp = strrchr(argv[0], '/')) != NULL)
		progname = endp + 1;
	else
		progname = argv[0];

	while ((c = getopt(argc, argv, "i:dG:l:kmor::S:t:u::U:W:x:")) != -1) {
		switch (c) {
		case 'd':
			do_mkdir = true;
			break;
		case 'G':
			do_chgid = true;
			gid = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			stripe_offset = strtoul(optarg, &endp, 0);
			if (*endp != '\0') {
				fprintf(stderr, "invalid MDT index '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 'k':
			do_keep = true;
			break;
		case 'l':
			do_link = true;
			tgt = optarg;
			break;
		case 'm':
			do_mknod = true;
			break;
		case 'o':
			do_open = true;
			break;
		case 'P':
			do_chprj = true;
			pid = strtoul(optarg, NULL, 0);
			break;
		case 'S':
			do_setsize = true;
			size = atoi(optarg);
			break;
		case 't':
			end = strtol(optarg, &endp, 0);
			if (end <= 0.0 || *endp != '\0')
				usage(progname);
			break;
		case 'r':
		case 'u':
			do_unlink = true;
			fmt_unlink = optarg;
			break;
		case 'U':
			do_chuid = true;
			uid = strtoul(optarg, NULL, 0);
			break;
		case 'W':
			do_write = true;
			size = atoi(optarg);
			break;
		case 'x':
			do_xattr = true;
			xattr_size = strtoul(optarg, &endp, 0);
			if (*endp != '\0') {
				fprintf(stderr, "invalid xattr size '%s'\n",
					optarg);
				return 1;
			}
			break;
		case '?':
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(progname);
		}
	}

	if (!do_open && (do_setsize || do_write || do_chuid || do_chgid ||
			 do_chprj)) {
		fprintf(stderr,
			"error: -S, -W, -U, -G, -P works only with -o\n");
		usage(progname);
	}

	if (do_open + do_mkdir + do_link + do_mknod > 1 ||
	    do_open + do_mkdir + do_link + do_mknod + do_unlink == 0) {
		fprintf(stderr, "error: only one of -o, -m, -l, -d\n");
		usage(progname);
	}
	if (do_mkdir && do_unlink)
		do_rmdir = true;

	if (!do_open && (do_keep || do_xattr)) {
		fprintf(stderr, "error: can only use -k|-x with -o\n");
		usage(progname);
	}

	switch (argc - optind) {
	case 3:
		begin = strtol(argv[argc - 2], NULL, 0);
	case 2:
		count = strtol(argv[argc - 1], NULL, 0);
	case 1:
		fmt = argv[optind];
		break;
	default:
		usage(progname);
	}

	has_fmt_spec = strchr(fmt, '%') != NULL;
	if (fmt_unlink != NULL)
		unlink_has_fmt_spec = strchr(fmt_unlink, '%') != NULL;

	if (do_xattr) {
		xattr_buf = malloc(xattr_size);
		if (!xattr_buf) {
			printf("malloc xattr buf error: %s\n", strerror(errno));
			return errno;
		}
	}

	fd_urandom = open("/dev/urandom", O_RDONLY);
	for (i = 0, start = last_t = now(), end += start;
	     i < count && now() < end; i++, begin++) {
		double tmp;

		filename = get_file_name(fmt, begin, has_fmt_spec);
		if (do_open) {
			int fd;

			fd = open(filename, O_CREAT|O_RDWR, 0644);
			if (fd < 0) {
				printf("open(%s) error: %s\n", filename,
				       strerror(errno));
				rc = errno;
				break;
			}

			if (do_write) {
				char tmp[4194304];
				int sz, count;

				if (fd_urandom < 0) {
					printf("open /dev/urandom error: %s\n",
					       strerror(errno));
					break;
				}

				sz = size;
				while (sz > 0) {
					if (sz > sizeof(tmp))
						count = sizeof(tmp);
					else
						count = sz;

					rc = read(fd_urandom, tmp, count);
					if (rc < 0) {
						printf("read error: %s\n",
						       strerror(errno));
						break;
					}
					rc = write(fd, tmp, count);
					if (rc < 0) {
						printf("write(%s) error: %s\n",
						       filename,
						       strerror(errno));
						break;
					}

					sz -= count;
				}
			}

			if (do_setsize) {
				rc = lseek(fd, (size - 6) < 0 ? 0 : size - 6,
					   SEEK_SET);
				if (rc < 0) {
					printf("lseek(%s, %d) error: %s\n",
					       filename, size, strerror(errno));
					break;
				}
				rc = write(fd, "Lustre", 6);
				if (rc < 0) {
					printf("write(%s, %d) error: %s\n",
					       filename, 6, strerror(errno));
					break;
				}
			}

			if (do_chuid || do_chgid) {
				rc = fchown(fd, do_chuid ? uid + i : -1,
					    do_chgid ? gid + i : -1);
				if (rc < 0) {
					printf("fchown(%s, %u, %u) error: %s\n",
					       filename, do_chuid ? uid : -1,
					       do_chgid ? gid : -1,
					       strerror(errno));
					break;
				}
			}

			if (do_chprj) {
				struct fsxattr fsx;

				rc = ioctl(fd, FS_IOC_FSGETXATTR, &fsx);
				if (rc < 0) {
					printf("ioctl(%s) error: %s\n",
					       "FS_IOC_GETXATTR",
					       strerror(errno));
					break;
				}

				fsx.fsx_projid = pid + i;
				rc = ioctl(fd, FS_IOC_FSSETXATTR, &fsx);
				if (rc < 0) {
					printf("ioctl(%s, %d) error: %s\n",
					       "FS_IOC_SETXATTR", pid,
					       strerror(errno));
					break;
				}
			}

			if (do_xattr) {
				strncpy(xattr_buf, filename, xattr_size);
				rc = fsetxattr(fd, "user.createmany", xattr_buf,
					       xattr_size, 0);
				if (rc < 0) {
					printf("fsetxattr(%s) error: %s\n",
					       filename, strerror(errno));
					rc = errno;
					break;
				}
			}

			if (!do_keep)
				close(fd);
			else if (fd > last_fd)
				last_fd = fd;
		} else if (do_link) {
			rc = link(tgt, filename);
			if (rc) {
				printf("link(%s, %s) error: %s\n",
				       tgt, filename, strerror(errno));
				rc = errno;
				break;
			}
		} else if (do_mkdir) {
			if (stripe_offset != -1) {
				rc = llapi_dir_create_pool(filename, 0755,
							   stripe_offset,
							   stripe_count,
							   stripe_pattern,
							   NULL);
				if (rc) {
					printf("llapi_dir_create_pool(%s) error: %s\n",
					       filename, strerror(-rc));
					rc = errno;
					break;
				}
			} else {
				rc = mkdir(filename, 0755);
				if (rc) {
					printf("mkdir(%s) error: %s\n",
					       filename, strerror(errno));
					rc = errno;
					break;
				}
			}
		} else if (do_mknod) {
			rc = mknod(filename, S_IFREG | 0444, 0);
			if (rc) {
				printf("mknod(%s) error: %s\n",
				       filename, strerror(errno));
				rc = errno;
				break;
			}
		}
		if (do_unlink) {
			if (fmt_unlink != NULL)
				filename = get_file_name(fmt_unlink, begin,
							 unlink_has_fmt_spec);

			rc = do_rmdir ? rmdir(filename) : unlink(filename);
			/* use rmdir if this is a directory */
			if (!do_rmdir && rc && errno == EISDIR) {
				do_rmdir = true;
				rc = rmdir(filename);
			}
			if (rc) {
				printf("unlink(%s) error: %s\n",
				       filename, strerror(errno));
				rc = errno;
				break;
			}
		}

		tmp = now();
		if (tmp - last_t >= 10.0 ||
		    (tmp - last_t > 2.0 && (i % 10000) == 0)) {
			printf(" - %s%s %ld (time %.2f total %.2f last %.2f)\n",
			       do_open ? do_keep ? "open/keep" : "open/close" :
					do_mkdir ? "mkdir" : do_link ? "link" :
					do_mknod ? "create" : "",
			       do_unlink ? do_mkdir ? "/rmdir" : "/unlink" : "",
			       i, tmp, tmp - start,
			       (i - last_i) / (tmp - last_t));
			last_t = tmp;
			last_i = i;
		}
	}
	close(fd_urandom);
	last_t = now();
	total = i;
	printf("total: %ld %s%s in %.2f seconds: %.2f ops/second\n", total,
	       do_open ? do_keep ? "open/keep" : "open/close" :
			do_mkdir ? "mkdir" : do_link ? "link" :
					     do_mknod ? "create" : "",
	       do_unlink ? do_mkdir ? "/rmdir" : "/unlink" : "",
	       last_t - start, ((double)total / (last_t - start)));

	if (xattr_buf)
		free(xattr_buf);

	if (!do_keep)
		return rc;

	stderr_fd = fileno(stderr);
	start = last_t;
	/* Assume fd is allocated in order, doing extra closes is not harmful */
	for (i = 0; i < total && last_fd > stderr_fd; i++, --last_fd) {
		close(last_fd);

		if ((i != 0 && (i % 10000) == 0) || now() - last_t >= 10.0) {
			double tmp = now();

			printf(" - closed %ld (time %.2f total %.2f last %.2f)\n",
			       i, tmp, tmp - start,
			       (i - last_i) / (tmp - last_t));
			last_t = tmp;
			last_i = i;
		}
	}
	last_t = now();

	printf("total: %ld close in %.2f seconds: %.2f close/second\n",
	       total, last_t - start, ((double)total / (last_t - start)));
	return rc;
}
