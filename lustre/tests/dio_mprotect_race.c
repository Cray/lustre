// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Race mprotect() against an unaligned O_DIRECT write.
 *
 * Each iteration fills a region of FILE with 'A', leaves 'C' in the
 * client's DIO bounce page pool with an unaligned DIO write to POOLFILE,
 * then writes 'B' over the region with one unaligned DIO write while a
 * second thread makes the tail of the user buffer PROT_NONE after a
 * delay.  The region is then read back.  The write may fail, but it
 * must never leave 'C' (or anything but 'A' and 'B') in the file, nor
 * report as written any byte that is not 'B'.
 *
 * Without -d, the delays sweep from 0 to a little more than the time an
 * uncontended write takes, measured first, so the window between the
 * up front fault-in and the end of the copy is found on any node.
 *
 * Exit status: 0 no bad write, 1 a bad write was seen, 2 error.
 *
 * Based on a reproducer by Andrew Perepechko.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CALIBRATE_RUNS	3

static char *buf;
static size_t len;
static size_t tail;
static long delay_ns;
static pthread_barrier_t bar;

static void usage_exit(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-i iterations] [-d max_delay_us] [-s size_mb] FILE POOLFILE\n",
		prog);
	exit(2);
}

static long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

/* make the tail of the buffer unreadable after a delay */
static void *prot_thread(void *arg)
{
	long t0;

	pthread_barrier_wait(&bar);
	t0 = now_ns();
	while (now_ns() - t0 < delay_ns)
		;
	if (mprotect(buf + len - tail, tail, PROT_NONE))
		perror("mprotect");
	return NULL;
}

static void fill(const char *path, int flags, char c, off_t off, char *b)
{
	int fd = open(path, flags);

	memset(b, c, len);
	if (fd < 0 || pwrite(fd, b, len, off) != (ssize_t)len || fsync(fd)) {
		perror(path);
		exit(2);
	}
	close(fd);
}

/*
 * One write of 'B' over 'A', racing mprotect() after @delay ns, or with
 * no race if @delay is negative.  Returns the write's result, with the
 * time it took in @took_ns.
 */
static ssize_t race_write(const char *file, const char *pool, off_t off,
			  char *pat, long delay, long *took_ns, int *err)
{
	pthread_t t;
	ssize_t rc;
	long t0;
	int fd;

	/* old data A in the region, pattern C left in the pool */
	fill(file, O_RDWR, 'A', off, pat);
	fill(pool, O_WRONLY | O_DIRECT, 'C', off, pat);

	buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		exit(2);
	}
	memset(buf, 'B', len);

	fd = open(file, O_WRONLY | O_DIRECT);
	if (fd < 0) {
		perror(file);
		exit(2);
	}
	if (delay >= 0) {
		delay_ns = delay;
		pthread_barrier_init(&bar, NULL, 2);
		if (pthread_create(&t, NULL, prot_thread, NULL)) {
			perror("pthread_create");
			exit(2);
		}
		pthread_barrier_wait(&bar);
	}
	t0 = now_ns();
	rc = pwrite(fd, buf, len, off);
	*err = errno;
	*took_ns = now_ns() - t0;
	if (delay >= 0) {
		pthread_join(t, NULL);
		pthread_barrier_destroy(&bar);
	}
	close(fd);
	munmap(buf, len);

	return rc;
}

int main(int argc, char **argv)
{
	long pg = sysconf(_SC_PAGESIZE);
	off_t off = 16 * pg + 1000;
	int iters = 100, hits = 0, failed = 0, full = 0, part = 0;
	long maxdelay = -1;
	size_t rlen;
	char *pat, *rbuf;
	off_t aoff;
	int it, c;

	len = 8 << 20;
	while ((c = getopt(argc, argv, "d:i:s:")) != -1) {
		switch (c) {
		case 'd':
			maxdelay = atol(optarg) * 1000;
			break;
		case 'i':
			iters = atoi(optarg);
			break;
		case 's':
			len = (size_t)atol(optarg) << 20;
			break;
		default:
			usage_exit(argv[0]);
		}
	}
	if (argc - optind != 2 || iters <= 0 || len == 0)
		usage_exit(argv[0]);

	tail = 4 * pg;
	aoff = off / pg * pg;
	rlen = (off + len + pg - 1) / pg * pg - aoff;
	pat = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED || posix_memalign((void **)&rbuf, pg, rlen)) {
		perror("buffers");
		return 2;
	}

	if (maxdelay < 0) {
		long took[CALIBRATE_RUNS], t;
		int err, j;

		/* the median, so a cold first write does not stretch it */
		for (it = 0; it < CALIBRATE_RUNS; it++) {
			if (race_write(argv[optind], argv[optind + 1], off,
				       pat, -1, &t, &err) != (ssize_t)len) {
				fprintf(stderr, "uncontended write failed: %s\n",
					strerror(err));
				return 2;
			}
			for (j = it; j > 0 && took[j - 1] > t; j--)
				took[j] = took[j - 1];
			took[j] = t;
		}
		t = took[CALIBRATE_RUNS / 2];
		maxdelay = t + t / 4;
	}
	printf("iterations %d, delays 0 to %ld us\n", iters, maxdelay / 1000);

	for (it = 0; it < iters; it++) {
		size_t na = 0, nb = 0, nc = 0, nx = 0, i;
		long delay = maxdelay * it / iters;
		long took;
		ssize_t rc;
		int fd, err;
		char *r;

		rc = race_write(argv[optind], argv[optind + 1], off, pat,
				delay, &took, &err);

		/* read the region back from the OST */
		fd = open(argv[optind], O_RDONLY | O_DIRECT);
		if (fd < 0 || pread(fd, rbuf, rlen, aoff) < 0) {
			perror("read back");
			return 2;
		}
		close(fd);
		r = rbuf + (off - aoff);
		for (i = 0; i < len; i++) {
			if (r[i] == 'A')
				na++;
			else if (r[i] == 'B')
				nb++;
			else if (r[i] == 'C')
				nc++;
			else
				nx++;
		}

		if (rc < 0)
			failed++;
		else if (rc == (ssize_t)len)
			full++;
		else
			part++;
		/* every byte write() reported must be B */
		for (i = 0; rc > 0 && i < (size_t)rc; i++)
			if (r[i] != 'B')
				break;
		if (nc || nx || (rc > 0 && i < (size_t)rc)) {
			hits++;
			printf("BAD it=%d delay=%ldus write=%zd A=%zu B=%zu C=%zu other=%zu\n",
			       it, delay / 1000, rc, na, nb, nc, nx);
		}
		if (rc < 0 && err != EFAULT)
			printf("it=%d write errno %d (%s)\n", it, err,
			       strerror(err));
	}
	printf("SUMMARY iterations=%d bad=%d write: full=%d short=%d failed=%d\n",
	       iters, hits, full, part, failed);

	return hits ? 1 : 0;
}
