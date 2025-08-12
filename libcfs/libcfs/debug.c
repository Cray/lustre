// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/stacktrace.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#ifdef HAVE_PANIC_NOTIFIER_H
#include <linux/panic_notifier.h>
#endif
#include "tracefile.h"

static char debug_file_name[1024];

unsigned int libcfs_subsystem_debug = LIBCFS_S_DEFAULT;
EXPORT_SYMBOL(libcfs_subsystem_debug);
module_param(libcfs_subsystem_debug, int, 0644);
MODULE_PARM_DESC(libcfs_subsystem_debug, "Lustre kernel debug subsystem mask");

unsigned int libcfs_debug = LIBCFS_D_DEFAULT;
EXPORT_SYMBOL(libcfs_debug);
module_param(libcfs_debug, int, 0644);
MODULE_PARM_DESC(libcfs_debug, "Lustre kernel debug mask");

static int libcfs_param_debug_mb_set(const char *val,
				     cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned int num;

	rc = kstrtouint(val, 0, &num);
	if (rc < 0)
		return rc;

	num = cfs_trace_set_debug_mb(num);

	*((unsigned int *)kp->arg) = num;
	num = cfs_trace_get_debug_mb();
	if (num)
		/* This value is more precise */
		*((unsigned int *)kp->arg) = num;

	return 0;
}

/* While debug_mb setting look like unsigned int, in fact
 * it needs quite a bunch of extra processing, so we define special
 * debug_mb parameter type with corresponding methods to handle this case
 */
static const struct kernel_param_ops param_ops_debug_mb = {
	.set = libcfs_param_debug_mb_set,
	.get = param_get_uint,
};

#define param_check_debug_mb(name, p) \
		__param_check(name, p, unsigned int)

static unsigned int libcfs_debug_mb;
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(libcfs_debug_mb, debug_mb, 0644);
#else
module_param_call(libcfs_debug_mb, libcfs_param_debug_mb_set, param_get_uint,
		  &param_ops_debug_mb, 0644);
#endif
MODULE_PARM_DESC(libcfs_debug_mb, "Total debug buffer size.");

unsigned int libcfs_subsystem_printk;
module_param(libcfs_subsystem_printk, uint, 0644);
MODULE_PARM_DESC(libcfs_subsystem_printk, "Lustre kernel debug subsystem console mask");

unsigned int libcfs_printk = D_CANTMASK;
module_param(libcfs_printk, uint, 0644);
MODULE_PARM_DESC(libcfs_printk, "Lustre kernel debug console mask");

unsigned int libcfs_console_ratelimit = 1;
module_param(libcfs_console_ratelimit, uint, 0644);
MODULE_PARM_DESC(libcfs_console_ratelimit, "Lustre kernel debug console ratelimit (0 to disable)");

static int param_set_delay_minmax(const char *val,
				  cfs_kernel_param_arg_t *kp,
				  long min, long max)
{
	long d;
	int sec;
	int rc;

	rc = kstrtoint(val, 0, &sec);
	if (rc)
		return -EINVAL;

	/* The sysfs setting is in centiseconds */
	d = cfs_time_seconds(sec) / 100;
	if (d < min || d > max)
		return -EINVAL;

	*((unsigned int *)kp->arg) = d;

	return 0;
}

static int param_get_delay(char *buffer, cfs_kernel_param_arg_t *kp)
{
	unsigned int d = *(unsigned int *)kp->arg;

	param_get_byte(buffer, kp);
	return sprintf(buffer, "%lu%c", jiffies_to_msecs(d * 10) / MSEC_PER_SEC,
		       strnchr(buffer, PAGE_SIZE, '\n') ? '\n' : '\0');
}

unsigned int libcfs_console_max_delay;
unsigned int libcfs_console_min_delay;

static int param_set_console_max_delay(const char *val,
				       cfs_kernel_param_arg_t *kp)
{
	return param_set_delay_minmax(val, kp,
				      libcfs_console_min_delay, INT_MAX);
}

static const struct kernel_param_ops param_ops_console_max_delay = {
	.set = param_set_console_max_delay,
	.get = param_get_delay,
};

#define param_check_console_max_delay(name, p) \
		__param_check(name, p, unsigned int)

#ifdef HAVE_KERNEL_PARAM_OPS
module_param(libcfs_console_max_delay, console_max_delay, 0644);
#else
module_param_call(libcfs_console_max_delay, param_set_console_max_delay,
		  param_get_delay, &param_ops_console_max_delay, 0644);
#endif
MODULE_PARM_DESC(libcfs_console_max_delay, "Lustre kernel debug console max delay (jiffies)");

static int param_set_console_min_delay(const char *val,
				       cfs_kernel_param_arg_t *kp)
{
	return param_set_delay_minmax(val, kp,
				      1, libcfs_console_max_delay);
}

static const struct kernel_param_ops param_ops_console_min_delay = {
	.set = param_set_console_min_delay,
	.get = param_get_delay,
};

#define param_check_console_min_delay(name, p) \
		__param_check(name, p, unsigned int)

#ifdef HAVE_KERNEL_PARAM_OPS
module_param(libcfs_console_min_delay, console_min_delay, 0644);
#else
module_param_call(libcfs_console_min_delay, param_set_console_min_delay,
		  param_get_delay, &param_ops_console_min_delay, 0644);
#endif
MODULE_PARM_DESC(libcfs_console_min_delay, "Lustre kernel debug console min delay (jiffies)");

#ifndef HAVE_PARAM_SET_UINT_MINMAX
static int param_set_uint_minmax(const char *val,
				 cfs_kernel_param_arg_t *kp,
				 unsigned int min, unsigned int max)
{
	unsigned int num;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtouint(val, 0, &num);
	if (ret < 0 || num < min || num > max)
		return -EINVAL;

	*((unsigned int *)kp->arg) = num;
	return 0;
}
#endif

static int param_set_uintpos(const char *val,
			     cfs_kernel_param_arg_t *kp)
{
	return param_set_uint_minmax(val, kp, 1, -1);
}

static const struct kernel_param_ops param_ops_uintpos = {
	.set = param_set_uintpos,
	.get = param_get_uint,
};

#define param_check_uintpos(name, p) \
		__param_check(name, p, unsigned int)

unsigned int libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(libcfs_console_backoff, uintpos, 0644);
#else
module_param_call(libcfs_console_backoff, param_set_uintpos, param_get_uint,
		  &param_ops_uintpos, 0644);
#endif
MODULE_PARM_DESC(libcfs_console_backoff, "Lustre kernel debug console backoff factor");

unsigned int libcfs_debug_binary = 1;

unsigned int libcfs_catastrophe;
EXPORT_SYMBOL(libcfs_catastrophe);

unsigned int libcfs_watchdog_ratelimit = 300;
EXPORT_SYMBOL(libcfs_watchdog_ratelimit);

unsigned int libcfs_panic_on_lbug = 1;
module_param(libcfs_panic_on_lbug, uint, 0644);
MODULE_PARM_DESC(libcfs_panic_on_lbug, "Lustre kernel panic on LBUG");

atomic64_t libcfs_kmem = ATOMIC64_INIT(0);
EXPORT_SYMBOL(libcfs_kmem);

static DECLARE_COMPLETION(debug_complete);

/* We need to pass a pointer here, but elsewhere this must be a const */
char *libcfs_debug_file_path = LIBCFS_DEBUG_FILE_PATH_DEFAULT;
EXPORT_SYMBOL(libcfs_debug_file_path);
module_param(libcfs_debug_file_path, charp, 0644);
MODULE_PARM_DESC(libcfs_debug_file_path,
		 "Path for dumping debug logs, set 'NONE' to prevent log dumping");

int libcfs_panic_in_progress;

/* libcfs_debug_token2mask() expects the returned string in lower-case */
static const char *libcfs_debug_subsys2str(int subsys)
{
	static const char *const libcfs_debug_subsystems[] =
		LIBCFS_DEBUG_SUBSYS_NAMES;

	if (subsys >= ARRAY_SIZE(libcfs_debug_subsystems))
		return NULL;

	return libcfs_debug_subsystems[subsys];
}

/* libcfs_debug_token2mask() expects the returned string in lower-case */
static const char *libcfs_debug_dbg2str(int debug)
{
	static const char * const libcfs_debug_masks[] =
		LIBCFS_DEBUG_MASKS_NAMES;

	if (debug >= ARRAY_SIZE(libcfs_debug_masks))
		return NULL;

	return libcfs_debug_masks[debug];
}

/* convert a binary mask to a string of bit names */
int cfs_mask2str(char *str, int size, u64 mask, const char *(*bit2str)(int bit),
		 char sep)
{
	const char *token;
	int len = 0;
	int i;

	if (mask == 0) {                        /* "0" */
		if (size > 0)
			str[0] = '0';
		len = 1;
	} else {                                /* space-separated tokens */
		for (i = 0; i < 64; i++) {
			if ((mask & BIT(i)) == 0)
				continue;

			token = bit2str(i);
			if (!token)             /* unused bit */
				continue;

			if (len > 0) {          /* separator? */
				if (len < size)
					str[len] = sep;
				len++;
			}

			while (*token != 0) {
				if (len < size)
					str[len] = *token;
				token++;
				len++;
			}
		}
	}

	/* terminate 'str' */
	if (len < size)
		str[len++] = '\n';
	if (len < size)
		str[len] = '\0';
	else if (size)
		str[size - 1] = '\0';

	return len;
}
EXPORT_SYMBOL(cfs_mask2str);

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 u64 *oldmask, u64 minmask, u64 allmask, u64 defmask)
{
	const char *debugstr;
	u64 newmask = *oldmask, found = 0;

	ENTRY;
	/* <str> must be a list of tokens separated by whitespace or comma,
	 * and optionally an operator ('+' or '-').  If an operator
	 * appears first in <str>, '*oldmask' is used as the starting point
	 * (relative), otherwise minmask is used (absolute).  An operator
	 * applies to all following tokens up to the next operator.
	 */
	while (*str != 0) {
		int i, len;
		char op = 0;

		while (isspace(*str) || *str == ',')
			str++;
		if (*str == 0)
			break;
		if (*str == '+' || *str == '-') {
			op = *str++;
			while (isspace(*str))
				str++;
			if (*str == 0)          /* trailing op */
				return -EINVAL;
		} else if (!found)
			newmask = minmask;


		/* find token length */
		for (len = 0; str[len] != 0 && !isspace(str[len]) &&
		     str[len] != '+' && str[len] != '-' && str[len] != ',';
		     len++);

		/* match token */
		found = 0;
		for (i = 0; i < 32; i++) {
			debugstr = bit2str(i);
			if (debugstr != NULL &&
			    strlen(debugstr) == len &&
			    strncasecmp(str, debugstr, len) == 0) {
				if (op == '-')
					newmask &= ~BIT(i);
			       else
					newmask |= BIT(i);
				found = 1;
				break;
			}
		}
		if (!found && len == 3 &&
		    (strncasecmp(str, "ALL", len) == 0)) {
			if (op == '-')
				newmask = minmask;
			else
				newmask = allmask;
			found = 1;
		}
		if (!found && strcasecmp(str, "DEFAULT") == 0) {
			if (op == '-')
				newmask = (newmask & ~defmask) | minmask;
			else if (op == '+')
				newmask |= defmask;
			else
				newmask = defmask;
			found = 1;
		}
		if (!found) {
			CWARN("unknown mask '%.*s'.\n"
			      "mask usage: [+|-]<all|type> ...\n", len, str);
			return -EINVAL;
		}
		str += len;
	}

	*oldmask = newmask;
	return 0;
}
EXPORT_SYMBOL(cfs_str2mask);

int libcfs_debug_mask2str(char *str, int size, int mask, int is_subsys)
{
	const char *(*bit2str)(int bit) = is_subsys ? libcfs_debug_subsys2str :
						      libcfs_debug_dbg2str;

	return cfs_mask2str(str, size, mask, bit2str, ' ');
}

int libcfs_debug_str2mask(int *mask, const char *str, int is_subsys)
{
	const char *(*bit2str)(int bit) = is_subsys ? libcfs_debug_subsys2str :
						      libcfs_debug_dbg2str;
	u64 newmask = *mask;
	int m = 0;
	int matched;
	int n, t;
	int rc;

	/* Allow a number for backwards compatibility */
	for (n = strlen(str); n > 0; n--)
		if (!isspace(str[n - 1]))
			break;
	matched = n;
	t = sscanf(str, "%i%n", &m, &matched);
	if (t >= 1 && matched == n) {
		/* don't print warning for lctl set_param debug=0 or -1 */
		if (m != 0 && m != -1)
			CWARN("using a numerical debug mask is deprecated\n");
		*mask = m;
		return 0;
	}

	rc = cfs_str2mask(str, bit2str, &newmask, is_subsys ? 0 : D_CANTMASK,
			  ~0, is_subsys ? LIBCFS_S_DEFAULT : LIBCFS_D_DEFAULT);

	*mask = newmask;

	return rc;
}

char lnet_debug_log_upcall[1024] = "/usr/lib/lustre/lnet_debug_log_upcall";

/* Upcall function once a Lustre log has been dumped.
 *
 * @file	path of the dumped log
 */
static void libcfs_run_debug_log_upcall(char *file)
{
	char *argv[3];
	int rc;
	static const char * const envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};

	ENTRY;
	argv[0] = lnet_debug_log_upcall;

	LASSERTF(file, "called on a null filename\n");
	argv[1] = file; /* only need to pass the path of the file */

	argv[2] = NULL;

	rc = call_usermodehelper(argv[0], argv, (char **)envp, 1);
	if (rc < 0 && rc != -ENOENT) {
		CERROR("Error %d invoking LNET debug log upcall %s %s; check /sys/kernel/debug/lnet/debug_log_upcall\n",
		       rc, argv[0], argv[1]);
	} else {
		CDEBUG(D_HA, "Invoked LNET debug log upcall %s %s\n",
		       argv[0], argv[1]);
	}
}

/**
 * Dump Lustre log to ::debug_file_path by calling tracefile_dump_all_pages()
 */
static void libcfs_debug_dumplog_internal(void *arg)
{
	static time64_t last_dump_time;
	time64_t current_time;

	current_time = ktime_get_real_seconds();

	if (strncmp(libcfs_debug_file_path, "NONE", 4) != 0 &&
	    current_time > last_dump_time) {
		last_dump_time = current_time;
		snprintf(debug_file_name, sizeof(debug_file_name) - 1,
			 "%s.%lld.%ld", libcfs_debug_file_path,
			 (s64)current_time, (uintptr_t)arg);
		pr_alert("LustreError: dumping log to %s\n", debug_file_name);
		cfs_tracefile_dump_all_pages(debug_file_name);
		libcfs_run_debug_log_upcall(debug_file_name);
	}
}

static int libcfs_debug_dumplog_thread(void *arg)
{
	libcfs_debug_dumplog_internal(arg);
	complete(&debug_complete);
	return 0;
}

static DEFINE_MUTEX(libcfs_debug_dumplog_lock);

void libcfs_debug_dumplog(void)
{
	struct task_struct *dumper;

	ENTRY;

	if (mutex_trylock(&libcfs_debug_dumplog_lock) == 0)
		return;

	/* If a previous call was interrupted, debug_complete->done
	 * might be elevated, and so we won't actually wait here.
	 * So we reinit the completion to ensure we wait for
	 * one thread to complete, though it might not be the one
	 * we start if there are overlaping thread.
	 */
	reinit_completion(&debug_complete);
	dumper = kthread_run(libcfs_debug_dumplog_thread,
			     (void *)(long)current->pid,
			     "libcfs_debug_dumper");
	if (IS_ERR(dumper))
		pr_err("LustreError: cannot start log dump thread: rc = %ld\n",
		       PTR_ERR(dumper));
	else
		wait_for_completion_interruptible(&debug_complete);

	mutex_unlock(&libcfs_debug_dumplog_lock);
}
EXPORT_SYMBOL(libcfs_debug_dumplog);

void
#ifdef HAVE_LBUG_WITH_LOC_IN_OBJTOOL
__noreturn
#endif
lbug_with_loc(struct libcfs_debug_msg_data *msgdata)
{
	libcfs_catastrophe = 1;
	libcfs_debug_msg(msgdata, "LBUG\n");

	if (in_interrupt()) {
		panic("LBUG in interrupt.\n");
		/* not reached */
	}

	dump_stack();
	if (libcfs_panic_on_lbug) {
		panic("LBUG");
	} else
		libcfs_debug_dumplog();
	set_current_state(TASK_UNINTERRUPTIBLE);
	while (1)
		schedule();
#ifndef HAVE_LBUG_WITH_LOC_IN_OBJTOOL
	/* not reached */
	panic("LBUG after schedule.");
#endif
}
EXPORT_SYMBOL(lbug_with_loc);

static int panic_notifier(struct notifier_block *self, unsigned long unused1,
			  void *unused2)
{
	if (libcfs_panic_in_progress)
		return 0;

	libcfs_panic_in_progress = 1;
	mb();

#ifdef LNET_DUMP_ON_PANIC
	/* This is currently disabled because it spews far too much to the
	 * console on the rare cases it is ever triggered. */

	if (in_interrupt()) {
		cfs_trace_debug_print();
	} else {
		libcfs_debug_dumplog_internal((void *)(long)current->pid);
	}
#endif
	return 0;
}

static struct notifier_block libcfs_panic_notifier = {
	.notifier_call		= panic_notifier,
	.next			= NULL,
	.priority		= 10000,
};

static void libcfs_register_panic_notifier(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &libcfs_panic_notifier);
}

static void libcfs_unregister_panic_notifier(void)
{
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &libcfs_panic_notifier);
}

static bool debug_started;

int libcfs_debug_init(unsigned long bufsize)
{
	unsigned int max = libcfs_debug_mb;
	int rc = 0;

	if (debug_started)
		return 0;

	debug_started = true;
	if (libcfs_console_max_delay <= 0 || /* not set by user or */
	    libcfs_console_min_delay <= 0 || /* set to invalid values */
	    libcfs_console_min_delay >= libcfs_console_max_delay) {
		libcfs_console_max_delay = CDEBUG_DEFAULT_MAX_DELAY;
		libcfs_console_min_delay = CDEBUG_DEFAULT_MIN_DELAY;
	}

	/* If libcfs_debug_mb is uninitialized then just make the
	 * total buffers smp_num_cpus * TCD_MAX_PAGES
	 */
	if (max < num_possible_cpus())
		max = TCD_MAX_PAGES;
	else
		max <<= (20 - PAGE_SHIFT);

	rc = cfs_tracefile_init(max);
	if (rc)
		return rc;

	libcfs_register_panic_notifier();
	kernel_param_lock(THIS_MODULE);
	libcfs_debug_mb = cfs_trace_get_debug_mb();
	kernel_param_unlock(THIS_MODULE);
	return rc;
}

int libcfs_debug_cleanup(void)
{
	libcfs_unregister_panic_notifier();
	kernel_param_lock(THIS_MODULE);
	cfs_tracefile_exit();
	kernel_param_unlock(THIS_MODULE);
	debug_started = false;
	return 0;
}

int libcfs_debug_clear_buffer(void)
{
	cfs_trace_flush_pages();
	return 0;
}

/* Debug markers, although printed by S_LNET should not be be marked as such. */
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_UNDEFINED
int libcfs_debug_mark_buffer(const char *text)
{
	CDEBUG(D_TRACE,
	       "**************************************************\n");
	LCONSOLE(D_WARNING, "DEBUG MARKER: %s\n", text);
	CDEBUG(D_TRACE,
	       "**************************************************\n");

	return 0;
}

#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_LNET
