/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd worker thread pool.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#ifndef _KFILND_WKR_
#define _KFILND_WKR_

/* The callbacks posted to this system need this format */
typedef void (*kfilnd_wkr_func)(void *devctx, void *context, int status);

/* Use this call after init and start to post work to the Workqueue */
int kfilnd_wkr_post(unsigned int cpt, kfilnd_wkr_func work_func,
		    void *dev_context,
		    void *work_context, int status);

/* Called when this API will no longer be used */
void kfilnd_wkr_cleanup(void);

/* Called once before kiflnd_wkr_cleanup() to stop the threads */
int kfilnd_wkr_stop(void);

/* Called once after kiflnd_wkr_init() to allow posting of work */
int kfilnd_wkr_start(void);

/* Called once to intialize this API */
int kfilnd_wkr_init(unsigned int max_parallel, unsigned int max_work, bool use_workqueues);

#endif /* _KFILND_WKR_ */
