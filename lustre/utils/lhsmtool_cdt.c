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
 * http://www.gnu.org/licenses/gpl-2.0.htm
 *
 * GPL HEADER END
 */
/*
 * Copyright 2018 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 */
/*
 * Lustre external HSM coordinator
 *
 * An HSM coordinator daemon acts on action requests from Lustre.
 * It moves them from WAIT->RUNNING->Done (SUCCESS, FAILED, CANCELED)
 * It handles the registration and unregistration of copytools
 *
 * This is provided as a demonstration, data is not persisted across failures
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include <lustre/lustreapi.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_fid.h>

#define MAX_PAYLOAD 4096 /* maximum payload size*/

FILE *fp;

struct hsm_queue_item {
	struct hsm_queue_item *next;
	struct hsm_action_list hal;
};

struct hsm_queue {
	struct hsm_queue_item *head;
	struct hsm_queue_item *tail;
	int count;
};

struct active_ct {
	struct obd_uuid uuid;
	int registered;
	struct hsm_queue active;
	__u32 archives;
};

#define MAX_COPYTOOLS 20

struct hsm_queues {
	struct hsm_queue waitq;
	struct active_ct copytools[MAX_COPYTOOLS];
	struct hsm_queue doneq;
	struct hsm_queue cancelq;
	struct hsm_queue failq;
	struct hsm_cdt_private *hcp;
};

bool is_empty_fid(struct lu_fid *a)
{
	const struct lu_fid fid_zero = {0, 0, 0};

	return !lu_fid_eq(a, &fid_zero);
}

void hsmq_enqueue(struct hsm_queue *queue,
		  struct hsm_queue_item *item)
{
	item->next = NULL;
	if (queue->head == NULL)
		queue->tail = queue->head = item;
	else
		queue->tail = queue->tail->next = item;

	queue->count++;
}

void hsmq_add_to_head(struct hsm_queue *queue,
		      struct hsm_queue_item *item)
{
	item->next = queue->head;
	queue->head = item;
	if (queue->tail == NULL)
		queue->tail = queue->head;
	queue->count++;
}

/*
 * Convert a HAL list into a series of 1-element lists and add it to the
 * waitq
 *
 * HSM seems to like single element HALs better, and it's easier to keep
 * track of state of a single HAI that way.
 */
void create_queue(struct hsm_queue *queue, struct hsm_action_list *hal)
{
	struct hsm_queue_item *new = NULL;
	struct hsm_action_item *hai;
	int i;
	int len;

	for (hai = hai_first(hal), i = 0; i < hal->hal_count;
	     hai = hai_next(hai), i++) {
		len = sizeof(struct hsm_queue_item) + hai->hai_len +
			LUSTRE_MAXFSNAME;
		new = malloc(len);
		if (!new) {
			fprintf(fp, "Failed to allocate request\n");
			continue;
		}
		memset(new, '\0', len);
		memcpy(&new->hal, hal, sizeof(struct hsm_action_list) +
		       LUSTRE_MAXFSNAME);
		new->hal.hal_count = 1;
		memcpy(hai_first(&new->hal), hai, hai->hai_len);

		/* Policy: restore has priority */
		if (hai->hai_action == HSMA_RESTORE)
			hsmq_add_to_head(queue, new);
		else
			hsmq_enqueue(queue, new);
	}
}

struct hsm_queue_item *hsmq_dequeue(struct hsm_queue *queue)
{
	struct hsm_queue_item *next = NULL;
	struct hsm_queue_item *tmp = queue->head;

	if (queue->head == NULL)
		return NULL;

	next = queue->head->next;
	queue->head = next;
	if (queue->head == NULL)
		queue->tail = NULL;

	queue->count--;

	tmp->next = NULL;

	return tmp;
}

struct hsm_queue_item *remove_from_queue(struct hsm_queue_item *item,
					 struct hsm_queue_item *last,
					 struct hsm_queue *queue)
{
	if (item == queue->head)
		return hsmq_dequeue(queue);
	else if (item == queue->tail)
		queue->tail = queue->tail->next;
	else
		last->next = item->next;

	if (queue->tail == NULL)
		queue->head = NULL;

	queue->count--;
	item->next = NULL;
	return item;
}

int nlmsg_send_to_ct(struct hsm_cdt_private *hcp,
		     struct obd_uuid uuid,
		     struct hsm_action_list *hal)
{
	struct hsm_send_to_ct_kernel *hct;
	struct hsm_action_item *hai = hai_first(hal);
	int len = sizeof(struct hsm_send_to_ct_kernel) + hal_size(hal);

	fprintf(fp, "send_to_ct %s %s "DFID"\n", uuid.uuid,
		hsm_copytool_action2name(hai->hai_action), PFID(&hai->hai_fid));

	hct = (struct hsm_send_to_ct_kernel *)malloc(len);
	memcpy(&hct->uuid, &uuid, sizeof(struct obd_uuid));
	memcpy(&hct->hal, hal, hal_size(hal));

	llapi_hsm_cdt_send(hcp, EXT_HSM_SEND_TO_CT, hct, len);
	return 0;
}

int nlmsg_send_progress_item(struct hsm_cdt_private *hcp,
			     struct hsm_action_item *hai,
			     struct hsm_progress_kernel_v2 *hpk)
{
	struct hsm_progress_item *hpi;
	int len = sizeof(struct hsm_progress_kernel_v2) + hai->hai_len;

	hpi = (struct hsm_progress_item *)malloc(len);
	memcpy(&hpi->hpi_hai, hai, hai->hai_len);
	memcpy(&hpi->hpi_hpk, hpk, sizeof(struct hsm_progress_kernel_v2));

	llapi_hsm_cdt_send(hcp, EXT_HSM_PROGRESS, hpi, len);
	return 0;
}

int nlmsg_send_request_list(struct hsm_cdt_private *hcp,
			    __u64 compound_id,
			    enum agent_req_status status,
			    struct hsm_action_list *hal,
			    enum ext_hsm_cmd cmd)
{
	struct hsm_request_item *hri;
	int len;

	/* hri is two 32 bit integers and a HAL */
	len = hal_size(hal) + 8;

	hri = (struct hsm_request_item *)malloc(len);
	hri->hri_compound_id = compound_id;
	hri->hri_status = status;
	memcpy(&hri->hri_hal, hal, hal_size(hal));

	llapi_hsm_cdt_send(hcp, cmd, hri, len);
	return 0;
}

struct hsm_action_list *search_for_hal(struct hsm_queue_item *hqi,
				       struct lu_fid *fid)
{
	struct hsm_action_list *hal;
	struct hsm_action_item *hai;

	for (; hqi; hqi = hqi->next) {
		hal = &hqi->hal;
		hai = hai_first(hal);
		if (lu_fid_eq(&hai->hai_fid, fid))
			return hal;
	}

	return NULL;
}

int hsm_action(void *msg, struct hsm_queues *queues)
{
	struct lu_fid *fid = msg;
	struct hsm_action_list *hal;
	enum agent_req_status status;
	int i = 0;

	hal = search_for_hal(queues->waitq.head, fid);
	if (hal) {
		status = ARS_WAITING;
		goto done;
	}

	hal = search_for_hal(queues->doneq.head, fid);
	if (hal) {
		status = ARS_SUCCEED;
		goto done;
	}

	hal = search_for_hal(queues->cancelq.head, fid);
	if (hal) {
		status = ARS_CANCELED;
		goto done;
	}

	hal = search_for_hal(queues->failq.head, fid);
	if (hal) {
		status = ARS_FAILED;
		goto done;
	}

	for (i = 0; i < MAX_COPYTOOLS; i++) {
		hal = search_for_hal(queues->copytools[i].active.head, fid);
		if (hal) {
			status = ARS_STARTED;
			goto done;
		}
	}

done:
	if (hal) {
		struct hsm_action_item *hai = hai_first(hal);

		nlmsg_send_request_list(queues->hcp, hai->hai_cookie,
					status,	hal, EXT_HSM_ACTION_REP);
	} else {
		fprintf(fp, "Progress: FID "DFID" not found\n", PFID(fid));
	}

	return 0;
}

int hsm_progress(void *msg, struct hsm_queues *queues)
{
	struct hsm_progress_kernel_v2 *hpk = msg;
	struct hsm_queue_item *hqi;
	struct hsm_queue *runq;
	struct hsm_action_list *hal;
	struct hsm_action_item *hai;
	__u64 first;
	__u64 last;
	int j = 0;

	fprintf(fp, "Progress: FID "DFID" cookie %llu\n"
	       "\textent: %llu %llu flags %d errval %d action %d\n"
	       "\tdata_version %llu padding %d\n",
	       PFID(&hpk->hpk_fid), hpk->hpk_cookie, hpk->hpk_extent.offset,
	       hpk->hpk_extent.length, hpk->hpk_flags, hpk->hpk_errval,
	       hpk->hpk_action, hpk->hpk_data_version, hpk->hpk_version);

	for (j = 0; j < MAX_COPYTOOLS; j++) {
		runq = &queues->copytools[j].active;
		if (runq->count == 0)
			continue;

		for (hqi = runq->head; hqi; hqi = hqi->next) {
			hal = &hqi->hal;
			hai = hai_first(hal);
			if (hai->hai_cookie == hpk->hpk_cookie)
				goto found;
		}
	}

	goto out;

found:
	fprintf(fp, "Found "DFID"\n", PFID(&hai->hai_fid));
	hai->hai_dfid = hpk->hpk_dfid;

	if (hai->hai_extent.length == -1 ||
	    (hai->hai_extent.offset == 0 && hai->hai_extent.length == 0)) {
		/* HAI extent is uninitialized, use the new one */
		hai->hai_extent.length = hpk->hpk_extent.length;
		hai->hai_extent.offset = hpk->hpk_extent.offset;
	}

	/* set the beginning of the new extent, calculate the length */
	first = MIN(hai->hai_extent.offset, hpk->hpk_extent.offset);
	last = MAX(hai->hai_extent.offset + hai->hai_extent.length,
		   hpk->hpk_extent.offset + hpk->hpk_extent.length);
	hai->hai_extent.offset = first;
	hai->hai_extent.length = last - first;

	fprintf(fp, "New Extent: %llu %llu\n", hai->hai_extent.offset,
		hai->hai_extent.length);
out:
	return 0;
}

int cancel_list(struct hsm_action_list *cancel_hal, struct hsm_queues *queues)
{
	struct hsm_queue *queue;
	struct hsm_queue_item *item;
	struct hsm_queue_item *last;
	struct hsm_action_list *hal;
	struct hsm_action_item *haia = NULL;
	struct hsm_action_item *hai;
	enum hsm_copytool_action action;
	bool found = false;
	int i = 0;

	if (cancel_hal)
		haia = hai_first(cancel_hal);

	/*
	 * First, search the waitq
	 */
	queue = &queues->waitq;
	do {
		last = NULL;
		for (item = queue->head; item != NULL && !found;
		     item = item->next) {
			hal = &item->hal;
			hai = hai_first(hal);
			if (!haia && !lu_fid_eq(&hai->hai_fid, &haia->hai_fid))
				continue;

			/* for NULL haia we clear everything */
			if (haia)
				found = true;

			fprintf(fp, "Cancelling: "DFID"\n",
				PFID(&hai->hai_fid));
			remove_from_queue(item, last, queue);

			if (queue != &queues->waitq) {
				fprintf(fp, "send_to_ct %d %p\n", i, hal);
				action = hai->hai_action;
				hai->hai_action = HSMA_CANCEL;
				nlmsg_send_to_ct(queues->hcp,
						 queues->copytools[i].uuid,
						 hal);
				hai->hai_action = action;
			}

			hsmq_enqueue(&queues->cancelq, item);
			if (found) {
				/* We've found something to cancel, mark
				 * the cancel action as DONE
				 * if nothing is found, we ignore the request
				 */
				create_queue(&queues->doneq, cancel_hal);
				break;
			}
			last = item;
		}

		/*
		 * Then search the active queues
		 */
		queue = &queues->copytools[i++].active;
	} while (!found && i < MAX_COPYTOOLS);

	return 0;
}

/**
 * Clear everything out of the queues
 */
int hsm_cancel_all(struct hsm_queues *queues)
{
	struct hsm_queue_item *hqi;

	/* Clear the wait queue */
	fprintf(fp, "clear wait and run queues\n");
	cancel_list(NULL, queues);

	fprintf(fp, "clear doneq\n");
	/* flush out the done and failed queues */
	do {
		hqi = hsmq_dequeue(&queues->doneq);
		if (!hqi)
			break;

		free(hqi);
		hqi = NULL;
	} while (true);

	fprintf(fp, "clear failq\n");
	do {
		hqi = hsmq_dequeue(&queues->failq);
		if (!hqi)
			break;

		free(hqi);
		hqi = NULL;
	} while (true);

	return 0;
}

int clear_one_queue(struct hsm_action_item *hai, struct hsm_queue *queue)
{
	struct hsm_queue_item *last = NULL;
	struct hsm_queue_item *hqi;
	struct hsm_action_list *tmphal;
	struct hsm_action_item *tmphai;

	for (hqi = queue->head; hqi; hqi = hqi->next) {
		tmphal = &hqi->hal;
		tmphai = hai_first(tmphal);

		if (lu_fid_eq(&tmphai->hai_fid, &hai->hai_fid) &&
		    tmphai->hai_action == hai->hai_action) {
			fprintf(fp, "Clearing instance\n");
			remove_from_queue(hqi, last, queue);
			free(hqi);
			last = NULL;
			hqi = queue->head;
			break;
		} else {
			last = hqi;
		}

		if (hqi == NULL)
			break;
	}
	return 0;
}

int clear_finished(struct hsm_action_item *hai, struct hsm_queues *queues)
{
	fprintf(fp, "Clearing duplicates of: "DFID" %llx\n",
		PFID(&hai->hai_fid),
		hai->hai_cookie);

	clear_one_queue(hai, &queues->waitq);
	clear_one_queue(hai, &queues->doneq);
	clear_one_queue(hai, &queues->cancelq);
	clear_one_queue(hai, &queues->failq);

	return 0;
}

int hsm_request(void *msg, struct hsm_queues *queues)
{
	struct hsm_action_list *hal = msg;
	struct hsm_action_item *hai;
	bool cancel = false;
	int i = 0;

	fprintf(fp, "------\n");
	fprintf(fp, "Request HAL: version %d count %d compound_id %llu flags %llu "
	       "archive_id %d\n\tpadding %d fsname %s\n",
	       hal->hal_version, hal->hal_count, hal->hal_compound_id,
	       hal->hal_flags, hal->hal_archive_id, hal->padding1,
	       hal->hal_fsname);

	for (hai = hai_first(hal); i < hal->hal_count;
	     i++, hai = hai_next(hai)) {
		if (hai->hai_action == HSMA_CANCEL) {
			cancel = true;
			cancel_list(hal, queues);
		} else
			clear_finished(hai, queues);

		/* Data fid is initially set to Lustre FID */
		if (hai->hai_action == HSMA_ARCHIVE)
			hai->hai_dfid = hai->hai_fid;

		fprintf(fp, "Request HAI: len %d action %s fid "DFID" dfid "DFID"\n"
		       "\textent: %llu %llu cookie %llu gid %llu data %s\n",
		       hai->hai_len, hsm_copytool_action2name(hai->hai_action),
		       PFID(&hai->hai_fid),
		       PFID(&hai->hai_dfid), hai->hai_extent.offset,
		       hai->hai_extent.length, hai->hai_cookie, hai->hai_gid,
		       hai->hai_data);
	}
	fprintf(fp, "------\n");

	/*
	 * For cancel, we move right to DONE
	 */
	if (!cancel)
		create_queue(&queues->waitq, hal);

	return 0;
}

int hsm_list_requests(void *msg, struct hsm_queues *queues)
{
	struct hsm_queue_item *hqi;
	struct hsm_action_list hal;
	int wait = 0;
	int active = 0;
	int done = 0;
	int failed = 0;
	int canceled = 0;
	int i;

	for (hqi = queues->waitq.head; hqi; hqi = hqi->next) {
		nlmsg_send_request_list(queues->hcp,
					hai_first(&hqi->hal)->hai_cookie,
					ARS_WAITING, &hqi->hal,
					EXT_HSM_REQUEST_LIST_REP);
		wait++;
	}

	for (i = 0; i < MAX_COPYTOOLS; i++) {
		if (queues->copytools[i].active.count == 0)
			continue;

		for (hqi = queues->copytools[i].active.head; hqi;
		     hqi = hqi->next) {
			nlmsg_send_request_list(queues->hcp,
						hai_first(&hqi->hal)->hai_cookie,
						ARS_STARTED, &hqi->hal,
						EXT_HSM_REQUEST_LIST_REP);
			active++;
		}
	}

	for (hqi = queues->doneq.head; hqi; hqi = hqi->next) {
		nlmsg_send_request_list(queues->hcp,
					hai_first(&hqi->hal)->hai_cookie,
					ARS_SUCCEED, &hqi->hal,
					EXT_HSM_REQUEST_LIST_REP);
		done++;
	}

	for (hqi = queues->failq.head; hqi; hqi = hqi->next) {
		nlmsg_send_request_list(queues->hcp,
					hai_first(&hqi->hal)->hai_cookie,
					ARS_FAILED, &hqi->hal,
					EXT_HSM_REQUEST_LIST_REP);
		failed++;
	}

	for (hqi = queues->cancelq.head; hqi; hqi = hqi->next) {
		nlmsg_send_request_list(queues->hcp,
					hai_first(&hqi->hal)->hai_cookie,
					ARS_CANCELED, &hqi->hal,
					EXT_HSM_REQUEST_LIST_REP);
		canceled++;
	}

	fprintf(fp, "Send request list wait: %d active %d done %d failed %d "
	       "canceled %d\n", wait, active, done, failed, canceled);
	bzero(&hal, sizeof(struct hsm_action_list));
	/* send list-done message */
	nlmsg_send_request_list(queues->hcp, 0, ARS_CANCELED, &hal,
				EXT_HSM_REQUEST_LIST_REP);

	return 0;
}

int hsm_register(void *msg, struct hsm_queues *queues)
{
	struct hsm_register_kernel *hrk = msg;
	int i = 0;
	int empty = -1;

	fprintf(fp, "Register: %s %d\n", hrk->uuid.uuid, hrk->archives);
	for (i = 0; i < MAX_COPYTOOLS; i++) {
		if (memcmp(&queues->copytools[i].uuid, &hrk->uuid,
			   sizeof(struct obd_uuid)) == 0) {
			fprintf(fp, "registered %d\n", i);
			empty = i;
			break;
		}
		if ((empty == -1) && (queues->copytools[i].registered == 0))
			empty = i;
	}
	if (empty != -1) {
		memcpy(&queues->copytools[empty].uuid, &hrk->uuid,
		       sizeof(struct obd_uuid));
		queues->copytools[empty].archives = hrk->archives;
		queues->copytools[empty].registered++;
		fprintf(fp, "registerd %s in slot %d\n", hrk->uuid.uuid, empty);
	} else {
		fprintf(fp, "could not register %s\n", hrk->uuid.uuid);
	}

	return 0;
}

int fail_queue(struct hsm_queue *queue, struct hsm_queue *failq)
{
	struct hsm_queue_item *hqi = NULL;

	hqi = hsmq_dequeue(queue);
	while (hqi != NULL) {
		hsmq_enqueue(failq, hqi);
		hqi = hsmq_dequeue(queue);
	}

	return 0;
}

int hsm_unregister(void *msg, struct hsm_queues *queues)
{
	struct hsm_unregister_kernel *huk = msg;

	int i = 0;

	fprintf(fp, "Unregister: %s\n", huk->uuid.uuid);

	for (i = 0; i < MAX_COPYTOOLS; i++) {
		if (memcmp(&queues->copytools[i].uuid.uuid, &huk->uuid.uuid,
			   sizeof(struct obd_uuid)) == 0) {
			fprintf(fp, "Unregistered %d\n", i);
			queues->copytools[i].registered--;
			if (queues->copytools[i].registered <= 0) {
				fail_queue(&queues->copytools[i].active,
					   &queues->failq);
				queues->copytools[i].registered = 0;
				queues->copytools[i].archives = 0;
				bzero(&queues->copytools[i].uuid,
				      sizeof(struct obd_uuid));
			}
			break;
		}
	}

	return 0;
}

int start_action(struct hsm_queues *queues)
{
	struct hsm_queue_item *tmp = NULL;
	int rc = -1;
	int i = 0;

	for (i = 0; i < MAX_COPYTOOLS && rc == -1; i++) {
		if (queues->waitq.count == 0) {
			rc = 0;
			break;
		}

		if ((queues->copytools[i].registered == 0) ||
		    (queues->copytools[i].active.count != 0))
			continue;

		/* Archive 0 handles everything */
		if ((queues->copytools[i].archives != 0) &&
		    (queues->copytools[i].archives !=
		     queues->waitq.head->hal.hal_archive_id))
			continue;

		tmp = hsmq_dequeue(&queues->waitq);

		if (tmp == NULL)
			break;

		hsmq_enqueue(&queues->copytools[i].active, tmp);
		nlmsg_send_to_ct(queues->hcp,
				 queues->copytools[i].uuid, &tmp->hal);
		rc = 0;
	}

	return rc;
}

int clear_done(struct hsm_record_update *hru, struct hsm_queues *queues)
{
	struct hsm_queue_item *hqi;
	struct hsm_queue_item *last = NULL;
	struct hsm_action_list *hal;
	struct hsm_action_item *hai;
	struct hsm_queue *runq;
	int i;

	for (i = 0; i < MAX_COPYTOOLS; i++) {
		runq = &queues->copytools[i].active;

		for (hqi = runq->head; hqi != NULL; hqi = hqi->next) {
			hal = &hqi->hal;
			hai = hai_first(hal);
			if (hai->hai_cookie != hru->cookie) {
				last = hqi;
				continue;
			}

			hai = hai_first(hal);
			remove_from_queue(hqi, last, runq);
			switch (hru->status) {
			case ARS_SUCCEED:
				clear_one_queue(hai, &queues->doneq);
				hsmq_enqueue(&queues->doneq, hqi);
				break;
			case ARS_FAILED:
				clear_one_queue(hai, &queues->failq);
				hsmq_enqueue(&queues->failq, hqi);
				break;
			case ARS_CANCELED:
				clear_one_queue(hai, &queues->cancelq);
				hsmq_enqueue(&queues->cancelq, hqi);
				break;
			default:
				fprintf(fp, "Bad State %d\n",
					hru->status);
				break;
			};

			fprintf(fp, "Moving to %s: "DFID" %llx\n",
				agent_req_status2name(hru->status),
				PFID(&hai->hai_fid),
				hru->cookie);

			if (queues->doneq.count > MAX_COPYTOOLS) {
				struct hsm_queue_item *hqia;

				hqia = hsmq_dequeue(&queues->doneq);
				hai = hai_first(&hqia->hal);
				fprintf(fp, "removing item from doneq "
					DFID"\n", PFID(&hai->hai_fid));
				if (hqia != NULL)
					free(hqia);
				hqia = NULL;
			}
		}
	}
	return 0;
}

void init_queue(struct hsm_queue *queue)
{
	queue->head = NULL;
	queue->tail = NULL;
	queue->count = 0;
}

int main(int argc, char **argv)
{
	struct hsm_queues queues;
	enum ext_hsm_cmd cmd;
	void *msg;
	size_t msgsize = MAX_PAYLOAD;
	int i = 0;

	fp = stdout;
	if (argc == 2) {
		fprintf(fp, "argv[1] = %s\n", argv[1]);
		fp = fopen(argv[1], "w+");
	}

	init_queue(&queues.waitq);
	init_queue(&queues.doneq);
	init_queue(&queues.failq);
	init_queue(&queues.cancelq);

	for (i = 0; i < MAX_COPYTOOLS; i++) {
		init_queue(&queues.copytools[i].active);
		queues.copytools[i].registered = 0;
		queues.copytools[i].archives = 0;
		bzero(&queues.copytools[i].uuid, sizeof(struct obd_uuid));
	}

	msg = malloc(msgsize);
	queues.hcp = llapi_hsm_cdt_connect(msgsize);

	fprintf(fp, "Waiting for message from kernel\n");
/* Read message from kernel */
	while (true) {
		cmd = llapi_hsm_cdt_recv(queues.hcp, msg, msgsize);

		switch (cmd) {
		case EXT_HSM_FAIL:
			fprintf(fp, "Failed to receive message %d\n", cmd);
			break;
		case EXT_HSM_ACTION:
			hsm_action(msg, &queues);
			break;
		case EXT_HSM_PROGRESS:
			hsm_progress(msg, &queues);
			break;
		case EXT_HSM_COMPLETE:
			clear_done(msg, &queues);
			break;
		case EXT_HSM_REQUEST:
			hsm_request(msg, &queues);
			break;
		case EXT_HSM_REQUEST_LIST_REQ:
			hsm_list_requests(msg, &queues);
			break;
		case EXT_HSM_CT_REGISTER:
			hsm_register(msg, &queues);
			break;
		case EXT_HSM_CT_UNREGISTER:
			hsm_unregister(msg, &queues);
			break;
		case EXT_HSM_CANCEL_ALL:
			hsm_cancel_all(&queues);
			break;
		default:
			fprintf(fp, "Unknown msg type %d\n", cmd);
			break;
		}

		start_action(&queues);
		fflush(fp);
	}
	llapi_hsm_cdt_disconnect(queues.hcp);
	queues.hcp = NULL;

	return 0;
}
