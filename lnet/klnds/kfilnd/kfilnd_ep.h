#ifndef _KFILND_EP_
#define _KFILND_EP_

#include "kfilnd.h"

struct kfilnd_ep_err_fail_loc_work {
	struct kfilnd_ep *ep;
	struct work_struct work;
	struct kfi_cq_err_entry err;
};

void kfilnd_ep_dereg_mr(struct kfilnd_ep *ep, struct kfilnd_transaction *tn);
int kfilnd_ep_reg_mr(struct kfilnd_ep *ep, struct kfilnd_transaction *tn);
int kfilnd_ep_post_tagged_send(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn);
int kfilnd_ep_cancel_tagged_recv(struct kfilnd_ep *ep,
				 struct kfilnd_transaction *tn);
int kfilnd_ep_post_tagged_recv(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn);
int kfilnd_ep_post_send(struct kfilnd_ep *ep, struct kfilnd_transaction *tn);
int kfilnd_ep_post_write(struct kfilnd_ep *ep, struct kfilnd_transaction *tn);
int kfilnd_ep_post_read(struct kfilnd_ep *ep, struct kfilnd_transaction *tn);
int kfilnd_ep_imm_buffer_put(struct kfilnd_immediate_buffer *buf);
int kfilnd_ep_post_imm_buffers(struct kfilnd_ep *ep);
void kfilnd_ep_cancel_imm_buffers(struct kfilnd_ep *ep);
void kfilnd_ep_free(struct kfilnd_ep *ep);
struct kfilnd_ep *kfilnd_ep_alloc(struct kfilnd_dev *dev,
				  unsigned int context_id, unsigned int cpt,
				  size_t nrx, size_t rx_size);

#endif /* _KFILND_EP_ */
