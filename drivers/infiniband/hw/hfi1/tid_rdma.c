// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2018 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "hfi.h"
#include "verbs.h"
#include "tid_rdma.h"

#define MAX_EXPECTED_PAGES     (MAX_EXPECTED_BUFFER / PAGE_SIZE)

#define RCV_TID_FLOW_TABLE_CTRL_FLOW_VALID_SMASK BIT_ULL(32)
#define RCV_TID_FLOW_TABLE_CTRL_HDR_SUPP_EN_SMASK BIT_ULL(33)
#define RCV_TID_FLOW_TABLE_CTRL_KEEP_AFTER_SEQ_ERR_SMASK BIT_ULL(34)
#define RCV_TID_FLOW_TABLE_CTRL_KEEP_ON_GEN_ERR_SMASK BIT_ULL(35)
#define RCV_TID_FLOW_TABLE_STATUS_SEQ_MISMATCH_SMASK BIT_ULL(37)
#define RCV_TID_FLOW_TABLE_STATUS_GEN_MISMATCH_SMASK BIT_ULL(38)

/*
 * J_KEY for kernel contexts when TID RDMA is used.
 * See generate_jkey() in hfi.h for more information.
 */
#define TID_RDMA_JKEY                   32
#define HFI1_KERNEL_MIN_JKEY HFI1_ADMIN_JKEY_RANGE
#define HFI1_KERNEL_MAX_JKEY (2 * HFI1_ADMIN_JKEY_RANGE - 1)

/* Maximum number of segments in flight per QP request. */
#define TID_RDMA_MAX_READ_SEGS_PER_REQ  6
#define TID_RDMA_MAX_WRITE_SEGS_PER_REQ 4
#define TID_RDMA_MAX_READ_SEGS          6

#define TID_RDMA_DESTQP_FLOW_SHIFT      11
#define TID_RDMA_DESTQP_FLOW_MASK       0x1f

#define TID_FLOW_SW_PSN BIT(0)

/* Maximum number of packets within a flow generation. */
#define MAX_TID_FLOW_PSN BIT(HFI1_KDETH_BTH_SEQ_SHIFT)

#define GENERATION_MASK 0xFFFFF

static inline u32 mask_generation(u32 a)
{
	return a & GENERATION_MASK;
}

/* Reserved generation value to set to unused flows for kernel contexts */
#define KERN_GENERATION_RESERVED mask_generation(U32_MAX)

#define TID_OPFN_QP_CTXT_MASK 0xff
#define TID_OPFN_QP_CTXT_SHIFT 56
#define TID_OPFN_QP_KDETH_MASK 0xff
#define TID_OPFN_QP_KDETH_SHIFT 48
#define TID_OPFN_MAX_LEN_MASK 0x7ff
#define TID_OPFN_MAX_LEN_SHIFT 37
#define TID_OPFN_TIMEOUT_MASK 0x1f
#define TID_OPFN_TIMEOUT_SHIFT 32
#define TID_OPFN_RESERVED_MASK 0x3f
#define TID_OPFN_RESERVED_SHIFT 26
#define TID_OPFN_URG_MASK 0x1
#define TID_OPFN_URG_SHIFT 25
#define TID_OPFN_VER_MASK 0x7
#define TID_OPFN_VER_SHIFT 22
#define TID_OPFN_JKEY_MASK 0x3f
#define TID_OPFN_JKEY_SHIFT 16
#define TID_OPFN_MAX_READ_MASK 0x3f
#define TID_OPFN_MAX_READ_SHIFT 10
#define TID_OPFN_MAX_WRITE_MASK 0x3f
#define TID_OPFN_MAX_WRITE_SHIFT 4

/*
 * OPFN TID layout
 *
 * 63               47               31               15
 * NNNNNNNNKKKKKKKK MMMMMMMMMMMTTTTT DDDDDDUVVVJJJJJJ RRRRRRWWWWWWCCCC
 * 3210987654321098 7654321098765432 1098765432109876 5432109876543210
 * N - the context Number
 * K - the Kdeth_qp
 * M - Max_len
 * T - Timeout
 * D - reserveD
 * V - version
 * U - Urg capable
 * J - Jkey
 * R - max_Read
 * W - max_Write
 * C - Capcode
 */

static u64 tid_rdma_opfn_encode(struct tid_rdma_params *p)
{
	return
		(((u64)p->qp & TID_OPFN_QP_CTXT_MASK) <<
			TID_OPFN_QP_CTXT_SHIFT) |
		((((u64)p->qp >> 16) & TID_OPFN_QP_KDETH_MASK) <<
			TID_OPFN_QP_KDETH_SHIFT) |
		(((u64)((p->max_len >> PAGE_SHIFT) - 1) &
			TID_OPFN_MAX_LEN_MASK) << TID_OPFN_MAX_LEN_SHIFT) |
		(((u64)p->timeout & TID_OPFN_TIMEOUT_MASK) <<
			TID_OPFN_TIMEOUT_SHIFT) |
		(((u64)p->urg & TID_OPFN_URG_MASK) << TID_OPFN_URG_SHIFT) |
		(((u64)p->jkey & TID_OPFN_JKEY_MASK) << TID_OPFN_JKEY_SHIFT) |
		(((u64)p->max_read & TID_OPFN_MAX_READ_MASK) <<
			TID_OPFN_MAX_READ_SHIFT) |
		(((u64)p->max_write & TID_OPFN_MAX_WRITE_MASK) <<
			TID_OPFN_MAX_WRITE_SHIFT);
}

static void tid_rdma_opfn_decode(struct tid_rdma_params *p, u64 data)
{
	p->max_len = (((data >> TID_OPFN_MAX_LEN_SHIFT) &
		TID_OPFN_MAX_LEN_MASK) + 1) << PAGE_SHIFT;
	p->jkey = (data >> TID_OPFN_JKEY_SHIFT) & TID_OPFN_JKEY_MASK;
	p->max_write = (data >> TID_OPFN_MAX_WRITE_SHIFT) &
		TID_OPFN_MAX_WRITE_MASK;
	p->max_read = (data >> TID_OPFN_MAX_READ_SHIFT) &
		TID_OPFN_MAX_READ_MASK;
	p->qp =
		((((data >> TID_OPFN_QP_KDETH_SHIFT) & TID_OPFN_QP_KDETH_MASK)
			<< 16) |
		((data >> TID_OPFN_QP_CTXT_SHIFT) & TID_OPFN_QP_CTXT_MASK));
	p->urg = (data >> TID_OPFN_URG_SHIFT) & TID_OPFN_URG_MASK;
	p->timeout = (data >> TID_OPFN_TIMEOUT_SHIFT) & TID_OPFN_TIMEOUT_MASK;
}

void tid_rdma_opfn_init(struct rvt_qp *qp, struct tid_rdma_params *p)
{
	struct hfi1_qp_priv *priv = qp->priv;

	p->qp = (kdeth_qp << 16) | priv->rcd->ctxt;
	p->max_len = TID_RDMA_MAX_SEGMENT_SIZE;
	p->jkey = priv->rcd->jkey;
	p->max_read = TID_RDMA_MAX_READ_SEGS_PER_REQ;
	p->max_write = TID_RDMA_MAX_WRITE_SEGS_PER_REQ;
	p->timeout = qp->timeout;
	p->urg = is_urg_masked(priv->rcd);
}

bool tid_rdma_conn_req(struct rvt_qp *qp, u64 *data)
{
	struct hfi1_qp_priv *priv = qp->priv;

	*data = tid_rdma_opfn_encode(&priv->tid_rdma.local);
	return true;
}

bool tid_rdma_conn_reply(struct rvt_qp *qp, u64 data)
{
	struct hfi1_qp_priv *priv = qp->priv;
	struct tid_rdma_params *remote, *old;
	bool ret = true;

	old = rcu_dereference_protected(priv->tid_rdma.remote,
					lockdep_is_held(&priv->opfn.lock));
	data &= ~0xf;
	/*
	 * If data passed in is zero, return true so as not to continue the
	 * negotiation process
	 */
	if (!data || !HFI1_CAP_IS_KSET(TID_RDMA))
		goto null;
	/*
	 * If kzalloc fails, return false. This will result in:
	 * * at the requester a new OPFN request being generated to retry
	 *   the negotiation
	 * * at the responder, 0 being returned to the requester so as to
	 *   disable TID RDMA at both the requester and the responder
	 */
	remote = kzalloc(sizeof(*remote), GFP_ATOMIC);
	if (!remote) {
		ret = false;
		goto null;
	}

	tid_rdma_opfn_decode(remote, data);
	priv->tid_timer_timeout_jiffies =
		usecs_to_jiffies((((4096UL * (1UL << remote->timeout)) /
				   1000UL) << 3) * 7);
	rcu_assign_pointer(priv->tid_rdma.remote, remote);
	/*
	 * A TID RDMA READ request's segment size is not equal to
	 * remote->max_len only when the request's data length is smaller
	 * than remote->max_len. In that case, there will be only one segment.
	 * Therefore, when priv->pkts_ps is used to calculate req->cur_seg
	 * during retry, it will lead to req->cur_seg = 0, which is exactly
	 * what is expected.
	 */
	priv->pkts_ps = (u16)rvt_div_mtu(qp, remote->max_len);
	priv->timeout_shift = ilog2(priv->pkts_ps - 1) + 1;
	goto free;
null:
	RCU_INIT_POINTER(priv->tid_rdma.remote, NULL);
	priv->timeout_shift = 0;
free:
	if (old)
		kfree_rcu(old, rcu_head);
	return ret;
}

bool tid_rdma_conn_resp(struct rvt_qp *qp, u64 *data)
{
	bool ret;

	ret = tid_rdma_conn_reply(qp, *data);
	*data = 0;
	/*
	 * If tid_rdma_conn_reply() returns error, set *data as 0 to indicate
	 * TID RDMA could not be enabled. This will result in TID RDMA being
	 * disabled at the requester too.
	 */
	if (ret)
		(void)tid_rdma_conn_req(qp, data);
	return ret;
}

void tid_rdma_conn_error(struct rvt_qp *qp)
{
	struct hfi1_qp_priv *priv = qp->priv;
	struct tid_rdma_params *old;

	old = rcu_dereference_protected(priv->tid_rdma.remote,
					lockdep_is_held(&priv->opfn.lock));
	RCU_INIT_POINTER(priv->tid_rdma.remote, NULL);
	if (old)
		kfree_rcu(old, rcu_head);
}

/**
 * tid_rdma_trigger_resume - field a trigger work request
 * @work - the work item
 *
 * Complete the off qp trigger processing by directly
 * calling the progress routine.
 */
static void tid_rdma_trigger_resume(struct work_struct *work)
{
}

void hfi1_rc_rcv_tid_rdma_write_req(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_write_data(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_write_resp(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_read_req(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_read_resp(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_resync(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_ack(struct hfi1_packet *packet)
{
}

bool hfi1_handle_kdeth_eflags(struct hfi1_ctxtdata *rcd,
			      struct hfi1_pportdata *ppd,
			      struct hfi1_packet *packet)
{
	return true;
}

/**
 * qp_to_rcd - determine the receive context used by a qp
 * @qp - the qp
 *
 * This routine returns the receive context associated
 * with a a qp's qpn.
 *
 * Returns the context.
 */
static struct hfi1_ctxtdata *qp_to_rcd(struct rvt_dev_info *rdi,
				       struct rvt_qp *qp)
{
	struct hfi1_ibdev *verbs_dev = container_of(rdi,
						    struct hfi1_ibdev,
						    rdi);
	struct hfi1_devdata *dd = container_of(verbs_dev,
					       struct hfi1_devdata,
					       verbs_dev);
	unsigned int ctxt;

	if (qp->ibqp.qp_num == 0)
		ctxt = 0;
	else
		ctxt = ((qp->ibqp.qp_num >> dd->qos_shift) %
			(dd->n_krcv_queues - 1)) + 1;

	return dd->rcd[ctxt];
}

int hfi1_qp_priv_init(struct rvt_dev_info *rdi, struct rvt_qp *qp,
		      struct ib_qp_init_attr *init_attr)
{
	struct hfi1_qp_priv *qpriv = qp->priv;

	qpriv->rcd = qp_to_rcd(rdi, qp);

	spin_lock_init(&qpriv->opfn.lock);
	INIT_WORK(&qpriv->opfn.opfn_work, opfn_send_conn_request);
	INIT_WORK(&qpriv->tid_rdma.trigger_work, tid_rdma_trigger_resume);
	qpriv->flow_state.psn = 0;
	qpriv->flow_state.index = RXE_NUM_TID_FLOWS;
	qpriv->flow_state.last_index = RXE_NUM_TID_FLOWS;
	qpriv->flow_state.generation = KERN_GENERATION_RESERVED;

	if (init_attr->qp_type == IB_QPT_RC && HFI1_CAP_IS_KSET(TID_RDMA)) {
		struct hfi1_devdata *dd = qpriv->rcd->dd;

		qpriv->pages = kzalloc_node(TID_RDMA_MAX_PAGES *
						sizeof(*qpriv->pages),
					    GFP_KERNEL, dd->node);
		if (!qpriv->pages)
			return -ENOMEM;
	}

	return 0;
}

void hfi1_qp_priv_tid_free(struct rvt_dev_info *rdi, struct rvt_qp *qp)
{
	struct hfi1_qp_priv *priv = qp->priv;

	if (qp->ibqp.qp_type == IB_QPT_RC && HFI1_CAP_IS_KSET(TID_RDMA)) {
		cancel_work_sync(&priv->opfn.opfn_work);
		kfree(priv->pages);
		priv->pages = NULL;
	}
}
