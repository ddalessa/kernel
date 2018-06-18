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
#include "qp.h"
#include "rc.h"
#include "verbs.h"
#include "tid_rdma.h"
#include "user_exp_rcv.h"
#include "trace.h"

/**
 * DOC: TID RDMA READ protocol
 *
 * This is an end-to-end protocol at the hfi1 level between two nodes that
 * improves performance by avoiding data copy on the requester side. It
 * converts a qualified RDMA READ request into a TID RDMA READ request on
 * the requester side and thereafter handles the request and response
 * differently. To be qualified, the RDMA READ request should meet the
 * following:
 * -- The total data length should be greater than 256K;
 * -- The total data length should be a multiple of 4K page size;
 * -- Each local scatter-gather entry should be 4K page aligned;
 * -- Each local scatter-gather entry should be a multiple of 4K page size;
 */

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

static u32 mask_generation(u32 a)
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

static struct tid_rdma_flow *find_flow_ib(struct tid_rdma_request *req,
					  u32 psn, u16 *fidx)
{
	u16 head, tail;
	struct tid_rdma_flow *flow;

	head = req->setup_head;
	tail = req->clear_tail;
	for ( ; CIRC_CNT(head, tail, req->n_max_flows);
	     tail = CIRC_NEXT(tail, req->n_max_flows)) {
		flow = &req->flows[tail];
		if (cmp_psn(psn, flow->flow_state.ib_spsn) >= 0 &&
		    cmp_psn(psn, flow->flow_state.ib_lpsn) <= 0) {
			if (fidx)
				*fidx = tail;
			return flow;
		}
	}
	return NULL;
}

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

static int hfi1_kern_setup_hw_flow(struct hfi1_ctxtdata *rcd,
				   struct rvt_qp *qp)
{
	return 0;
}

void hfi1_kern_clear_hw_flow(struct hfi1_ctxtdata *rcd, struct rvt_qp *qp)
{
}

static int hfi1_kern_exp_rcv_setup(struct tid_rdma_request *req,
				   struct rvt_sge_state *ss, bool *last)
{
	return 0;
}

int hfi1_kern_exp_rcv_clear(struct tid_rdma_request *req)
	__must_hold(&req->qp->s_lock)
{
	return 0;
}

void hfi1_kern_exp_rcv_clear_all(struct tid_rdma_request *req)
	__must_hold(&req->qp->s_lock)
{
}

/*
 * Validate and accept the TID RDMA READ request parameters.
 * Return 0 if the request is accepted successfully;
 * Return 1 otherwise.
 */
static int tid_rdma_rcv_read_request(struct rvt_qp *qp,
				     struct rvt_ack_entry *e,
				     struct hfi1_packet *packet,
				     struct ib_other_headers *ohdr,
				     u32 bth0, u32 psn, u64 vaddr, u32 len)
{
	int ret = 0;
	struct hfi1_qp_priv *qpriv = qp->priv;
	struct tid_rdma_request *req;
	struct tid_rdma_flow *flow;
	u32 flow_psn, i, tidlen = 0, pktlen, tlen;

	req = ack_to_tid_req(e);

	/* Validate the payload first */
	flow = &req->flows[req->setup_head];

	/* payload length = packet length - (header length + ICRC length) */
	pktlen = packet->tlen - (packet->hlen + 4);
	memcpy(flow->fstate->tid_entry, packet->ebuf, pktlen);
	flow->tidcnt = pktlen / sizeof(*flow->fstate->tid_entry);

	/*
	 * Walk the TID_ENTRY list to make sure we have enough space for a
	 * complete segment. Also calculate the number of required packets.
	 */
	flow->npkts = rvt_div_round_up_mtu(qp, len);
	for (i = 0; i < flow->tidcnt; i++) {
		tlen = EXP_TID_GET(flow->fstate->tid_entry[i], LEN);
		if (!tlen) {
			ret = 1;
			goto done;
		}
		/*
		 * For tid pair (tidctr == 3), the buffer size of the pair
		 * should be the sum of the buffer size described by each
		 * tid entry. However, only the first entry needs to be
		 * specified in the request (see WFR HAS Section 8.5.7.1).
		 */
		tidlen += tlen;
	}
	if (tidlen * PAGE_SIZE < len) {
		ret = 1;
		goto done;
	}

	/* Empty the flow array */
	req->clear_tail = req->setup_head;
	flow->req = req;
	flow->pkt = 0;
	flow->tid_idx = 0;
	flow->tid_offset = 0;
	flow->sent = 0;
	flow->tid_qpn = be32_to_cpu(ohdr->u.tid_rdma.r_req.tid_flow_qp);
	flow->idx = (flow->tid_qpn >> TID_RDMA_DESTQP_FLOW_SHIFT) &
		    TID_RDMA_DESTQP_FLOW_MASK;
	flow_psn = mask_psn(be32_to_cpu(ohdr->u.tid_rdma.r_req.tid_flow_psn));
	flow->flow_state.generation = flow_psn >> HFI1_KDETH_BTH_SEQ_SHIFT;
	flow->flow_state.spsn = flow_psn & HFI1_KDETH_BTH_SEQ_MASK;
	flow->length = len;

	flow->flow_state.lpsn = flow->flow_state.spsn +
		flow->npkts - 1;
	flow->flow_state.ib_spsn = psn;
	flow->flow_state.ib_lpsn = flow->flow_state.ib_spsn + flow->npkts - 1;

	/* Set the initial flow index to the current flow. */
	req->flow_idx = req->setup_head;

	/* advance circular buffer head */
	req->setup_head = (req->setup_head + 1) & (req->n_max_flows - 1);

	/*
	 * Compute last PSN for request.
	 */
	e->opcode = (bth0 >> 24) & 0xff;
	e->psn = psn;
	e->lpsn = psn + flow->npkts - 1;
	e->sent = 0;

	req->n_flows = qpriv->tid_rdma.local.max_read;
	req->state = TID_REQUEST_ACTIVE;
	req->cur_seg = 0;
	req->comp_seg = 0;
	req->ack_seg = 0;
	req->isge = 0;
	req->seg_len = qpriv->tid_rdma.local.max_len;
	req->total_len = len;
	req->total_segs = 1;
	req->r_flow_psn = e->psn;
done:
	return ret;
}

static int tid_rdma_rcv_error(struct hfi1_packet *packet,
			      struct ib_other_headers *ohdr,
			      struct rvt_qp *qp, u32 psn, int diff)
{
	struct hfi1_ibport *ibp = to_iport(qp->ibqp.device, qp->port_num);
	struct hfi1_ctxtdata *rcd = ((struct hfi1_qp_priv *)qp->priv)->rcd;
	struct rvt_ack_entry *e;
	struct tid_rdma_request *req;
	unsigned long flags;
	u8 prev;
	bool old_req;

	if (diff > 0) {
		/* sequence error */
		if (!qp->r_nak_state) {
			ibp->rvp.n_rc_seqnak++;
			qp->r_nak_state = IB_NAK_PSN_ERROR;
			qp->r_ack_psn = qp->r_psn;
			rc_defered_ack(rcd, qp);
		}
		goto done;
	}

	ibp->rvp.n_rc_dupreq++;

	spin_lock_irqsave(&qp->s_lock, flags);
	e = find_prev_entry(qp, psn, &prev, NULL, &old_req);
	if (!e || (e->opcode != TID_OP(WRITE_REQ) &&
		   e->opcode != TID_OP(READ_REQ)))
		goto unlock;

	req = ack_to_tid_req(e);
	req->r_flow_psn = psn;
	if (e->opcode == TID_OP(WRITE_REQ)) {
	} else {
		struct ib_reth *reth;
		u32 offset;
		u32 len;
		u32 rkey;
		u64 vaddr;
		int ok;
		u32 bth0;

		reth = &ohdr->u.tid_rdma.r_req.reth;
		/*
		 * The requester always restarts from the start of the original
		 * request.
		 */
		offset = delta_psn(psn, e->psn) * qp->pmtu;
		len = be32_to_cpu(reth->length);
		if (psn != e->psn || len != req->total_len)
			goto unlock;

		if (e->rdma_sge.mr) {
			rvt_put_mr(e->rdma_sge.mr);
			e->rdma_sge.mr = NULL;
		}

		rkey = be32_to_cpu(reth->rkey);
		vaddr = get_ib_reth_vaddr(reth);

		qp->r_len = len;
		ok = rvt_rkey_ok(qp, &e->rdma_sge, len, vaddr, rkey,
				 IB_ACCESS_REMOTE_READ);
		if (unlikely(!ok))
			goto unlock;

		/*
		 * If all the response packets for the current request have
		 * been sent out and this request is complete (old_request
		 * == false) and the TID flow may be unusable (the
		 * req->clear_tail is advanced). However, when an earlier
		 * request is received, this request will not be complete any
		 * more (qp->s_tail_ack_queue is moved back, see below).
		 * Consequently, we need to update the TID flow info everytime
		 * a duplicate request is received.
		 */
		bth0 = be32_to_cpu(ohdr->bth[0]);
		if (tid_rdma_rcv_read_request(qp, e, packet, ohdr, bth0, psn,
					      vaddr, len))
			goto unlock;

		/*
		 * If all the response packets for the current request have
		 * been sent out and this request is complete (old_request
		 * == false) and the TID flow may be unusable (the
		 * req->clear_tail is advanced). However, when an earlier
		 * request is received, this request will not be complete any
		 * more (qp->s_tail_ack_queue is moved back, see below).
		 * Consequently, we need to update the TID flow info everytime
		 * a duplicate request is received.
		 */
		bth0 = be32_to_cpu(ohdr->bth[0]);
		if (tid_rdma_rcv_read_request(qp, e, packet, ohdr, bth0, psn,
					      vaddr, len))
			goto unlock;

		/*
		 * True if the request is already scheduled (between
		 * qp->s_tail_ack_queue and qp->r_head_ack_queue);
		 */
		if (old_req)
			goto unlock;
	}
	/* Re-process old requests.*/
	qp->s_tail_ack_queue = prev;
	/*
	 * Since the qp->s_tail_ack_queue is modified, the
	 * qp->s_ack_state must be changed to re-initialize
	 * qp->s_ack_rdma_sge; Otherwise, we will end up in
	 * wrong memory region.
	 */
	qp->s_ack_state = OP(ACKNOWLEDGE);
	qp->r_state = e->opcode;
	qp->r_nak_state = 0;
	qp->s_flags |= RVT_S_RESP_PENDING;
	hfi1_schedule_send(qp);
unlock:
	spin_unlock_irqrestore(&qp->s_lock, flags);
done:
	return 1;
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
	/* HANDLER FOR TID RDMA READ REQUEST packet (Responder side)*/

	/*
	 * 1. Verify TID RDMA READ REQ as per IB_OPCODE_RC_RDMA_READ
	 *    (see hfi1_rc_rcv())
	 * 2. Put TID RDMA READ REQ into the response queueu (s_ack_queue)
	 *     - Setup struct tid_rdma_req with request info
	 *     - Initialize struct tid_rdma_flow info;
	 *     - Copy TID entries;
	 * 3. Set the qp->s_ack_state as state diagram in design doc.
	 * 4. Set RVT_S_RESP_PENDING in s_flags.
	 * 5. Kick the send engine (hfi1_schedule_send())
	 */
	struct hfi1_ctxtdata *rcd = packet->rcd;
	struct rvt_qp *qp = packet->qp;
	struct hfi1_ibport *ibp = to_iport(qp->ibqp.device, qp->port_num);
	struct ib_other_headers *ohdr = packet->ohdr;
	struct rvt_ack_entry *e;
	unsigned long flags;
	struct ib_reth *reth;
	struct hfi1_qp_priv *qpriv = qp->priv;
	u32 bth0, psn, len, rkey;
	bool is_fecn;
	u8 next;
	u64 vaddr;
	int diff;
	u8 nack_state = IB_NAK_INVALID_REQUEST;

	bth0 = be32_to_cpu(ohdr->bth[0]);
	if (hfi1_ruc_check_hdr(ibp, packet))
		return;

	is_fecn = process_ecn(qp, packet, false);
	psn = mask_psn(be32_to_cpu(ohdr->bth[2]));

	if (qp->state == IB_QPS_RTR && !(qp->r_flags & RVT_R_COMM_EST))
		rvt_comm_est(qp);

	if (unlikely(!(qp->qp_access_flags & IB_ACCESS_REMOTE_READ)))
		goto nack_inv;

	reth = &ohdr->u.tid_rdma.r_req.reth;
	vaddr = be64_to_cpu(reth->vaddr);
	len = be32_to_cpu(reth->length);
	/* The length needs to be in multiples of PAGE_SIZE */
	if (!len || len & ~PAGE_MASK || len > qpriv->tid_rdma.local.max_len)
		goto nack_inv;

	diff = delta_psn(psn, qp->r_psn);
	if (unlikely(diff)) {
		if (tid_rdma_rcv_error(packet, ohdr, qp, psn, diff))
			return;
		goto send_ack;
	}

	/* We've verified the request, insert it into the ack queue. */
	next = qp->r_head_ack_queue + 1;
	if (next > rvt_size_atomic(ib_to_rvt(qp->ibqp.device)))
		next = 0;
	spin_lock_irqsave(&qp->s_lock, flags);
	if (unlikely(next == qp->s_tail_ack_queue)) {
		if (!qp->s_ack_queue[next].sent) {
			nack_state = IB_NAK_REMOTE_OPERATIONAL_ERROR;
			goto nack_inv_unlock;
		}
		update_ack_queue(qp, next);
	}
	e = &qp->s_ack_queue[qp->r_head_ack_queue];
	if (e->rdma_sge.mr) {
		rvt_put_mr(e->rdma_sge.mr);
		e->rdma_sge.mr = NULL;
	}

	rkey = be32_to_cpu(reth->rkey);
	qp->r_len = len;

	if (unlikely(!rvt_rkey_ok(qp, &e->rdma_sge, qp->r_len, vaddr,
				  rkey, IB_ACCESS_REMOTE_READ)))
		goto nack_acc;

	/* Accept the request parameters */
	if (tid_rdma_rcv_read_request(qp, e, packet, ohdr, bth0, psn, vaddr,
				      len))
		goto nack_inv_unlock;

	qp->r_state = e->opcode;
	qp->r_nak_state = 0;
	/*
	 * We need to increment the MSN here instead of when we
	 * finish sending the result since a duplicate request would
	 * increment it more than once.
	 */
	qp->r_msn++;
	qp->r_psn += e->lpsn - e->psn + 1;

	qp->r_head_ack_queue = next;

	/* Schedule the send tasklet. */
	qp->s_flags |= RVT_S_RESP_PENDING;
	hfi1_schedule_send(qp);

	spin_unlock_irqrestore(&qp->s_lock, flags);
	if (is_fecn)
		goto send_ack;
	return;

nack_inv_unlock:
	spin_unlock_irqrestore(&qp->s_lock, flags);
nack_inv:
	rvt_rc_error(qp, IB_WC_LOC_QP_OP_ERR);
	qp->r_nak_state = nack_state;
	qp->r_ack_psn = qp->r_psn;
	/* Queue NAK for later */
	rc_defered_ack(rcd, qp);
	return;
nack_acc:
	spin_unlock_irqrestore(&qp->s_lock, flags);
	rvt_rc_error(qp, IB_WC_LOC_PROT_ERR);
	qp->r_nak_state = IB_NAK_REMOTE_ACCESS_ERROR;
	qp->r_ack_psn = qp->r_psn;
send_ack:
	hfi1_send_rc_ack(packet, is_fecn);
}

static inline struct tid_rdma_request *
find_tid_request(struct rvt_qp *qp, u32 psn, enum ib_wr_opcode opcode)
	__must_hold(&qp->s_lock)
{
	struct rvt_swqe *wqe;
	struct tid_rdma_request *req = NULL;
	u32 i, end;

	end = qp->s_cur + 1;
	if (end == qp->s_size)
		end = 0;
	for (i = qp->s_acked; i != end;) {
		wqe = rvt_get_swqe_ptr(qp, i);
		if (cmp_psn(psn, wqe->psn) >= 0 &&
		    cmp_psn(psn, wqe->lpsn) <= 0) {
			if (wqe->wr.opcode == opcode)
				req = wqe_to_tid_req(wqe);
			break;
		}
		if (++i == qp->s_size)
			i = 0;
	}

	return req;
}

void hfi1_rc_rcv_tid_rdma_read_resp(struct hfi1_packet *packet)
{
	/* HANDLER FOR TID RDMA READ RESPONSE packet (Requestor side */

	/*
	 * 1. Find matching SWQE
	 * 2. Check that the entire segment has been read.
	 * 3. Remove RVT_S_WAIT_TID_RESP from s_flags.
	 * 4. Free the TID flow resources.
	 * 5. Kick the send engine (hfi1_schedule_send())
	 */
	struct ib_other_headers *ohdr = packet->ohdr;
	struct rvt_qp *qp = packet->qp;
	struct hfi1_qp_priv *priv = qp->priv;
	struct hfi1_ctxtdata *rcd = packet->rcd;
	struct tid_rdma_request *req;
	struct tid_rdma_flow *flow;
	u32 opcode, aeth;
	bool is_fecn;
	unsigned long flags;
	u32 kpsn, ipsn;

	is_fecn = process_ecn(qp, packet, false);
	kpsn = mask_psn(be32_to_cpu(ohdr->bth[2]));
	aeth = be32_to_cpu(ohdr->u.tid_rdma.r_rsp.aeth);
	opcode = (be32_to_cpu(ohdr->bth[0]) >> 24) & 0xff;

	spin_lock_irqsave(&qp->s_lock, flags);
	ipsn = mask_psn(be32_to_cpu(ohdr->u.tid_rdma.r_rsp.verbs_psn));
	req = find_tid_request(qp, ipsn, IB_WR_TID_RDMA_READ);
	if (unlikely(!req))
		goto ack_op_err;

	flow = &req->flows[req->clear_tail];
	/* When header suppression is disabled */
	if (cmp_psn(ipsn, flow->flow_state.ib_lpsn))
		goto ack_done;
	req->ack_pending--;
	priv->pending_tid_r_segs--;
	qp->s_num_rd_atomic--;
	if ((qp->s_flags & RVT_S_WAIT_FENCE) &&
	    !qp->s_num_rd_atomic) {
		qp->s_flags &= ~(RVT_S_WAIT_FENCE |
				 RVT_S_WAIT_ACK);
		hfi1_schedule_send(qp);
	}
	if (qp->s_flags & RVT_S_WAIT_RDMAR) {
		qp->s_flags &= ~(RVT_S_WAIT_RDMAR | RVT_S_WAIT_ACK);
		hfi1_schedule_send(qp);
	}

	trace_hfi1_ack(qp, ipsn);

	if (!do_rc_ack(qp, aeth, ipsn, opcode, 0, rcd))
		goto ack_done;

	/* Release the tid resources */
	hfi1_kern_exp_rcv_clear(req);

	/* If not done yet, build next read request */
	if (++req->comp_seg >= req->total_segs) {
		priv->tid_r_comp++;
		req->state = TID_REQUEST_COMPLETE;
	}

	/*
	 * Clear the hw flow under two conditions:
	 * 1. This request is a sync point and it is complete;
	 * 2. Current request is completed and there are no more requests.
	 */
	if ((req->state == TID_REQUEST_SYNC &&
	     req->comp_seg == req->cur_seg) ||
	    priv->tid_r_comp == priv->tid_r_reqs) {
		hfi1_kern_clear_hw_flow(priv->rcd, qp);
		if (req->state == TID_REQUEST_SYNC)
			req->state = TID_REQUEST_ACTIVE;
	}

	hfi1_schedule_send(qp);
	goto ack_done;

ack_op_err:
	/*
	 * The test indicates that the send engine has finished its cleanup
	 * after sending the request and it's now safe to put the QP into error
	 * state. However, if the wqe queue is empty (qp->s_acked == qp->s_tail
	 * == qp->s_head), it would be unsafe to complete the wqe pointed by
	 * qp->s_acked here. Putting the qp into error state will safely flush
	 * all remaining requests.
	 */
	if (qp->s_last == qp->s_acked)
		rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR);

ack_done:
	spin_unlock_irqrestore(&qp->s_lock, flags);
	if (is_fecn)
		hfi1_send_rc_ack(packet, is_fecn);
}

void hfi1_rc_rcv_tid_rdma_resync(struct hfi1_packet *packet)
{
}

void hfi1_rc_rcv_tid_rdma_ack(struct hfi1_packet *packet)
{
}

void hfi1_kern_read_tid_flow_free(struct rvt_qp *qp)
	__must_hold(&qp->s_lock)
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
	int i;

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
		for (i = 0; i < qp->s_size; i++) {
			struct hfi1_swqe_priv *priv;
			struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, i);

			priv = kzalloc(sizeof(*priv), GFP_KERNEL);
			if (!priv)
				return -ENOMEM;

			/*
			 * Initialize various TID RDMA request variables.
			 * These variables are "static", which is why they
			 * can be pre-initialized here before the WRs has
			 * even been submitted.
			 * However, non-NULL values for these variables do not
			 * imply that this WQE has been enabled for TID RDMA.
			 * Drivers should check the WQE's opcode to determine
			 * if a request is a TID RDMA one or not.
			 */
			priv->tid_req.qp = qp;
			priv->tid_req.rcd = qpriv->rcd;
			priv->tid_req.e.swqe = wqe;
			wqe->priv = priv;
		}
		for (i = 0; i < rvt_max_atomic(rdi); i++) {
			struct hfi1_ack_priv *priv;

			priv = kzalloc(sizeof(*priv), GFP_KERNEL);
			if (!priv)
				return -ENOMEM;

			priv->tid_req.qp = qp;
			priv->tid_req.rcd = qpriv->rcd;
			priv->tid_req.e.ack = &qp->s_ack_queue[i];
			qp->s_ack_queue[i].priv = priv;
		}
	}

	return 0;
}

void hfi1_qp_priv_tid_free(struct rvt_dev_info *rdi, struct rvt_qp *qp)
{
	struct hfi1_qp_priv *priv = qp->priv;
	struct rvt_swqe *wqe;
	u32 i;

	if (qp->ibqp.qp_type == IB_QPT_RC && HFI1_CAP_IS_KSET(TID_RDMA)) {
		for (i = 0; i < qp->s_size; i++) {
			struct hfi1_swqe_priv *priv;

			wqe = rvt_get_swqe_ptr(qp, i);
			priv = wqe->priv;
			kfree(priv);
			wqe->priv = NULL;
		}
		for (i = 0; i < rvt_max_atomic(rdi); i++) {
			struct hfi1_ack_priv *priv = qp->s_ack_queue[i].priv;

			kfree(priv);
			qp->s_ack_queue[i].priv = NULL;
		}
		cancel_work_sync(&priv->opfn.opfn_work);
		kfree(priv->pages);
		priv->pages = NULL;
	}
}

/*
 *  "Rewind" the TID request information.
 *  This means that we reset the state back to ACTIVE,
 *  find the proper flow, set the flow index to that flow,
 *  and reset the flow information.
 */
void hfi1_tid_rdma_restart_req(struct rvt_qp *qp, struct rvt_swqe *wqe,
			       u32 *bth2)
{
	struct tid_rdma_request *req = wqe_to_tid_req(wqe);
	struct tid_rdma_flow *flow;
	int diff;
	u32 tididx = 0;
	u16 fidx;

	if (wqe->wr.opcode == IB_WR_TID_RDMA_READ) {
		*bth2 = mask_psn(qp->s_psn);
		flow = find_flow_ib(req, *bth2, &fidx);
		if (!flow)
			return;
	} else {
		return;
	}

	diff = delta_psn(*bth2, flow->flow_state.ib_spsn);

	flow->sent = 0;
	flow->pkt = 0;
	flow->tid_idx = 0;
	flow->tid_offset = 0;
	if (diff) {
		for (tididx = 0; tididx < flow->tidcnt; tididx++) {
			u32 tidentry = flow->fstate->tid_entry[tididx], tidlen,
			tidnpkts, npkts;

			flow->tid_offset = 0;
			tidlen = EXP_TID_GET(tidentry, LEN) * PAGE_SIZE;
			tidnpkts = rvt_div_round_up_mtu(qp, tidlen);
			npkts = min_t(u32, diff, tidnpkts);
			flow->pkt += npkts;
			flow->sent += (npkts == tidnpkts ? tidlen :
				       npkts * qp->pmtu);
			flow->tid_offset += npkts * qp->pmtu;
			diff -= npkts;
			if (!diff)
				break;
		}
	}

	if (flow->tid_offset ==
		EXP_TID_GET(flow->fstate->tid_entry[tididx], LEN) * PAGE_SIZE) {
		tididx++;
		flow->tid_offset = 0;
	}
	flow->tid_idx = tididx;
	/* Move flow_idx to correct index */
	req->flow_idx = fidx;

	req->state = TID_REQUEST_ACTIVE;
}

u32 hfi1_build_tid_rdma_read_packet(struct rvt_swqe *wqe,
				    struct ib_other_headers *ohdr, u32 *bth1,
				    u32 *bth2, u32 *len)
{
	struct tid_rdma_request *req = wqe_to_tid_req(wqe);
	struct tid_rdma_flow *flow = &req->flows[req->flow_idx];
	struct rvt_qp *qp = req->qp;
	struct hfi1_qp_priv *qpriv = qp->priv;
	struct hfi1_swqe_priv *wpriv = wqe->priv;
	struct tid_rdma_read_req *rreq = &ohdr->u.tid_rdma.r_req;
	struct tid_rdma_params *remote;
	u32 req_len = 0;
	void *req_addr = NULL;

	/* This is the IB psn used to send the request */
	*bth2 = mask_psn(flow->flow_state.ib_spsn + flow->pkt);

	/* TID Entries for TID RDMA READ payload */
	req_addr = &flow->fstate->tid_entry[flow->tid_idx];
	req_len = sizeof(*flow->fstate->tid_entry) *
			(flow->tidcnt - flow->tid_idx);

	memset(&ohdr->u.tid_rdma.r_req, 0, sizeof(ohdr->u.tid_rdma.r_req));
	wpriv->ss.sge.vaddr = req_addr;
	wpriv->ss.sge.sge_length = req_len;
	wpriv->ss.sge.length = wpriv->ss.sge.sge_length;
	/*
	 * We can safely zero these out. Since the first SGE covers the
	 * entire packet, nothing else should even look at the MR.
	 */
	wpriv->ss.sge.mr = NULL;
	wpriv->ss.sge.m = 0;
	wpriv->ss.sge.n = 0;

	wpriv->ss.sg_list = NULL;
	wpriv->ss.total_len = wpriv->ss.sge.sge_length;
	wpriv->ss.num_sge = 1;

	/* Construct the TID RDMA READ REQ packet header */
	rcu_read_lock();
	remote = rcu_dereference(qpriv->tid_rdma.remote);

	KDETH_RESET(rreq->kdeth0, KVER, 0x1);
	KDETH_RESET(rreq->kdeth1, JKEY, remote->jkey);
	rreq->reth.vaddr = cpu_to_be64(wqe->rdma_wr.remote_addr +
			   req->cur_seg * req->seg_len + flow->sent);
	rreq->reth.rkey = cpu_to_be32(wqe->rdma_wr.rkey);
	rreq->reth.length = cpu_to_be32(*len);
	rreq->tid_flow_psn =
		cpu_to_be32((flow->flow_state.generation <<
			     HFI1_KDETH_BTH_SEQ_SHIFT) |
			    ((flow->flow_state.spsn + flow->pkt) &
			     HFI1_KDETH_BTH_SEQ_MASK));
	rreq->tid_flow_qp =
		cpu_to_be32(qpriv->tid_rdma.local.qp |
			    ((flow->idx & TID_RDMA_DESTQP_FLOW_MASK) <<
			     TID_RDMA_DESTQP_FLOW_SHIFT) |
			    qpriv->rcd->ctxt);
	rreq->verbs_qp = cpu_to_be32(qp->remote_qpn);
	*bth1 &= ~RVT_QPN_MASK;
	*bth1 |= remote->qp;
	*bth2 |= IB_BTH_REQ_ACK;
	rcu_read_unlock();

	/* We are done with this segment */
	flow->sent += *len;
	req->cur_seg++;
	qp->s_state = TID_OP(READ_REQ);
	req->ack_pending++;
	req->flow_idx = (req->flow_idx + 1) & (req->n_max_flows - 1);
	qpriv->pending_tid_r_segs++;
	qp->s_num_rd_atomic++;

	/* Set the TID RDMA READ request payload size */
	*len = req_len;

	return sizeof(ohdr->u.tid_rdma.r_req) / sizeof(u32);
}

/*
 * @len: contains the data length to read upon entry and the read request
 *       payload length upon exit.
 */
u32 hfi1_build_tid_rdma_read_req(struct rvt_qp *qp, struct rvt_swqe *wqe,
				 struct ib_other_headers *ohdr, u32 *bth1,
				 u32 *bth2, u32 *len)
	 __must_hold(&qp->s_lock)
{
	struct hfi1_qp_priv *qpriv = qp->priv;
	struct tid_rdma_request *req = wqe_to_tid_req(wqe);
	struct tid_rdma_flow *flow = NULL;
	u32 hdwords = 0;
	bool last;
	bool retry = true;
	u32 npkts = rvt_div_round_up_mtu(qp, *len);

	/*
	 * Check sync conditions. Make sure that there are no pending
	 * segments before freeing the flow.
	 */
sync_check:
	if (req->state == TID_REQUEST_SYNC) {
		if (qpriv->pending_tid_r_segs)
			goto done;

		hfi1_kern_clear_hw_flow(req->rcd, qp);
		req->state = TID_REQUEST_ACTIVE;
	}

	/*
	 * If the request for this segment is resent, the tid resources should
	 * have been allocated before. In this case, req->flow_idx should
	 * fall behind req->setup_head.
	 */
	if (req->flow_idx == req->setup_head) {
		retry = false;
		if (req->state == TID_REQUEST_RESEND) {
			/*
			 * This is the first new segment for a request whose
			 * earlier segments have been re-sent. We need to
			 * set up the sge pointer correctly.
			 */
			restart_sge(&qp->s_sge, wqe, req->s_next_psn,
				    qp->pmtu);
			req->isge = 0;
			req->state = TID_REQUEST_ACTIVE;
		}

		/*
		 * Check sync. The last PSN of each generation is reserved for
		 * RESYNC.
		 */
		if ((qpriv->flow_state.psn + npkts) > MAX_TID_FLOW_PSN - 1) {
			req->state = TID_REQUEST_SYNC;
			goto sync_check;
		}

		/* Allocate the flow if not yet */
		if (hfi1_kern_setup_hw_flow(qpriv->rcd, qp))
			goto done;

		/*
		 * The following call will advance req->setup_head after
		 * allocating the tid entries.
		 */
		if (hfi1_kern_exp_rcv_setup(req, &qp->s_sge, &last)) {
			req->state = TID_REQUEST_QUEUED;

			/*
			 * We don't have resources for this segment. The QP has
			 * already been queued.
			 */
			goto done;
		}
	}

	/* req->flow_idx should only be one slot behind req->setup_head */
	flow = &req->flows[req->flow_idx];
	flow->pkt = 0;
	flow->tid_idx = 0;
	flow->sent = 0;
	if (!retry) {
		/* Set the first and last IB PSN for the flow in use.*/
		flow->flow_state.ib_spsn = req->s_next_psn;
		flow->flow_state.ib_lpsn =
			flow->flow_state.ib_spsn + flow->npkts - 1;
	}

	/* Calculate the next segment start psn.*/
	req->s_next_psn += flow->npkts;

	/* Build the packet header */
	hdwords = hfi1_build_tid_rdma_read_packet(wqe, ohdr, bth1, bth2, len);
done:
	return hdwords;
}

u32 hfi1_build_tid_rdma_read_resp(struct rvt_qp *qp, struct rvt_ack_entry *e,
				  struct ib_other_headers *ohdr, u32 *bth0,
				  u32 *bth1, u32 *bth2, u32 *len, bool *last)
{
	struct hfi1_ack_priv *epriv = e->priv;
	struct tid_rdma_request *req = &epriv->tid_req;
	struct hfi1_qp_priv *qpriv = qp->priv;
	struct tid_rdma_flow *flow = &req->flows[req->clear_tail];
	u32 tidentry = flow->fstate->tid_entry[flow->tid_idx];
	u32 tidlen = EXP_TID_GET(tidentry, LEN) << PAGE_SHIFT;
	struct tid_rdma_read_resp *resp = &ohdr->u.tid_rdma.r_rsp;
	u32 next_offset, om = KDETH_OM_LARGE;
	bool last_pkt;
	u32 hdwords = 0;
	struct tid_rdma_params *remote;

	*len = min_t(u32, qp->pmtu, tidlen - flow->tid_offset);
	flow->sent += *len;
	next_offset = flow->tid_offset + *len;
	last_pkt = (flow->sent >= flow->length);

	rcu_read_lock();
	remote = rcu_dereference(qpriv->tid_rdma.remote);
	if (!remote) {
		rcu_read_unlock();
		goto done;
	}
	KDETH_RESET(resp->kdeth0, KVER, 0x1);
	KDETH_SET(resp->kdeth0, SH, !last_pkt);
	KDETH_SET(resp->kdeth0, INTR, !!(!last_pkt && remote->urg));
	KDETH_SET(resp->kdeth0, TIDCTRL, EXP_TID_GET(tidentry, CTRL));
	KDETH_SET(resp->kdeth0, TID, EXP_TID_GET(tidentry, IDX));
	KDETH_SET(resp->kdeth0, OM, om == KDETH_OM_LARGE);
	KDETH_SET(resp->kdeth0, OFFSET, flow->tid_offset / om);
	KDETH_RESET(resp->kdeth1, JKEY, remote->jkey);
	resp->verbs_qp = cpu_to_be32(qp->remote_qpn);
	rcu_read_unlock();

	resp->aeth = rvt_compute_aeth(qp);
	resp->verbs_psn = cpu_to_be32(mask_psn(flow->flow_state.ib_spsn +
					       flow->pkt));

	*bth0 = TID_OP(READ_RESP) << 24;
	*bth1 = flow->tid_qpn;
	*bth2 = mask_psn(((flow->flow_state.spsn + flow->pkt++) &
			  HFI1_KDETH_BTH_SEQ_MASK) |
			 (flow->flow_state.generation <<
			  HFI1_KDETH_BTH_SEQ_SHIFT));
	*last = last_pkt;
	if (last_pkt)
		/* Advance to next flow */
		req->clear_tail = (req->clear_tail + 1) &
				  (req->n_max_flows - 1);

	if (next_offset >= tidlen) {
		flow->tid_offset = 0;
		flow->tid_idx++;
	} else {
		flow->tid_offset = next_offset;
	}

	hdwords = sizeof(ohdr->u.tid_rdma.r_rsp) / sizeof(u32);

done:
	return hdwords;
}
