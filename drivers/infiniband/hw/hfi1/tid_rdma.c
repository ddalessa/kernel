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

	return 0;
}
