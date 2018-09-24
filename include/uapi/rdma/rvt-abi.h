/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */

/*
 * Copyright(c) 2015 - 2018 Intel Corporation.
 */

/*
 * This file contains defines, structures, etc. that are used
 * to communicate between kernel and user code.
 */

#ifndef RVT_ABI_USER_H
#define RVT_ABI_USER_H

#include <linux/types.h>
#ifndef RDMA_ATOMIC_UAPI
#define RDMA_ATOMIC_UAPI(_type, _name) _type _name
#endif
/*
 * This structure is used to contain the head pointer, tail pointer,
 * and completion queue entries as a single memory allocation so
 * it can be mmap'ed into user space.
 */
struct rvt_cq_wc {
	/* index of next entry to fill */
	RDMA_ATOMIC_UAPI(u32, head);
	/* index of next ib_poll_cq() entry */
	RDMA_ATOMIC_UAPI(u32, tail);

	/* these are actually size ibcq.cqe + 1 */
	struct ib_uverbs_wc uqueue[0];
};

#endif /* RVT_ABI_USER_H */
