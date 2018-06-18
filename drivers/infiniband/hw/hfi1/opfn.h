/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
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
#ifndef _HFI1_OPFN_H
#define _HFI1_OPFN_H

/**
 * DOC: Omni Path Feature Negotion (OPFN)
 *
 * OPFN is a discovery protocol for Intel Omni-Path fabric that
 * allows two RC QPs to negotiate a common feature that both QPs
 * can support. Currently, the only OPA feature that OPFN
 * supports is TID RDMA.
 *
 * Architecture
 *
 * OPFN involves the communication between two QPs on the HFI
 * level on an Omni-Path fabric, and ULPs have no knowledge of
 * OPFN at all.
 *
 * Implementation
 *
 * OPFN extends the existing IB RC protocol with the following
 * changes:
 * -- Uses Bit 24 (reserved) of DWORD 1 of Base Transport
 *    Header (BTH1) to indicate that the RC QP supports OPFN;
 * -- Uses a combination of RC COMPARE_SWAP opcode (0x13) and
 *    the address U64_MAX (0xFFFFFFFFFFFFFFFF) as an OPFN
 *    request; The 64-bit data carried with the request/response
 *    contains the parameters for negotiation and will be
 *    defined in tid_rdma.c file;
 * -- Defines IB_WR_RESERVED3 as IB_WR_OPFN.
 *
 * The OPFN communication will be triggered when an RC QP
 * receives a request with Bit 24 of BTH1 set. The responder QP
 * will then post send an OPFN request with its local
 * parameters, which will be sent to the requester QP once all
 * existing requests on the responder QP side have been sent.
 * Once the requester QP receives the OPFN request, it will
 * keep a copy of the responder QP's parameters, and return a
 * response packet with its own local parameters. The responder
 * QP receives the response packet and keeps a copy of the requester
 * QP's parameters. After this exchange, each side has the parameters
 * for both sides and therefore can select the right parameters
 * for future transactions
 */

/* STL Verbs Extended */
#define IB_BTHE_E_SHIFT           24

struct hfi1_opfn_data {
	bool extended;
};

#endif /* _HFI1_OPFN_H */
