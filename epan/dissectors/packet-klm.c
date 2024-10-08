/* packet-klm.c    2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for klm dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-nfs.h"

void proto_register_klm(void);
void proto_reg_handoff_klm(void);

static int proto_klm;
static int hf_klm_procedure_v1;
static int hf_klm_exclusive;
static int hf_klm_lock;
static int hf_klm_servername;
static int hf_klm_pid;
static int hf_klm_offset;
static int hf_klm_len;
static int hf_klm_stats;
static int hf_klm_holder;
static int hf_klm_block;

static int ett_klm;
static int ett_klm_lock;
static int ett_klm_holder;

#define KLMPROC_TEST   1
#define KLMPROC_LOCK   2
#define KLMPROC_CANCEL 3
#define KLMPROC_UNLOCK 4

#define KLM_PROGRAM 100020

static const value_string names_klm_stats[] =
{
#define KLM_GRANTED		0
		{	KLM_GRANTED,	"KLM_GRANTED"	},
#define KLM_DENIED		1
		{	KLM_DENIED,	"KLM_DENIED"	},
#define KLM_DENIED_NOLOCKS	2
		{	KLM_DENIED_NOLOCKS,	"KLM_DENIED_NOLOCKS"	},
#define KLM_WORKING		3
		{	KLM_WORKING,	"KLM_WORKING"	},
		{	0,		NULL }
};

static int
dissect_holder(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;

	lock_item = proto_tree_add_item(tree, hf_klm_holder, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_klm_holder);

	offset = dissect_rpc_bool( tvb, lock_tree,
			hf_klm_exclusive, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_pid, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_offset, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_len, offset);

	return offset;
}

static int
dissect_lock(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset, rpc_call_info_value *civ)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;

	lock_item = proto_tree_add_item(tree, hf_klm_lock, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_klm_lock);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_klm_servername, offset, NULL);

	offset = dissect_nfs3_fh(tvb, offset, pinfo, lock_tree,"fh", NULL, civ);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_pid, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_offset, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_klm_len, offset);

	return offset;
}

static int
dissect_klm_unlock_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	return dissect_lock(tvb, pinfo, tree, 0, (rpc_call_info_value*)data);
}

static int
dissect_klm_stat_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return dissect_rpc_uint32(tvb, tree, hf_klm_stats, 0);
}

static int
dissect_klm_lock_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	offset = dissect_rpc_bool( tvb, tree,
			hf_klm_block, offset);

	offset = dissect_rpc_bool( tvb, tree,
			hf_klm_exclusive, offset);

	offset = dissect_lock(tvb, pinfo, tree, offset, (rpc_call_info_value*)data);

	return offset;
}

static int
dissect_klm_test_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int32_t	stats;
	int offset = 0;

	stats = tvb_get_ntohl(tvb, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_klm_stats, offset);

	if (stats == KLM_DENIED) {
		offset = dissect_holder(tvb, tree, offset);
	}

	return offset;
}

static int
dissect_klm_test_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	offset = dissect_rpc_bool( tvb, tree,
			hf_klm_exclusive, offset);

	offset = dissect_lock(tvb, pinfo, tree, offset, (rpc_call_info_value*)data);

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
static const vsff klm1_proc[] = {
	{ KLMPROC_TEST,	"TEST",
		dissect_klm_test_call,	dissect_klm_test_reply },
	{ KLMPROC_LOCK,	"LOCK",
		dissect_klm_lock_call,	dissect_klm_stat_reply },
	{ KLMPROC_CANCEL,	"CANCEL",
		dissect_klm_lock_call,	dissect_klm_stat_reply },
	{ KLMPROC_UNLOCK,	"UNLOCK",
		dissect_klm_unlock_call,	dissect_klm_stat_reply },
	{ 0,	NULL,		NULL,				NULL }
};
static const rpc_prog_vers_info klm_vers_info[] = {
	{ 1, klm1_proc, &hf_klm_procedure_v1 },
};
static const value_string klm1_proc_vals[] = {
	{ KLMPROC_TEST,	  "TEST" },
	{ KLMPROC_LOCK,	  "LOCK" },
	{ KLMPROC_CANCEL, "CANCEL" },
	{ KLMPROC_UNLOCK, "UNLOCK" },
	{ 0,	NULL}
};

void
proto_register_klm(void)
{
	static struct true_false_string tfs_exclusive = { "Exclusive", "Not exclusive" };
	static struct true_false_string tfs_block = { "Block", "Do not block" };

	static hf_register_info hf[] = {
		{ &hf_klm_procedure_v1, {
			"V1 Procedure", "klm.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(klm1_proc_vals), 0, NULL, HFILL }},
		{ &hf_klm_exclusive, {
			"exclusive", "klm.exclusive", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_exclusive), 0x0, "Exclusive lock", HFILL }},

		{ &hf_klm_lock, {
			"lock", "klm.lock", FT_NONE, BASE_NONE,
			NULL, 0, "KLM lock structure", HFILL }},

		{ &hf_klm_servername, {
			"server name", "klm.servername", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_klm_pid, {
			"pid", "klm.pid", FT_UINT32, BASE_DEC,
			NULL, 0, "ProcessID", HFILL }},

		{ &hf_klm_offset, {
			"offset", "klm.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "File offset", HFILL }},

		{ &hf_klm_len, {
			"length", "klm.len", FT_UINT32, BASE_DEC,
			NULL, 0, "Length of lock region", HFILL }},

		{ &hf_klm_stats, {
			"stats", "klm.stats", FT_UINT32, BASE_DEC,
			VALS(names_klm_stats), 0, NULL, HFILL }},

		{ &hf_klm_holder, {
			"holder", "klm.holder", FT_NONE, BASE_NONE,
			NULL, 0, "KLM lock holder", HFILL }},

		{ &hf_klm_block, {
			"block", "klm.block", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_block), 0x0, NULL, HFILL }},

	};

	static int *ett[] = {
		&ett_klm,
		&ett_klm_lock,
		&ett_klm_holder,
	};

	proto_klm = proto_register_protocol("Kernel Lock Manager",
	    "KLM", "klm");
	proto_register_field_array(proto_klm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_klm(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_klm, KLM_PROGRAM, ett_klm,
	    G_N_ELEMENTS(klm_vers_info), klm_vers_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
