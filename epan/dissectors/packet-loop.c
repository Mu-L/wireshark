/* packet-loop.c
 * Routines for Ethernet loopback/Configuration Test Protocol dissection,
 * as documented in section 8 "Ethernet Configuration Testing Protocol" of
 * the v2.0 DIX Ethernet specification.
 *
 * See
 *
 *    http://decnet.ipv7.net/docs/dundas/aa-k759b-tk.pdf
 *
 * for a copy of the DIX spec and
 *
 *    http://stuff.mit.edu/people/jhawk/ctp.html
 *
 * for section 8.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_loop(void);
void proto_reg_handoff_loop(void);

static dissector_handle_t loop_handle;

static int proto_loop;
static int hf_loop_skipcount;
static int hf_loop_function;
static int hf_loop_relevant_function;
static int hf_loop_receipt_number;
static int hf_loop_forwarding_address;

static int ett_loop;

#define FUNC_REPLY              1
#define FUNC_FORWARD_DATA       2

static const value_string function_vals[] = {
  { FUNC_REPLY, "Reply" },
  { FUNC_FORWARD_DATA, "Forward Data" },
  { 0, NULL }
};

static int
dissect_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree  *loop_tree = NULL;
  proto_item  *ti;
  uint16_t    function;
  int         offset = 0;
  int         skip_offset;
  bool        set_info = true;
  bool        more_function;
  tvbuff_t    *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LOOP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_loop, tvb, offset, -1, ENC_NA);
    loop_tree = proto_item_add_subtree(ti, ett_loop);

    proto_tree_add_item(loop_tree, hf_loop_skipcount, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  }
  skip_offset = 2 + tvb_get_letohs(tvb, offset);
  offset += 2;

  do {
    function = tvb_get_letohs(tvb, offset);
    if (offset == skip_offset) {
      col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str(function, function_vals, "Unknown function (%u)"));

      ti = proto_tree_add_uint(loop_tree, hf_loop_relevant_function, tvb, offset, 2, function);
      proto_item_set_generated(ti);
      set_info = false;
    }
    proto_tree_add_uint(loop_tree, hf_loop_function, tvb, offset, 2, function);
    offset += 2;
    switch (function) {

    case FUNC_REPLY:
      proto_tree_add_item(loop_tree, hf_loop_receipt_number, tvb, offset, 2,
                            ENC_LITTLE_ENDIAN);
      offset += 2;
      more_function = false;
      break;

    case FUNC_FORWARD_DATA:
      proto_tree_add_item(loop_tree, hf_loop_forwarding_address, tvb, offset,
                            6, ENC_NA);
      offset += 6;
      more_function = true;
      break;

    default:
      more_function = false;
      break;
    }
  } while (more_function);

  if (set_info) {
    col_set_str(pinfo->cinfo, COL_INFO, "No valid function found");
  }

  if (tvb_reported_length_remaining(tvb, offset) > 0)
  {
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);
  }
  return tvb_captured_length(tvb);
}

void
proto_register_loop(void)
{
  static hf_register_info hf[] = {
    { &hf_loop_skipcount,
      { "skipCount",            "loop.skipcount",
    FT_UINT16,  BASE_DEC,       NULL,   0x0,
      NULL, HFILL }},

    { &hf_loop_function,
      { "Function",             "loop.function",
    FT_UINT16,  BASE_DEC,       VALS(function_vals),    0x0,
      NULL, HFILL }},

    { &hf_loop_relevant_function,
      { "Relevant function",            "loop.relevant_function",
    FT_UINT16,  BASE_DEC,       VALS(function_vals),    0x0,
      NULL, HFILL }},

    { &hf_loop_receipt_number,
      { "Receipt number",       "loop.receipt_number",
    FT_UINT16,  BASE_DEC,       NULL,   0x0,
      NULL, HFILL }},

    { &hf_loop_forwarding_address,
      { "Forwarding address",   "loop.forwarding_address",
    FT_ETHER,   BASE_NONE,      NULL,   0x0,
      NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_loop,
  };

  proto_loop = proto_register_protocol("Configuration Test Protocol (loopback)",
                                       "LOOP", "loop");
  proto_register_field_array(proto_loop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  loop_handle = register_dissector("loop", dissect_loop, proto_loop);
}

void
proto_reg_handoff_loop(void)
{
  dissector_add_uint("ethertype", ETHERTYPE_LOOP, loop_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
