/* packet-ethercat-frame.c
 * Routines for ethercat packet disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

#include "packet-ethercat-frame.h"

void proto_register_ethercat_frame(void);
void proto_reg_handoff_ethercat_frame(void);

/* Define the Ethercat frame proto */
static int proto_ethercat_frame;

static dissector_table_t ethercat_frame_dissector_table;

static dissector_handle_t ethercat_frame_handle;

/* Define the tree for the EtherCAT frame */
static int ett_ethercat_frame;
static int hf_ethercat_frame_length;
static int hf_ethercat_frame_reserved;
static int hf_ethercat_frame_type;

static const value_string EthercatFrameTypes[] =
{
   { 1, "EtherCAT command", },
   { 2, "ADS", },
   { 3, "RAW-IO", },
   { 4, "NV", },
   { 5, "Mailbox"},
   { 0,  NULL }
};

static const value_string ethercat_frame_reserved_vals[] =
{
   { 0, "Valid"},
   { 1, "Invalid (must be zero for conformance with the protocol specification)"},
   { 0, NULL}
};

/* Ethercat Frame */
static int dissect_ethercat_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   tvbuff_t *next_tvb;
   proto_item *ti;
   proto_tree *ethercat_frame_tree;
   int offset = 0;
   EtherCATFrameParserHDR hdr;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECATF");

   col_clear(pinfo->cinfo, COL_INFO);

   if (tree)
   {
      ti = proto_tree_add_item(tree, proto_ethercat_frame, tvb, offset, EtherCATFrameParserHDR_Len, ENC_NA);
      ethercat_frame_tree = proto_item_add_subtree(ti, ett_ethercat_frame);

      proto_tree_add_item(ethercat_frame_tree, hf_ethercat_frame_length, tvb, offset, EtherCATFrameParserHDR_Len, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(ethercat_frame_tree, hf_ethercat_frame_reserved, tvb, offset, EtherCATFrameParserHDR_Len, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(ethercat_frame_tree, hf_ethercat_frame_type, tvb, offset, EtherCATFrameParserHDR_Len, ENC_LITTLE_ENDIAN);
   }
   hdr.hdr = tvb_get_letohs(tvb, offset);
   offset = EtherCATFrameParserHDR_Len;

   /* The EtherCAT frame header has now been processed, allow sub dissectors to
      handle the rest of the PDU. */
   next_tvb = tvb_new_subset_remaining (tvb, offset);

   if (!dissector_try_uint(ethercat_frame_dissector_table, hdr.v.protocol,
       next_tvb, pinfo, tree))
   {
      col_add_fstr (pinfo->cinfo, COL_PROTOCOL, "0x%04x", hdr.v.protocol);
      /* No sub dissector wanted to handle this payload, decode it as general
      data instead. */
      call_data_dissector(next_tvb, pinfo, tree);
   }
   return tvb_captured_length(tvb);
}

void proto_register_ethercat_frame(void)
{
   static hf_register_info hf[] =
      {
         { &hf_ethercat_frame_length,
           { "Length", "ecatf.length",
             FT_UINT16, BASE_HEX, NULL, 0x07FF,
             NULL, HFILL }
         },

         { &hf_ethercat_frame_reserved,
           { "Reserved", "ecatf.reserved",
             FT_UINT16, BASE_HEX, VALS(ethercat_frame_reserved_vals), 0x0800,
             NULL, HFILL}
         },

         { &hf_ethercat_frame_type,
           { "Type", "ecatf.type",
             FT_UINT16, BASE_HEX, VALS(EthercatFrameTypes), 0xF000,
             "E88A4 Types", HFILL }
         }
      };

   static int *ett[] =
      {
         &ett_ethercat_frame
      };

   proto_ethercat_frame = proto_register_protocol("EtherCAT frame header", "ETHERCAT", "ecatf");
   proto_register_field_array(proto_ethercat_frame,hf,array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   ethercat_frame_handle = register_dissector("ecatf", dissect_ethercat_frame, proto_ethercat_frame);

   /* Define a handle (ecatf.type) for sub dissectors that want to dissect
      the Ethercat frame ether type (E88A4) payload. */
   ethercat_frame_dissector_table = register_dissector_table("ecatf.type", "EtherCAT frame type",
                                                             proto_ethercat_frame, FT_UINT8, BASE_DEC);
}

void proto_reg_handoff_ethercat_frame(void)
{
   dissector_add_uint("ethertype", ETHERTYPE_ECATF, ethercat_frame_handle);
   dissector_add_uint_with_preference("udp.port", ETHERTYPE_ECATF, ethercat_frame_handle);
   dissector_add_uint_with_preference("tcp.port", ETHERTYPE_ECATF, ethercat_frame_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
