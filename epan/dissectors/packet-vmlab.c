/* packet-vmlab.c
 * Routines for VMware Lab Manager Frame Dis-assembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* History
 *
 * Apr 4, 2010 - David Aggeler
 *
 * - Initial version based on packet-vlan.c
 *
 *   VMware Lab Manager is using this encapsulation directly as Ethernet Frames
 *   or inside VLANs. The Ethernet type was originally registered to Akimbi, but VMware
 *   acquired this company in 2006. No public information found, so the decoding here
 *   is an educated guess. Since one of the features of Lab Manager is to separate
 *   VMs with equal host name, IP and MAC Address, I expect the upper layer dissectors
 *   (namely ARP, ICMP, IP, TCP) to create false alerts, since identical configurations
 *   may communicate at the same time. The main goal of this dissector is to be able
 *   to troubleshoot connectivity, preferably pings. It's also a little to understand
 *   as to how host spanning fenced configurations actually talk.
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

void proto_register_vmlab(void);
void proto_reg_handoff_vmlab(void);

static dissector_handle_t vmlab_handle;
static dissector_handle_t ethertype_handle;

static int proto_vmlab;

static int hf_vmlab_flags_part1;           /* Unknown so far */
static int hf_vmlab_flags_fragment;
static int hf_vmlab_flags_part2;           /* Unknown so far */

static int hf_vmlab_portgroup;
static int hf_vmlab_eth_src;
static int hf_vmlab_eth_dst;
static int hf_vmlab_eth_addr;
static int hf_vmlab_etype;
static int hf_vmlab_trailer;

static int ett_vmlab;

static int
dissect_vmlab(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree*     vmlab_tree;
    proto_item*     ti;

    uint32_t        offset=0;

    uint8_t         attributes;
    uint8_t         portgroup;
    ethertype_data_t ethertype_data;

    uint16_t        encap_proto;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMLAB");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vmlab, tvb, 0, 24, ENC_NA);
    vmlab_tree = proto_item_add_subtree(ti, ett_vmlab);

    /* Flags*/
    attributes = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_part1,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_fragment, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vmlab_tree, hf_vmlab_flags_part2,    tvb, offset, 1, ENC_BIG_ENDIAN);
    if (attributes & 0x04) {
        proto_item_append_text(ti, ", Fragment");
    }
    offset += 1;

    /* Portgroup*/
    portgroup = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(vmlab_tree, hf_vmlab_portgroup, tvb, offset, 1, portgroup);
    proto_item_append_text(ti, ", Portgroup: %d", portgroup);
    offset += 1;

    /* The next two bytes were always 0x0000 as far as I could tell*/
    offset += 2;

    /* Not really clear, what the difference between this and the next MAC address is
       Both are usually equal*/
    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_addr, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_dst, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* Source MAC*/
    proto_tree_add_item(vmlab_tree, hf_vmlab_eth_src, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_item_append_text(ti, ", Src: %s, Dst: %s",
                           tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_ETHER, offset-6),
                           tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_ETHER, offset-12));

    /* Encapsulated Ethertype is also part of the block*/
    encap_proto = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(vmlab_tree, hf_vmlab_etype, tvb, offset, 2, encap_proto);
    offset += 2;

    /* Now call whatever was encapsulated*/
    ethertype_data.etype = encap_proto;
    ethertype_data.payload_offset = offset;
    ethertype_data.fh_tree = vmlab_tree;
    ethertype_data.trailer_id = hf_vmlab_trailer;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    return tvb_captured_length(tvb);
}

void
proto_register_vmlab(void)
{
    static hf_register_info hf[] = {

        { &hf_vmlab_flags_part1,    { "Unknown", "vmlab.unknown1",
            FT_UINT8, BASE_HEX,  NULL, 0xF8, NULL, HFILL }},
        { &hf_vmlab_flags_fragment, { "More Fragments", "vmlab.fragment",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        { &hf_vmlab_flags_part2,    { "Unknown", "vmlab.unknown2",
            FT_UINT8, BASE_HEX,  NULL, 0x03, NULL, HFILL }},

        { &hf_vmlab_portgroup,      { "Portgroup", "vmlab.pgrp",
            FT_UINT8, BASE_DEC,  NULL, 0, NULL, HFILL }},
        { &hf_vmlab_eth_src,        { "Source", "vmlab.src",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_eth_dst,        { "Destination", "vmlab.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_eth_addr,       { "Address", "vmlab.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vmlab_etype,          { "Encapsulated Type", "vmlab.subtype",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }},
        { &hf_vmlab_trailer,        { "Trailer", "vmlab.trailer",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };
    static int *ett[] = {
        &ett_vmlab
    };

    proto_vmlab = proto_register_protocol("VMware Lab Manager", "VMLAB", "vmlab");
    proto_register_field_array(proto_vmlab, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    vmlab_handle = register_dissector("vmlab", dissect_vmlab, proto_vmlab);
}

void
proto_reg_handoff_vmlab(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_VMLAB, vmlab_handle);

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_vmlab);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
