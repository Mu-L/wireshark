/* packet-mesh-header.c
 * Routines for Mesh Header dissection
 * Javier Cardona <javier@cozybit.com>
 * Copyright 2007, Marvell Semiconductors Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_mesh(void);

/* Initialize the protocol and registered fields */
static int proto_mesh;
static int hf_mesh_ttl;
static int hf_mesh_e2eseq;

/* Initialize the subtree pointers */
static int ett_mesh;

/* Code to actually dissect the packets */
static int
dissect_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *mesh_tree;
  uint8_t mesh_ttl;
  uint16_t mesh_e2eseq;

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mesh");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_mesh, tvb, 0, 5, ENC_NA);
    mesh_tree = proto_item_add_subtree(ti, ett_mesh);

    /* add an item to the subtree, see section 1.6 for more information */
    mesh_ttl = tvb_get_uint8(tvb, 2);
    proto_tree_add_uint(mesh_tree, hf_mesh_ttl, tvb, 2, 1, mesh_ttl);

    mesh_e2eseq = tvb_get_ntohs(tvb, 3);
    proto_tree_add_uint(mesh_tree, hf_mesh_e2eseq, tvb, 3, 2, mesh_e2eseq);
  }

  /* Return the amount of data this dissector was able to dissect */
  return 5;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_mesh(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mesh_ttl,
      { "Mesh TTL", "mesh.ttl", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_mesh_e2eseq,
      { "Mesh End-to-end Seq", "mesh.e2eseq", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_mesh
  };

  /* Register the protocol name and description */
  proto_mesh = proto_register_protocol("Mesh Header", "Mesh", "mesh");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mesh, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("mesh", dissect_mesh, proto_mesh);
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
