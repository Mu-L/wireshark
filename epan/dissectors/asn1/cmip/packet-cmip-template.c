/* packet-cmip.c
 * Routines for X.711 CMIP packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>
#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-x509if.h"
#include "packet-cmip.h"

#define PNAME  "X711 CMIP"
#define PSNAME "CMIP"
#define PFNAME "cmip"

void proto_register_cmip(void);
void proto_reg_handoff_cmip(void);

/* XXX some stuff we need until we can get rid of it */
#include "packet-ses.h"
#include "packet-pres.h"

/* Initialize the protocol and registered fields */
static int proto_cmip;
static int hf_cmip_actionType_OID;
static int hf_cmip_eventType_OID;
static int hf_cmip_attributeId_OID;
static int hf_cmip_errorId_OID;

#include "packet-cmip-hf.c"

/* Initialize the subtree pointers */
static int ett_cmip;
#include "packet-cmip-ett.c"

static expert_field ei_wrong_spdu_type;

static uint32_t opcode;

static dissector_handle_t cmip_handle;

/* Dissector table */
static dissector_table_t attribute_id_dissector_table;

#include "packet-cmip-table.c"

static int opcode_type;
#define OPCODE_INVOKE        1
#define OPCODE_RETURN_RESULT 2
#define OPCODE_RETURN_ERROR  3
#define OPCODE_REJECT        4

static const char *object_identifier_id;

#include "packet-cmip-val.h"
#include "packet-cmip-fn.c"




/* XXX this one should be broken out later and moved into the conformance file */
static int
dissect_cmip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	struct SESSION_DATA_STRUCTURE* session;
	proto_item *item;
	proto_tree *tree;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	session = (struct SESSION_DATA_STRUCTURE*)data;

	if(session->spdu_type == 0 ) {
		proto_tree_add_expert_format(parent_tree, pinfo, &ei_wrong_spdu_type, tvb, 0, -1,
			"Internal error: wrong spdu type %x from session dissector.", session->spdu_type);
		return 0;
	}

	asn1_ctx.private_data = session;

	item = proto_tree_add_item(parent_tree, proto_cmip, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_cmip);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMIP");
  	col_clear(pinfo->cinfo, COL_INFO);
	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
		case SES_DISCONNECT:
		case SES_FINISH:
		case SES_REFUSE:
			dissect_cmip_CMIPUserInfo(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_ABORT:
			dissect_cmip_CMIPAbortInfo(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_DATA_TRANSFER:
			dissect_cmip_ROS(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		default:
			;
	}

	return tvb_captured_length(tvb);
}

/*--- proto_register_cmip ----------------------------------------------*/
void proto_register_cmip(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmip_actionType_OID,
      { "actionType", "cmip.actionType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventType_OID,
      { "eventType", "cmip.eventType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeId_OID,
      { "attributeId", "cmip.attributeId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_errorId_OID,
      { "errorId", "cmip.errorId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

#include "packet-cmip-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_cmip,
#include "packet-cmip-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_wrong_spdu_type, { "cmip.wrong_spdu_type", PI_PROTOCOL, PI_ERROR, "Internal error: wrong spdu type", EXPFILL }},
  };

  expert_module_t* expert_cmip;

  /* Register protocol */
  proto_cmip = proto_register_protocol(PNAME, PSNAME, PFNAME);
  cmip_handle = register_dissector("cmip", dissect_cmip, proto_cmip);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_cmip = expert_register_protocol(proto_cmip);
  expert_register_field_array(expert_cmip, ei, array_length(ei));

#include "packet-cmip-dis-tab.c"

  attribute_id_dissector_table = register_dissector_table("cmip.attribute_id", "CMIP Attribute Id", proto_cmip, FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_cmip -------------------------------------------*/
void proto_reg_handoff_cmip(void) {
	register_ber_oid_dissector_handle("2.9.0.0.2", cmip_handle, proto_cmip, "cmip");
	register_ber_oid_dissector_handle("2.9.1.1.4", cmip_handle, proto_cmip, "joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

	oid_add_from_string("managedObjectClass(3) alarmRecord(1)", "2.9.3.2.3.1");
	oid_add_from_string("managedObjectClass(3) attributeValueChangeRecord(2)", "2.9.3.2.3.2");
	oid_add_from_string("managedObjectClass(3) discriminator(3)", "2.9.3.2.3.3");
	oid_add_from_string("managedObjectClass(3) eventForwardingDiscriminator(4)", "2.9.3.2.3.4");
	oid_add_from_string("managedObjectClass(3) eventLogRecord(5)", "2.9.3.2.3.5");
	oid_add_from_string("managedObjectClass(3) log(6)", "2.9.3.2.3.6");
	oid_add_from_string("managedObjectClass(3) logRecord(7)", "2.9.3.2.3.7");
	oid_add_from_string("managedObjectClass(3) objectCreationRecord(8)", "2.9.3.2.3.8");
	oid_add_from_string("managedObjectClass(3) objectDeletionRecord(9)", "2.9.3.2.3.9");
	oid_add_from_string("managedObjectClass(3) relationshipChangeRecord(10)", "2.9.3.2.3.10");
	oid_add_from_string("managedObjectClass(3) securityAlarmReportRecord(11)", "2.9.3.2.3.11");
	oid_add_from_string("managedObjectClass(3) stateChangeRecord(12)", "2.9.3.2.3.12");
	oid_add_from_string("managedObjectClass(3) system(13)", "2.9.3.2.3.13");
	oid_add_from_string("managedObjectClass(3) top(14)", "2.9.3.2.3.14");
	oid_add_from_string("administrativeStatePackage(14)", "2.9.3.2.4.14");

/*#include "packet-cmip-dis-tab.c" */
}

