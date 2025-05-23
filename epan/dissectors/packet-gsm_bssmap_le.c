/* packet-gsm_bssmap_le.c
 * Routines for GSM Lb Interface BSSMAP dissection
 *
 * Copyright 2008, Johnny Mitrevski <mitrevj@hotmail.com>
 *
 * 3GPP TS 49.031 version v7.4.0 (2009-09)
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
#include <epan/tap.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-bssap.h"
#include "packet-gsm_a_common.h"

void proto_register_gsm_bssmap_le(void);
void proto_reg_handoff_gsm_bssmap_le(void);

/* PROTOTYPES/FORWARDS */

/* Message Type definitions */
#define BSSMAP_LE_PERFORM_LOCATION_REQUEST              43
#define BSSMAP_LE_PERFORM_LOCATION_RESPONSE             45
#define BSSMAP_LE_PERFORM_LOCATION_ABORT                46
#define BSSMAP_LE_PERFORM_LOCATION_INFORMATION          47
#define BSSMAP_LE_CONNECTION_ORIENTED_INFORMATION       42
#define BSSMAP_LE_CONNECTIONLESS_INFORMATION            58
#define BSSMAP_LE_RESET                                 48
#define BSSMAP_LE_RESET_ACKNOWLEDGE                     49

static const value_string gsm_bssmap_le_msg_strings[] = {
	{ 0, "Reserved" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ BSSMAP_LE_PERFORM_LOCATION_REQUEST,	     "Perform Location Request" },
	{ BSSMAP_LE_PERFORM_LOCATION_RESPONSE,	     "Perform Location Response" },
	{ BSSMAP_LE_PERFORM_LOCATION_ABORT,	     "Perform Location Abort" },
	{ BSSMAP_LE_PERFORM_LOCATION_INFORMATION,    "Perform Location Information" },
	{ BSSMAP_LE_CONNECTION_ORIENTED_INFORMATION, "Connection Oriented Information" },
	{ BSSMAP_LE_CONNECTIONLESS_INFORMATION,	     "Connectionless Information" },
	{ BSSMAP_LE_RESET,			     "Reset" },
	{ BSSMAP_LE_RESET_ACKNOWLEDGE,		     "Reset Acknowledge" },
	{ 0, NULL }
};

/* Information Element definitions */
#define BSSMAP_LE_LCS_QOS                                    62
#define BSSMAP_LE_LCS_PRIORITY                               67
#define BSSMAP_LE_LOCATION_TYPE                              68
#define BSSMAP_LE_GANSS_LOCATION_TYPE                        130
#define BSSMAP_LE_GEOGRAPHIC_LOCATION                        69
#define BSSMAP_LE_POSITIONING_DATA                           70
#define BSSMAP_LE_GANSS_POSITIONING_DATA                     131
#define BSSMAP_LE_VELOCITY_DATA                              85
#define BSSMAP_LE_LCS_CAUSE                                  71
#define BSSMAP_LE_LCS_CLIENT_TYPE                            72
#define BSSMAP_LE_APDU                                       73
#define BSSMAP_LE_NETWORK_ELEMENT_IDENTITY                   74
#define BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA              75
#define BSSMAP_LE_REQUESTED_GANSS_ASSISTANCE_DATA            65
#define BSSMAP_LE_DECIPHERING_KEYS                           76
#define BSSMAP_LE_RETURN_ERROR_REQUEST                       77
#define BSSMAP_LE_RETURN_ERROR_CAUSE                         78
#define BSSMAP_LE_SEGMENTATION                               79
#define BSSMAP_LE_CLASSMARK_INFORMATION_TYPE_3               19
#define BSSMAP_LE_CAUSE                                      4
#define BSSMAP_LE_CELL_IDENTIFIER                            5
#define BSSMAP_LE_CHOSEN_CHANNEL                             33
#define BSSMAP_LE_IMSI                                       0
#define BSSMAP_LE_RESERVED_NOTE1                             1
#define BSSMAP_LE_RESERVED_NOTE2                             2
#define BSSMAP_LE_RESERVED_NOTE3                             3
#define BSSMAP_LE_LCS_CAPABILITY                             80
#define BSSMAP_LE_PACKET_MEASUREMENT_REPORT                  81
#define BSSMAP_LE_CELL_IDENTITY_LIST                         82
#define BSSMAP_LE_IMEI                                       128

static const value_string gsm_bssmap_le_elem_strings[] = {
	{ DE_BMAPLE_LCSQOS,		"LCS QoS" },
	{ DE_BMAPLE_LCS_PRIO,		"LCS Priority" },
	{ DE_BMAPLE_LOC_TYPE,		"Location Type" },
	{ DE_BMAPLE_GANSS_LOC_TYPE,	"GANSS Location Type" },
	{ DE_BMAPLE_GEO_LOC,		"Geographic Location" },
	{ DE_BMAPLE_POS_DATA,		"Positioning Data" },
	{ DE_BMAPLE_GANSS_POS_DATA,	"GANSS Positioning Data" },
	{ DE_BMAPLE_VELOC_DATA,		"Velocity Data" },
	{ DE_BMAPLE_LCS_CAUSE,		"LCS Cause" },
	{ DE_BMAPLE_LCS_CLIENT_TYPE,	"LCS Client Type" },
	{ DE_BMAPLE_APDU,		"APDU" },
	{ DE_BMAPLE_NETWORK_ELEM_ID,	"Network Element Identity" },
	{ DE_BMAPLE_REQ_GPS_ASSIST_D,	"Requested GPS Assistance Data" },
	{ DE_BMAPLE_REQ_GNSS_ASSIST_D,	"Requested GANSS Assistance Data" },
	{ DE_BMAPLE_DECIPH_KEYS,	"Deciphering Keys" },
	{ DE_BMAPLE_RETURN_ERROR_REQ,	"Return Error Request" },
	{ DE_BMAPLE_RETURN_ERROR_CAUSE, "Return Error Cause" },
	{ DE_BMAPLE_SEGMENTATION,	"Segmentation" },
	{ DE_BMAPLE_CLASSMARK_TYPE_3,	"Classmark Information Type 3" },
	{ DE_BMAPLE_CAUSE,		"Cause" },
	{ DE_BMAPLE_CELL_IDENTIFIER,	"Cell Identifier" },
	{ DE_BMAPLE_CHOSEN_CHANNEL,	"Chosen Channel" },
	{ DE_BMAPLE_IMSI,		"IMSI" },
	{ DE_BMAPLE_RES1,		"Reserved" },
	{ DE_BMAPLE_RES2,		"Reserved" },
	{ DE_BMAPLE_RES3,		"Reserved" },
	{ DE_BMAPLE_LCS_CAPABILITY,	"LCS Capability" },
	{ DE_BMAPLE_PACKET_MEAS_REP,	"Packet Measurement Report" },
	{ DE_BMAPLE_MEAS_CELL_ID,	"Cell Identity List" },
	{ DE_BMAPLE_IMEI,		"IMEI" },
	{ 0, NULL }
};
value_string_ext gsm_bssmap_le_elem_strings_ext = VALUE_STRING_EXT_INIT(gsm_bssmap_le_elem_strings);

static const value_string gsm_apdu_protocol_id_strings[] = {
	{ 0,	"reserved" },
	{ 1,	"BSSLAP" },
	{ 2,	"LLP" },
	{ 3,	"SMLCPP" },
	{ 0, NULL },
};

/* Velocity Requested definitions */
static const value_string bssmap_le_velocity_requested_vals[] = {
	{ 0, "do not report velocity" },
	{ 1, "report velocity if available" },
	{ 0, NULL}
};

/* Vertical Coordinate definitions */
static const value_string bssmap_le_vertical_coordinate_indicator_vals[] = {
	{ 0, "vertical coordinate not requested" },
	{ 1, "vertical coordinate is requested" },
	{ 0, NULL}
};

/* Horizontal Accuracy definitions */
static const value_string bssmap_le_horizontal_accuracy_indicator_vals[] = {
	{ 0, "horizontal accuracy is not specified" },
	{ 1, "horizontal accuracy is specified" },
	{ 0, NULL}
};

/* Vertical Accuracy definitions */
static const value_string bssmap_le_vertical_accuracy_indicator_vals[] = {
	{ 0, "vertical accuracy is not specified" },
	{ 1, "vertical accuracy is specified" },
	{ 0, NULL}
};

/* Response Time definitions */
static const value_string bssmap_le_response_time_definitions_vals[] = {
	{ 0, "Response Time is not specified" },
	{ 1, "Low Delay" },
	{ 2, "Delay Tolerant" },
	{ 3, "reserved" },
	{ 0, NULL}
};

static const value_string bssmap_le_loc_inf_vals[] = {
	{ 0, "Current Geographic Location" },
	{ 1, "Location Assistance Information for the target MS" },
	{ 2, "Deciphering keys for broadcast assistance data for the target MS" },
	{ 0, NULL }
};

static const value_string bssmap_le_pos_method_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Mobile Assisted E-OTD" },
	{ 2, "Mobile Based E-OTD" },
	{ 3, "Assisted GPS" },
	{ 4, "Assisted GANSS" },
	{ 5, "Assisted GPS and Assisted GANSS" },
	{ 0, NULL }
};

static const value_string bssmap_le_pos_data_pos_method_vals[] = {
    { 0, "Timing Advance" },
    { 1, "Reserved" },
    { 2, "Reserved" },
    { 3, "Mobile Assisted E - OTD" },
    { 4, "Mobile Based E - OTD" },
    { 5, "Mobile Assisted GPS" },
    { 6, "Mobile Based GPS" },
    { 7, "Conventional GPS" },
    { 8, "U - TDOA" },
    { 9, "Reserved for UTRAN use only" },
    { 0xa, "Reserved for UTRAN use only" },
    { 0xb, "Reserved for UTRAN use only" },
    { 0xc, "Cell ID" },
    { 0, NULL }
};

static const value_string bssmap_le_pos_data_usage_vals[] = {
    { 0, "Attempted unsuccessfully due to failure or interruption" },
    { 1, "Attempted successfully : results not used to generate location" },
    { 2, "Attempted successfully : results used to verify but not generate location" },
    { 3, "Attempted successfully : results used to generate location" },
    { 4, "Attempted successfully : method or methods used by the MS cannot be determined" },
    { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_bssmap_le;
int hf_gsm_bssmap_le_elem_id;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_bssmap_le()
*/
static int hf_gsm_bssmap_le_msg_type;
static int hf_gsm_bssmap_le_apdu_protocol_id;
static int hf_gsm_bssmap_le_spare;
static int hf_gsm_bssmap_le_ciphering_key_flag;
static int hf_gsm_bssmap_le_current_deciphering_key_value;
static int hf_gsm_bssmap_le_next_deciphering_key_value;
static int hf_gsm_bssmap_le_acq_ass;
static int hf_gsm_bssmap_le_ref_time;
static int hf_gsm_bssmap_le_ref_loc;
static int hf_gsm_bssmap_le_dgps_corr;
static int hf_gsm_bssmap_le_nav_mod;
static int hf_gsm_bssmap_le_iono_mod;
static int hf_gsm_bssmap_le_utc_mod;
static int hf_gsm_bssmap_le_almanac;
static int hf_gsm_bssmap_le_ephemeris_ext_chk;
static int hf_gsm_bssmap_le_ephemeris_ext;
static int hf_gsm_bssmap_le_real_time_int;
static int hf_gsm_bssmap_le_lcs_cause_value;
static int hf_gsm_bssmap_le_diagnostic_value;
static int hf_gsm_bssmap_le_client_category;
static int hf_gsm_bssmap_le_client_subtype;
static int hf_gsm_bssmap_le_velocity_requested;
static int hf_gsm_bssmap_le_vertical_coordinate_indicator;
static int hf_gsm_bssmap_le_horizontal_accuracy_indicator;
static int hf_gsm_bssmap_le_horizontal_accuracy;
static int hf_gsm_bssmap_le_vertical_accuracy_indicator;
static int hf_gsm_bssmap_le_vertical_accuracy;
static int hf_gsm_bssmap_le_response_time_category;
static int hf_gsm_bssmap_le_apdu;
static int hf_gsm_bssmap_le_message_elements;
static int hf_gsm_bssmap_le_location_inf;
static int hf_gsm_bssmap_le_pos_method;
static int hf_gsm_bssmap_le_pos_data_disc;
static int hf_gsm_bssmap_le_pos_data_pos_method;
static int hf_gsm_bssmap_le_pos_data_usage;


/* Initialize the subtree pointers */
static int ett_bssmap_le_msg;

static expert_field ei_gsm_a_bssmap_le_not_decoded_yet;
static expert_field ei_gsm_a_bssmap_le_extraneous_data;
static expert_field ei_gsm_a_bssmap_le_missing_mandatory_element;

static dissector_handle_t gsm_bsslap_handle;
static dissector_handle_t bssmap_le_handle;

static proto_tree *g_tree;

#define	NUM_GSM_BSSMAP_LE_ELEM array_length(gsm_bssmap_le_elem_strings)
int ett_gsm_bssmap_le_elem[NUM_GSM_BSSMAP_LE_ELEM];

/*
 * 10.3 APDU
 */

static uint16_t
de_bmaple_apdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset;
	uint8_t   apdu_protocol_id;
	tvbuff_t *APDU_tvb;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_bssmap_le_apdu, tvb, curr_offset, len, ENC_NA);

	/*
	 * dissect the embedded APDU message
	 * if someone writes a TS 09.31 dissector
	 *
	 * The APDU octets 4 to n are coded in the same way as the
	 * equivalent octet in the APDU element of 3GPP TS 49.031 BSSAP-LE.
	 */

	apdu_protocol_id = tvb_get_uint8(tvb,curr_offset);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_apdu_protocol_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	switch(apdu_protocol_id){
	case 1:
		/* BSSLAP
		 * the embedded message is as defined in 3GPP TS 08.71(3GPP TS 48.071 version 7.2.0 Release 7)
		 */
		APDU_tvb = tvb_new_subset_length(tvb, curr_offset+1, len-1);
		if(gsm_bsslap_handle)
			call_dissector(gsm_bsslap_handle, APDU_tvb, pinfo, g_tree);
		break;
	case 2:
		/* LLP
		 * The embedded message contains a Facility Information Element as defined in 3GPP TS 04.71
		 * excluding the Facility IEI and length of Facility IEI octets defined in 3GPP TS 04.71.(3GPP TS 44.071).
		 */
		break;
	case 3:
		/* SMLCPP
		 * The embedded message is as defined in 3GPP TS 08.31(TS 48.031).
		 */
		break;
	default:
		break;
	}

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);

	return curr_offset - offset;
}
/*
 * 10.4 Cause
 * coded as the value part of the Cause IE defined in 3GPP TS 48.008
 */
/*
 * 10.5 Cell Identifier
 * coded as the value part of the Cell Identifier IE defined in 3GPP TS 48.008
 */
/*
 * 10.6 Chosen Channel
 * coded as the value part of the Chosen Channel IE defined in 3GPP TS 48.008
 */
/*
 * 10.7 Classmark Information Type 3
 * coded as the value part of the Classmark Information Type 3 IE defined in 3GPP TS 48.008
 */
/*
 * 10.8 Deciphering Keys
 */
static uint16_t
de_bmaple_decihp_keys(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	int bit_offset;

	/* Spare bits */
	bit_offset = (offset<<3);
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
	bit_offset += 7;

	/* Extract the Ciphering Key Flag and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_ciphering_key_flag, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	/*offset++;*/

	/* Extract the Current Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_current_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	bit_offset += 56;
	/*offset += 7;*/

	/* Extract the Next Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_next_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	/*offset += 7;*/

	return len;
}
/*
 * 10.9 Geographic Location
 * contains an octet sequence identical to that for Geographical Information
 * defined in 3GPP TS 23.032..
 */
/*
 * 10.10 Requested GPS Assistance Data
 */
static uint16_t
de_bmaple_req_gps_ass_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* Octet 3 H G F E D C B A */
	/* bit H Acquisition Assistance */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_acq_ass, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit G Reference Time */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ref_time, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit F Reference Location */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ref_loc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit E DGPS Corrections */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_dgps_corr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit D Navigation Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_nav_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit C Ionospheric Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_iono_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit B UTC Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_utc_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit A Almanac */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_almanac, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* Octet 4 P O N M L K J I
	 * bits L through P are Spare bits
	 */
	/* bit K Ephemeris Extension Check */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ephemeris_ext_chk, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit J Ephemeris Extension */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ephemeris_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit I Real-Time Integrity */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_real_time_int, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* Octet 5 to Octet 8+2n Satellite related data */
	proto_tree_add_expert_format(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, curr_offset, len-2, "Satellite related data Not decoded yet");
	return len;
}
/*
 * 10.11 IMSI
 * coded as the value part of the Mobile Identity IE defined in 3GPP TS 24.008 (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall
 * be ignored by the receiver
 */
/*
 * 10.12 (void)
 */
/*
 * 10.13 LCS Cause
 */
static const value_string bssmap_le_lcs_cause_values[] = {
	{ 0, "Unspecified" },
	{ 1, "System Failure" },
	{ 2, "Protocol Error" },
	{ 3, "Data missing in position request" },
	{ 4, "Unexpected data value in position request" },
	{ 5, "Position method failure" },
	{ 6, "Target MS Unreachable" },
	{ 7, "Location request aborted" },
	{ 8, "Facility not supported" },
	{ 9, "Inter-BSC Handover Ongoing" },
	{ 10, "Intra-BSC Handover Complete" },
	{ 11, "Congestion" },
	{ 12, "Inter NSE cell change" },
	{ 13, "Routing Area Update" },
	{ 14, "PTMSI reallocation" },
	{ 15, "Suspension of GPRS services" },
	{ 0, NULL}
};

static const value_string bssmap_le_position_method_failure_diagnostic_vals[] = {
	{ 0, "Congestion" },
	{ 1, "insufficientResources" },
	{ 2, "insufficientMeasurementData" },
	{ 3, "inconsistentMeasurementData" },
	{ 4, "locationProcedureNotCompleted" },
	{ 5, "locationProcedureNotSupportedByTargetMS" },
	{ 6, "qoSNotAttainable" },
	{ 7, "positionMethodNotAvailableInNetwork" },
	{ 8, "positionMethodNotAvailableInLocationArea" },
	{ 0, NULL}
};
static uint16_t
de_bmaple_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* cause value  */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_lcs_cause_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	if (len == 2)
	{
		/* Diagnostic value (note) */
		proto_tree_add_item(tree, hf_gsm_bssmap_le_diagnostic_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
	}

	return curr_offset - offset;
}
/*
 * 10.14 LCS Client Type
 */
/* Client Category definitions */
static const value_string bssmap_le_client_category[] = {
	{ 0, "Value Added Client" },
	{ 2, "PLMN Operator" },
	{ 3, "Emergency Services"},
	{ 4, "Lawful Intercept Services"},
	{ 0, NULL}
};

/* Client Subtype definitions */
static const value_string bssmap_le_client_subtype[] = {
	{ 0, "unspecified" },
	{ 1, "broadcast service" },
	{ 2, "O&M" },
	{ 3, "anonymous statistics" },
	{ 4, "Target MS service support" },
	{ 0, NULL}
};

static uint16_t
de_bmaple_client(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint8_t bitCount;

	bitCount = offset<<3;
	curr_offset = offset;

	/* Extract the client category and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_category, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	bitCount = bitCount + 4;

	/* Extract the client subtype and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_subtype, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	/*bitCount = bitCount + 4;*/
	curr_offset++;

	return curr_offset - offset;
}
/*
 * 10.15 LCS Priority
 * coded as the LCS-Priority octet in 3GPP TS 29.002
 */
/*
 * 10.16 LCS QoS
 */
static uint16_t
de_bmaple_lcs_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint64_t verticalCoordIndicator, velocityRequested, horizontalAccuracyIndicator, verticalAccuracyIndicator;
	uint16_t bitCount;

	bitCount = offset << 3;

	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 6, ENC_BIG_ENDIAN);
	bitCount = bitCount + 6;

	/* Extract Velocity requested element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_velocity_requested, tvb, bitCount, 1, &velocityRequested, ENC_BIG_ENDIAN);
	bitCount++;

	/* Extract vertical coordinator element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_vertical_coordinate_indicator, tvb, bitCount, 1, &verticalCoordIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	/* Extract horizontal accuracy element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_horizontal_accuracy_indicator, tvb, bitCount, 1, &horizontalAccuracyIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	if(horizontalAccuracyIndicator == 1)
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_horizontal_accuracy, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}
	else
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}

	/* Extract vertical accuracy element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_vertical_accuracy_indicator, tvb, bitCount, 1, &verticalAccuracyIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	if(verticalAccuracyIndicator == 1)
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_vertical_accuracy, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}
	else
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}

	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_response_time_category, tvb, bitCount, 2, ENC_BIG_ENDIAN);
	/*bitCount = bitCount + 2;*/

	return len;
}
/*
 * 10.17 (void)
 */
/*
 * 10.18 Location Type
 */
static uint16_t
de_bmaple_location_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* Location information (octet 3)  */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_location_inf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	if (len == 1) {
		return len;
	}
	/* Positioning Method (octet 4) */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_method, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return curr_offset - offset;
}
/*
 * 10.19 Network Element Identity
 */
/*
 * 10.20 Positioning Data
 */
static uint16_t
de_bmaple_pos_dta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset, value;

	curr_offset = offset;

	/* Octet 3	spare	Positioning Data Discriminator*/
	proto_tree_add_item_ret_uint(tree, hf_gsm_bssmap_le_pos_data_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &value);
	curr_offset++;

	if (value != 0) {
		return len;
	}
	/* 0000	indicate usage of each positioning method that was attempted either successfully or unsuccessfully;
	 * 1 octet of data is provided for each positioning method included
	 */
	while (curr_offset < (offset +len)) {
		/* Octet x	positioning method	usage*/
		proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_data_pos_method, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_data_usage, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
	}

	return len;
}
/*
 * 10.21 Return Error Request
 */
/*
 * 10.22 Return Error Cause
 */
/*
 * 10.23 (void)
 */
/*
 * 10.24 Segmentation
 */
/*
 * 10.25 (void)
 */
/*
 * 10.26 LCS Capability
 * coded as the value part of the LCS Capability
 * information element in 3GPP TS 48.018, not including
 * 3GPP TS 48.018 IEI and length indicator
 */
/* Dissector for the LCS Capability element */
static uint16_t
be_lcs_capability(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the LCS Capability element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.27 Packet Measurement Report
 * coded as the Packet Measurement Report
 * message or the Packet Enhanced Measurement Report message
 * starting with the 6-bit MESSAGE_TYPE (see clause 11 in
 * 3GPP TS 44.060) and ending with the Non-distribution contents
 * (i.e. the RLC/MAC padding bits are not included). The end of the
 * message is padded with 0-bits to the nearest octet boundary.
 */
/* Dissector for the Packet Measurement Report element */
static uint16_t
be_packet_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the Packet Measurement Report element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);

	return len;
}

/*
 * 10.28 Cell Identity List
 * coded as the value part of the Cell Identity List IE
 * defined in 3GPP TS 48.071.
 */
/* Dissector for the Measured Cell Identity List element */
static uint16_t
be_measured_cell_identity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the Measured Cell Identity List element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);

	return len;
}

/*
 * 10.29 IMEI
 * IMEI coded as the value part of the Mobile Identity IE defined in
 * 3GPP TS 24.008 (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall
 * be ignored by the receiver.
 */
/*
 * 10.30 Velocity Data
 * contains an octet sequence identical to that for Description of
 * Velocity defined in 3GPP TS 23.032.
 */
/*
 * 10.31 Requested GANSS Assistance Data
 */
/*
 * 10.32 GANSS Positioning Data
 */
/*
 * 10.33 GANSS Location Type
 */


#define	NUM_GSM_BSSMAP_LE_MSG array_length(gsm_bssmap_le_msg_strings)
static int ett_gsm_bssmap_le_msg[NUM_GSM_BSSMAP_LE_MSG];

/*
This enum is defined in packet-gsm_a_common.h to
make it possible to use element dissecton from this dissector
in other dissectors.

It is shown here as a comment for easier reference.

Note this enum must be of the same size as the element decoding list below

typedef enum
{
	DE_BMAPLE_LCSQOS,			/ 10.16 LCS QoS /
	DE_BMAPLE_LCS_PRIO,			/ LCS Priority /
	DE_BMAPLE_LOC_TYPE,			/ 10.18 Location Type /
	DE_BMAPLE_GANSS_LOC_TYPE,	/ GANSS Location Type /
	DE_BMAPLE_GEO_LOC,			/ 10.9 Geographic Location /
	DE_BMAPLE_POS_DATA,			/ 10.20 Positioning Data /
	DE_BMAPLE_GANSS_POS_DATA,	/ GANSS Positioning Data /
	DE_BMAPLE_VELOC_DATA,		/ Velocity Data /
	DE_BMAPLE_LCS_CAUSE,		/ 10.13 LCS Cause /
	DE_BMAPLE_LCS_CLIENT_TYPE,	/ LCS Client Type /
	DE_BMAPLE_APDU,				/ 10.3 APDU /
	DE_BMAPLE_NETWORK_ELEM_ID,	/ Network Element Identity /
	DE_BMAPLE_REQ_GPS_ASSIST_D, / 10.10 Requested GPS Assistance Data /
	DE_BMAPLE_REQ_GNSS_ASSIST_D,/ Requested GANSS Assistance Data /
	DE_BMAPLE_DECIPH_KEYS,		/ 10.8 Deciphering Keys /
	DE_BMAPLE_RETURN_ERROR_REQ,	/ Return Error Request /
	DE_BMAPLE_RETURN_ERROR_CAUSE,	/ Return Error Cause /
	DE_BMAPLE_SEGMENTATION,		/ Segmentation /
	DE_BMAPLE_CLASSMARK_TYPE_3,	/ 10.7 Classmark Information Type 3 /
	DE_BMAPLE_CAUSE,			/ 10.4 Cause /
	DE_BMAPLE_CELL_IDENTIFIER,	/ 10.5 Cell Identifier /
	DE_BMAPLE_CHOSEN_CHANNEL,	/ 10.6 Chosen Channel /
	DE_BMAPLE_IMSI,				/ 10.11 IMSI /
	DE_BMAPLE_RES1,				/ Reserved /
	DE_BMAPLE_RES2,				/ Reserved /
	DE_BMAPLE_RES3,				/ Reserved /
	DE_BMAPLE_LCS_CAPABILITY,	/ LCS Capability /
	DE_BMAPLE_PACKET_MEAS_REP,	/ Packet Measurement Report /
	DE_BMAPLE_MEAS_CELL_ID,		/ Measured Cell Identity /
	DE_BMAPLE_IMEI,				/ IMEI /
	BMAPLE_NONE					/ NONE /
}
bssmap_le_elem_idx_t;
*/


uint16_t (*bssmap_le_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string, int string_len) = {
	/* NOTE: The null types below are defined elsewhere. i.e in packet-gsm_a_bssmap.c */
	de_bmaple_lcs_qos,				/* 10.16 LCS QoS */
	NULL,							/* LCS Priority */
	de_bmaple_location_type,		/* 10.18 Location Type */
	be_ganss_loc_type,				/* GANSS Location Type */
	NULL,							/* 10.9 Geographic Location */
	de_bmaple_pos_dta,				/* 10.20 Positioning Data */
	be_ganss_pos_dta,				/* GANSS Positioning Data */
	NULL,							/* Velocity Data */
	de_bmaple_cause,				/* 10.13 LCS Cause */
	de_bmaple_client,				/* LCS Client Type */
	de_bmaple_apdu,					/* APDU */
	NULL,							/* Network Element Identity */
	de_bmaple_req_gps_ass_data,		/* 10.10 Requested GPS Assistance Data */
	be_ganss_ass_dta,				/* Requested GANSS Assistance Data */
	de_bmaple_decihp_keys,			/* 10.8 Deciphering Keys */
	NULL,							/* Return Error Request */
	NULL,							/* Return Error Cause */
	NULL,							/* Segmentation */
	NULL,							/* 10.7 Classmark Information Type 3 */
	NULL,							/* Cause */
	NULL,							/* Cell Identifier */
	NULL,							/* 10.6 Chosen Channel */
	de_mid,							/* 10.11 IMSI */
	NULL,							/* Reserved */
	NULL,							/* Reserved */
	NULL,							/* Reserved */
	be_lcs_capability,				/* LCS Capability */
	be_packet_meas_rep,				/* Packet Measurement Report */
	be_measured_cell_identity,		/* Measured Cell Identity List */
	de_mid,							/* IMEI (use same dissector as IMSI) */

	NULL,	/* NONE */

};

/*
 * 9.1 PERFORM LOCATION REQUEST
 */
static void
bssmap_le_perf_loc_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Type 9.1.1 M 3-n */
	ELEM_MAND_TLV(BSSMAP_LE_LOCATION_TYPE, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_TYPE, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element)
	/* Cell Identifier 9.1.2 O 5-10 */
	ELEM_MAND_TLV(BSSMAP_LE_CELL_IDENTIFIER, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* Classmark Information Type 3 9.1.3 O 3-14 */
	ELEM_OPT_TLV(BSSMAP_LE_CLASSMARK_INFORMATION_TYPE_3, GSM_A_PDU_TYPE_BSSMAP, BE_CM_INFO_3, NULL);
	/* LCS Client Type 9.1.4 C (note 3) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CLIENT_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CLIENT_TYPE, NULL);
	/* Chosen Channel 9.1.5 O 2 */
	ELEM_OPT_TLV(BSSMAP_LE_CHOSEN_CHANNEL, GSM_A_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, NULL);
	/* LCS Priority 9.1.6 O 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_PRIORITY, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO, NULL);
	/* LCS QoS 9.1.6a C (note 1) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_QOS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCSQOS, NULL);
	/* GPS Assistance Data 9.1.7 C (note 2) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA, GSM_A_PDU_TYPE_BSSMAP, BE_GPS_ASSIST_DATA, NULL);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TELV(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);
	/* LCS Capability 9.1.9 O */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CAPABILITY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAPABILITY, NULL);
	/* Packet Measurement Report 9.1.10 O*/
	ELEM_OPT_TLV(BSSMAP_LE_PACKET_MEASUREMENT_REPORT, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_PACKET_MEAS_REP, NULL);
	/* Measured Cell Identity List 9.1.11 O*/
	ELEM_OPT_TLV(BSSMAP_LE_CELL_IDENTITY_LIST, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MEAS_CELL_ID, NULL);
	/* IMSI	9.1.12	O (note 4)	5-10 */
	ELEM_OPT_TLV(BSSMAP_LE_IMSI, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMSI, NULL);
	/* IMEI	9.1.13	O (note 4)	10 (use same decode as IMSI) */
	ELEM_OPT_TLV(BSSMAP_LE_IMEI, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMEI, NULL);
	/* GANSS Location Type	9.1.14	C	3 */
	ELEM_OPT_TLV(BSSMAP_LE_GANSS_LOCATION_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE, NULL);
	/* GANSS Assistance Data	9.1.15	C (note 5)	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_REQUESTED_GANSS_ASSISTANCE_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GNSS_ASSIST_D, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);

}

/*
 * 9.2 PERFORM LOCATION RESPONSE
 */
static void
bssmap_le_perf_loc_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Estimate 9.2.1 C (note 1) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_GEOGRAPHIC_LOCATION, BSSAP_PDU_TYPE_BSSMAP, BE_LOC_EST, NULL);
	/* Positioning Data 9.2.2 O 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_POSITIONING_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_POS_DATA, NULL);
	/* Deciphering Keys 9.2.3 C (note 2) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_DECIPHERING_KEYS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_DECIPH_KEYS, NULL);
	/* LCS Cause 9.2.4 C (note 3) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);
	/* Velocity Estimate	9.2.5	O	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_VELOCITY_DATA, BSSAP_PDU_TYPE_BSSMAP, BE_VEL_EST, NULL);
	/* GANSS Positioning Data	9.2.6	O	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_GANSS_POSITIONING_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_POS_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.8 CONNECTION ORIENTED INFORMATION
 */
static void
bssmap_le_connection_oriented(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* APDU 9.8.1 M 3-n */
	ELEM_MAND_TELV(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* Segmentation 9.8.2 */
	ELEM_OPT_TLV(BSSMAP_LE_SEGMENTATION, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.9	CONNECTIONLESS INFORMATION
 *
Network Element Identity (source)	3.2.2.69	Both	M	3-n
Network Element Identity (target)	3.2.2.69	Both	M	3-n
APDU	3.2.2.68	Both	M	3-n
Segmentation	3.2,2,74	Both	C (note 1)	5
Return Error Request	3.2.2.72	Both	C (note 2)	3-n
Return Error Cause	3.2.2.73	Both	C (note 3)	3-n
*/

/*
 * 9.11 RESET ACKNOWLEDGE
 * no data
 */

/*
 * 9.12 PERFORM LOCATION INFORMATION
 */
static void
bssmap_le_perf_loc_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Cell Identifier 9.12.1 M */
	ELEM_MAND_TLV(BSSMAP_LE_CELL_IDENTIFIER, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TELV(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

static void (*bssmap_le_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len) = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	bssmap_le_perf_loc_request,	/* Perform Location Request */
	bssmap_le_perf_loc_resp,	/* Perform Location Response */
	bssmap_perf_loc_abort,		/* Abort */
	bssmap_le_perf_loc_info,	/* Perform Location Information */
	bssmap_le_connection_oriented,	/* Connection Oriented Information */
	NULL,						/* Connectionless Information */
	bssmap_reset,				/* Reset */
	NULL,		/* Reset Acknowledge */

	NULL,	/* NONE */
};

static int
dissect_bssmap_le(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	static gsm_a_tap_rec_t	tap_rec[4];
	static gsm_a_tap_rec_t *tap_p;
	static unsigned		tap_current=0;
	uint8_t	oct;
	uint32_t	offset, saved_offset;
	uint32_t	len;
	int	idx;
	proto_item	*bssmap_le_item = NULL;
	proto_tree	*bssmap_le_tree = NULL;
	const char	*str;
	sccp_msg_info_t *sccp_msg_p = (sccp_msg_info_t *)data;

	if (!(sccp_msg_p && sccp_msg_p->data.co.assoc)) {
		sccp_msg_p = NULL;
	}

	col_append_str(pinfo->cinfo, COL_INFO, "(BSSMAP LE) ");

	/*
	 * set tap record pointer
	 */
	tap_current++;
	if (tap_current >= 4)
	{
		tap_current = 0;
	}
	tap_p = &tap_rec[tap_current];


	offset = 0;
	saved_offset = offset;

	g_tree = tree;

	len = tvb_reported_length(tvb);

	/*
	 * add BSSMAP message name
	 */
	oct = tvb_get_uint8(tvb, offset++);

	str = try_val_to_str_idx((uint32_t) oct, gsm_bssmap_le_msg_strings, &idx);

	if (sccp_msg_p && !sccp_msg_p->data.co.label) {
		sccp_msg_p->data.co.label = wmem_strdup(wmem_file_scope(),
												val_to_str((uint32_t) oct,
												gsm_bssmap_le_msg_strings, "BSSMAP LE(0x%02x)"));
	}

	/*
	 * create the protocol tree
	 */
	if (str == NULL)
	{
		bssmap_le_item =
		proto_tree_add_protocol_format(tree, proto_bssmap_le, tvb, 0, len,
			"Lb - I/F BSSMAP LE - Unknown BSSMAP Message Type (0x%02x)",
			oct);

		bssmap_le_tree = proto_item_add_subtree(bssmap_le_item, ett_bssmap_le_msg);
	}
	else
	{
		bssmap_le_item =
		proto_tree_add_protocol_format(tree, proto_bssmap_le, tvb, 0, -1,
			"Lb - I/F BSSMAP LE - %s",
			str);

		bssmap_le_tree = proto_item_add_subtree(bssmap_le_item, ett_gsm_bssmap_le_msg[idx]);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

		/*
		 * add BSSMAP message name
		 */
		proto_tree_add_uint_format(bssmap_le_tree, hf_gsm_bssmap_le_msg_type,
		tvb, saved_offset, 1, oct, "Message Type %s",str);
	}

	tap_p->pdu_type = BSSAP_PDU_TYPE_BSSMAP;
	tap_p->message_type = oct;

	tap_queue_packet(gsm_a_tap, pinfo, tap_p);

	if (str == NULL) return len;

	if (offset >= len) return len;

	/*
	 * decode elements
	 */
	if (bssmap_le_msg_fcn[idx] == NULL)
	{
		proto_tree_add_item(bssmap_le_tree, hf_gsm_bssmap_le_message_elements, tvb, offset, len - offset, ENC_NA);
	}
	else
	{
		(*bssmap_le_msg_fcn[idx])(tvb, bssmap_le_tree, pinfo, offset, len - offset);
	}

	return len;
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_bssmap_le(void)
{
	unsigned i;
	unsigned last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_gsm_bssmap_le_msg_type,
		  { "BSSMAP LE Message Type",	"gsm_bssmap_le.msgtype",
		    FT_UINT8, BASE_HEX, VALS(gsm_bssmap_le_msg_strings), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_elem_id,
		  { "Element ID",	"gsm_bssmap_le.elem_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_apdu_protocol_id,
		  { "Protocol ID", "gsm_bssmap_le.apdu_protocol_id",
		    FT_UINT8, BASE_DEC, VALS(gsm_apdu_protocol_id_strings), 0x0,
		    "APDU embedded protocol id", HFILL }
		},
		{ &hf_gsm_bssmap_le_spare,
		  { "Spare", "gsm_bssmap_le.spare",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_ciphering_key_flag,
		  { "Ciphering Key Flag", "gsm_bssmap_le.decipheringKeys.flag",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_current_deciphering_key_value,
		  { "Current Deciphering Key Value", "gsm_bssmap_le.decipheringKeys.current",
		    FT_UINT64, BASE_HEX, NULL, 0x0, NULL,
		    HFILL}
		},
		{ &hf_gsm_bssmap_le_next_deciphering_key_value,
		  { "Next Deciphering Key Value", "gsm_bssmap_le.decipheringKeys.next",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_acq_ass,
		  { "Acquisition Assistance", "gsm_bssmap_le.acq_ass",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_time,
		  { "Reference Time", "gsm_bssmap_le.ref_time",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_loc,
		  { "Reference Location", "gsm_bssmap_le.ref_loc",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_dgps_corr,
		  { "DGPS Corrections", "gsm_bssmap_le.gps_corr",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_nav_mod,
		  { "Navigation Model", "gsm_bssmap_le.nav_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_iono_mod,
		  { "Ionospheric Model", "gsm_bssmap_le.iono_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_utc_mod,
		  { "UTC Model", "gsm_bssmap_le.utc_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_almanac,
		  { "Almanac", "gsm_bssmap_le.almanac",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext_chk,
		  { "Ephemeris Extension Check", "gsm_bssmap_le.ephemeris_ext_chk",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext,
		  { "Ephemeris Extension", "gsm_bssmap_le.ephemeris_ext",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_real_time_int,
		  { "Real-Time Integrity", "gsm_bssmap_le.real_time_int",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_lcs_cause_value,
		  { "Cause Value", "gsm_bssmap_le.lcsCauseValue",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_lcs_cause_values), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_diagnostic_value,
		  { "Diagnostic Value", "gsm_bssmap_le.diagnosticValue",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_position_method_failure_diagnostic_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_client_category,
		  { "Client Category", "gsm_bssmap_le.lcsClientType.clientCategory",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_client_category), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_client_subtype,
		  { "Client Subtype", "gsm_bssmap_le.lcsClientType.clientSubtype",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_client_subtype), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_velocity_requested,
		  { "Velocity Requested", "gsm_bssmap_le.lcsQos.velocityRequested",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_velocity_requested_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_coordinate_indicator,
		  { "Vertical Coordinate Indicator", "gsm_bssmap_le.lcsQos.verticalCoordinateIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_vertical_coordinate_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_horizontal_accuracy_indicator,
		  { "Horizontal Accuracy Indicator", "gsm_bssmap_le.lcsQos.horizontalAccuracyIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_horizontal_accuracy_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_horizontal_accuracy,
		  { "Horizontal Accuracy", "gsm_bssmap_le.lcsQos.horizontalAccuracy",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_accuracy,
		  { "Vertical Accuracy", "gsm_bssmap_le.lcsQos.verticalAccuracy",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_accuracy_indicator,
		  { "Vertical Accuracy Indicator", "gsm_bssmap_le.lcsQos.verticalAccuracyIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_vertical_accuracy_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_response_time_category,
		  { "Response Time Category", "gsm_bssmap_le.lcsQos.responseTimeCategory",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_response_time_definitions_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_apdu,
		  { "APDU", "gsm_bssmap_le.apdu",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_message_elements,
		  { "Message Elements", "gsm_bssmap_le.message_elements",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_location_inf,
		{ "Location Information", "gsm_bssmap_le.location_inf",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_loc_inf_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_method,
		{ "Positioning Method", "gsm_bssmap_le.pos_method",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_method_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_disc,
		{ "Positioning Data Discriminator", "gsm_bssmap_le.pos_data_disc",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_pos_method,
		{ "Positioning Method", "gsm_bssmap_le.pos_data.pos_method",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_data_pos_method_vals), 0xf8,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_usage,
		{ "Usage", "gsm_bssmap_le.pos_data.usage",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_data_usage_vals), 0x03,
			NULL, HFILL }
		},
	};

	expert_module_t* expert_gsm_a_bssmap_le;

	static ei_register_info ei[] = {
		{ &ei_gsm_a_bssmap_le_not_decoded_yet, { "gsm_bssmap_le.not_decoded_yet", PI_UNDECODED, PI_WARN, "Not decoded yet", EXPFILL }},
		{ &ei_gsm_a_bssmap_le_extraneous_data, { "gsm_bssmap_le.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec (report to wireshark.org)", EXPFILL }},
		{ &ei_gsm_a_bssmap_le_missing_mandatory_element, { "gsm_bssmap_le.missing_mandatory_element", PI_PROTOCOL, PI_WARN, "Missing Mandatory element, rest of dissection is suspect", EXPFILL }},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	int *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_LE_MSG +
		  NUM_GSM_BSSMAP_LE_ELEM];

	ett[0] = &ett_bssmap_le_msg;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_BSSMAP_LE_MSG; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_bssmap_le_msg[i];
	}

	for (i=0; i < NUM_GSM_BSSMAP_LE_ELEM; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_bssmap_le_elem[i];
	}

	/* Register the protocol name and description */

	proto_bssmap_le =
		proto_register_protocol("Lb-I/F BSSMAP LE", "GSM BSSMAP LE", "gsm_bssmap_le");

	proto_register_field_array(proto_bssmap_le, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gsm_a_bssmap_le = expert_register_protocol(proto_bssmap_le);
	expert_register_field_array(expert_gsm_a_bssmap_le, ei, array_length(ei));

	bssmap_le_handle = register_dissector("gsm_bssmap_le", dissect_bssmap_le, proto_bssmap_le);
}

void
proto_reg_handoff_gsm_bssmap_le(void)
{
	dissector_add_uint("bssap_le.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_le_handle);

	gsm_bsslap_handle = find_dissector_add_dependency("gsm_bsslap", proto_bssmap_le);
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
