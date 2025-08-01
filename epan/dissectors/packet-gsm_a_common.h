/* packet-gsm_a_common.h
 *
 *   Reference [3]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 4.7.0 Release 4)
 *   (ETSI TS 124 008 V6.8.0 (2005-03))
 *
 *   Reference [5]
 *   Point-to-Point (PP) Short Message Service (SMS)
 *   support on mobile radio interface
 *   (3GPP TS 24.011 version 4.1.1 Release 4)
 *
 *   Reference [7]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 5.9.0 Release 5)
 *
 *   Reference [8]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 6.7.0 Release 6)
 *   (3GPP TS 24.008 version 6.8.0 Release 6)
 *
 *   Reference [9]
 *   Digital cellular telecommunications system (Phase 2+);
 *   Group Call Control (GCC) protocol
 *   (GSM 04.68 version 8.1.0 Release 1999)
 *
 *   Reference [10]
 *   Digital cellular telecommunications system (Phase 2+);
 *   Broadcast Call Control (BCC) protocol
 *   (3GPP TS 44.069 version 11.0.0 Release 11)
 *
 *   Reference [11]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 13.7.0 Release 13)
 *
 *   Reference [12]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 14.4.0 Release 14)
 *
 *   Reference [13]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 15.1.0 Release 15)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
 *
 * Added Dissection of Group Call Control (GCC) protocol.
 * Added Dissection of Broadcast Call Control (BCC) protocol.
 * Copyright 2015, Michail Koreshkov <michail.koreshkov [at] zte.com.cn
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_GSM_A_COMMON_H__
#define __PACKET_GSM_A_COMMON_H__

#include <epan/proto.h>

#include "packet-sccp.h"
#include "packet-e212.h"
#include "ws_symbol_export.h"

/* PROTOTYPES/FORWARDS */
typedef uint16_t (*elem_fcn)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
typedef void (*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);

/* globals needed as a result of spltting the packet-gsm_a.c into several files
 * until further restructuring can take place to make them more modular
 */

/* common PD values */
extern const value_string protocol_discriminator_vals[];
extern const value_string gsm_a_pd_short_str_vals[];

extern uint16_t de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
extern uint16_t de_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

/* Needed to share the packet-gsm_a_common.c functions */
extern value_string_ext gsm_bssmap_elem_strings_ext;
extern int ett_gsm_bssmap_elem[];
extern elem_fcn bssmap_elem_fcn[];
extern int hf_gsm_a_bssmap_elem_id;

extern value_string_ext gsm_dtap_elem_strings_ext;
extern int ett_gsm_dtap_elem[];
extern elem_fcn dtap_elem_fcn[];
extern int hf_gsm_a_dtap_elem_id;

extern value_string_ext gsm_rp_elem_strings_ext;
extern int ett_gsm_rp_elem[];
extern elem_fcn rp_elem_fcn[];
extern int hf_gsm_a_rp_elem_id;

extern value_string_ext gsm_rr_elem_strings_ext;
extern int ett_gsm_rr_elem[];
extern elem_fcn rr_elem_fcn[];
extern int hf_gsm_a_rr_elem_id;
extern void get_rr_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);

extern value_string_ext gsm_common_elem_strings_ext;
extern int ett_gsm_common_elem[];
extern elem_fcn common_elem_fcn[];
extern int hf_gsm_a_common_elem_id;

extern value_string_ext gsm_gm_elem_strings_ext;
extern int ett_gsm_gm_elem[];
extern elem_fcn gm_elem_fcn[];
extern int hf_gsm_a_gm_elem_id;
extern void get_gmm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);
extern void get_sm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);

extern value_string_ext gsm_bsslap_elem_strings_ext;
extern int ett_gsm_bsslap_elem[];
extern elem_fcn bsslap_elem_fcn[];
extern int hf_gsm_a_bsslap_elem_id;

extern value_string_ext gsm_bssmap_le_elem_strings_ext;
extern int ett_gsm_bssmap_le_elem[];
extern elem_fcn bssmap_le_elem_fcn[];
extern int hf_gsm_bssmap_le_elem_id;

extern value_string_ext nas_eps_common_elem_strings_ext;
extern int ett_nas_eps_common_elem[];
extern elem_fcn nas_eps_common_elem_fcn[];
extern int hf_nas_eps_common_elem_id;

extern value_string_ext nas_emm_elem_strings_ext;
extern int ett_nas_eps_emm_elem[];
extern elem_fcn emm_elem_fcn[];
extern int hf_nas_eps_emm_elem_id;

extern value_string_ext nas_esm_elem_strings_ext;
extern int ett_nas_eps_esm_elem[];
extern elem_fcn esm_elem_fcn[];
extern int hf_nas_eps_esm_elem_id;

extern value_string_ext sgsap_elem_strings_ext;
extern int ett_sgsap_elem[];
extern elem_fcn sgsap_elem_fcn[];
extern int hf_sgsap_elem_id;

extern value_string_ext bssgp_elem_strings_ext;
extern int ett_bssgp_elem[];
extern elem_fcn bssgp_elem_fcn[];
extern int hf_bssgp_elem_id;

extern value_string_ext gmr1_ie_common_strings_ext;
extern elem_fcn gmr1_ie_common_func[];
extern int ett_gmr1_ie_common[];

extern value_string_ext gmr1_ie_rr_strings_ext;
extern elem_fcn gmr1_ie_rr_func[];
extern int ett_gmr1_ie_rr[];

extern value_string_ext nas_5gs_common_elem_strings_ext;
extern int ett_nas_5gs_common_elem[];
extern elem_fcn nas_5gs_common_elem_fcn[];
extern int hf_nas_5gs_common_elem_id;

extern value_string_ext nas_5gs_mm_elem_strings_ext;
extern int ett_nas_5gs_mm_elem[];
extern elem_fcn nas_5gs_mm_elem_fcn[];
extern int hf_nas_5gs_mm_elem_id;

extern value_string_ext nas_5gs_sm_elem_strings_ext;
extern int ett_nas_5gs_sm_elem[];
extern elem_fcn nas_5gs_sm_elem_fcn[];
extern int hf_nas_5gs_sm_elem_id;

extern value_string_ext nas_5gs_updp_elem_strings_ext;
extern int ett_nas_5gs_updp_elem[];
extern elem_fcn nas_5gs_updp_elem_fcn[];
extern int hf_nas_5gs_updp_elem_id;

extern sccp_assoc_info_t* sccp_assoc;

extern int gsm_a_tap;
extern packet_info *gsm_a_dtap_pinfo;

/* TS 23 032 */
int dissect_geographical_description(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
uint16_t dissect_description_of_velocity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);


/* common field values */
extern int hf_gsm_a_extension;
extern int hf_gsm_a_tmsi;
extern int hf_gsm_a_L3_protocol_discriminator;
extern int hf_gsm_a_call_prio;
extern int hf_gsm_a_b8spare;
extern int hf_gsm_a_skip_ind;
extern int hf_gsm_a_rr_chnl_needed_ch1;
extern int hf_gsm_a_rr_t3212;
extern int hf_gsm_a_gm_rac;
extern int hf_gsm_a_spare_bits;
extern int hf_gsm_a_lac;

/* Inter protocol filters*/
extern int hf_3gpp_tmsi;

/* flags for the packet-gsm_a_common routines */
#define GSM_A_PDU_TYPE_BSSMAP       0  /* BSSAP_PDU_TYPE_BSSMAP i.e. 0 - until split complete at least! */
#define GSM_A_PDU_TYPE_DTAP         1  /* BSSAP_PDU_TYPE_DTAP i.e. 1   - until split complete at least! */
#define GSM_A_PDU_TYPE_RP           2
#define GSM_A_PDU_TYPE_RR           3
#define GSM_A_PDU_TYPE_COMMON       4
#define GSM_A_PDU_TYPE_GM           5
#define GSM_A_PDU_TYPE_BSSLAP       6
#define GSM_A_PDU_TYPE_SACCH        7
#define GSM_PDU_TYPE_BSSMAP_LE      8
#define NAS_PDU_TYPE_COMMON         9
#define NAS_PDU_TYPE_EMM            10
#define NAS_PDU_TYPE_ESM            11
#define SGSAP_PDU_TYPE              12
#define BSSGP_PDU_TYPE              13
#define GMR1_IE_COMMON              14
#define GMR1_IE_RR                  15
#define NAS_5GS_PDU_TYPE_COMMON     16
#define NAS_5GS_PDU_TYPE_MM         17
#define NAS_5GS_PDU_TYPE_SM         18
#define NAS_5GS_PDU_TYPE_UPDP       19

extern const char* get_gsm_a_msg_string(int pdu_type, int idx);

/*
 * this should be set on a per message basis, if possible
 */
#define IS_UPLINK_FALSE     0
#define IS_UPLINK_TRUE      1
#define IS_UPLINK_UNKNOWN   2

/* Defines for handling half octet mandatory V IEs
 * Named LEFT and RIGHT (as displayed) because the GSM definitions and our internal representation
 * have the bits numbered in opposite senses
 */
#define LEFT_NIBBLE     (2)
#define RIGHT_NIBBLE    (1)

/* FUNCTIONS */

/* ELEMENT FUNCTIONS */
#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len, pinfo, ei) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, ei, tvb, curr_offset, (edc_len) - (edc_max_len)); \
        curr_offset += ((edc_len) - (edc_max_len)); \
    }

#define NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) <= (curr_offset - offset)) return(nmdc_len);

#define SET_ELEM_VARS(SEV_pdu_type, SEV_elem_names_ext, SEV_elem_ett, SEV_elem_funcs, ei_unknown) \
    switch (SEV_pdu_type) \
    { \
    case GSM_A_PDU_TYPE_BSSMAP: \
        SEV_elem_names_ext = gsm_bssmap_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_bssmap_elem; \
        SEV_elem_funcs = bssmap_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_DTAP: \
        SEV_elem_names_ext = gsm_dtap_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_dtap_elem; \
        SEV_elem_funcs = dtap_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_RP: \
        SEV_elem_names_ext = gsm_rp_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_rp_elem; \
        SEV_elem_funcs = rp_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_RR: \
        SEV_elem_names_ext = gsm_rr_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_rr_elem; \
        SEV_elem_funcs = rr_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_COMMON: \
        SEV_elem_names_ext = gsm_common_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_common_elem; \
        SEV_elem_funcs = common_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_GM: \
        SEV_elem_names_ext = gsm_gm_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_gm_elem; \
        SEV_elem_funcs = gm_elem_fcn; \
        break; \
    case GSM_A_PDU_TYPE_BSSLAP: \
        SEV_elem_names_ext = gsm_bsslap_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_bsslap_elem; \
        SEV_elem_funcs = bsslap_elem_fcn; \
        break; \
    case GSM_PDU_TYPE_BSSMAP_LE: \
        SEV_elem_names_ext = gsm_bssmap_le_elem_strings_ext; \
        SEV_elem_ett = ett_gsm_bssmap_le_elem; \
        SEV_elem_funcs = bssmap_le_elem_fcn; \
        break; \
    case NAS_PDU_TYPE_COMMON: \
        SEV_elem_names_ext = nas_eps_common_elem_strings_ext; \
        SEV_elem_ett = ett_nas_eps_common_elem; \
        SEV_elem_funcs = nas_eps_common_elem_fcn; \
        break; \
    case NAS_PDU_TYPE_EMM: \
        SEV_elem_names_ext = nas_emm_elem_strings_ext; \
        SEV_elem_ett = ett_nas_eps_emm_elem; \
        SEV_elem_funcs = emm_elem_fcn; \
        break; \
    case NAS_PDU_TYPE_ESM: \
        SEV_elem_names_ext = nas_esm_elem_strings_ext; \
        SEV_elem_ett = ett_nas_eps_esm_elem; \
        SEV_elem_funcs = esm_elem_fcn; \
        break; \
    case SGSAP_PDU_TYPE: \
        SEV_elem_names_ext = sgsap_elem_strings_ext; \
        SEV_elem_ett = ett_sgsap_elem; \
        SEV_elem_funcs = sgsap_elem_fcn; \
        break; \
    case BSSGP_PDU_TYPE: \
        SEV_elem_names_ext = bssgp_elem_strings_ext; \
        SEV_elem_ett = ett_bssgp_elem; \
        SEV_elem_funcs = bssgp_elem_fcn; \
        break; \
    case GMR1_IE_COMMON: \
        SEV_elem_names_ext = gmr1_ie_common_strings_ext; \
        SEV_elem_ett = ett_gmr1_ie_common; \
        SEV_elem_funcs = gmr1_ie_common_func; \
        break; \
    case GMR1_IE_RR: \
        SEV_elem_names_ext = gmr1_ie_rr_strings_ext; \
        SEV_elem_ett = ett_gmr1_ie_rr; \
        SEV_elem_funcs = gmr1_ie_rr_func; \
        break; \
    case NAS_5GS_PDU_TYPE_COMMON: \
        SEV_elem_names_ext = nas_5gs_common_elem_strings_ext; \
        SEV_elem_ett = ett_nas_5gs_common_elem; \
        SEV_elem_funcs = nas_5gs_common_elem_fcn; \
        break; \
    case NAS_5GS_PDU_TYPE_MM: \
        SEV_elem_names_ext = nas_5gs_mm_elem_strings_ext; \
        SEV_elem_ett = ett_nas_5gs_mm_elem; \
        SEV_elem_funcs = nas_5gs_mm_elem_fcn; \
        break; \
    case NAS_5GS_PDU_TYPE_SM: \
        SEV_elem_names_ext = nas_5gs_sm_elem_strings_ext; \
        SEV_elem_ett = ett_nas_5gs_sm_elem; \
        SEV_elem_funcs = nas_5gs_sm_elem_fcn; \
        break; \
    case NAS_5GS_PDU_TYPE_UPDP: \
        SEV_elem_names_ext = nas_5gs_updp_elem_strings_ext; \
        SEV_elem_ett = ett_nas_5gs_updp_elem; \
        SEV_elem_funcs = nas_5gs_updp_elem_fcn; \
        break; \
    default: \
        proto_tree_add_expert_format(tree, pinfo, ei_unknown, \
            tvb, curr_offset, -1, \
            "Unknown PDU type (%u) gsm_a_common", SEV_pdu_type); \
        return(consumed); \
    }

/*
 * Type Length Value (TLV) element dissector
 */
WS_DLL_PUBLIC uint16_t elem_tlv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, unsigned len, const char *name_add);

/*
 * Type Extendable Length Value (TLVE) element dissector
 */
uint16_t elem_telv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, unsigned len, const char *name_add);

/*
 * Type Length Value (TLV-E) element dissector
 */
uint16_t elem_tlv_e(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, unsigned len, const char *name_add);

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
WS_DLL_PUBLIC uint16_t elem_tv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, const char *name_add);

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
WS_DLL_PUBLIC uint16_t elem_tv_short(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, const char *name_add);

/*
 * Type (T) element dissector
 */
WS_DLL_PUBLIC uint16_t elem_t(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint8_t iei, int pdu_type, int idx, uint32_t offset, const char *name_add);

/*
 * Length Value (LV) element dissector
 */
WS_DLL_PUBLIC uint16_t elem_lv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int pdu_type, int idx, uint32_t offset, unsigned len, const char *name_add);

/*
 * Length Value (LV-E) element dissector
 */
uint16_t elem_lv_e(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int pdu_type, int idx, uint32_t offset, unsigned len, const char *name_add);

/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
WS_DLL_PUBLIC uint16_t elem_v(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int pdu_type, int idx, uint32_t offset, const char *name_add);

/*
 * Short Value (V_SHORT) element dissector
 *
 * nibble used in this functions to indicate left or right nibble of the octet
 * This is expected to be used right nibble first, as the tables of 24.008.
 */
WS_DLL_PUBLIC uint16_t elem_v_short(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int pdu_type, int idx, uint32_t offset, uint32_t nibble);


/* XXX: Most (if not all) the functions which make use of the following macros have the variables 'consumed',
 *      'curr_offset', and 'cur_len' declared as *unsigned*.  This means that the 'if (curr_len <= 0)' statement
 *      originally at the end of each of the macros would always be false since an unsigned cannot be less than 0.
 *      I've chosen to change the statement to 'if ((signed)curr_len <= 0)'. (Although this may be a bit of a
 *      hack, it seems simpler than changing declarations to signed in all the places these macros are used).
 *      Is there a better approach ?
 */

#define ELEM_MAND_TLV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_tlv(tvb, tree, pinfo, (uint8_t) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
            EMT_iei, \
            get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
            /* coverity[array_null] */ \
            (EMT_elem_name_addition == NULL) ? "" : EMT_elem_name_addition \
            ); \
    } \
}
/* This is a version where the length field can be one or two octets depending
 * if the extension bit is set or not (TS 48.016 p 10.1.2).
 *         8        7 6 5 4 3 2 1
 * octet 2 0/1 ext  length
 * octet 2a length
 */
#define ELEM_MAND_TELV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_telv(tvb, tree, pinfo, (uint8_t) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
            EMT_iei, \
            get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
            /* coverity[array_null] */ \
            (EMT_elem_name_addition == NULL) ? "" : EMT_elem_name_addition \
            ); \
    } \
}

#define ELEM_MAND_TLV_E(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_tlv_e(tvb, tree, pinfo, (uint8_t) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
            EMT_iei, \
            get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
            /* coverity[array_null] */ \
            (EMT_elem_name_addition == NULL) ? "" : EMT_elem_name_addition \
            ); \
    } \
}
#define ELEM_OPT_TLV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_tlv(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_OPT_TELV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_telv(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_OPT_TLV_E(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_tlv_e(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_MAND_TV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_tv(tvb, tree, pinfo, (uint8_t) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, EMT_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory,\
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
            EMT_iei, \
            get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
            /* coverity[array_null] */ \
            (EMT_elem_name_addition == NULL) ? "" : EMT_elem_name_addition \
        ); \
    } \
}

#define ELEM_OPT_TV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_tv(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_OPT_TV_SHORT(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_tv_short(tvb, tree, pinfo, EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_OPT_T(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return; \
    if ((consumed = elem_t(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

#define ELEM_MAND_LV(EML_pdu_type, EML_elem_idx, EML_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_lv(tvb, tree, pinfo, EML_pdu_type, EML_elem_idx, curr_offset, curr_len, EML_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory,\
            tvb, curr_offset, 0, \
            "Missing Mandatory element %s%s, rest of dissection is suspect", \
            get_gsm_a_msg_string(EML_pdu_type, EML_elem_idx), \
            /* coverity[array_null] */ \
            (EML_elem_name_addition == NULL) ? "" : EML_elem_name_addition \
        ); \
    } \
}

#define ELEM_MAND_LV_E(EML_pdu_type, EML_elem_idx, EML_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_lv_e(tvb, tree, pinfo, EML_pdu_type, EML_elem_idx, curr_offset, curr_len, EML_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory,\
            tvb, curr_offset, 0, \
            "Missing Mandatory element %s%s, rest of dissection is suspect", \
            get_gsm_a_msg_string(EML_pdu_type, EML_elem_idx), \
            /* coverity[array_null] */ \
            (EML_elem_name_addition == NULL) ? "" : EML_elem_name_addition \
        ); \
    } \
}

#define ELEM_MAND_V(EMV_pdu_type, EMV_elem_idx, EMV_elem_name_addition, ei_mandatory) \
{\
    if (((signed)curr_len > 0) && \
        ((consumed = elem_v(tvb, tree, pinfo, EMV_pdu_type, EMV_elem_idx, curr_offset, EMV_elem_name_addition)) > 0)) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory,\
            tvb, curr_offset, 0, \
            "Missing Mandatory element %s%s, rest of dissection is suspect", \
            get_gsm_a_msg_string(EMV_pdu_type, EMV_elem_idx), \
            /* coverity[array_null] */ \
            (EMV_elem_name_addition == NULL) ? "" : EMV_elem_name_addition \
        ); \
    } \
}

#define ELEM_MAND_VV_SHORT(EMV_pdu_type1, EMV_elem_idx1, EMV_pdu_type2, EMV_elem_idx2, ei_mandatory) \
{\
    if ((signed)curr_len > 0) \
    { \
        elem_v_short(tvb, tree, pinfo, EMV_pdu_type1, EMV_elem_idx1, curr_offset, RIGHT_NIBBLE); \
        elem_v_short(tvb, tree, pinfo, EMV_pdu_type2, EMV_elem_idx2, curr_offset, LEFT_NIBBLE); \
        curr_offset ++ ; /* consumed length is 1, regardless of contents */ \
        curr_len -- ; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_mandatory,\
            tvb, curr_offset, 0, \
            "Missing Mandatory elements %s %s, rest of dissection is suspect", \
            get_gsm_a_msg_string(EMV_pdu_type1, EMV_elem_idx1), \
            get_gsm_a_msg_string(EMV_pdu_type2, EMV_elem_idx2) \
            /* coverity[array_null] */ \
        ); \
    } \
}

/*
 * this enum must be kept in-sync with 'gsm_a_pd_str'
 * it is used as an index into the array
 */
typedef enum
{
    PD_GCC = 0,
    PD_BCC,
    PD_RSVD_1,
    PD_CC,
    PD_GTTP,
    PD_MM,
    PD_RR,
    PD_UNK_1,
    PD_GMM,
    PD_SMS,
    PD_SM,
    PD_SS,
    PD_LCS,
    PD_UNK_2,
    PD_RSVD_EXT,
    PD_TP
}
gsm_a_pd_str_e;

typedef struct _gsm_a_tap_rec_t {
    /*
     * value from packet-bssap.h
     */
    uint8_t     pdu_type;
    uint8_t     message_type;
    gsm_a_pd_str_e  protocol_disc;
} gsm_a_tap_rec_t;

void bssmap_old_bss_to_new_bss_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo);
void bssmap_new_bss_to_old_bss_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo);

void dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);

uint16_t be_cell_id_aux(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len, uint8_t disc);
uint16_t be_cell_id_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len, uint8_t disc, e212_number_type_t number_type);
uint16_t be_cell_id_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_chan_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

WS_DLL_PUBLIC
uint16_t de_lai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_mid(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_cell_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bearer_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bearer_cap_uplink(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_emlpp_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_ganss_loc_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_ganss_pos_dta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t be_ganss_ass_dta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_cn_common_gsm_map_nas_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_cs_domain_spec_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_ps_domain_spec_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_plmn_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_ms_cm_3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_serv_cat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_sm_apn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_sm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_sm_mbms_prot_conf_opt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_sm_pco(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_sm_pdp_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
WS_DLL_PUBLIC
uint16_t de_sm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_sm_tmgi(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len, char* add_string _U_, int string_len _U_);
uint16_t de_time_zone(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_gmm_voice_domain_pref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

uint16_t de_sup_codec_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

uint16_t de_gc_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);
uint16_t de_gc_timer3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

WS_DLL_PUBLIC
uint16_t de_rr_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_ch_dsc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_chnl_needed(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_rr_meas_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_rr_mob_all(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);

WS_DLL_PUBLIC
uint16_t de_rej_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
WS_DLL_PUBLIC
uint16_t de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_spare_nibble(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);

uint16_t de_emm_ue_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_emm_trac_area_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_emm_sec_par_from_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);
uint16_t de_emm_sec_par_to_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);
uint16_t de_emm_ue_add_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_esm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_esm_apn_aggr_max_br(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);
uint16_t de_esm_ext_apn_agr_max_br(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_esm_ext_eps_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_esm_rel_assist_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);

void nas_esm_pdn_con_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);

uint16_t de_nas_5gs_cmn_dnn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_mm_ue_radio_cap_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len, char* add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_cmn_s_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_cmn_service_level_aa_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_sm_qos_rules(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_sm_qos_flow_des(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
uint16_t de_nas_5gs_sm_session_ambr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
void de_nas_5gs_intra_n1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_);
void de_nas_5gs_n1_mode_to_s1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_);
void de_nas_5gs_s1_mode_to_n1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_);
void dissect_nas_5gs_updp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
void dtap_rr_cip_mode_cpte(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);

void bssmap_perf_loc_abort(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
void bssmap_reset(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
void bssmap_conn_oriented(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
uint16_t bssmap_dissect_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);


void rp_data_n_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);

uint16_t de_sgsap_ecgi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC const value_string gsm_a_bssmap_msg_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_mm_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_rr_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_cc_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_gmm_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_sms_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_sm_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_ss_strings[];
WS_DLL_PUBLIC const value_string gsm_a_dtap_msg_tp_strings[];
WS_DLL_PUBLIC const value_string gsm_a_rr_short_pd_msg_strings[];
WS_DLL_PUBLIC const char *gsm_a_pd_str[];

extern const value_string gsm_a_sm_qos_del_of_err_sdu_vals[];
extern const value_string gsm_a_sm_qos_traffic_cls_vals[];
extern const value_string gsm_a_sm_qos_ber_vals[];
extern const value_string gsm_a_sm_qos_sdu_err_rat_vals[];
extern const value_string gsm_a_sm_qos_traff_hdl_pri_vals[];

extern const value_string gsm_a_dtap_type_of_number_values[];
extern const value_string gsm_a_dtap_numbering_plan_id_values[];
extern const value_string gsm_a_sms_vals[];
extern const value_string tighter_cap_level_vals[];
extern value_string_ext gsm_a_rr_rxlev_vals_ext;
extern const value_string gsm_a_rr_rxqual_vals[];
extern const value_string gsm_a_gm_type_of_ciph_alg_vals[];

extern value_string_ext nas_eps_emm_cause_values_ext;
extern const value_string nas_eps_emm_cause_values[];
extern const value_string nas_eps_esm_cause_vals[];

extern const value_string nas_5gs_pdu_session_id_vals[];
extern const value_string nas_5gs_sm_cause_vals[];

typedef enum
{
    /* Common Information Elements [3] 10.5.1 */
    DE_CELL_ID,                        /* Cell Identity */
    DE_CIPH_KEY_SEQ_NUM,               /* Ciphering Key Sequence Number */
    DE_LAI,                            /* Location Area Identification */
    DE_MID,                            /* Mobile Identity */
    DE_MS_CM_1,                        /* Mobile Station Classmark 1 */
    DE_MS_CM_2,                        /* Mobile Station Classmark 2 */
    DE_MS_CM_3,                        /* Mobile Station Classmark 3 */
    DE_SPARE_NIBBLE,                   /* Spare Half Octet */
    DE_D_GB_CALL_REF,                  /* Descriptive group or broadcast call reference */
    DE_G_CIPH_KEY_NUM,                 /* Group Cipher Key Number */
    DE_PD_SAPI,                        /* PD and SAPI $(CCBS)$ */
    DE_PRIO,                           /* Priority Level */
    DE_CN_COMMON_GSM_MAP_NAS_SYS_INFO, /* CN Common GSM-MAP NAS system information */
    DE_CS_DOMAIN_SPEC_SYS_INFO,        /* CS domain specific system information */
    DE_PS_DOMAIN_SPEC_SYS_INFO,        /* PS domain specific system information */
    DE_PLMN_LIST,                      /* PLMN List */
    DE_NAS_CONT_FOR_PS_HO,             /* 10.5.1.14 NAS container for PS HO */
    DE_MS_NET_FEAT_SUP,                /* 10.5.1.15 MS network feature support */

    DE_COMMON_NONE          /* NONE */
}
common_elem_idx_t;

typedef enum
{
    BE_UDEF_0,                          /* Undefined */
    BE_CIC,                             /* Circuit Identity Code */
    BE_RSVD_1,                          /* Reserved */
    BE_RES_AVAIL,                       /* Resource Available */
    BE_CAUSE,                           /* Cause */
    BE_CELL_ID,                         /* Cell Identifier */
    BE_PRIO,                            /* Priority */
    BE_L3_HEADER_INFO,                  /* Layer 3 Header Information */
    BE_IMSI,                            /* IMSI */
    BE_TMSI,                            /* TMSI */
    BE_ENC_INFO,                        /* Encryption Information */
    BE_CHAN_TYPE,                       /* Channel Type */
    BE_PERIODICITY,                     /* Periodicity */
    BE_EXT_RES_IND,                     /* Extended Resource Indicator */
    BE_NUM_MS,                          /* Number Of MSs */
    BE_RSVD_2,                          /* Reserved */
    BE_RSVD_3,                          /* Reserved */
    BE_RSVD_4,                          /* Reserved */
    BE_CM_INFO_2,                       /* Classmark Information Type 2 */
    BE_CM_INFO_3,                       /* Classmark Information Type 3 */
    BE_INT_BAND,                        /* Interference Band To Be Used */
    BE_RR_CAUSE,                        /* RR Cause */
    BE_RSVD_5,                          /* Reserved */
    BE_L3_INFO,                         /* Layer 3 Information */
    BE_DLCI,                            /* DLCI */
    BE_DOWN_DTX_FLAG,                   /* Downlink DTX Flag */
    BE_CELL_ID_LIST,                    /* Cell Identifier List */
    BE_RESP_REQ,                        /* Response Request */
    BE_RES_IND_METHOD,                  /* Resource Indication Method */
    BE_CM_INFO_1,                       /* Classmark Information Type 1 */
    BE_CIC_LIST,                        /* Circuit Identity Code List */
    BE_DIAG,                            /* Diagnostic */
    BE_L3_MSG,                          /* Layer 3 Message Contents */
    BE_CHOSEN_CHAN,                     /* Chosen Channel */
    BE_TOT_RES_ACC,                     /* Total Resource Accessible */
    BE_CIPH_RESP_MODE,                  /* Cipher Response Mode */
    BE_CHAN_NEEDED,                     /* Channel Needed */
    BE_TRACE_TYPE,                      /* Trace Type */
    BE_TRIGGERID,                       /* TriggerID */
    BE_TRACE_REF,                       /* Trace Reference */
    BE_TRANSID,                         /* TransactionID */
    BE_MID,                             /* Mobile Identity */
    BE_OMCID,                           /* OMCID */
    BE_FOR_IND,                         /* Forward Indicator */
    BE_CHOSEN_ENC_ALG,                  /* Chosen Encryption Algorithm */
    BE_CCT_POOL,                        /* Circuit Pool */
    BE_CCT_POOL_LIST,                   /* Circuit Pool List */
    BE_TIME_IND,                        /* Time Indication */
    BE_RES_SIT,                         /* Resource Situation */
    BE_CURR_CHAN_1,                     /* Current Channel Type 1 */
    BE_QUE_IND,                         /* Queueing Indicator */
    BE_ASS_REQ,                         /* Assignment Requirement */
    BE_UDEF_52,                         /* Undefined */
    BE_TALKER_FLAG,                     /* Talker Flag */
    BE_CONN_REL_REQ,                    /* Connection Release Requested */
    BE_GROUP_CALL_REF,                  /* Group Call Reference */
    BE_EMLPP_PRIO,                      /* eMLPP Priority */
    BE_CONF_EVO_IND,                    /* Configuration Evolution Indication */
    BE_OLD2NEW_INFO,                    /* Old BSS to New BSS Information */
    BE_LSA_ID,                          /* LSA Identifier */
    BE_LSA_ID_LIST,                     /* LSA Identifier List */
    BE_LSA_INFO,                        /* LSA Information */
    BE_LCS_QOS,                         /* LCS QoS */
    BE_LSA_ACC_CTRL,                    /* LSA access control suppression */
    BE_SPEECH_VER,                      /* Speech Version */
    BE_UDEF_65,                         /* Undefined */
    BE_UDEF_66,                         /* Undefined */
    BE_LCS_PRIO,                        /* LCS Priority */
    BE_LOC_TYPE,                        /* Location Type */
    BE_LOC_EST,                         /* Location Estimate */
    BE_POS_DATA,                        /* Positioning Data */
    BE_LCS_CAUSE,                       /* 3.2.2.66 LCS Cause */
    BE_LCS_CLIENT,                      /* 10.14 LCS Client Type */
    BE_APDU,                            /* APDU */
    BE_NE_ID,                           /* Network Element Identity */
    BE_GPS_ASSIST_DATA,                 /* GPS Assistance Data */
    BE_DECIPH_KEYS,                     /* Deciphering Keys */
    BE_RET_ERR_REQ,                     /* Return Error Request */
    BE_RET_ERR_CAUSE,                   /* Return Error Cause */
    BE_SEG,                             /* Segmentation */
    BE_SERV_HO,                         /* Service Handover */
    BE_SRC_RNC_TO_TAR_RNC_UMTS,         /* Source RNC to target RNC transparent information (UMTS) */
    BE_SRC_RNC_TO_TAR_RNC_CDMA,         /* Source RNC to target RNC transparent information (cdma2000) */
    BE_GERAN_CLS_M,                     /* GERAN Classmark */
    BE_GERAN_BSC_CONT,                  /* GERAN BSC Container */
    BE_VEL_EST,                         /* Velocity Estimate */
    BE_UDEF_86,                         /* Undefined */
    BE_UDEF_87,                         /* Undefined */
    BE_UDEF_88,                         /* Undefined */
    BE_UDEF_89,                         /* Undefined */
    BE_UDEF_90,                         /* Undefined */
    BE_UDEF_91,                         /* Undefined */
    BE_UDEF_92,                         /* Undefined */
    BE_UDEF_93,                         /* Undefined */
    BE_UDEF_94,                         /* Undefined */
    BE_UDEF_95,                         /* Undefined */
    BE_UDEF_96,                         /* Undefined */
    BE_NEW_BSS_TO_OLD_BSS_INF,          /* New BSS to Old BSS Information */
    BE_UDEF_98,                         /* Undefined */
    BE_INTER_SYS_INF,                   /* Inter-System Information */
    BE_SNA_ACC_INF,                     /* SNA Access Information */
    BE_VSTK_RAND_INF,                   /* VSTK_RAND Information */
    BE_VSTK_INF,                        /* VSTK Information */
    BE_PAGING_INF,                      /* Paging Information */
    BE_IMEI,                            /* IMEI */
    BE_VGCS_FEAT_FLG,                   /* VGCS Feature Flags */
    BE_TALKER_PRI,                      /* Talker Priority */
    BE_EMRG_SET_IND,                    /* Emergency Set Indication */
    BE_TALKER_ID,                       /* Talker Identity */
    BE_CELL_ID_LIST_SEG,                /* Cell Identifier List Segment */
    BE_SMS_TO_VGCS,                     /* SMS to VGCS */
    BE_VGCS_TALKER_MOD,                 /* VGCS Talker Mode */
    BE_VGS_VBS_CELL_STAT,               /* VGCS/VBS Cell Status */
    BE_CELL_ID_LST_SEG_F_EST_CELLS,     /* Cell Identifier List Segment for established cells */
    BE_CELL_ID_LST_SEG_F_CELL_TB_EST,   /* Cell Identifier List Segment for cells to be established */
    BE_CELL_ID_LST_SEG_F_REL_CELL,      /* Cell Identifier List Segment for released cells - no user present */
    BE_CELL_ID_LST_SEG_F_NOT_EST_CELL,  /* Cell Identifier List Segment for not established cells - no establishment possible */
    BE_GANSS_ASS_DTA,                   /* GANSS Assistance Data */
    BE_GANSS_POS_DTA,                   /* GANSS Positioning Data */
    BE_GANSS_LOC_TYP,                   /* GANSS Location Type */
    BE_APP_DATA,                        /* Application Data */
    BE_DATA_ID,                         /* Data Identity */
    BE_APP_DATA_INF,                    /* Application Data Information */
    BE_MSISDN,                          /* MSISDN */
    BE_AOIP_TRANS_LAY_ADD,              /* AoIP Transport Layer Address */
    BE_SPEECH_CODEC_LST,                /* Speech Codec List */
    BE_SPEECH_CODEC,                    /* Speech Codec */
    BE_CALL_ID,                         /* Call Identifier */
    BE_CALL_ID_LST,                     /* Call Identifier List */
    BE_A_ITF_SEL_FOR_RESET,             /* A-Interface Selector for RESET */
    BE_UDEF_130,                        /* Undefined */
    BE_KC128,                           /* Kc128 */
    BE_CSG_ID,                          /* CSG Identifier */
    BE_REDIR_ATT_FLG,                   /* Redirect Attempt Flag               3.2.2.111    */
    BE_REROUTE_REJ_CAUSE,               /* Reroute Reject Cause                3.2.2.112    */
    BE_SEND_SEQN,                       /* Send Sequence Number                3.2.2.113    */
    BE_REROUTE_OUTCOME,                 /* Reroute complete outcome            3.2.2.114    */
    BE_GLOBAL_CALL_REF,                 /* Global Call Reference               3.2.2.115    */
    BE_LCLS_CONF,                       /* LCLS-Configuration                  3.2.2.116    */
    BE_LCLS_CON_STATUS_CONTROL,         /* LCLS-Connection-Status-Control      3.2.2.117    */
    BE_LCLS_CORR_NOT_NEEDED,            /* LCLS-Correlation-Not-Needed         3.2.2.118    */
    BE_LCLS_BSS_STATUS,                 /* LCLS-BSS-Status                     3.2.2.119    */
    BE_LCLS_BREAK_REQ,                  /* LCLS-Break-Request                  3.2.2.120    */
    BE_CSFB_IND,                        /* CSFB Indication                     3.2.2.121    */
    BE_CS_TO_PS_SRVCC,                  /* CS to PS SRVCC                      3.2.2.122    */
    BE_SRC_ENB_2_TGT_ENB_TRANSP_INF,    /* Source eNB to target eNB transparent information (E-UTRAN)" 3.2.2.123    */
    BE_CS_TO_PS_SRVCC_IND,              /* CS to PS SRVCC Indication           3.2.2.124    */
    BE_CN_TO_MS_TRANSP,                 /* CN to MS transparent information    3.2.2.125    */
    BE_SELECTED_PLMN_ID,                /* Selected PLMN ID                    3.2.2.126    */
    BE_LAST_USED_E_UTRAN_PLMN_ID,       /* Last used E-UTRAN PLMN ID           3.2.2.127    */
    BE_UDEF_150,                         /* Undefined Old Location Area Identification    3.2.2.128 */
    BE_UDEF_151,                         /* Undefined Attach Indicator    3.2.2.129 */
    BE_UDEF_152,                         /* Undefined Selected Operator    3.2.2.130 */
    BE_UDEF_153,                         /* Undefined PS Registered Operator    3.2.2.131 */
    BE_UDEF_154,                         /* Undefined CS Registered Operator    3.2.2.132*/
    BE_UDEF_155,                         /* Undefined */
    BE_UDEF_156,                         /* Undefined */
    BE_UDEF_157,                         /* Undefined */
    BE_UDEF_158,                         /* Undefined */
    BE_UDEF_159,                         /* Undefined */
    BE_UDEF_160,                         /* Undefined */
    BE_UDEF_161,                         /* Undefined */
    BE_UDEF_162,                         /* Undefined */
    BE_UDEF_163,                         /* Undefined */
    BE_UDEF_164,                         /* Undefined */
    BE_UDEF_165,                         /* Undefined */
    BE_UDEF_166,                         /* Undefined */
    BE_UDEF_167,                         /* Undefined */
    BE_UDEF_168,                         /* Undefined */
    BE_UDEF_169,                         /* Undefined */
    BE_UDEF_170,                         /* Undefined */
    BE_UDEF_171,                         /* Undefined */
    BE_UDEF_172,                         /* Undefined */
    BE_UDEF_173,                         /* Undefined */
    BE_UDEF_174,                         /* Undefined */
    BE_UDEF_175,                         /* Undefined */
    BE_UDEF_176,                         /* Undefined */
    BE_UDEF_177,                         /* Undefined */
    BE_UDEF_178,                         /* Undefined */
    BE_UDEF_179,                         /* Undefined */
    BE_UDEF_180,                         /* Undefined */
    BE_UDEF_181,                         /* Undefined */
    BE_UDEF_182,                         /* Undefined */
    BE_UDEF_183,                         /* Undefined */
    BE_UDEF_184,                         /* Undefined */
    BE_UDEF_185,                         /* Undefined */
    BE_UDEF_186,                         /* Undefined */
    BE_UDEF_187,                         /* Undefined */
    BE_UDEF_188,                         /* Undefined */
    BE_UDEF_189,                         /* Undefined */
    BE_UDEF_190,                         /* Undefined */
    BE_UDEF_191,                         /* Undefined */
    BE_UDEF_192,                         /* Undefined */
    BE_UDEF_193,                         /* Undefined */
    BE_UDEF_194,                         /* Undefined */
    BE_UDEF_195,                         /* Undefined */
    BE_UDEF_196,                         /* Undefined */
    BE_UDEF_197,                         /* Undefined */
    BE_UDEF_198,                         /* Undefined */
    BE_UDEF_199,                         /* Undefined */
    BE_UDEF_200,                         /* Undefined */
    BE_UDEF_201,                         /* Undefined */
    BE_UDEF_202,                         /* Undefined */
    BE_UDEF_203,                         /* Undefined */
    BE_UDEF_204,                         /* Undefined */
    BE_UDEF_205,                         /* Undefined */
    BE_UDEF_206,                         /* Undefined */
    BE_UDEF_207,                         /* Undefined */
    BE_UDEF_208,                         /* Undefined */
    BE_UDEF_209,                         /* Undefined */
    BE_UDEF_210,                         /* Undefined */
    BE_UDEF_211,                         /* Undefined */
    BE_UDEF_212,                         /* Undefined */
    BE_UDEF_213,                         /* Undefined */
    BE_UDEF_214,                         /* Undefined */
    BE_UDEF_215,                         /* Undefined */
    BE_UDEF_216,                         /* Undefined */
    BE_UDEF_217,                         /* Undefined */
    BE_UDEF_218,                         /* Undefined */
    BE_UDEF_219,                         /* Undefined */
    BE_UDEF_220,                         /* Undefined */
    BE_UDEF_221,                         /* Undefined */
    BE_UDEF_222,                         /* Undefined */
    BE_UDEF_223,                         /* Undefined */
    BE_UDEF_224,                         /* Undefined */
    BE_UDEF_225,                         /* Undefined */
    BE_UDEF_226,                         /* Undefined */
    BE_UDEF_227,                         /* Undefined */
    BE_UDEF_228,                         /* Undefined */
    BE_UDEF_229,                         /* Undefined */
    BE_UDEF_230,                         /* Undefined */
    BE_UDEF_231,                         /* Undefined */
    BE_UDEF_232,                         /* Undefined */
    BE_UDEF_233,                         /* Undefined */
    BE_UDEF_234,                         /* Undefined */
    BE_UDEF_235,                         /* Undefined */
    BE_UDEF_236,                         /* Undefined */
    BE_UDEF_237,                         /* Undefined */
    BE_UDEF_238,                         /* Undefined */
    BE_UDEF_239,                         /* Undefined */
    BE_OSMOCOM_OSMUX_SUPPORT = 0xf0,    /* Osmocom extension: Osmux Support */
    BE_OSMOCOM_OSMUX_CID = 0xf1,        /* Osmocom extension: Osmux CID */
    BE_NONE                             /* NONE */
}
bssmap_elem_idx_t;

typedef enum
{
    /* BSSMAP LE Elements */
    DE_BMAPLE_LCSQOS,           /* LCS QOS */
    DE_BMAPLE_LCS_PRIO,         /* LCS Priority */
    DE_BMAPLE_LOC_TYPE,         /* Location Type */
    DE_BMAPLE_GANSS_LOC_TYPE,   /* GANSS Location Type */
    DE_BMAPLE_GEO_LOC,          /* 10.9 Geographic Location */
    DE_BMAPLE_POS_DATA,         /* Positioning Data */
    DE_BMAPLE_GANSS_POS_DATA,   /* GANSS Positioning Data */
    DE_BMAPLE_VELOC_DATA,       /* Velocity Data */
    DE_BMAPLE_LCS_CAUSE,        /* LCS Cause */
    DE_BMAPLE_LCS_CLIENT_TYPE,  /* LCS Client Type */
    DE_BMAPLE_APDU,             /* 10.3 APDU */
    DE_BMAPLE_NETWORK_ELEM_ID,  /* Network Element Identity */
    DE_BMAPLE_REQ_GPS_ASSIST_D, /* 10.10 Requested GPS Assistance Data */
    DE_BMAPLE_REQ_GNSS_ASSIST_D,/* Requested GANSS Assistance Data */
    DE_BMAPLE_DECIPH_KEYS,      /* 10.8 Deciphering Keys */
    DE_BMAPLE_RETURN_ERROR_REQ, /* Return Error Request */
    DE_BMAPLE_RETURN_ERROR_CAUSE,   /* Return Error Cause */
    DE_BMAPLE_SEGMENTATION,     /* Segmentation */
    DE_BMAPLE_CLASSMARK_TYPE_3, /* Classmark Information Type 3 */
    DE_BMAPLE_CAUSE,            /* 10.4 Cause */
    DE_BMAPLE_CELL_IDENTIFIER,  /* 10.5 Cell Identifier */
    DE_BMAPLE_CHOSEN_CHANNEL,   /* 10.6 Chosen Channel */
    DE_BMAPLE_IMSI,             /* 10.11 IMSI */
    DE_BMAPLE_RES1,             /* Reserved */
    DE_BMAPLE_RES2,             /* Reserved */
    DE_BMAPLE_RES3,             /* Reserved */
    DE_BMAPLE_LCS_CAPABILITY,   /* LCS Capability */
    DE_BMAPLE_PACKET_MEAS_REP,  /* Packet Measurement Report */
    DE_BMAPLE_MEAS_CELL_ID,     /* Measured Cell Identity */
    DE_BMAPLE_IMEI,             /* IMEI */
    BMAPLE_NONE                 /* NONE */
}
bssmap_le_elem_idx_t;

typedef enum
{
    /* BSS LAP Elements 5 */
    DE_BLAP_RES1,           /* Reserved */
    DE_BLAP_TA,             /* Timing Advance */
    DE_BLAP_RES3,           /* Reserved */          /* (note) */
    DE_BLAP_RES4,           /* Cell Identity */
    DE_BLAP_RES5,           /* Reserved */          /* (note) */
    DE_BLAP_RES6,           /* Reserved */          /* (note) */
    DE_BLAP_RES7,           /* Reserved */          /* (note) */
    DE_BLAP_CH_DESC,        /* Channel Description */
    DE_BLAP_RES9,           /* Reserved */          /* (note) */
    DE_BLAP_RES10,          /* Reserved */          /* (note) */
    DE_BLAP_RES11,          /* Reserved */          /* (note) */
    DE_BLAP_MEAS_REP,       /* Measurement Report */
    DE_BLAP_RES13,          /* Reserved */          /* (note) */
    DE_BLAP_CAUSE,          /* Cause */
    DE_BLAP_RRLP_FLG,       /* RRLP Flag */
    DE_BLAP_RRLP_IE,        /* RRLP IE */
    DE_BLAP_CELL_ID_LIST,   /* Cell Identity List */
    DE_BLAP_ENH_MEAS_REP,   /* Enhanced Measurement Report */
    DE_BLAP_LAC,            /* Location Area Code */
    DE_BLAP_FREQ_LIST,      /* Frequency List */
    DE_BLAP_MS_POW,         /* MS Power */
    DE_BLAP_DELTA_TIME,     /* Delta Timer */
    DE_BLAP_SERV_CELL_ID,   /* Serving Cell Identifier */
    DE_BLAP_ENC_KEY,        /* Encryption Key (Kc) */
    DE_BLAP_CIP_M_SET,      /* Cipher Mode Setting */
    DE_BLAP_CH_MODE,        /* Channel Mode */
    DE_BLAP_POLL_REP,       /* Polling Repetition */
    DE_BLAP_PKT_CH_DESC,    /* Packet Channel Description */
    DE_BLAP_TLLI,           /* TLLI */
    DE_BLAP_TFI,            /* TFI */
    DE_BLAP_START_TIME,     /* Starting Time */
    BSSLAP_NONE             /* NONE */
}
bsslap_elem_idx_t;

typedef enum
{
    /* Mobility Management Information Elements [3] 10.5.3 */
    DE_AUTH_PARAM_RAND,             /* Authentication Parameter RAND */
    DE_AUTH_PARAM_AUTN,             /* Authentication Parameter AUTN (UMTS and EPS authentication challenge) */
    DE_AUTH_RESP_PARAM,             /* Authentication Response Parameter */
    DE_AUTH_RESP_PARAM_EXT,         /* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
    DE_AUTH_FAIL_PARAM,             /* Authentication Failure Parameter (UMTS and EPS authentication challenge) */
    DE_CM_SRVC_TYPE,                /* CM Service Type */
    DE_ID_TYPE,                     /* Identity Type */
    DE_LOC_UPD_TYPE,                /* Location Updating Type */
    DE_NETWORK_NAME,                /* Network Name */
    DE_REJ_CAUSE,                   /* Reject Cause */
    DE_FOP,                         /* Follow-on Proceed */
    DE_TIME_ZONE,                   /* Time Zone */
    DE_TIME_ZONE_TIME,              /* Time Zone and Time */
    DE_CTS_PERM,                    /* CTS Permission */
    DE_LSA_ID,                      /* LSA Identifier */
    DE_DAY_SAVING_TIME,             /* Daylight Saving Time */
    DE_EMERGENCY_NUM_LIST,          /* Emergency Number List */
    DE_ADD_UPD_PARAMS,              /* Additional update parameters */
    DE_MM_TIMER,                    /* MM Timer */
    /* Call Control Information Elements 10.5.4 */
    DE_AUX_STATES,                  /* Auxiliary States */
    DE_BEARER_CAP,                  /* Bearer Capability */
    DE_CC_CAP,                      /* Call Control Capabilities */
    DE_CALL_STATE,                  /* Call State */
    DE_CLD_PARTY_BCD_NUM,           /* Called Party BCD Number */
    DE_CLD_PARTY_SUB_ADDR,          /* Called Party Subaddress */
    DE_CLG_PARTY_BCD_NUM,           /* Calling Party BCD Number */
    DE_CLG_PARTY_SUB_ADDR,          /* Calling Party Subaddress */
    DE_CAUSE,                       /* Cause */
    DE_CLIR_SUP,                    /* CLIR Suppression */
    DE_CLIR_INV,                    /* CLIR Invocation */
    DE_CONGESTION,                  /* Congestion Level */
    DE_CONN_NUM,                    /* Connected Number */
    DE_CONN_SUB_ADDR,               /* Connected Subaddress */
    DE_FACILITY,                    /* Facility */
    DE_HLC,                         /* High Layer Compatibility */
    DE_KEYPAD_FACILITY,             /* Keypad Facility */
    DE_LLC,                         /* Low Layer Compatibility */
    DE_MORE_DATA,                   /* More Data */
    DE_NOT_IND,                     /* Notification Indicator */
    DE_PROG_IND,                    /* Progress Indicator */
    DE_RECALL_TYPE,                 /* Recall type $(CCBS)$ */
    DE_RED_PARTY_BCD_NUM,           /* Redirecting Party BCD Number */
    DE_RED_PARTY_SUB_ADDR,          /* Redirecting Party Subaddress */
    DE_REPEAT_IND,                  /* Repeat Indicator */
    DE_REV_CALL_SETUP_DIR,          /* Reverse Call Setup Direction */
    DE_SETUP_CONTAINER,             /* SETUP Container $(CCBS)$ */
    DE_SIGNAL,                      /* Signal */
    DE_SS_VER_IND,                  /* SS Version Indicator */
    DE_USER_USER,                   /* User-user */
    DE_ALERT_PATTERN,               /* Alerting Pattern $(NIA)$ */
    DE_ALLOWED_ACTIONS,             /* Allowed Actions $(CCBS)$ */
    DE_SI,                          /* Stream Identifier */
    DE_NET_CC_CAP,                  /* Network Call Control Capabilities */
    DE_CAUSE_NO_CLI,                /* Cause of No CLI */
    DE_SUP_CODEC_LIST,              /* Supported Codec List */
    DE_SERV_CAT,                    /* Service Category */
    DE_REDIAL,                      /* 10.5.4.34 Redial */
    DE_NET_INIT_SERV_UPG,           /* 10.5.4.35 Network-initiated Service Upgrade ind */
    /* Short Message Service Information Elements [5] 8.1.4 */
    DE_CP_USER_DATA,                /* CP-User Data */
    DE_CP_CAUSE,                    /* CP-Cause */
    /* Tests procedures information elements 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0 */
    DE_TP_SUB_CHANNEL,                  /* Close TCH Loop Cmd Sub-channel */
    DE_TP_ACK,                          /* Open Loop Cmd Ack */
    DE_TP_LOOP_TYPE,                    /* Close Multi-slot Loop Cmd Loop type*/
    DE_TP_LOOP_ACK,                     /* Close Multi-slot Loop Ack Result */
    DE_TP_TESTED_DEVICE,                /* Test Interface Tested device */
    DE_TP_PDU_DESCRIPTION,              /* GPRS Test Mode Cmd PDU description */
    DE_TP_MODE_FLAG,                    /* GPRS Test Mode Cmd Mode flag */
    DE_TP_EGPRS_MODE_FLAG,              /* EGPRS Start Radio Block Loopback Cmd Mode flag */
    DE_TP_MS_POSITIONING_TECHNOLOGY,    /* MS Positioning Technology */
    DE_TP_UE_TEST_LOOP_MODE,            /* Close UE Test Loop Mode */
    DE_TP_UE_POSITIONING_TECHNOLOGY,    /* UE Positioning Technology */
    DE_TP_RLC_SDU_COUNTER_VALUE,        /* RLC SDU Counter Value */
    DE_TP_EPC_UE_TEST_LOOP_MODE,        /* UE Test Loop Mode */
    DE_TP_EPC_UE_TL_A_LB_SETUP,         /* UE Test Loop Mode A LB Setup */
    DE_TP_EPC_UE_TL_B_LB_SETUP,         /* UE Test Loop Mode B LB Setup */
    DE_TP_EPC_UE_TL_C_SETUP,            /* UE Test Loop Mode C Setup */
    DE_TP_EPC_UE_TL_D_SETUP,            /* UE Test Loop Mode D Setup */
    DE_TP_EPC_UE_TL_E_SETUP,            /* UE Test Loop Mode E Setup */
    DE_TP_EPC_UE_TL_F_SETUP,            /* UE Test Loop Mode F Setup */
    DE_TP_EPC_UE_TL_GH_SETUP,           /* UE Test Loop Mode GH Setup */
    DE_TP_EPC_UE_POSITIONING_TECHNOLOGY,/* UE Positioning Technology */
    DE_TP_EPC_MBMS_PACKET_COUNTER_VALUE,/* MBMS Packet Counter Value */
    DE_TP_EPC_ELLIPSOID_POINT_WITH_ALT, /* ellipsoidPointWithAltitude */
    DE_TP_EPC_HORIZONTAL_VELOCITY,      /* horizontalVelocity */
    DE_TP_EPC_GNSS_TOD_MSEC,            /* gnss-TOD-msec */
    /* Group Call Control Service Information Elements ETSI TS 100 948 V8.1.0 (GSM 04.68 version 8.1.0 Release 1999) */
    DE_GCC_CALL_REF,                    /* Call Reference */
    DE_GCC_CALL_STATE,                  /* Call state */
    DE_GCC_CAUSE,                       /* Cause */
    DE_GCC_ORIG_IND,                    /* Originator indication */
    DE_GCC_STATE_ATTR,                  /* State attributes */
    /* Broadcast Call Control Information Elements ETSI TS 144 069 V10.0.0 (3GPP TS 44.069 version 10.0.0 Release 10) */
    DE_BCC_CALL_REF,                    /* Call Reference */
    DE_BCC_CALL_STATE,                  /* Call state */
    DE_BCC_CAUSE,                       /* Cause */
    DE_BCC_ORIG_IND,                    /* Originator indication */
    DE_BCC_STATE_ATTR,                  /* State attributes */
    DE_BCC_COMPR_OTDI,                  /* Compressed otdi */
    DE_NONE                             /* NONE */
}
dtap_elem_idx_t;

typedef enum
{
    /* GPRS Mobility Management Information Elements [3] 10.5.5 */
    DE_ADD_UPD_TYPE,                /* [11] 10.5.5.0 Additional Update Type */
    DE_ATTACH_RES,                  /* [7] 10.5.5.1 Attach Result*/
    DE_ATTACH_TYPE,                 /* [7] 10.5.5.2 Attach Type */
    DE_CIPH_ALG,                    /* [7] 10.5.5.3 Ciphering Algorithm */
    DE_INTEG_ALG,                   /* [11] 10.5.5.3a Integrity Algorithm */
    DE_TMSI_STAT,                   /* [7] 10.5.5.4 TMSI Status */
    DE_DETACH_TYPE,                 /* [7] 10.5.5.5 Detach Type */
    DE_DRX_PARAM,                   /* [7] 10.5.5.6 DRX Parameter */
    DE_FORCE_TO_STAND,              /* [7] 10.5.5.7 Force to Standby */
    DE_FORCE_TO_STAND_H,            /* [7] 10.5.5.7 Force to Standby - Info is in the high nibble */
    DE_P_TMSI_SIG,                  /* [7] 10.5.5.8 P-TMSI Signature */
    DE_P_TMSI_SIG_2,                /* [7] 10.5.5.8a P-TMSI Signature 2 */
    DE_ID_TYPE_2,                   /* [7] 10.5.5.9 Identity Type 2 */
    DE_IMEISV_REQ,                  /* [7] 10.5.5.10 IMEISV Request */
    DE_REC_N_PDU_NUM_LIST,          /* [7] 10.5.5.11 Receive N-PDU Numbers List */
    DE_MS_NET_CAP,                  /* [7] 10.5.5.12 MS Network Capability */
    DE_MS_RAD_ACC_CAP,              /* [7] 10.5.5.12a MS Radio Access Capability */
    DE_GMM_CAUSE,                   /* [7] 10.5.5.14 GMM Cause */
    DE_RAI,                         /* [7] 10.5.5.15 Routing Area Identification */
    DE_RAI_2,                       /* [7] 10.5.5.15a Routing Area Identification 2 */
    DE_UPD_RES,                     /* [7] 10.5.5.17 Update Result */
    DE_UPD_TYPE,                    /* [7] 10.5.5.18 Update Type */
    DE_AC_REF_NUM,                  /* [7] 10.5.5.19 A&C Reference Number */
    DE_AC_REF_NUM_H,                /* A&C Reference Number - Info is in the high nibble */
    DE_SRVC_TYPE,                   /* [7] 10.5.5.20 Service Type */
    DE_CELL_NOT,                    /* [7] 10.5.5.21 Cell Notification */
    DE_PS_LCS_CAP,                  /* [7] 10.5.5.22 PS LCS Capability */
    DE_NET_FEAT_SUP,                /* [7] 10.5.5.23 Network Feature Support */
    DE_ADD_NET_FEAT_SUP,            /* [11] 10.5.5.23a Additional network feature support */
    DE_RAT_INFO_CONTAINER,          /* [7] 10.5.5.24 Inter RAT information container */
    DE_REQ_MS_INFO,                 /* [7] 10.5.5.25 Requested MS information */
    DE_UE_NETWORK_CAP,              /* [7] 10.5.5.26 UE network capability */
    DE_EUTRAN_IRAT_INFO_CONTAINER,  /* [7] 10.5.5.27 E-UTRAN inter RAT information container */
    DE_VOICE_DOMAIN_PREF,           /* [7] 10.5.5.28 Voice domain preference and UE's usage setting */
    DE_PTMSI_TYPE,                  /* [10] 10.5.5.29 P-TMSI type */
    DE_LAI_2,                       /* [10] 10.5.5.30 Location Area Identification 2 */
    DE_NET_RES_ID_CONT,             /* [11] 10.5.5.31 Network resource identifier container */
    DE_EXT_DRX_PARAMS,              /* [11] 10.5.5.32 Extended DRX parameters */
    DE_MAC,                         /* [11] 10.5.5.33 Message Authentication Code */
    DE_UP_INTEG_IND,                /* [11] 10.5.5.34 User Plane integrity indicator */
    DE_DCN_ID,                      /* [12] 10.5.5.35 DCN-ID */
    DE_PLMN_ID_CN_OPERATOR,         /* [12] 10.5.5.36 PLMN identity of the CN operator */
    DE_NON_3GPP_NW_PROV_POL,        /* [12] 10.5.5.37 Non-3GPP NW provided policies */
    /* Session Management Information Elements [3] 10.5.6 */
    DE_ACC_POINT_NAME,              /* Access Point Name */
    DE_NET_SAPI,                    /* Network Service Access Point Identifier */
    DE_PRO_CONF_OPT,                /* Protocol Configuration Options */
    DE_EXT_PRO_CONF_OPT,            /* Extended Protocol Configuration Options */
    DE_PD_PRO_ADDR,                 /* Packet Data Protocol Address */
    DE_QOS,                         /* Quality Of Service */
    DE_RE_ATTEMPT_IND,              /* Re-attempt indicator */
    DE_EXT_QOS,                     /* [13] Extended quality of service */
    DE_SM_CAUSE,                    /* SM Cause */
    DE_SM_CAUSE_2,                  /* SM Cause 2 */
    DE_LINKED_TI,                   /* Linked TI */
    DE_LLC_SAPI,                    /* LLC Service Access Point Identifier */
    DE_TEAR_DOWN_IND,               /* Tear Down Indicator */
    DE_PACKET_FLOW_ID,              /* Packet Flow Identifier */
    DE_TRAFFIC_FLOW_TEMPLATE,       /* Traffic Flow Template */
    DE_TMGI,                        /* Temporary Mobile Group Identity (TMGI) */
    DE_MBMS_BEARER_CAP,             /* MBMS bearer capabilities */
    DE_MBMS_PROT_CONF_OPT,          /* MBMS protocol configuration options */
    DE_ENH_NSAPI,                   /* Enhanced network service access point identifier */
    DE_REQ_TYPE,                    /* Request type */
    DE_SM_NOTIF_IND,                /* Notification indicator */
    DE_SM_CONNECTIVITY_TYPE,        /* Connectivity type */
    DE_SM_WLAN_OFFLOAD_ACCEPT,      /* WLAN offload acceptability */
    DE_NBIFOM_CONT,                 /* NBIFOM container */
    /* GPRS Common Information Elements [8] 10.5.7 */
    DE_PDP_CONTEXT_STAT,            /* [8] 10.5.7.1     PDP Context Status */
    DE_RAD_PRIO,                    /* [8] 10.5.7.2     Radio Priority */
    DE_GPRS_TIMER,                  /* [8] 10.5.7.3     GPRS Timer */
    DE_GPRS_TIMER_2,                /* [8] 10.5.7.4     GPRS Timer 2 */
    DE_GPRS_TIMER_3,                /* [10] 10.5.7.4a   GPRS Timer 3 */
    DE_RAD_PRIO_2,                  /* [8] 10.5.7.5     Radio Priority 2 */
    DE_MBMS_CTX_STATUS,             /* [8] 10.5.7.6     MBMS context status */
    DE_UPLINK_DATA_STATUS,          /* [8] 10.5.7.7     Uplink data status */
    DE_DEVICE_PROPERTIES,           /* [10] 10.5.7.8    Device properties */
    DE_GM_NONE                          /* NONE */
}
gm_elem_idx_t;

typedef enum
{
    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1  */
    DE_RR_BA_RANGE,                 /* [3]  10.5.2.1a    BA Range */
    DE_RR_CELL_CH_DSC,              /* [3]  10.5.2.1b    Cell Channel Description    */
    DE_RR_BA_LIST_PREF,             /* [3]  10.5.2.1c    BA List Pref */
    DE_RR_UTRAN_FREQ_LIST,          /* [3]  10.5.2.1d    UTRAN Frequency List */
    DE_RR_CELL_SELECT_INDIC,        /* [3]  10.5.2.1e    Cell selection indicator after release of all TCH and SDCCH IE */
    DE_RR_CELL_DSC,                 /* 10.5.2.2   RR Cell Description              */
    DE_RR_CELL_OPT_BCCH,            /* [3]  10.5.2.3    Cell Options (BCCH)        */
    DE_RR_CELL_OPT_SACCH,           /* [3]  10.5.2.3a   Cell Options (SACCH)       */
    DE_RR_CELL_SEL_PARAM,           /* [3]  10.5.2.4    Cell Selection Parameters  */
/*
 * [3]  10.5.2.4a   (void)
 */
    DE_RR_CH_DSC,                   /* [3]  10.5.2.5    Channel Description         */
    DE_RR_CH_DSC2,                  /* [3]  10.5.2.5a   Channel Description 2       */
    DE_RR_CH_DSC3,                  /* [3]  10.5.2.5c   Channel Description 3       */
    DE_RR_CH_MODE,                  /* [3]  10.5.2.6    Channel Mode                */
    DE_RR_CH_MODE2,                 /* [3]  10.5.2.7    Channel Mode 2              */
    DE_RR_UTRAN_CM,                 /* [3]  10.5.2.7a   UTRAN Classmark */
/* [3]  10.5.2.7b   (void) */
    DE_RR_CM_ENQ_MASK,              /* [3]  10.5.2.7c   Classmark Enquiry Mask      */
/* [3]  10.5.2.7d   GERAN Iu Mode Classmark information element                     */
    DE_RR_CHNL_NEEDED,              /* [3]  10.5.2.8    Channel Needed
 * [3]  10.5.2.8a   (void) */
    DE_RR_CHNL_REQ_DESC2,           /* [3]  10.5.2.8b   Channel Request Description 2 */
    DE_RR_CIP_MODE_SET,             /* [3]  10.5.2.9    Cipher Mode Setting         */
    DE_RR_CIP_MODE_RESP,            /* [3]  10.5.2.10   Cipher Response             */
    DE_RR_CTRL_CH_DESC,             /* [3]  10.5.2.11   Control Channel Description */
    DE_RR_DTM_INFO_DETAILS,         /* [3]  10.5.2.11a  DTM Information Details */
    DE_RR_DYN_ARFCN_MAP,            /* [3]  10.5.2.11b  Dynamic ARFCN Mapping       */
    DE_RR_FREQ_CH_SEQ,              /* [3]  10.5.2.12   Frequency Channel Sequence  */
    DE_RR_FREQ_LIST,                /* [3]  10.5.2.13   Frequency List              */
    DE_RR_FREQ_SHORT_LIST,          /* [3]  10.5.2.14   Frequency Short List        */
    DE_RR_FREQ_SHORT_LIST2,         /* [3]  10.5.2.14a  Frequency Short List 2      */
/* [3]  10.5.2.14b  Group Channel Description */
    DE_RR_GPRS_RESUMPTION,          /* [3]  10.5.2.14c  GPRS Resumption */
    DE_RR_GPRS_BROADCAST_INFORMATION, /* [3]  10.5.2.14d  GPRS broadcast information */
/* [3]  10.5.2.14e  Enhanced DTM CS Release Indication*/

    DE_RR_HO_REF,                   /* 10.5.2.15  Handover Reference                */

    DE_RR_IA_REST_OCT,              /* [3] 10.5.2.16 IA Rest Octets             */
    DE_RR_IAR_REST_OCT,             /* [3] 10.5.2.17 IAR Rest Octets                */
    DE_RR_IAX_REST_OCT,             /* [3] 10.5.2.18 IAX Rest Octets                */
    DE_RR_L2_PSEUDO_LEN,            /* [3] 10.5.2.19 L2 Pseudo Length               */
    DE_RR_MEAS_RES,                 /* [3] 10.5.2.20 Measurement Results        */
 /* [3] 10.5.2.20a GPRS Measurement Results */
    DE_RR_MOB_ALL,                  /* [3] 10.5.2.21 Mobile Allocation              */
    DE_RR_MOB_TIME_DIFF,            /* [3] 10.5.2.21a Mobile Time Difference        */
    DE_RR_MULTIRATE_CONF,           /* [3] 10.5.2.21aa MultiRate configuration      */
    DE_RR_MULT_ALL,                 /* [3] 10.5.2.21b Multislot Allocation          */
/*
 * [3] 10.5.2.21c NC mode
 */
    DE_RR_NEIGH_CELL_DESC,          /* [3] 10.5.2.22 Neighbour Cell Description */
    DE_RR_NEIGH_CELL_DESC2,         /* [3] 10.5.2.22a Neighbour Cell Description 2  */
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets */
    DE_RR_P1_REST_OCT,              /* [3] 10.5.2.23 P1 Rest Octets */
    DE_RR_P2_REST_OCT,              /* [3] 10.5.2.24 P2 Rest Octets */
    DE_RR_P3_REST_OCT,              /* [3] 10.5.2.25 P3 Rest Octets */
    DE_RR_PACKET_CH_DESC,           /* [3] 10.5.2.25a Packet Channel Description    */
    DE_RR_DED_MOD_OR_TBF,           /* [3] 10.5.2.25b Dedicated mode or TBF         */
    DE_RR_PKT_UL_ASS,               /* [3] 10.5.2.25c RR Packet Uplink Assignment */
    DE_RR_PKT_DL_ASS,               /* [3] 10.5.2.25d RR Packet Downlink Assignment */
    DE_RR_PKT_DL_ASS_TYPE2,         /* [3] 10.5.2.25d RR Packet Downlink Assignment Type 2 */
    DE_RR_PAGE_MODE,                /* [3] 10.5.2.26 Page Mode                      */
    DE_RR_NCC_PERM,                 /* [3] 10.5.2.27 NCC Permitted */
    DE_RR_POW_CMD,                  /* 10.5.2.28  Power Command                     */
    DE_RR_POW_CMD_AND_ACC_TYPE,     /* 10.5.2.28a Power Command and access type     */
    DE_RR_RACH_CTRL_PARAM,          /* [3] 10.5.2.29 RACH Control Parameters */
    DE_RR_REQ_REF,                  /* [3] 10.5.2.30 Request Reference              */
    DE_RR_CAUSE,                    /* 10.5.2.31  RR Cause                          */
    DE_RR_SYNC_IND,                 /* 10.5.2.39  Synchronization Indication        */
    DE_RR_SI1_REST_OCT,             /* [3] 10.5.2.32 SI1 Rest Octets */
/* [3] 10.5.2.33 SI 2bis Rest Octets */
    DE_RR_SI2TER_REST_OCT,          /* [3] 10.5.2.33a SI 2ter Rest Octets */
    DE_RR_SI2QUATER_REST_OCT,       /* [3] 10.5.2.33b SI 2quater Rest Octets */
    DE_RR_SI3_REST_OCT,             /* [3] 10.5.2.34 SI3 Rest Octets */
    DE_RR_SI4_REST_OCT,             /* [3] 10.5.2.35 SI4 Rest Octets */
    DE_RR_SI6_REST_OCT,             /* [3] 10.5.2.35a SI6 Rest Octets */
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
    DE_RR_SI13_REST_OCT,                /* [3] 10.5.2.37b SI13 Rest Octets */
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
    DE_RR_SI21_REST_OCT,            /* [3] 10.5.2.37m SI21 Rest Octets */
    DE_RR_STARTING_TIME,            /* [3] 10.5.2.38 Starting Time                  */
    DE_RR_TIMING_ADV,               /* [3] 10.5.2.40 Timing Advance                 */
    DE_RR_TIME_DIFF,                /* [3] 10.5.2.41 Time Difference                */
    DE_RR_TLLI,                     /* [3] 10.5.2.41a TLLI                          */
    DE_RR_TMSI_PTMSI,               /* [3] 10.5.2.42 TMSI/P-TMSI */
    DE_RR_VGCS_TAR_MODE_IND,        /* [3] 10.5.2.42a VGCS target mode Indication   */
    DE_RR_VGCS_CIP_PAR,             /* [3] 10.5.2.42b   VGCS Ciphering Parameters   */

    DE_RR_WAIT_IND,                 /* [3] 10.5.2.43 Wait Indication */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$ */
    DE_RR_EXT_MEAS_RESULT,      /* [3] 10.5.2.45 Extended Measurement Results */
    DE_RR_EXT_MEAS_FREQ_LIST,       /* [3] 10.5.2.46 Extended Measurement Frequency List */
    DE_RR_SUS_CAU,                  /* [3] 10.5.2.47 Suspension Cause               */
    DE_RR_APDU_ID,                  /* [3] 10.5.2.48 APDU ID */
    DE_RR_APDU_FLAGS,               /* [3] 10.5.2.49 APDU Flags */
    DE_RR_APDU_DATA,                /* [3] 10.5.2.50 APDU Data */
    DE_RR_HO_TO_UTRAN_CMD,          /* [3] 10.5.2.51 Handover To UTRAN Command */
/* [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
    DE_RR_SERV_SUP,                 /* 10.5.2.57 Service Support                        */
/* 10.5.2.58 MBMS p-t-m Channel Description
 */

    DE_RR_DED_SERV_INF,             /* [3] 10.5.2.59    Dedicated Service Information */

/*
 * 10.5.2.60 MPRACH Description
 * 10.5.2.61 Restriction Timer
 * 10.5.2.62 MBMS Session Identity
 * 10.5.2.63 Reduced group or broadcast call reference
 * 10.5.2.64 Talker Priority status
 * 10.5.2.65 Talker Identity
 * 10.5.2.66 Token
 * 10.5.2.67 PS Cause
 * 10.5.2.68 VGCS AMR Configuration
 */
    DE_RR_CARRIER_IND,              /* 10.5.2.69 Carrier Indication */
    DE_RR_FEATURE_INDICATOR,        /* 10.5.2.76 feature Indicator */
    DE_RR_EXTENDED_TSC_SET,         /* 10.5.2.82 Extended TSC Set */
    DE_RR_EC_REQUEST_REFERENCE,     /* 10.5.2.83 EC Request reference */
    DE_RR_EC_PKT_CH_DSC1,           /* 10.5.2.84 EC Packet Channel Description Type 1 */
    DE_RR_EC_PKT_CH_DSC2,           /* 10.5.2.85 EC Packet Channel Description Type 2 */
    DE_RR_EC_FUA,                   /* 10.5.2.86 EC Fixed Uplink Allocation */

    DE_RR_NONE                          /* NONE */
}
rr_elem_idx_t;

typedef enum
{
    DE_EPS_CMN_ADD_INFO,                        /* 9.9.2.0  Additional information */
    DE_EPS_CMN_DEVICE_PROPERTIES,               /* 9.9.2.0A Device properties */
    DE_EPS_CMN_EPS_BE_CTX_STATUS,               /* 9.9.2.1  EPS bearer context status */
    DE_EPS_CMN_LOC_AREA_ID,                     /* 9.9.2.2  Location area identification */
    DE_EPS_CMN_MOB_ID,                          /* 9.9.2.3  Mobile identity */
    DE_EPS_MS_CM_2,                             /* 9.9.2.4  Mobile station classmark 2 */
    DE_EPS_MS_CM_3,                             /* 9.9.2.5  Mobile station classmark 3 */
    DE_EPS_NAS_SEC_PAR_FROM_EUTRA,              /* 9.9.2.6  NAS security parameters from E-UTRA */
    DE_EPS_NAS_SEC_PAR_TO_EUTRA,                /* 9.9.2.7  NAS security parameters to E-UTRA */

    DE_EPS_CMN_PLM_LST,                         /* 9.9.2.8  PLMN list */
    DE_EPS_CMN_SUP_CODEC_LST,                   /* 9.9.2.6  9.9.2.10    Supported codec list */
    DE_EPS_COMMON_NONE                          /* NONE */
}
nas_eps_common_elem_idx_t;

typedef enum
{
    /* 9.9.3    EPS Mobility Management (EMM) information elements */
    DE_EMM_ADD_UPD_RES,         /* 9.9.3.0A Additional update result */
    DE_EMM_ADD_UPD_TYPE,        /* 9.9.3.0B Additional update type */
    DE_EMM_AUTH_FAIL_PAR,       /* 9.9.3.1  Authentication failure parameter (dissected in packet-gsm_a_dtap.c)*/
    DE_EMM_AUTN,                /* 9.9.3.2  Authentication parameter AUTN */
    DE_EMM_AUTH_PAR_RAND,       /* 9.9.3.3  Authentication parameter RAND */
    DE_EMM_RAT_UTIL_CNTRL,      /* 9.9.3.3A RAT utilization control */
    DE_EMM_AUTH_RESP_PAR,       /* 9.9.3.4  Authentication response parameter */
    DE_EMM_SMS_SERVICES_STATUS, /* 9.9.3.4B SMS services status */
    DE_EMM_CSFB_RESP,           /* 9.9.3.5  CSFB response */
    DE_EMM_DAYL_SAV_T,          /* 9.9.3.6  Daylight saving time */
    DE_EMM_DET_TYPE,            /* 9.9.3.7  Detach type */
    DE_EMM_DRX_PAR,             /* 9.9.3.8  DRX parameter (dissected in packet-gsm_a_gm.c)*/
    DE_EMM_CAUSE,               /* 9.9.3.9  EMM cause */
    DE_EMM_ATT_RES,             /* 9.9.3.10 EPS attach result (Coded inline */
    DE_EMM_ATT_TYPE,            /* 9.9.3.11 EPS attach type (Coded Inline)*/
    DE_EMM_EPS_MID,             /* 9.9.3.12 EPS mobile identity */
    DE_EMM_EPS_NET_FEATURE_SUP, /* 9.9.3.12A EPS network feature support */
    DE_EMM_EPS_UPD_RES,         /* 9.9.3.13 EPS update result ( Coded inline)*/
    DE_EMM_EPS_UPD_TYPE,        /* 9.9.3.14 EPS update type */
    DE_EMM_ESM_MSG_CONT,        /* 9.9.3.15 ESM message conta */
    DE_EMM_GPRS_TIMER,          /* 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
    DE_EMM_GPRS_TIMER_2,        /* 9.9.3.16A GPRS timer 2, See subclause 10.5.7.4 in 3GPP TS 24.008. */
    DE_EMM_GPRS_TIMER_3,        /* 9.9.3.16B GPRS timer 3, See subclause 10.5.7.4a in 3GPP TS 24.008. */
    DE_EMM_ID_TYPE_2,           /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    DE_EMM_IMEISV_REQ,          /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    DE_EMM_KSI_AND_SEQ_NO,      /* 9.9.3.19 KSI and sequence number */
    DE_EMM_MS_NET_CAP,          /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
    DE_EMM_MS_NET_FEAT_SUP,     /* 9.9.3.20A MS network feature support, See subclause 10.5.1.15 in 3GPP TS 24.008. */
    DE_EMM_NAS_KEY_SET_ID,      /* 9.9.3.21 NAS key set identifier (coded inline)*/
    DE_EMM_NAS_MSG_CONT,        /* 9.9.3.22 NAS message container */
    DE_EMM_NAS_SEC_ALGS,        /* 9.9.3.23 NAS security algorithms */
    DE_EMM_NET_NAME,            /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
    DE_EMM_NONCE,               /* 9.9.3.25 Nonce */
    DE_EMM_PAGING_ID,           /* 9.9.3.25A Paging identity */
    DE_EMM_P_TMSI_SIGN,         /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
    DE_EMM_EXT_CAUSE,           /* 9.9.3.26A Extended EMM cause */
    DE_EMM_SERV_TYPE,           /* 9.9.3.27 Service type */
    DE_EMM_SHORT_MAC,           /* 9.9.3.28 Short MAC */
    DE_EMM_TZ,                  /* 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
    DE_EMM_TZ_AND_T,            /* 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
    DE_EMM_TMSI_STAT,           /* 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
    DE_EMM_TRAC_AREA_ID,        /* 9.9.3.32 Tracking area identity */
    DE_EMM_TRAC_AREA_ID_LST,    /* 9.9.3.33 Tracking area identity list */
    DE_EMM_UE_NET_CAP,          /* 9.9.3.34 UE network capability */
    DE_EMM_UE_RA_CAP_INF_UPD_NEED, /* 9.9.3.35 UE radio capability information update needed */
    DE_EMM_UE_SEC_CAP,          /* 9.9.3.36 UE security capability */
    DE_EMM_EMERG_NUM_LIST,      /* 9.9.3.37 Emergency Number List */
    DE_EMM_EXT_EMERG_NUM_LIST,  /* 9.9.3.37a Extended Emergency Number List */
    DE_EMM_CLI,                 /* 9.9.3.38 CLI */
    DE_EMM_SS_CODE,             /* 9.9.3.39 SS Code */
    DE_EMM_LCS_IND,             /* 9.9.3.40 LCS indicator */
    DE_EMM_LCS_CLIENT_ID,       /* 9.9.3.41 LCS client identity */
    DE_EMM_GEN_MSG_CONT_TYPE,   /* 9.9.3.42 Generic message container type */
    DE_EMM_GEN_MSG_CONT,        /* 9.9.3.43 Generic message container */
    DE_EMM_VOICE_DMN_PREF,      /* 9.9.3.44 Voice domain preference and UE's usage setting */
    DE_EMM_GUTI_TYPE,           /* 9.9.3.45 GUTI type */
    DE_EMM_EXT_DRX_PARAMS,      /* 9.9.3.46 Extended DRX parameters */
    DE_EMM_DATA_SERV_TYPE,      /* 9.9.3.47 Data service type */
    DE_EMM_DCN_ID,              /* 9.9.3.48 DCN-ID, See subclause 10.5.5.35 in 3GPP TS 24.008 */
    DE_EMM_NON_3GPP_NW_PROV_POL, /* 9.9.3.49 Non-3GPP NW provided policies, See subclause 10.5.5.37 in 3GPP TS 24.008 */
    DE_EMM_HASH_MME,            /* 9.9.3.50 HashMME */
    DE_EMM_REPLAYED_NAS_MSG_CONT, /* 9.9.3.51 Replayed NAS message container */
    DE_EMM_NETWORK_POLICY,      /* 9.9.3.52 Network policy */
    DE_EMM_UE_ADD_SEC_CAP,      /* 9.9.3.53 UE additional security capability */
    DE_EMM_UE_STATUS,           /* 9.9.3.54 UE status */
    DE_EMM_ADD_INFO_REQ,        /* 9.9.3.55 Additional information requested */
    DE_EMM_CIPH_KEY_DATA,       /* 9.9.3.56 Ciphering key data */
    DE_EMM_N1_UE_NETWORK_CAP,   /* 9.9.3.57 N1 UE network capability */
    DE_EMM_UE_RADIO_CAP_ID_AVAIL, /* 9.9.3.58 UE radio capability ID availability */
    DE_EMM_UE_RADIO_CAP_ID_REQ, /* 9.9.3.59 UE radio capability ID request */
    DE_EMM_UE_RADIO_CAP_ID,     /* 9.9.3.60 UE radio capability ID */
    DE_EMM_UE_RADIO_CAP_ID_DEL_IND, /* 9.9.3.61 UE radio capability ID deletion indication */
    DE_EMM_WUS_ASSIST_INFO,     /* 9.9.3.62 WUS assistance information */
    DE_EMM_NB_S1_DRX_PARAM,     /* 9.9.3.63 NB-S1 DRX parameter */
    DE_EMM_IMSI_OFFSET,         /* 9.9.3.64 IMSI offset */
    DE_EMM_UE_REQUEST_TYPE,     /* 9.9.3.65 UE request type */
    DE_EMM_PAGING_RESTRICTION,  /* 9.9.3.66 Paging restriction */
    DE_EMM_EPS_ADD_REQ_RESULT,  /* 9.9.3.67 EPS additional request result */
    DE_EMM_UNAVAIL_INFO,        /* 9.9.3.69 Unavailability information */
    DE_EMM_UNAVAIL_CONFIG,      /* 9.9.3.70 Unavailability configuration */
    DE_EMM_UE_INFO_REQ,         /* 9.9.3.71 UE information request */
    DE_EMM_UE_COARSE_LOC_INFO,  /* 9.9.3.72 UE coarse location information */
    DE_EMM_NONE                 /* NONE */
}
nas_emm_elem_idx_t;

/* 9.9.4 EPS Session Management (ESM) information elements */
typedef enum
{
    DE_ESM_APN,                     /* 9.9.4.1 Access point name */
    DE_ESM_APN_AGR_MAX_BR,          /* 9.9.4.2 APN aggregate maximum bit rate */
    DE_ESM_CONNECTIVITY_TYPE,       /* 9.9.4.2A Connectivity type */
    DE_ESM_EPS_QOS,                 /* 9.9.4.3 EPS quality of service */
    DE_ESM_CAUSE,                   /* 9.9.4.4 ESM cause */
    DE_ESM_INF_TRF_FLG,             /* 9.9.4.5 ESM information transfer flag */
    DE_ESM_LNKED_EPS_B_ID,          /* 9.9.4.6 Linked EPS bearer identity  */
    DE_ESM_LLC_SAPI,                /* 9.9.4.7 LLC service access point identifier */
    DE_ESM_NOTIF_IND,               /* 9.9.4.7a Notification indicator */
    DE_ESM_P_FLW_ID,                /* 9.9.4.8 Packet flow identifier  */
    DE_ESM_PDN_ADDR,                /* 9.9.4.9 PDN address */
    DE_ESM_PDN_TYPE,                /* 9.9.4.10 PDN type */
    DE_ESM_PROT_CONF_OPT,           /* 9.9.4.11 Protocol configuration options */
    DE_ESM_QOS,                     /* 9.9.4.12 Quality of service */
    DE_ESM_RA_PRI,                  /* 9.9.4.13 Radio priority  */
    DE_ESM_RE_ATTEMPT_IND,          /* 9.9.4.13a Re-attempt indicator */
    DE_ESM_REQ_TYPE,                /* 9.9.4.14 Request type */
    DE_ESM_TRAF_FLOW_AGR_DESC,      /* 9.9.4.15 Traffic flow aggregate description */
    DE_ESM_TRAF_FLOW_TEMPL,         /* 9.9.4.16 Traffic flow template */
    DE_ESM_TID,                     /* 9.9.4.17 Transaction identifier */
    DE_ESM_WLAN_OFFLOAD_ACCEPT,     /* 9.9.4.18 WLAN offload acceptability */
    DE_ESM_NBIFOM_CONT,             /* 9.9.4.19 NBIFOM container */
    DE_ESM_REMOTE_UE_CONTEXT_LIST,  /* 9.9.4.20 Remote UE context list */
    DE_ESM_PKMF_ADDRESS,            /* 9.9.4.21 PKMF address */
    DE_ESM_HDR_COMPR_CONFIG,        /* 9.9.4.22 Header compression configuration */
    DE_ESM_CTRL_PLANE_ONLY_IND,     /* 9.9.4.23 Control plane only indication */
    DE_ESM_USER_DATA_CONT,          /* 9.9.4.24 User data container */
    DE_ESM_REL_ASSIST_IND,          /* 9.9.4.25 Release assistance indication */
    DE_ESM_EXT_PCO,                 /* 9.9.4.26 Extended protocol configuration options */
    DE_ESM_HDR_COMPR_CONFIG_STATUS, /* 9.9.4.27 Header compression configuration status */
    DE_ESM_SERV_PLMN_RATE_CTRL,     /* 9.9.4.28 Serving PLMN rate control */
    DE_ESM_EXT_APN_AGR_MAX_BR,      /* 9.9.4.29 Extended APN aggregate maximum bit rate */
    DE_ESM_EXT_EPS_QOS,             /* 9.9.4.30 Extended EPS quality of service */
    DE_ESM_NONE                     /* NONE */
}
nas_esm_elem_idx_t;

typedef enum
{

    DE_SGSAP_IMSI,                                  /* 9.4.6 IMSI*/
    DE_SGSAP_VLR_NAME,                              /* 9.4.22 VLR name*/
    DE_SGSAP_TMSI,                                  /* 9.4.20 TMSI */
    DE_SGSAP_LOC_AREA_ID,                           /* 9.4.11 Location area identifier */
    DE_SGSAP_CH_NEEDED,                             /* 9.4.23 Channel Needed */
    DE_SGSAP_EMLPP_PRIO,                            /* 9.4.24 eMLPP Priority*/
    DE_SGSAP_TMSI_STATUS,                           /* 9.4.21 TMSI status */
    DE_SGSAP_SGS_CAUSE,                             /* 9.4.18 SGs cause*/
    DE_SGSAP_MME_NAME,                              /* 9.4.13 MME name*/
    DE_SGSAP_EPS_LOC_UPD_TYPE,                      /* 9.4.2 EPS location update type*/
    DE_SGSAP_GLOBAL_CN_ID,                          /* 9.4.4 Global CN-Id*/

    DE_SGSAP_UDEF_11,                               /* Undefined */
    DE_SGSAP_UDEF_12,                               /* Undefined */

    DE_SGSAP_MID,                                   /* 9.4.14 Mobile identity*/
    DE_SGSAP_REJ_CAUSE,                             /* 9.4.16 Reject cause */
    DE_SGSAP_IMSI_DET_EPS,                          /* 9.4.7 IMSI detach from EPS service type */
    DE_SGSAP_IMSI_DET_NON_EPS,                      /* 9.4.8 IMSI detach from non-EPS service type */

    DE_SGSAP_IMEISV,                                /* 9.4.5 IMEISV */
    DE_SGSAP_NAS_MSG_CONTAINER,                     /* 9.4.15 NAS message container*/
    DE_SGSAP_MM_INFO,                               /* 9.4.12 MM information*/

    DE_SGSAP_UDEF_20,                               /* Undefined */
    DE_SGSAP_UDEF_21,                               /* Undefined */
    DE_SGSAP_UDEF_22,                               /* Undefined */

    DE_SGSAP_ERR_MSG,                               /* 9.4.3 Erroneous message*/
    DE_SGSAP_CLI,                                   /* 9.4.1 CLI */
    DE_SGSAP_LCS_CLIENT_ID,                         /* 9.4.9 LCS client identity */
    DE_SGSAP_LCS_INDIC,                             /* 9.4.10 LCS indicator */
    DE_SGSAP_SS_CODE,                               /* 9.4.19 SS code */
    DE_SGSAP_SERV_INDIC,                            /* 9.4.17 Service indicator */
    DE_SGSAP_UE_TZ,                                 /* 9.4.21b UE Time Zone */
    DE_SGSAP_MSC_2,                                 /* 9.4.14a Mobile Station Classmark 2 */
    DE_SGSAP_TAID,                                  /* 9.4.21a Tracking Area Identity */
    DE_SGSAP_ECGI,                                  /* 9.4.3a E-UTRAN Cell Global Identity */
    DE_SGSAP_UE_EMM_MODE,                           /* 9.4.21c UE EMM mode*/
    DE_SGSAP_ADD_PAGING_IND,                        /* 9.4.25 Additional paging indicators */
    DE_SGSAP_TMSI_BASED_NRI_CONT,                   /* 9.4.26 TMSI based NRI container */
    DE_SGSAP_SELECTED_CS_DMN_OP,                    /* 9.4.27 Selected CS domain operator */

    DE_SGAP_NONE                            /* NONE */
}
sgsap_elem_idx_t;

typedef enum
{
    DE_NAS_5GS_MM_5GMM_CAP,                  /* 9.11.3.1     5GMM capability*/
    DE_NAS_5GS_MM_5GMM_CAUSE,                /* 9.11.3.2     5GMM cause*/
    DE_NAS_5GS_MM_5GS_DRX_PARAM,             /* 9.11.3.2A    5GS DRX parameters*/
    DE_NAS_5GS_MM_5GS_IDENTITY_TYPE,         /* 9.11.3.3     5GS identity type*/
    DE_NAS_5GS_MM_5GS_MOBILE_ID,             /* 9.11.3.4     5GS mobile identity*/
    DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,           /* 9.11.3.5     5GS network feature support*/
    DE_NAS_5GS_MM_5GS_REG_RES,               /* 9.11.3.6     5GS registration result*/
    DE_NAS_5GS_MM_5GS_REG_TYPE,              /* 9.11.3.7     5GS registration type*/
    DE_NAS_5GS_MM_5GS_TA_ID,                 /* 9.11.3.8     5GS tracking area identity */
    DE_NAS_5GS_MM_5GS_TA_ID_LIST,            /* 9.11.3.9     5GS tracking area identity list */
    DE_NAS_5GS_MM_UPDATE_TYPE,               /* 9.11.3.9A    5GS update type */
    DE_NAS_5GS_MM_ABBA,                      /* 9.11.3.10    ABBA */
                                             /* 9.11.3.11    void */
    DE_NAS_5GS_MM_ADD_5G_SEC_INF,            /* 9.11.3.12    Additional 5G security information */
    DE_NAS_5GS_MM_ADD_INF_REQ,               /* 9.11.3.12A   Additional information requested */
    DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,         /* 9.11.3.13    Allowed PDU session status*/
    DE_NAS_5GS_MM_AUT_FAIL_PAR,              /* 9.11.3.14    Authentication failure parameter */
    DE_NAS_5GS_MM_AUT_PAR_AUTN,              /* 9.11.3.15    Authentication parameter AUTN*/
    DE_NAS_5GS_MM_AUT_PAR_RAND,              /* 9.11.3.16    Authentication parameter RAND*/
    DE_NAS_5GS_MM_AUT_RESP_PAR,              /* 9.11.3.17    Authentication response parameter */
    DE_NAS_5GS_MM_CONF_UPD_IND,              /* 9.11.3.18    Configuration update indication*/
    DE_NAS_5GS_MM_CAG_INFORMATION_LIST,      /* 9.11.3.18A   CAG information list*/
    DE_NAS_5GS_MM_CIOT_SMALL_DATA_CONT,      /* 9.11.3.18B   CIoT small data container */
    DE_NAS_5GS_MM_CIPHERING_KEY_DATA,        /* 9.11.3.18C   Ciphering key data*/
    DE_NAS_5GS_MM_CTRL_PLANE_SERVICE_TYPE,   /* 9.11.3.18D   Control plane service type*/
    DE_NAS_5GS_MM_DLGT_SAVING_TIME,          /* 9.11.3.19    Daylight saving time*/
    DE_NAS_5GS_MM_DE_REG_TYPE,               /* 9.11.3.20    De-registration type*/
                                             /* 9.11.3.21    Void */
                                             /* 9.11.3.22    Void*/
    DE_NAS_5GS_MM_EMRG_NR_LIST,              /* 9.11.3.23    Emergency number list */
    DE_NAS_5GS_MM_EPS_BEARER_CTX_STATUS,     /* 9.11.3.23A   EPS bearer context status */
    DE_NAS_5GS_MM_EPS_NAS_MSG_CONT,          /* 9.11.3.24    EPS NAS message container */
    DE_NAS_5GS_MM_EPS_NAS_SEC_ALGO,          /* 9.11.3.25    EPS NAS security algorithms */
    DE_NAS_5GS_MM_EXT_EMERG_NUM_LIST,        /* 9.11.3.26    Extended emergency number list */
    DE_NAS_5GS_MM_EXTENDED_DRX_PARAMETERS,   /* 9.11.3.26A   Extended DRX parameters */
                                             /* 9.11.3.27    Void*/
    DE_NAS_5GS_MM_IMEISV_REQ,                /* 9.11.3.28    IMEISV request*/
    DE_NAS_5GS_MM_LADN_INDIC,                /* 9.11.3.29    LADN indication*/
    DE_NAS_5GS_MM_LADN_INF,                  /* 9.11.3.30    LADN information */
    DE_NAS_5GS_MM_MICO_IND,                  /* 9.11.3.31    MICO indication*/
    DE_NAS_5GS_MM_MA_PDU_SES_INF,            /* 9.11.3.31A   MA PDU session information */
    DE_NAS_5GS_MM_MAPPED_NSSAI,              /* 9.11.3.31B   Mapped NSSAI */
    DE_NAS_5GS_MM_MOBILE_STATION_CLSMK_2,    /* 9.11.3.31C   Mobile station classmark 2 */
    DE_NAS_5GS_MM_NAS_KEY_SET_ID,            /* 9.11.3.32    NAS key set identifier*/
    DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1,         /* 9.11.3.32    NAS key set identifier*/
    DE_NAS_5GS_MM_NAS_MSG_CONT,              /* 9.11.3.33    NAS message container*/
    DE_NAS_5GS_MM_NAS_SEC_ALGO,              /* 9.11.3.34    NAS security algorithms*/
    DE_NAS_5GS_MM_NW_NAME,                   /* 9.11.3.35    Network name*/
    DE_NAS_5GS_MM_NW_SLICING_IND,            /* 9.11.3.36    Network slicing indication */
    DE_NAS_5GS_MM_NW_NON_3GPP_NW_PROV_POL,   /* 9.11.3.36A   Non-3GPP NW provided policies */
    DE_NAS_5GS_MM_NSSAI,                     /* 9.11.3.37    NSSAI*/
    DE_NAS_5GS_MM_NSSAI_INC_MODE,            /* 9.11.3.37A   NSSAI inclusion mode */
    DE_NAS_5GS_MM_OP_DEF_ACC_CAT_DEF,        /* 9.11.3.38    Operator-defined access category definitions */
    DE_NAS_5GS_MM_PLD_CONT,                  /* 9.11.3.39    Payload container*/
    DE_NAS_5GS_MM_PLD_CONT_TYPE,             /* 9.11.3.40    Payload container type*/
    DE_NAS_5GS_MM_PDU_SES_ID_2,              /* 9.11.3.41    PDU session identity 2 */
    DE_NAS_5GS_MM_PDU_SES_REACT_RES,         /* 9.11.3.42    PDU session reactivation result*/
    DE_NAS_5GS_MM_PDU_SES_REACT_RES_ERR_C,   /* 9.11.3.43    PDU session reactivation result error cause */
    DE_NAS_5GS_MM_PDU_SES_STATUS,            /* 9.11.3.44    PDU session status */
    DE_NAS_5GS_MM_PLMN_LIST,                 /* 9.11.3.45    PLMN list*/
    DE_NAS_5GS_MM_REJ_NSSAI,                 /* 9.11.3.46    Rejected NSSAI*/
    DE_NAS_5GS_MM_REL_ASS_IND,               /* 9.11.3.46A   Release assistance indication*/
    DE_NAS_5GS_MM_REQ_TYPE,                  /* 9.11.3.47    Request type */
    DE_NAS_5GS_MM_S1_UE_NW_CAP,              /* 9.11.3.48    S1 UE network capability*/
    DE_NAS_5GS_MM_S1_UE_SEC_CAP,             /* 9.11.3.48A   S1 UE security capability*/
    DE_NAS_5GS_MM_SAL,                       /* 9.11.3.49    Service area list*/
    DE_NAS_5GS_MM_SERV_TYPE,                 /* 9.11.3.50    Service type,*/
    DE_NAS_5GS_MM_SMS_IND,                   /* 9.11.3.50A   SMS indication */
    DE_NAS_5GS_MM_SOR_TRANSP_CONT,           /* 9.11.3.51    SOR transparent container */
    DE_NAS_5GS_MM_SUPPORTED_CODEC_LIST,      /* 9.11.3.51A   Supported codec list */
    DE_NAS_5GS_MM_TZ,                        /* 9.11.3.52    Time zone*/
    DE_NAS_5GS_MM_TZ_AND_T,                  /* 9.11.3.53    Time zone and time*/
    DE_NAS_5GS_MM_UE_PAR_UPD_TRANSP_CONT,    /* 9.11.3.53A   UE parameters update transparent container */
    DE_NAS_5GS_MM_UE_SEC_CAP,                /* 9.11.3.54    UE security capability*/
    DE_NAS_5GS_MM_UE_USAGE_SET,              /* 9.11.3.55    UE's usage setting */
    DE_NAS_5GS_MM_UE_STATUS,                 /* 9.11.3.56    UE status */
    DE_NAS_5GS_MM_UL_DATA_STATUS,            /* 9.11.3.57    Uplink data status */
    DE_NAS_5GS_MM_UE_RADIO_CAP_ID,           /* 9.11.3.68    UE radio capability ID*/
    DE_NAS_5GS_MM_UE_RADIO_CAP_ID_DEL_IND,   /* 9.11.3.69    UE radio capability ID deletion indication*/
    DE_NAS_5GS_MM_TRUNCATED_5G_S_TMSI_CONF,  /* 9.11.3.70    Truncated 5G-S-TMSI configuration*/
    DE_NAS_5GS_MM_WUS_ASSISTANCE_INF,        /* 9.11.3.71    WUS assistance information*/
    DE_NAS_5GS_MM_N5GC_INDICATION,           /* 9.11.3.72    N5GC indication*/
    DE_NAS_5GS_MM_NB_N1_MODE_DRX_PARS,       /* 9.11.3.73    NB-N1 mode DRX parameters*/
    DE_NAS_5GS_MM_ADDITIONAL_CONF_IND,       /* 9.11.3.74    Additional configuration indication*/
    DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI,   /* 9.11.3.75    Extended rejected NSSAI*/
    DE_NAS_5GS_MM_UE_REQUEST_TYPE,           /* 9.11.3.76    UE request type */
    DE_NAS_5GS_MM_PAGING_RESTRICTION,        /* 9.11.3.77    Paging restriction */
    DE_NAS_5GS_MM_NID,                       /* 9.11.3.79    NID */
    DE_NAS_5GS_MM_PEIPS_ASSIST_INFO,         /* 9.11.3.80    PEIPS assistance information */
    DE_NAS_5GS_MM_5GS_ADD_REQ_RES,           /* 9.11.3.81    5GS additional request result */
    DE_NAS_5GS_MM_NSSRG_INFO,                /* 9.11.3.82    NSSRG information */
    DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND,  /* 9.11.3.83    List of PLMNs to be used in disaster condition */
    DE_NAS_5GS_MM_REG_WAIT_RANGE,            /* 9.11.3.84    Registration wait range */
    DE_NAS_5GS_MM_PLMN_ID,                   /* 9.11.3.85    PLMN identity */
    DE_NAS_5GS_MM_EXT_CAG_INFO_LIST,         /* 9.11.3.86    Extended CAG information list */
    DE_NAS_5GS_MM_NSAG_INFO,                 /* 9.11.3.87    NSAG information */
    DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID,      /* 9.11.3.88    ProSe relay transaction identity */
    DE_NAS_5GS_MM_RELAY_KEY_REQ_PARAMS,      /* 9.11.3.89    Relay key request parameters */
    DE_NAS_5GS_MM_RELAY_KEY_RESP_PARAMS,     /* 9.11.3.90    Relay key response parameters */
    DE_NAS_5GS_MM_PRIO_IND,                  /* 9.11.3.91    Priority indicator */
    DE_NAS_5GS_MM_SNPN_LIST,                 /* 9.11.3.92    SNPN list */
    DE_NAS_5GS_MM_N3IWF_ID,                  /* 9.11.3.93    N3IWF identifier */
    DE_NAS_5GS_MM_TNAN_INFO,                 /* 9.11.3.94    TNAN information */
    DE_NAS_5GS_MM_RAN_TIMING_SYNC,           /* 9.11.3.95    RAN timing synchronization */
    DE_NAS_5GS_MM_EXT_LADN_INFO,             /* 9.11.3.96    Extended LADN information */
    DE_NAS_5GS_MM_ALT_NSSAI,                 /* 9.11.3.97    Alternative NSSAI */
    DE_NAS_5GS_MM_TYPE_6_IE_CONT,            /* 9.11.3.98    Type 6 IE container */
    DE_NAS_5GS_MM_N3GPP_ACC_PATH_SWITCH_IND, /* 9.11.9.99    Non-3GPP access path switching indication */
    DE_NAS_5GS_MM_S_NSSAI_LOC_VALID_INFO,    /* 9.11.3.100   S-NSSAI location validity information */
    DE_NAS_5GS_MM_S_NSSAI_TIME_VALID_INFO,   /* 9.11.3.101   S-NSSAI time validity information */
    DE_NAS_5GS_MM_N3GPP_PATH_SWITCH_INFO,    /* 9.11.3.102   Non-3GPP path switching information */
    DE_NAS_5GS_MM_PARTIAL_NSSAI,             /* 9.11.3.103   Partial NSSAI */
    DE_NAS_5GS_MM_AU3N_IND,                  /* 9.11.3.104   AUN3 indication */
    DE_NAS_5GS_MM_FEAT_AUTH_IND,             /* 9.11.3.105   Feature authorization indication */
    DE_NAS_5GS_MM_PAYLOAD_CONT_INFO,         /* 9.11.3.106   Payload container information */
    DE_NAS_5GS_MM_AUN3_DEVICE_SEC_KEY,       /* 9.11.3.107   AUN3 device security key */
    DE_NAS_5GS_MM_ON_DEMAND_NSSAI,           /* 9.11.3.108   On-demand NSSAI */
    DE_NAS_5GS_MM_EXT_5GMM_CAUSE,            /* 9.11.3.109   Extended 5GMM cause */
    DE_NAS_5GS_MM_NONE        /* NONE */
}
nas_5gs_mm_elem_idx_t;


#endif /* __PACKET_GSM_A_COMMON_H__ */

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
