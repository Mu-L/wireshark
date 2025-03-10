/* packet-rsl.c
 * Routines for Radio Signalling Link (RSL) dissection.
 *
 * Copyright 2007, 2011, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2009-2011, Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-cops.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * REF: 3GPP TS 48.058 version 6.1.0 Release 6
 * http://www.3gpp.org/ftp/Specs/html-info/48058.htm
 *
 * Huawei paging encapsulation in RSL from:
 * https://patents.google.com/patent/EP2192796B1/en
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-gsm_a_common.h"
#include "lapd_sapi.h"
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>

#include "packet-rtp.h"
#include "packet-rtcp.h"

void proto_register_rsl(void);
void proto_reg_handoff_rsl(void);

uint16_t parse_reduced_frame_number(tvbuff_t *tvb, const int offset);

/* Initialize the protocol and registered fields */
static int proto_rsl;

static int hf_rsl_msg_type;
static int hf_rsl_T_bit;
static int hf_rsl_msg_dsc;
static int hf_rsl_ie_id;
static int hf_rsl_ie_length;
static int hf_rsl_ch_no_Cbits;
static int hf_rsl_ch_no_TN;
static int hf_rsl_acc_delay;
static int hf_rsl_rach_slot_cnt;
static int hf_rsl_rach_busy_cnt;
static int hf_rsl_rach_acc_cnt;
static int hf_rsl_req_ref_ra;
static int hf_rsl_req_ref_ra_est_cause;
static int hf_rsl_req_ref_T1prim;
static int hf_rsl_req_ref_T3;
static int hf_rsl_req_ref_T2;
static int hf_rsl_req_ref_rfn;
static int hf_rsl_timing_adv;
static int hf_rsl_ho_ref;
static int hf_rsl_l1inf_power_lev;
static int hf_rsl_l1inf_fpc;
static int hf_rsl_l1inf_srr;
static int hf_rsl_ms_power_lev;
static int hf_rsl_ms_fpc;
static int hf_rsl_act_timing_adv;
static int hf_rsl_phy_ctx;
static int hf_rsl_na;
static int hf_rsl_ch_type;
static int hf_rsl_prio;
static int hf_rsl_sapi;
static int hf_rsl_rbit;
static int hf_rsl_a3a2;
static int hf_rsl_a1_0;
static int hf_rsl_a1_1;
static int hf_rsl_a1_2;
static int hf_rsl_epc_mode;
static int hf_rsl_bs_fpc_epc_mode;
static int hf_rsl_bs_power;
static int hf_rsl_cm_dtxd;
static int hf_rsl_cm_dtxu;
static int hf_rsl_speech_or_data;
static int hf_rsl_ch_rate_and_type;
static int hf_rsl_speech_coding_alg;
static int hf_rsl_t_nt_bit;
static int hf_rsl_ra_if_data_rte;
static int hf_rsl_data_rte;
static int hf_rsl_alg_id;
static int hf_rsl_key;
static int hf_rsl_cause;
static int hf_rsl_rel_mode;
static int hf_rsl_interf_band;
static int hf_rsl_interf_band_reserved;
static int hf_rsl_meas_res_no;
static int hf_rsl_extension_bit;
static int hf_rsl_dtxd;
static int hf_rsl_rxlev_full_up;
static int hf_rsl_rxlev_sub_up;
static int hf_rsl_rxqual_full_up;
static int hf_rsl_rxqual_sub_up;
static int hf_rsl_class;
static int hf_rsl_cause_value;
static int hf_rsl_paging_grp;
static int hf_rsl_paging_load;
static int hf_rsl_sys_info_type;
static int hf_rsl_timing_offset;
static int hf_rsl_ch_needed;
static int hf_rsl_cbch_load_type;
static int hf_rsl_msg_slt_cnt;
static int hf_rsl_ch_ind;
static int hf_rsl_command;
static int hf_rsl_command_ext;
static int hf_rsl_emlpp_prio;
static int hf_rsl_rtd;
static int hf_rsl_delay_ind;
static int hf_rsl_tfo;
static int hf_rsl_speech_mode_s;
static int hf_rsl_speech_mode_m;
static int hf_rsl_conn_id;
static int hf_rsl_rtp_payload;
static int hf_rsl_rtp_csd_fmt_d;
static int hf_rsl_rtp_csd_fmt_ir;
static int hf_rsl_local_port;
static int hf_rsl_remote_port;
static int hf_rsl_local_ip;
static int hf_rsl_remote_ip;
static int hf_rsl_cstat_tx_pkts;
static int hf_rsl_cstat_tx_octs;
static int hf_rsl_cstat_rx_pkts;
static int hf_rsl_cstat_rx_octs;
static int hf_rsl_cstat_lost_pkts;
static int hf_rsl_cstat_ia_jitter;
static int hf_rsl_cstat_avg_tx_dly;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_rsl_channel_description_tag;
static int hf_rsl_mobile_allocation_tag;
static int hf_rsl_mobile_allocation_len;
static int hf_rsl_no_resources_required;
static int hf_rsl_llsdu_ccch;
static int hf_rsl_llsdu_sacch;
static int hf_rsl_llsdu;
static int hf_rsl_rach_supplementary_information;
static int hf_rsl_full_immediate_assign_info_field;
static int hf_rsl_layer_3_message;
static int hf_rsl_descriptive_group_or_broadcast_call_reference;
static int hf_rsl_group_channel_description;
static int hf_rsl_uic;
static int hf_rsl_codec_list;
static int hf_rsl_cb_cmd_type;
static int hf_rsl_cb_def_bcast;
static int hf_rsl_cb_last_block;
static int hf_rsl_etws_pn;

/* Encapsulating paging messages into a packet REF: EP2192796 - proprietor Huawei */
static int hf_rsl_paging_spare;
static int hf_rsl_paging_msg_no;
static int hf_rsl_paging_package_ch_no;
static int hf_rsl_paging_package_ch_needed;
static int hf_rsl_paging_emlpp_prio;
static int hf_rsl_paging_type;
static int hf_rsl_paging_group_cs;
static int hf_rsl_paging_group_empty_package;
static int hf_rsl_paging_group_ps_spare;

/* Physical Context dissection */
static int hf_rsl_phy_ctx_ie_id;
static int hf_rsl_phy_ctx_ext_rand_access;
static int hf_rsl_phy_ctx_ab_rx_lvl;
static int hf_rsl_phy_ctx_ab_err_bits;
static int hf_rsl_phy_ctx_rx_lvl_ext;

/* Osmocom specific IEs */
static int hf_rsl_osmo_rep_acch_rxqual;
static int hf_rsl_osmo_rep_acch_ul_sacch;
static int hf_rsl_osmo_rep_acch_dl_sacch;
static int hf_rsl_osmo_rep_acch_dl_facch_all;
static int hf_rsl_osmo_rep_acch_dl_facch_cmd;
static int hf_rsl_osmo_top_acch_val;
static int hf_rsl_osmo_top_acch_sacch;
static int hf_rsl_osmo_top_acch_facch;
static int hf_rsl_osmo_top_acch_rxqual;
static int hf_rsl_osmo_tsc_set;
static int hf_rsl_osmo_tsc_val;
static int hf_rsl_osmo_osmux_cid;

/* Initialize the subtree pointers */
static int ett_rsl;
static int ett_ie_link_id;
static int ett_ie_act_type;
static int ett_ie_bs_power;
static int ett_ie_bs_power_params;
static int ett_ie_ch_id;
static int ett_ie_ch_mode;
static int ett_ie_enc_inf;
static int ett_ie_ch_no;
static int ett_ie_frame_no;
static int ett_ie_ho_ref;
static int ett_ie_l1_inf;
static int ett_ie_L3_inf;
static int ett_ie_ms_id;
static int ett_ie_ms_pow;
static int ett_ie_ms_pow_params;
static int ett_ie_phy_ctx;
static int ett_ie_paging_grp;
static int ett_ie_paging_load;
static int ett_ie_access_delay;
static int ett_ie_rach_load;
static int ett_ie_req_ref;
static int ett_ie_req_ref_ra;
static int ett_ie_rel_mode;
static int ett_ie_resource_inf;
static int ett_ie_rlm_cause;
static int ett_ie_staring_time;
static int ett_ie_timing_adv;
static int ett_ie_uplink_meas;
static int ett_ie_full_imm_ass_inf;
static int ett_ie_smscb_inf;
static int ett_ie_ms_timing_offset;
static int ett_ie_err_msg;
static int ett_ie_full_bcch_inf;
static int ett_ie_ch_needed;
static int ett_ie_cb_cmd_type;
static int ett_ie_smscb_mess;
static int ett_ie_cbch_load_inf;
static int ett_ie_smscb_ch_ind;
static int ett_ie_grp_call_ref;
static int ett_ie_ch_desc;
static int ett_ie_nch_drx;
static int ett_ie_cmd_ind;
static int ett_ie_emlpp_prio;
static int ett_ie_uic;
static int ett_ie_main_ch_ref;
static int ett_ie_multirate_conf;
static int ett_ie_multirate_cntrl;
static int ett_ie_sup_codec_types;
static int ett_ie_codec_conf;
static int ett_ie_rtd;
static int ett_ie_tfo_status;
static int ett_ie_llp_apdu;
static int ett_ie_tfo_transp_cont;
static int ett_ie_cause;
static int ett_ie_meas_res_no;
static int ett_ie_message_id;
static int ett_ie_sys_info_type;
static int ett_ie_speech_mode;
static int ett_ie_conn_id;
static int ett_ie_remote_ip;
static int ett_ie_remote_port;
static int ett_ie_local_port;
static int ett_ie_local_ip;
static int ett_ie_rtp_payload;
static int ett_ie_etws_pn;
static int ett_ie_osmo_rep_acch_cap;
static int ett_ie_osmo_top_acch_cap;
static int ett_ie_osmo_training_seq;

/* Encapsulating paging messages into a packet REF: EP2192796 - proprietor Huawei */
static int ett_ie_paging_package;
static int ett_ie_paging_package_number;
static int ett_ie_paging_package_info;
static int ett_ie_paging_package_ch_a_emlpp;
static int ett_ie_paging_group_paras;

/* Physical Context dissection */
static int ett_phy_ctx_ie;
static int ett_phy_ctx_ie_ext_rand_access;
static int ett_phy_ctx_ab_rx_lvl_err_bits;
static int ett_phy_ctx_rxlvl_ext;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_rsl_speech_or_data_indicator;
static expert_field ei_rsl_facility_information_element_3gpp_ts_44071;
static expert_field ei_rsl_embedded_message_tfo_configuration;
static expert_field ei_rsl_mobile_allocation_deprecated;

static proto_tree *top_tree;
static dissector_handle_t rsl_handle;
static dissector_handle_t gsm_cbch_handle;
static dissector_handle_t gsm_cbs_handle;
static dissector_handle_t gsm_a_ccch_handle;
static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t gsm_a_sacch_handle;

/* Decode things as nanoBTS traces */
static bool global_rsl_use_nano_bts;

/* Decode Osmocom specific messages and IEs */
static bool global_rsl_use_osmo_bts;

/* Decode things in Physical Context Information field. */
static bool global_rsl_dissect_phy_ctx_inf = true;

/* Forward declarations */
static int dissct_rsl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

static const true_false_string rsl_t_bit_vals = {
  "Considered transparent by BTS",
  "Not considered transparent by BTS"
};

static const true_false_string rsl_na_vals = {
  "Not Applicable",
  "Applicable"
};

static const true_false_string rsl_extension_bit_value = {
  "Extension",
  "No Extension"
};

/*
 * 9.1 Message discriminator
 */
 /* Radio link Layer Management Messages */
static const value_string rsl_msg_disc_vals[] = {
    {  0x00,    "Reserved" },
    {  0x01,    "Radio Link Layer Management messages" },
    {  0x04,    "Dedicated Channel Management messages" },
    {  0x06,    "Common Channel Management messages" },
    {  0x08,    "TRX Management messages" },
    {  0x10,    "Location Services messages" },
    {  0x3f,    "ip.access Vendor Specific messages" },
    {  0x55,    "HUAWEI Paging Extension" },
    { 0,            NULL }
};
#define RSL_MSGDISC_IPACCESS   0x3f
/*
 * 9.2 MESSAGE TYPE
 */
/* Radio link Layer Management Messages */
#define RSL_MSG_TYPE_DATA_REQ            1   /* 0x01 */
#define RSL_MSG_TYPE_DATA_IND            2   /* 0x02 */
#define RSL_MSG_TYPE_ERROR_IND           3   /* 0x03 */
#define RSL_MSG_TYPE_EST_REQ             4   /* 0x04 */
#define RSL_MSG_TYPE_EST_CONF            5   /* 0x05 */
#define RSL_MSG_EST_IND                  6   /* 0x06 */
#define RSL_MSG_REL_REQ                  7   /* 0x07 */
#define RSL_MSG_REL_CONF                 8   /* 0x08 */
#define RSL_MSG_REL_IND                  9   /* 0x09 */
#define RSL_MSG_UNIT_DATA_REQ           10  /* 0x0a */
#define RSL_MSG_UNIT_DATA_IND           11  /* 0x0b */
/* Common Channel Management messages */
#define RSL_MSG_BCCH_INFO               17  /* 0x11 */
#define RSL_MSG_CCCH_LOAD_IND           18  /* 0x12 */
#define RSL_MSG_CHANRQD                 19  /* 0x13 */
#define RSL_MSG_DELETE_IND              20  /* 0x14 */
#define RSL_MSG_PAGING_CMD              21  /* 0x15 */
#define RSL_MSG_IMM_ASS_CMD             22  /* 0x16 */
#define RSL_MSG_SMS_BC_REQ              23  /* 0x17 8.5.7 */

/* Encapsulating paging messages into a packet REF: EP2192796 - proprietor Huawei */
#define RSL_MSG_TYPE_PAGING             24  /* 0x18 */

/* TRX Management messages */
#define RSL_MSG_RF_RES_IND              25  /* 8.6.1 */
#define RSL_MSG_SACCH_FILL              26  /* 8.6.2 */
#define RSL_MSG_OVERLOAD                27  /* 8.6.3 */
#define RSL_MSG_ERROR_REPORT            28  /* 8.6.4 */
#define RSL_MSG_SMS_BC_CMD              29  /* 8.5.8 */
#define RSL_MSG_CBCH_LOAD_IND           30  /* 8.5.9 */
#define RSL_MSG_NOT_CMD                 31  /* 8.5.10 */

/* 0 0 1 - - - - - Dedicated Channel Management messages: */
#define RSL_MSG_CHAN_ACTIV              33
#define RSL_MSG_CHAN_ACTIV_ACK          34
#define RSL_MSG_CHAN_ACTIV_N_ACK        35
#define RSL_MSG_CONN_FAIL               36
#define RSL_MSG_DEACTIVATE_SACCH        37

#define RSL_MSG_ENCR_CMD                38  /* 8.4.6 */
#define RSL_MSG_HANDODET                39  /* 8.4.7 */
#define RSL_MSG_MEAS_RES                40  /* 8.4.8 */
#define RSL_MSG_MODE_MODIFY_REQ         41  /* 8.4.9 */
#define RSL_MSG_MODE_MODIFY_ACK         42  /* 8.4.10 */
#define RSL_MSG_MODE_MODIFY_NACK        43  /* 8.4.11 */
#define RSL_MSG_PHY_CONTEXT_REQ         44  /* 8.4.12 */
#define RSL_MSG_PHY_CONTEXT_CONF        45  /* 8.4.13 */
#define RSL_MSG_RF_CHAN_REL             46  /* 8.4.14 */
#define RSL_MSG_MS_POWER_CONTROL        47  /* 8.4.15 */
#define RSL_MSG_BS_POWER_CONTROL        48  /* 8.4.16 */
#define RSL_MSG_PREPROC_CONFIG          49  /* 8.4.17 */
#define RSL_MSG_PREPROC_MEAS_RES        50  /* 8.4.18 */
#define RSL_MSG_RF_CHAN_REL_ACK         51  /* 8.4.19 */
#define RSL_MSG_SACCH_INFO_MODIFY       52  /* 8.4.20 */
#define RSL_MSG_TALKER_DET              53  /* 8.4.21 */
#define RSL_MSG_LISTENER_DET            54  /* 8.4.22 */
#define RSL_MSG_REMOTE_CODEC_CONF_REP   55  /* 8.4.23 */
#define RSL_MSG_R_T_D_REP               56  /* 8.4.24 */
#define RSL_MSG_PRE_HANDO_NOTIF         57  /* 8.4.25 */
#define RSL_MSG_MR_CODEC_MOD_REQ        58  /* 8.4.26 */
#define RSL_MSG_MR_CODEC_MOD_ACK        59  /* 8.4.27 */
#define RSL_MSG_MR_CODEC_MOD_NACK       60  /* 8.4.28 */
#define RSL_MSG_MR_CODEC_MOD_PER        61  /* 8.4.29 */
#define RSL_MSG_TFO_REP                 62  /* 8.4.30 */
#define RSL_MSG_TFO_MOD_REQ             63  /* 8.4.31 */
    /*  0 1 - - - - - - Location Services messages: */
#define RSL_MSG_LOC_INF                 65  /* 8.7.1 */

/* Vendor-Specific messages of ip.access nanoBTS. There is no public documentation
 * about those extensions, all information in this dissector is based on lawful
 * protocol reverse enginering by Harald Welte <laforge@gnumonks.org> */
#define RSL_MSG_TYPE_IPAC_MEAS_PP_DEF     0x60
#define RSL_MSG_TYPE_IPAC_HO_CAND_INQ     0x61
#define RSL_MSG_TYPE_IPAC_HO_CAND_RESP    0x62

#define RSL_MSG_TYPE_IPAC_PDCH_ACT        0x48
#define RSL_MSG_TYPE_IPAC_PDCH_ACT_ACK    0x49
#define RSL_MSG_TYPE_IPAC_PDCH_ACT_NACK   0x4a
#define RSL_MSG_TYPE_IPAC_PDCH_DEACT      0x4b
#define RSL_MSG_TYPE_IPAC_PDCH_DEACT_ACK  0x4c
#define RSL_MSG_TYPE_IPAC_PDCH_DEACT_NACK 0x4d

#define RSL_MSG_TYPE_IPAC_CRCX            0x70
#define RSL_MSG_TYPE_IPAC_CRCX_ACK        0x71
#define RSL_MSG_TYPE_IPAC_CRCX_NACK       0x72
#define RSL_MSG_TYPE_IPAC_MDCX            0x73
#define RSL_MSG_TYPE_IPAC_MDCX_ACK        0x74
#define RSL_MSG_TYPE_IPAC_MDCX_NACK       0x75
#define RSL_MSG_TYPE_IPAC_DLCX_IND        0x76
#define RSL_MSG_TYPE_IPAC_DLCX            0x77
#define RSL_MSG_TYPE_IPAC_DLCX_ACK        0x78
#define RSL_MSG_TYPE_IPAC_DLCX_NACK       0x79
#define RSL_MSG_TYPE_OSMO_ETWS_CMD        0x7f

#define RSL_IE_IPAC_SRTP_CONFIG           0xe0
#define RSL_IE_IPAC_PROXY_UDP             0xe1
#define RSL_IE_IPAC_BSCMPL_TOUT           0xe2
#define RSL_IE_IPAC_REMOTE_IP             0xf0
#define RSL_IE_IPAC_REMOTE_PORT           0xf1
#define RSL_IE_IPAC_RTP_PAYLOAD           0xf2
#define RSL_IE_IPAC_LOCAL_PORT            0xf3
#define RSL_IE_IPAC_SPEECH_MODE           0xf4
#define RSL_IE_IPAC_LOCAL_IP              0xf5
#define RSL_IE_IPAC_CONN_STAT             0xf6
#define RSL_IE_IPAC_HO_C_PARMS            0xf7
#define RSL_IE_IPAC_CONN_ID               0xf8
#define RSL_IE_IPAC_RTP_CSD_FMT           0xf9
#define RSL_IE_IPAC_RTP_JIT_BUF           0xfa
#define RSL_IE_IPAC_RTP_COMPR             0xfb
#define RSL_IE_IPAC_RTP_PAYLOAD2          0xfc
#define RSL_IE_IPAC_RTP_MPLEX             0xfd
#define RSL_IE_IPAC_RTP_MPLEX_ID          0xfe

/* Osmocom specific RSL IEs */
#define RSL_IE_OSMO_REP_ACCH_CAP          0x60
#define RSL_IE_OSMO_TRAINING_SEQUENCE     0x61
#define RSL_IE_OSMO_TOP_ACCH_CAP          0x62
#define RSL_IE_OSMO_OSMUX_CID             0x63

static const value_string rsl_msg_type_vals[] = {
      /*    0 0 0 0 - - - - Radio Link Layer Management messages: */
/* 0x01 */ { RSL_MSG_TYPE_DATA_REQ,      "DATA REQuest" },                               /* 8.3.1 */
/* 0x02 */ {  RSL_MSG_TYPE_DATA_IND,     "DATA INDication" },                            /* 8.3.2 */
/* 0x03 */ {  RSL_MSG_TYPE_ERROR_IND,    "ERROR INDication" },                           /* 8.3.3 */
/* 0x04 */ {  RSL_MSG_TYPE_EST_REQ,      "ESTablish REQuest" },                          /* 8.3.4 */
/* 0x05 */ {  RSL_MSG_TYPE_EST_CONF,     "ESTablish CONFirm" },                          /* 8.3.5 */
/* 0x06 */ {  RSL_MSG_EST_IND,           "ESTablish INDication" },                       /* 8.3.6 */
/* 0x07 */ {  RSL_MSG_REL_REQ,           "RELease REQuest" },                            /* 8.3.7 */
/* 0x08 */ {  RSL_MSG_REL_CONF,          "RELease CONFirm" },                            /* 8.3.8 */
/* 0x09 */ {  RSL_MSG_REL_IND,           "RELease INDication" },                         /* 8.3.9 */
/* 0x0a */ {  RSL_MSG_UNIT_DATA_REQ,     "UNIT DATA REQuest" },                          /* 8.3.10 */
/* 0x0b */ {  RSL_MSG_UNIT_DATA_IND,     "UNIT DATA INDication" },                       /* 8.3.11 */
    /* 0 0 0 1 - - - - Common Channel Management/TRX Management messages: */
/* 0x11 */ {  RSL_MSG_BCCH_INFO,         "BCCH INFOrmation" },                           /* 8.5.1 */
/* 0x12 */ {  RSL_MSG_CCCH_LOAD_IND,     "CCCH LOAD INDication" },                       /* 8.5.2 */
/* 0x13 */ {  RSL_MSG_CHANRQD,           "CHANnel ReQuireD" },                           /* 8.5.3 */
/* 0x14 */ {  RSL_MSG_DELETE_IND,        "DELETE INDication" },                          /* 8.5.4 */
/* 0x15 */ {  RSL_MSG_PAGING_CMD,        "PAGING CoMmanD" },                             /* 8.5.5 */
/* 0x16 */ {  RSL_MSG_IMM_ASS_CMD,       "IMMEDIATE ASSIGN COMMAND" },                   /* 8.5.6 */
/* 0x17 */ {  RSL_MSG_SMS_BC_REQ,        "SMS BroadCast REQuest" },                      /* 8.5.7 */

/* Encapsulating paging messages into a packet EP2192796 - proprietor Huawei */
/* 0x18 */ {  RSL_MSG_TYPE_PAGING,       "PAGING Huawei extension" },

/* 0x19 */ {  RSL_MSG_RF_RES_IND,        "RF RESource INDication" },                     /* 8.6.1 */
/* 0x1a */ {  RSL_MSG_SACCH_FILL,        "SACCH FILLing" },                              /* 8.6.2 */
/* 0x1b */ {  RSL_MSG_OVERLOAD,          "OVERLOAD" },                                   /* 8.6.3 */
/* 0x1c */ {  RSL_MSG_ERROR_REPORT,      "ERROR REPORT" },                               /* 8.6.4 */
/* 0x1d */ {  RSL_MSG_SMS_BC_CMD,        "SMS BroadCast CoMmanD" },                      /* 8.5.8 */
/* 0x1e */ {  RSL_MSG_CBCH_LOAD_IND,     "CBCH LOAD INDication" },                       /* 8.5.9 */
/* 0x1f */ {  RSL_MSG_NOT_CMD,           "NOTification CoMmanD" },                       /* 8.5.10 */

/* 0 0 1 - - - - - Dedicated Channel Management messages: */
/* 0x21 */ {  RSL_MSG_CHAN_ACTIV,        "CHANnel ACTIVation" },                         /* 8.4.1 */
/* 0x22 */ {  RSL_MSG_CHAN_ACTIV_ACK,    "CHANnel ACTIVation ACKnowledge" },             /* 8.4.2 */
/* 0x23 */ {  RSL_MSG_CHAN_ACTIV_N_ACK,  "CHANnel ACTIVation Negative ACK" },            /* 8.4.3 */
/* 0x24 */ {  RSL_MSG_CONN_FAIL,         "CONNection FAILure" },                         /* 8.4.4 */
/* 0x25 */ {  RSL_MSG_DEACTIVATE_SACCH,  "DEACTIVATE SACCH" },                           /* 8.4.5 */
/* 0x26 */ {  RSL_MSG_ENCR_CMD,          "ENCRyption CoMmanD" },                         /* 8.4.6 */
/* 0x27 */ {  RSL_MSG_HANDODET,          "HANDOver DETection" },                         /* 8.4.7 */
/* 0x28 */ {  RSL_MSG_MEAS_RES,          "MEASurement RESult" },                         /* 8.4.8 */
/* 0x29 */ {  RSL_MSG_MODE_MODIFY_REQ,   "MODE MODIFY REQuest" },                        /* 8.4.9 */
/* 0x2a */ {  RSL_MSG_MODE_MODIFY_ACK,   "MODE MODIFY ACKnowledge" },                    /* 8.4.10 */
/* 0x2v */ {  RSL_MSG_MODE_MODIFY_NACK,  "MODE MODIFY Negative ACKnowledge" },           /* 8.4.11 */
/* 0x2b */ {  RSL_MSG_PHY_CONTEXT_REQ,   "PHYsical CONTEXT REQuest" },                   /* 8.4.12 */
/* 0x2d */ {  RSL_MSG_PHY_CONTEXT_CONF,  "PHYsical CONTEXT CONFirm" },                   /* 8.4.13 */
/* 0x2e */ {  RSL_MSG_RF_CHAN_REL,       "RF CHANnel RELease" },                         /* 8.4.14 */
/* 0x2f */ {  RSL_MSG_MS_POWER_CONTROL,  "MS POWER CONTROL" },                           /* 8.4.15 */
/* 0x30 */ {  RSL_MSG_BS_POWER_CONTROL,  "BS POWER CONTROL" },                           /* 8.4.16 */
/* 0x31 */ {  RSL_MSG_PREPROC_CONFIG,    "PREPROCess CONFIGure" },                       /* 8.4.17 */
/* 0x32 */ {  RSL_MSG_PREPROC_MEAS_RES,  "PREPROCessed MEASurement RESult" },            /* 8.4.18 */
/* 0x33 */ {  RSL_MSG_RF_CHAN_REL_ACK,   "RF CHANnel RELease ACKnowledge" },             /* 8.4.19 */
/* 0x34 */ {  RSL_MSG_SACCH_INFO_MODIFY, "SACCH INFO MODIFY" },                          /* 8.4.20 */
/* 0x35 */ {  RSL_MSG_TALKER_DET,        "TALKER DETection" },                           /* 8.4.21 */
/* 0x36 */ {  RSL_MSG_LISTENER_DET,      "LISTENER DETection" },                         /* 8.4.22 */
/* 0x37 */ {  RSL_MSG_REMOTE_CODEC_CONF_REP, "REMOTE CODEC CONFiguration REPort" },      /* 8.4.23 */
/* 0x38 */ {  RSL_MSG_R_T_D_REP,         "Round Trip Delay REPort" },                    /* 8.4.24 */
/* 0x39 */ {  RSL_MSG_PRE_HANDO_NOTIF,   "PRE-HANDOver NOTIFication" },                  /* 8.4.25 */
/* 0x3a */ {  RSL_MSG_MR_CODEC_MOD_REQ,  "MultiRate CODEC MODification REQuest" },       /* 8.4.26 */
/* 0x3b */ {  RSL_MSG_MR_CODEC_MOD_ACK,  "MultiRate CODEC MOD ACKnowledge" },            /* 8.4.27 */
/* 0x3c */ {  RSL_MSG_MR_CODEC_MOD_NACK, "MultiRate CODEC MOD Negative ACKnowledge" },   /* 8.4.28 */
/* 0x3d */ {  RSL_MSG_MR_CODEC_MOD_PER,  "MultiRate CODEC MOD PERformed" },              /* 8.4.29 */
/* 0x3e */ {  RSL_MSG_TFO_REP,           "TFO REPort" },                                 /* 8.4.30 */
/* 0x3f */ {  RSL_MSG_TFO_MOD_REQ,       "TFO MODification REQuest" },                   /* 8.4.31 */
    /*  0 1 - - - - - - Location Services messages: */
/* 0x41 */ {  0x41,    "Location Information" },                       /* 8.7.1 */
    /* ip.access */
/* 0x48 */ {  RSL_MSG_TYPE_IPAC_PDCH_ACT,       "ip.access PDCH ACTIVATION" },
/* 0x49 */ {  RSL_MSG_TYPE_IPAC_PDCH_ACT_ACK,   "ip.access PDCH ACTIVATION ACK" },
/* 0x4a */ {  RSL_MSG_TYPE_IPAC_PDCH_ACT_NACK,  "ip.access PDCH ACTIVATION NACK" },
/* 0x4b */ {  RSL_MSG_TYPE_IPAC_PDCH_DEACT,     "ip.access PDCH DEACTIVATION" },
/* 0x4c */ {  RSL_MSG_TYPE_IPAC_PDCH_DEACT_ACK, "ip.access PDCH DEACTIVATION ACK" },
/* 0x4d */ {  RSL_MSG_TYPE_IPAC_PDCH_DEACT_NACK,"ip.access PDCH DEACTIVATION NACK" },
/* 0x60 */ {  RSL_MSG_TYPE_IPAC_MEAS_PP_DEF,    "ip.access MEASurement PREPROCessing DeFauLT" },
/* 0x61 */ {  RSL_MSG_TYPE_IPAC_HO_CAND_INQ,    "ip.access HANDOover CANDidate ENQuiry" },
/* 0x62 */ {  RSL_MSG_TYPE_IPAC_HO_CAND_RESP,   "ip.access HANDOover CANDidate RESPonse" },
/* 0x70 */ {  RSL_MSG_TYPE_IPAC_CRCX,           "ip.access CRCX" },
/* 0x71 */ {  RSL_MSG_TYPE_IPAC_CRCX_ACK,       "ip.access CRCX ACK" },
/* 0x72 */ {  RSL_MSG_TYPE_IPAC_CRCX_NACK,      "ip.access CRCX NACK" },
/* 0x73 */ {  RSL_MSG_TYPE_IPAC_MDCX,           "ip.access MDCX" },
/* 0x74 */ {  RSL_MSG_TYPE_IPAC_MDCX_ACK,       "ip.access MDCX ACK" },
/* 0x75 */ {  RSL_MSG_TYPE_IPAC_MDCX_NACK,      "ip.access MDCX NACK" },
/* 0x76 */ {  RSL_MSG_TYPE_IPAC_DLCX_IND,       "ip.access DLCX INDication" },
/* 0x77 */ {  RSL_MSG_TYPE_IPAC_DLCX,           "ip.access DLCX" },
/* 0x78 */ {  RSL_MSG_TYPE_IPAC_DLCX_ACK,       "ip.access DLCX ACK" },
/* 0x79 */ {  RSL_MSG_TYPE_IPAC_DLCX_NACK,      "ip.access DLCX NACK" },
/* 0x7f */ {  RSL_MSG_TYPE_OSMO_ETWS_CMD,       "Osmocom PRIMARY ETWS CMD" },
/* 0x48 */ { 0,        NULL }
};
static value_string_ext rsl_msg_type_vals_ext = VALUE_STRING_EXT_INIT(rsl_msg_type_vals);

#define RSL_IE_CH_NO                     1
#define RSL_IE_LINK_ID                   2
#define RSL_IE_ACT_TYPE                  3
#define RSL_IE_BS_POW                    4
#define RSL_IE_CH_ID                     5

#define RSL_IE_CH_MODE                   6
#define RSL_IE_ENC_INF                   7
#define RSL_IE_FRAME_NO                  8
#define RSL_IE_HO_REF                    9
#define RSL_IE_L1_INF                   10

#define RSL_IE_L3_INF                   11
#define RSL_IE_MS_ID                    12
#define RSL_IE_MS_POW                   13
#define RSL_IE_PAGING_GRP               14
#define RSL_IE_PAGING_LOAD              15

#define RSL_IE_PHY_CTX                  16
#define RSL_IE_ACCESS_DELAY             17
#define RSL_IE_RACH_LOAD                18
#define RSL_IE_REQ_REF                  19
#define RSL_IE_REL_MODE                 20

#define RSL_IE_RESOURCE_INF             21
#define RSL_IE_RLM_CAUSE                22
#define RSL_IE_STARTING_TIME            23
#define RSL_IE_TIMING_ADV               24

#define RSL_IE_UPLINK_MEAS              25
#define RSL_IE_CAUSE                    26
#define RSL_IE_MEAS_RES_NO              27
#define RSL_IE_MESSAGE_ID               28

#define RSL_IE_SYS_INFO_TYPE            30
#define RSL_IE_MS_POWER_PARAM           31
#define RSL_IE_BS_POWER_PARAM           32
#define RSL_IE_PREPROC_PARAM            33
#define RSL_IE_PREPROC_MEAS             34

#define RSL_IE_FULL_IMM_ASS_INF         35
#define RSL_IE_SMSCB_INF                36
#define RSL_IE_FULL_MS_TIMING_OFFSET    37
#define RSL_IE_ERR_MSG                  38
#define RSL_IE_FULL_BCCH_INF            39

#define RSL_IE_CH_NEEDED                40
#define RSL_IE_CB_CMD_TYPE              41
#define RSL_IE_SMSCB_MESS               42
#define RSL_IE_CBCH_LOAD_INF            43


#define RSL_IE_SMSCB_CH_IND             46
#define RSL_IE_GRP_CALL_REF             47
#define RSL_IE_CH_DESC                  48
#define RSL_IE_NCH_DRX_INF              49

#define RSL_IE_CMD_IND                  50
#define RSL_IE_EMLPP_PRIO               51
#define RSL_IE_UIC                      52
#define RSL_IE_MAIN_CH_REF              53
#define RSL_IE_MULTIRATE_CONF           54

#define RSL_IE_MULTIRATE_CNTRL          55
#define RSL_IE_SUP_CODEC_TYPES          56
#define RSL_IE_CODEC_CONF               57
#define RSL_IE_RTD                      58
#define RSL_IE_TFO_STATUS               59

#define RSL_IE_LLP_APDU                 60
#define RSL_IE_TFO_TRANSP_CONT          61

static const value_string rsl_ie_type_vals[] = {
/* 0x01 */    { RSL_IE_CH_NO,           "Channel Number" },             /*  9.3.1 */
/* 0x02 */    { RSL_IE_LINK_ID,         "Link Identifier" },            /*  9.3.2 */
/* 0x03 */    { RSL_IE_ACT_TYPE,        "Activation Type" },            /*  9.3.3 */
/* 0x04 */    { RSL_IE_BS_POW,          "BS Power" },                   /*  9.3.4 */
/* 0x05 */    { RSL_IE_CH_ID,           "Channel Identification" },     /*  9.3.5 */
/* 0x06 */    { RSL_IE_CH_MODE,         "Channel Mode" },               /*  9.3.6 */
/* 0x07 */    { RSL_IE_ENC_INF,         "Encryption Information" },     /*  9.3.7 */
/* 0x08 */    { RSL_IE_FRAME_NO,        "Frame Number" },               /*  9.3.8 */
/* 0x09 */    { RSL_IE_HO_REF,          "Handover Reference" },         /*  9.3.9 */
/* 0x0a */    { RSL_IE_L1_INF,          "L1 Information" },             /*  9.3.10 */
/* 0x0b */    { RSL_IE_L3_INF,          "L3 Information" },             /*  9.3.11 */
/* 0x0c */    { RSL_IE_MS_ID,           "MS Identity" },                /*  9.3.12 */
/* 0x0d */    { RSL_IE_MS_POW,          "MS Power" },                   /*  9.3.13 */
/* 0x0e */    { RSL_IE_PAGING_GRP,      "Paging Group" },               /*  9.3.14 */
/* 0x0f */    { RSL_IE_PAGING_LOAD,     "Paging Load" },                /*  9.3.15 */
/* 0x10 */    { RSL_IE_PHY_CTX,         "Physical Context" },           /*  9.3.16 */
/* 0x11 */    { RSL_IE_ACCESS_DELAY,    "Access Delay" },               /*  9.3.17 */
/* 0x12 */    { RSL_IE_RACH_LOAD,       "RACH Load" },                  /*  9.3.18 */
/* 0x12 */    { RSL_IE_REQ_REF,         "Request Reference" },          /*  9.3.19 */
/* 0x14 */    { RSL_IE_REL_MODE,        "Release Mode" },               /*  9.3.20 */
/* 0x15 */    { RSL_IE_RESOURCE_INF,    "Resource Information" },       /*  9.3.21 */
/* 0x16 */    { RSL_IE_RLM_CAUSE,       "RLM Cause" },                  /*  9.3.22 */
/* 0x17 */    { RSL_IE_STARTING_TIME,   "Starting Time" },              /*  9.3.23 */
/* 0x18 */    { RSL_IE_TIMING_ADV,      "Timing Advance" },             /*  9.3.24 */
/* 0x19 */    { RSL_IE_UPLINK_MEAS,     "Uplink Measurements" },        /*  9.3.25 */
/* 0x1a */    { RSL_IE_CAUSE,           "Cause" },                      /*  9.3.26 */
/* 0x1b */    { RSL_IE_MEAS_RES_NO,     "Measurement Result Number" },  /*  9.3.27 */
/* 0x1c */    { RSL_IE_MESSAGE_ID,      "Message Identifier" },         /*  9.3.28 */
/* 0x1d */    {  0x1d,                  "reserved" },                   /*  */
/* 0x1e */    { RSL_IE_SYS_INFO_TYPE,   "System Info Type" },           /*  9.3.30 */
/* 0x1f */    { RSL_IE_MS_POWER_PARAM,  "MS Power Parameters" },        /*  9.3.31 */
/* 0x20 */    { RSL_IE_BS_POWER_PARAM,  "BS Power Parameters" },        /*  9.3.32 */
/* 0x21 */    { RSL_IE_PREPROC_PARAM,   "Pre-processing Parameters" },  /*  9.3.33 */
/* 0x22 */    { RSL_IE_PREPROC_MEAS,    "Pre-processed Measurements" }, /*  9.3.34 */
/* 0x23 */    {  0x23,                  "reserved" },                   /*  */
/* 0x24 */    { RSL_IE_SMSCB_INF,       "SMSCB Information" },          /*  9.3.36 */
/* 0x25 */    { RSL_IE_FULL_MS_TIMING_OFFSET,  "MS Timing Offset" },           /*  9.3.37 */
/* 0x26 */    { RSL_IE_ERR_MSG,         "Erroneous Message" },          /*  9.3.38 */
/* 0x27 */    { RSL_IE_FULL_BCCH_INF,   "Full BCCH Information" },      /*  9.3.39 */
/* 0x28 */    { RSL_IE_CH_NEEDED,       "Channel Needed" },             /*  9.3.40 */
/* 0x29 */    { RSL_IE_CB_CMD_TYPE,     "CB Command type" },            /*  9.3.41 */
/* 0x2a */    { RSL_IE_SMSCB_MESS,      "SMSCB Message" },              /*  9.3.42 */
/* 0x2b */    { RSL_IE_CBCH_LOAD_INF,   "Full Immediate Assign Info" }, /*  9.3.35 */
/* 0x2c */    {  0x2c,                  "SACCH Information" },          /*  9.3.29 */
/* 0x2d */    {  0x2d,                  "CBCH Load Information" },      /*  9.3.43 */
/* 0x2e */    { RSL_IE_SMSCB_CH_IND,    "SMSCB Channel Indicator" },    /*  9.3.44 */
/* 0x2f */    { RSL_IE_GRP_CALL_REF,    "Group Call Reference" },       /*  9.3.45 */
/* 0x30 */    { RSL_IE_CH_DESC,         "Channel Description" },        /*  9.3.46 */
/* 0x31 */    { RSL_IE_NCH_DRX_INF,     "NCH DRX Information" },        /*  9.3.47 */
/* 0x32 */    { RSL_IE_CMD_IND,         "Command Indicator" },          /*  9.3.48 */
/* 0x33 */    { RSL_IE_EMLPP_PRIO,      "eMLPP Priority" },             /*  9.3.49 */
/* 0x34 */    { RSL_IE_UIC,             "UIC" },                        /*  9.3.50 */
/* 0x35 */    { RSL_IE_MAIN_CH_REF,     "Main Channel Reference" },     /*  9.3.51 */
/* 0x36 */    { RSL_IE_MULTIRATE_CONF,  "MultiRate Configuration" },    /*  9.3.52 */
/* 0x37 */    { RSL_IE_MULTIRATE_CNTRL, "MultiRate Control" },          /*  9.3.53 */
/* 0x38 */    { RSL_IE_SUP_CODEC_TYPES, "Supported Codec Types" },      /*  9.3.54 */
/* 0x39 */    { RSL_IE_CODEC_CONF,      "Codec Configuration" },        /*  9.3.55 */
/* 0x3a */    { RSL_IE_RTD,             "Round Trip Delay" },           /*  9.3.56 */
/* 0x3b */    { RSL_IE_TFO_STATUS,      "TFO Status" },                 /*  9.3.57 */
/* 0x3c */    { RSL_IE_LLP_APDU,        "LLP APDU" },                   /*  9.3.58 */
/* 0x3d */    { RSL_IE_TFO_TRANSP_CONT, "TFO Transparent Container" },  /*  9.3.59 */
    /*
            0 0 1 1 1 1 1 0
            to
            1 1 1 0 1 1 1 1
            Reserved for future use

            1 1 1 1 0 0 0 0
            to
            1 1 1 1 1 1 1 1
            Not used

    */
/* 0x60 */    { RSL_IE_OSMO_REP_ACCH_CAP, "Repeated ACCH Capabilities" },
/* 0x61 */    { RSL_IE_OSMO_TRAINING_SEQUENCE, "Training Sequence Code/Set" },
/* 0x62 */    { RSL_IE_OSMO_TOP_ACCH_CAP, "Temporary ACCH Overpower Capabilities" },
/* 0x63 */    { RSL_IE_OSMO_OSMUX_CID, "Osmux CID" },
/* 0xe0 */    { RSL_IE_IPAC_SRTP_CONFIG,"SRTP Configuration" },
/* 0xe1 */    { RSL_IE_IPAC_PROXY_UDP,  "BSC Proxy UDP Port" },
/* 0xe2 */    { RSL_IE_IPAC_BSCMPL_TOUT,"BSC Multiplex Timeout" },
/* 0xf0 */    { RSL_IE_IPAC_REMOTE_IP,  "Remote IP Address" },
/* 0xf1 */    { RSL_IE_IPAC_REMOTE_PORT,"Remote RTP Port" },
/* 0xf2 */    { RSL_IE_IPAC_RTP_PAYLOAD,"RTP Payload Type" },
/* 0xf3 */    { RSL_IE_IPAC_LOCAL_PORT, "Local RTP Port" },
/* 0xf4 */    { RSL_IE_IPAC_SPEECH_MODE,"Speech Mode" },
/* 0xf5 */    { RSL_IE_IPAC_LOCAL_IP,   "Local IP Address" },
/* 0xf6 */    { RSL_IE_IPAC_CONN_STAT,  "Connection Statistics" },
/* 0xf7 */    { RSL_IE_IPAC_HO_C_PARMS, "Handover C Parameters" },
/* 0xf8 */    { RSL_IE_IPAC_CONN_ID,    "Connection Identifier" },
/* 0xf9 */    { RSL_IE_IPAC_RTP_CSD_FMT,"RTP CSD Format" },
/* 0xfa */    { RSL_IE_IPAC_RTP_JIT_BUF,"RTP Jitter Buffer" },
/* 0xfb */    { RSL_IE_IPAC_RTP_COMPR,  "RTP Compression" },
/* 0xfc */    { RSL_IE_IPAC_RTP_PAYLOAD2,"RTP Payload Type 2" },
/* 0xfd */    { RSL_IE_IPAC_RTP_MPLEX,  "RTP Multiplex" },
/* 0xfe */    { RSL_IE_IPAC_RTP_MPLEX_ID,"RTP Multiplex Identifier" },
    { 0, NULL }
};
static value_string_ext rsl_ie_type_vals_ext = VALUE_STRING_EXT_INIT(rsl_ie_type_vals);


/*
C5  C4  C3  C2  C1
0   0   0   0   1   Bm + ACCH's
0   0   0   1   T   Lm + ACCH's
0   0   1   T   T   SDCCH/4 + ACCH
0   1   T   T   T   SDCCH/8 + ACCH
1   0   0   0   0   BCCH
1   0   0   0   1   Uplink CCCH (RACH)
1   0   0   1   0   Downlink CCCH (PCH + AGCH)
*/
static const value_string rsl_ch_no_Cbits_vals[] = {
    {  0x01,    "Bm + ACCH" },
    {  0x02,    "Lm + ACCH (sub-chan 0)" },
    {  0x03,    "Lm + ACCH (sub-chan 1)" },
    {  0x04,    "SDCCH/4 + ACCH (sub-chan 0)" },
    {  0x05,    "SDCCH/4 + ACCH (sub-chan 1)" },
    {  0x06,    "SDCCH/4 + ACCH (sub-chan 2)" },
    {  0x07,    "SDCCH/4 + ACCH (sub-chan 3)" },
    {  0x08,    "SDCCH/8 + ACCH (sub-chan 0)" },
    {  0x09,    "SDCCH/8 + ACCH (sub-chan 1)" },
    {  0x0a,    "SDCCH/8 + ACCH (sub-chan 2)" },
    {  0x0b,    "SDCCH/8 + ACCH (sub-chan 3)" },
    {  0x0c,    "SDCCH/8 + ACCH (sub-chan 4)" },
    {  0x0d,    "SDCCH/8 + ACCH (sub-chan 5)" },
    {  0x0e,    "SDCCH/8 + ACCH (sub-chan 6)" },
    {  0x0f,    "SDCCH/8 + ACCH (sub-chan 7)" },
    {  0x10,    "BCCH" },
    {  0x11,    "Uplink CCCH (RACH)" },
    {  0x12,    "Downlink CCCH (PCH + AGCH)" },
    /* used by Osmocom and Ericsson */
    {  0x18,    "PDCH" },
    { 0,            NULL }
};
static value_string_ext rsl_ch_no_Cbits_vals_ext = VALUE_STRING_EXT_INIT(rsl_ch_no_Cbits_vals);

#define RSL_PHY_CTX_IE_EXT_RAND_ACCES 0x42
#define RSL_PHY_CTX_IE_AB_RX_LEVEL_ERR_BITS 0x43
#define RSL_PHY_CTX_IE_RX_LEVEL_EXT 0x45

/* Physical Context IE vals*/
static const value_string rsl_phy_con_ie_vals[] = {
    {  RSL_PHY_CTX_IE_EXT_RAND_ACCES,           "Ext RandAccess" },
    {  RSL_PHY_CTX_IE_AB_RX_LEVEL_ERR_BITS,     "AB RxLevel&ErrBits" },
    {  RSL_PHY_CTX_IE_RX_LEVEL_EXT,             "RxLevel Ext" },
    { 0,            NULL }
};
static value_string_ext rsl_phy_con_ie_vals_ext = VALUE_STRING_EXT_INIT(rsl_phy_con_ie_vals);

/* Section 9.3.41 CB Command Type; bits 5 to 8 */
static const value_string rsl_cb_cmd_type_vals[] = {
    { 0x0, "Normal Message Broadcast" },
    { 0x8, "Schedule Message Broadcast" },
    { 0xE, "Default Message Broadcast" },
    { 0xF, "Null Message Broadcast" },
    { 0, NULL }
};

/* Section 9.3.41 CB Command Type; bit 4 */
static const value_string rsl_cb_cmd_type_def_bcast_vals[] = {
    { 0x0, "Normal Message" },
    { 0x1, "Null Message" },
    { 0, NULL }
};

/* Section 9.3.41 CB Command Type; bits 1 and 2 */
static const value_string rsl_cb_cmd_type_last_block_vals[] = {
    { 0x0, "Block 4/4" },
    { 0x1, "Block 1/4" },
    { 0x2, "Block 2/4" },
    { 0x3, "Block 3/4" },
    { 0, NULL }
};


/* From openbsc/include/openbsc/tlv.h */
enum tlv_type {
    TLV_TYPE_UNKNOWN,
    TLV_TYPE_FIXED,
    TLV_TYPE_T,
    TLV_TYPE_TV,
    TLV_TYPE_TLV,
    TLV_TYPE_TL16V
};

struct tlv_def {
    enum tlv_type type;
    uint8_t       fixed_len;
};

struct tlv_definition {
    struct tlv_def def[0x100];
};

/* This structure is initialized in proto_register_rsl() */
static struct tlv_definition rsl_att_tlvdef;

/* 9.3.1 Channel number         9.3.1   M TV 2 */
static int
dissect_rsl_ie_ch_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CH_NO)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_ch_no, NULL, "Channel number IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* C-bits */
    proto_tree_add_item(ie_tree, hf_rsl_ch_no_Cbits, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* TN is time slot number, binary represented as in 3GPP TS 45.002.
     * 3 Bits
     */
    proto_tree_add_item(ie_tree, hf_rsl_ch_no_TN, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}

static const value_string rsl_ch_type_vals[] = {
    {  0x00,    "Main signalling channel (FACCH or SDCCH)" },
    {  0x01,    "SACCH" },
    { 0,            NULL }
};

static const value_string rsl_prio_vals[] = {
    {  0x00,    "Normal Priority" },
    {  0x01,    "High Priority" },
    {  0x02,    "Low Priority" },
    { 0,            NULL }
};

/*
 * 9.3.2 Link Identifier M TV 2
 */
static int
dissect_rsl_ie_link_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     octet;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_LINK_ID)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_link_id, NULL, "Link Identifier IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    octet = tvb_get_uint8(tvb, offset);

    if ((octet & 0x20) == 0x20) {
        /* Not applicable */
        proto_tree_add_item(ie_tree, hf_rsl_na, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        return offset;
    }
    /* channel type */
    proto_tree_add_item(ie_tree, hf_rsl_ch_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* NA - Not applicable */
    proto_tree_add_item(ie_tree, hf_rsl_na, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Priority */
    proto_tree_add_item(ie_tree, hf_rsl_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* SAPI
     * The SAPI field contains the SAPI value as defined in 3GPP TS 44.005.
     */
    proto_tree_add_item(ie_tree, hf_rsl_sapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.3 Activation Type
 */
static const true_false_string rsl_rbit_vals = {
  "Reactivation",
  "Initial activation"
};

static const value_string rsl_a3a2_vals[] = {
    {  0x00,    "Activation related to intra-cell channel change" },
    {  0x01,    "Activation related to inter-cell channel change (handover)" },
    {  0x02,    "Activation related to secondary channels" },
    /* non-standard value used by Ericsson */
    {  0x03,    "Activation related to packet data channel" },
    { 0,            NULL }
};

static const true_false_string rsl_a1_0_vals = {
  "related to normal assignment procedure",
  "related to immediate assignment procedure"
};

static const true_false_string rsl_a1_1_vals = {
  "related to synchronous handover procedure",
  "related to asynchronous handover procedure"
};

static const true_false_string rsl_a1_2_vals = {
  "related to multislot configuration",
  "related to additional assignment procedure"
};

static int
dissect_rsl_ie_act_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;
    unsigned    octet;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_ACT_TYPE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_act_type, NULL, "Activation Type IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* The R bit indicates if the procedure is an initial activation or a reactivation. */
    proto_tree_add_item(ie_tree, hf_rsl_rbit, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* The A-bits indicate the type of activation, which defines the access procedure
     * and the operation of the data link layer
     */
    octet = (tvb_get_uint8(tvb, offset) & 0x06) >> 1;
    proto_tree_add_item(ie_tree, hf_rsl_a3a2, tvb, offset, 1, ENC_BIG_ENDIAN);
    switch (octet) {
    case 0:
        /* Activation related to intra-cell channel change */
        proto_tree_add_item(ie_tree, hf_rsl_a1_0, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 1:
        /* Activation related to inter-cell channel change (handover) */
        proto_tree_add_item(ie_tree, hf_rsl_a1_1, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* Activation related to secondary channels */
        proto_tree_add_item(ie_tree, hf_rsl_a1_2, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        break;
    }
    offset++;

    return offset;
}
/*
 * 9.3.4 BS Power
 */

static const true_false_string rsl_epc_mode_vals = {
  "Channel in EPC mode",
  "Channel not in EPC mode"
};

static const true_false_string rsl_fpc_epc_mode_vals = {
  "Fast Power Control in use",
  "Fast Power Control not in use"
};

static const value_string rsl_rlm_bs_power_vals[] = {
    {  0x00,    "Pn" },
    {  0x01,    "Pn - 2 dB" },
    {  0x02,    "Pn - 4 dB" },
    {  0x03,    "Pn - 6 dB" },
    {  0x04,    "Pn - 8 dB" },
    {  0x05,    "Pn - 10 dB" },
    {  0x06,    "Pn - 12 dB" },
    {  0x07,    "Pn - 14 dB" },
    {  0x08,    "Pn - 16 dB" },
    {  0x09,    "Pn - 18 dB" },
    {  0x0a,    "Pn - 20 dB" },
    {  0x0b,    "Pn - 22 dB" },
    {  0x0c,    "Pn - 24 dB" },
    {  0x0d,    "Pn - 26 dB" },
    {  0x0e,    "Pn - 28 dB" },
    {  0x0f,    "Pn - 30 dB" },
    { 0,            NULL }
};
static value_string_ext rsl_rlm_bs_power_vals_ext = VALUE_STRING_EXT_INIT(rsl_rlm_bs_power_vals);

static int
dissect_rsl_ie_bs_power(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_BS_POW)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_bs_power, NULL, "BS Power IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* EPC mode */
    proto_tree_add_item(ie_tree, hf_rsl_epc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* FPC_EPC mode */
    proto_tree_add_item(ie_tree, hf_rsl_bs_fpc_epc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* The Power Level field (octet 2) indicates the number of 2 dB steps by
     * which the power shall be reduced from its nominal value, Pn,
     * set by the network operator to adjust the coverage.
     * Thus the Power Level values correspond to the following powers (relative to Pn):
     */
    proto_tree_add_item(ie_tree, hf_rsl_bs_power, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/*
 * 9.3.5 Channel Identification
 */
static int
dissect_rsl_ie_ch_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint32_t    ma_length;
    uint8_t     length;
    int         ie_offset;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CH_ID)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ch_id, &ti, "Channel Identification IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    ie_offset = offset;

    /* 3GPP TS 44.018 "Channel Description"
     * the whole of the 3GPP TS 44.018 element including the element identifier and
     * length should be included.
     * XXX Hmm a type 3 IE (TV).
     */
    proto_tree_add_item(ie_tree, hf_rsl_channel_description_tag, tvb, offset, 1, ENC_NA);
    de_rr_ch_dsc(tvb, ie_tree, pinfo, offset+1, length, NULL, 0);
    offset += 4;

    /* 3GPP TS 48.058 (version 15.0.0), section 9.3.5 "Channel Identification" states
     * that the 3GPP TS 44.018 "Mobile Allocation" IE shall for compatibility reasons
     * be included but empty, i.e. the length shall be zero. Decode it anyway. */
    proto_tree_add_item(ie_tree, hf_rsl_mobile_allocation_tag, tvb, offset++, 1, ENC_NA);
    proto_tree_add_item_ret_uint(ie_tree, hf_rsl_mobile_allocation_len,
                                 tvb, offset++, 1, ENC_NA, &ma_length);
    if (ma_length > 0) {
        de_rr_mob_all(tvb, ie_tree, pinfo, offset, ma_length, NULL, 0);
        proto_tree_add_expert(ie_tree, pinfo, &ei_rsl_mobile_allocation_deprecated,
                              tvb, offset, ma_length);
    }

    return ie_offset + length;
}
/*
 * 9.3.6 Channel Mode
 */

static const true_false_string rsl_dtx_vals = {
  "DTX is applied",
  "DTX is not applied"
};
static const value_string rsl_speech_or_data_vals[] = {
    {  0x01,    "Speech" },
    {  0x02,    "Data" },
    {  0x03,    "Signalling" },
    { 0,            NULL }
};
static const value_string rsl_ch_rate_and_type_vals[] = {
    {  0x01,    "SDCCH" },
    {  0x08,    "Full rate TCH channel Bm" },
    {  0x09,    "Half rate TCH channel Lm" },
    {  0x0a,    "Full rate TCH channel bi-directional Bm, Multislot configuration" },
    {  0x18,    "Full rate TCH channel Bm Group call channel" },
    {  0x19,    "Half rate TCH channel Lm Group call channel" },
    {  0x1a,    "Full rate TCH channel uni-directional downlink Bm, Multislot configuration" },
    {  0x28,    "Full rate TCH channel Bm Broadcast call channel" },
    {  0x29,    "PHalf rate TCH channel Lm Broadcast call channel" },
    /* Osmocom specific extensions: */
    {  0x88,    "Full rate TCH channel Bm in VAMOS mode" },
    {  0x89,    "Half rate TCH channel Lm in VAMOS mode" },
    { 0,            NULL }
};
static value_string_ext rsl_ch_rate_and_type_vals_ext = VALUE_STRING_EXT_INIT(rsl_ch_rate_and_type_vals);

static const value_string rsl_speech_coding_alg_vals[] = {
    {  0x01,    "GSM speech coding algorithm version 1: GSM FR or GSM HR" },
    {  0x11,    "GSM speech coding algorithm version 2: GSM EFR (half rate not defined in this version of the protocol)" },
    {  0x21,    "GSM speech coding algorithm version 3: FR AMR or HR AMR" },
    {  0x31,    "GSM speech coding algorithm version 4: OFR AMR-WB or OHR AMR-WB" },
    {  0x09,    "GSM speech coding algorithm version 5: FR AMR-WB" },
    {  0x0d,    "GSM speech coding algorithm version 6: OHR AMR" },
    { 0,            NULL }
};

static const true_false_string t_nt_bit_vals = {
  "Non-transparent service",
  "Transparent service"
};

static const value_string rsl_ra_if_data_rte_vals[] = {
    {  0x21,    "asymmetric 43.5 kbit/s (downlink) + 14.5 kbit/s (uplink)" },
    {  0x22,    "asymmetric 29.0 kbit/s (downlink) + 14.5 kbit/s (uplink)" },
    {  0x23,    "asymmetric 43.5 kbit/s (downlink) + 29.0 kbit/s (uplink)" },
    {  0x29,    "asymmetric 14.5 kbit/s (downlink) + 43.5 kbit/s (uplink)" },
    {  0x2a,    "asymmetric 14.5 kbit/s (downlink) + 29.0 kbit/s (uplink)" },
    {  0x2b,    "asymmetric 29.0 kbit/s (downlink) + 43.5 kbit/s (uplink)" },
    {  0x34,    "43.5 kbit/s" },
    {  0x31,    "28.8 kbit/s" },
    {  0x18,    "14.5 kbit/s" },
    {  0x10,    "12 kbit/s" },
    {  0x11,    "6 kbit/s" },
    { 0,            NULL }
};

static const value_string rsl_data_rte_vals[] = {
    {  0x38,    "32 kbit/s" },
    {  0x39,    "29 kbit/s" },
    {  0x18,    "14.4 kbit/s" },
    {  0x10,    "9.6 kbit/s" },
    {  0x11,    "4.8 kbit/s" },
    {  0x12,    "2.4 kbit/s" },
    {  0x13,    "1.2 kbit/s" },
    {  0x14,    "600 bit/s" },
    {  0x15,    "1 200/75 bit/s (1 200 network-to-MS, 75 MS-to-network)" },
    { 0,            NULL }
};

static int
dissect_rsl_ie_ch_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     length;
    int         ie_offset;
    uint8_t     ie_id;
    uint8_t     octet;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CH_MODE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ch_mode, &ti, "Channel Mode IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /* The DTX bits of octet 3 indicate whether DTX is applied
     * DTXd indicates use of DTX in the downlink direction (BTS to MS) and
     * DTXu indicates use of DTX in the uplink direction (MS to BTS).
     */
    proto_tree_add_item(ie_tree, hf_rsl_cm_dtxd, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_cm_dtxu, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The "Speech or data indicator" field (octet 4) */
    proto_tree_add_item(ie_tree, hf_rsl_speech_or_data, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_uint8(tvb, offset);
    offset++;
    /* Channel rate and type */
    proto_tree_add_item(ie_tree, hf_rsl_ch_rate_and_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Speech coding algor./data rate + transp ind */
    switch (octet) {
    case 1:
        /* Speech */
        proto_tree_add_item(ie_tree, hf_rsl_speech_coding_alg, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* Data */
        proto_tree_add_item(ie_tree, hf_rsl_extension_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ie_tree, hf_rsl_t_nt_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        octet = tvb_get_uint8(tvb, offset);
        if ((octet & 0x40) == 0x40) {
            /* Non-transparent service */
            /* For the non-transparent service, bits 6 to 1 indicate the radio interface data rate:*/
            proto_tree_add_item(ie_tree, hf_rsl_ra_if_data_rte, tvb, offset, 1, ENC_BIG_ENDIAN);
        }else{
            /* For the transparent service, bits 6-1 indicate the data rate: */
            proto_tree_add_item(ie_tree, hf_rsl_data_rte, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        break;
    case 3:
        /* Signalling
         * If octet 4 indicates signalling then octet 6 is coded as follows:
         * 0000 0000 No resources required
         */
        proto_tree_add_item(ie_tree, hf_rsl_no_resources_required, tvb, offset, 1, ENC_NA);
        break;
    default:
        /* Should not happen */
        proto_tree_add_expert(ie_tree, pinfo, &ei_rsl_speech_or_data_indicator, tvb, offset, 1);
        break;
    }

    offset++;

    return ie_offset + length;
}

/*
 * 9.3.7 Encryption information
 */

/* The Algorithm Identifier field (octet 3) indicates the relevant ciphering algorithm. It is coded as: */
static const value_string rsl_algorithm_id_vals[] = {
    {  0x00,    "Reserved" },
    {  0x01,    "No encryption shall be used" },
    {  0x02,    "GSM encryption algorithm version 1 (A5/1)" },
    {  0x03,    "GSM A5/2" },
    {  0x04,    "GSM A5/3" },
    {  0x05,    "GSM A5/4" },
    {  0x06,    "GSM A5/5" },
    {  0x07,    "GSM A5/6" },
    {  0x08,    "GSM A5/7" },
    { 0,            NULL }
};

static int
dissect_rsl_ie_enc_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_ENC_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_enc_inf, &ti, "Encryption information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Algorithm Identifier field (octet 3) */
    proto_tree_add_item(ie_tree, hf_rsl_alg_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* key */
    proto_tree_add_item(ie_tree, hf_rsl_key, tvb, offset+1, length -1, ENC_NA);

    return offset + length;

}
/*
 * 9.3.8 Frame Number
 */
static int
dissect_rsl_ie_frame_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    proto_item *ti;
    uint8_t     ie_id;
    uint16_t    rfn;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_FRAME_NO)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_ie_frame_no, NULL, "Frame Number IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    rfn = parse_reduced_frame_number(tvb, offset);
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ti = proto_tree_add_uint(ie_tree, hf_rsl_req_ref_rfn, tvb, offset - 2, 2, rfn);
    proto_item_set_generated(ti);

    return offset;
}

/*
 * 9.3.9 Handover reference
 */
static int
dissect_rsl_ie_ho_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_HO_REF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_ho_ref, NULL, "Handover reference IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Hand-over reference */
    proto_tree_add_item(ie_tree, hf_rsl_ho_ref, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.10 L1 Information
 */

static int
dissect_rsl_ie_l1_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_L1_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_ie_l1_inf, NULL, "L1 Information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Octets 2-3 contain the L1 header information of SACCH blocks.
     * The information fields and codings are as defined in 3GPP TS 44.004.
     */
    /* Power level */
    proto_tree_add_item(ie_tree, hf_rsl_l1inf_power_lev, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* FPC */
    proto_tree_add_item(ie_tree, hf_rsl_l1inf_fpc, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* SRR (SACCH Repetition Request) bit */
    proto_tree_add_item(ie_tree, hf_rsl_l1inf_srr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Actual Timing Advance */
    proto_tree_add_item(ie_tree, hf_rsl_act_timing_adv, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

typedef enum
{
   L3_INF_CCCH,
   L3_INF_SACCH,
   L3_INF_OTHER
}l3_inf_t;
/*
 * 9.3.11 L3 Information            9.3.11  M TLV >=3
 *
 * This element contains a link layer service data unit (L3 message).
 * It is used to forward a complete L3 message as specified in
 * 3GPP TS 24.008 or 3GPP TS 44.018 between BTS and BSC.
 */
static int
dissect_rsl_ie_L3_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory, l3_inf_t type)
{
    proto_item *ti;
    proto_tree *ie_tree;
    tvbuff_t   *next_tvb;
    uint16_t    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_L3_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_L3_inf, &ti, "L3 Information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, length+3);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset= offset+2;

    if (type == L3_INF_CCCH)
    {
       /* L3 PDUs carried on CCCH have L2 PSEUDO LENGTH octet or are RR Short PD format */
       proto_tree_add_item(ie_tree, hf_rsl_llsdu_ccch, tvb, offset, length, ENC_NA);
       next_tvb = tvb_new_subset_length(tvb, offset, length);
       /* The gsm_a_ccch dissector is the only one handling messages with L2 pseudo-length,
        * so we pass it also downlink SACCH (SI5/SI6 and related) */
       call_dissector(gsm_a_ccch_handle, next_tvb, pinfo, top_tree);
    }
    else if (type == L3_INF_SACCH)
    {
       /* L3 PDUs carried on SACCH are normal format or are RR Short PD format */
       proto_tree_add_item(ie_tree, hf_rsl_llsdu_sacch, tvb, offset, length, ENC_NA);
       next_tvb = tvb_new_subset_length(tvb, offset, length);
       call_dissector(gsm_a_sacch_handle, next_tvb, pinfo, top_tree);
    }
    else
    {
       /* Link Layer Service Data Unit (i.e. a layer 3 message
        * as defined in 3GPP TS 24.008 or 3GPP TS 44.018)
        */
       proto_tree_add_item(ie_tree, hf_rsl_llsdu, tvb, offset, length, ENC_NA);
       next_tvb = tvb_new_subset_length(tvb, offset, length);
       call_dissector(gsm_a_dtap_handle, next_tvb, pinfo, top_tree);
    }

    offset = offset + length;

    return offset;
 }

/*
 * 9.3.12 MS Identity
 */
static int
dissect_rsl_ie_ms_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MS_ID)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ms_id, &ti, "MS Identity IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    de_mid(tvb, ie_tree, pinfo, offset, length, NULL, 0);

    offset = offset + length;

    return offset;
}


/*
 * 9.3.13 MS Power
 */
static int
dissect_rsl_ie_ms_pow(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MS_POW)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_ms_pow, NULL, "MS Power IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* MS power level */
    proto_tree_add_item(ie_tree, hf_rsl_ms_power_lev, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* FPC */
    proto_tree_add_item(ie_tree, hf_rsl_ms_fpc, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Reserved */
    offset++;

    return offset;
}

/*
 * 9.3.14 Paging Group M TV 2 2
 */
static int
dissect_rsl_ie_paging_grp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_PAGING_GRP)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_paging_grp, NULL, "Paging Group IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* The Paging Group field (octet 2) contains the binary representation of the paging
     * group as defined in 3GPP TS 45.002.
     */
    proto_tree_add_item(ie_tree, hf_rsl_paging_grp, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;

}

/*
 * 9.3.15 Paging Load
 */
static int
dissect_rsl_ie_paging_load(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_PAGING_LOAD)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_ie_paging_load, NULL, "Paging Load IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
     * Paging Buffer Space.
     */
    proto_tree_add_item(ie_tree, hf_rsl_paging_load, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    return offset;

}

/* Physical Context dissection *
 * Rx Level Ext *
 *
 */
static int
dissect_rsl_phy_ctx_rx_lvl_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree *rxlvl_ext_tree;
    proto_item *ti;
    int length;

    rxlvl_ext_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_phy_ctx_rxlvl_ext, &ti, "RxLevel Rxt (called in Pre-processed Measurements)");

    /* Phy Ctx Element Identifier */
    proto_tree_add_item(rxlvl_ext_tree, hf_rsl_phy_ctx_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length + 2);
    proto_tree_add_item(rxlvl_ext_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Rx Level Ext */
    proto_tree_add_item(rxlvl_ext_tree, hf_rsl_phy_ctx_rx_lvl_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/* Physical Context dissection*
 * AB RxLevel&ErrBits *
 *
 */
static int
dissect_rsl_phy_ctx_ab_rx_lvl_err_bits(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree *ab_tree;
    proto_tree *ti;
    int length;

    ab_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_phy_ctx_ab_rx_lvl_err_bits, &ti, "AB RxLevel&ErrBits IE");

    /* Phy Ctx Element Identifier */
    proto_tree_add_item(ab_tree, hf_rsl_phy_ctx_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length + 2);
    proto_tree_add_item(ab_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* AB Rx Level */
    proto_tree_add_item(ab_tree, hf_rsl_phy_ctx_ab_rx_lvl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Training Err Bits */
    proto_tree_add_item(ab_tree, hf_rsl_phy_ctx_ab_err_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}
/* Physcial Context dissection*
 * Ext RandAccess *
 *
 */
static int
dissect_rsl_phy_ctx_ext_rand_access(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree *ext_rand_access_tree;
    proto_item *ti;
    unsigned length;

    ext_rand_access_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_phy_ctx_ie_ext_rand_access, &ti, "Ext RandAccess IE");
    /* Phy Ctx Element identifier */
    proto_tree_add_item(ext_rand_access_tree, hf_rsl_phy_ctx_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ext_rand_access_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ext_rand_access_tree, hf_rsl_phy_ctx_ext_rand_access, tvb, offset, length, ENC_NA);
    offset = offset + length;
    return offset;
}
/* Physical Context IE dissection
 *
 */
static int
dissect_phy_ctx_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, uint8_t length)
{
    proto_tree *phy_ctx_tree;
    uint8_t phy_ctx_ie_type;

    phy_ctx_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_phy_ctx_ie, NULL, "Physical Context dissection");
    phy_ctx_ie_type = tvb_get_uint8(tvb, offset);

    switch (phy_ctx_ie_type) {
        /* Ext RandAccess */
        case RSL_PHY_CTX_IE_EXT_RAND_ACCES:
            /* Ext RandAccess */
            offset = dissect_rsl_phy_ctx_ext_rand_access(tvb, pinfo, phy_ctx_tree, offset);
            /* AB Rx Level */
            offset = dissect_rsl_phy_ctx_ab_rx_lvl_err_bits(tvb, pinfo, phy_ctx_tree, offset);
            /* Rx Level Ext */
            offset = dissect_rsl_phy_ctx_rx_lvl_ext(tvb, pinfo, phy_ctx_tree, offset);
            break;
        /* AB RxLevel&ErrBits */
        case RSL_PHY_CTX_IE_AB_RX_LEVEL_ERR_BITS:
            /* AB Rx Level */
            offset = dissect_rsl_phy_ctx_ab_rx_lvl_err_bits(tvb, pinfo, phy_ctx_tree, offset);
            /* Rx Level Ext */
            offset = dissect_rsl_phy_ctx_rx_lvl_ext(tvb, pinfo, phy_ctx_tree, offset);
            break;
        /* RXLevelExt */
        case RSL_PHY_CTX_IE_RX_LEVEL_EXT:
            /* Rx Level Ext */
            offset = dissect_rsl_phy_ctx_rx_lvl_ext(tvb, pinfo, phy_ctx_tree, offset);
            break;
        default:
            break;
    }

    return offset;
}

/*
 * 9.3.16 Physical Context TLV
 */
static int
dissect_rsl_ie_phy_ctx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_PHY_CTX)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_phy_ctx, &ti, "Physical Context IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
     * Physical Context Information:
     *  The Physical Context Information field is not specified.
     *  This information should not be analysed by BSC, but merely
     *  forwarded from one TRX/channel to another.
     */
    if(global_rsl_dissect_phy_ctx_inf){
        offset = dissect_phy_ctx_ie(tvb, pinfo, ie_tree, offset, length);
    }else{
        proto_tree_add_item(ie_tree, hf_rsl_phy_ctx, tvb, offset, length, ENC_NA);
        offset = offset + length;
    }

    return offset;
}
/*
 * 9.3.17 Access Delay M TV 2
 */
static int
dissect_rsl_ie_access_delay(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_ACCESS_DELAY)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_access_delay, NULL, "Access Delay IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_rsl_acc_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}

/*
 * 9.3.18 RACH Load
 */

static int
dissect_rsl_ie_rach_load(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;
    int         ie_offset;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_RACH_LOAD)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_rach_load, &ti, "RACH Load IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /*
     * This element is used to carry information on the load of the RACH (Random Access Channel)
     * associated with this CCCH timeslot. It is of variable length.
     */
    /*  RACH Slot Count */
    proto_tree_add_item(ie_tree, hf_rsl_rach_slot_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset +2;
    length = length -2;
    /* RACH Busy Count */
    proto_tree_add_item(ie_tree, hf_rsl_rach_busy_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset +2;
    length = length -2;

    /* RACH Access Count */
    proto_tree_add_item(ie_tree, hf_rsl_rach_acc_cnt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset +2;
    length = length -2;

    /* Supplementary Information */
    if ( length > 0) {
        proto_tree_add_item(ie_tree, hf_rsl_rach_supplementary_information, tvb, offset, length, ENC_NA);
    }
    offset = ie_offset + length;

    return offset;
}

/*
 * 9.3.19 Request Reference M TV 4
 */
static int
dissect_rsl_ie_req_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree, *ra_tree;
    uint8_t     ie_id;
    uint16_t    rfn;
    proto_item *ti;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_REQ_REF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_ie_req_ref, NULL, "Request Reference IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ti = proto_tree_add_item(ie_tree, hf_rsl_req_ref_ra, tvb, offset, 1, ENC_BIG_ENDIAN);
    ra_tree = proto_item_add_subtree(ti, ett_ie_req_ref_ra);
    proto_tree_add_item(ra_tree, hf_rsl_req_ref_ra_est_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    rfn = parse_reduced_frame_number(tvb, offset);
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ti = proto_tree_add_uint(ie_tree, hf_rsl_req_ref_rfn, tvb, offset - 2, 2, rfn);
    proto_item_set_generated(ti);
    return offset;
}

static const value_string rel_mode_vals[] = {
    {  0x00,    "Normal Release" },
    {  0x01,    "Local End Release" },
    { 0,            NULL }
};

/*
 * 9.3.20 Release Mode              9.3.20  M TV 2
 */
static int
dissect_rsl_ie_rel_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_REL_MODE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_rel_mode, NULL, "Release Mode IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*  The M bit is coded as follows:
     * 0 normal release
     * 1 local end release
     */
    proto_tree_add_item(ie_tree, hf_rsl_rel_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    return offset;
}

static const value_string rsl_rlm_cause_vals[] = {
    {  0x00,    "reserved" },
    {  0x01,    "timer T200 expired (N200+1) times" },
    {  0x02,    "re-establishment request" },
    {  0x03,    "unsolicited UA response" },
    {  0x04,    "unsolicited DM response" },
    {  0x05,    "unsolicited DM response, multiple frame established state" },
    {  0x06,    "unsolicited supervisory response" },
    {  0x07,    "sequence error" },
    {  0x08,    "U-frame with incorrect parameters" },
    {  0x09,    "S-frame with incorrect parameters" },
    {  0x0a,    "I-frame with incorrect use of M bit" },
    {  0x0b,    "I-frame with incorrect length" },
    {  0x0c,    "frame not implemented" },
    {  0x0d,    "SABM command, multiple frame established state" },
    {  0x0e,    "SABM frame with information not allowed in this state" },
    { 0,            NULL }
};
static value_string_ext rsl_rlm_cause_vals_ext = VALUE_STRING_EXT_INIT(rsl_rlm_cause_vals);

/*
 * 9.3.21 Resource Information
 */
static int
dissect_rsl_ie_resource_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     ie_id;
    unsigned    length;
    int         ie_offset;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_RESOURCE_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_resource_inf, &ti, "Resource Information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    ie_offset = offset;

    while (length > 0) {
        proto_tree_add_item(ie_tree, hf_rsl_ch_no_Cbits, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* TN is time slot number, binary represented as in 3GPP TS 45.002.
         * 3 Bits
         */
        proto_tree_add_item(ie_tree, hf_rsl_ch_no_TN, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Interference level (1) */
        /* Interf Band */
        proto_tree_add_item(ie_tree, hf_rsl_interf_band, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Interf Band reserved bits */
        proto_tree_add_item(ie_tree, hf_rsl_interf_band_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        length = length - 2;
    }
    return ie_offset + length;
}

/*
 * 9.3.22 RLM Cause             9.3.22  M TLV 2-4
 */
static int
dissect_rsl_ie_rlm_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;

    unsigned    length;
    /* uint8_t     octet; */
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_RLM_CAUSE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_rlm_cause, &ti, "RLM Cause IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (length == 0)
        return offset;

    /* The Cause Value is a one octet field if the extension bit is set to 0.
     * If the extension bit is set to 1, the Cause Value is a two octet field.
     */
        /* XXX: Code doesn't reflect the comment above ?? */
    /* octet = tvb_get_uint8(tvb, offset); */
    proto_tree_add_item(ie_tree, hf_rsl_extension_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.23 Starting Time
 */
static int
dissect_rsl_ie_starting_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_STARTING_TIME)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_ie_staring_time, NULL, "Starting Time IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.24 Timing Advance
 */
static int
dissect_rsl_ie_timing_adv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_TIMING_ADV)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_timing_adv, NULL, "Timing Advance IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_timing_adv, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.25 Uplink Measurements
 */
static const true_false_string rsl_dtxd_vals = {
  "Employed",
  "Not employed"
};

static int
dissect_rsl_ie_uplik_meas(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    int         ie_offset;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_UPLINK_MEAS)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_uplink_meas, &ti, "Uplink Measurements IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /* Octet 3
     * 8    7    6  5   4   3   2   1
     * rfu  DTXd | RXLEV.FULL.up
     */
    proto_tree_add_item(ie_tree, hf_rsl_dtxd, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_rxlev_full_up, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Octet4
     * 8    7   6   5   4   3   2   1
     * Reserved |  RXLEV.SUB.up 4
     */
    proto_tree_add_item(ie_tree, hf_rsl_rxlev_sub_up, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 5
     * 8    7    6  5   4         3 2   1
     * Reserved | RXQUAL.FULL.up | RXQUAL.SUB.up
     */
    proto_tree_add_item(ie_tree, hf_rsl_rxqual_full_up, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_rxqual_sub_up, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 6 - N
     * Supplementary Measurement Information
     */
    return ie_offset+length;
}

 /*
  * 9.3.26 Cause
  */
static const value_string rsl_class_vals[] = {
    {  0x00,    "Normal event" },
    {  0x01,    "Normal event" },
    {  0x02,    "Resource unavailable" },
    {  0x03,    "Service or option not available" },
    {  0x04,    "Service or option not implemented" },
    {  0x05,    "Invalid message (e.g. parameter out of range)" },
    {  0x06,    "Protocol error" },
    {  0x07,    "Interworking" },
    { 0,            NULL }
};

static const value_string rsl_cause_value_vals[] = {
    {  0x00,    "radio interface failure" },
    {  0x01,    "radio link failure" },
    {  0x02,    "handover access failure" },
    /* 0x03..0x06: "reserved for international use" */
    {  0x07,    "O&M intervention" },
    /* 0x08..0x0e: "reserved for international use" */
    {  0x0f,    "normal event, unspecified" },
    /* 0x10..0x17: "reserved for international use" */
    /* 0x18..0x1f: "reserved for national use" */
    {  0x20,    "equipment failure" },
    {  0x21,    "radio resource not available" },
    {  0x22,    "terrestrial channel failure" },
    {  0x23,    "CCCH overload" },
    {  0x24,    "ACCH overload" },
    {  0x25,    "processor overload" },
    /* 0x26: "reserved for international use" */
    {  0x27,    "BTS not equipped" },
    {  0x28,    "remote transcoder issue" },
    /* 0x29..0x2b: "reserved for international use" */
    /* 0x2c..0x2e: "reserved for national use" */
    {  0x2f,    "resource not available, unspecified" },
    {  0x30,    "requested transcoding/rate adaption not available" },
    /* 0x31..0x37: "reserved for international use" */
    /* 0x38..0x3e: "reserved for national use" */
    {  0x3f,    "service or option not implemented, unspecified" },
    {  0x40,    "encryption algorithm not implemented" },
    /* 0x41..0x47: "reserved for international use" */
    /* 0x48..0x4e: "reserved for national use" */
    {  0x4f,    "service or option not implemented, unspecified" },
    {  0x50,    "radio channel already activated/allocated" },
    /* 0x51..0x57: "reserved for international use" */
    /* 0x58..0x5e: "reserved for national use" */
    {  0x5f,    "invalid message, unspecified" },
    {  0x60,    "message discriminator error" },
    {  0x61,    "message type error" },
    {  0x62,    "message sequence error" },
    {  0x63,    "general information element error" },
    {  0x64,    "mandatory information element error" },
    {  0x65,    "optional information element error" },
    {  0x66,    "information element non-existent" },
    {  0x67,    "information element length error" },
    {  0x68,    "invalid information element contents" },
    /* 0x69..0x6b: "reserved for international use" */
    /* 0x6c..0x6e: "reserved for national use" */
    {  0x6f,    "protocol error, unspecified" },
    /* 0x70..0x77: "reserved for international use" */
    /* 0x78..0x7e: "reserved for international use" */
    {  0x7f,    "interworking, unspecified" },
    { 0,            NULL }
};
static value_string_ext rsl_cause_value_vals_ext = VALUE_STRING_EXT_INIT(rsl_cause_value_vals);

static int
dissect_rsl_ie_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     octet;
    int         ie_offset;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CAUSE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_cause, &ti, "Cause IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /* Cause Value */
    octet = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ie_tree, hf_rsl_extension_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ie_tree, hf_rsl_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((octet & 0x80) != 0x80) {
        proto_tree_add_item(ie_tree, hf_rsl_cause_value, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        /* TODO: Cause Extension*/
        offset++;
    }
    offset++;

    /* TODO: Diagnostic(s) if any */
    return ie_offset+length;
}
/*
 * 9.3.27 Measurement result number
 */

static int
dissect_rsl_ie_meas_res_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MEAS_RES_NO)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_meas_res_no, NULL, "Measurement result number IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Measurement result number */
    proto_tree_add_item(ie_tree, hf_rsl_meas_res_no, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/*
 * 9.3.28 Message Identifier
 */
static int
dissect_rsl_ie_message_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MESSAGE_ID)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_message_id, NULL, "Message Identifier IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Message Type */
    proto_tree_add_item(ie_tree, hf_rsl_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}
/*
 * 9.3.30 System Info Type
 */
static const value_string rsl_sys_info_type_vals[] = {
    {  0x00,    "SYSTEM INFORMATION 8" },
    {  0x01,    "SYSTEM INFORMATION 1" },
    {  0x02,    "SYSTEM INFORMATION 2" },
    {  0x03,    "SYSTEM INFORMATION 3" },
    {  0x04,    "SYSTEM INFORMATION 4" },
    {  0x05,    "SYSTEM INFORMATION 5" },
    {  0x06,    "SYSTEM INFORMATION 6" },
    {  0x07,    "SYSTEM INFORMATION 7" },
    {  0x08,    "SYSTEM INFORMATION 16" },
    {  0x09,    "SYSTEM INFORMATION 17" },
    {  0x0a,    "SYSTEM INFORMATION 2bis" },
    {  0x0b,    "SYSTEM INFORMATION 2ter" },
    {  0x0d,    "SYSTEM INFORMATION 5bis" },
    {  0x0e,    "SYSTEM INFORMATION 5ter" },
    {  0x0f,    "SYSTEM INFORMATION 10" },
    {  0x28,    "SYSTEM INFORMATION 13" },
    {  0x29,    "SYSTEM INFORMATION 2quater" },
    {  0x2a,    "SYSTEM INFORMATION 9" },
    {  0x2b,    "SYSTEM INFORMATION 18" },
    {  0x2c,    "SYSTEM INFORMATION 19" },
    {  0x2d,    "SYSTEM INFORMATION 20" },
    {  0x47,    "EXTENDED MEASUREMENT ORDER" },
    {  0x48,    "MEASUREMENT INFORMATION" },
    { 0,            NULL }
};
static value_string_ext rsl_sys_info_type_vals_ext = VALUE_STRING_EXT_INIT(rsl_sys_info_type_vals);


static int
dissect_rsl_ie_sys_info_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                             bool is_mandatory, uint8_t *sys_info_type)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_SYS_INFO_TYPE) {
            *sys_info_type = 0xff;
            return offset;
        }
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_sys_info_type, NULL, "System Info Type IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Message Type */
    *sys_info_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_rsl_sys_info_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.31 MS Power Parameters
 */
static int
dissect_rsl_ie_ms_pow_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     ie_id;

    unsigned    length;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MS_POWER_PARAM)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ms_pow_params, &ti, "MS Power Parameters IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset+length;
}

/*
 * 9.3.32 BS Power Parameters
 */
static int
dissect_rsl_ie_bs_power_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     ie_id;

    unsigned    length;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_BS_POWER_PARAM)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_bs_power_params, &ti, "BS Power Parameters IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset+length;
}

/*
 * 9.3.35 Full Immediate Assign Info TLV 25
 */
static int
dissect_rsl_ie_full_imm_ass_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;

    unsigned    length;
    tvbuff_t    *next_tvb;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_FULL_IMM_ASS_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_full_imm_ass_inf, &ti, "Full Immediate Assign Info IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*  The Full Immediate Assign Info field (octets 3-25)
     * contains a complete immediate assign message (IMMEDIATE ASSIGNMENT or
     * IMMEDIATE ASSIGNMENT EXTENDED or IMMEDIATE ASSIGNMENT REJECT)
     * as defined in 3GPP TS 44.018.
     */
    proto_tree_add_item(ie_tree, hf_rsl_full_immediate_assign_info_field, tvb, offset, length, ENC_NA);
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    call_dissector(gsm_a_ccch_handle, next_tvb, pinfo, top_tree);

    offset = offset + length;

    return offset;
}

/*
 * 9.3.36 SMSCB Information
 *
 * This element is used to convey a complete frame to be broadcast on the CBCH
 * including the Layer 2 header for the radio path.
 */
static int
dissect_rsl_ie_smscb_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    tvbuff_t   *next_tvb;

    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_SMSCB_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_smscb_inf, &ti, "SMSCB Information IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*
     * SMSCB frame
     */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    call_dissector(gsm_cbch_handle, next_tvb, pinfo, top_tree);

    offset = offset + length;

    return offset;
}

/*
 * 9.3.37 MS Timing Offset
 */

static int
dissect_rsl_ie_ms_timing_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_FULL_MS_TIMING_OFFSET)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_ms_timing_offset, NULL, "MS Timing Offset IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Timing Offset
     * The meaning of the MS Timing Offset is as defined in 3GPP TS 45.010.
     * The value of MS Timing Offset is the binary value of the 8-bit Timing Offset field (octet 2) - 63.
     * The range of MS Timing Offset is therefore -63 to 192.
     */
    proto_tree_add_item(ie_tree, hf_rsl_timing_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.38 Erroneous Message
 * This information element is used to carry a complete A-bis interface message
 * which was considered erroneous at reception.
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_rsl_ie_err_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;

    unsigned    length;
    uint8_t     ie_id;
    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_ERR_MSG)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_err_msg, &ti, "Erroneous Message IE ");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);

    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Received Message */
    offset = dissct_rsl_msg(tvb, pinfo, ie_tree, offset);

    return offset;
}

/*
 * 9.3.39 Full BCCH Information (message name)
 */
static int
dissect_rsl_ie_full_bcch_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    tvbuff_t   *next_tvb;
    uint16_t    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_FULL_BCCH_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_full_bcch_inf, &ti, "Full BCCH Information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
     * Octets 3-25 contain the complete L3 message as defined in 3GPP TS 44.018.
     */

    proto_tree_add_item(ie_tree, hf_rsl_layer_3_message, tvb, offset, length, ENC_NA);
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    call_dissector(gsm_a_ccch_handle, next_tvb, pinfo, top_tree);

    offset = offset + length;

    return offset;
 }

/*
 * 9.3.40 Channel Needed
 */
static const value_string rsl_ch_needed_vals[] = {
    {  0x00,    "Any Channel" },
    {  0x01,    "SDCCH" },
    {  0x02,    "TCH/F (Full rate)" },
    {  0x03,    "TCH/F or TCH/H (Dual rate)" },
    { 0,            NULL }
};

static int
dissect_rsl_ie_ch_needed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CH_NEEDED)
            return offset;
    }


    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ch_needed, NULL, "Channel Needed IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Channel */
    proto_tree_add_item(ie_tree, hf_rsl_ch_needed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/*
 * 9.3.41 CB Command type
 */
static int
dissect_rsl_ie_cb_cmd_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CB_CMD_TYPE)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_cb_cmd_type, NULL, "CB Command type IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_cb_cmd_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_cb_def_bcast, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_cb_last_block, tvb, offset, 1, ENC_NA);
    offset++;

    return offset;
}

/*
 * 9.3.42 SMSCB Message
 */
static int
dissect_rsl_ie_smscb_mess(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    tvbuff_t   *next_tvb;
    unsigned    length;
    uint8_t     ie_id;
    int         ie_offset;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_SMSCB_MESS)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_smscb_mess, &ti, "SMSCB Message IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /*
     * SMSCB Message
     */

    next_tvb = tvb_new_subset_length(tvb, offset, length);
    call_dissector(gsm_cbs_handle, next_tvb, pinfo, top_tree);

    offset = ie_offset + length;

    return offset;
}

static int
dissect_rsl_ie_etws_pn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    int         ie_offset;

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_smscb_mess, &ti, "SMSCB Message IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ie_offset = offset;

    /*
     * ETWS Primary Notification
     */

    proto_tree_add_item(ie_tree, hf_rsl_etws_pn, tvb, offset, length, ENC_NA);

    offset = ie_offset + length;

    return offset;
}

/*
 * 9.3.43 CBCH Load Information
 */

static const true_false_string rsl_cbch_load_type_vals = {
  "Overflow",
  "Underflow"
};

static int
dissect_rsl_ie_cbch_load_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *item;
    proto_tree *ie_tree;
    uint8_t     ie_id;
    uint8_t     octet;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CBCH_LOAD_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_cbch_load_inf, NULL, "CBCH Load Information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    octet = tvb_get_uint8(tvb, offset);
    /* CBCH Load Type */
    proto_tree_add_item(ie_tree, hf_rsl_cbch_load_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Message Slot Count */
    item = proto_tree_add_item(ie_tree, hf_rsl_msg_slt_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((octet & 0x80) == 0x80) {
        proto_item_append_text(item, "The amount of SMSCB messages (1 to 15) that are needed immediately by BTS");
    }else{
        proto_item_append_text(item, "The amount of delay in message slots (1 to 15) that is needed immediately by BTS");
    }
    offset++;

    return offset;
}

/*
 * 9.3.44 SMSCB Channel Indicator
 */

static const value_string rsl_ch_ind_vals[] = {
    {  0x00,    "Basic CBCH" },
    {  0x01,    "Extended CBCH (supporting the extended CBCH by the network or MSs is optional)" },
    { 0,            NULL }
};

static int
dissect_rsl_ie_smscb_ch_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_SMSCB_CH_IND)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_smscb_ch_ind, NULL, "SMSCB Channel Indicator IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Channel Ind */
    proto_tree_add_item(ie_tree, hf_rsl_ch_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.45 Group call reference
 */
static int
dissect_rsl_ie_grp_call_ref(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_GRP_CALL_REF)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_grp_call_ref, &ti, "Group call reference IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_descriptive_group_or_broadcast_call_reference, tvb, offset, length, ENC_NA);

    /* The octets 3 to 7 are coded in the same way as the octets 2 to 6
     * in the Descriptive group or broadcast call reference
     * information element as defined in 3GPP TS 24.008.
     */
    de_d_gb_call_ref(tvb, ie_tree, pinfo, offset, length, NULL, 0);

    offset = offset + length;

    return offset;
}
/*
 * 9.3.46 Channel description
 */
static int
dissect_rsl_ie_ch_desc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CH_DESC)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_ch_desc, &ti, "Channel description IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_group_channel_description, tvb, offset, length, ENC_NA);

    /* Octet j (j = 3, 4, ..., n) is the unchanged octet j-2 of a radio interface Group Channel description
     * information element as defined in 3GPP TS 44.018, n-2 is equal to the length of the radio interface
     * Group channel description information element
     */

    offset = offset + length;

    return offset;
}
/*
 * 9.3.47 NCH DRX information
 * This is a variable length element used to pass a radio interface information element
 * from BSC to BTS.
 */
static int
dissect_rsl_ie_nch_drx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_NCH_DRX_INF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_nch_drx, NULL, "NCH DRX information IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* NCH DRX information */
    /* Octet 3 bits 7 and 8 are spare and set to zero. */
    /* Octet 3 bit 6 is the NLN status parameter as defined in 3GPP TS 44.018.*/
    /* Octet 3 bits 3, 4 and 5 are bits 1, 2 and 3 of the radio interface
     * eMLPP priority as defined in 3GPP TS 44.018.
     */
    /* Octet 3 bits 1 and 2 are bits 1 and 2 of the radio interface NLN
     * as defined in 3GPP TS 44.018.
     */

    offset++;

    return offset;
}
/*
 * 9.3.48 Command indicator
 */

static int
dissect_rsl_ie_cmd_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;
    bool        ext;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CMD_IND)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_ie_cmd_ind, &ti, "Command indicator IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length + 2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Extension bit */
    proto_tree_add_item_ret_boolean(ie_tree, hf_rsl_extension_bit, tvb,
                                    offset, 1, ENC_BIG_ENDIAN, &ext);
    if (ext) {
        /* If the extension bit E (bit 8) is set to 1 then the Command value
         * is a 2 octet field (octets 3 and 3a) */
        proto_tree_add_item(ie_tree, hf_rsl_command_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        proto_item *pi;
        uint32_t   value;

        pi = proto_tree_add_item_ret_uint(ie_tree, hf_rsl_command, tvb,
                                          offset, 1, ENC_BIG_ENDIAN, &value);
        offset++;

        if (value == 0x00) /* 0b0000000 */
            proto_item_append_text(pi, " (Start)");
        else if (value == 0x01) /* 0b0000001 */
            proto_item_append_text(pi, " (Stop)");
        else if (value <= 0x40) /* 0b0000010 .. 0b1000000 */
            proto_item_append_text(pi, " (reserved for international use)");
        else /* 0b1000001 .. 0b1111111 */
            proto_item_append_text(pi, " (reserved for national use)");
    }

    return offset;
}
/*
 * 9.3.49 eMLPP Priority
 */
static const value_string rsl_emlpp_prio_vals[] = {
    {  0x00,    "no priority applied" },
    {  0x01,    "call priority level 4" },
    {  0x02,    "call priority level 3" },
    {  0x03,    "call priority level 2" },
    {  0x04,    "call priority level 1" },
    {  0x05,    "call priority level 0" },
    {  0x06,    "call priority level B" },
    {  0x07,    "call priority level A" },
    { 0,            NULL }
};

static int
dissect_rsl_ie_emlpp_prio(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_EMLPP_PRIO)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_emlpp_prio, NULL, "eMLPP Priority IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* The call priority field (bit 3 to 1 of octet 2) is coded in the same way
     * as the call priority field (bit 3 to 1 of octet 5) in the
     * Descriptive group or broadcast call reference information element
     * as defined in 3GPP TS 24.008.
     */
    proto_tree_add_item(ie_tree, hf_rsl_emlpp_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}

/*
 * 9.3.50 UIC
 */
static int
dissect_rsl_ie_uic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_UIC)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_uic, NULL, "UIC IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Octet 3 bits 1 to 6 contain the radio interface octet 2 bits 3 to 8 of the
     * UIC information element as defined in 3GPP TS 44.018.
     */
    proto_tree_add_item(ie_tree, hf_rsl_uic, tvb, offset, 1, ENC_NA);
    offset++;

    return offset;
}

/*
 * 9.3.51 Main channel reference
 */

static int
dissect_rsl_ie_main_ch_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MAIN_CH_REF)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_main_ch_ref, NULL, "Main channel reference IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* TN is time slot number, binary represented as in 3GPP TS 45.002.
     * 3 Bits
     */
    proto_tree_add_item(ie_tree, hf_rsl_ch_no_TN, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}

/*
 * 9.3.52 MultiRate configuration
 */

static int
dissect_rsl_ie_multirate_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MULTIRATE_CONF)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_multirate_conf, &ti, "MultiRate configuration IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Rest of element coded as in 3GPP TS 44.018 not including
     * 3GPP TS 44.018 element identifier or 3GPP TS 44.018 octet length value
     */

    de_rr_multirate_conf(tvb, ie_tree, pinfo, offset, length, NULL, 0);

    offset = offset + length;

    return offset;
}

/*
 * 9.3.53 MultiRate Control
 */
static int
dissect_rsl_ie_multirate_cntrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_MULTIRATE_CNTRL)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_ie_multirate_cntrl, NULL, "MultiRate Control IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Bit 8 -5 Spare */
    /* The OD field (bit 5 of octet 3) indicates if the BSC expects distant parameters or
     * TFO Decision algorithm result from the BTS
     */
    /* The PRE field (bit 4 of octet 3) indicates if an handover is to be expected soon or not. */
    /* The RAE field (bits 2-3, octet 3) defines whether the RATSCCH mechanism is enabled or not.*/
    offset++;

    return offset;
}

/*
 * 9.3.54 Supported Codec Types
 * This element indicates the codec types supported by the BSS or remote BSS.
 */
static int
dissect_rsl_ie_sup_codec_types(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_SUP_CODEC_TYPES)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_sup_codec_types, &ti, "Supported Codec Types IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_rsl_codec_list, tvb, offset, length, ENC_NA);

    /* The Codec List field (octet 4) lists the codec types that are supported
     * by the BSS and Transcoder, and are therefore potential candidates for TFO
     * establishment.
     */
    /* The Codec List extension 1 field (octet 5) lists additional codec types
     * that are supported by the BSS and Transcoder, and are therefore potential
     * candidates for TFO establishment. When no codec from this list is supported,
     * then this field shall not be sent, and the extension bit of octet 4 shall
     * be set to 0.
     */
    /* If bit 4 of the Codec List field (octet 4) indicates that FR AMR is supported
     * or if bit 5 of the Codec List field (octet 4) indicates that HR AMR is supported
     * and bit 8 is set to 0, or if bit 6 of the Codec List field (octet 4) indicates
     * that UMTS AMR is supported, or if bit 7 of the Codec List field (octet 4)
     * indicates that UMTS AMR 2 is supported, or if bit 1, 3, 4 or 5 of the Codec List
     * extension 1 field (octet 5) indicates that AMR WB is supported, the following
     * two octets (after the Codec List field and its extensions) is present
     */

    return offset + length;

}
/*
 * 9.3.55 Codec Configuration
 */
/* The Active Codec Type field (bits 1-8, octet 3) indicates the type of codec in use. It is coded as follows: */
/*
0 0 0 0 . 0 0 0 0: Full Rate Codec in use
0 0 0 0 . 0 0 0 1: Half Rate Codec in use
0 0 0 0 . 0 0 1 0: Enhanced Full Rate Codec in use
0 0 0 0 . 0 0 1 1: FR Adaptive Multi Rate Codec in use
0 0 0 0 . 0 1 0 0: HR Adaptive Multi Rate Codec in use
0 0 0 0 . 0 1 0 1: UMTS Adaptive Multi Rate Codec in use
0 0 0 0 . 0 1 1 0: UMTS Adaptive Multi Rate 2 Codec in use
0 0 0 0 . 1 0 0 1: Full Rate Adaptive Multi-Rate WideBand Codec in use
0 0 0 0 1 0 1 0 UMTS Adaptive Multi-Rate WideBand Codec in use
0 0 0 0 1 0 1 1 8PSK Half Rate Adaptive Multi-Rate Codec in use
0 0 0 0 1 1 0 0 8PSK Full Rate Adaptive Multi-Rate WideBand Codec in use
0 0 0 0 1 1 0 1 8PSK Half Rate Adaptive Multi-Rate WideBand Codec in use
All other values are reserved for future use
*/
static int
dissect_rsl_ie_codec_conf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    unsigned    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_CODEC_CONF)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_codec_conf, &ti, "Codec Configuration IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Active Codec Type */

    return offset + length;
}

/*
 * 9.3.56 Round Trip Delay
 * This element indicates the value of the calculated round trip delay between the BTS
 * and the transcoder, or between the BTS and the remote BTS, if TFO is established.
 */

static const value_string rsl_delay_ind_vals[] = {
    {  0x00,    "The RTD field contains the BTS-Transcoder round trip delay" },
    {  0x01,    "The RTD field contains the BTS-Remote BTS round trip delay" },
    { 0,            NULL }
};
static int
dissect_rsl_ie_rtd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *rtd_item;
    proto_tree *ie_tree;
    uint8_t     ie_id;
    uint8_t     rtd;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_RTD)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_rtd, NULL, "Round Trip Delay IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* The RTD field is the binary representation of the value of the
     * round trip delay in 20 ms increments.
     */
    rtd = (tvb_get_uint8(tvb, offset)>>1)*20;
    rtd_item = proto_tree_add_uint(tree, hf_rsl_rtd, tvb, offset, 1, rtd);
    proto_item_append_text(rtd_item, " ms");

    /* The Delay IND field indicates if the delay corresponds to a BTS
     * to transcoder delay or to a BTS to remote BTS delay.
     */
    proto_tree_add_item(ie_tree, hf_rsl_delay_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/*
 * 9.3.57 TFO Status
 * This element indicates if TFO is established. It is coded in 2 octets
 */

static const true_false_string rsl_tfo_vals = {
  "TFO is established",
  "TFO is not established"
};

static int
dissect_rsl_ie_tfo_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_tree *ie_tree;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_TFO_STATUS)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_tfo_status, NULL, "TFO Status IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ie_tree, hf_rsl_tfo, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    return offset;
}
/*
 * 9.3.58 LLP APDU
 */

static int
dissect_rsl_ie_llp_apdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     length;
    int         ie_offset;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_LLP_APDU)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_llp_apdu, &ti, "LLP APDU IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    ie_offset = offset;

    /* The rest of the information element contains the embedded message
     * that contains a Facility Information Element as defined in
     * 3GPP TS 44.071 excluding the Facility IEI and length of Facility IEI
     * octets defined in 3GPP TS 44.071.
     */
    /* TODO: Given traces with LLP data this IE could be further dissected */
    proto_tree_add_expert(tree, pinfo, &ei_rsl_facility_information_element_3gpp_ts_44071, tvb, offset, length);
    return ie_offset + length;
}
/*
 * 9.3.59 TFO transparent container
 * This is a variable length element that conveys a message associated with TFO protocol,
 * as defined in 3GPP TS 28.062. This element can be sent from the BSC to the BTS or
 * from the BTS to the BSC. The BTS shall retrieve the information it is able to understand,
 * and forward transparently the complete information to the BSC or to the TRAU.
 */
static int
dissect_rsl_ie_tfo_transp_cont(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint8_t     length;
    int         ie_offset;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_TFO_TRANSP_CONT)
            return offset;
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ie_tfo_transp_cont, &ti, "TFO transparent container IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Length */
    length = tvb_get_uint8(tvb, offset);
    proto_item_set_len(ti, length+2);
    proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    ie_offset = offset;

    /* The rest of the information element contains the embedded message
     * that contains a Facility Information Element as defined in
     * 3GPP TS 44.071 excluding the Facility IEI and length of Facility IEI
     * octets defined in 3GPP TS 44.071.
     */
    proto_tree_add_expert(tree, pinfo, &ei_rsl_embedded_message_tfo_configuration, tvb, offset, length);
    return ie_offset + length;
}

/* Encapsulating paging messages into a packet EP2192796 - proprietor Huawei */
static const true_false_string rsl_paging_type_vals = {
    "Packet Switched (PS)",
    "Circuit Switched (CS)"
};

static int
dissect_rsl_paging_group_paras(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree *ie_tree;
    uint8_t    paging_type, i, length;

    /* Paging Type */
    paging_type = (tvb_get_uint8(tvb, offset) & 0x80) >> 7;
    /* Calculating whole length of Paging Package Info */
    if(paging_type == 0){
       length = 2; /* length of Paging Group Paras if it is CS type (2 byte Cs Paging Group Para) */
    }else{
       length = 5; /* length of Paging Group Paras if it is PS type (1 byte spare, 4x 1 byte of PS Paging Group Para */
    }

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ie_paging_group_paras, NULL, "Paging Group Paras");

    /* Paging Type */
    proto_tree_add_item(ie_tree, hf_rsl_paging_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* CS Paging Group */
    if(paging_type == 0){
       proto_tree_add_item(ie_tree, hf_rsl_paging_group_cs, tvb, offset, 1, ENC_BIG_ENDIAN);
       offset++;
       proto_tree_add_item(ie_tree, hf_rsl_paging_group_empty_package, tvb, offset, 1, ENC_BIG_ENDIAN);
       offset++; /* move over empty (0x00) packet */
    }
    /* PS Paging Group */
    else
    {
       proto_tree_add_item(ie_tree, hf_rsl_paging_group_ps_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
       offset++;
       for(i = 1; i <= 4; i++){
           proto_tree_add_item(ie_tree, hf_rsl_paging_grp, tvb, offset, 1, ENC_BIG_ENDIAN);
           offset++;
       }

    }
    return offset;
}
/* Paging Package Channel And eMLPP. REF: EP2192786B1 *
 * Channel Needed *
 * in REF values from 9.3.40 used but "Channel Needed" is optional, and 0 is filled when invalid. *
 * eMLPP Priority *
 * in REf values from 9.3.49 used but "eMLPP Priority" is optional, and 0 is filled when invalid. *
 */
static const value_string rsl_paging_ch_needed_vals[] = {
    {  0x00,   "Invalid Channel" },
    {  0x01,   "SDCCH" },
    {  0x02,   "TCH/F (Full rate)" },
    {  0x03,   "TCH/F or TCH/H (Dual rate)" },
    { 0,               NULL }
};

static const value_string rsl_paging_emlpp_prio_vals[] = {
    {  0x00,    "invalid call priority" },
    {  0x01,    "call priority level 4" },
    {  0x02,    "call priority level 3" },
    {  0x03,    "call priority level 2" },
    {  0x04,    "call priority level 1" },
    {  0x05,    "call priority level 0" },
    {  0x06,    "call priority level B" },
    {  0x07,    "call priority level A" },
    { 0,            NULL }
};

static int
dissect_rsl_paging_package_channel_and_emlpp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree *ie_tree;

    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_ie_paging_package_ch_a_emlpp, NULL, "Channel and eMLPP");

    /* Channel Number */
    proto_tree_add_item(ie_tree, hf_rsl_paging_package_ch_no, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Channel Needed */
    proto_tree_add_item(ie_tree, hf_rsl_paging_package_ch_needed, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* eMLPP Priority */
    proto_tree_add_item(ie_tree, hf_rsl_paging_emlpp_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}
/* Paging Package dissection. REF: EP2192796B1
 *
 */
static int
dissect_rsl_paging_package(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, uint8_t package_number)
{
    proto_tree *ie_tree;
    uint8_t    i, length, paging_type;

    for(i = 1; i <= package_number; i++){
       /* Calculating whole length of Paging Package Info */
        length = (tvb_get_uint8(tvb, offset+2) + 3);
        paging_type = (tvb_get_uint8(tvb, offset + length) & 0x80) >> 7;
       if(paging_type == 0){
           length = length + 2; /* length of Paging Group Paras if it is CS type (2 byte Cs Paging Group Para) */
       }else{
           length = length + 5; /* length of Paging Group Paras if it is PS type (1 byte spare, 4x 1 byte of PS Paging Group Para */
       }

       ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_ie_paging_package, NULL, "Paging Package Info %u", i);

       offset = dissect_rsl_paging_package_channel_and_emlpp(tvb, pinfo, ie_tree, offset);
       offset = dissect_rsl_ie_ms_id(tvb, pinfo, ie_tree, offset, true);

       offset = dissect_rsl_paging_group_paras(tvb, pinfo, ie_tree, offset);
    }

    return offset;
}
/* Paging Package Number dissection. REF: EP2192796B1
 *
 */
static int
dissect_rsl_paging_package_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int *offset)
{
    proto_tree *ie_tree;
    uint8_t package_number;

    ie_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_ie_paging_package_number, NULL, "Paging Package Number");

    /* SPARE */
    proto_tree_add_item(ie_tree, hf_rsl_paging_spare, tvb, *offset, 1, ENC_BIG_ENDIAN);
    /* Paging Msg Number */
    package_number = tvb_get_uint8(tvb, *offset) & 0x0f;
    proto_tree_add_item(ie_tree, hf_rsl_paging_msg_no, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;
    return package_number;
}

static int
dissect_rsl_ie_osmo_rep_acch_cap(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 proto_tree *tree, int offset,
                                 bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint32_t    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_OSMO_REP_ACCH_CAP)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
                                     ett_ie_osmo_rep_acch_cap, &ti,
                                     "Osmocom Repeated ACCH Capabilities IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset++, 1, ENC_NA);
    /* Length */
    proto_tree_add_item_ret_uint(ie_tree, hf_rsl_ie_length, tvb, offset++, 1, ENC_NA, &length);
    proto_item_set_len(ti, length + 2);

    proto_tree_add_item(ie_tree, hf_rsl_osmo_rep_acch_rxqual, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_rep_acch_ul_sacch, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_rep_acch_dl_sacch, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_rep_acch_dl_facch_all, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_rep_acch_dl_facch_cmd, tvb, offset, 1, ENC_NA);
    offset++;

    return offset;
}

static int
dissect_rsl_ie_osmo_top_acch_cap(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 proto_tree *tree, int offset,
                                 bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint32_t    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_OSMO_TOP_ACCH_CAP)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
                                     ett_ie_osmo_top_acch_cap, &ti,
                                     "Osmocom Temporary ACCH Overpower Capabilities IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset++, 1, ENC_NA);
    /* Length */
    proto_tree_add_item_ret_uint(ie_tree, hf_rsl_ie_length, tvb, offset++, 1, ENC_NA, &length);
    proto_item_set_len(ti, length + 2);

    proto_tree_add_item(ie_tree, hf_rsl_osmo_top_acch_sacch, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_top_acch_facch, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_top_acch_rxqual, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_top_acch_val, tvb, offset, 1, ENC_NA);
    offset++;

    return offset;
}

static const value_string rsl_osmo_tsc_set_vals[] = {
    { 0, "TSC Set 1" },
    { 1, "TSC Set 2" },
    { 2, "TSC Set 3" },
    { 3, "TSC Set 4" },
    { 0, NULL }
};

static int
dissect_rsl_ie_osmo_training_seq(tvbuff_t *tvb, packet_info *pinfo _U_,
                                 proto_tree *tree, int offset,
                                 bool is_mandatory)
{
    proto_item *ti;
    proto_tree *ie_tree;
    uint32_t    length;
    uint8_t     ie_id;

    if (is_mandatory == false) {
        ie_id = tvb_get_uint8(tvb, offset);
        if (ie_id != RSL_IE_OSMO_TRAINING_SEQUENCE)
            return offset;
    }
    ie_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
                                     ett_ie_osmo_training_seq, &ti,
                                     "Osmocom Training Sequence IE");

    /* Element identifier */
    proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset++, 1, ENC_NA);
    /* Length */
    proto_tree_add_item_ret_uint(ie_tree, hf_rsl_ie_length, tvb, offset++, 1, ENC_NA, &length);
    proto_item_set_len(ti, length + 2);

    proto_tree_add_item(ie_tree, hf_rsl_osmo_tsc_set, tvb, offset++, 1, ENC_NA);
    proto_tree_add_item(ie_tree, hf_rsl_osmo_tsc_val, tvb, offset++, 1, ENC_NA);

    return offset;
}

struct dyn_pl_info_t {
    uint8_t rtp_codec;
    uint8_t rtp_pt;
};

static int
dissct_rsl_ipaccess_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint8_t msg_type;
    uint32_t local_addr = 0;
    uint16_t local_port = 0;
    uint32_t rtp_codec = 255, rtp_pt = 0;
    address src_addr;
    rtp_dyn_payload_t *dyn_pl = NULL;
    struct dyn_pl_info_t *dyn_pl_info;
    conversation_t *conv;
    bool use_osmux = false;

    msg_type = tvb_get_uint8(tvb, offset) & 0x7f;
    offset++;

    /* parse TLV attributes */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        uint8_t tag;
        unsigned int len, hlen;
        const struct tlv_def *tdef;
        proto_item *ti;
        proto_tree *ie_tree = NULL;

        tag = tvb_get_uint8(tvb, offset);
        tdef = &rsl_att_tlvdef.def[tag];

        switch (tdef->type) {
        case TLV_TYPE_FIXED:
            hlen = 1;
            len = tdef->fixed_len;
            break;
        case TLV_TYPE_T:
            hlen = 1;
            len = 0;
            break;
        case TLV_TYPE_TV:
            hlen = 1;
            len = 1;
            break;
        case TLV_TYPE_TLV:
            hlen = 2;
            len = tvb_get_uint8(tvb, offset+1);
            break;
        case TLV_TYPE_TL16V:
            hlen = 3;
            len = tvb_get_uint8(tvb, offset+1) << 8 |
                tvb_get_uint8(tvb, offset+2);
            break;
        case TLV_TYPE_UNKNOWN:
        default:
            return tvb_reported_length(tvb);
        }


        switch (tag) {
        case RSL_IE_CH_NO:
            dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_FRAME_NO:
            dissect_rsl_ie_frame_no(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_MS_POW:
            dissect_rsl_ie_ms_pow(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_BS_POW:
            dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_MS_POWER_PARAM:
            dissect_rsl_ie_ms_pow_params(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_BS_POWER_PARAM:
            dissect_rsl_ie_bs_power_params(tvb, pinfo, tree, offset, false);
            break;
        case RSL_IE_CAUSE:
            dissect_rsl_ie_cause(tvb, pinfo, tree, offset, false);
            break;
        default:
            ti = proto_tree_add_item(tree, hf_rsl_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            ie_tree = proto_item_add_subtree(ti, ett_ie_local_port);
        }

        offset += hlen;

        switch (tag) {
        case RSL_IE_IPAC_REMOTE_IP:
            proto_tree_add_item(ie_tree, hf_rsl_remote_ip, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_IPAC_REMOTE_PORT:
            proto_tree_add_item(ie_tree, hf_rsl_remote_port, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_IPAC_LOCAL_IP:
            proto_tree_add_item(ie_tree, hf_rsl_local_ip, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            local_addr = tvb_get_ipv4(tvb, offset);
            break;
        case RSL_IE_IPAC_LOCAL_PORT:
            proto_tree_add_item(ie_tree, hf_rsl_local_port, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            local_port = tvb_get_ntohs(tvb, offset);
            break;
        case RSL_IE_IPAC_SPEECH_MODE:
            proto_tree_add_item_ret_uint(ie_tree, hf_rsl_speech_mode_s, tvb,
                                offset, len, ENC_BIG_ENDIAN, &rtp_codec);
            conv = find_or_create_conversation(pinfo);
            dyn_pl_info = (struct dyn_pl_info_t *)conversation_get_proto_data(conv, proto_rsl);
            if (!dyn_pl_info) {
                dyn_pl_info = (struct dyn_pl_info_t *)wmem_alloc0(wmem_file_scope(), sizeof(*dyn_pl_info));
                conversation_add_proto_data(conv, proto_rsl, (void *)dyn_pl_info);
            }
            dyn_pl_info->rtp_codec = rtp_codec;

            proto_tree_add_item(ie_tree, hf_rsl_speech_mode_m, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_IPAC_RTP_PAYLOAD:
        case RSL_IE_IPAC_RTP_PAYLOAD2:
            /* Need to set pl here */
            proto_tree_add_item_ret_uint(ie_tree, hf_rsl_rtp_payload, tvb,
                                offset, len, ENC_BIG_ENDIAN, &rtp_pt);
            conv = find_or_create_conversation(pinfo);
            dyn_pl_info = (struct dyn_pl_info_t *)conversation_get_proto_data(conv, proto_rsl);
            if (!dyn_pl_info) {
                dyn_pl_info = (struct dyn_pl_info_t *)wmem_alloc0(wmem_file_scope(), sizeof(*dyn_pl_info));
                conversation_add_proto_data(conv, proto_rsl, (void *)dyn_pl_info);
                dyn_pl_info->rtp_codec = rtp_codec;
            }
            dyn_pl_info->rtp_pt = rtp_pt;

            break;
        case RSL_IE_IPAC_RTP_CSD_FMT:
            proto_tree_add_item(ie_tree, hf_rsl_rtp_csd_fmt_d, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_rtp_csd_fmt_ir, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_IPAC_CONN_ID:
            proto_tree_add_item(ie_tree, hf_rsl_conn_id, tvb,
                                offset, len, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_IPAC_CONN_STAT:
            proto_tree_add_item(ie_tree, hf_rsl_cstat_tx_pkts, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_tx_octs, tvb,
                                offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_rx_pkts, tvb,
                                offset+8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_rx_octs, tvb,
                                offset+12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_lost_pkts, tvb,
                                offset+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_ia_jitter, tvb,
                                offset+20, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ie_tree, hf_rsl_cstat_avg_tx_dly, tvb,
                                offset+24, 4, ENC_BIG_ENDIAN);
            break;
        case RSL_IE_OSMO_OSMUX_CID:
            if (global_rsl_use_osmo_bts) {
                proto_tree_add_item(ie_tree, hf_rsl_osmo_osmux_cid, tvb,
                                    offset, len, ENC_BIG_ENDIAN);
                use_osmux = true;
            }
            break;
        }
        offset += len;
    }

    switch (msg_type) {
    case RSL_MSG_TYPE_IPAC_CRCX_ACK:
        if (!use_osmux) {
            /* Notify the RTP and RTCP dissectors about a new RTP stream */
            src_addr.type = AT_IPv4;
            src_addr.len = 4;
            src_addr.data = (uint8_t *)&local_addr;

            conv = find_or_create_conversation(pinfo);
            dyn_pl_info = (struct dyn_pl_info_t *)conversation_get_proto_data(conv, proto_rsl);
            if (dyn_pl_info && (dyn_pl_info->rtp_codec == 2 || dyn_pl_info->rtp_codec == 5)) {
                dyn_pl = rtp_dyn_payload_new();
                rtp_dyn_payload_insert(dyn_pl, dyn_pl_info->rtp_pt, "AMR", 8000, 1);
            }
            conversation_delete_proto_data(conv, proto_rsl);
            wmem_free(wmem_file_scope(), dyn_pl_info);
            rtp_add_address(pinfo, PT_UDP, &src_addr, local_port, 0,
                            "GSM A-bis/IP", pinfo->num, 0, dyn_pl);
            rtcp_add_address(pinfo, &src_addr, local_port+1, 0,
                             "GSM A-bis/IP", pinfo->num);
        }
        break;
    }
    return offset;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissct_rsl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint8_t msg_disc, msg_type, sys_info_type;
    uint8_t paging_package_number;

    msg_disc = tvb_get_uint8(tvb, offset++) >> 1;
    msg_type = tvb_get_uint8(tvb, offset) & 0x7f;
    proto_tree_add_item(tree, hf_rsl_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (msg_disc == RSL_MSGDISC_IPACCESS) {
        offset = dissct_rsl_ipaccess_msg(tvb, pinfo, tree, offset);
        return offset;
    }
    offset++;

    increment_dissection_depth(pinfo);
    switch (msg_type) {
/* Radio Link Layer Management messages */
    /* 8.3.1 DATA REQUEST */
    case RSL_MSG_TYPE_DATA_REQ:
        /* Channel number           9.3.1   M TV 2      */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2      */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /* L3 Information           9.3.11  M TLV >=3   */
        offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, true, L3_INF_OTHER);
        break;
    /* 8.3.2 DATA INDICATION */
    case RSL_MSG_TYPE_DATA_IND:
        /* Channel number           9.3.1   M TV 2      */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2      */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /* L3 Information           9.3.11  M TLV >=3   */
        offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, true, L3_INF_OTHER);
        break;
    /* 8.3.3 ERROR INDICATION */
    case RSL_MSG_TYPE_ERROR_IND:
        /* Channel number           9.3.1   M TV 2      */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2      */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /* RLM Cause                9.3.22  M TLV 2-4   */
        offset = dissect_rsl_ie_rlm_cause(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.4 ESTABLISH REQUEST */
    case RSL_MSG_TYPE_EST_REQ:
        /* Channel number           9.3.1   M TV 2      */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2      */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.5 ESTABLISH CONFIRM */
    case RSL_MSG_TYPE_EST_CONF:
        /* Channel number           9.3.1   M TV 2      */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2      */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.6 */
    case RSL_MSG_EST_IND:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /*  L3 Information          9.3.11  O (note 1) TLV 3-23  */
        if (tvb_reported_length_remaining(tvb, offset) >1)
            offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false, L3_INF_OTHER);
        break;
    /* 8.3.7 RELEASE REQUEST */
    case RSL_MSG_REL_REQ:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /* Release Mode             9.3.20  M TV 2              */
        offset = dissect_rsl_ie_rel_mode(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.8 RELEASE CONFIRM */
    case RSL_MSG_REL_CONF:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.9 RELEASE INDICATION */
    case RSL_MSG_REL_IND:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        break;
    /* 8.3.10 UNIT DATA REQUEST 10 */
    case RSL_MSG_UNIT_DATA_REQ:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /*  L3 Information          9.3.11  O (note 1) TLV 3-23  */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false, L3_INF_OTHER);
        break;
    /* 8.3.11 UNIT DATA INDICATION */
    case RSL_MSG_UNIT_DATA_IND:
        /*  Channel number          9.3.1   M TV 2               */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  Link Identifier         9.3.2   M TV 2               */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /*  L3 Information          9.3.11  M TLV 3-25           */
        offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, true, L3_INF_OTHER);
        break;
/* Common Channel Management/TRX Management messages */
    /* 8.5.1 BCCH INFORMATION 17*/
    case RSL_MSG_BCCH_INFO:
        /*  Channel number          9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /*  System Info Type        9.3.30  M TV 2 */
        offset = dissect_rsl_ie_sys_info_type(tvb, pinfo, tree, offset, true, &sys_info_type);
        /*  Full BCCH Info (SYS INFO) 9.3.39 O 1) TLV 25 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_full_bcch_inf(tvb, pinfo, tree, offset, false);
        /*  Starting Time           9.3.23  O 2) TV 3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_starting_time(tvb, pinfo, tree, offset, false);
        break;
    /* 8.5.2 CCCH LOAD INDICATION 18*/
    case RSL_MSG_CCCH_LOAD_IND:
        /*  Channel number (note)   9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Either RACH Load or Paging Load present */
        /*  RACH Load               9.3.18  C 1) TLV >=8 */
        offset = dissect_rsl_ie_rach_load(tvb, pinfo, tree, offset, false);
        /*  Paging Load             9.3.15  C 2) TV 3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_paging_load(tvb, pinfo, tree, offset, false);
        break;
    /* 8.5.3 */
    case RSL_MSG_CHANRQD: /* 19 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Request Reference        9.3.19  M TV 4 */
        offset = dissect_rsl_ie_req_ref(tvb, pinfo, tree, offset, true);
        /* Access Delay             9.3.17  M TV 2 */
        offset = dissect_rsl_ie_access_delay(tvb, pinfo, tree, offset, true);
        /* Physical Context         9.3.16  O 1) TLV >=2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_phy_ctx(tvb, pinfo, tree, offset, false);
        break;
    /* 8.5.4 DELETE INDICATION */
    case RSL_MSG_DELETE_IND: /* 20 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Full Imm. Assign Info    9.3.35  M TLV 25 */
        offset = dissect_rsl_ie_full_imm_ass_inf(tvb, pinfo, tree, offset, true);
        break;
    case RSL_MSG_PAGING_CMD:    /* 21 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Paging Group             9.3.14  M TV 2 2 */
        offset = dissect_rsl_ie_paging_grp(tvb, pinfo, tree, offset, true);
        /* MS Identity              9.3.12  M TLV 2-10 2 */
        offset = dissect_rsl_ie_ms_id(tvb, pinfo, tree, offset, true);
        /* Channel Needed           9.3.40  O 1) TV 2 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ch_needed(tvb, pinfo, tree, offset, false);
        /* eMLPP Priority           9.3.49  O 2) TV 2 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_emlpp_prio(tvb, pinfo, tree, offset, false);
        break;
    /* 8.5.6 IMMEDIATE ASSIGN COMMAND */
    case RSL_MSG_IMM_ASS_CMD:   /* 22 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Full Imm. Assign Info    9.3.35  M TLV 25 */
        offset = dissect_rsl_ie_full_imm_ass_inf(tvb, pinfo, tree, offset, true);
        break;
    /* 8.5.7 SMS BROADCAST REQUEST */
    case RSL_MSG_SMS_BC_REQ:    /*  23   8.5.7 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* SMSCB Information        9.3.36  M TV 24 */
        offset = dissect_rsl_ie_smscb_inf(tvb, pinfo, tree, offset, true);
        /* SMSCB Channel Indicator  9.3.44  O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_smscb_ch_ind(tvb, pinfo, tree, offset, false);
        break;
/* 8.6 TRX MANAGEMENT MESSAGES */
    /* 8.6.1 RF RESOURCE INDICATION */
    case RSL_MSG_RF_RES_IND:    /*  24   8.6.1 */
        /* Resource Information     9.3.21  M TLV >=2 */
        offset = dissect_rsl_ie_resource_inf(tvb, pinfo, tree, offset, true);
        break;
    /* 8.6.2 SACCH FILLING */
    case RSL_MSG_SACCH_FILL:    /*  25   8.6.2 */
        /* System Info Type         9.3.30  M TV 2 */
        offset = dissect_rsl_ie_sys_info_type(tvb, pinfo, tree, offset, true, &sys_info_type);
        /* L3 Info (SYS INFO)       9.3.11 O 1) TLV 22 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
           offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false,
                                          (sys_info_type == 0x48) ? L3_INF_SACCH : L3_INF_CCCH);
        /* Starting Time            9.3.23 O 2) TV 3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_starting_time(tvb, pinfo, tree, offset, false);
        break;
    case RSL_MSG_OVERLOAD:      /*  27   8.6.3 */
        /* Cause                    9.3.26  M TLV >=3 */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        break;
    case RSL_MSG_ERROR_REPORT:  /*  28   8.6.4 */
        /* Cause                    9.3.26  M TLV >=3 */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        /* Message Identifier       9.3.28  O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_message_id(tvb, pinfo, tree, offset, false);
        /* Channel Number           9.3.1   O 2) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, false);
        /* Link identifier          9.3.2   O 3) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, false);
        /* Erroneous Message        9.3.38  O 4) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_err_msg(tvb, pinfo, tree, offset, false);
        break;
    /* 8.5.8 SMS BROADCAST COMMAND */
    case RSL_MSG_SMS_BC_CMD:    /*  29   8.5.8 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* CB Command type          9.3.41  M TV 2 */
        offset = dissect_rsl_ie_cb_cmd_type(tvb, pinfo, tree, offset, true);
        /* SMSCB message            9.3.42  M TLV 2-90 */
        offset = dissect_rsl_ie_smscb_mess(tvb, pinfo, tree, offset, true);
        /* SMSCB Channel Indicator  9.3.44  O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_smscb_ch_ind(tvb, pinfo, tree, offset, false);
        break;
    case RSL_MSG_CBCH_LOAD_IND: /*  30   8.5.9 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* CBCH Load Information    9.3.43  M TV 2 */
        offset = dissect_rsl_ie_cbch_load_inf(tvb, pinfo, tree, offset, true);
        /* SMSCB Channel Indicator  9.3.44 O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_smscb_ch_ind(tvb, pinfo, tree, offset, false);
        break;
    case RSL_MSG_NOT_CMD:       /*  31   8.5.10 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Command indicator        9.3.48 M 1) TLV 3-4 */
        offset = dissect_rsl_ie_cmd_ind(tvb, pinfo, tree, offset, true);
        /* Group call reference     9.3.45 O TLV 7 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_grp_call_ref(tvb, pinfo, tree, offset, false);
        /* Channel Description      9.3.46 O TLV 3-n */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ch_desc(tvb, pinfo, tree, offset, false);
        /* NCH DRX information      9.3.47 O TLV 3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_nch_drx(tvb, pinfo, tree, offset, false);
        break;

/* Dedicated Channel Management messages: */
    /* 8.4.1 CHANNEL ACTIVATION 33*/
    case RSL_MSG_CHAN_ACTIV:
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Activation Type          9.3.3   M TV 2          */
        offset = dissect_rsl_ie_act_type(tvb, pinfo, tree, offset, true);
        /* Channel Mode             9.3.6   M TLV 8-9       */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            /* mandatory in 48.008, but not in Ericsson + Osmocom */
            offset = dissect_rsl_ie_ch_mode(tvb, pinfo, tree, offset, true);
        /* Channel Identification   9.3.5   O 7) TLV 8      */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ch_id(tvb, pinfo, tree, offset, false);
        /* Encryption information   9.3.7   O 1) TLV >=3    */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, false);
        /* Handover Reference       9.3.9   C 2) TV 2       */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ho_ref(tvb, pinfo, tree, offset, false);
        /* BS Power                 9.3.4   O 3) TV 2       */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, false);
        /* MS Power                 9.3.13  O 3) TV 2       */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ms_pow(tvb, pinfo, tree, offset, false);
        /* Timing Advance           9.3.24  C 3) 4) TV 2    */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_timing_adv(tvb, pinfo, tree, offset, false);
        /* BS Power Parameters      9.3.32  O 5) TLV >=2    */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_bs_power_params(tvb, pinfo, tree, offset, false);
        /* MS Power Parameters      9.3.31  O 5) TLV >=2    */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ms_pow_params(tvb, pinfo, tree, offset, false);
        /* Physical Context         9.3.16  O 6) TLV >=2    */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_phy_ctx(tvb, pinfo, tree, offset, false);
        /* SACCH Information        9.3.29  O 8) TLV >=3    */
        /* UIC                      9.3.50  O 9) TLV 3      */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_uic(tvb, pinfo, tree, offset, false);
        /* Main channel reference   9.3.51  O 10) TV 2      */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_main_ch_ref(tvb, pinfo, tree, offset, false);
        /* MultiRate configuration  9.3.52  O 11) TLV >=4   */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, false);
        /* MultiRate Control        9.3.53  O 12) TV 2      */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_cntrl(tvb, pinfo, tree, offset, false);
            /* Supported Codec Types    9.3.54  O 12) TLV >=5   */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_sup_codec_types(tvb, pinfo, tree, offset, false);
        /* TFO transparent container 9.3.59 O 12) TLV >=3   */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_tfo_transp_cont(tvb, pinfo, tree, offset, false);
        /* Osmocom specific IEs */
        if (global_rsl_use_osmo_bts) {
            /* Repeated ACCH Capabilities O TLV */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_rep_acch_cap(tvb, pinfo, tree, offset, false);
            /* Temporary ACCH Overpower Capabilities O TLV */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_top_acch_cap(tvb, pinfo, tree, offset, false);
            /* Training Sequence O TLV 2 */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_training_seq(tvb, pinfo, tree, offset, false);
        }
        break;

    /* 8.4.2 CHANNEL ACTIVATION ACKNOWLEDGE 34*/
    case RSL_MSG_CHAN_ACTIV_ACK:
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Frame number             9.3.8   M TV 3          */
        offset = dissect_rsl_ie_frame_no(tvb, pinfo, tree, offset, true);
        break;
    case RSL_MSG_CHAN_ACTIV_N_ACK:
    /* 8.4.3 CHANNEL ACTIVATION NEGATIVE ACKNOWLEDGE */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Cause                    9.3.26  M TLV >=3       */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.4 CONNECTION FAILURE INDICATION */
    case RSL_MSG_CONN_FAIL:
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Cause                    9.3.26  M TLV >=3       */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.5 DEACTIVATE SACCH */
    case RSL_MSG_DEACTIVATE_SACCH:
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.6 ENCRYPTION COMMAND */
    case RSL_MSG_ENCR_CMD:          /*  38   8.4.6 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Encryption information   9.3.7   M TLV >=3       */
        offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, true);
        /* Link Identifier          9.3.2   M TV 2          */
        offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, true);
        /* L3 Info (CIPH MOD CMD)   9.3.11  M TLV 6         */
        offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, true, L3_INF_OTHER);
        break;
    /* 8.4.7 HANDOVER DETECTION */
    case RSL_MSG_HANDODET:          /*  39   8.4.7 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Access Delay             9.3.17 O 1) TV 2        */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_access_delay(tvb, pinfo, tree, offset, false);
        /* Osmocom specific IEs */
        if (global_rsl_use_osmo_bts) {
            /* Training Sequence O TLV 2 */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_training_seq(tvb, pinfo, tree, offset, false);
        }
        break;
    /* 8.4.8 MEASUREMENT RESULT 40 */
    case RSL_MSG_MEAS_RES:
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Measurement result number 9.3.27 M TV 2          */
        offset = dissect_rsl_ie_meas_res_no(tvb, pinfo, tree, offset, true);
        /* Uplink Measurements      9.3.25  M TLV >=5       */
        offset = dissect_rsl_ie_uplik_meas(tvb, pinfo, tree, offset, true);
        /* BS Power                 9.3.4   M TV 2          */
        offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, true);
        /* L1 Information           9.3.10 O 1) TV 3        */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_l1_inf(tvb, pinfo, tree, offset, false);
        /* L3 Info (MEAS REP, EXT MEAS REP or ENH MEAS REP) 9.3.11 O 1) TLV 21 */
        if (tvb_reported_length_remaining(tvb, offset) > 3){
            /* Try to figure out of we have (MEAS REP, EXT MEAS REP or ENH MEAS REP) */
            if ( ( tvb_get_uint8(tvb, offset+3) & 0xFE ) == 0x10 ) {
                /* ENH MEAS REP */
                offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false, L3_INF_SACCH);
            }else{
                offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false, L3_INF_OTHER);
            }
        }
        /* MS Timing Offset         9.3.37 O 2) TV 2        */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ms_timing_offset(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.9 MODE MODIFY */
    case RSL_MSG_MODE_MODIFY_REQ:   /*  41  8.4.9 */
        /* Channel number           9.3.1 M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Channel Mode             9.3.6 M TLV 8-9 */
        offset = dissect_rsl_ie_ch_mode(tvb, pinfo, tree, offset, true);
        /* Encryption information   9.3.7 O 1) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, false);
        /* Main channel reference   9.3.45 O 2) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_main_ch_ref(tvb, pinfo, tree, offset, false);
        /* MultiRate configuration  9.3.52 O 3) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, false);
        /* Multirate Control        9.3.53 O 4) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_cntrl(tvb, pinfo, tree, offset, false);
        /* Supported Codec Types    9.3.54 O 4) TLV >=5 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_sup_codec_types(tvb, pinfo, tree, offset, false);
        /* TFO transparent container 9.3.59 O 4) TLV */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_tfo_transp_cont(tvb, pinfo, tree, offset, false);
        /* Osmocom specific IEs */
        if (global_rsl_use_osmo_bts) {
            /* Repeated ACCH Capabilities O TLV */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_rep_acch_cap(tvb, pinfo, tree, offset, false);
            /* Temporary ACCH Overpower Capabilities O TLV */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_top_acch_cap(tvb, pinfo, tree, offset, false);
            /* Training Sequence O TLV 2 */
            if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_osmo_training_seq(tvb, pinfo, tree, offset, false);
        }
        break;
    /* 8.4.10 MODE MODIFY ACKNOWLEDGE */
    case RSL_MSG_MODE_MODIFY_ACK:   /*  42  8.4.10 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.11 MODE MODIFY NEGATIVE ACKNOWLEDGE */
    case RSL_MSG_MODE_MODIFY_NACK:  /*  43  8.4.11 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Cause                    9.3.26  M TLV >=3       */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.12 PHYSICAL CONTEXT REQUEST */
    case RSL_MSG_PHY_CONTEXT_REQ:   /*  44  8.4.12 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.13 PHYSICAL CONTEXT CONFIRM */
    case RSL_MSG_PHY_CONTEXT_CONF:  /*  45  8.4.13 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* BS Power                 9.3.4   M TV 2 */
        offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, true);
        /* MS Power                 9.3.13  M TV 2 */
        offset = dissect_rsl_ie_ms_pow(tvb, pinfo, tree, offset, true);
        /* Timing Advance           9.3.24  M TV 2 */
        offset = dissect_rsl_ie_timing_adv(tvb, pinfo, tree, offset, true);
        /* Physical Context         9.3.16  O 1) TLV */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_phy_ctx(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.14 RF CHANNEL RELEASE */
    case RSL_MSG_RF_CHAN_REL:       /*  46  8.4.14 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.15 MS POWER CONTROL */
    case RSL_MSG_MS_POWER_CONTROL:  /*  47  8.4.15 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MS Power                 9.3.13  M TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ms_pow(tvb, pinfo, tree, offset, false);
        /* MS Power Parameters      9.3.31  O 1) TLV >=2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_ms_pow_params(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.16 BS POWER CONTROL */
    case RSL_MSG_BS_POWER_CONTROL:  /*  48  8.4.16 */
        /* Channel number           9.3.1 M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* BS Power                 9.3.4 M TV 2 */
        offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, true);
        /* BS Power Parameters      9.3.32 O 1) TLV >=2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_bs_power_params(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.17 PREPROCESS CONFIGURE */
    case RSL_MSG_PREPROC_CONFIG:        /*  49  8.4.17 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Preproc. Parameters      9.3.33  M TLV >=3 */
        break;
    /* 8.4.18 PREPROCESSED MEASUREMENT RESULT */
    case RSL_MSG_PREPROC_MEAS_RES:  /*  50  8.4.18 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Preproc. Measurements    9.3.34  M TLV >=2 */
        break;
    /* 8.4.19 RF CHANNEL RELEASE ACKNOWLEDGE */
    case RSL_MSG_RF_CHAN_REL_ACK:       /*  51  8.4.19 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.20 SACCH INFO MODIFY */
    case RSL_MSG_SACCH_INFO_MODIFY: /*  52  8.4.20 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* System Info Type         9.3.30  M TV 2 */
        offset = dissect_rsl_ie_sys_info_type(tvb, pinfo, tree, offset, true, &sys_info_type);
        /* L3 Info                  9.3.11  O 1) TLV 22 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, false,
                                           (sys_info_type == 0x48) ? L3_INF_SACCH : L3_INF_CCCH);
        /* Starting Time            9.3.23  O 2) TV 3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_starting_time(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.21 TALKER DETECTION */
    case RSL_MSG_TALKER_DET:            /*  53  8.4.21 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Access Delay             9.3.17  O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.22 LISTENER DETECTION */
    case RSL_MSG_LISTENER_DET:      /*  54  8.4.22 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Access Delay             9.3.17  O 1) TV 2 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
                offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.23 REMOTE CODEC CONFIGURATION REPORT */
    case RSL_MSG_REMOTE_CODEC_CONF_REP:/*   55  8.4.23 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Codec Configuration      9.3.55  M TLV >=3 */
        offset = dissect_rsl_ie_codec_conf(tvb, pinfo, tree, offset, true);
        /* Supported Codec Types    9.3.54  M TLV >=5 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_sup_codec_types(tvb, pinfo, tree, offset, false);
        /* TFO transparent container 9.3.59 O 4) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_tfo_transp_cont(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.24 ROUND TRIP DELAY REPORT */
    case RSL_MSG_R_T_D_REP:         /*  56  8.4.24 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Round Trip Delay         9.3.56  M TV 2 */
        offset = dissect_rsl_ie_rtd(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.25 PRE-HANDOVER NOTIFICATION */
    case RSL_MSG_PRE_HANDO_NOTIF:       /*  57  8.4.25 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MultiRateControl         9.3.53  M TV 2 */
        offset = dissect_rsl_ie_multirate_cntrl(tvb, pinfo, tree, offset, true);
        /* Codec Configuration      9.3.55  M TLV >=3 */
        offset = dissect_rsl_ie_codec_conf(tvb, pinfo, tree, offset, true);
        /* TFO transparent container 9.3.59 O 4) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_tfo_transp_cont(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.26 MULTIRATE CODEC MODIFICATION REQUEST */
    case RSL_MSG_MR_CODEC_MOD_REQ:  /*  58  8.4.26 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MultiRate Configuration  9.3.52  O 1) TLV >=4 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, false);
        break;
    /*  8.4.27 MULTIRATE CODEC MODIFICATION ACKNOWLEDGE */
    case RSL_MSG_MR_CODEC_MOD_ACK:  /*  59  8.4.27 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MultiRate Configuration  9.3.52  O 1) TLV >=4 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, false);
        break;
    /* 8.4.28 MULTIRATE CODEC MODIFICATION NEGATIVE ACKNOWLEDGE */
    case RSL_MSG_MR_CODEC_MOD_NACK: /*  60  8.4.28 */
        /* Channel number           9.3.1   M TV 2          */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* Cause                    9.3.26  M TLV >=3       */
        offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.29 MULTIRATE CODEC MODIFICATION PERFORMED */
    case RSL_MSG_MR_CODEC_MOD_PER:  /*  61  8.4.29 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MultiRate Configuration  9.3.52  M TLV >=4 */
        offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.30 TFO REPORT */
    case RSL_MSG_TFO_REP:               /*  62  8.4.30 */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* TFO Status               9.3.57  M TV 1 */
        offset = dissect_rsl_ie_tfo_status(tvb, pinfo, tree, offset, true);
        break;
    /* 8.4.31 TFO MODIFICATION REQUEST */
    case RSL_MSG_TFO_MOD_REQ:           /*  63  8.4.31 */
        /* Channel number           9.3.1 M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* MultiRateControl         9.3.53 M TV 2 */
        offset = dissect_rsl_ie_multirate_cntrl(tvb, pinfo, tree, offset, true);
        /* Supported Codec Type     9.3.54 O 1) TLV >=5 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_sup_codec_types(tvb, pinfo, tree, offset, false);
        /* TFO transparent container 9.3.59 O 4) TLV >=3 */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            offset = dissect_rsl_ie_tfo_transp_cont(tvb, pinfo, tree, offset, false);
        break;
    /*  0 1 - - - - - - Location Services messages: */
    /* 8.7.1 LOCATION INFORMATION */
    case RSL_MSG_LOC_INF:               /*  65  8.7.1 */
        /* LLP APDU 9.3.58 M LV 2-N */
        offset = dissect_rsl_ie_llp_apdu(tvb, pinfo, tree, offset, true);
        break;
    /* Encapsulating paging messages into a packet EP2192796 - proprietor Huawei */
    case RSL_MSG_TYPE_PAGING:
       paging_package_number = dissect_rsl_paging_package_number(tvb, pinfo, tree, &offset);
       offset = dissect_rsl_paging_package(tvb, pinfo, tree, offset, paging_package_number);
       break;
    case RSL_MSG_TYPE_OSMO_ETWS_CMD:
        /* See http://ftp.osmocom.org/docs/latest/osmobts-abis.pdf Section 5.5 on ETWS */
        /* Channel number           9.3.1   M TV 2 */
        offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, true);
        /* ETWS PN (Osmocom)  Osmo 5.6.17   M TLV 2-58 */
        offset = dissect_rsl_ie_etws_pn(tvb, pinfo, tree, offset);
        break;
    /* the following messages are ip.access specific but sent without
     * ip.access memssage discriminator */
    case RSL_MSG_TYPE_IPAC_MEAS_PP_DEF:
    case RSL_MSG_TYPE_IPAC_HO_CAND_INQ:
    case RSL_MSG_TYPE_IPAC_HO_CAND_RESP:
    case RSL_MSG_TYPE_IPAC_PDCH_ACT:
    case RSL_MSG_TYPE_IPAC_PDCH_ACT_ACK:
    case RSL_MSG_TYPE_IPAC_PDCH_ACT_NACK:
    case RSL_MSG_TYPE_IPAC_PDCH_DEACT:
    case RSL_MSG_TYPE_IPAC_PDCH_DEACT_ACK:
    case RSL_MSG_TYPE_IPAC_PDCH_DEACT_NACK:
        if (global_rsl_use_nano_bts)
            offset = dissct_rsl_ipaccess_msg(tvb, pinfo, tree, offset-1);
    default:
        break;
    }
    decrement_dissection_depth(pinfo);

    return offset;

}

static const value_string rsl_ipacc_spm_s_vals[] = {
    { 0,     "GSM FR codec (GSM type 1, FS)" },
    { 1,     "GSM EFR codec (GSM type 2, FS)" },
    { 2,     "GSM AMR/FR codec (GSM type 3, FS)" },
    { 3,     "GSM HR codec (GSM type 1, HS)" },
    { 5,     "GSM AMR/HR codec (GSM type 3, HS)" },
    { 0xf,   "As specified by RTP Payload Type IE" },
    { 0, NULL }
};

static const value_string rsl_ipacc_spm_m_vals[] = {
    { 0,     "Send and Receive" },
    { 1,     "Receive Only" },
    { 2,     "Send Only" },
    { 0, NULL }
};

static const value_string rsl_ipacc_rtp_csd_fmt_d_vals[] = {
    { 0,     "External TRAU format" },
    { 1,     "Non-TRAU Packed format" },
    { 2,     "TRAU within the BTS" },
    { 3,     "IWF-Free BTS-BTS Data" },
    { 0, NULL }
};

static const value_string rsl_ipacc_rtp_csd_fmt_ir_vals[] = {
    { 0,     "8kb/s" },
    { 1,     "16kb/s" },
    { 2,     "32kb/s" },
    { 3,     "64kb/s" },
    { 0, NULL }
};

/* GSM 04.08 9.1.8 Channel request, ESTABLISHMENT CAUSE */
static void
req_ref_ra_est_cause_convert(char *result, uint32_t ra)
{
    char *str;

    switch (ra & 0xe0) { /* 3 bit Establishment Cause codes */
    case 0x00:
        str = "Location updating and the network does not set NECI bit to 1";
        goto found;
    case 0x80:
        str = "Answer to paging: 'Any Channel', or ('TCH/F' or 'TCH/H or TCH/F') if MS is 'Full rate only'";
        goto found;
    case 0xa0:
        str = "Emergency call";
        goto found;
    case 0xc0:
        str = "Call re-establishment; TCH/F was in use, or TCH/H was in use but the network does not set NECI bit to 1";
        goto found;
    case 0xe0:
        str = "Originating call and TCH/F is needed, or originating call and the network does not set NECI bit to 1,"
              " or procedures that can be completed with a SDCCH and the network does not set NECI bit to 1";
        goto found;
    }

    switch (ra & 0xf0) { /* 4 bit Establishment Cause codes */
    case 0x00:
        str = "Location updating and the network sets NECI bit to 1";
        goto found;
    case 0x10:
        str = "Answer to paging: 'SDCCH' / Other procedures which can be completed with an SDCCH and the network sets NECI bit to 1";
        goto found;
    case 0x20:
        str = "Answer to paging: MS is dual rate capable and requests 'TCH/F' only";
        goto found;
    case 0x30:
        str = "Answer to paging: MS is dual rate capable and requests 'TCH/H or TCH/F'";
        goto found;
    case 0x40:
        str = "Originating speech call from dual-rate mobile station when TCH/H is sufficient and the network sets NECI bit to 1";
        goto found;
    case 0x50:
        str = "Originating data call from dual-rate mobile station when TCH/H is sufficient and the network sets NECI bit to 1";
        goto found;
    case 0x70:
        str = "Reserved for future use. An SDCCH may be allocated";
        goto found;
    }

    switch (ra & 0xf8) { /* 5 bit Establishment Cause codes */
    case 0x60:
        str = "Reserved for future use. An SDCCH may be allocated";
        goto found;
    }

    switch (ra & 0xfc) { /* 6 bit Establishment Cause codes */
    case 0x68:
        str = "Call re-establishment; TCH/H was in use and the network sets NECI bit to 1";
        goto found;
    case 0x6c:
        str = "Call re-establishment; TCH/H + TCH/H was in use and the network sets NECI bit to 1";
        goto found;
    }

    snprintf(result, ITEM_LABEL_LENGTH, "unknown ra %u", ra);
    return;

found:
    snprintf(result, ITEM_LABEL_LENGTH, "%s", str);
}

static int
dissect_rsl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *rsl_tree;
    uint8_t     msg_type;


    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSL");
    col_clear(pinfo->cinfo, COL_INFO);

    msg_type = tvb_get_uint8(tvb, offset+1) & 0x7f;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_ext(msg_type, &rsl_msg_type_vals_ext, "unknown %u"));

    top_tree = tree;
    ti = proto_tree_add_item(tree, proto_rsl, tvb, 0, -1, ENC_NA);

    /* if nanoBTS specific vendor messages are not enabled, skip */
    if (!global_rsl_use_nano_bts) {
        uint8_t msg_disc = tvb_get_uint8(tvb, offset) >> 1;

        if (msg_disc == RSL_MSGDISC_IPACCESS)
            return 0;
    }
    rsl_tree = proto_item_add_subtree(ti, ett_rsl);

    /* 9.1 Message discriminator */
    proto_tree_add_item(rsl_tree, hf_rsl_msg_dsc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsl_tree, hf_rsl_T_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset = dissct_rsl_msg(tvb, pinfo, rsl_tree, offset);

    return offset;
}

/* Register the protocol with Wireshark */
void proto_register_rsl(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_rsl_msg_dsc,
          { "Message discriminator",           "gsm_abis_rsl.msg_dsc",
            FT_UINT8, BASE_DEC, VALS(rsl_msg_disc_vals), 0xfe,
            NULL, HFILL }
        },
        { &hf_rsl_T_bit,
          { "T bit",           "gsm_abis_rsl.T_bit",
            FT_BOOLEAN, 8, TFS(&rsl_t_bit_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_msg_type,
          { "Message type",           "gsm_abis_rsl.msg_type",
            FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &rsl_msg_type_vals_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_rsl_ie_id,
          { "Element identifier",           "gsm_abis_rsl.ie_id",
            FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &rsl_ie_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_ie_length,
          { "Length",           "gsm_abis_rsl.ie_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_ch_no_Cbits,
          { "C-bits",           "gsm_abis_rsl.ch_no_Cbits",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_ch_no_Cbits_vals_ext, 0xf8,
            NULL, HFILL }
        },
        { &hf_rsl_ch_no_TN,
          { "Time slot number (TN)",  "gsm_abis_rsl.ch_no_TN",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_rtd,
          { "Round Trip Delay (RTD)",  "gsm_abis_rsl.rtd",
            FT_UINT8, BASE_DEC, NULL, 0xfe,
            NULL, HFILL }
        },
        { &hf_rsl_delay_ind,
          { "Delay IND",  "gsm_abis_rsl.delay_ind",
            FT_UINT8, BASE_DEC, VALS(rsl_delay_ind_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_tfo,
          { "TFO",           "gsm_abis_rsl.tfo",
            FT_BOOLEAN, 8, TFS(&rsl_tfo_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_ra,
          { "Random Access Information (RA)", "gsm_abis_rsl.req_ref_ra",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_ra_est_cause,
          { "Channel Request Establishment Cause", "gsm_abis_rsl.req_ref_ra.est_cause",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(req_ref_ra_est_cause_convert), 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_T1prim,
          { "T1'",           "gsm_abis_rsl.req_ref_T1prim",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_T3,
          { "T3",           "gsm_abis_rsl.req_ref_T3",
            FT_UINT16, BASE_DEC, NULL, 0x07e0,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_T2,
          { "T2",           "gsm_abis_rsl.req_ref_T2",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_rsl_req_ref_rfn,
          { "RFN",          "gsm_abis_rsl.req_ref_rfn",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Reduced Frame Number", HFILL }
        },
        { &hf_rsl_timing_adv,
          { "Timing Advance",           "gsm_abis_rsl.timing_adv",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_ho_ref,
          { "Hand-over reference",           "gsm_abis_rsl.ho_ref",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_l1inf_power_lev,
          { "MS power level",           "gsm_abis_rsl.ms_power_lev",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_rsl_l1inf_fpc,
          { "FPC/EPC",           "gsm_abis_rsl.ms_fpc",
            FT_BOOLEAN, 8, TFS(&tfs_inuse_not_inuse), 0x04,
            NULL, HFILL }
        },
        { &hf_rsl_l1inf_srr,
          { "SRR (SACCH Repetition)",           "gsm_abis_rsl.srr",
            FT_BOOLEAN, 8, TFS(&tfs_required_not_required), 0x02,
            NULL, HFILL }
        },
        { &hf_rsl_ms_power_lev,
          { "MS power level",           "gsm_abis_rsl.ms_power_lev",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_rsl_ms_fpc,
          { "FPC/EPC",           "gsm_abis_rsl.ms_fpc",
            FT_BOOLEAN, 8, TFS(&tfs_inuse_not_inuse), 0x20,
            NULL, HFILL }
        },
        { &hf_rsl_act_timing_adv,
          { "Actual Timing Advance",           "gsm_abis_rsl.act_timing_adv",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_dtxd,
          { "DTXd",           "gsm_abis_rsl.dtxd",
            FT_BOOLEAN, 8, TFS(&rsl_dtxd_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_rsl_rxlev_full_up,
          { "RXLEV.FULL.up",           "gsm_abis_rsl.rxlev_full_up",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_a_rr_rxlev_vals_ext, 0x3f,
            NULL, HFILL }
        },
        { &hf_rsl_rxlev_sub_up,
          { "RXLEV.SUB.up",           "gsm_abis_rsl.rxlev_sub_up",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_a_rr_rxlev_vals_ext, 0x3f,
            NULL, HFILL }
        },
        { &hf_rsl_rxqual_full_up,
          { "RXQUAL.FULL.up",           "gsm_abis_rsl.rxqual_full_up",
            FT_UINT8, BASE_DEC, VALS(gsm_a_rr_rxqual_vals), 0x38,
            NULL, HFILL }
        },
        { &hf_rsl_rxqual_sub_up,
          { "RXQUAL.SUB.up",           "gsm_abis_rsl.rxqual_sub_up",
            FT_UINT8, BASE_DEC, VALS(gsm_a_rr_rxqual_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_acc_delay,
          { "Access Delay",           "gsm_abis_rsl.acc_del",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_rach_slot_cnt,
          { "RACH Slot Count",           "gsm_abis_rsl.rach_slot_cnt",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_rach_busy_cnt,
          { "RACH Busy Count",           "gsm_abis_rsl.rach_busy_cnt",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_rach_acc_cnt,
          { "RACH Access Count",           "gsm_abis_rsl.rach_acc_cnt",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_phy_ctx,
          { "Physical Context",           "gsm_abis_rsl.phy_ctx",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_na,
          { "Not applicable (NA)",           "gsm_abis_rsl.na",
            FT_BOOLEAN, 8, TFS(&rsl_na_vals), 0x20,
            NULL, HFILL }
        },
        { &hf_rsl_ch_type,
          { "channel type",           "gsm_abis_rsl.ch_type",
            FT_UINT8, BASE_DEC, VALS(rsl_ch_type_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_rsl_prio,
          { "Priority",           "gsm_abis_rsl.prio",
            FT_UINT8, BASE_DEC, VALS(rsl_prio_vals), 0x18,
            NULL, HFILL }
        },
        { &hf_rsl_sapi,
          { "SAPI",           "gsm_abis_rsl.sapi",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_rbit,
          { "R",           "gsm_abis_rsl.rbit",
            FT_BOOLEAN, 8, TFS(&rsl_rbit_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_rsl_a3a2,
          { "A3A2",           "gsm_abis_rsl.a3a2",
            FT_UINT8, BASE_DEC, VALS(rsl_a3a2_vals), 0x06,
            NULL, HFILL }
        },
        { &hf_rsl_a1_0,
          { "A1",           "gsm_abis_rsl.a1_0",
            FT_BOOLEAN, 8, TFS(&rsl_a1_0_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_a1_1,
          { "A1",           "gsm_abis_rsl.a1_1",
            FT_BOOLEAN, 8, TFS(&rsl_a1_1_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_a1_2,
          { "A1",           "gsm_abis_rsl.a2_0",
            FT_BOOLEAN, 8, TFS(&rsl_a1_2_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_epc_mode,
          { "EPC mode", "gsm_abis_rsl.epc_mode",
            FT_BOOLEAN, 8, TFS(&rsl_epc_mode_vals), 0x20,
            NULL, HFILL }
        },
        { &hf_rsl_bs_fpc_epc_mode,
          { "FPC-EPC mode", "gsm_abis_rsl.fpc_epc_mode",
            FT_BOOLEAN, 8, TFS(&rsl_fpc_epc_mode_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_rsl_bs_power,
          { "Power Level",           "gsm_abis_rsl.bs_power",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_rlm_bs_power_vals_ext, 0x0f,
            NULL, HFILL }
        },
        { &hf_rsl_cm_dtxd,
          { "DTXd", "gsm_abis_rsl.cm_dtxd",
            FT_BOOLEAN, 8, TFS(&rsl_dtx_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_rsl_cm_dtxu,
          { "DTXu", "gsm_abis_rsl.cm_dtxu",
            FT_BOOLEAN, 8, TFS(&rsl_dtx_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_speech_or_data,
          { "Speech or data indicator",           "gsm_abis_rsl.speech_or_data",
            FT_UINT8, BASE_DEC, VALS(rsl_speech_or_data_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_ch_rate_and_type,
          { "Channel rate and type",           "gsm_abis_rsl.ch_rate_and_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_ch_rate_and_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_speech_coding_alg,
          { "Speech coding algorithm",           "gsm_abis_rsl.speech_coding_alg",
            FT_UINT8, BASE_DEC, VALS(rsl_speech_coding_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_t_nt_bit,
          { "Transparent indication", "gsm_abis_rsl.t_nt_bit",
            FT_BOOLEAN, 8, TFS(&t_nt_bit_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_rsl_ra_if_data_rte,
          { "Radio interface data rate",           "gsm_abis_rsl.ra_if_data_rte",
            FT_UINT8, BASE_DEC, VALS(rsl_ra_if_data_rte_vals), 0x3f,
            NULL, HFILL }
        },
        { &hf_rsl_data_rte,
          { "Data rate",           "gsm_abis_rsl.data_rte",
            FT_UINT8, BASE_DEC, VALS(rsl_data_rte_vals), 0x3f,
            NULL, HFILL }
        },
        { &hf_rsl_alg_id,
          { "Algorithm Identifier",           "gsm_abis_rsl.alg_id",
            FT_UINT8, BASE_DEC, VALS(rsl_algorithm_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_key,
          { "KEY",           "gsm_abis_rsl.key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_cause,
          { "Cause",           "gsm_abis_rsl.cause",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_rlm_cause_vals_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_rsl_rel_mode,
          { "Release Mode",           "gsm_abis_rsl.rel_mode",
            FT_UINT8, BASE_DEC, VALS(rel_mode_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_interf_band,
          { "Interf Band",           "gsm_abis_rsl.interf_band",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_rsl_interf_band_reserved,
          { "Interf Band reserved bits",           "gsm_abis_rsl.interf_band_reserved",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_rsl_meas_res_no,
          { "Measurement result number",           "gsm_abis_rsl.meas_res_no",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_extension_bit,
          { "Extension", "gsm_abis_rsl.extension_bit",
            FT_BOOLEAN, 8, TFS(&rsl_extension_bit_value), 0x80,
            NULL, HFILL }},
        { &hf_rsl_class,
          { "Class",           "gsm_abis_rsl.class",
            FT_UINT8, BASE_DEC, VALS(rsl_class_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_rsl_cause_value,
          { "Cause Value",           "gsm_abis_rsl.cause_value",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_cause_value_vals_ext, 0x7f,
            NULL, HFILL }
        },
        { &hf_rsl_paging_grp,
          { "Paging Group",           "gsm_abis_rsl.paging_grp",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_paging_load,
          { "Paging Buffer Space",           "gsm_abis_rsl.paging_load",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_sys_info_type,
          { "System Info Type",           "gsm_abis_rsl.sys_info_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsl_sys_info_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_timing_offset,
          { "Timing Offset",           "gsm_abis_rsl.timing_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_ch_needed,
          { "Channel Needed",           "gsm_abis_rsl.ch_needed",
            FT_UINT8, BASE_DEC, VALS(rsl_ch_needed_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_rsl_cbch_load_type,
          { "CBCH Load Type", "gsm_abis_rsl.cbch_load_type",
            FT_BOOLEAN, 8, TFS(&rsl_cbch_load_type_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_rsl_msg_slt_cnt,
          { "Message Slot Count", "gsm_abis_rsl.sg_slt_cnt",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_rsl_ch_ind,
          { "Channel Ind",           "gsm_abis_rsl.ch_ind",
            FT_UINT8, BASE_DEC, VALS(rsl_ch_ind_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_rsl_command,
          { "Command",           "gsm_abis_rsl.cmd",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_rsl_command_ext,
          { "Command (extended)", "gsm_abis_rsl.cmd_ext",
            FT_UINT16, BASE_DEC, NULL, 0x7fff,
            NULL, HFILL }
        },
        { &hf_rsl_emlpp_prio,
          { "eMLPP Priority",           "gsm_abis_rsl.emlpp_prio",
            FT_UINT8, BASE_DEC, VALS(rsl_emlpp_prio_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_speech_mode_s,
          { "ip.access Speech Mode S", "gsm_abis_rsl.ipacc.speech_mode_s",
            FT_UINT8, BASE_HEX, VALS(rsl_ipacc_spm_s_vals),
            0xf, NULL, HFILL }
        },
        { &hf_rsl_speech_mode_m,
          { "ip.access Speech Mode M", "gsm_abis_rsl.ipacc.speech_mode_m",
            FT_UINT8, BASE_HEX, VALS(rsl_ipacc_spm_m_vals),
            0xf0, NULL, HFILL }
        },
        { &hf_rsl_conn_id,
          { "ip.access Connection ID", "gsm_abis_rsl.ipacc.conn_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_rsl_rtp_payload,
          { "ip.access RTP Payload Type", "gsm_abis_rsl.ipacc.rtp_payload",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_rsl_rtp_csd_fmt_d,
          { "ip.access RTP CSD Format D", "gsm_abis_rsl.ipacc.rtp_csd_fmt_d",
            FT_UINT8, BASE_HEX, VALS(rsl_ipacc_rtp_csd_fmt_d_vals),
            0x0f, NULL, HFILL },
        },
        { &hf_rsl_rtp_csd_fmt_ir,
          { "ip.access RTP CSD Format IR", "gsm_abis_rsl.ipacc.rtp_csd_fmt_ir",
            FT_UINT8, BASE_HEX, VALS(rsl_ipacc_rtp_csd_fmt_ir_vals),
            0xf0, NULL, HFILL },
        },
        { &hf_rsl_local_port,
          { "ip.access Local RTP Port", "gsm_abis_rsl.ipacc.local_port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_rsl_remote_port,
          { "ip.access Remote RTP Port", "gsm_abis_rsl.ipacc.remote_port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_rsl_local_ip,
          { "ip.access Local IP Address", "gsm_abis_rsl.ipacc.local_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_rsl_remote_ip,
          { "ip.access Remote IP Address", "gsm_abis_rsl.ipacc.remote_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_rsl_cstat_tx_pkts,
          { "Packets Sent", "gsm_abis_rsl.ipacc.cstat.tx_pkts",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_tx_octs,
          { "Octets Sent", "gsm_abis_rsl.ipacc.cstat.tx_octets",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_rx_pkts,
          { "Packets Received", "gsm_abis_rsl.ipacc.cstat.rx_pkts",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_rx_octs,
          { "Octets Received", "gsm_abis_rsl.ipacc.cstat.rx_octets",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_lost_pkts,
          { "Packets Lost", "gsm_abis_rsl.ipacc.cstat.lost_pkts",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_ia_jitter,
          { "Inter-arrival Jitter", "gsm_abis_rsl.ipacc.cstat.ia_jitter",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rsl_cstat_avg_tx_dly,
          { "Average Tx Delay", "gsm_abis_rsl.ipacc.cstat.avg_tx_delay",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        /* Encapsulating paging messages into a packet EP2192796 - proprietor Huawei */
        { &hf_rsl_paging_spare,
          { "SPARE", "gsm_abis_rsl.paging_spare",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL }
        },
        { &hf_rsl_paging_msg_no,
         { "Paging Msg Number", "gsm_abis_rsl.paging_msg_no",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL }
        },
        { &hf_rsl_paging_package_ch_no,
          { "Channel Number Downlink CCCH (PCH + AGCH)", "gsm_abis_rsl.paging_package_ch_no",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL }
        },
        { &hf_rsl_paging_package_ch_needed,
         { "Channel Needed", "gsm_abis_rsl.paging_package_ch_needed",
           FT_UINT8, BASE_DEC, VALS(rsl_paging_ch_needed_vals), 0x18,
           NULL, HFILL }
        },
        { &hf_rsl_paging_emlpp_prio,
          { "eMLPP Priority", "gsm_abis_rsl.paging_emlpp_prio",
          FT_UINT8, BASE_DEC, VALS(rsl_paging_emlpp_prio_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_paging_type,
         { "Paging Type", "gsm_abis_rsl.paging_type",
           FT_BOOLEAN, 8, TFS(&rsl_paging_type_vals), 0x80,
           NULL, HFILL }
        },
        { &hf_rsl_paging_group_cs,
         { "Paging Group", "gsm_abis_rsl.paging_group_cs",
           FT_UINT8, BASE_DEC, NULL, 0x7f,
           NULL, HFILL }
        },
        { &hf_rsl_paging_group_empty_package,
         { "Empty package Paging Group", "gsm_abis_rsl.paging_group_empty_package",
           FT_UINT8, BASE_HEX, NULL, 0xff,
           NULL, HFILL }
        },
        { &hf_rsl_paging_group_ps_spare,
         { "PS Paging Group SPARE", "gsm_abis_rsl.paging_group_ps_spare",
           FT_UINT8, BASE_DEC, NULL, 0x7f,
           NULL, HFILL }
        },
        /* Physical Context */
        { &hf_rsl_phy_ctx_ie_id,
          { "Element identifier", "gsm_abis_rsl.phy_ctx_ie_id",
            FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &rsl_phy_con_ie_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_phy_ctx_ext_rand_access,
          { "RandRef11bit", "gsm_abis_rsl.phy_ctx_ext_rand_access",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rsl_phy_ctx_ab_rx_lvl,
          { "AB Rx Level", "gsm_abis_rsl.phy_ctx_ab_rx_lvl",
            FT_UINT8, BASE_HEX_DEC, NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_rsl_phy_ctx_ab_err_bits,
          { "Training Err Bits", "gsm_abis_rsl.phy_ctx_ab_err_bits",
            FT_UINT8, BASE_HEX, NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_rsl_phy_ctx_rx_lvl_ext,
          { "Rx Level Ext", "gsm_abis_rsl.phy_ctx_rx_lvl_ext",
            FT_UINT8, BASE_HEX_DEC, NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_rsl_cb_cmd_type,
          { "CB Command", "gsm_abis_rsl.cb_cmd_type.command",
            FT_UINT8, BASE_HEX, VALS(rsl_cb_cmd_type_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_rsl_cb_def_bcast,
          { "CB Default Broadcast", "gsm_abis_rsl.cb_cmd_type.def_bcast",
            FT_UINT8, BASE_HEX, VALS(rsl_cb_cmd_type_def_bcast_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_rsl_cb_last_block,
          { "CB Last Block", "gsm_abis_rsl.cb_cmd_type.last_block",
            FT_UINT8, BASE_HEX, VALS(rsl_cb_cmd_type_last_block_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_rsl_etws_pn,
          { "ETWS Primary Notification", "gsm_abis_rsl.etws_pn",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_rep_acch_rxqual,
          { "RxQual Threshold", "gsm_abis_rsl.osmo_rep_acch.rxqual",
            FT_UINT8, BASE_DEC, VALS(gsm_a_rr_rxqual_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_rep_acch_ul_sacch,
          { "Uplink SACCH", "gsm_abis_rsl.osmo_rep_acch.ul_sacch",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_rep_acch_dl_sacch,
          { "Downlink SACCH", "gsm_abis_rsl.osmo_rep_acch.dl_sacch",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_rep_acch_dl_facch_all,
          { "Downlink FACCH (all LDPDm message types)",
            "gsm_abis_rsl.osmo_rep_acch.dl_facch_all",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_rep_acch_dl_facch_cmd,
          { "Downlink FACCH (LAPDm commands only)",
            "gsm_abis_rsl.osmo_rep_acch.dl_facch_cmd",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_top_acch_val,
          { "Overpower value", "gsm_abis_rsl.osmo_top_acch.val",
            FT_UINT8, BASE_DEC | BASE_UNIT_STRING, UNS(&units_decibels), 0x07,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_top_acch_rxqual,
          { "Uplink RxQual threshold", "gsm_abis_rsl.osmo_top_acch.rxqual",
            FT_UINT8, BASE_DEC, VALS(gsm_a_rr_rxqual_vals), 0x38,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_top_acch_facch,
          { "FACCH Overpower", "gsm_abis_rsl.osmo_top_acch.facch",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_top_acch_sacch,
          { "SACCH Overpower", "gsm_abis_rsl.osmo_top_acch.sacch",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_tsc_set,
          { "Training Sequence Set", "gsm_abis_rsl.osmo_tsc_set",
            FT_UINT8, BASE_DEC, VALS(rsl_osmo_tsc_set_vals), 0,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_tsc_val,
          { "Training Sequence Code", "gsm_abis_rsl.osmo_tsc_val",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_rsl_osmo_osmux_cid,
          { "Osmux CID", "gsm_abis_rsl.osmo_osmux_cid",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_rsl_channel_description_tag, { "Channel Description Tag", "gsm_abis_rsl.channel_description_tag", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_mobile_allocation_tag, { "Mobile Allocation Tag", "gsm_abis_rsl.mobile_allocation_tag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_mobile_allocation_len, { "Mobile Allocation Length", "gsm_abis_rsl.mobile_allocation_len", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_no_resources_required, { "0 No resources required(All other values are reserved)", "gsm_abis_rsl.no_resources_required", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_llsdu_ccch, { "Link Layer Service Data Unit (L3 Message)(CCCH)", "gsm_abis_rsl.llsdu.ccch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_llsdu_sacch, { "Link Layer Service Data Unit (L3 Message)(SACCH)", "gsm_abis_rsl.llsdu.sacch", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_llsdu, { "Link Layer Service Data Unit (L3 Message)", "gsm_abis_rsl.llsdu", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_rach_supplementary_information, { "Supplementary Information", "gsm_abis_rsl.supplementary_information", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_full_immediate_assign_info_field, { "Full Immediate Assign Info field", "gsm_abis_rsl.full_immediate_assign_info_field", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_layer_3_message, { "Layer 3 message", "gsm_abis_rsl.layer_3_message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_descriptive_group_or_broadcast_call_reference, { "Descriptive group or broadcast call reference", "gsm_abis_rsl.descriptive_group_or_broadcast_call_reference", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_group_channel_description, { "Group Channel Description", "gsm_abis_rsl.group_channel_description", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_uic, { "UIC", "gsm_abis_rsl.uic", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsl_codec_list, { "Codec List", "gsm_abis_rsl.codec_list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_rsl,
        &ett_ie_link_id,
        &ett_ie_act_type,
        &ett_ie_bs_power,
        &ett_ie_bs_power_params,
        &ett_ie_ch_id,
        &ett_ie_ch_mode,
        &ett_ie_enc_inf,
        &ett_ie_ch_no,
        &ett_ie_frame_no,
        &ett_ie_ho_ref,
        &ett_ie_l1_inf,
        &ett_ie_L3_inf,
        &ett_ie_ms_id,
        &ett_ie_ms_pow,
        &ett_ie_ms_pow_params,
        &ett_ie_phy_ctx,
        &ett_ie_paging_grp,
        &ett_ie_paging_load,
        &ett_ie_access_delay,
        &ett_ie_rach_load,
        &ett_ie_req_ref,
        &ett_ie_req_ref_ra,
        &ett_ie_rel_mode,
        &ett_ie_resource_inf,
        &ett_ie_rlm_cause,
        &ett_ie_staring_time,
        &ett_ie_timing_adv,
        &ett_ie_uplink_meas,
        &ett_ie_full_imm_ass_inf,
        &ett_ie_smscb_inf,
        &ett_ie_ms_timing_offset,
        &ett_ie_err_msg,
        &ett_ie_full_bcch_inf,
        &ett_ie_ch_needed,
        &ett_ie_cb_cmd_type,
        &ett_ie_smscb_mess,
        &ett_ie_cbch_load_inf,
        &ett_ie_smscb_ch_ind,
        &ett_ie_grp_call_ref,
        &ett_ie_ch_desc,
        &ett_ie_nch_drx,
        &ett_ie_cmd_ind,
        &ett_ie_emlpp_prio,
        &ett_ie_uic,
        &ett_ie_main_ch_ref,
        &ett_ie_multirate_conf,
        &ett_ie_multirate_cntrl,
        &ett_ie_sup_codec_types,
        &ett_ie_codec_conf,
        &ett_ie_rtd,
        &ett_ie_tfo_status,
        &ett_ie_llp_apdu,
        &ett_ie_tfo_transp_cont,
        &ett_ie_cause,
        &ett_ie_meas_res_no,
        &ett_ie_message_id,
        &ett_ie_sys_info_type,
        &ett_ie_speech_mode,
        &ett_ie_conn_id,
        &ett_ie_remote_ip,
        &ett_ie_remote_port,
        &ett_ie_local_port,
        &ett_ie_local_ip,
        &ett_ie_rtp_payload,
        &ett_ie_paging_package,
        &ett_ie_paging_package_number,
        &ett_ie_paging_package_info,
        &ett_ie_paging_package_ch_a_emlpp,
        &ett_ie_paging_group_paras,
        &ett_phy_ctx_ie,
        &ett_phy_ctx_ie_ext_rand_access,
        &ett_phy_ctx_ab_rx_lvl_err_bits,
        &ett_phy_ctx_rxlvl_ext,
        &ett_ie_etws_pn,
        &ett_ie_osmo_rep_acch_cap,
        &ett_ie_osmo_top_acch_cap,
        &ett_ie_osmo_training_seq,
    };
    static ei_register_info ei[] = {
      /* Generated from convert_proto_tree_add_text.pl */
      { &ei_rsl_speech_or_data_indicator, { "gsm_abis_rsl.speech_or_data_indicator.bad", PI_PROTOCOL, PI_WARN, "Speech or data indicator != 1,2 or 3", EXPFILL }},
      { &ei_rsl_facility_information_element_3gpp_ts_44071, { "gsm_abis_rsl.facility_information_element_3gpp_ts_44071", PI_PROTOCOL, PI_NOTE, "Facility Information Element as defined in 3GPP TS 44.071", EXPFILL }},
      { &ei_rsl_embedded_message_tfo_configuration, { "gsm_abis_rsl.embedded_message_tfo_configuration", PI_PROTOCOL, PI_NOTE, "Embedded message that contains the TFO configuration", EXPFILL }},
      { &ei_rsl_mobile_allocation_deprecated, { "gsm_abis_rsl.mobile_allocation_deprecated", PI_PROTOCOL, PI_NOTE,
                                                "3GPP TS 24.008 Mobile Allocation IE shall for compatibility reasons "
                                                "be included but empty (see 3GPP TS 48.058, section 9.3.5)", EXPFILL }},
    };

    module_t *rsl_module;
    expert_module_t *expert_rsl;

#define RSL_ATT_TLVDEF(_attr, _type, _fixed_len)                \
        rsl_att_tlvdef.def[_attr].type = _type;                 \
        rsl_att_tlvdef.def[_attr].fixed_len = _fixed_len;       \

    /* We register even the standard RSL IE TVLs here, not just the
     * ip.access vendor specific elements.  This is due to the fact that we
     * don't have any formal specification for the ip.access RSL dialect,
     * and this way any standard elements will be 'known' to the TLV
     * parser, which can then gracefully skip over such elements and
     * continue decoding the message.  This will work even if the switch
     * statement in dissct_rsl_ipaccess_msg() doesn't contain explicit code
     * to decode them (yet?).
     */
    RSL_ATT_TLVDEF(RSL_IE_CH_NO,             TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_LINK_ID,           TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_ACT_TYPE,          TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_BS_POW,            TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_CH_ID,             TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CH_MODE,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_ENC_INF,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_FRAME_NO,          TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_HO_REF,            TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_L1_INF,            TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_L3_INF,            TLV_TYPE_TL16V,         0);
    RSL_ATT_TLVDEF(RSL_IE_MS_ID,             TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_MS_POW,            TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_PAGING_GRP,        TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_PAGING_LOAD,       TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_PHY_CTX,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_ACCESS_DELAY,      TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_RACH_LOAD,         TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_REQ_REF,           TLV_TYPE_FIXED,         3);
    RSL_ATT_TLVDEF(RSL_IE_REL_MODE,          TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_RESOURCE_INF,      TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_RLM_CAUSE,         TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_STARTING_TIME,     TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_TIMING_ADV,        TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_UPLINK_MEAS,       TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CAUSE,             TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_MEAS_RES_NO,       TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_MESSAGE_ID,        TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_SYS_INFO_TYPE,     TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_MS_POWER_PARAM,    TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_BS_POWER_PARAM,    TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_PREPROC_PARAM,     TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_PREPROC_MEAS,      TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_ERR_MSG,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_FULL_BCCH_INF,     TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CH_NEEDED,         TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_CB_CMD_TYPE,       TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_SMSCB_MESS,        TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_FULL_IMM_ASS_INF,  TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CBCH_LOAD_INF,     TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_SMSCB_CH_IND,      TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_GRP_CALL_REF,      TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CH_DESC,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_NCH_DRX_INF,       TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CMD_IND,           TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_EMLPP_PRIO,        TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_UIC,               TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_MAIN_CH_REF,       TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_MULTIRATE_CONF,    TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_MULTIRATE_CNTRL,   TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_SUP_CODEC_TYPES,   TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_CODEC_CONF,        TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_RTD,               TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_TFO_STATUS,        TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_LLP_APDU,          TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_REMOTE_IP,    TLV_TYPE_FIXED,         4);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_REMOTE_PORT,  TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_LOCAL_IP,     TLV_TYPE_FIXED,         4);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_CONN_STAT,    TLV_TYPE_TLV,           0);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_LOCAL_PORT,   TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_SPEECH_MODE,  TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_CONN_ID,      TLV_TYPE_FIXED,         2);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_RTP_PAYLOAD2, TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_RTP_PAYLOAD,  TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_IPAC_RTP_CSD_FMT,  TLV_TYPE_TV,            0);
    RSL_ATT_TLVDEF(RSL_IE_OSMO_TRAINING_SEQUENCE, TLV_TYPE_TLV,      0);
    RSL_ATT_TLVDEF(RSL_IE_OSMO_OSMUX_CID,    TLV_TYPE_TLV,           0);

    /* Register the protocol name and description */
    proto_rsl = proto_register_protocol("Radio Signalling Link (RSL)", "RSL", "gsm_abis_rsl");

    proto_register_field_array(proto_rsl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rsl = expert_register_protocol(proto_rsl);
    expert_register_field_array(expert_rsl, ei, array_length(ei));

    rsl_handle = register_dissector("gsm_abis_rsl", dissect_rsl, proto_rsl);

    rsl_module = prefs_register_protocol(proto_rsl, NULL);
    prefs_register_bool_preference(rsl_module, "use_ipaccess_rsl",
                                   "Use nanoBTS definitions",
                                   "Use ipaccess nanoBTS specific definitions for RSL",
                                   &global_rsl_use_nano_bts);
    prefs_register_bool_preference(rsl_module, "use_osmocom_rsl",
                                   "Use Osmocom definitions",
                                   "Use Osmocom specific definitions for RSL",
                                   &global_rsl_use_osmo_bts);
    prefs_register_bool_preference(rsl_module, "dissect_phy_ctx_inf",
                                   "Decode Physical Context Information field",
                                   "The Physical Context Information field is not specified "
                                   "This information should be not be analysed by BSC, but merely "
                                   "forwarded from one TRX/channel to another.",
                                   &global_rsl_dissect_phy_ctx_inf);
}

void
proto_reg_handoff_rsl(void)
{
    dissector_add_uint("lapd.gsm.sapi", LAPD_GSM_SAPI_RA_SIG_PROC, rsl_handle);

    gsm_cbch_handle = find_dissector_add_dependency("gsm_cbch", proto_rsl);
    gsm_cbs_handle = find_dissector_add_dependency("gsm_cbs", proto_rsl);
    gsm_a_ccch_handle = find_dissector_add_dependency("gsm_a_ccch", proto_rsl);
    gsm_a_dtap_handle = find_dissector_add_dependency("gsm_a_dtap", proto_rsl);
    gsm_a_sacch_handle = find_dissector_add_dependency("gsm_a_sacch", proto_rsl);
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
