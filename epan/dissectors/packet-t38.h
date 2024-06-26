/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-t38.h                                                               */
/* asn2wrs.py -q -L -p t38 -c ./t38.cnf -s ./packet-t38-template -D . -O ../.. T38_2002.asn */

/* packet-t38.h
 *
 * Routines for T38 dissection
 * 2003 Hans Viens
 * 2004 Alejandro Vaquero, add support to conversation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ws_symbol_export.h"

#define MAX_T38_DATA_ITEMS 4
#define MAX_T38_DESC 128

typedef struct _t38_packet_info {
	guint16 seq_num;	/* UDPTLPacket sequence number */
	gint32 type_msg;	/* 0=t30-indicator    1=data */
	guint32 t30ind_value;
	guint32 data_value;	/* standard and speed */
	guint32 setup_frame_number;
	guint32 Data_Field_field_type_value;
	guint8	t30_Facsimile_Control;
	gchar   desc[MAX_T38_DESC]; /* Description used to be displayed in the frame label Graph Analysis */
	gchar   desc_comment[MAX_T38_DESC]; /* Description used to be displayed in the Comment Graph Analysis */
	double time_first_t4_data;
	guint32 frame_num_first_t4_data;
} t38_packet_info;


#define MAX_T38_SETUP_METHOD_SIZE 7


/* Info to save the State to reassemble Data (e.g. HDLC) and the Setup (e.g. SDP) in T38 conversations */
typedef struct _t38_conv_info t38_conv_info;

struct _t38_conv_info {

	guint32 reass_ID;
	int reass_start_seqnum;
	guint32 reass_start_data_field;
	guint32 reass_data_type;
	gint32 last_seqnum; /* used to avoid duplicated seq num shown in the Graph Analysis */
	guint32 packet_lost;
	guint32 burst_lost;
	double time_first_t4_data;
	guint32 additional_hdlc_data_field_counter;
	gint32 seqnum_prev_data_field;
	t38_conv_info *next;

};

/* Info to save the State to reassemble Data (e.g. HDLC) and the Setup (e.g. SDP) in T38 conversations */
typedef struct _t38_conv
{
	gchar   setup_method[MAX_T38_SETUP_METHOD_SIZE + 1];
	guint32 setup_frame_number;
	t38_conv_info src_t38_info;
	t38_conv_info dst_t38_info;
} t38_conv;

/* Add an T38 conversation with the given details */
WS_DLL_PUBLIC
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number);


WS_DLL_PUBLIC const value_string t38_T30_indicator_vals[];
WS_DLL_PUBLIC const value_string t38_T30_data_vals[];



