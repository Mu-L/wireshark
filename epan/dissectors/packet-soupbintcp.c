/* packet-soupbintcp.c
 * Routines for SoupBinTCP 3.0 protocol dissection
 * Copyright 2013 David Arnold <davida@pobox.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * SoupBinTCP is a framing protocol published and used by NASDAQ to
 * encapsulate both market data (ITCH) and order entry (OUCH)
 * protocols.  It is derived from the original SOUP protocol, which
 * was ASCII-based, and relied on an EOL indicator as a message
 * boundary.
 *
 * SoupBinTCP was introduced with OUCH-4.0 / ITCH-4.0 when those
 * protocols also switched to using a binary representation for
 * numerical values.
 *
 * The SOUP/SoupBinTCP protocols are also commonly used by other
 * financial exchanges, although frequently they are more SOUP-like
 * than exactly the same.  This dissector doesn't attempt to support
 * any other SOUP-like variants; I think it's probably better to have
 * separate (if similar) dissectors for them.
 *
 * The only really complexity in the protocol is the message sequence
 * numbering.  See the comments below for an explanation of how it is
 * handled.
 *
 * Specifications are available from NASDAQ's website, although the
 * links to find them tend to move around over time.  At the time of
 * writing the correct URL is:
 *
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/soupbintcp.pdf
 *
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/expert.h>

#include <wsutil/strtoi.h>

/* For tcp_dissect_pdus() */
#include "packet-tcp.h"

void proto_register_soupbintcp(void);
void proto_reg_handoff_soupbintcp(void);

/** Session data stored in the conversation */
struct conv_data {
    /** Next expected sequence number
     *
     * Set by the Login Accepted packet, and then updated for each
     * subsequent Sequenced Data packet during dissection. */
    unsigned next_seq;
};


/** Per-PDU data, stored in the frame's private data pointer */
struct pdu_data {
    /** Sequence number for this PDU */
    unsigned seq_num;
};


/** Packet names, indexed by message type code value */
static const value_string pkt_type_val[] = {
    { '+', "Debug Packet" },
    { 'A', "Login Accepted" },
    { 'H', "Server Heartbeat" },
    { 'J', "Login Rejected" },
    { 'L', "Login Request" },
    { 'O', "Logout Request" },
    { 'R', "Client Heartbeat" },
    { 'S', "Sequenced Data" },
    { 'U', "Unsequenced Data" },
    { 'Z', "End of Session" },
    { 0, NULL }
};


/** Login reject reasons, indexed by code value */
static const value_string reject_code_val[] = {
    { 'A', "Not authorized" },
    { 'S', "Session not available" },
    { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_soupbintcp;
static dissector_handle_t soupbintcp_handle;
static heur_dissector_list_t heur_subdissector_list;

/* Preferences */
static bool soupbintcp_desegment = true;

/* Initialize the subtree pointers */
static int ett_soupbintcp;

/* Header field formatting */
static int hf_soupbintcp_packet_length;
static int hf_soupbintcp_packet_type;
static int hf_soupbintcp_message;
static int hf_soupbintcp_text;
static int hf_soupbintcp_username;
static int hf_soupbintcp_password;
static int hf_soupbintcp_session;
static int hf_soupbintcp_seq_num;
static int hf_soupbintcp_next_seq_num;
static int hf_soupbintcp_req_seq_num;
static int hf_soupbintcp_reject_code;

static expert_field ei_soupbintcp_next_seq_num_invalid;
static expert_field ei_soupbintcp_req_seq_num_invalid;

/** Dissector for SoupBinTCP messages */
static void
dissect_soupbintcp_common(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree)
{
    struct conv_data *conv_data;
    struct pdu_data  *pdu_data;
    const char       *pkt_name;
    int32_t           seq_num;
    bool              seq_num_valid;
    proto_item       *ti;
    proto_tree       *soupbintcp_tree = NULL;
    conversation_t   *conv            = NULL;
    uint16_t          expected_len;
    uint8_t           pkt_type;
    int               offset          = 0;
    unsigned          this_seq        = 0, next_seq = 0, key;
    heur_dtbl_entry_t *hdtbl_entry;
    proto_item       *pi;

    /* Record the start of the packet to use as a sequence number key */
    key = (unsigned)tvb_raw_offset(tvb);

    /* Get the 16-bit big-endian SOUP packet length */
    expected_len = tvb_get_ntohs(tvb, 0);

    /* Get the 1-byte SOUP message type */
    pkt_type = tvb_get_uint8(tvb, 2);

    /* Since we use the packet name a few times, get and save that value */
    pkt_name = val_to_str(pkt_type, pkt_type_val, "Unknown (%u)");

    /* Set the protocol name in the summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SoupBinTCP");

    /* Set the packet name in the info column */
    col_add_str(pinfo->cinfo, COL_INFO, pkt_name);

    /* Sequence number tracking
     *
     * SOUP does not number packets from client to server (the server
     * acknowledges all important messages, so the client should use
     * the acks to figure out if the server received the message, and
     * otherwise resend it).
     *
     * Packets from server to client are numbered, but it's implicit.
     * The Login Accept packet contains the next sequence number that
     * the server will send, and the client needs to count the
     * Sequenced Data packets that it receives to know what their
     * sequence numbers are.
     *
     * So, we grab the next sequence number from the Login Acceptance
     * packet, and save it in a conversation_t we associate with the
     * TCP session.  Then, for each Sequenced Data packet we receive,
     * the first time it's processed (when PINFO_FD_VISITED() is
     * false), we write it into the PDU's frame's private data pointer
     * and increment the saved sequence number (in the conversation_t).
     *
     * If the visited flag is true, then we've dissected this packet
     * already, and so we can fetch the sequence number from the
     * frame's private data area.
     *
     * In either case, if there's any problem, we report zero as the
     * sequence number, and try to continue dissecting. */

    /* If first dissection of Login Accept, save sequence number */
    if (pkt_type == 'A' && !PINFO_FD_VISITED(pinfo)) {
        ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, 13, 20, ENC_ASCII),
            NULL, &next_seq);

        /* Create new conversation for this session */
        conv = conversation_new(pinfo->num,
                                &pinfo->src,
                                &pinfo->dst,
                                conversation_pt_to_conversation_type(pinfo->ptype),
                                pinfo->srcport,
                                pinfo->destport,
                                0);

        /* Store starting sequence number for session's packets */
        conv_data = wmem_new(wmem_file_scope(), struct conv_data);
        conv_data->next_seq = next_seq;
        conversation_add_proto_data(conv, proto_soupbintcp, conv_data);
    }

    /* Handle sequence numbering for a Sequenced Data packet */
    if (pkt_type == 'S') {
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Get next expected sequence number from conversation */
            conv = find_conversation_pinfo(pinfo, 0);
            if (!conv) {
                this_seq = 0;
            } else {
                conv_data = (struct conv_data *)conversation_get_proto_data(conv,
                                                        proto_soupbintcp);
                if (conv_data) {
                    this_seq = conv_data->next_seq++;
                } else {
                    this_seq = 0;
                }

                pdu_data = wmem_new(wmem_file_scope(), struct pdu_data);
                pdu_data->seq_num = this_seq;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_soupbintcp, key, pdu_data);
            }
        } else {
            pdu_data = (struct pdu_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_soupbintcp, key);
            if (pdu_data) {
                this_seq = pdu_data->seq_num;
            } else {
                this_seq = 0;
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", SeqNum = %u", this_seq);
    }

    if (tree) {
        /* Create sub-tree for SoupBinTCP details */
        ti = proto_tree_add_item(tree,
                                 proto_soupbintcp,
                                 tvb, 0, -1, ENC_NA);

        soupbintcp_tree = proto_item_add_subtree(ti, ett_soupbintcp);

        /* Append the packet name to the sub-tree item */
        proto_item_append_text(ti, ", %s", pkt_name);

        /* Length */
        proto_tree_add_item(soupbintcp_tree,
                            hf_soupbintcp_packet_length,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Type */
        proto_tree_add_item(soupbintcp_tree,
                            hf_soupbintcp_packet_type,
                            tvb, offset, 1, ENC_ASCII);
        offset += 1;

        switch (pkt_type) {
        case '+': /* Debug Message */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_text,
                                tvb, offset, expected_len - 1, ENC_ASCII);
            break;

        case 'A': /* Login Accept */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_session,
                                tvb, offset, 10, ENC_ASCII);
            offset += 10;

            seq_num_valid = ws_strtoi32(tvb_get_string_enc(pinfo->pool,
                tvb, offset, 20, ENC_ASCII), NULL, &seq_num);
            pi = proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_next_seq_num,
                                               tvb, offset, 20,
                                               "X", "%d", seq_num);
            if (!seq_num_valid)
                expert_add_info(pinfo, pi, &ei_soupbintcp_next_seq_num_invalid);

            break;

        case 'J': /* Login Reject */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_reject_code,
                                tvb, offset, 1, ENC_ASCII);
            break;

        case 'U': /* Unsequenced Data */
            /* Display handled by sub-dissector */
            break;

        case 'S': /* Sequenced Data */
            proto_item_append_text(ti, ", SeqNum=%u", this_seq);
            proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_seq_num,
                                               tvb, offset, 0,
                                               "X",
                                               "%u (Calculated)",
                                               this_seq);

            /* Display handled by sub-dissector */
            break;

        case 'L': /* Login Request */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_username,
                                tvb, offset, 6, ENC_ASCII);
            offset += 6;

            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_password,
                                tvb, offset, 10, ENC_ASCII);
            offset += 10;

            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_session,
                                tvb, offset, 10, ENC_ASCII);
            offset += 10;

            seq_num_valid = ws_strtoi32(tvb_get_string_enc(pinfo->pool,
                tvb, offset, 20, ENC_ASCII), NULL, &seq_num);
            pi = proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_req_seq_num,
                                               tvb, offset, 20,
                                               "X", "%d", seq_num);
            if (!seq_num_valid)
                expert_add_info(pinfo, pi, &ei_soupbintcp_req_seq_num_invalid);

            break;

        case 'H': /* Server Heartbeat */
            break;

        case 'O': /* Logout Request */
            break;

        case 'R': /* Client Heartbeat */
            break;

        case 'Z': /* End of Session */
            break;

        default:
            /* Unknown */
            proto_tree_add_item(tree,
                                hf_soupbintcp_message,
                                tvb, offset, -1, ENC_NA);
            break;
        }
    }

    /* Call sub-dissector for encapsulated data */
    if (pkt_type == 'S' || pkt_type == 'U') {
        tvbuff_t         *sub_tvb;

        /* Sub-dissector tvb starts at 3 (length (2) + pkt_type (1)) */
        sub_tvb = tvb_new_subset_remaining(tvb, 3);

        /* Otherwise, try heuristic dissectors */
        if (dissector_try_heuristic(heur_subdissector_list,
                                    sub_tvb,
                                    pinfo,
                                    tree,
                                    &hdtbl_entry,
                                    NULL)) {
            return;
        }

        /* Otherwise, give up, and just print the bytes in hex */
        if (tree) {
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_message,
                                sub_tvb, 0, -1,
                                ENC_NA);
        }
    }
}


/** Return the size of the PDU in @p tvb, starting at @p offset */
static unsigned
get_soupbintcp_pdu_len(
    packet_info *pinfo _U_,
    tvbuff_t    *tvb,
    int          offset,
    void        *data _U_)
{
    /* Determine the length of the PDU using the SOUP header's 16-bit
       big-endian length (at offset zero).  We're guaranteed to get at
       least two bytes here because we told tcp_dissect_pdus() that we
       needed them.  Add 2 to the retrieved value, because the SOUP
       length doesn't include the length field itself. */
    return (unsigned)tvb_get_ntohs(tvb, offset) + 2;
}


/** Dissect a possibly-reassembled TCP PDU */
static int
dissect_soupbintcp_tcp_pdu(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void        *data _U_)
{
    dissect_soupbintcp_common(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}


/** Dissect a TCP segment containing SoupBinTCP data */
static int
dissect_soupbintcp_tcp(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void        *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     soupbintcp_desegment, 2,
                     get_soupbintcp_pdu_len,
                     dissect_soupbintcp_tcp_pdu, data);
    return tvb_captured_length(tvb);
}

void
proto_register_soupbintcp(void)
{
    expert_module_t* expert_soupbinttcp;

    static hf_register_info hf[] = {

        { &hf_soupbintcp_packet_length,
          { "Packet Length", "soupbintcp.packet_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Packet length, in bytes, NOT including these two bytes.",
            HFILL }},

        { &hf_soupbintcp_packet_type,
          { "Packet Type", "soupbintcp.packet_type",
            FT_CHAR, BASE_HEX, VALS(pkt_type_val), 0x0,
            "Message type code",
            HFILL }},

        { &hf_soupbintcp_reject_code,
          { "Login Reject Code", "soupbintcp.reject_code",
            FT_CHAR, BASE_HEX, VALS(reject_code_val), 0x0,
            "Login reject reason code",
            HFILL }},

        { &hf_soupbintcp_message,
          { "Message", "soupbintcp.message",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Content of SoupBinTCP frame",
            HFILL }},

        { &hf_soupbintcp_text,
          { "Debug Text", "soupbintcp.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Free-form, human-readable text",
            HFILL }},

        { &hf_soupbintcp_username,
          { "User Name", "soupbintcp.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "User's login name",
            HFILL }},

        { &hf_soupbintcp_password,
          { "Password", "soupbintcp.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "User's login password",
            HFILL }},

        { &hf_soupbintcp_session,
          { "Session", "soupbintcp.session",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Session identifier, or send all spaces to log into the currently "
            "active session",
            HFILL }},

        { &hf_soupbintcp_seq_num,
          { "Sequence number", "soupbintcp.seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Calculated sequence number for this message",
            HFILL }},

        { &hf_soupbintcp_next_seq_num,
          { "Next sequence number", "soupbintcp.next_seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Sequence number of next Sequenced Data message to be delivered",
            HFILL }},

        { &hf_soupbintcp_req_seq_num,
          { "Requested sequence number", "soupbintcp.req_seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Request to begin (re)transmission of Sequenced Data at this "
            "sequence number, or, if zero, to begin transmission with the "
            "next message generated",
            HFILL }}
    };

    static int *ett[] = {
        &ett_soupbintcp
    };

    static ei_register_info ei[] = {
        { &ei_soupbintcp_req_seq_num_invalid, { "soupbintcp.req_seq_num.invalid", PI_MALFORMED, PI_ERROR,
            "Sequence number of next Sequenced Data message to be delivered is an invalid string", EXPFILL }},
        { &ei_soupbintcp_next_seq_num_invalid, { "soupbintcp.next_seq_num.invalid", PI_MALFORMED, PI_ERROR,
            "Request to begin (re)transmission is an invalid string", EXPFILL }}
        };

    module_t *soupbintcp_module;

    proto_soupbintcp = proto_register_protocol("SoupBinTCP", "SoupBinTCP", "soupbintcp");
    soupbintcp_handle = register_dissector("soupbintcp", dissect_soupbintcp_tcp, proto_soupbintcp);

    proto_register_field_array(proto_soupbintcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    soupbintcp_module = prefs_register_protocol(proto_soupbintcp, NULL);

    prefs_register_bool_preference(
        soupbintcp_module,
        "desegment",
        "Reassemble SoupBinTCP messages spanning multiple TCP segments",
        "Whether the SoupBinTCP dissector should reassemble messages "
        "spanning multiple TCP segments.",
        &soupbintcp_desegment);

    heur_subdissector_list = register_heur_dissector_list_with_description("soupbintcp", "SoupBinTCP encapsulated data", proto_soupbintcp);

    expert_soupbinttcp = expert_register_protocol(proto_soupbintcp);
    expert_register_field_array(expert_soupbinttcp, ei, array_length(ei));
}


void
proto_reg_handoff_soupbintcp(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "", soupbintcp_handle);
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
