/** @file
 *
 * Some content from gtk/help_dlg.h by Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 */

#ifndef __HELP_URL_H__
#define __HELP_URL_H__

#include <ws_attributes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file help_url.h
 * "Help" URLs.
 */

typedef enum {
    TOPIC_ACTION_NONE,

    /* pages online at www.wireshark.org */
    ONLINEPAGE_WIRESHARK_HOME,
    ONLINEPAGE_WIRESHARK_WIKI,
    ONLINEPAGE_USERGUIDE,
    ONLINEPAGE_FAQ,
    ONLINEPAGE_WIRESHARK_DOWNLOAD,
    ONLINEPAGE_DOCS,
    ONLINEPAGE_SAMPLE_FILES,
    ONLINEPAGE_CAPTURE_SETUP,
    ONLINEPAGE_NETWORK_MEDIA,
    ONLINEPAGE_SAMPLE_CAPTURES,
    ONLINEPAGE_SECURITY,
    ONLINEPAGE_ASK,
    ONLINEPAGE_DFILTER_REF,

    /* pages online at stratoshark.org */
    ONLINEPAGE_STRATOSHARK_HOME,
    ONLINEPAGE_STRATOSHARK_WIKI,
    ONLINEPAGE_STRATOSHARK_DOWNLOAD,

    /* local manual pages */
    LOCALPAGE_MAN_WIRESHARK = 100,
    LOCALPAGE_MAN_STRATOSHARK,
    LOCALPAGE_MAN_WIRESHARK_FILTER,
    LOCALPAGE_MAN_CAPINFOS,
    LOCALPAGE_MAN_DUMPCAP,
    LOCALPAGE_MAN_EDITCAP,
    LOCALPAGE_MAN_MERGECAP,
    LOCALPAGE_MAN_RAWSHARK,
    LOCALPAGE_MAN_REORDERCAP,
    LOCALPAGE_MAN_TEXT2PCAP,
    LOCALPAGE_MAN_TSHARK,

    /* Release Notes */
    LOCALPAGE_WIRESHARK_RELEASE_NOTES,
    LOCALPAGE_STRATOSHARK_RELEASE_NOTES,

    /* help pages (textfiles or HTML User's Guide) */
    HELP_CONTENT = 200,
    HELP_GETTING_STARTED,           /* currently unused */
    HELP_CAPTURE_OPTIONS,           /* currently unused */
    HELP_CAPTURE_FILTERS_DIALOG,
    HELP_DISPLAY_FILTERS_DIALOG,
    HELP_FILTER_EXPRESSION_DIALOG,
    HELP_DISPLAY_MACRO_DIALOG,
    HELP_COLORING_RULES_DIALOG,
    HELP_CONFIG_PROFILES_DIALOG,
    HELP_PRINT_DIALOG,
    HELP_FIND_DIALOG,
    HELP_FILESET_DIALOG,
    HELP_FIREWALL_DIALOG,
    HELP_GOTO_DIALOG,
    HELP_CAPTURE_OPTIONS_DIALOG,
    HELP_CAPTURE_MANAGE_INTERFACES_DIALOG,
    HELP_ENABLED_PROTOCOLS_DIALOG,
    HELP_ENABLED_HEURISTICS_DIALOG,
    HELP_DECODE_AS_DIALOG,
    HELP_DECODE_AS_SHOW_DIALOG,
    HELP_FOLLOW_STREAM_DIALOG,
    HELP_SHOW_PACKET_BYTES_DIALOG,
    HELP_EXPERT_INFO_DIALOG,
    HELP_EXTCAP_OPTIONS_DIALOG,
    HELP_STATS_SUMMARY_DIALOG,
    HELP_STATS_PROTO_HIERARCHY_DIALOG,
    HELP_STATS_ENDPOINTS_DIALOG,
    HELP_STATS_CONVERSATIONS_DIALOG,
    HELP_STATS_IO_GRAPH_DIALOG,
    HELP_STATS_LTE_MAC_TRAFFIC_DIALOG,
    HELP_STATS_LTE_RLC_TRAFFIC_DIALOG,
    HELP_STATS_TCP_STREAM_GRAPHS_DIALOG,
    HELP_STATS_WLAN_TRAFFIC_DIALOG,
    HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG,
    HELP_PREFERENCES_DIALOG,
    HELP_CAPTURE_INFO_DIALOG,
    HELP_EXPORT_FILE_DIALOG,
    HELP_EXPORT_BYTES_DIALOG,
    HELP_EXPORT_PDUS_DIALOG,
    HELP_STRIP_HEADERS_DIALOG,
    HELP_EXPORT_OBJECT_LIST,
    HELP_OPEN_DIALOG,
    HELP_MERGE_DIALOG,
    HELP_IMPORT_DIALOG,
    HELP_SAVE_DIALOG,
    HELP_EXPORT_FILE_WIN32_DIALOG,
    HELP_OPEN_WIN32_DIALOG,
    HELP_MERGE_WIN32_DIALOG,
    HELP_SAVE_WIN32_DIALOG,
    HELP_TIME_SHIFT_DIALOG,
    HELP_TELEPHONY_VOIP_CALLS_DIALOG,
    HELP_TELEPHONY_RTP_ANALYSIS_DIALOG,
    HELP_TELEPHONY_RTP_STREAMS_DIALOG,
    HELP_NEW_PACKET_DIALOG,
    HELP_IAX2_ANALYSIS_DIALOG,
    HELP_TELEPHONY_RTP_PLAYER_DIALOG,
    HELP_STAT_FLOW_GRAPH,
    HELP_STATS_PLOT_DIALOG
} topic_action_e;

/** Given a page in the Wireshark User's Guide return its URL. Returns a
 *  URL to a local file if present, or to the online guide if the local
 *  file is unavailable.
 *
 * @param page A page in the User's Guide.
 * @return A static URL. The return value must be freed with g_free().
 */
WS_RETNONNULL char *user_guide_url(const char *page);

/** Given a topic action return its URL. If the attempt fails NULL
 *  will be returned.
 *
 * @param action Topic action.
 * @return A static URL. The return value must be freed with g_free().
 */
WS_RETNONNULL char *topic_action_url(topic_action_e action);

/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param topic the topic to display
 */
void topic_action(topic_action_e topic);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __HELP_URL_H__ */
