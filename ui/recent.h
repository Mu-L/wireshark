/** @file
 *
 * Definitions for recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RECENT_H__
#define __RECENT_H__

#include <glib.h>

#include <stdio.h>
#include "epan/timestamp.h"
#include "ui/ws_ui_util.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Recent user interface settings.
 *  @ingroup main_window_group
 */

/** ???. */
#define RECENT_KEY_CAPTURE_FILE         "recent.capture_file"

/** ???. */
#define RECENT_KEY_DISPLAY_FILTER       "recent.display_filter"

#define RECENT_KEY_COL_WIDTH            "column.width"

#define RECENT_KEY_CAPTURE_FILTER       "recent.capture_filter"

#define RECENT_KEY_REMOTE_HOST          "recent.remote_host"

typedef struct _col_width_data {
    int    width;
    char   xalign;
} col_width_data;

/** Defines used in col_width_data.xalign */
#define COLUMN_XALIGN_DEFAULT  0
#define COLUMN_XALIGN_LEFT    'L'
#define COLUMN_XALIGN_CENTER  'C'
#define COLUMN_XALIGN_RIGHT   'R'

typedef enum {
    BYTES_HEX,
    BYTES_BITS,
    BYTES_DEC,
    BYTES_OCT
} bytes_view_type;

typedef enum {
    BYTES_ENC_FROM_PACKET, // frame_data packet_char_enc
    BYTES_ENC_ASCII,
    BYTES_ENC_EBCDIC
} bytes_encoding_type;

typedef enum {
    SEARCH_IN_PACKET_LIST,
    SEARCH_IN_PACKET_DETAILS,
    SEARCH_IN_PACKET_BYTES
} search_in_type;

typedef enum {
    SEARCH_CHAR_SET_NARROW_AND_WIDE,
    SEARCH_CHAR_SET_NARROW,
    SEARCH_CHAR_SET_WIDE
} search_char_set_type;

typedef enum {
    SEARCH_TYPE_DISPLAY_FILTER,
    SEARCH_TYPE_HEX_VALUE,
    SEARCH_TYPE_STRING,
    SEARCH_TYPE_REGEX
} search_type_type;

typedef enum {
    SHOW_ASCII,
    SHOW_ASCII_CONTROL,
    SHOW_CARRAY,
    SHOW_EBCDIC,
    SHOW_HEXDUMP,
    SHOW_HTML,
    SHOW_IMAGE,
    SHOW_JSON,
    SHOW_RAW,
    SHOW_RUSTARRAY,
    SHOW_CODEC, // Will map to UTF-8 in the combobox (other codecs
                // are generated at runtime).
    SHOW_YAML
} bytes_show_type;

typedef enum {
    FOLLOW_DELTA_NONE,
    FOLLOW_DELTA_TURN,
    FOLLOW_DELTA_ALL
} follow_delta_type;

typedef enum {
    DecodeAsNone,
    DecodeAsBASE64,
    DecodeAsCompressed,
    DecodeAsHexDigits,
    DecodeAsPercentEncoding,
    DecodeAsQuotedPrintable,
    DecodeAsROT13
} bytes_decode_type;

/** Recent settings. */
typedef struct recent_settings_tag {
    bool        main_toolbar_show;
    bool        filter_toolbar_show;
    bool        wireless_toolbar_show;
    bool        packet_list_show;
    bool        tree_view_show;
    bool        byte_view_show;
    bool        packet_diagram_show;
    bool        statusbar_show;
    bool        packet_list_colorize;
    bool        capture_auto_scroll;
    ts_type     gui_time_format;
    int         gui_time_precision;
    ts_seconds_type gui_seconds_format;
    int         gui_zoom_level;
    bytes_view_type gui_bytes_view;
    bytes_encoding_type gui_bytes_encoding;
    bool        gui_packet_diagram_field_values;
    bool        gui_allow_hover_selection;

    search_in_type  gui_search_in;
    search_char_set_type gui_search_char_set;
    bool        gui_search_case_sensitive;
    bool        gui_search_reverse_dir;
    bool        gui_search_multiple_occurs;
    search_type_type gui_search_type;
    bytes_show_type gui_follow_show;
    follow_delta_type gui_follow_delta;
    bytes_decode_type gui_show_bytes_decode;
    bytes_show_type gui_show_bytes_show;

    int         gui_geometry_main_x;
    int         gui_geometry_main_y;
    int         gui_geometry_main_width;
    int         gui_geometry_main_height;

    bool        gui_geometry_main_maximized;
    bool        gui_geometry_leftalign_actions;

    int         gui_geometry_main_upper_pane;
    int         gui_geometry_main_lower_pane;
    char       *gui_geometry_main;
    char       *gui_geometry_main_master_split;
    char       *gui_geometry_main_extra_split;
    bool        privs_warn_if_elevated;
    bool        sys_warn_if_no_capture;
    GList      *col_width_list;                     /* column widths */
    GList      *conversation_tabs;                  /* enabled conversation dialog tabs */
    GList      *conversation_tabs_columns;          /* save the columns for conversation dialogs */
    GList      *endpoint_tabs;                      /* enabled endpoint dialog tabs */
    GList      *endpoint_tabs_columns;              /* save the columns for endpoint dialogs */
    int         gui_profile_switch_check_count;     /* number of packets / events to check for automatic profile switching */
    char       *gui_fileopen_remembered_dir;        /* folder of last capture loaded in File Open dialog */
    bool        gui_rlc_use_pdus_from_mac;
    GList      *custom_colors;
    GList      *gui_additional_toolbars;
    GList      *interface_toolbars;

    bool        gui_tsgd_throughput_show;            /* tcp_stream_dialog throughput checkbox */
    bool        gui_tsgd_goodput_show;               /* tcp_stream_dialog goodput checkbox */
    double      gui_tsgd_ma_window_size;             /* tcp_stream_dialog ma_window_size */
} recent_settings_t;

/** Global recent settings. */
extern recent_settings_t recent;

/** Initialize recent settings module (done at startup) */
extern void recent_init(void);

/** Cleanup/Frees recent settings (done at shutdown) */
extern void recent_cleanup(void);

/** Write recent_common settings file.
 *
 * @return true if succeeded, false if failed
 */
extern bool write_recent(void);

/** Write profile recent settings file.
 *
 * @return true if succeeded, false if failed
 */
extern bool write_profile_recent(void);

/** Read recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_static(char **rf_path_return, int *rf_errno_return);

/** Read profile recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_profile_static(char **rf_path_return, int *rf_errno_return);

/** Read recent settings file (dynamic part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_dynamic(char **rf_path_return, int *rf_errno_return);

/**
 * Given a -o command line string, parse it and set the recent value in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 *
 * @param prefarg a string of the form "<recent name>:<recent value>", as might appear
 * as an argument to a "-o" command line option
 * @return PREFS_SET_OK or PREFS_SET_SYNTAX_ERR
 */
extern int recent_set_arg(char *prefarg);

/** Free the recent settings list of column width information
 *
 * @param rs the recent settings (currently a global)
 */
extern void recent_free_column_width_info(recent_settings_t *rs);

/** Insert an entry in the recent column width setting for
 * the given column, which should have been just added to
 * the column list preference. (This keeps them in sync.)
 *
 * @param col column number
 */
extern void recent_insert_column(int col);

/** Remove an entry in the recent column width setting for
 * the given column, which should have been just removed to
 * the column list preference. (This keeps them in sync.)
 *
 * @param col column number
 */
extern void recent_remove_column(int col);

/** Get the column width for the given column
 *
 * @param col column number
 */
extern int recent_get_column_width(int col);

/** Set the column width for the given column
 *
 * @param col column number
 * @param width column width
 */
extern void recent_set_column_width(int col, int width);

/** Get the column xalign for the given column
 *
 * @param col column number
 */
extern char recent_get_column_xalign(int col);

/** Set the column xalign for the given column
 *
 * @param col column number
 * @param xalign column alignment
 */
extern void recent_set_column_xalign(int col, char xalign);

/* save the window and its current geometry into the geometry hashtable */
extern void window_geom_save(const char *name, window_geometry_t *geom);

/* load the desired geometry for this window from the geometry hashtable */
extern bool window_geom_load(const char *name, window_geometry_t *geom);

extern void window_splitter_save(const char *name, const char *splitter_state);

extern const char * window_splitter_load(const char *name);

/**
 * Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 */
extern GList *recent_get_cfilter_list(const char *ifname);

/**
 * Add a capture filter to the global recent capture filter list or
 * the recent capture filter list for an interface.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @param s text of capture filter
 */
extern void recent_add_cfilter(const char *ifname, const char *s);

/**
 * Get the value of an entry for a remote host from the remote host list.
 *
 * @param host host name for the remote host.
 *
 * @return pointer to the entry for the remote host.
 */
extern struct remote_host *recent_get_remote_host(const char *host);

/**
 * Get the number of entries of the remote host list.
 *
 * @return number of entries in the list.
 */
extern int recent_get_remote_host_list_size(void);

/**
 * Iterate over all items in the remote host list, calling a
 * function for each member
 *
 * @param func function to be called
 * @param user_data argument to pass as user data to the function
 */
extern void recent_remote_host_list_foreach(GFunc func, void *user_data);

/**
 * Free all entries of the remote host list.
 */
extern void recent_free_remote_host_list(void);

/**
 * Add an entry to the remote_host_list.
 *
 * @param host Key of the entry
 * @param rh Value of the entry
 */
extern void recent_add_remote_host(char *host, struct remote_host *rh);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* recent.h */
