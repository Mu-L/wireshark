/* capture.c
 * Routines for packet capture
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#ifdef HAVE_LIBPCAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <ws_exit_codes.h>

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include "extcap.h"
#include "file.h"
#include "ui/capture.h"
#include "capture/capture_ifinfo.h"
#include <capture/capture_sync.h>
#include "capture/iface_monitor.h"
#include "ui/capture_info.h"
#include "ui/capture_ui_utils.h"
#include "ui/iface_lists.h"
#include "ui/util.h"
#include "ui/urls.h"
#include "capture/capture-pcap-util.h"

#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif

#include "ui/simple_dialog.h"
#include "ui/ws_ui_util.h"

#include <wsutil/application_flavor.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/str_util.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

typedef struct if_stat_cache_item_s {
    char *name;
    struct pcap_stat ps;
} if_stat_cache_item_t;

struct if_stat_cache_s {
    int stat_fd;
    ws_process_id fork_child;
    GList *cache_list;  /* List of if_stat_chache_entry_t */
};

/* this callback mechanism should possibly be replaced by the g_signal_...() stuff (if I only would know how :-) */
typedef struct {
    capture_callback_t cb_fct;
    void *user_data;
} capture_callback_data_t;

static GList *capture_callbacks;

static void
capture_callback_invoke(int event, capture_session *cap_session)
{
    capture_callback_data_t *cb;
    GList *cb_item = capture_callbacks;

    /* there should be at least one interested */
    ws_assert(cb_item != NULL);

    while(cb_item != NULL) {
        cb = (capture_callback_data_t *)cb_item->data;
        cb->cb_fct(event, cap_session, cb->user_data);
        cb_item = g_list_next(cb_item);
    }
}


void
capture_callback_add(capture_callback_t func, void *user_data)
{
    capture_callback_data_t *cb;

    cb = g_new(capture_callback_data_t, 1);
    cb->cb_fct = func;
    cb->user_data = user_data;

    capture_callbacks = g_list_prepend(capture_callbacks, cb);
}

void
capture_callback_remove(capture_callback_t func, void *user_data)
{
    capture_callback_data_t *cb;
    GList *cb_item = capture_callbacks;

    while(cb_item != NULL) {
        cb = (capture_callback_data_t *)cb_item->data;
        if(cb->cb_fct == func && cb->user_data == user_data) {
            capture_callbacks = g_list_remove(capture_callbacks, cb);
            g_free(cb);
            return;
        }
        cb_item = g_list_next(cb_item);
    }

    ws_assert_not_reached();
}

/**
 * Start a capture.
 *
 * @return true if the capture starts successfully, false otherwise.
 */
bool
capture_start(capture_options *capture_opts, GPtrArray *capture_comments,
              capture_session *cap_session, info_data_t* cap_data,
              void(*update_cb)(void))
{
    GString *source;

    cap_session->state = CAPTURE_PREPARING;
    cap_session->count = 0;
    ws_message("Capture Start ...");
    source = get_iface_list_string(capture_opts, IFLIST_SHOW_FILTER);
    cf_set_tempfile_source((capture_file *)cap_session->cf, source->str);
    g_string_free(source, TRUE);
    iface_mon_enable(false);
    /* try to start the capture child process */
    if (!sync_pipe_start(capture_opts, capture_comments, cap_session,
                         cap_data, update_cb)) {
        iface_mon_enable(true);
        /* We failed to start the capture child. */
        if(capture_opts->save_file != NULL) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
        }

        ws_message("Capture Start failed.");
        cap_session->state = CAPTURE_STOPPED;
        return false;
    }

    // Do we need data structures for ignoring duplicate frames?
    if (prefs.ignore_dup_frames && capture_opts->real_time_mode) {
        fifo_string_cache_init(&cap_session->frame_dup_cache,
                prefs.ignore_dup_frames_cache_entries, g_free);
        cap_session->frame_cksum = g_checksum_new(G_CHECKSUM_SHA256);
    }

    /* the capture child might not respond shortly after bringing it up */
    /* (for example: it will block if no input arrives from an input capture pipe (e.g. mkfifo)) */

    /* to prevent problems, bring the main GUI into "capture mode" right after a successful */
    /* spawn/exec of the capture child, without waiting for any response from it */
    capture_callback_invoke(capture_cb_capture_prepared, cap_session);

    wtap_rec_init(&cap_session->rec, 1514);

    cap_session->wtap = NULL;

    if (capture_opts->show_info) {
        if (cap_data->counts.counts_hash != NULL)
        {
            /* Clean up any previous lists of packet counts */
            g_hash_table_destroy(cap_data->counts.counts_hash);
        }

        cap_data->counts.counts_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
        cap_data->counts.other = 0;
        cap_data->counts.total = 0;

        cap_data->ui.counts = &cap_data->counts;

        capture_info_ui_create(&cap_data->ui, cap_session);
    }

    return true;
}


void
capture_stop(capture_session *cap_session)
{
    ws_message("Capture Stop ...");

    capture_callback_invoke(capture_cb_capture_stopping, cap_session);

    if (!extcap_session_stop(cap_session)) {
        extcap_request_stop(cap_session);
        cap_session->capture_opts->stop_after_extcaps = true;
    } else {
        /* stop the capture child gracefully */
        sync_pipe_stop(cap_session);
    }
}


void
capture_kill_child(capture_session *cap_session)
{
    ws_info("Capture Kill");

    /* kill the capture child */
    sync_pipe_kill(cap_session->fork_child);
}

#ifdef _WIN32
  #define NO_PACKETS_CAPTURED_PLATFORM_HELP \
            "\n\n" \
            "Wireless (Wi-Fi/WLAN):\n" \
            "Try to switch off promiscuous mode in the Capture Options."
#else
  #define NO_PACKETS_CAPTURED_PLATFORM_HELP
#endif

static void
capture_input_no_packets(capture_session *cap_session)
{
    simple_message_box(ESD_TYPE_INFO, NULL,
            "Help about capturing can be found at "
            WS_WIKI_URL("CaptureSetup")
            NO_PACKETS_CAPTURED_PLATFORM_HELP,
            "No packets captured. "
            "As no data was captured, closing the %scapture file.",
            (cf_is_tempfile((capture_file *)cap_session->cf)) ? "temporary " : "");
    cf_close((capture_file *)cap_session->cf);
}

/* We've succeeded in doing a (non real-time) capture; try to read it into a new capture file */
static bool
capture_input_read_all(capture_session *cap_session, bool is_tempfile,
                       bool drops_known, uint32_t drops)
{
    capture_options *capture_opts = cap_session->capture_opts;
    int err;

    /* Capture succeeded; attempt to open the capture file. */
    if (cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err) != CF_OK) {
        /* We're not doing a capture any more, so we don't have a save file. */
        return false;
    }

    /* Set the read filter to NULL. */
    /* XXX - this is odd here; try to put it somewhere where it fits better */
    cf_set_rfcode((capture_file *)cap_session->cf, NULL);

    /* Get the packet-drop statistics.

       XXX - there are currently no packet-drop statistics stored
       in libpcap captures, and that's what we're reading.

       At some point, we will add support in Wiretap to return
       packet-drop statistics for capture file formats that store it,
       and will make "cf_read()" get those statistics from Wiretap.
       We clear the statistics (marking them as "not known") in
       "cf_open()", and "cf_read()" will only fetch them and mark
       them as known if Wiretap supplies them, so if we get the
       statistics now, after calling "cf_open()" but before calling
       "cf_read()", the values we store will be used by "cf_read()".

       If a future libpcap capture file format stores the statistics,
       we'll put them into the capture file that we write, and will
       thus not have to set them here - "cf_read()" will get them from
       the file and use them. */
    if (drops_known) {
        cf_set_drops_known((capture_file *)cap_session->cf, true);

        /* XXX - on some systems, libpcap doesn't bother filling in
           "ps_ifdrop" - it doesn't even set it to zero - so we don't
           bother looking at it.

           Ideally, libpcap would have an interface that gave us
           several statistics - perhaps including various interface
           error statistics - and would tell us which of them it
           supplies, allowing us to display only the ones it does. */
        cf_set_drops((capture_file *)cap_session->cf, drops);
    }

    /* read in the packet data */
    switch (cf_read((capture_file *)cap_session->cf, /*reloading=*/false)) {

        case CF_READ_OK:
        case CF_READ_ERROR:
            /* Just because we got an error, that doesn't mean we were unable
               to read any of the file; we handle what we could get from the
               file. */
            break;

        case CF_READ_ABORTED:
            /* The user asked to abort the read, but that might be to
               restart the capture, so let the caller decide whether
               to exit. */
            //exit_application(0);
            return false;
    }

    /* if we didn't capture even a single packet, report that and
       close the file again */
    if(cap_session->count == 0 && !capture_opts->restart) {
        capture_input_no_packets(cap_session);
    }
    return true;
}

static const char *
cf_open_error_message(int err, char *err_info)
{
    const char *errmsg;
    static char errmsg_errno[1024 + 1];

    if (err < 0) {
        /* Wiretap error. */
        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            /* Seen only when opening a capture file for reading. */
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                "The file \"%%s\" isn't a capture file in a format %s understands.",
                application_flavor_name_proper());
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_UNSUPPORTED:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                "The file \"%%s\" contains record data that %s doesn't support.\n"
                "(%s)", application_flavor_name_proper(),
                err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                "The file \"%%s\" is a capture for a network type that %s doesn't support.",
                application_flavor_name_proper());
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_BAD_FILE:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" appears to be damaged or corrupt.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_CANT_OPEN:
            errmsg = "The file \"%s\" could not be opened for some unknown reason.";
            break;

        case WTAP_ERR_SHORT_READ:
            errmsg = "The file \"%s\" appears to have been cut short"
                " in the middle of a packet or other data.";
            break;

        case WTAP_ERR_DECOMPRESS:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" cannot be decompressed; it may be damaged or corrupt.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_INTERNAL:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "An internal error occurred opening the file \"%%s\".\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" cannot be decompressed; it is compressed in a way that We don't support.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        default:
            snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" could not be opened: %s.",
                       wtap_strerror(err));
            errmsg = errmsg_errno;
            break;
        }
    }
    else
        errmsg = file_open_error_message(err, false);
    return errmsg;
}

/* capture child tells us we have a new (or the first) capture file */
static bool
capture_input_new_file(capture_session *cap_session, char *new_file)
{
    capture_options *capture_opts = cap_session->capture_opts;
    bool is_tempfile;
    int  err;
    char *err_info;
    char *err_msg;

    if(cap_session->state == CAPTURE_PREPARING) {
        ws_message("Capture started");
    }
    ws_message("File: \"%s\"", new_file);

    ws_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

    /* free the old filename */
    if(capture_opts->save_file != NULL) {
        /* we start a new capture file, close the old one (if we had one before). */
        /* (we can only have an open capture file in real_time_mode!) */
        if (((capture_file*)cap_session->cf)->state == FILE_READ_PENDING) {
            capture_callback_invoke(capture_cb_capture_fixed_finished, cap_session);
        } else if (((capture_file*)cap_session->cf)->state != FILE_CLOSED) {
            cap_session->session_will_restart = true;
            capture_callback_invoke(capture_cb_capture_update_finished, cap_session);
            cf_finish_tail((capture_file *)cap_session->cf,
                           &cap_session->rec, &err,
                           &cap_session->frame_dup_cache, cap_session->frame_cksum);
            cf_close((capture_file *)cap_session->cf);
        }
        g_free(capture_opts->save_file);
        is_tempfile = false;
        cf_set_tempfile((capture_file *)cap_session->cf, false);
    } else {
        /* we didn't have a save_file before; must be a tempfile */
        is_tempfile = true;
        cf_set_tempfile((capture_file *)cap_session->cf, true);
    }

    /* save the new filename */
    capture_opts->save_file = g_strdup(new_file);

    /* if we are in real-time mode, open the new file now */
    if(capture_opts->real_time_mode) {
        /* Attempt to open the capture file and set up to read from it. */
        switch(cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
            case CF_OK:
                break;
            case CF_ERROR:
                /* Don't unlink (delete) the save file - leave it around,
                   for debugging purposes. */
                g_free(capture_opts->save_file);
                capture_opts->save_file = NULL;
                return false;
        }
    } else {
        /* A new file, so we don't have any pending packets to read. */
        cap_session->count_pending = 0;
        capture_callback_invoke(capture_cb_capture_prepared, cap_session);
    }

    if(capture_opts->show_info) {
        if (cap_session->wtap != NULL) {
            wtap_close(cap_session->wtap);
        }

        cap_session->wtap = wtap_open_offline(new_file, WTAP_TYPE_AUTO, &err, &err_info, false);
        if (!cap_session->wtap) {
            err_msg = ws_strdup_printf(cf_open_error_message(err, err_info),
                                      new_file);
            ws_warning("capture_input_new_file: %d (%s)", err, err_msg);
            g_free(err_msg);
            return false;
        }
    }

    if(capture_opts->real_time_mode) {
        capture_callback_invoke(capture_cb_capture_update_started, cap_session);
    } else {
        capture_callback_invoke(capture_cb_capture_fixed_started, cap_session);
    }
    cap_session->state = CAPTURE_RUNNING;

    return true;
}

/* new packets arrived */
static void
capture_info_new_packets(int to_read, wtap *wth, info_data_t* cap_info)
{
    int err;
    char *err_info;
    int64_t data_offset;
    wtap_rec rec;

    cap_info->ui.new_packets = to_read;

    /*ws_warning("new packets: %u", to_read);*/

    wtap_rec_init(&rec, 1514);
    while (to_read > 0) {
        wtap_cleareof(wth);
        if (!wtap_read(wth, &rec, &err, &err_info, &data_offset)) {
            /* Read failed. capture_input_new_packets should handle
             * aborting the capture, etc. if necessary. */
            break;
        }
        if (rec.rec_type == REC_TYPE_PACKET) {
            capture_packet_info_t cpinfo;

            /* Setup the capture packet structure */
            cpinfo.counts = cap_info->counts.counts_hash;

            cap_info->counts.total++;
            if (!try_capture_dissector("wtap_encap",
                                        rec.rec_header.packet_header.pkt_encap,
                                        ws_buffer_start_ptr(&rec.data),
                                        0,
                                        rec.rec_header.packet_header.caplen,
                                        &cpinfo,
                                        &rec.rec_header.packet_header.pseudo_header))
                cap_info->counts.other++;

            /*ws_warning("new packet");*/
            to_read--;
        }
        wtap_rec_reset(&rec);
    }
    wtap_rec_cleanup(&rec);

    capture_info_ui_update(&cap_info->ui);
}

/* capture child tells us we have new packets to read */
static void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
    capture_options *capture_opts = cap_session->capture_opts;
    int  err;

    ws_assert(capture_opts->save_file);

    if(capture_opts->real_time_mode) {
        if (((capture_file*)cap_session->cf)->state == FILE_READ_PENDING) {
            /* Attempt to open the capture file and set up to read from it. */
            switch (cf_open((capture_file*)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, cf_is_tempfile((capture_file*)cap_session->cf), &err)) {
            case CF_OK:
                break;
            case CF_ERROR:
                /* Don't unlink (delete) the save file - leave it around,
                   for debugging purposes. */
                g_free(capture_opts->save_file);
                capture_opts->save_file = NULL;
                capture_kill_child(cap_session);
            }
            capture_callback_invoke(capture_cb_capture_update_started, cap_session);
        }
        /* Read from the capture file the number of records the child told us it added. */
        to_read += cap_session->count_pending;
        cap_session->count_pending = 0;
        switch (cf_continue_tail((capture_file *)cap_session->cf, to_read,
                                 &cap_session->rec, &err,
                                 &cap_session->frame_dup_cache, cap_session->frame_cksum)) {

            case CF_READ_OK:
            case CF_READ_ERROR:
                /* Just because we got an error, that doesn't mean we were unable
                   to read any of the file; we handle what we could get from the
                   file.

                   XXX - abort on a read error? */
                capture_callback_invoke(capture_cb_capture_update_continue, cap_session);
                break;

            case CF_READ_ABORTED:
                /* Kill the child capture process; the user wants to exit, and we
                   shouldn't just leave it running. */
                capture_kill_child(cap_session);
                break;
        }
    } else {
        cf_fake_continue_tail((capture_file *)cap_session->cf);
        cap_session->count_pending += to_read;

        capture_callback_invoke(capture_cb_capture_fixed_continue, cap_session);
    }

    if(cap_session->wtap)
        capture_info_new_packets(to_read, cap_session->wtap, cap_session->cap_data_info);
}


/* Capture child told us how many dropped packets it counted.
 */
static void
capture_input_drops(capture_session *cap_session, uint32_t dropped, const char* interface_name)
{
    if (interface_name != NULL) {
        ws_info("%u packet%s dropped from %s", dropped, plurality(dropped, "", "s"), interface_name);
    } else {
        ws_info("%u packet%s dropped", dropped, plurality(dropped, "", "s"));
    }

    ws_assert(cap_session->state == CAPTURE_RUNNING);

    cf_set_drops_known((capture_file *)cap_session->cf, true);
    cf_set_drops((capture_file *)cap_session->cf, dropped);
}


/* Capture child told us that an error has occurred while starting/running
   the capture.
   The buffer we're handed has *two* null-terminated strings in it - a
   primary message and a secondary message, one right after the other.
   The secondary message might be a null string.
 */
static void
capture_input_error(capture_session *cap_session _U_, char *error_msg,
                    char *secondary_error_msg)
{
    char *safe_error_msg;
    char *safe_secondary_error_msg;

    /* The primary message might be an empty string, e.g. when the error was
     * from extcap. (The extcap stderr is gathered when the session closes
     * and printed in capture_input_closed below.) */
    if (*error_msg != '\0') {
        ws_message("Error message from child: \"%s\", \"%s\"", error_msg, secondary_error_msg);
    }

    ws_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

    safe_error_msg = simple_dialog_format_message(error_msg);
    if (secondary_error_msg != NULL && *secondary_error_msg != '\0') {
        /* We have both primary and secondary messages. */
        safe_secondary_error_msg = simple_dialog_format_message(secondary_error_msg);
        simple_message_box(ESD_TYPE_ERROR, NULL, safe_secondary_error_msg,
                           "%s", safe_error_msg);
        g_free(safe_secondary_error_msg);
    } else {
        /* We have only a primary message. */
        simple_message_box(ESD_TYPE_ERROR, NULL, NULL, "%s", safe_error_msg);
    }
    g_free(safe_error_msg);

    /* the capture child will close the sync_pipe if required, nothing to do for now */
}

/* Capture child told us that an error has occurred while parsing a
   capture filter when starting/running the capture.
 */
static void
capture_input_cfilter_error(capture_session *cap_session, unsigned i,
                            const char *error_message)
{
    capture_options *capture_opts = cap_session->capture_opts;
    dfilter_t *rfcode = NULL;
    char *safe_cfilter;
    char *safe_descr;
    char *safe_cfilter_error_msg;
    const char *secondary_error_msg;
    interface_options *interface_opts;

    ws_message("Capture filter error message from child: \"%s\"", error_message);

    ws_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);
    ws_assert(i < capture_opts->ifaces->len);

    interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
    safe_cfilter = simple_dialog_format_message(interface_opts->cfilter);
    safe_descr = simple_dialog_format_message(interface_opts->descr);
    safe_cfilter_error_msg = simple_dialog_format_message(error_message);
    /* Did the user try a display filter? */
    if (dfilter_compile(interface_opts->cfilter, &rfcode, NULL) && rfcode != NULL) {
        secondary_error_msg =
                "That string looks like a valid display filter.\n"
                "\n"
                "Note that display filters and capture filters don't have the same syntax,\n"
                "so you can't use most display filter expressions as capture filters.\n"
                "\n"
                "See the User's Guide for a description of the capture filter syntax.";
    } else {
        secondary_error_msg =
                "See the User's Guide for a description of the capture filter syntax.";
    }
    simple_message_box(ESD_TYPE_ERROR, NULL,
                       secondary_error_msg,
                       "\"%s\" is not a valid capture filter for interface \"%s\" (%s).",
                       safe_cfilter, safe_descr, safe_cfilter_error_msg);
    g_free(safe_cfilter_error_msg);
    g_free(safe_descr);
    g_free(safe_cfilter);

    /* the capture child will close the sync_pipe if required, nothing to do for now */
}

/* capture child closed its side of the pipe, do the required cleanup */
static void
capture_input_closed(capture_session *cap_session, char *msg)
{
    capture_options *capture_opts = cap_session->capture_opts;
    int  err;

    ws_message("Capture stopped.");
    ws_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

    if (msg != NULL && msg[0] != '\0') {
        ESD_TYPE_E dlg_type = ESD_TYPE_ERROR;
        if (strstr(msg, " WARNING] ")) {
            dlg_type = ESD_TYPE_WARN;
        }
        /*
         * ws_log prefixes log messages with a timestamp delimited by " -- " and possibly
         * a function name delimited by "(): ". Log it to sterr, but omit it in the UI.
         */
        char **msg_lines = g_strsplit(msg, "\n", 0);
        GString* gui_msg = g_string_new(NULL);

        for (char **line = msg_lines; *line != NULL; line++) {
            if (gui_msg->len > 0) {
                g_string_append(gui_msg, "\n");
            }
            char *plain_msg = strstr(*line, "(): ");
            if (plain_msg != NULL) {
                plain_msg += strlen("(): ");
            } else if ((plain_msg = strstr(*line, " -- ")) != NULL) {
                plain_msg += strlen(" -- ");
            } else {
                plain_msg = *line;
            }
            g_string_append(gui_msg, plain_msg);
        }
        ws_warning("%s", msg);
        simple_dialog(dlg_type, ESD_BTN_OK, "%s", gui_msg->str);
        g_string_free(gui_msg, TRUE);
        g_strfreev(msg_lines);
    }

    wtap_rec_cleanup(&cap_session->rec);
    if(cap_session->state == CAPTURE_PREPARING) {
        /* We started the capture child, but we didn't manage to start
           the capture process; note that the attempt to start it
           failed. */
        capture_callback_invoke(capture_cb_capture_failed, cap_session);
    } else {
        /* We started a capture; process what's left of the capture file if
           we were in "update list of packets in real time" mode, or process
           all of it if we weren't. */
        if(((capture_file*)cap_session->cf)->state == FILE_READ_IN_PROGRESS) {
            cf_read_status_t status;

            /* Read what remains of the capture file. */
            status = cf_finish_tail((capture_file *)cap_session->cf,
                                    &cap_session->rec, &err,
                                    &cap_session->frame_dup_cache, cap_session->frame_cksum);

            // The real-time reading of the pcap is done. Now we can clear the
            // dup-frame cache, if present. But check that we actually have
            // data structures to clear (by checking frame-checksum); the user
            // could have changed the preference *during* the live capture.
            if (cap_session->frame_cksum != NULL) {
                fifo_string_cache_free(&cap_session->frame_dup_cache);
                g_checksum_free(cap_session->frame_cksum);
                cap_session->frame_cksum = NULL;
            }

            /* Tell the GUI we are not doing a capture any more.
               Must be done after the cf_finish_tail(), so file lengths are
               correctly displayed */
            cap_session->session_will_restart = false;
            capture_callback_invoke(capture_cb_capture_update_finished, cap_session);

            /* Finish the capture. */
            switch (status) {

                case CF_READ_OK:
                    if (cap_session->count == 0 && !capture_opts->restart) {
                        capture_input_no_packets(cap_session);
                    }
                    break;
                case CF_READ_ERROR:
                    /* Just because we got an error, that doesn't mean we were unable
                       to read any of the file; we handle what we could get from the
                       file. */
                    break;

                case CF_READ_ABORTED:
                    /* The user asked to abort the read, but that might be to
                       restart the capture, so let the caller decide whether
                       to exit. */
                    //exit_application(0);
                    break;
            }
        } else if (((capture_file*)cap_session->cf)->state == FILE_READ_PENDING) {
            /* first of all, we are not doing a capture any more */
            capture_callback_invoke(capture_cb_capture_fixed_finished, cap_session);

            /* this is a normal mode capture and if no error happened, read in the capture file data */
            if(capture_opts->save_file != NULL) {
                capture_input_read_all(cap_session, cf_is_tempfile((capture_file *)cap_session->cf),
                        cf_get_drops_known((capture_file *)cap_session->cf), cf_get_drops((capture_file *)cap_session->cf));
            }
        } else {
            /* First, tell the GUI we are not capturing nor stopping a capture
               anymore. We need to do this if we're aborting the capture but
               not quitting the program (e.g., restarting the capture.) */
            capture_callback_invoke(capture_cb_capture_update_finished, cap_session);

            if (cap_session->frame_cksum != NULL) {
                fifo_string_cache_free(&cap_session->frame_dup_cache);
                g_checksum_free(cap_session->frame_cksum);
                cap_session->frame_cksum = NULL;
            }

            cf_close((capture_file *)cap_session->cf);
        }
    }

    capture_info_ui_destroy(&cap_session->cap_data_info->ui);
    if(cap_session->wtap) {
        wtap_close(cap_session->wtap);
        cap_session->wtap = NULL;
    }

    cap_session->state = CAPTURE_STOPPED;

    /* if we couldn't open a capture file, there's nothing more for us to do */
    if(capture_opts->save_file == NULL) {
        cf_close((capture_file *)cap_session->cf);
        return;
    }

    /* does the user wants to restart the current capture? */
    if(capture_opts->restart) {
        capture_opts->restart = false;

        /* If we have a ring buffer, the original save file has been overwritten
           with the "ring filename".  Restore it before starting again */
        if ((capture_opts->multi_files_on) && (capture_opts->orig_save_file != NULL)) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = g_strdup(capture_opts->orig_save_file);
        }

        /* If it was a tempfile, throw away the old filename (so it will become a tempfile again) */
        if (cf_is_tempfile((capture_file *)cap_session->cf)) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
        }
    } else {

        /* If we're in multiple file mode, restore the original save file
           name (template), so that it will be used if a new capture is started
           without opening the Capture Options dialog. Any files we just wrote
           won't get overwritten. If we set it to NULL, a tempfile name would
           be used, but that doesn't work in multiple file mode - we could turn
           off multiple file mode instead, but that would change the behavior
           if the Capture Options dialog is re-opened. */
        if ((capture_opts->multi_files_on) && (capture_opts->orig_save_file != NULL)) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = g_strdup(capture_opts->orig_save_file);
        } else {
            /* We're not doing a capture any more, so we don't have a save file.
               If a new capture is started without opening the Capture Options
               dialog (Start button or double-clicking on an interface from
               the welcome screen), we'll use a tempfile. Thus if our current
               capture is to a permanent file, we won't overwrite it. */
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
        }
    }
}

if_stat_cache_t *
capture_stat_start(capture_options *capture_opts)
{
    int stat_fd;
    ws_process_id fork_child;
    char *msg;
    if_stat_cache_t *sc = g_new0(if_stat_cache_t, 1);
    if_stat_cache_item_t *sc_item;
    unsigned i;
    interface_t *device;

    sc->stat_fd = -1;
    sc->fork_child = WS_INVALID_PID;

    /* Fire up dumpcap. */
    /*
     * XXX - on systems with BPF, the number of BPF devices limits the
     * number of devices on which you can capture simultaneously.
     *
     * This means that
     *
     *    1) this might fail if you run out of BPF devices
     *
     * and
     *
     *    2) opening every interface could leave too few BPF devices
     *       for *other* programs.
     *
     * It also means the system could end up getting a lot of traffic
     * that it has to pass through the networking stack and capture
     * mechanism, so opening all the devices and presenting packet
     * counts might not always be a good idea.
     */
    if (sync_interface_stats_open(&stat_fd, &fork_child, NULL, &msg, NULL) == 0) {
        sc->stat_fd = stat_fd;
        sc->fork_child = fork_child;

        /* Initialize the cache */
        for (i = 0; i < capture_opts->all_ifaces->len; i++) {
            device = &g_array_index(capture_opts->all_ifaces, interface_t, i);
            if (device->if_info.type != IF_PIPE && device->if_info.type != IF_EXTCAP) {
                sc_item = g_new0(if_stat_cache_item_t, 1);
                ws_assert(device->if_info.name);
                sc_item->name = g_strdup(device->if_info.name);
                sc->cache_list = g_list_prepend(sc->cache_list, sc_item);
            }
        }
    } else {
        ws_warning("%s", msg);
        g_free(msg); /* XXX: should we display this to the user via the GUI? */
    }
    return sc;
}

if_stat_cache_t *
capture_interface_stat_start(capture_options *capture_opts _U_, GList **if_list)
{
    int stat_fd;
    ws_process_id fork_child;
    char *msg;
    if_stat_cache_t *sc = g_new0(if_stat_cache_t, 1);
    if_stat_cache_item_t *sc_item;
    char *data = NULL;

    sc->stat_fd = -1;
    sc->fork_child = WS_INVALID_PID;

    /* Fire up dumpcap. */
    /*
     * XXX - on systems with BPF, the number of BPF devices limits the
     * number of devices on which you can capture simultaneously.
     *
     * This means that
     *
     *    1) this might fail if you run out of BPF devices
     *
     * and
     *
     *    2) opening every interface could leave too few BPF devices
     *       for *other* programs.
     *
     * It also means the system could end up getting a lot of traffic
     * that it has to pass through the networking stack and capture
     * mechanism, so opening all the devices and presenting packet
     * counts might not always be a good idea.
     */
    /* XXX - We should use capture_opts to control whether we request
     * the monitor_mode version of the supported link-types for interfaces.
     */
    int status;
    iface_mon_enable(false);
    status = sync_interface_stats_open(&stat_fd, &fork_child, &data, &msg, NULL);
    iface_mon_enable(true);
    /* In order to initialize the stat cache (below), we need to have
     * filled in capture_opts->all_ifaces
     *
     * Note that the operation above can return a failed status but
     * valid data, e.g. if dumpcap returns an interface list but none
     * of them have permission to do a capture.
     */
    int err = 0;
    char *err_msg = NULL;
    *if_list = deserialize_interface_list(data, &err, &err_msg);
    if (err != 0) {
        ws_info("%s", err_msg);
        g_free(err_msg);
    }
    if (status == 0) {
        sc->stat_fd = stat_fd;
        sc->fork_child = fork_child;

        /* Initialize the cache */
        for (GList *if_entry = *if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
            if_info_t *if_info = (if_info_t*)if_entry->data;
            /* We just got this list from dumpcap so it shouldn't
             * contain stdin, pipes, extcaps, or remote interfaces
             * list. We could test if_info->type and the name to
             * exclude those types from the cache anyway, though.
             */
            sc_item = g_new0(if_stat_cache_item_t, 1);
            ws_assert(if_info->name);
            sc_item->name = g_strdup(if_info->name);
            sc->cache_list = g_list_prepend(sc->cache_list, sc_item);
        }
    } else if (status == WS_EXIT_NO_INTERFACES) {
        /*
            * No interfaces were found.  If that's not the
            * result of an error when fetching the local
            * interfaces, let the user know.
            */
        ws_info("%s", msg);
        g_free(msg); /* XXX: should we display this to the user via the GUI? */
    } else {
        ws_warning("%s", msg);
        g_free(msg); /* XXX: should we display this to the user via the GUI? */
    }

#ifdef HAVE_PCAP_REMOTE
    *if_list = append_remote_list(*if_list);
#endif

    *if_list = append_extcap_interface_list(*if_list);
    return sc;
}

#define MAX_STAT_LINE_LEN 500

static void
capture_stat_cache_update(if_stat_cache_t *sc)
{
    char stat_line[MAX_STAT_LINE_LEN] = "";
    char **stat_parts;
    GList *sc_entry;
    if_stat_cache_item_t *sc_item;

    if (!sc || sc->fork_child == WS_INVALID_PID) {
        return;
    }

    while (sync_pipe_gets_nonblock(sc->stat_fd, stat_line, MAX_STAT_LINE_LEN) > 0) {
        g_strstrip(stat_line);
        stat_parts = g_strsplit(stat_line, "\t", 3);
        if (stat_parts[0] == NULL || stat_parts[1] == NULL ||
                stat_parts[2] == NULL) {
            g_strfreev(stat_parts);
            continue;
        }
        for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
            sc_item = (if_stat_cache_item_t *)sc_entry->data;
            if (strcmp(sc_item->name, stat_parts[0]) == 0) {
                sc_item->ps.ps_recv = (u_int) strtoul(stat_parts[1], NULL, 10);
                sc_item->ps.ps_drop = (u_int) strtoul(stat_parts[2], NULL, 10);
            }
        }
        g_strfreev(stat_parts);
    }
}

bool
capture_stats(if_stat_cache_t *sc, char *ifname, struct pcap_stat *ps)
{
    GList *sc_entry;
    if_stat_cache_item_t *sc_item;

    if (!sc || sc->fork_child == WS_INVALID_PID || !ifname || !ps) {
        return false;
    }

    capture_stat_cache_update(sc);
    for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
        sc_item = (if_stat_cache_item_t *)sc_entry->data;
        if (strcmp(sc_item->name, ifname) == 0) {
            memcpy(ps, &sc_item->ps, sizeof(struct pcap_stat));
            return true;
        }
    }
    return false;
}

void
capture_stat_stop(if_stat_cache_t *sc)
{
    GList *sc_entry;
    if_stat_cache_item_t *sc_item;
    int ret;
    char *msg;

    if (!sc) {
        return;
    }

    if (sc->fork_child != WS_INVALID_PID) {
        ret = sync_interface_stats_close(&sc->stat_fd, &sc->fork_child, &msg);
        if (ret == -1) {
            /* XXX - report failure? */
            g_free(msg);
        }
    }

    for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
        sc_item = (if_stat_cache_item_t *)sc_entry->data;
        g_free(sc_item->name);
        g_free(sc_item);
    }
    g_list_free(sc->cache_list);
    g_free(sc);
}

/* Initialize a capture session for our callbacks. */
void
capture_input_init(capture_session *cap_session, capture_file *cf)
{
    capture_session_init(cap_session, cf,
                         capture_input_new_file, capture_input_new_packets,
                         capture_input_drops, capture_input_error,
                         capture_input_cfilter_error, capture_input_closed);
}
#endif /* HAVE_LIBPCAP */
