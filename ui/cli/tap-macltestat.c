/* tap-macltestat.c
 * Copyright 2011 Martin Mathieson
 *
 * Used for LTE and NR MAC PDUs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-mac-lte.h>

void register_tap_listener_mac_lte_stat(void);

/**********************************************/
/* Table column identifiers and title strings */

enum {
    RAT_COLUMN,
    RNTI_COLUMN,
    RNTI_TYPE_COLUMN,
    UEID_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    UL_BW_COLUMN,
    UL_PADDING_PERCENT_COLUMN,
    UL_RETX_FRAMES_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    DL_BW_COLUMN,
    DL_PADDING_PERCENT_COLUMN,
    DL_CRC_FAILED_COLUMN,
    DL_RETX_FRAMES_COLUMN,
    NUM_UE_COLUMNS
};


static const char *ue_titles[] = { "RAT", " RNTI", "  Type", "UEId",
                                    "UL Frames", "UL Bytes", "UL Mb/sec", " UL Pad %", "UL ReTX",
                                    "DL Frames", "DL Bytes", "DL Mb/sec", " DL Pad %", "DL CRC Fail", "DL ReTX"};


/* Stats for one UE */
typedef struct mac_lte_nr_row_data {
    /* Key for matching this row */
    uint8_t  rat;
    uint16_t rnti;
    uint8_t  rnti_type;
    uint16_t ueid;

    bool is_predefined_data;

    uint32_t UL_frames;
    uint32_t UL_raw_bytes;   /* all bytes */
    uint32_t UL_total_bytes; /* payload */
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    uint32_t UL_padding_bytes;
    uint32_t UL_CRC_errors;
    uint32_t UL_retx_frames;

    uint32_t DL_frames;
    uint32_t DL_raw_bytes;   /* all bytes */
    uint32_t DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    uint32_t DL_padding_bytes;

    uint32_t DL_CRC_failures;
    uint32_t DL_retx_frames;

} mac_lte_nr_row_data;


/* One row/UE list item in the UE table */
typedef struct mac_lte_ep {
    struct mac_lte_ep *next;
    struct mac_lte_nr_row_data stats;
} mac_lte_ep_t;


/* Common channel stats (i.e. independent of UEs) */
typedef struct mac_lte_common_stats {
    uint32_t all_frames;
    uint32_t mib_frames;
    uint32_t sib_frames;
    uint32_t sib_bytes;
    uint32_t pch_frames;
    uint32_t pch_bytes;
    uint32_t pch_paging_ids;
    uint32_t rar_frames;
    uint32_t rar_entries;

    uint16_t max_ul_ues_in_tti;
    uint16_t max_dl_ues_in_tti;
} mac_lte_common_stats;


/* Top-level struct for MAC LTE statistics */
typedef struct mac_lte_nr_stat_t {
    /* Common stats */
    mac_lte_common_stats common_stats;

    /* Keep track of unique rntis & ueids. N.B. only used for counting number of UEs - not for lookup */
    uint8_t used_ueids[65535];
    uint8_t used_rntis[65535];
    uint16_t number_of_ueids;
    uint16_t number_of_rntis;

    /* List of UE entries */
    mac_lte_ep_t  *ep_list;
} mac_lte_nr_stat_t;


/* Reset the statistics window */
static void
mac_lte_stat_reset(void *phs)
{
    mac_lte_nr_stat_t *mac_lte_stat = (mac_lte_nr_stat_t *)phs;
    mac_lte_ep_t *list = mac_lte_stat->ep_list;

    /* Reset counts of unique ueids & rntis */
    memset(mac_lte_stat->used_ueids, 0, 65535);
    mac_lte_stat->number_of_ueids = 0;
    memset(mac_lte_stat->used_rntis, 0, 65535);
    mac_lte_stat->number_of_rntis = 0;

    /* Zero common stats */
    memset(&(mac_lte_stat->common_stats), 0, sizeof(mac_lte_common_stats));

    while (list != NULL) {
        mac_lte_ep_t *ptr = list;
        list = list->next;
        g_free(ptr);
    }
    mac_lte_stat->ep_list = NULL;
}


/* Free memory used by tap */
static void
mac_lte_stat_finish(void *phs)
{
    mac_lte_nr_stat_t *mac_lte_stat = (mac_lte_nr_stat_t *)phs;
    mac_lte_ep_t *list = mac_lte_stat->ep_list;

    while (list != NULL) {
        mac_lte_ep_t *ptr = list;
        list = list->next;
        g_free(ptr);
    }

    g_free(mac_lte_stat);
}


/* Allocate a mac_lte_ep_t struct to store info for new UE */
static mac_lte_ep_t *alloc_mac_lte_ep(const struct mac_3gpp_tap_info *si, packet_info *pinfo _U_)
{
    mac_lte_ep_t *ep;

    if (!si) {
        return NULL;
    }

    if (!(ep = g_new(mac_lte_ep_t, 1))) {
        return NULL;
    }

    /* Copy SI data into ep->stats */
    ep->stats.rnti = si->rnti;
    ep->stats.rnti_type = si->rntiType;
    ep->stats.ueid = si->ueid;

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
    ep->stats.UL_raw_bytes = 0;
    ep->stats.UL_padding_bytes = 0;

    ep->stats.DL_total_bytes = 0;
    ep->stats.DL_raw_bytes = 0;
    ep->stats.DL_padding_bytes = 0;

    ep->stats.UL_CRC_errors = 0;
    ep->stats.DL_CRC_failures = 0;
    ep->stats.UL_retx_frames = 0;
    ep->stats.DL_retx_frames = 0;

    ep->next = NULL;

    return ep;
}


/* Update counts of unique rntis & ueids */
static void update_ueid_rnti_counts(uint16_t rnti, uint16_t ueid, mac_lte_nr_stat_t *hs)
{
    if (hs->number_of_ueids == 65535 || hs->number_of_rntis == 65535) {
        /* Arrays are already full! */
        return;
    }

    if (!hs->used_ueids[ueid]) {
        hs->used_ueids[ueid] = true;
        hs->number_of_ueids++;
    }
    if (!hs->used_rntis[rnti]) {
        hs->used_rntis[rnti] = true;
        hs->number_of_rntis++;
    }
}


/* Process stat struct for a MAC LTE frame */
static tap_packet_status
mac_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                    const void *phi, tap_flags_t flags _U_)
{
    /* Get reference to stat instance */
    mac_lte_nr_stat_t *hs = (mac_lte_nr_stat_t*)phs;
    mac_lte_ep_t *tmp = NULL, *te = NULL;
    int i;

    /* Cast tap info struct */
    const struct mac_3gpp_tap_info *si = (const struct mac_3gpp_tap_info *)phi;

    if (!hs) {
        return TAP_PACKET_DONT_REDRAW;
    }

    hs->common_stats.all_frames++;

    /* For common channels, just update global counters */
    switch (si->rntiType) {
        case P_RNTI:
            hs->common_stats.pch_frames++;
            hs->common_stats.pch_bytes += si->single_number_of_bytes;
            hs->common_stats.pch_paging_ids += si->number_of_paging_ids;
            return TAP_PACKET_REDRAW;
        case SI_RNTI:
            hs->common_stats.sib_frames++;
            hs->common_stats.sib_bytes += si->single_number_of_bytes;
            return TAP_PACKET_REDRAW;
        case NO_RNTI:
            hs->common_stats.mib_frames++;
            return TAP_PACKET_REDRAW;
        case RA_RNTI:
            hs->common_stats.rar_frames++;
            hs->common_stats.rar_entries += si->number_of_rars;
            return TAP_PACKET_REDRAW;
        case C_RNTI:
        case SPS_RNTI:
            /* Drop through for per-UE update */
            break;

        default:
            /* Error */
            return TAP_PACKET_DONT_REDRAW;
    }

    /* Check/update max UEs/tti counter */
    switch (si->direction) {
        case DIRECTION_UPLINK:
            hs->common_stats.max_ul_ues_in_tti =
                MAX(hs->common_stats.max_ul_ues_in_tti, si->ueInTTI);
            break;
        case DIRECTION_DOWNLINK:
            hs->common_stats.max_dl_ues_in_tti =
                MAX(hs->common_stats.max_dl_ues_in_tti, si->ueInTTI);
            break;
    }

    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        /* Allocate new list */
        hs->ep_list = alloc_mac_lte_ep(si, pinfo);
        /* Make it the first/only entry */
        te = hs->ep_list;

        /* Update counts of unique ueids & rntis */
        update_ueid_rnti_counts(si->rnti, si->ueid, hs);
    } else {
        /* Look among existing rows for this RNTI */
        /* TODO: with different data structures, could avoid this linear search */
        for (tmp = hs->ep_list; tmp != NULL; tmp = tmp->next) {
            /* Match only by RAT, RNTI and UEId together */
            if ((tmp->stats.rat  == si->rat) &&
                (tmp->stats.rnti == si->rnti) &&
                (tmp->stats.ueid == si->ueid)) {
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one now */
        if (te == NULL) {
            if ((te = alloc_mac_lte_ep(si, pinfo))) {
                /* Add new item to end of list */
                mac_lte_ep_t *p = hs->ep_list;
                while (p->next) {
                    p = p->next;
                }
                p->next = te;
                te->next = NULL;

                /* Update counts of unique ueids & rntis */
                update_ueid_rnti_counts(si->rnti, si->ueid, hs);
            }
        }
    }

    /* Really should have a row pointer by now */
    if (!te) {
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Update entry with details from si */
    te->stats.rat = si->rat;
    te->stats.rnti = si->rnti;
    te->stats.is_predefined_data = si->isPredefinedData;

    /* Uplink */
    if (si->direction == DIRECTION_UPLINK) {
        if (si->isPHYRetx) {
            te->stats.UL_retx_frames++;
            return TAP_PACKET_REDRAW;
        }

        if (si->crcStatusValid && (si->crcStatus != crc_success)) {
            te->stats.UL_CRC_errors++;
            return TAP_PACKET_REDRAW;
        }

        /* Update time range */
        if (te->stats.UL_frames == 0) {
            te->stats.UL_time_start = si->mac_time;
        }
        te->stats.UL_time_stop = si->mac_time;

        te->stats.UL_frames++;

        te->stats.UL_raw_bytes += si->raw_length;
        te->stats.UL_padding_bytes += si->padding_bytes;

        if (si->isPredefinedData) {
            te->stats.UL_total_bytes += si->single_number_of_bytes;
        }
        else {
            for (i = 0; i < MAC_3GPP_DATA_LCID_COUNT_MAX; i++) {
                te->stats.UL_total_bytes += si->bytes_for_lcid[i];
            }
        }
    }

    /* Downlink */
    else {
        if (si->isPHYRetx) {
            te->stats.DL_retx_frames++;
            return TAP_PACKET_REDRAW;
        }

        if (si->crcStatusValid && (si->crcStatus != crc_success)) {
            te->stats.DL_CRC_failures++;
            return TAP_PACKET_REDRAW;
        }

        /* Update time range */
        if (te->stats.DL_frames == 0) {
            te->stats.DL_time_start = si->mac_time;
        }
        te->stats.DL_time_stop = si->mac_time;

        te->stats.DL_frames++;

        te->stats.DL_raw_bytes += si->raw_length;
        te->stats.DL_padding_bytes += si->padding_bytes;

        if (si->isPredefinedData) {
            te->stats.DL_total_bytes += si->single_number_of_bytes;
        }
        else {
            for (i = 0; i < MAC_3GPP_DATA_LCID_COUNT_MAX; i++) {
                te->stats.DL_total_bytes += si->bytes_for_lcid[i];
            }
        }

    }

    return TAP_PACKET_REDRAW;
}


/* Calculate and return a bandwidth figure, in Mbs */
static float calculate_bw(nstime_t *start_time, nstime_t *stop_time, uint32_t bytes)
{
    /* Can only calculate bandwidth if have time delta */
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        float elapsed_ms = (((float)stop_time->secs -  (float)start_time->secs) * 1000) +
                           (((float)stop_time->nsecs - (float)start_time->nsecs) / 1000000);

        /* Only really meaningful if have a few frames spread over time...
           For now at least avoid dividing by something very close to 0.0 */
        if (elapsed_ms < 2.0) {
           return 0.0f;
        }
        return ((bytes * 8) / elapsed_ms) / 1000;
    }
    else {
        return 0.0f;
    }
}



/* Output the accumulated stats */
static void
mac_lte_stat_draw(void *phs)
{
    int i;
    uint16_t number_of_ues = 0;

    /* Deref the struct */
    mac_lte_nr_stat_t *hs = (mac_lte_nr_stat_t*)phs;
    mac_lte_ep_t *list = hs->ep_list, *tmp = 0;

    /* System data */
    printf("System data:\n");
    printf("============\n");
    printf("Max UL UEs/TTI: %u     Max DL UEs/TTI: %u\n\n",
           hs->common_stats.max_ul_ues_in_tti, hs->common_stats.max_dl_ues_in_tti);

    /* Common channel data */
    printf("Common channel data:\n");
    printf("====================\n");
    printf("MIBs: %u    ", hs->common_stats.mib_frames);
    printf("SIB Frames: %u    ", hs->common_stats.sib_frames);
    printf("SIB Bytes: %u    ", hs->common_stats.sib_bytes);
    printf("PCH Frames: %u    ", hs->common_stats.pch_frames);
    printf("PCH Bytes: %u    ", hs->common_stats.pch_bytes);
    printf("PCH Paging IDs: %u    ", hs->common_stats.pch_paging_ids);
    printf("RAR Frames: %u    ", hs->common_stats.rar_frames);
    printf("RAR Entries: %u\n\n", hs->common_stats.rar_entries);


    /* Per-UE table entries */

    /* Set title to show how many UEs in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    printf("UL/DL-SCH data (%u entries - %u unique RNTIs, %u unique UEIds):\n",
           number_of_ues, hs->number_of_rntis, hs->number_of_ueids);
    printf("==================================================================\n");

    /* Show column titles */
    for (i=0; i < NUM_UE_COLUMNS; i++) {
        printf("%s  ", ue_titles[i]);
    }
    printf("\n");

    /* Write a row for each UE */
    for (tmp = list; tmp; tmp=tmp->next) {
        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&tmp->stats.UL_time_start,
                                   &tmp->stats.UL_time_stop,
                                   tmp->stats.UL_total_bytes);
        float DL_bw = calculate_bw(&tmp->stats.DL_time_start,
                                   &tmp->stats.DL_time_stop,
                                   tmp->stats.DL_total_bytes);

        printf("%s %5u %7s %5u %10u %9u %10f %10f %8u %10u %9u %10f %10f %12u %8u\n",
               (tmp->stats.rat == MAC_RAT_LTE) ? "LTE " : "NR  ",
               tmp->stats.rnti,
               (tmp->stats.rnti_type == C_RNTI) ? "C-RNTI" : "SPS-RNTI",
               tmp->stats.ueid,
               tmp->stats.UL_frames,
               tmp->stats.UL_total_bytes,
               UL_bw,
               tmp->stats.UL_raw_bytes ?
                                    (((float)tmp->stats.UL_padding_bytes / (float)tmp->stats.UL_raw_bytes) * 100.0) :
                                    0.0,
               tmp->stats.UL_retx_frames,
               tmp->stats.DL_frames,
               tmp->stats.DL_total_bytes,
               DL_bw,
               tmp->stats.DL_raw_bytes ?
                                    (((float)tmp->stats.DL_padding_bytes / (float)tmp->stats.DL_raw_bytes) * 100.0) :
                                    0.0,
               tmp->stats.DL_CRC_failures,
               tmp->stats.DL_retx_frames);
    }
}

/* Create a new MAC LTE stats struct */
static bool mac_lte_stat_init(const char *opt_arg, void *userdata _U_)
{
    mac_lte_nr_stat_t    *hs;
    const char    *filter = NULL;
    GString       *error_string;

    /* Check for a filter string */
    if (strncmp(opt_arg, "mac-3gpp,stat,", 14) == 0) {
        /* Skip those characters from filter to display */
        filter = opt_arg + 14;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create struct */
    hs = g_new0(mac_lte_nr_stat_t, 1);
    hs->ep_list = NULL;

    error_string = register_tap_listener("mac-3gpp", hs,
                                         filter, TL_REQUIRES_NOTHING,
                                         mac_lte_stat_reset,
                                         mac_lte_stat_packet,
                                         mac_lte_stat_draw,
                                         mac_lte_stat_finish);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        return false;
    }

    return true;
}

static stat_tap_ui mac_lte_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "mac-3gpp,stat",
    mac_lte_stat_init,
    0,
    NULL
};

/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_mac_lte_stat(void)
{
    register_stat_tap_ui(&mac_lte_stat_ui, NULL);
}
