/* tap_camelsrt.c
 * CAMEL Service Response Time statistics for tshark
 * Copyright 2006 Florent Drouin (based on tap_h225rassrt.c from Lars Roland)
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

#include "epan/packet.h"
#include <epan/tap.h>
#include "epan/value_string.h"
#include "epan/asn1.h"
#include "epan/dissectors/packet-camel.h"
#include "epan/dissectors/packet-tcap.h"
#include "epan/timestats.h"
#include "epan/stat_tap_ui.h"

#include <wsutil/cmdarg_err.h>

void register_tap_listener_camelsrt(void);

/* Save the first NUM_RAS_STATS stats in the array to calculate percentile */
#define NUM_RAS_STATS 500000

/* Number of couple message Request/Response to analyze*/
#define NB_CRITERIA 7

/* used to keep track of the statistics for an entire program interface */
struct camelsrt_t {
  uint32_t count[NB_CAMELSRT_CATEGORY];
  timestat_t stats[NB_CAMELSRT_CATEGORY];
  nstime_t delta_time[NB_CAMELSRT_CATEGORY][NUM_RAS_STATS];
};

/* Reset the counter */
static void camelsrt_reset(void *phs)
{
  struct camelsrt_t *hs = (struct camelsrt_t *)phs;
  memset(hs, 0, sizeof(struct camelsrt_t));
}

/* Free our memory */
static void camelsrt_finish(void *phs)
{
  struct camelsrt_t *hs = (struct camelsrt_t *)phs;
  g_free(hs);
}

/* Collect stats */
static tap_packet_status camelsrt_packet(void *phs,
                                         packet_info *pinfo _U_,
                                         epan_dissect_t *edt _U_,
                                         const void *phi, tap_flags_t flags _U_)
{
  struct camelsrt_t *hs = (struct camelsrt_t *)phs;
  const struct camelsrt_info_t * pi = (const struct camelsrt_info_t *)phi;
  int i;

  for (i=0; i<NB_CAMELSRT_CATEGORY; i++) {
    if (pi->bool_msginfo[i] &&
        pi->msginfo[i].is_delta_time
        && pi->msginfo[i].request_available
        && !pi->msginfo[i].is_duplicate ) {

      time_stat_update(&(hs->stats[i]),
                       &(pi->msginfo[i].delta_time),
                       pinfo);

      if (hs->count[i] < NUM_RAS_STATS) {
        hs->delta_time[i][hs->count[i]++]
          = pi->msginfo[i].delta_time;
      }
    }
  }
  return TAP_PACKET_REDRAW;
}

/* Print stat output */
static void camelsrt_draw(void *phs)
{
  struct camelsrt_t *hs = (struct camelsrt_t *)phs;
  unsigned j, z;
  uint32_t li;
  int somme, iteration = 0;
  timestat_t *rtd_temp;
  double x, delay, delay_max, delay_min, delta;
  double criteria[NB_CRITERIA] = { 5.0, 10.0, 75.0, 90.0, 95.0, 99.0, 99.90 };
  double delay_criteria[NB_CRITERIA];
  char* tmp_str;

  printf("\n");
  printf("Camel Service Response Time (SRT) Statistics:\n");
  printf("=================================================================================================\n");
  printf("|        Category         | Measure |  Min SRT  |  Max SRT  |  Avg SRT  | Min frame | Max frame |\n");
  printf("|-------------------------|---------|-----------|-----------|-----------|-----------|-----------|\n");

  j = 1;
  tmp_str = val_to_str_wmem(NULL, j, camelSRTtype_naming, "Unknown Message 0x%02x");
  printf("|%24s |%8u |%8.2f s |%8.2f s |%8.2f s |%10u |%10u |\n",
         tmp_str,
         hs->stats[j].num,
         nstime_to_sec(&(hs->stats[j].min)),
         nstime_to_sec(&(hs->stats[j].max)),
         get_average(&(hs->stats[j].tot), hs->stats[j].num)/1000.0,
         hs->stats[j].min_num,
         hs->stats[j].max_num
         );
  wmem_free(NULL, tmp_str);
  for (j=2; j<NB_CAMELSRT_CATEGORY; j++) {
    if (hs->stats[j].num == 0) {
      tmp_str = val_to_str_wmem(NULL, j, camelSRTtype_naming, "Unknown Message 0x%02x");
      printf("|%24s |%8u |%8.2f ms|%8.2f ms|%8.2f ms|%10u |%10u |\n",
             tmp_str, 0U, 0.0, 0.0, 0.0, 0U, 0U);
      wmem_free(NULL, tmp_str);
      continue;
    }

    tmp_str = val_to_str_wmem(NULL, j, camelSRTtype_naming, "Unknown Message 0x%02x");
    printf("|%24s |%8u |%8.2f ms|%8.2f ms|%8.2f ms|%10u |%10u |\n",
           tmp_str,
           hs->stats[j].num,
           MIN(9999, nstime_to_msec(&(hs->stats[j].min))),
           MIN(9999, nstime_to_msec(&(hs->stats[j].max))),
           MIN(9999, get_average(&(hs->stats[j].tot), hs->stats[j].num)),
           hs->stats[j].min_num,
           hs->stats[j].max_num
           );
    wmem_free(NULL, tmp_str);
  } /* j category */

  printf("=================================================================================================\n");
  /*
   * Display 95%
   */

  printf("|   Category/Criteria     |");
  for (z=0; z<NB_CRITERIA; z++) printf("%7.2f%% |", criteria[z]);
  printf("\n");

  printf("|-------------------------|");
  for (z=0; z<NB_CRITERIA; z++) printf("---------|");
  printf("\n");
  /* calculate the delay max to have a given number of messages (in percentage) */
  for (j=2; j<NB_CAMELSRT_CATEGORY;j++) {

    rtd_temp = &(hs->stats[j]);

    if (hs->count[j] > 0) {
      /* Calculate the delay to answer to p% of the MS */
      for (z=0; z<NB_CRITERIA; z++) {
        iteration = 0;
        delay_max = (double)rtd_temp->max.secs*1000 +(double)rtd_temp->max.nsecs/1000000;
        delay_min = (double)rtd_temp->min.secs*1000 +(double)rtd_temp->min.nsecs/1000000;
        delay = delay_min;
        delta = delay_max-delay_min;
        while ( (delta > 0.001) && (iteration < 10000) ) {
          somme = 0;
          iteration++;

          for (li=0; li<hs->count[j]; li++) {
            x = hs->delta_time[j][li].secs*1000
              + (double)hs->delta_time[j][li].nsecs/1000000;
            if (x <= delay) somme++;
          }
          if ( somme*100 > hs->count[j]*criteria[z] ) { /* trop grand */
            delay_max = delay;
            delay = (delay_max+delay_min)/2;
            delta = delay_max-delay_min;
          } else { /* trop petit */
            delay_min = delay;
            delay = (delay_max+delay_min)/2;
            delta = delay_max-delay_min;
          }
        } /* while */
        delay_criteria[z] = delay;
      } /* z criteria */
      /* Append the result to the table */
      tmp_str = val_to_str_wmem(NULL, j, camelSRTtype_naming, "Unknown Message 0x%02x");
      printf("X%24s |", tmp_str);
      wmem_free(NULL, tmp_str);
      for (z=0; z<NB_CRITERIA; z++) printf("%8.2f |", MIN(9999, delay_criteria[z]));
      printf("\n");
    } else { /* count */
      tmp_str = val_to_str_wmem(NULL, j, camelSRTtype_naming, "Unknown Message 0x%02x");
      printf("X%24s |", tmp_str);
      wmem_free(NULL, tmp_str);
      for (z=0; z<NB_CRITERIA; z++) printf("%8.2f |", 0.0);
      printf("\n");
    } /* count */
  }/* j category */
  printf("===========================");
  for (z=0; z<NB_CRITERIA; z++) printf("==========");
  printf("\n");
}

static bool camelsrt_init(const char *opt_arg, void *userdata _U_)
{
  struct camelsrt_t *p_camelsrt;
  GString *error_string;
  const char *filter;

  p_camelsrt = g_new(struct camelsrt_t, 1);
  camelsrt_reset(p_camelsrt);

  if (!strncmp(opt_arg, "camel,srt,", 10)) {
    filter = opt_arg+10;
  } else {
    filter = NULL;
  }

  error_string = register_tap_listener("CAMEL",
                                     p_camelsrt,
                                     filter,
                                     TL_REQUIRES_NOTHING,
                                     camelsrt_reset,
                                     camelsrt_packet,
                                     camelsrt_draw,
                                     camelsrt_finish);

  if (error_string) {
    /* error, we failed to attach to the tap. clean up */
    camelsrt_finish((void *)p_camelsrt);

    cmdarg_err("Couldn't register camel,srt tap: %s", error_string->str);
    g_string_free(error_string, TRUE);
    return false;
  }

  /*
   * If we are using tshark, we have to display the stats, even if the stats are not persistent
   * As the frame are proceeded in the chronological order, we do not need persistent stats
   * Whereas, with wireshark, it is not possible to have the correct display, if the stats are
   * not saved along the analyze
   */
  gtcap_StatSRT = true;
  gcamel_StatSRT = true;

  return true;
}

static stat_tap_ui camelsrt_ui = {
  REGISTER_STAT_GROUP_GENERIC,
  NULL,
  "camel,srt",
  camelsrt_init,
  0,
  NULL
};

void
register_tap_listener_camelsrt(void)
{
  register_stat_tap_ui(&camelsrt_ui, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
