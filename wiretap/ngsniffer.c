/* ngsniffer.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The code in ngsniffer.c that decodes the time fields for each packet in the
 * Sniffer trace originally came from code from TCPVIEW:
 *
 * TCPVIEW
 *
 * Author:	Martin Hunt
 *		Networks and Distributed Computing
 *		Computing & Communications
 *		University of Washington
 *		Administration Building, AG-44
 *		Seattle, WA  98195
 *		Internet: martinh@cac.washington.edu
 *
 *
 * Copyright 1992 by the University of Washington
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appears in all copies and that both the
 * above copyright notice and this permission notice appear in supporting
 * documentation, and that the name of the University of Washington not be
 * used in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  This software is made
 * available "as is", and
 * THE UNIVERSITY OF WASHINGTON DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * WITH REGARD TO THIS SOFTWARE, INCLUDING WITHOUT LIMITATION ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND IN
 * NO EVENT SHALL THE UNIVERSITY OF WASHINGTON BE LIABLE FOR ANY SPECIAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, TORT
 * (INCLUDING NEGLIGENCE) OR STRICT LIABILITY, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#include "config.h"
#include "ngsniffer.h"

#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/ws_assert.h>

/* Magic number in Sniffer files. */
static const char ngsniffer_magic[] = {
	'T', 'R', 'S', 'N', 'I', 'F', 'F', ' ', 'd', 'a', 't', 'a',
	' ', ' ', ' ', ' ', 0x1a
};

/*
 * Sniffer record types.
 */
#define REC_VERS	1	/* Version record (f_vers) */
#define REC_FRAME2	4	/* Frame data (f_frame2) */
#define	REC_FRAME4	8	/* Frame data (f_frame4) */
#define REC_FRAME6	12	/* Frame data (f_frame6) (see below) */
#define REC_EOF		3	/* End-of-file record (no data follows) */
/*
 * and now for some unknown header types
 */
#define REC_HEADER1	6	/* Header containing various information,
				 * not yet reverse engineered - some binary,
				 * some strings (Serial numbers?  Names
				 * under which the software is registered?
				 * Software version numbers?  Mysterious
				 * strings such as "PA-55X" and "PA-30X"
				 * and "PA-57X" and "PA-11X"?), some strings
				 * that are partially overwritten
				 * ("UNSERIALIZED", "Network General
				 * Corporation"), differing from major
				 * version to major version */
#define REC_HEADER2	7	/* Header containing ??? */
#define REC_V2DESC	8	/* In version 2 sniffer traces contains
				 * info about this capturing session,
				 * in the form of a multi-line string
				 * with NL as the line separator.
				 * Collides with REC_FRAME4 */
#define REC_HEADER3	13	/* Retransmission counts? */
#define REC_HEADER4	14	/* ? */
#define REC_HEADER5	15	/* ? */
#define REC_HEADER6	16	/* More broadcast/retransmission counts? */
#define REC_HEADER7	17	/* ? */

/*
 * Sniffer record header structure.
 */
struct rec_header {
	uint16_t	type;		/* record type */
	uint16_t	length;		/* record length */
};

/*
 * Sniffer version record format.
 */
struct vers_rec {
	int16_t	maj_vers;	/* major version number */
	int16_t	min_vers;	/* minor version number */
	int16_t	time_dos;	/* DOS-format time */
	int16_t	date;		/* DOS-format date */
	int8_t	type;		/* what type of records follow */
	uint8_t	network;	/* network type */
	int8_t	format;		/* format version */
	uint8_t	timeunit;	/* timestamp units */
	int8_t	cmprs_vers;	/* compression version */
	int8_t	cmprs_level;	/* compression level */
	int16_t	rsvd[2];	/* reserved */
};

/*
 * Network types.
 */
#define NETWORK_TRING		0	/* Token ring */
#define NETWORK_ENET		1	/* Ethernet */
#define NETWORK_ARCNET		2	/* ARCNET */
#define NETWORK_STARLAN		3	/* StarLAN */
#define NETWORK_PCNW		4	/* PC Network broadband (Sytek?) */
#define NETWORK_LOCALTALK	5	/* LocalTalk */
#define NETWORK_SYNCHRO		7	/* Internetwork analyzer (synchronous) */
#define NETWORK_ASYNC		8	/* Internetwork analyzer (asynchronous) */
#define NETWORK_FDDI		9	/* FDDI */
#define NETWORK_ATM		10	/* ATM */

/*
 * Sniffer type 2 data record format - followed by frame data.
 *
 * The Expert Sniffer Network Analyzer Operations manual, Release 5.50,
 * documents some of the values used in "fs" and "flags".  "flags" don't
 * look as if they'd be of much interest to us, as those are internal
 * flags for state used by the Sniffer, but "fs" gives various status
 * bits including error indications *and*:
 *
 *	ISDN channel information for ISDN;
 *
 *	PPP vs. SLIP information for Async.
 *
 * In that section it also refers to "FDDI analyzers using the NPI PCI
 * FDDI adapter" and "FDDI analyzers using the NPI ISA FDDI adapter",
 * referring to the first as "F1SNIFF" and the second as "FDSNIFF";
 * those sound as if they *could* be replacements for "TRSNIFF" in
 * the file header, but that manual says, earlier, that the header
 * starts with "TRSNIFF data, no matter where the frames were
 * collected".
 *
 * It also says that a type 2 record has an 8-bit "time_high"
 * and an 8-bit "time_day" field; the code here used to have a
 * 16-bit "time_high" value, but that gave wrong time stamps on at
 * least some captures.  Did some older manual have it as a 16-bit
 * "tstamp_high", so that perhaps it depends on the version number
 * in the file, or is it "tstamp_high" plus "tstamp_day" in all
 * versions?  (I forget whether this came purely from tcpview, or if
 * I saw any of it in an NAI document.)
 *
 * We interpret them as unsigned, as interpreting them as signed
 * would appear to allow time stamps that precede the start of the
 * capture.  The description of the record format shows them as
 * "char", but the section "How the Analyzer Stores Time" shows a
 * time stamp structure with those fields being "unsigned char".
 *
 * In addition, the description of the record format has the comment
 * for the "time_day" field saying it's the time in days since the
 * start of the capture, but the "How the Analyzer Stores Time"
 * section says it's increased by 1 if the capture continues past
 * midnight - and also says that the time stamp structure has a time
 * relative to midnight when the capture started, not since the
 * actual capture start, so that might be a difference between
 * the internal time stamp in the Sniffer software and the time
 * stamp in capture files (i.e., the latter might be relative to
 * the time when the capture starts).
 */
struct frame2_rec {
	uint16_t time_low;	/* low part of time stamp */
	uint16_t time_med;	/* middle part of time stamp */
	uint8_t  time_high;	/* high part of the time stamp */
	uint8_t  time_day;	/* time in days since start of capture */
	int16_t  size;		/* number of bytes of data */
	uint8_t  fs;		/* frame error status bits */
	uint8_t  flags;		/* buffer flags */
	int16_t  true_size;	/* size of original frame, in bytes */
	int16_t  rsvd;		/* reserved */
};

/*
 * Bits in "fs".
 *
 * The bits differ for different link-layer types.
 */

/*
 * Ethernet.
 */
#define FS_ETH_CRC		0x80	/* CRC error */
#define FS_ETH_ALIGN		0x40	/* bad alignment */
#define FS_ETH_RU		0x20	/* "RU out of resources" */
#define FS_ETH_OVERRUN		0x10	/* DMA overrun */
#define FS_ETH_RUNT		0x08	/* frame too small */
#define FS_ETH_COLLISION	0x02	/* collision fragment */

/*
 * FDDI.
 */
#define FS_FDDI_INVALID		0x10	/* frame indicators are invalid */
#define FS_FDDI_ERROR		0x20	/* "frame error bit 1" */
#define FS_FDDI_PCI_VDL		0x01	/* VDL (Valid Data Length?) error on frame on PCI adapter */
#define FS_FDDI_PCI_CRC		0x02	/* CRC error on frame on PCI adapter */
#define FS_FDDI_ISA_CRC		0x20	/* CRC error on frame on ISA adapter */

/*
 * Internetwork analyzer (synchronous and asynchronous).
 */
#define FS_WAN_DTE		0x80	/* DTE->DCE frame */

/*
 * Internetwork analyzer (synchronous).
 */
#define FS_SYNC_LOST		0x01	/* some frames were lost */
#define FS_SYNC_CRC		0x02	/* CRC error */
#define FS_SYNC_ABORT		0x04	/* aborted frame */
#define FS_ISDN_CHAN_MASK	0x18	/* ISDN channel */
#define FS_ISDN_CHAN_D		0x18	/* ISDN channel D */
#define FS_ISDN_CHAN_B1		0x08	/* ISDN channel B1 */
#define FS_ISDN_CHAN_B2		0x10	/* ISDN channel B2 */

/*
 * Internetwork analyzer (asynchronous).
 * XXX - are some of these synchronous flags?  They're listed with the
 * asynchronous flags in the Sniffer 5.50 Network Analyzer Operations
 * manual.  Is one of the "overrun" errors a synchronous overrun error?
 */
#define FS_ASYNC_LOST		0x01	/* some frames were lost */
#define FS_ASYNC_OVERRUN	0x02	/* UART overrun, lost bytes */
#define FS_ASYNC_FRAMING	0x04	/* bad character (framing error?) */
#define FS_ASYNC_PPP		0x08	/* PPP frame */
#define FS_ASYNC_SLIP		0x10	/* SLIP frame */
#define FS_ASYNC_ALIGN		0x20	/* alignment or DLPP(?) error */
#define FS_ASYNC_OVERRUN2	0x40	/* overrun or bad frame length */

/*
 * Sniffer type 4 data record format - followed by frame data.
 *
 * The ATM Sniffer manual says that the "flags" field holds "buffer flags;
 * BF_xxxx", but doesn't say what the BF_xxxx flags are.  They may
 * be the same as they are in a type 2 record, in which case they're
 * probably not of much interest to us.
 *
 * XXX - the manual also says there's an 8-byte "ATMTimeStamp" driver
 * time stamp at the end of "ATMSaveInfo", but, from an ATM Sniffer capture
 * file I've looked at, that appears not to be the case.
 */

/*
 * Fields from the AAL5 trailer for the frame, if it's an AAL5 frame
 * rather than a cell.
 */
typedef struct _ATM_AAL5Trailer {
	uint16_t aal5t_u2u;	/* user-to-user indicator */
	uint16_t aal5t_len;	/* length of the packet */
	uint32_t aal5t_chksum;	/* checksum for AAL5 packet */
} ATM_AAL5Trailer;

typedef struct _ATMTimeStamp {
	uint32_t msw;	/* most significant word */
	uint32_t lsw;	/* least significant word */
} ATMTimeStamp;

typedef struct _ATMSaveInfo {
	uint32_t StatusWord;	/* status word from driver */
	ATM_AAL5Trailer Trailer; /* AAL5 trailer */
	uint8_t  AppTrafType;	/* traffic type */
	uint8_t  AppHLType;	/* protocol type */
	uint16_t AppReserved;	/* reserved */
	uint16_t Vpi;		/* virtual path identifier */
	uint16_t Vci;		/* virtual circuit identifier */
	uint16_t channel;	/* link: 0 for DCE, 1 for DTE */
	uint16_t cells;		/* number of cells */
	uint32_t AppVal1;	/* type-dependent */
	uint32_t AppVal2;	/* type-dependent */
} ATMSaveInfo;

/*
 * Bits in StatusWord.
 */
#define	SW_ERRMASK		0x0F	/* Error mask: */
#define	SW_RX_FIFO_UNDERRUN	0x01	/* Receive FIFO underrun */
#define	SW_RX_FIFO_OVERRUN	0x02	/* Receive FIFO overrun */
#define	SW_RX_PKT_TOO_LONG	0x03	/* Received packet > max size */
#define	SW_CRC_ERROR		0x04	/* CRC error */
#define	SW_USER_ABORTED_RX	0x05	/* User aborted receive */
#define	SW_BUF_LEN_TOO_LONG	0x06	/* buffer len > max buf */
#define	SW_INTERNAL_T1_ERROR	0x07	/* Internal T1 error */
#define	SW_RX_CHANNEL_DEACTIV8	0x08	/* Rx channel deactivate */

#define	SW_ERROR		0x80	/* Error indicator */
#define	SW_CONGESTION		0x40	/* Congestion indicator */
#define	SW_CLP			0x20	/* Cell loss priority indicator */
#define	SW_RAW_CELL		0x100	/* RAW cell indicator */
#define	SW_OAM_CELL		0x200	/* OAM cell indicator */

/*
 * Bits in AppTrafType.
 *
 * For AAL types other than AAL5, the packet data is presumably for a
 * single cell, not a reassembled frame, as the ATM Sniffer manual says
 * it doesn't reassemble cells other than AAL5 cells.
 */
#define	ATT_AALTYPE		0x0F	/* AAL type: */
#define	ATT_AAL_UNKNOWN		0x00	/* Unknown AAL */
#define	ATT_AAL1		0x01	/* AAL1 */
#define	ATT_AAL3_4		0x02	/* AAL3/4 */
#define	ATT_AAL5		0x03	/* AAL5 */
#define	ATT_AAL_USER		0x04	/* User AAL */
#define	ATT_AAL_SIGNALLING	0x05	/* Signaling AAL */
#define	ATT_OAMCELL		0x06	/* OAM cell */

#define	ATT_HLTYPE		0xF0	/* Higher-layer type: */
#define	ATT_HL_UNKNOWN		0x00	/* unknown */
#define	ATT_HL_LLCMX		0x10	/* LLC multiplexed (probably RFC 1483) */
#define	ATT_HL_VCMX		0x20	/* VC multiplexed (probably RFC 1483) */
#define	ATT_HL_LANE		0x30	/* LAN Emulation */
#define	ATT_HL_ILMI		0x40	/* ILMI */
#define	ATT_HL_FRMR		0x50	/* Frame Relay */
#define	ATT_HL_SPANS		0x60	/* FORE SPANS */
#define	ATT_HL_IPSILON		0x70	/* Ipsilon */

/*
 * Values for AppHLType; the interpretation depends on the ATT_HLTYPE
 * bits in AppTrafType.
 */
#define	AHLT_UNKNOWN		0x0
#define	AHLT_VCMX_802_3_FCS	0x1	/* VCMX: 802.3 FCS */
#define	AHLT_LANE_LE_CTRL	0x1	/* LANE: LE Ctrl */
#define	AHLT_IPSILON_FT0	0x1	/* Ipsilon: Flow Type 0 */
#define	AHLT_VCMX_802_4_FCS	0x2	/* VCMX: 802.4 FCS */
#define	AHLT_LANE_802_3		0x2	/* LANE: 802.3 */
#define	AHLT_IPSILON_FT1	0x2	/* Ipsilon: Flow Type 1 */
#define	AHLT_VCMX_802_5_FCS	0x3	/* VCMX: 802.5 FCS */
#define	AHLT_LANE_802_5		0x3	/* LANE: 802.5 */
#define	AHLT_IPSILON_FT2	0x3	/* Ipsilon: Flow Type 2 */
#define	AHLT_VCMX_FDDI_FCS	0x4	/* VCMX: FDDI FCS */
#define	AHLT_LANE_802_3_MC	0x4	/* LANE: 802.3 multicast */
#define	AHLT_VCMX_802_6_FCS	0x5	/* VCMX: 802.6 FCS */
#define	AHLT_LANE_802_5_MC	0x5	/* LANE: 802.5 multicast */
#define	AHLT_VCMX_802_3		0x7	/* VCMX: 802.3 */
#define	AHLT_VCMX_802_4		0x8	/* VCMX: 802.4 */
#define	AHLT_VCMX_802_5		0x9	/* VCMX: 802.5 */
#define	AHLT_VCMX_FDDI		0xa	/* VCMX: FDDI */
#define	AHLT_VCMX_802_6		0xb	/* VCMX: 802.6 */
#define	AHLT_VCMX_FRAGMENTS	0xc	/* VCMX: Fragments */
#define	AHLT_VCMX_BPDU		0xe	/* VCMX: BPDU */

struct frame4_rec {
	uint16_t time_low;	/* low part of time stamp */
	uint16_t time_med;	/* middle part of time stamp */
	uint8_t  time_high;	/* high part of time stamp */
	uint8_t  time_day;	/* time in days since start of capture */
	int16_t  size;		/* number of bytes of data */
	int8_t   fs;		/* frame error status bits */
	int8_t   flags;		/* buffer flags */
	int16_t  true_size;	/* size of original frame, in bytes */
	int16_t  rsvd3;		/* reserved */
	int16_t  atm_pad;	/* pad to 4-byte boundary */
	ATMSaveInfo atm_info;	/* ATM-specific stuff */
};

/*
 * XXX - I have a version 5.50 file with a bunch of token ring
 * records listed as type "12".  The record format below was
 * derived from frame4_rec and a bit of experimentation.
 * - Gerald
 */
struct frame6_rec {
	uint16_t time_low;	/* low part of time stamp */
	uint16_t time_med;	/* middle part of time stamp */
	uint8_t  time_high;	/* high part of time stamp */
	uint8_t  time_day;	/* time in days since start of capture */
	int16_t  size;		/* number of bytes of data */
	uint8_t  fs;		/* frame error status bits */
	uint8_t  flags;		/* buffer flags */
	int16_t  true_size;	/* size of original frame, in bytes */
	uint8_t  chemical_x[22];/* ? */
};

/*
 * Network type values in some type 7 records.
 *
 * Captures with a major version number of 2 appear to have type 7
 * records with text in them (at least one I have does).
 *
 * Captures with a major version of 4, and at least some captures with
 * a major version of 5, have type 7 records with those values in the
 * 5th byte.
 *
 * However, some captures with a major version number of 5 appear not to
 * have type 7 records at all (at least one I have doesn't), but do appear
 * to put non-zero values in the "rsvd" field of the version header (at
 * least one I have does) - at least some other captures with smaller version
 * numbers appear to put 0 there, so *maybe* that's where the network
 * (sub)type is hidden in those captures.  The version 5 captures I've seen
 * that *do* have type 7 records put 0 there, so it's not as if *all* V5
 * captures have something in the "rsvd" field, however.
 *
 * The semantics of these network types is inferred from the Sniffer
 * documentation, as they correspond to types described in the UI;
 * in particular, see
 *
 *	http://www.mcafee.com/common/media/sniffer/support/sdos/operation.pdf
 *
 * starting at page 3-10 (56 of 496).
 *
 * XXX - I've seen X.25 captures with NET_ROUTER, and I've seen bridge/
 * router captures with NET_HDLC.  Sigh....  Are those just captures for
 * which the user set the wrong network type when capturing?
 */
#define NET_SDLC	0	/* Probably "SDLC then SNA" */
#define NET_HDLC	1	/* Used for X.25; is it used for other
				   things as well, or is it "HDLC then
				   X.25", as referred to by the document
				   cited above, and only used for X.25? */
#define NET_FRAME_RELAY	2
#define NET_ROUTER	3	/* Probably "Router/Bridge", for various
				   point-to-point protocols for use between
				   bridges and routers, including PPP as well
				   as various proprietary protocols; also
				   used for ISDN, for reasons not obvious
				   to me, given that a Sniffer knows
				   whether it's using a WAN or an ISDN pod */
#define NET_PPP		4	/* "Asynchronous", which includes SLIP too */
#define NET_SMDS	5	/* Not mentioned in the document, but
				   that's a document for version 5.50 of
				   the Sniffer, and that version might use
				   version 5 in the file format and thus
				   might not be using type 7 records */

/*
 * Values for V.timeunit, in picoseconds, so that they can be represented
 * as integers.  These values must be < 2^(64-40); see below.
 *
 * XXX - at least some captures with a V.timeunit value of 2 show
 * packets with time stamps in 2011 if the time stamp is interpreted
 * to be in units of 15 microseconds.  The capture predates 2008,
 * so that interpretation is probably wrong.  Perhaps the interpretation
 * of V.timeunit depends on the version number of the file?
 */
static const uint32_t Psec[] = {
	15000000,		/* 15.0 usecs = 15000000 psecs */
	  838096,		/* .838096 usecs = 838096 psecs */
	15000000,		/* 15.0 usecs = 15000000 psecs */
	  500000,		/* 0.5 usecs = 500000 psecs */
	 2000000,		/* 2.0 usecs = 2000000 psecs */
	 1000000,		/* 1.0 usecs = 1000000 psecs */
				/* XXX - Sniffer doc says 0.08 usecs = 80000 psecs */
	  100000		/* 0.1 usecs = 100000 psecs */
};
#define NUM_NGSNIFF_TIMEUNITS array_length(Psec)

/* Information for a compressed Sniffer data stream. */
typedef struct {
	unsigned char *buf;	/* buffer into which we uncompress data */
	unsigned int nbytes;	/* number of bytes of data in that buffer */
	int	nextout;	/* offset in that buffer of stream's current position */
	int64_t	comp_offset;	/* current offset in compressed data stream */
	int64_t	uncomp_offset;	/* current offset in uncompressed data stream */
} ngsniffer_comp_stream_t;

typedef struct {
	unsigned	maj_vers;
	unsigned	min_vers;
	bool is_compressed;
	uint32_t	timeunit;
	time_t	start;
	unsigned	network;		/* network type */
	ngsniffer_comp_stream_t seq;	/* sequential access */
	ngsniffer_comp_stream_t rand;	/* random access */
	GList	*first_blob;		/* list element for first blob */
	GList	*last_blob;		/* list element for last blob */
	GList	*current_blob;		/* list element for current blob */
} ngsniffer_t;

/*
 * DOS date to "struct tm" conversion values.
 */
/* DOS year = upper 7 bits */
#define DOS_YEAR_OFFSET (1980-1900)	/* tm_year = year+1900, DOS date year year+1980 */
#define DOS_YEAR_SHIFT	9
#define DOS_YEAR_MASK	(0x7F<<DOS_YEAR_SHIFT)
/* DOS month = next 4 bits */
#define DOS_MONTH_OFFSET	(-1)	/* tm_mon = month #-1, DOS date month = month # */
#define DOS_MONTH_SHIFT	5
#define DOS_MONTH_MASK	(0x0F<<DOS_MONTH_SHIFT)
/* DOS day = next 5 bits */
#define DOS_DAY_SHIFT	0
#define DOS_DAY_MASK	(0x1F<<DOS_DAY_SHIFT)

static int process_header_records(wtap *wth, int *err, char **err_info,
    int16_t maj_vers, uint8_t network);
static int process_rec_header2_v2(wtap *wth, unsigned char *buffer,
    uint16_t length, int *err, char **err_info);
static int process_rec_header2_v145(wtap *wth, unsigned char *buffer,
    uint16_t length, int16_t maj_vers, int *err, char **err_info);
static bool ngsniffer_read(wtap *wth, wtap_rec *rec,
    int *err, char **err_info, int64_t *data_offset);
static bool ngsniffer_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, int *err, char **err_info);
static bool read_rec_header(wtap *wth, bool is_random,
    struct rec_header *hdr, int *err, char **err_info);
static bool process_frame_record(wtap *wth, bool is_random,
    unsigned *padding, struct rec_header *hdr, wtap_rec *rec,
    int *err, char **err_info);
static void set_metadata_frame2(wtap *wth, wtap_rec *rec,
    struct frame2_rec *frame2);
static void set_pseudo_header_frame4(union wtap_pseudo_header *pseudo_header,
    struct frame4_rec *frame4);
static void set_pseudo_header_frame6(wtap *wth,
    union wtap_pseudo_header *pseudo_header, struct frame6_rec *frame6);
static int infer_pkt_encap(const uint8_t *pd, int len);
static int fix_pseudo_header(int encap, wtap_rec *rec, int len);
static void ngsniffer_sequential_close(wtap *wth);
static void ngsniffer_close(wtap *wth);
static bool ngsniffer_dump(wtap_dumper *wdh, const wtap_rec *rec,
    int *err, char **err_info);
static bool ngsniffer_dump_finish(wtap_dumper *wdh, int *err,
    char **err_info);
static int SnifferDecompress( unsigned char * inbuf, size_t inlen,
    unsigned char * outbuf, size_t outlen, int *err, char **err_info );
static bool ng_read_bytes_or_eof(wtap *wth, void *buffer,
    unsigned int nbytes, bool is_random, int *err, char **err_info);
static bool ng_read_bytes(wtap *wth, void *buffer, unsigned int nbytes,
    bool is_random, int *err, char **err_info);
static bool read_blob(FILE_T infile, ngsniffer_comp_stream_t *comp_stream,
    int *err, char **err_info);
static bool ng_skip_bytes_seq(wtap *wth, unsigned int count, int *err,
    char **err_info);
static bool ng_file_seek_rand(wtap *wth, int64_t offset, int *err,
    char **err_info);

static int ngsniffer_uncompressed_file_type_subtype = -1;
static int ngsniffer_compressed_file_type_subtype = -1;

void register_ngsniffer(void);

wtap_open_return_val
ngsniffer_open(wtap *wth, int *err, char **err_info)
{
	char magic[sizeof ngsniffer_magic];
	char record_type[2];
	char record_length[4]; /* only the first 2 bytes are length,
				  the last 2 are "reserved" and are thrown away */
	uint16_t type;
	struct vers_rec version;
	uint16_t maj_vers;
	uint16_t	start_date;
#if 0
	uint16_t	start_time;
#endif
	static const int sniffer_encap[] = {
		WTAP_ENCAP_TOKEN_RING,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_ARCNET,
		WTAP_ENCAP_UNKNOWN,	/* StarLAN */
		WTAP_ENCAP_UNKNOWN,	/* PC Network broadband */
		WTAP_ENCAP_UNKNOWN,	/* LocalTalk */
		WTAP_ENCAP_UNKNOWN,	/* Znet */
		WTAP_ENCAP_PER_PACKET,	/* Internetwork analyzer (synchronous) */
		WTAP_ENCAP_PER_PACKET,	/* Internetwork analyzer (asynchronous) */
		WTAP_ENCAP_FDDI_BITSWAPPED,
		WTAP_ENCAP_ATM_PDUS
	};
	#define NUM_NGSNIFF_ENCAPS array_length(sniffer_encap)
	struct tm tm;
	int64_t current_offset;
	ngsniffer_t *ngsniffer;

	/* Read in the string that should be at the start of a Sniffer file */
	if (!wtap_read_bytes(wth->fh, magic, sizeof magic, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic, ngsniffer_magic, sizeof ngsniffer_magic)) {
		return WTAP_OPEN_NOT_MINE;
	}

	/*
	 * Read the first record, which the manual says is a version
	 * record.
	 */
	if (!wtap_read_bytes(wth->fh, record_type, 2, err, err_info))
		return WTAP_OPEN_ERROR;
	if (!wtap_read_bytes(wth->fh, record_length, 4, err, err_info))
		return WTAP_OPEN_ERROR;

	type = pletoh16(record_type);

	if (type != REC_VERS) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("ngsniffer: Sniffer file doesn't start with a version record");
		return WTAP_OPEN_ERROR;
	}

	if (!wtap_read_bytes(wth->fh, &version, sizeof version, err, err_info))
		return WTAP_OPEN_ERROR;

	/* Check the data link type. */
	if (version.network >= NUM_NGSNIFF_ENCAPS
	    || sniffer_encap[version.network] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("ngsniffer: network type %u unknown or unsupported",
		    version.network);
		return WTAP_OPEN_ERROR;
	}

	/* Check the time unit */
	if (version.timeunit >= NUM_NGSNIFF_TIMEUNITS) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("ngsniffer: Unknown timeunit %u", version.timeunit);
		return WTAP_OPEN_ERROR;
	}

	/* Set encap type before reading header records because the
	 * header record may change encap type.
	 */
	wth->file_encap = sniffer_encap[version.network];

	/*
	 * We don't know how to handle the remaining header record types,
	 * so we just skip them - except for REC_HEADER2 records, which
	 * we look at, for "Internetwork analyzer" captures, to attempt to
	 * determine what the link-layer encapsulation is.
	 *
	 * XXX - in some version 1.16 internetwork analyzer files
	 * generated by the Windows Sniffer when saving Windows
	 * Sniffer files as DOS Sniffer files, there's no REC_HEADER2
	 * record, but the first "rsvd" word is 1 for PRI ISDN files, 2
	 * for BRI ISDN files, and 0 for non-ISDN files; is that something
	 * the DOS Sniffer understands?
	 */
	maj_vers = pletoh16(&version.maj_vers);
	if (process_header_records(wth, err, err_info, maj_vers,
	    version.network) < 0)
		return WTAP_OPEN_ERROR;
	if ((version.network == NETWORK_SYNCHRO ||
	    version.network == NETWORK_ASYNC) &&
	    wth->file_encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * Well, we haven't determined the internetwork analyzer
		 * subtype yet...
		 */
		switch (maj_vers) {

		case 1:
			/*
			 * ... and this is a version 1 capture; look
			 * at the first "rsvd" word.
			 */
			switch (pletoh16(&version.rsvd[0])) {

			case 1:
			case 2:
				wth->file_encap = WTAP_ENCAP_ISDN;
				break;
			}
			break;

		case 3:
			/*
			 * ...and this is a version 3 capture; we've
			 * seen nothing in those that obviously
			 * indicates the capture type, but the only
			 * one we've seen is a Frame Relay capture,
			 * so mark it as Frame Relay for now.
			 */
			wth->file_encap = WTAP_ENCAP_FRELAY_WITH_PHDR;
			break;
		}
	}

	current_offset = file_tell(wth->fh);

	/*
	 * Now, if we have a random stream open, position it to the same
	 * location, which should be the beginning of the real data, and
	 * should be the beginning of the compressed data.
	 *
	 * XXX - will we see any records other than REC_FRAME2, REC_FRAME4,
	 * or REC_EOF after this?  If not, we can get rid of the loop in
	 * "ngsniffer_read()".
	 */
	if (wth->random_fh != NULL) {
		if (file_seek(wth->random_fh, current_offset, SEEK_SET, err) == -1)
			return WTAP_OPEN_ERROR;
	}

	/* This is a ngsniffer file */
	ngsniffer = g_new(ngsniffer_t, 1);
	wth->priv = (void *)ngsniffer;

	/* compressed or uncompressed Sniffer file? */
	if (version.format != 1) {
		wth->file_type_subtype = ngsniffer_compressed_file_type_subtype;
		ngsniffer->is_compressed = true;
	} else {
		wth->file_type_subtype = ngsniffer_uncompressed_file_type_subtype;
		ngsniffer->is_compressed = false;
	}

	ngsniffer->maj_vers = maj_vers;
	ngsniffer->min_vers = pletoh16(&version.min_vers);

	/* We haven't allocated any uncompression buffers yet. */
	ngsniffer->seq.buf = NULL;
	ngsniffer->seq.nbytes = 0;
	ngsniffer->seq.nextout = 0;
	ngsniffer->rand.buf = NULL;
	ngsniffer->rand.nbytes = 0;
	ngsniffer->rand.nextout = 0;

	/* Set the current file offset; the offset in the compressed file
	   and in the uncompressed data stream currently the same. */
	ngsniffer->seq.uncomp_offset = current_offset;
	ngsniffer->seq.comp_offset = current_offset;
	ngsniffer->rand.uncomp_offset = current_offset;
	ngsniffer->rand.comp_offset = current_offset;

	/* We don't yet have any list of compressed blobs. */
	ngsniffer->first_blob = NULL;
	ngsniffer->last_blob = NULL;
	ngsniffer->current_blob = NULL;

	wth->subtype_read = ngsniffer_read;
	wth->subtype_seek_read = ngsniffer_seek_read;
	wth->subtype_sequential_close = ngsniffer_sequential_close;
	wth->subtype_close = ngsniffer_close;
	wth->snapshot_length = 0;	/* not available in header, only in frame */
	ngsniffer->timeunit = Psec[version.timeunit];
	ngsniffer->network = version.network;

	/* Get capture start time */
	start_date = pletoh16(&version.date);
	tm.tm_year = ((start_date&DOS_YEAR_MASK)>>DOS_YEAR_SHIFT) + DOS_YEAR_OFFSET;
	tm.tm_mon = ((start_date&DOS_MONTH_MASK)>>DOS_MONTH_SHIFT) + DOS_MONTH_OFFSET;
	tm.tm_mday = ((start_date&DOS_DAY_MASK)>>DOS_DAY_SHIFT);
	/*
	 * The time does not appear to act as an offset; only the date.
	 * XXX - sometimes it does appear to act as an offset; is this
	 * version-dependent?
	 */
#if 0
	start_time = pletoh16(&version.time_dos);
	tm.tm_hour = (start_time&0xf800)>>11;
	tm.tm_min = (start_time&0x7e0)>>5;
	tm.tm_sec = (start_time&0x1f)<<1;
#else
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
#endif
	tm.tm_isdst = -1;
	ngsniffer->start = mktime(&tm);
	/*
	 * XXX - what if "secs" is -1?  Unlikely,
	 * but if the capture was done in a time
	 * zone that switches between standard and
	 * summer time sometime other than when we
	 * do, and thus the time was one that doesn't
	 * exist here because a switch from standard
	 * to summer time zips over it, it could
	 * happen.
	 *
	 * On the other hand, if the capture was done
	 * in a different time zone, this won't work
	 * right anyway; unfortunately, the time zone
	 * isn't stored in the capture file.
	 */

	wth->file_tsprec = WTAP_TSPREC_NSEC;	/* XXX */

	return WTAP_OPEN_MINE;
}

static int
process_header_records(wtap *wth, int *err, char **err_info, int16_t maj_vers,
    uint8_t network)
{
	char record_type[2];
	char record_length[4]; /* only the first 2 bytes are length,
				  the last 2 are "reserved" and are thrown away */
	uint16_t rec_type, rec_length_remaining;
	int bytes_to_read;
	unsigned char buffer[256];

	for (;;) {
		if (!wtap_read_bytes_or_eof(wth->fh, record_type, 2, err, err_info)) {
			if (*err != 0)
				return -1;
			return 0;	/* EOF */
		}

		rec_type = pletoh16(record_type);
		if ((rec_type != REC_HEADER1) && (rec_type != REC_HEADER2)
			&& (rec_type != REC_HEADER3) && (rec_type != REC_HEADER4)
			&& (rec_type != REC_HEADER5) && (rec_type != REC_HEADER6)
			&& (rec_type != REC_HEADER7)
			&& ((rec_type != REC_V2DESC) || (maj_vers > 2)) ) {
			/*
			 * Well, this is either some unknown header type
			 * (we ignore this case), an uncompressed data
			 * frame or the length of a compressed blob
			 * which implies data. Seek backwards over the
			 * two bytes we read, and return.
			 */
			if (file_seek(wth->fh, -2, SEEK_CUR, err) == -1)
				return -1;
			return 0;
		}

		if (!wtap_read_bytes(wth->fh, record_length, 4,
		    err, err_info))
			return -1;

		rec_length_remaining = pletoh16(record_length);

		/*
		 * Is this is an "Internetwork analyzer" capture, and
		 * is this a REC_HEADER2 record?
		 *
		 * If so, it appears to specify the particular type
		 * of network we're on.
		 *
		 * XXX - handle sync and async differently?  (E.g.,
		 * does this apply only to sync?)
		 */
		if ((network == NETWORK_SYNCHRO || network == NETWORK_ASYNC) &&
		    rec_type == REC_HEADER2) {
			/*
			 * Yes, get the first up-to-256 bytes of the
			 * record data.
			 */
			bytes_to_read = MIN(rec_length_remaining, (int)sizeof buffer);
			if (!wtap_read_bytes(wth->fh, buffer,
			    bytes_to_read, err, err_info))
				return -1;

			switch (maj_vers) {

			case 2:
				if (process_rec_header2_v2(wth, buffer,
				    rec_length_remaining, err, err_info) < 0)
					return -1;
				break;

			case 1:
			case 4:
			case 5:
				if (process_rec_header2_v145(wth, buffer,
				    rec_length_remaining, maj_vers, err, err_info) < 0)
					return -1;
				break;
			}

			/*
			 * Skip the rest of the record.
			 */
			if (rec_length_remaining > sizeof buffer) {
				if (file_seek(wth->fh, rec_length_remaining - sizeof buffer,
				    SEEK_CUR, err) == -1)
					return -1;
			}
		} else {
			/* Nope, just skip over the data. */
			if (file_seek(wth->fh, rec_length_remaining, SEEK_CUR, err) == -1)
				return -1;
		}
	}
}

static int
process_rec_header2_v2(wtap *wth, unsigned char *buffer, uint16_t length,
    int *err, char **err_info)
{
	static const char x_25_str[] = "HDLC\nX.25\n";

	/*
	 * There appears to be a string in a REC_HEADER2 record, with
	 * a list of protocols.  In one X.25 capture I've seen, the
	 * string was "HDLC\nX.25\nCLNP\nISO_TP\nSESS\nPRES\nVTP\nACSE".
	 * Presumably CLNP and everything else is per-packet, but
	 * we assume "HDLC\nX.25\n" indicates that it's an X.25 capture.
	 */
	if (length < sizeof x_25_str - 1) {
		/*
		 * There's not enough data to compare.
		 */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup("ngsniffer: WAN capture has too-short protocol list");
		return -1;
	}

	if (strncmp((char *)buffer, x_25_str, sizeof x_25_str - 1) == 0) {
		/*
		 * X.25.
		 */
		wth->file_encap = WTAP_ENCAP_LAPB;
	} else {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("ngsniffer: WAN capture protocol string %.*s unknown",
		    length, buffer);
		return -1;
	}
	return 0;
}

static int
process_rec_header2_v145(wtap *wth, unsigned char *buffer, uint16_t length,
    int16_t maj_vers, int *err, char **err_info)
{
	/*
	 * The 5th byte of the REC_HEADER2 record appears to be a
	 * network type.
	 */
	if (length < 5) {
		/*
		 * There is no 5th byte; give up.
		 */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup("ngsniffer: WAN capture has no network subtype");
		return -1;
	}

	/*
	 * The X.25 captures I've seen have a type of NET_HDLC, and the
	 * Sniffer documentation seems to imply that it's used for
	 * X.25, although it could be used for other purposes as well.
	 *
	 * NET_ROUTER is used for all sorts of point-to-point protocols,
	 * including ISDN.  It appears, from the documentation, that the
	 * Sniffer attempts to infer the particular protocol by looking
	 * at the traffic; it's not clear whether it stores in the file
	 * an indication of the protocol it inferred was being used.
	 *
	 * Unfortunately, it also appears that NET_HDLC is used for
	 * stuff other than X.25 as well, so we can't just interpret
	 * it unconditionally as X.25.
	 *
	 * For now, we interpret both NET_HDLC and NET_ROUTER as "per-packet
	 * encapsulation".  We remember that we saw NET_ROUTER, though,
	 * as it appears that we can infer whether a packet is PPP or
	 * ISDN based on the channel number subfield of the frame error
	 * status bits - if it's 0, it's PPP, otherwise it's ISDN and
	 * the channel number indicates which channel it is.  We assume
	 * NET_HDLC isn't used for ISDN.
	 */
	switch (buffer[4]) {

	case NET_SDLC:
		wth->file_encap = WTAP_ENCAP_SDLC;
		break;

	case NET_HDLC:
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
		break;

	case NET_FRAME_RELAY:
		wth->file_encap = WTAP_ENCAP_FRELAY_WITH_PHDR;
		break;

	case NET_ROUTER:
		/*
		 * For most of the version 4 capture files I've seen,
		 * 0xfa in buffer[1] means the file is an ISDN capture,
		 * but there's one PPP file with 0xfa there; does that
		 * mean that the 0xfa has nothing to do with ISDN,
		 * or is that just an ISDN file with no D channel
		 * packets?  (The channel number is not 0 in any
		 * of the packets, so perhaps it is.)
		 *
		 * For one version 5 ISDN capture I've seen, there's
		 * a 0x01 in buffer[6]; none of the non-ISDN version
		 * 5 captures have it.
		 */
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
		switch (maj_vers) {

		case 4:
			if (buffer[1] == 0xfa)
				wth->file_encap = WTAP_ENCAP_ISDN;
			break;

		case 5:
			if (length < 7) {
				/*
				 * There is no 5th byte; give up.
				 */
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = g_strdup("ngsniffer: WAN bridge/router capture has no ISDN flag");
				return -1;
			}
			if (buffer[6] == 0x01)
				wth->file_encap = WTAP_ENCAP_ISDN;
			break;
		}
		break;

	case NET_PPP:
		wth->file_encap = WTAP_ENCAP_PPP_WITH_PHDR;
		break;

	default:
		/*
		 * Reject these until we can figure them out.
		 */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("ngsniffer: WAN network subtype %u unknown or unsupported",
		    buffer[4]);
		return -1;
	}
	return 0;
}

/* Read the next packet */
static bool
ngsniffer_read(wtap *wth, wtap_rec *rec, int *err, char **err_info,
    int64_t *data_offset)
{
	ngsniffer_t *ngsniffer;
	struct rec_header hdr;
	unsigned	padding;

	ngsniffer = (ngsniffer_t *)wth->priv;
	for (;;) {
		/*
		 * We use the uncompressed offset, as that's what
		 * we need to use for compressed files.
		 */
		*data_offset = ngsniffer->seq.uncomp_offset;

		/*
		 * Read the record header.
		 */
		if (!read_rec_header(wth, false, &hdr, err, err_info)) {
			/* Read error or short read */
			return false;
		}

		/*
		 * Process the record.
		 */
		switch (hdr.type) {

		case REC_FRAME2:
		case REC_FRAME4:
		case REC_FRAME6:
			/* Frame record */
			if (!process_frame_record(wth, false, &padding,
			    &hdr, rec, err, err_info)) {
				/* Read error, short read, or other error */
				return false;
			}

			/*
			 * Skip any extra data in the record.
			 */
			if (padding != 0) {
				if (!ng_skip_bytes_seq(wth, padding, err,
				    err_info))
					return false;
			}
			return true;

		case REC_EOF:
			/*
			 * End of file.  Skip past any data (if any),
			 * the length of which is in hdr.length, and
			 * return an EOF indication.
			 */
			if (hdr.length != 0) {
				if (!ng_skip_bytes_seq(wth, hdr.length, err,
				    err_info))
					return false;
			}
			*err = 0;	/* EOF, not error */
			return false;

		default:
			/*
			 * Well, we don't know what it is, or we know what
			 * it is but can't handle it.  Skip past the data
			 * portion (if any), the length of which is in
			 * hdr.length, and keep looping.
			 */
			if (hdr.length != 0) {
				if (!ng_skip_bytes_seq(wth, hdr.length, err,
				    err_info))
					return false;
			}
			break;
		}
	}
}

static bool
ngsniffer_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    int *err, char **err_info)
{
	struct rec_header hdr;

	if (!ng_file_seek_rand(wth, seek_off, err, err_info))
		return false;

	if (!read_rec_header(wth, true, &hdr, err, err_info)) {
		/* Read error or short read */
		return false;
	}

	/*
	 * hdr.type is the record type.
	 */
	switch (hdr.type) {

	case REC_FRAME2:
	case REC_FRAME4:
	case REC_FRAME6:
		/* Frame record */
		if (!process_frame_record(wth, true, NULL, &hdr, rec,
		    err, err_info)) {
			/* Read error, short read, or other error */
			return false;
		}
		break;

	default:
		/*
		 * Other record type, or EOF.
		 * This "can't happen".
		 */
		ws_assert_not_reached();
		return false;
	}

	return true;
}

/*
 * Read the record header.
 *
 * Returns true on success, false on error.
 */
static bool
read_rec_header(wtap *wth, bool is_random, struct rec_header *hdr,
    int *err, char **err_info)
{
	char	record_type[2];
	char	record_length[4]; /* only 1st 2 bytes are length */

	/*
	 * Read the record type.
	 */
	if (!ng_read_bytes_or_eof(wth, record_type, 2, is_random, err, err_info)) {
		if (*err != 0)
			return false;
		/*
		 * End-of-file; construct a fake EOF record.
		 * (A file might have an EOF record at the end, or
		 * it might just come to an end.)
		 * (XXX - is that true of all Sniffer files?)
		 */
		hdr->type = REC_EOF;
		hdr->length = 0;
		return true;
	}

	/*
	 * Read the record length.
	 */
	if (!ng_read_bytes(wth, record_length, 4, is_random, err, err_info))
		return false;

	hdr->type = pletoh16(record_type);
	hdr->length = pletoh16(record_length);
	return true;
}

/*
 * Returns true on success, false on error.
 * If padding is non-null, sets *padding to the amount of padding at
 * the end of the record.
 */
static bool
process_frame_record(wtap *wth, bool is_random, unsigned *padding,
    struct rec_header *hdr, wtap_rec *rec, int *err,
    char **err_info)
{
	ngsniffer_t *ngsniffer;
	unsigned	rec_length_remaining;
	struct frame2_rec frame2;
	struct frame4_rec frame4;
	struct frame6_rec frame6;
	uint16_t	time_low, time_med, true_size, size;
	uint8_t	time_high, time_day;
	uint64_t t, tsecs, tpsecs;

	rec_length_remaining = hdr->length;

	/* Initialize - we'll be setting some presence flags below. */
	wtap_setup_packet_rec(rec, wth->file_encap);
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = 0;

	ngsniffer = (ngsniffer_t *)wth->priv;
	switch (hdr->type) {

	case REC_FRAME2:
		if (ngsniffer->network == NETWORK_ATM) {
			/*
			 * We shouldn't get a frame2 record in
			 * an ATM capture.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("ngsniffer: REC_FRAME2 record in an ATM Sniffer file");
			return false;
		}

		/* Do we have an f_frame2_struct worth of data? */
		if (rec_length_remaining < sizeof frame2) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("ngsniffer: REC_FRAME2 record length is less than record header length");
			return false;
		}

		/* Read the f_frame2_struct */
		if (!ng_read_bytes(wth, &frame2, (unsigned int)sizeof frame2,
		   is_random, err, err_info))
			return false;
		time_low = pletoh16(&frame2.time_low);
		time_med = pletoh16(&frame2.time_med);
		time_high = frame2.time_high;
		time_day = frame2.time_day;
		size = pletoh16(&frame2.size);
		true_size = pletoh16(&frame2.true_size);

		rec_length_remaining -= (unsigned)sizeof frame2;	/* we already read that much */

		set_metadata_frame2(wth, rec, &frame2);
		break;

	case REC_FRAME4:
		if (ngsniffer->network != NETWORK_ATM) {
			/*
			 * We shouldn't get a frame2 record in
			 * a non-ATM capture.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("ngsniffer: REC_FRAME4 record in a non-ATM Sniffer file");
			return false;
		}

		/*
		 * XXX - it looks as if some version 4 captures have
		 * a bogus record length, based on the assumption
		 * that the record is a frame2 record, i.e. the length
		 * was calculated based on the record being a frame2
		 * record, so it's too short by (sizeof frame4 - sizeof frame2).
		 */
		if (ngsniffer->maj_vers < 5 && ngsniffer->min_vers >= 95)
			rec_length_remaining += (unsigned)(sizeof frame4 - sizeof frame2);

		/* Do we have an f_frame4_struct worth of data? */
		if (rec_length_remaining < sizeof frame4) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("ngsniffer: REC_FRAME4 record length is less than record header length");
			return false;
		}

		/* Read the f_frame4_struct */
		if (!ng_read_bytes(wth, &frame4, (unsigned int)sizeof frame4,
		    is_random, err, err_info))
			return false;
		time_low = pletoh16(&frame4.time_low);
		time_med = pletoh16(&frame4.time_med);
		time_high = frame4.time_high;
		time_day = frame4.time_day;
		size = pletoh16(&frame4.size);
		true_size = pletoh16(&frame4.true_size);

		rec_length_remaining -= (unsigned)sizeof frame4;	/* we already read that much */

		set_pseudo_header_frame4(&rec->rec_header.packet_header.pseudo_header, &frame4);
		break;

	case REC_FRAME6:
		/* Do we have an f_frame6_struct worth of data? */
		if (rec_length_remaining < sizeof frame6) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("ngsniffer: REC_FRAME6 record length is less than record header length");
			return false;
		}

		/* Read the f_frame6_struct */
		if (!ng_read_bytes(wth, &frame6, (unsigned int)sizeof frame6,
		    is_random, err, err_info))
			return false;
		time_low = pletoh16(&frame6.time_low);
		time_med = pletoh16(&frame6.time_med);
		time_high = frame6.time_high;
		time_day = frame6.time_day;
		size = pletoh16(&frame6.size);
		true_size = pletoh16(&frame6.true_size);

		rec_length_remaining -= (unsigned)sizeof frame6;	/* we already read that much */

		set_pseudo_header_frame6(wth, &rec->rec_header.packet_header.pseudo_header, &frame6);
		break;

	default:
		/*
		 * This should never happen.
		 */
		ws_assert_not_reached();
		return false;
	}

	/*
	 * Is the frame data size greater than what's left of the
	 * record?
	 */
	if (size > rec_length_remaining) {
		/*
		 * Yes - treat this as an error.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("ngsniffer: Record length is less than packet size");
		return false;
	}

	/*
	 * The maximum value of length is 65535, which is less than
	 * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
	 * it.
	 */
	if (padding != NULL) {
		/*
		 * Padding, if the frame data size is less than what's
		 * left of the record.
		 */
		*padding = rec_length_remaining - size;
	}

	rec->presence_flags |= true_size ? WTAP_HAS_TS|WTAP_HAS_CAP_LEN : WTAP_HAS_TS;
	rec->rec_header.packet_header.len = true_size ? true_size : size;
	rec->rec_header.packet_header.caplen = size;

	/*
	 * Read the packet data.
	 */
	ws_buffer_assure_space(&rec->data, size);
	if (!ng_read_bytes(wth, ws_buffer_start_ptr(&rec->data), size, is_random,
	    err, err_info))
		return false;

	rec->rec_header.packet_header.pkt_encap = fix_pseudo_header(wth->file_encap,
	    rec, size);

	/*
	 * 40-bit time stamp, in units of timeunit picoseconds.
	 */
	t = (((uint64_t)time_high)<<32) | (((uint64_t)time_med) << 16) | time_low;

	/*
	 * timeunit is always < 2^(64-40), so t * timeunit fits in 64
	 * bits.  That gives a 64-bit time stamp, in units of
	 * picoseconds.
	 */
	t *= ngsniffer->timeunit;

	/*
	 * Convert to seconds and picoseconds.
	 */
	tsecs = t/UINT64_C(1000000000000);
	tpsecs = t - tsecs*UINT64_C(1000000000000);

	/*
	 * Add in the time_day value (86400 seconds/day).
	 */
	tsecs += time_day*86400;

	/*
	 * Add in the capture start time.
	 */
	tsecs += ngsniffer->start;

	rec->ts.secs = (time_t)tsecs;
	rec->ts.nsecs = (int)(tpsecs/1000);	/* psecs to nsecs */

	return true;	/* success */
}

static void
set_metadata_frame2(wtap *wth, wtap_rec *rec, struct frame2_rec *frame2)
{
	ngsniffer_t *ngsniffer;
	uint32_t pack_flags;
	union wtap_pseudo_header *pseudo_header;

	ngsniffer = (ngsniffer_t *)wth->priv;

	/*
	 * In one PPP "Internetwork analyzer" capture:
	 *
	 *	The only bit seen in "frame2.fs" is the 0x80 bit, which
	 *	probably indicates the packet's direction; all other
	 *	bits were zero.  The Expert Sniffer Network Analyzer
	 *	5.50 Operations manual says that bit is the FS_DTE bit
	 *	for async/PPP data.  The other bits are error bits
	 *	plus bits indicating whether the frame is PPP or SLIP,
	 *	but the PPP bit isn't set.
	 *
	 *	All bits in "frame2.flags" were zero.
	 *
	 * In one X.25 "Internetwork analyzer" capture:
	 *
	 *	The only bit seen in "frame2.fs" is the 0x80 bit, which
	 *	probably indicates the packet's direction; all other
	 *	bits were zero.
	 *
	 *	"frame2.flags" was always 0x18; however, the Sniffer
	 *	manual says that just means that a display filter was
	 *	calculated for the frame, and it should be displayed,
	 *	so perhaps that's just a quirk of that particular capture.
	 *
	 * In one Ethernet capture:
	 *
	 *	"frame2.fs" was always 0; the Sniffer manual says they're
	 *	error bits of various sorts.
	 *
	 *	"frame2.flags" was either 0 or 0x18, with no obvious
	 *	correlation with anything.  See previous comment
	 *	about display filters.
	 *
	 * In one Token Ring capture:
	 *
	 *	"frame2.fs" was either 0 or 0xcc; the Sniffer manual says
	 *	nothing about those bits for Token Ring captures.
	 *
	 *	"frame2.flags" was either 0 or 0x18, with no obvious
	 *	correlation with anything.  See previous comment
	 *	about display filters.
	 */
	switch (ngsniffer->network) {

	case NETWORK_ENET:
		pack_flags = 0;
		if (frame2->fs & FS_ETH_CRC)
			pack_flags |= PACK_FLAGS_CRC_ERROR;
		if (frame2->fs & FS_ETH_ALIGN)
			pack_flags |= PACK_FLAGS_UNALIGNED_FRAME;
		if (frame2->fs & FS_ETH_RUNT)
			pack_flags |= PACK_FLAGS_PACKET_TOO_SHORT;
		wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, pack_flags);
		break;

	case NETWORK_FDDI:
		pack_flags = 0;
		if (!(frame2->fs & FS_FDDI_INVALID) &&
		    (frame2->fs & (FS_FDDI_PCI_CRC|FS_FDDI_ISA_CRC)))
			pack_flags |= PACK_FLAGS_CRC_ERROR;
		wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, pack_flags);
		break;

	case NETWORK_SYNCHRO:
		pack_flags = 0;
		if (frame2->fs & FS_SYNC_CRC)
			pack_flags |= PACK_FLAGS_CRC_ERROR;
		wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, pack_flags);
		break;
	}

	pseudo_header = &rec->rec_header.packet_header.pseudo_header;
	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/*
		 * XXX - do we ever have an FCS?  If not, why do we often
		 * have 4 extra bytes of stuff at the end?  Do some
		 * PC Ethernet interfaces report the length including the
		 * FCS but not store the FCS in the packet, or do some
		 * Ethernet drivers work that way?
		 */
		pseudo_header->eth.fcs_len = 0;
		break;

	case WTAP_ENCAP_PPP_WITH_PHDR:
	case WTAP_ENCAP_SDLC:
		pseudo_header->p2p.sent = (frame2->fs & FS_WAN_DTE) ? true : false;
		break;

	case WTAP_ENCAP_LAPB:
	case WTAP_ENCAP_FRELAY_WITH_PHDR:
	case WTAP_ENCAP_PER_PACKET:
		pseudo_header->dte_dce.flags = (frame2->fs & FS_WAN_DTE) ? 0x00 : FROM_DCE;
		break;

	case WTAP_ENCAP_ISDN:
		pseudo_header->isdn.uton = (frame2->fs & FS_WAN_DTE) ? false : true;
		switch (frame2->fs & FS_ISDN_CHAN_MASK) {

		case FS_ISDN_CHAN_D:
			pseudo_header->isdn.channel = 0;	/* D-channel */
			break;

		case FS_ISDN_CHAN_B1:
			pseudo_header->isdn.channel = 1;	/* B1-channel */
			break;

		case FS_ISDN_CHAN_B2:
			pseudo_header->isdn.channel = 2;	/* B2-channel */
			break;

		default:
			pseudo_header->isdn.channel = 30;	/* XXX */
			break;
		}
	}
}

static void
set_pseudo_header_frame4(union wtap_pseudo_header *pseudo_header,
    struct frame4_rec *frame4)
{
	uint32_t StatusWord;
	uint8_t aal_type, hl_type;
	uint16_t vpi, vci;

	/*
	 * Map flags from frame4.atm_info.StatusWord.
	 */
	pseudo_header->atm.flags = 0;
	StatusWord = pletoh32(&frame4->atm_info.StatusWord);
	if (StatusWord & SW_RAW_CELL)
		pseudo_header->atm.flags |= ATM_RAW_CELL;

	aal_type = frame4->atm_info.AppTrafType & ATT_AALTYPE;
	hl_type = frame4->atm_info.AppTrafType & ATT_HLTYPE;
	vpi = pletoh16(&frame4->atm_info.Vpi);
	vci = pletoh16(&frame4->atm_info.Vci);

	switch (aal_type) {

	case ATT_AAL_UNKNOWN:
		/*
		 * Map ATT_AAL_UNKNOWN on VPI 0, VCI 5 to ATT_AAL_SIGNALLING,
		 * as that's the VPCI used for signalling.
		 *
		 * XXX - is this necessary, or will frames to 0/5 always
		 * have ATT_AAL_SIGNALLING?
		 */
		if (vpi == 0 && vci == 5)
			pseudo_header->atm.aal = AAL_SIGNALLING;
		else
			pseudo_header->atm.aal = AAL_UNKNOWN;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	case ATT_AAL1:
		pseudo_header->atm.aal = AAL_1;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	case ATT_AAL3_4:
		pseudo_header->atm.aal = AAL_3_4;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	case ATT_AAL5:
		pseudo_header->atm.aal = AAL_5;
		switch (hl_type) {

		case ATT_HL_UNKNOWN:
			pseudo_header->atm.type = TRAF_UNKNOWN;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;

		case ATT_HL_LLCMX:
			pseudo_header->atm.type = TRAF_LLCMX;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;

		case ATT_HL_VCMX:
			pseudo_header->atm.type = TRAF_VCMX;
			switch (frame4->atm_info.AppHLType) {

			case AHLT_UNKNOWN:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case AHLT_VCMX_802_3_FCS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_802_3_FCS;
				break;

			case AHLT_VCMX_802_4_FCS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_802_4_FCS;
				break;

			case AHLT_VCMX_802_5_FCS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_802_5_FCS;
				break;

			case AHLT_VCMX_FDDI_FCS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_FDDI_FCS;
				break;

			case AHLT_VCMX_802_6_FCS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_802_6_FCS;
				break;

			case AHLT_VCMX_802_3:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_802_3;
				break;

			case AHLT_VCMX_802_4:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_802_4;
				break;

			case AHLT_VCMX_802_5:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_802_5;
				break;

			case AHLT_VCMX_FDDI:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_FDDI;
				break;

			case AHLT_VCMX_802_6:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_802_6;
				break;

			case AHLT_VCMX_FRAGMENTS:
				pseudo_header->atm.subtype =
				    TRAF_ST_VCMX_FRAGMENTS;
				break;

			case AHLT_VCMX_BPDU:
				pseudo_header->atm.subtype = TRAF_ST_VCMX_BPDU;
				break;

			default:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;
			}
			break;

		case ATT_HL_LANE:
			pseudo_header->atm.type = TRAF_LANE;
			switch (frame4->atm_info.AppHLType) {

			case AHLT_UNKNOWN:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case AHLT_LANE_LE_CTRL:
				pseudo_header->atm.subtype =
				    TRAF_ST_LANE_LE_CTRL;
				break;

			case AHLT_LANE_802_3:
				pseudo_header->atm.subtype = TRAF_ST_LANE_802_3;
				break;

			case AHLT_LANE_802_5:
				pseudo_header->atm.subtype = TRAF_ST_LANE_802_5;
				break;

			case AHLT_LANE_802_3_MC:
				pseudo_header->atm.subtype =
				    TRAF_ST_LANE_802_3_MC;
				break;

			case AHLT_LANE_802_5_MC:
				pseudo_header->atm.subtype =
				    TRAF_ST_LANE_802_5_MC;
				break;

			default:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;
			}
			break;

		case ATT_HL_ILMI:
			pseudo_header->atm.type = TRAF_ILMI;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;

		case ATT_HL_FRMR:
			pseudo_header->atm.type = TRAF_FR;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;

		case ATT_HL_SPANS:
			pseudo_header->atm.type = TRAF_SPANS;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;

		case ATT_HL_IPSILON:
			pseudo_header->atm.type = TRAF_IPSILON;
			switch (frame4->atm_info.AppHLType) {

			case AHLT_UNKNOWN:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;

			case AHLT_IPSILON_FT0:
				pseudo_header->atm.subtype =
				    TRAF_ST_IPSILON_FT0;
				break;

			case AHLT_IPSILON_FT1:
				pseudo_header->atm.subtype =
				    TRAF_ST_IPSILON_FT1;
				break;

			case AHLT_IPSILON_FT2:
				pseudo_header->atm.subtype =
				    TRAF_ST_IPSILON_FT2;
				break;

			default:
				pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
				break;
			}
			break;

		default:
			pseudo_header->atm.type = TRAF_UNKNOWN;
			pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
			break;
		}
		break;

	case ATT_AAL_USER:
		pseudo_header->atm.aal = AAL_USER;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	case ATT_AAL_SIGNALLING:
		pseudo_header->atm.aal = AAL_SIGNALLING;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	case ATT_OAMCELL:
		pseudo_header->atm.aal = AAL_OAMCELL;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;

	default:
		pseudo_header->atm.aal = AAL_UNKNOWN;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
		break;
	}
	pseudo_header->atm.vpi = vpi;
	pseudo_header->atm.vci = vci;
	pseudo_header->atm.channel = pletoh16(&frame4->atm_info.channel);
	pseudo_header->atm.cells = pletoh16(&frame4->atm_info.cells);
	pseudo_header->atm.aal5t_u2u = pletoh16(&frame4->atm_info.Trailer.aal5t_u2u);
	pseudo_header->atm.aal5t_len = pletoh16(&frame4->atm_info.Trailer.aal5t_len);
	pseudo_header->atm.aal5t_chksum = pntoh32(&frame4->atm_info.Trailer.aal5t_chksum);
}

static void
set_pseudo_header_frame6(wtap *wth, union wtap_pseudo_header *pseudo_header,
    struct frame6_rec *frame6 _U_)
{
	/* XXX - Once the frame format is divined, something will most likely go here */

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* XXX - is there an FCS? */
		pseudo_header->eth.fcs_len = -1;
		break;
	}
}

/*
 * OK, this capture is from an "Internetwork analyzer", and we either
 * didn't see a type 7 record or it had a network type such as NET_HDLC
 * that doesn't tell us which *particular* HDLC derivative this is;
 * let's look at the first few bytes of the packet, a pointer to which
 * was passed to us as an argument, and see whether it looks like PPP,
 * Frame Relay, Wellfleet HDLC, Cisco HDLC, or LAPB - or, if it's none
 * of those, assume it's LAPD.
 *
 * (XXX - are there any "Internetwork analyzer" captures that don't
 * have type 7 records?  If so, is there some other field that will
 * tell us what type of capture it is?)
 */
static int
infer_pkt_encap(const uint8_t *pd, int len)
{
	int i;

	if (len <= 0) {
		/*
		 * Nothing to infer, but it doesn't matter how you
		 * dissect an empty packet.  Let's just say PPP.
		 */
		return WTAP_ENCAP_PPP_WITH_PHDR;
	}

	if (pd[0] == 0xFF) {
		/*
		 * PPP.  (XXX - check for 0xFF 0x03?)
		 */
		return WTAP_ENCAP_PPP_WITH_PHDR;
	}

	if (len >= 2) {
		if (pd[0] == 0x07 && pd[1] == 0x03) {
			/*
			 * Wellfleet HDLC.
			 */
			return WTAP_ENCAP_WFLEET_HDLC;
		} else if ((pd[0] == 0x0F && pd[1] == 0x00) ||
			   (pd[0] == 0x8F && pd[1] == 0x00)) {
			/*
			 * Cisco HDLC.
			 */
			return WTAP_ENCAP_CHDLC_WITH_PHDR;
		}

		/*
		 * Check for Frame Relay.  Look for packets with at least
		 * 3 bytes of header - 2 bytes of DLCI followed by 1 byte
		 * of control, which, for now, we require to be 0x03 (UI),
		 * although there might be other frame types as well.
		 * Scan forward until we see the last DLCI byte, with
		 * the low-order bit being 1, and then check the next
		 * byte, if it exists, to see if it's a control byte.
		 *
		 * XXX - in version 4 and 5 captures, wouldn't this just
		 * have a capture subtype of NET_FRAME_RELAY?  Or is this
		 * here only to handle other versions of the capture
		 * file, where we might just not yet have found where
		 * the subtype is specified in the capture?
		 *
		 * Bay Networks/Nortel Networks had a mechanism in the Optivity
		 * software for some of their routers to save captures
		 * in Sniffer format; they use a version number of 4.9, but
		 * don't put out any header records before the first FRAME2
		 * record. That means we have to use heuristics to guess
		 * what type of packet we have.
		 */
		for (i = 0; i < len && (pd[i] & 0x01) == 0; i++)
			;
		if (i >= len - 1) {
			/*
			 * Either all the bytes have the low-order bit
			 * clear, so we didn't even find the last DLCI
			 * byte, or the very last byte had the low-order
			 * bit set, so, if that's a DLCI, it fills the
			 * buffer, so there is no control byte after
			 * the last DLCI byte.
			 */
			return WTAP_ENCAP_LAPB;
		}
		i++;	/* advance to the byte after the last DLCI byte */
		if (pd[i] == 0x03)
			return WTAP_ENCAP_FRELAY_WITH_PHDR;
	}

	/*
	 * Assume LAPB, for now.  If we support other HDLC encapsulations,
	 * we can check whether the low-order bit of the first byte is
	 * set (as it should be for LAPB) if no other checks pass.
	 *
	 * Or, if it's truly impossible to distinguish ISDN from non-ISDN
	 * captures, we could assume it's ISDN if it's not anything
	 * else.
	 */
	return WTAP_ENCAP_LAPB;
}

static int
fix_pseudo_header(int encap, wtap_rec *rec, int len)
{
	const uint8_t *pd;
	union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;

	pd = ws_buffer_start_ptr(&rec->data);
	switch (encap) {

	case WTAP_ENCAP_PER_PACKET:
		/*
		 * Infer the packet type from the first two bytes.
		 */
		encap = infer_pkt_encap(pd, len);

		/*
		 * Fix up the pseudo-header to match the new
		 * encapsulation type.
		 */
		switch (encap) {

		case WTAP_ENCAP_WFLEET_HDLC:
		case WTAP_ENCAP_CHDLC_WITH_PHDR:
		case WTAP_ENCAP_PPP_WITH_PHDR:
			if (pseudo_header->dte_dce.flags == 0)
				pseudo_header->p2p.sent = true;
			else
				pseudo_header->p2p.sent = false;
			break;

		case WTAP_ENCAP_ISDN:
			if (pseudo_header->dte_dce.flags == 0x00)
				pseudo_header->isdn.uton = false;
			else
				pseudo_header->isdn.uton = true;

			/*
			 * XXX - this is currently a per-packet
			 * encapsulation type, and we can't determine
			 * whether a capture is an ISDN capture before
			 * seeing any packets, and B-channel PPP packets
			 * look like PPP packets and are given
			 * WTAP_ENCAP_PPP_WITH_PHDR, not WTAP_ENCAP_ISDN,
			 * so we assume this is a D-channel packet and
			 * thus give it a channel number of 0.
			 */
			pseudo_header->isdn.channel = 0;
			break;
		}
		break;

	case WTAP_ENCAP_ATM_PDUS:
		/*
		 * If the Windows Sniffer writes out one of its ATM
		 * capture files in DOS Sniffer format, it doesn't
		 * distinguish between LE Control and LANE encapsulated
		 * LAN frames, it just marks them as LAN frames,
		 * so we fix that up here.
		 *
		 * I've also seen DOS Sniffer captures claiming that
		 * LANE packets that *don't* start with FF 00 are
		 * marked as LE Control frames, so we fix that up
		 * as well.
		 */
		if (pseudo_header->atm.type == TRAF_LANE && len >= 2) {
			if (pd[0] == 0xff && pd[1] == 0x00) {
				/*
				 * This must be LE Control.
				 */
				pseudo_header->atm.subtype =
				    TRAF_ST_LANE_LE_CTRL;
			} else {
				/*
				 * This can't be LE Control.
				 */
				if (pseudo_header->atm.subtype ==
				    TRAF_ST_LANE_LE_CTRL) {
					/*
					 * XXX - Ethernet or Token Ring?
					 */
					pseudo_header->atm.subtype =
					    TRAF_ST_LANE_802_3;
				}
			}
		}
		break;
	}
	return encap;
}

/* Throw away the buffers used by the sequential I/O stream, but not
   those used by the random I/O stream. */
static void
ngsniffer_sequential_close(wtap *wth)
{
	ngsniffer_t *ngsniffer;

	ngsniffer = (ngsniffer_t *)wth->priv;
	if (ngsniffer->seq.buf != NULL) {
		g_free(ngsniffer->seq.buf);
		ngsniffer->seq.buf = NULL;
	}
}

static void
free_blob(void *data, void *user_data _U_)
{
	g_free(data);
}

/* Close stuff used by the random I/O stream, if any, and free up any
   private data structures.  (If there's a "sequential_close" routine
   for a capture file type, it'll be called before the "close" routine
   is called, so we don't have to free the sequential buffer here.) */
static void
ngsniffer_close(wtap *wth)
{
	ngsniffer_t *ngsniffer;

	ngsniffer = (ngsniffer_t *)wth->priv;
	g_free(ngsniffer->rand.buf);
	g_list_foreach(ngsniffer->first_blob, free_blob, NULL);
	g_list_free(ngsniffer->first_blob);
}

typedef struct {
	bool first_frame;
	time_t start;
} ngsniffer_dump_t;

static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	1,		/* WTAP_ENCAP_ETHERNET */
	0,		/* WTAP_ENCAP_TOKEN_RING */
	-1,		/* WTAP_ENCAP_SLIP -> unsupported */
	7,		/* WTAP_ENCAP_PPP -> Internetwork analyzer (synchronous) FIXME ! */
	9,		/* WTAP_ENCAP_FDDI */
	9,		/* WTAP_ENCAP_FDDI_BITSWAPPED */
	-1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
	2,		/* WTAP_ENCAP_ARCNET */
	-1,		/* WTAP_ENCAP_ARCNET_LINUX -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP */
	7,		/* WTAP_ENCAP_LAPB -> Internetwork analyzer (synchronous) */
	-1,		/* WTAP_ENCAP_ATM_PDUS */
	-1,		/* WTAP_ENCAP_NULL -> unsupported */
	-1,		/* WTAP_ENCAP_ASCEND -> unsupported */
	-1,		/* WTAP_ENCAP_ISDN -> unsupported */
	-1,		/* WTAP_ENCAP_IP_OVER_FC -> unsupported */
	7,		/* WTAP_ENCAP_PPP_WITH_PHDR -> Internetwork analyzer (synchronous) FIXME ! */
};
#define NUM_WTAP_ENCAPS array_length(wtap_encap)

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
static int
ngsniffer_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || (unsigned)encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNWRITABLE_ENCAP;

	return 0;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool
ngsniffer_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_)
{
	ngsniffer_dump_t *ngsniffer;
	char buf[6] = {REC_VERS, 0x00, 0x12, 0x00, 0x00, 0x00}; /* version record */

	/* This is a sniffer file */
	wdh->subtype_write = ngsniffer_dump;
	wdh->subtype_finish = ngsniffer_dump_finish;

	ngsniffer = g_new(ngsniffer_dump_t, 1);
	wdh->priv = (void *)ngsniffer;
	ngsniffer->first_frame = true;
	ngsniffer->start = 0;

	/* Write the file header. */
	if (!wtap_dump_file_write(wdh, ngsniffer_magic, sizeof ngsniffer_magic,
				  err))
		return false;
	if (!wtap_dump_file_write(wdh, buf, 6, err))
		return false;

	return true;
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool
ngsniffer_dump(wtap_dumper *wdh, const wtap_rec *rec,
	       int *err, char **err_info _U_)
{
	const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
	ngsniffer_dump_t *ngsniffer = (ngsniffer_dump_t *)wdh->priv;
	struct frame2_rec rec_hdr;
	char buf[6];
	time_t tsecs;
	uint64_t t;
	uint16_t t_low, t_med;
	uint8_t t_high;
	struct vers_rec version;
	int16_t maj_vers, min_vers;
	uint16_t start_date;
	struct tm *tm;

	/* We can only write packet records. */
	if (rec->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		*err_info = wtap_unwritable_rec_type_err_string(rec);
		return false;
	}

	/*
	 * Make sure this packet doesn't have a link-layer type that
	 * differs from the one for the file.
	 */
	if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
		*err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
		return false;
	}

	/* The captured length field is 16 bits, so there's a hard
	   limit of 65535. */
	if (rec->rec_header.packet_header.caplen > 65535) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return false;
	}

	/* Sniffer files have a capture start date in the file header, and
	   have times relative to the beginning of that day in the packet
	   headers; pick the date of the first packet as the capture start
	   date. */
	if (ngsniffer->first_frame) {
		ngsniffer->first_frame=false;
		tm = localtime(&rec->ts.secs);
		if (tm != NULL && tm->tm_year >= DOS_YEAR_OFFSET) {
			start_date = (tm->tm_year - DOS_YEAR_OFFSET) << DOS_YEAR_SHIFT;
			start_date |= (tm->tm_mon - DOS_MONTH_OFFSET) << DOS_MONTH_SHIFT;
			start_date |= tm->tm_mday << DOS_DAY_SHIFT;
			/* record the start date, not the start time */
			ngsniffer->start = rec->ts.secs - (3600*tm->tm_hour + 60*tm->tm_min + tm->tm_sec);
		} else {
			start_date = 0;
			ngsniffer->start = 0;
		}

		/* "sniffer" version ? */
		maj_vers = 4;
		min_vers = 0;
		version.maj_vers = GUINT16_TO_LE(maj_vers);
		version.min_vers = GUINT16_TO_LE(min_vers);
		version.time_dos = 0;
		version.date = GUINT16_TO_LE(start_date);
		version.type = 4;
		version.network = wtap_encap[wdh->file_encap];
		version.format = 1;
		version.timeunit = 1; /* 0.838096 */
		version.cmprs_vers = 0;
		version.cmprs_level = 0;
		version.rsvd[0] = 0;
		version.rsvd[1] = 0;
		if (!wtap_dump_file_write(wdh, &version, sizeof version, err))
			return false;
	}

	buf[0] = REC_FRAME2;
	buf[1] = 0x00;
	buf[2] = (char)((rec->rec_header.packet_header.caplen + sizeof(struct frame2_rec))%256);
	buf[3] = (char)((rec->rec_header.packet_header.caplen + sizeof(struct frame2_rec))/256);
	buf[4] = 0x00;
	buf[5] = 0x00;
	if (!wtap_dump_file_write(wdh, buf, 6, err))
		return false;
	/* Seconds since the start of the capture */
	tsecs = rec->ts.secs - ngsniffer->start;
	/* Extract the number of days since the start of the capture */
	rec_hdr.time_day = (uint8_t)(tsecs / 86400);	/* # days of capture - 86400 secs/day */
	tsecs -= rec_hdr.time_day * 86400;	/* time within day */
	/* Convert to picoseconds */
	t = tsecs*UINT64_C(1000000000000) +
		rec->ts.nsecs*UINT64_C(1000);
	/* Convert to units of timeunit = 1 */
	t /= Psec[1];
	t_low = (uint16_t)((t >> 0) & 0xFFFF);
	t_med = (uint16_t)((t >> 16) & 0xFFFF);
	t_high = (uint8_t)((t >> 32) & 0xFF);
	rec_hdr.time_low = GUINT16_TO_LE(t_low);
	rec_hdr.time_med = GUINT16_TO_LE(t_med);
	rec_hdr.time_high = t_high;
	rec_hdr.size = GUINT16_TO_LE(rec->rec_header.packet_header.caplen);
	switch (wdh->file_encap) {

	case WTAP_ENCAP_LAPB:
	case WTAP_ENCAP_FRELAY_WITH_PHDR:
		rec_hdr.fs = (pseudo_header->dte_dce.flags & FROM_DCE) ? 0x00 : FS_WAN_DTE;
		break;

	case WTAP_ENCAP_PPP_WITH_PHDR:
	case WTAP_ENCAP_SDLC:
		rec_hdr.fs = pseudo_header->p2p.sent ? 0x00 : FS_WAN_DTE;
		break;

	case WTAP_ENCAP_ISDN:
		rec_hdr.fs = pseudo_header->isdn.uton ? FS_WAN_DTE : 0x00;
		switch (pseudo_header->isdn.channel) {

		case 0:		/* D-channel */
			rec_hdr.fs |= FS_ISDN_CHAN_D;
			break;

		case 1:		/* B1-channel */
			rec_hdr.fs |= FS_ISDN_CHAN_B1;
			break;

		case 2:		/* B2-channel */
			rec_hdr.fs |= FS_ISDN_CHAN_B2;
			break;
		}
		break;

	default:
		rec_hdr.fs = 0;
		break;
	}
	rec_hdr.flags = 0;
	rec_hdr.true_size = rec->rec_header.packet_header.len != rec->rec_header.packet_header.caplen ? GUINT16_TO_LE(rec->rec_header.packet_header.len) : 0;
	rec_hdr.rsvd = 0;
	if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
		return false;
	if (!wtap_dump_file_write(wdh, ws_buffer_start_ptr(&rec->data),
	    rec->rec_header.packet_header.caplen, err))
		return false;
	return true;
}

/* Finish writing to a dump file.
   Returns true on success, false on failure. */
static bool
ngsniffer_dump_finish(wtap_dumper *wdh, int *err, char **err_info _U_)
{
	/* EOF record */
	char buf[6] = {REC_EOF, 0x00, 0x00, 0x00, 0x00, 0x00};

	if (!wtap_dump_file_write(wdh, buf, 6, err))
		return false;
	return true;
}

/*
   SnifferDecompress() decompresses a blob of compressed data from a
   Sniffer(R) capture file.

   This function is Copyright (c) 1999-2999 Tim Farley

   Parameters
      inbuf - buffer of compressed bytes from file, not including
	      the preceding length word
      inlen - length of inbuf in bytes (max 64k)
      outbuf - decompressed contents, could contain a partial Sniffer
	      record at the end.
      outlen - length of outbuf.
      err - return error code here
      err_info - for WTAP_ERR_DECOMPRESS, return descriptive string here

   Return value is the number of bytes in outbuf on return.
*/

/*
 * Make sure we have at least "length" bytes remaining
 * in the input buffer.
 */
#define CHECK_INPUT_POINTER( length ) \
	if ( pin + (length - 1) >= pin_end ) \
	{ \
		*err = WTAP_ERR_DECOMPRESS; \
		*err_info = g_strdup("ngsniffer: Compressed data item goes past the end of the compressed block"); \
		return ( -1 ); \
	}

/*
 * Make sure the byte containing the high order part of a buffer
 * offset is present.
 *
 * If it is, then fetch it and combine it with the low-order part.
 */
#define FETCH_OFFSET_HIGH \
	CHECK_INPUT_POINTER( 1 ); \
	offset = code_low + ((unsigned int)(*pin++) << 4) + 3;

/*
 * Make sure the output buffer is big enough to get "length"
 * bytes added to it.
 */
#define CHECK_OUTPUT_LENGTH( length ) \
	if ( pout + length > pout_end ) \
	{ \
		*err = WTAP_ERR_UNC_OVERFLOW; \
		return ( -1 ); \
	}

/*
 * Make sure we have another byte to fetch, and then fetch it and
 * append it to the buffer "length" times.
 */
#define APPEND_RLE_BYTE( length ) \
	/* If length would put us past end of output, avoid overflow */ \
	CHECK_OUTPUT_LENGTH( length ); \
	CHECK_INPUT_POINTER( 1 ); \
	memset( pout, *pin++, length ); \
	pout += length;

/*
 * Make sure the specified offset and length refer, in the output
 * buffer, to data that's entirely within the part of the output
 * buffer that we've already filled in.
 *
 * Then append the string from the specified offset, with the
 * specified length, to the output buffer.
 */
#define APPEND_LZW_STRING( offset, length ) \
	/* If length would put us past end of output, avoid overflow */ \
	CHECK_OUTPUT_LENGTH( length ); \
	/* Check if offset would put us back past begin of buffer */ \
	if ( pout - offset < outbuf ) \
	{ \
		*err = WTAP_ERR_DECOMPRESS; \
		*err_info = g_strdup("ngsniffer: LZ77 compressed data has bad offset to string"); \
		return ( -1 ); \
	} \
	/* Check if offset would cause us to copy on top of ourselves */ \
	if ( pout - offset + length > pout ) \
	{ \
		*err = WTAP_ERR_DECOMPRESS; \
		*err_info = g_strdup("ngsniffer: LZ77 compressed data has bad offset to string"); \
		return ( -1 ); \
	} \
	/* Copy the string from previous text to output position, \
	   advance output pointer */ \
	memcpy( pout, pout - offset, length ); \
	pout += length;

static int
SnifferDecompress(unsigned char *inbuf, size_t inlen, unsigned char *outbuf,
		  size_t outlen, int *err, char **err_info)
{
	unsigned char * pin  = inbuf;
	unsigned char * pout = outbuf;
	unsigned char * pin_end  = pin + inlen;
	unsigned char * pout_end = pout + outlen;
	unsigned int bit_mask;      /* one bit is set in this, to mask with bit_value */
	unsigned int bit_value = 0; /* cache the last 16 coding bits we retrieved */
	unsigned int code_type;     /* encoding type, from high 4 bits of byte */
	unsigned int code_low;      /* other 4 bits from encoding byte */
	int length;		    /* length of RLE sequence or repeated string */
	int offset;		    /* offset of string to repeat */

	if (inlen > UINT16_MAX) {
		return ( -1 );
	}

	bit_mask  = 0;  /* don't have any bits yet */
	/* Process until we've consumed all the input */
	while (pin < pin_end)
	{
		/* Shift down the bit mask we use to see what's encoded */
		bit_mask = bit_mask >> 1;

		/* If there are no bits left, time to get another 16 bits */
		if ( 0 == bit_mask )
		{
			/* make sure there are at least *three* bytes
			   available - the two bytes of the bit value,
			   plus one byte after it */
			CHECK_INPUT_POINTER( 3 );
			bit_mask  = 0x8000;  /* start with the high bit */
			bit_value = pletoh16(pin);   /* get the next 16 bits */
			pin += 2;          /* skip over what we just grabbed */
		}

		/* Use the bits in bit_value to see what's encoded and what is raw data */
		if ( !(bit_mask & bit_value) )
		{
			/* bit not set - raw byte we just copy */

			/* If length would put us past end of output, avoid overflow */
			CHECK_OUTPUT_LENGTH( 1 );
			*(pout++) = *(pin++);
		}
		else
		{
			/* bit set - next item is encoded.  Peel off high nybble
			   of next byte to see the encoding type.  Set aside low
			   nybble while we are at it */
			code_type = (unsigned int) ((*pin) >> 4 ) & 0xF;
			code_low  = (unsigned int) ((*pin) & 0xF );
			pin++;   /* increment over the code byte we just retrieved */

			/* Based on the code type, decode the compressed string */
			switch ( code_type )
			{
			case 0  :   /* RLE short runs */
				/*
				  Run length is the low nybble of the first code byte.
				  Byte to repeat immediately follows.
				  Total code size: 2 bytes.
				*/
				length = code_low + 3;

				/* check the length and then, if it's OK,
				   generate the repeated series of bytes */
				APPEND_RLE_BYTE( length );
				break;
			case 1  :   /* RLE long runs */
				/*
				  Low 4 bits of run length is the low nybble of the
				  first code byte, upper 8 bits of run length is in
				  the next byte.
				  Byte to repeat immediately follows.
				  Total code size: 3 bytes.
				*/
				CHECK_INPUT_POINTER( 1 );
				length = code_low + ((unsigned int)(*pin++) << 4) + 19;

				/* check the length and then, if it's OK,
				   generate the repeated series of bytes */
				APPEND_RLE_BYTE( length );
				break;
			case 2  :   /* LZ77 long strings */
				/*
				  Low 4 bits of offset to string is the low nybble of the
				  first code byte, upper 8 bits of offset is in
				  the next byte.
				  Length of string immediately follows.
				  Total code size: 3 bytes.
				*/
				FETCH_OFFSET_HIGH;

				/* get length from next byte, make sure it won't overrun buf */
				CHECK_INPUT_POINTER( 1 );
				length = (unsigned int)(*pin++) + 16;

				/* check the offset and length and then, if
				   they're OK, copy the data */
				APPEND_LZW_STRING( offset, length );
				break;
			default :   /* (3 to 15): LZ77 short strings */
				/*
				  Low 4 bits of offset to string is the low nybble of the
				  first code byte, upper 8 bits of offset is in
				  the next byte.
				  Length of string to repeat is overloaded into code_type.
				  Total code size: 2 bytes.
				*/
				FETCH_OFFSET_HIGH;

				/* get length from code_type */
				length = code_type;

				/* check the offset and length and then, if
				   they're OK, copy the data */
				APPEND_LZW_STRING( offset, length );
				break;
			}
		}
	}

	return (int) ( pout - outbuf );  /* return length of expanded text */
}

/*
 * XXX - is there any guarantee that 65535 bytes is big enough to hold the
 * uncompressed data from any blob?
 */
#define	OUTBUF_SIZE	65536
#define	INBUF_SIZE	65536

/* Information about a compressed blob; we save the offset in the
   underlying compressed file, and the offset in the uncompressed data
   stream, of the blob. */
typedef struct {
	int64_t	blob_comp_offset;
	int64_t	blob_uncomp_offset;
} blob_info_t;

static bool
ng_read_bytes_or_eof(wtap *wth, void *buffer, unsigned int nbytes, bool is_random,
    int *err, char **err_info)
{
	ngsniffer_t *ngsniffer;
	FILE_T infile;
	ngsniffer_comp_stream_t *comp_stream;
	unsigned char *outbuffer = (unsigned char *)buffer; /* where to write next decompressed data */
	blob_info_t *blob;
	unsigned int bytes_to_copy;
	unsigned int bytes_left;

	ngsniffer = (ngsniffer_t *)wth->priv;
	if (is_random) {
		infile = wth->random_fh;
		comp_stream = &ngsniffer->rand;
	} else {
		infile = wth->fh;
		comp_stream = &ngsniffer->seq;
	}

	if (!ngsniffer->is_compressed) {
		/* Uncompressed - just read bytes */
		if (!wtap_read_bytes_or_eof(infile, buffer, nbytes, err, err_info))
			return false;
		comp_stream->uncomp_offset += nbytes;
		comp_stream->comp_offset += nbytes;
		return true;
	}

	/*
	 * Compressed.
	 *
	 * Allocate the stream buffer if it hasn't already been allocated.
	 */
	if (comp_stream->buf == NULL) {
		comp_stream->buf = (unsigned char *)g_malloc(OUTBUF_SIZE);

		if (is_random) {
			/* This is the first read of the random file, so we're at
			   the beginning of the sequence of blobs in the file
			   (as we've not done any random reads yet to move the
			   current position in the random stream); set the
			   current blob to be the first blob. */
			ngsniffer->current_blob = ngsniffer->first_blob;
		} else {
			/* This is the first sequential read; if we also have a
			   random stream open, allocate the first element for the
			   list of blobs, and make it the last element as well. */
			if (wth->random_fh != NULL) {
				ws_assert(ngsniffer->first_blob == NULL);
				blob = g_new(blob_info_t,1);
				blob->blob_comp_offset = comp_stream->comp_offset;
				blob->blob_uncomp_offset = comp_stream->uncomp_offset;
				ngsniffer->first_blob = g_list_append(ngsniffer->first_blob,
								      blob);
				ngsniffer->last_blob = ngsniffer->first_blob;
			}
		}

		/* Now read the first blob into the buffer. */
		if (!read_blob(infile, comp_stream, err, err_info))
			return false;
	}
	while (nbytes > 0) {
		bytes_left = comp_stream->nbytes - comp_stream->nextout;
		if (bytes_left == 0) {
			/* There's no decompressed stuff left to copy from the current
			   blob; get the next blob. */

			if (is_random) {
				/* Move to the next blob in the list. */
				ngsniffer->current_blob = g_list_next(ngsniffer->current_blob);
				if (!ngsniffer->current_blob) {
					/*
					 * XXX - this "can't happen"; we should have a
					 * blob for every byte in the file.
					 */
					*err = WTAP_ERR_CANT_SEEK;
					return false;
				}
			} else {
				/* If we also have a random stream open, add a new element,
				   for this blob, to the list of blobs; we know the list is
				   non-empty, as we initialized it on the first sequential
				   read, so we just add the new element at the end, and
				   adjust the pointer to the last element to refer to it. */
				if (wth->random_fh != NULL) {
					blob = g_new(blob_info_t,1);
					blob->blob_comp_offset = comp_stream->comp_offset;
					blob->blob_uncomp_offset = comp_stream->uncomp_offset;
					ngsniffer->last_blob = g_list_append(ngsniffer->last_blob,
									     blob);
				}
			}

			if (!read_blob(infile, comp_stream, err, err_info))
				return false;
			bytes_left = comp_stream->nbytes - comp_stream->nextout;
		}

		bytes_to_copy = nbytes;
		if (bytes_to_copy > bytes_left)
			bytes_to_copy = bytes_left;
		memcpy(outbuffer, &comp_stream->buf[comp_stream->nextout],
		       bytes_to_copy);
		nbytes -= bytes_to_copy;
		outbuffer += bytes_to_copy;
		comp_stream->nextout += bytes_to_copy;
		comp_stream->uncomp_offset += bytes_to_copy;
	}
	return true;
}

static bool
ng_read_bytes(wtap *wth, void *buffer, unsigned int nbytes, bool is_random,
    int *err, char **err_info)
{
	if (!ng_read_bytes_or_eof(wth, buffer, nbytes, is_random, err, err_info)) {
		/*
		 * In this case, even reading zero bytes, because we're at
		 * the end of the file, is a short read.
		 */
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return false;
	}
	return true;
}

/* Read a blob from a compressed stream.
   Return false and set "*err" and "*err_info" on error, otherwise return true. */
static bool
read_blob(FILE_T infile, ngsniffer_comp_stream_t *comp_stream, int *err,
	  char **err_info)
{
	int in_len;
	unsigned short blob_len;
	int16_t blob_len_host;
	bool uncompressed;
	unsigned char *file_inbuf;
	int out_len;

	/* Read one 16-bit word which is length of next compressed blob */
	if (!wtap_read_bytes_or_eof(infile, &blob_len, 2, err, err_info))
		return false;
	comp_stream->comp_offset += 2;
	blob_len_host = pletoh16(&blob_len);

	/* Compressed or uncompressed? */
	if (blob_len_host < 0) {
		/* Uncompressed blob; blob length is absolute value of the number. */
		in_len = -blob_len_host;
		uncompressed = true;
	} else {
		in_len = blob_len_host;
		uncompressed = false;
	}

	file_inbuf = (unsigned char *)g_malloc(INBUF_SIZE);

	/* Read the blob */
	if (!wtap_read_bytes(infile, file_inbuf, in_len, err, err_info)) {
		g_free(file_inbuf);
		return false;
	}
	comp_stream->comp_offset += in_len;

	if (uncompressed) {
		memcpy(comp_stream->buf, file_inbuf, in_len);
		out_len = in_len;
	} else {
		/* Decompress the blob */
		out_len = SnifferDecompress(file_inbuf, in_len,
					    comp_stream->buf, OUTBUF_SIZE, err,
					    err_info);
		if (out_len < 0) {
			g_free(file_inbuf);
			return false;
		}
	}

	g_free(file_inbuf);
	comp_stream->nextout = 0;
	comp_stream->nbytes = out_len;
	return true;
}

/* Skip some number of bytes forward in the sequential stream. */
static bool
ng_skip_bytes_seq(wtap *wth, unsigned int count, int *err, char **err_info)
{
	ngsniffer_t *ngsniffer;
	char *buf;
	unsigned int amount_to_read;

	ngsniffer = (ngsniffer_t *)wth->priv;

	if (!ngsniffer->is_compressed) {
		/* Uncompressed - just read forward and discard data */
		ngsniffer->seq.uncomp_offset += count;
		return wtap_read_bytes(wth->fh, NULL, count, err, err_info);
	}

	/*
	 * Compressed.
	 *
	 * Now read and discard "count" bytes.
	 */
	buf = (char *)g_malloc(INBUF_SIZE);
	while (count != 0) {
		if (count > INBUF_SIZE)
			amount_to_read = INBUF_SIZE;
		else
			amount_to_read = count;

		if (!ng_read_bytes(wth, buf, amount_to_read, false, err, err_info)) {
			g_free(buf);
			return false;	/* error */
		}

		count -= amount_to_read;
	}

	g_free(buf);
	return true;
}

/* Seek to a given offset in the random data stream.

   On compressed files, we see whether we're seeking to a position within
   the blob we currently have in memory and, if not, we find in the list
   of blobs the last blob that starts at or before the position to which
   we're seeking, and read that blob in.  We can then move to the appropriate
   position within the blob we have in memory (whether it's the blob we
   already had in memory or, if necessary, the one we read in). */
static bool
ng_file_seek_rand(wtap *wth, int64_t offset, int *err, char **err_info)
{
	ngsniffer_t *ngsniffer;
	int64_t delta;
	GList *new_list, *next_list;
	blob_info_t *next_blob, *new_blob;

	ngsniffer = (ngsniffer_t *)wth->priv;

	if (!ngsniffer->is_compressed) {
		/* Uncompressed - just seek. */
		if (file_seek(wth->random_fh, offset, SEEK_SET, err) == -1)
			return false;
		return true;
	}

	/*
	 * Compressed.
	 *
	 * How many *uncompressed* should we move forward or
	 * backward?
	 */
	delta = offset - ngsniffer->rand.uncomp_offset;

	/* Is the place to which we're seeking within the current buffer, or
	   will we have to read a different blob into the buffer? */
	new_list = NULL;
	if (delta > 0) {
		/* We're going forwards.
		   Is the place to which we're seeking within the current buffer? */
		if ((size_t)(ngsniffer->rand.nextout + delta) >= ngsniffer->rand.nbytes) {
			/* No.  Search for a blob that contains the target
			   offset in the uncompressed byte stream. */
			if (ngsniffer->current_blob == NULL) {
				/* We haven't read anything from the random
				   file yet, so we have no current blob;
				   search all the blobs, starting with
				   the first one. */
				new_list = ngsniffer->first_blob;
			} else {
				/* We're seeking forward, so start searching
				   with the blob after the current one. */
				new_list = g_list_next(ngsniffer->current_blob);
			}
			while (new_list) {
				next_list = g_list_next(new_list);
				if (next_list == NULL) {
					/* No more blobs; the current one is it. */
					break;
				}

				next_blob = (blob_info_t *)next_list->data;
				/* Does the next blob start after the target offset?
				   If so, the current blob is the one we want. */
				if (next_blob->blob_uncomp_offset > offset)
					break;

				new_list = next_list;
			}
			if (new_list == NULL) {
				/*
				 * We're seeking past the end of what
				 * we've read so far.
				 */
				*err = WTAP_ERR_CANT_SEEK;
				return false;
			}
		}
	} else if (delta < 0) {
		/* We're going backwards.
		   Is the place to which we're seeking within the current buffer? */
		if (ngsniffer->rand.nextout + delta < 0) {
			/* No.  Search for a blob that contains the target
			   offset in the uncompressed byte stream. */
			if (ngsniffer->current_blob == NULL) {
				/* We haven't read anything from the random
				   file yet, so we have no current blob;
				   search all the blobs, starting with
				   the last one. */
				new_list = ngsniffer->last_blob;
			} else {
				/* We're seeking backward, so start searching
				   with the blob before the current one. */
				new_list = g_list_previous(ngsniffer->current_blob);
			}
			while (new_list) {
				/* Does this blob start at or before the target offset?
				   If so, the current blob is the one we want. */
				new_blob = (blob_info_t *)new_list->data;
				if (new_blob->blob_uncomp_offset <= offset)
					break;

				/* It doesn't - skip to the previous blob. */
				new_list = g_list_previous(new_list);
			}
			if (new_list == NULL) {
				/*
				 * XXX - shouldn't happen.
				 */
				*err = WTAP_ERR_CANT_SEEK;
				return false;
			}
		}
	}

	if (new_list != NULL) {
		/* The place to which we're seeking isn't in the current buffer;
		   move to a new blob. */
		new_blob = (blob_info_t *)new_list->data;

		/* Seek in the compressed file to the offset in the compressed file
		   of the beginning of that blob. */
		if (file_seek(wth->random_fh, new_blob->blob_comp_offset, SEEK_SET, err) == -1)
			return false;

		/*
		 * Do we have a buffer for the random stream yet?
		 */
		if (ngsniffer->rand.buf == NULL) {
			/*
			 * No - allocate it, as we'll be reading into it.
			 */
			ngsniffer->rand.buf = (unsigned char *)g_malloc(OUTBUF_SIZE);
		}

		/* Make the blob we found the current one. */
		ngsniffer->current_blob = new_list;

		/* Now set the current offsets to the offsets of the beginning
		   of the blob. */
		ngsniffer->rand.uncomp_offset = new_blob->blob_uncomp_offset;
		ngsniffer->rand.comp_offset = new_blob->blob_comp_offset;

		/* Now fill the buffer. */
		if (!read_blob(wth->random_fh, &ngsniffer->rand, err, err_info))
			return false;

		/* Set "delta" to the amount to move within this blob; it had
		   better be >= 0, and < the amount of uncompressed data in
		   the blob, as otherwise it'd mean we need to seek before
		   the beginning or after the end of this blob. */
		delta = offset - ngsniffer->rand.uncomp_offset;
		ws_assert(delta >= 0 && (unsigned long)delta < ngsniffer->rand.nbytes);
	}

	/* OK, the place to which we're seeking is in the buffer; adjust
	   "ngsniffer->rand.nextout" to point to the place to which
	   we're seeking, and adjust "ngsniffer->rand.uncomp_offset" to be
	   the destination offset. */
	ngsniffer->rand.nextout += (int) delta;
	ngsniffer->rand.uncomp_offset += delta;

	return true;
}

static const struct supported_block_type ngsniffer_uncompressed_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info ngsniffer_uncompressed_info = {
	"Sniffer (DOS)", "ngsniffer", "cap", "enc;trc;fdc;syc",
	false, BLOCKS_SUPPORTED(ngsniffer_uncompressed_blocks_supported),
	ngsniffer_dump_can_write_encap, ngsniffer_dump_open, NULL
};

static const struct supported_block_type ngsniffer_compressed_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info ngsniffer_compressed_info = {
	"Sniffer (DOS), compressed", "ngsniffer_comp", "cap", "enc;trc;fdc;syc",
	false, BLOCKS_SUPPORTED(ngsniffer_compressed_blocks_supported),
	NULL, NULL, NULL
};

void register_ngsniffer(void)
{
	ngsniffer_uncompressed_file_type_subtype = wtap_register_file_type_subtype(&ngsniffer_uncompressed_info);
	ngsniffer_compressed_file_type_subtype = wtap_register_file_type_subtype(&ngsniffer_compressed_info);

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("NGSNIFFER_UNCOMPRESSED",
	    ngsniffer_uncompressed_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("NGSNIFFER_COMPRESSED",
	    ngsniffer_compressed_file_type_subtype);
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
