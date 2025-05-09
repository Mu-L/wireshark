/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-t124.c                                                              */
/* asn2wrs.py -q -L -p t124 -c ./t124.cnf -s ./packet-t124-template -D . -O ../.. GCC-PROTOCOL.asn ../t125/MCS-PROTOCOL.asn */

/* packet-t124.c
 * Routines for t124 packet dissection
 * Copyright 2010, Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <wsutil/array.h>

#include <epan/asn1.h>
#include "packet-per.h"
#include "packet-ber.h"
#include "packet-t124.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "GENERIC-CONFERENCE-CONTROL T.124"
#define PSNAME "T.124"
#define PFNAME "t124"

void proto_register_t124(void);
void proto_reg_handoff_t124(void);

/* Initialize the protocol and registered fields */
static int proto_t124;
static proto_tree *top_tree;

static int hf_t124_object;                        /* T_object */
static int hf_t124_h221NonStandard;               /* H221NonStandardIdentifier */
static int hf_t124_key;                           /* Key */
static int hf_t124_data;                          /* OCTET_STRING */
static int hf_t124_UserData_item;                 /* UserData_item */
static int hf_t124_value;                         /* T_value */
static int hf_t124_numeric;                       /* SimpleNumericString */
static int hf_t124_text;                          /* SimpleTextString */
static int hf_t124_unicodeText;                   /* TextString */
static int hf_t124_passwordString;                /* PasswordSelector */
static int hf_t124_responseData;                  /* UserData */
static int hf_t124_passwordInTheClear;            /* NULL */
static int hf_t124_nonStandardAlgorithm;          /* NonStandardParameter */
static int hf_t124_responseAlgorithm;             /* ChallengeResponseAlgorithm */
static int hf_t124_challengeData;                 /* UserData */
static int hf_t124_challengeTag;                  /* INTEGER */
static int hf_t124_challengeSet;                  /* SET_OF_ChallengeItem */
static int hf_t124_challengeSet_item;             /* ChallengeItem */
static int hf_t124_responseItem;                  /* ChallengeResponseItem */
static int hf_t124_passwordInTheClear_01;         /* PasswordSelector */
static int hf_t124_challengeRequestResponse;      /* T_challengeRequestResponse */
static int hf_t124_challengeRequest;              /* ChallengeRequest */
static int hf_t124_challengeResponse;             /* ChallengeResponse */
static int hf_t124_nonStandardScheme;             /* NonStandardParameter */
static int hf_t124_priority;                      /* INTEGER_0_65535 */
static int hf_t124_scheme;                        /* ConferencePriorityScheme */
static int hf_t124_conventional;                  /* NULL */
static int hf_t124_counted;                       /* NULL */
static int hf_t124_anonymous;                     /* NULL */
static int hf_t124_nonStandardCategory;           /* NonStandardParameter */
static int hf_t124_conventional_only;             /* NULL */
static int hf_t124_counted_only;                  /* NULL */
static int hf_t124_anonymous_only;                /* NULL */
static int hf_t124_conventional_control;          /* NULL */
static int hf_t124_unrestricted_mode;             /* NULL */
static int hf_t124_non_standard_mode;             /* NonStandardParameter */
static int hf_t124_NetworkAddress_item;           /* NetworkAddress_item */
static int hf_t124_aggregatedChannel;             /* T_aggregatedChannel */
static int hf_t124_transferModes;                 /* T_transferModes */
static int hf_t124_speech;                        /* BOOLEAN */
static int hf_t124_voice_band;                    /* BOOLEAN */
static int hf_t124_digital_56k;                   /* BOOLEAN */
static int hf_t124_digital_64k;                   /* BOOLEAN */
static int hf_t124_digital_128k;                  /* BOOLEAN */
static int hf_t124_digital_192k;                  /* BOOLEAN */
static int hf_t124_digital_256k;                  /* BOOLEAN */
static int hf_t124_digital_320k;                  /* BOOLEAN */
static int hf_t124_digital_384k;                  /* BOOLEAN */
static int hf_t124_digital_512k;                  /* BOOLEAN */
static int hf_t124_digital_768k;                  /* BOOLEAN */
static int hf_t124_digital_1152k;                 /* BOOLEAN */
static int hf_t124_digital_1472k;                 /* BOOLEAN */
static int hf_t124_digital_1536k;                 /* BOOLEAN */
static int hf_t124_digital_1920k;                 /* BOOLEAN */
static int hf_t124_packet_mode;                   /* BOOLEAN */
static int hf_t124_frame_mode;                    /* BOOLEAN */
static int hf_t124_atm;                           /* BOOLEAN */
static int hf_t124_internationalNumber;           /* DiallingString */
static int hf_t124_subAddress;                    /* SubAddressString */
static int hf_t124_extraDialling;                 /* ExtraDiallingString */
static int hf_t124_highLayerCompatibility;        /* T_highLayerCompatibility */
static int hf_t124_telephony3kHz;                 /* BOOLEAN */
static int hf_t124_telephony7kHz;                 /* BOOLEAN */
static int hf_t124_videotelephony;                /* BOOLEAN */
static int hf_t124_videoconference;               /* BOOLEAN */
static int hf_t124_audiographic;                  /* BOOLEAN */
static int hf_t124_audiovisual;                   /* BOOLEAN */
static int hf_t124_multimedia;                    /* BOOLEAN */
static int hf_t124_transportConnection;           /* T_transportConnection */
static int hf_t124_nsapAddress;                   /* OCTET_STRING_SIZE_1_20 */
static int hf_t124_transportSelector;             /* OCTET_STRING */
static int hf_t124_nonStandard;                   /* NonStandardParameter */
static int hf_t124_callingNode;                   /* NULL */
static int hf_t124_calledNode;                    /* NULL */
static int hf_t124_unknown;                       /* INTEGER_0_4294967295 */
static int hf_t124_conferenceName;                /* ConferenceName */
static int hf_t124_conferenceNameModifier;        /* ConferenceNameModifier */
static int hf_t124_conferenceDescription;         /* TextString */
static int hf_t124_lockedConference;              /* BOOLEAN */
static int hf_t124_passwordInTheClearRequired;    /* BOOLEAN */
static int hf_t124_networkAddress;                /* NetworkAddress */
static int hf_t124_defaultConferenceFlag;         /* BOOLEAN */
static int hf_t124_conferenceMode;                /* ConferenceMode */
static int hf_t124_convenerPassword;              /* Password */
static int hf_t124_password;                      /* Password */
static int hf_t124_listedConference;              /* BOOLEAN */
static int hf_t124_conductibleConference;         /* BOOLEAN */
static int hf_t124_terminationMethod;             /* TerminationMethod */
static int hf_t124_conductorPrivileges;           /* SET_OF_Privilege */
static int hf_t124_conductorPrivileges_item;      /* Privilege */
static int hf_t124_conductedPrivileges;           /* SET_OF_Privilege */
static int hf_t124_conductedPrivileges_item;      /* Privilege */
static int hf_t124_nonConductedPrivileges;        /* SET_OF_Privilege */
static int hf_t124_nonConductedPrivileges_item;   /* Privilege */
static int hf_t124_callerIdentifier;              /* TextString */
static int hf_t124_userData_set_of;               /* UserData */
static int hf_t124_conferencePriority;            /* ConferencePriority */
static int hf_t124_nodeID;                        /* UserID */
static int hf_t124_tag;                           /* INTEGER */
static int hf_t124_result;                        /* T_result */
static int hf_t124_nodeType;                      /* NodeType */
static int hf_t124_asymmetryIndicator;            /* AsymmetryIndicator */
static int hf_t124_conferenceList;                /* SET_OF_ConferenceDescriptor */
static int hf_t124_conferenceList_item;           /* ConferenceDescriptor */
static int hf_t124_queryResponseResult;           /* QueryResponseResult */
static int hf_t124_waitForInvitationFlag;         /* BOOLEAN */
static int hf_t124_noUnlistedConferenceFlag;      /* BOOLEAN */
static int hf_t124_conferenceName_01;             /* ConferenceNameSelector */
static int hf_t124_password_01;                   /* PasswordChallengeRequestResponse */
static int hf_t124_convenerPassword_01;           /* PasswordSelector */
static int hf_t124_nodeCategory;                  /* NodeCategory */
static int hf_t124_topNodeID;                     /* UserID */
static int hf_t124_conferenceNameAlias;           /* ConferenceNameSelector */
static int hf_t124_joinResponseResult;            /* JoinResponseResult */
static int hf_t124_inviteResponseResult;          /* InviteResponseResult */
static int hf_t124_t124Identifier;                /* Key */
static int hf_t124_connectPDU;                    /* T_connectPDU */
static int hf_t124_conferenceCreateRequest;       /* ConferenceCreateRequest */
static int hf_t124_conferenceCreateResponse;      /* ConferenceCreateResponse */
static int hf_t124_conferenceQueryRequest;        /* ConferenceQueryRequest */
static int hf_t124_conferenceQueryResponse;       /* ConferenceQueryResponse */
static int hf_t124_conferenceJoinRequest;         /* ConferenceJoinRequest */
static int hf_t124_conferenceJoinResponse;        /* ConferenceJoinResponse */
static int hf_t124_conferenceInviteRequest;       /* ConferenceInviteRequest */
static int hf_t124_conferenceInviteResponse;      /* ConferenceInviteResponse */
static int hf_t124_heightLimit;                   /* INTEGER_0_MAX */
static int hf_t124_subHeight;                     /* INTEGER_0_MAX */
static int hf_t124_subInterval;                   /* INTEGER_0_MAX */
static int hf_t124_static;                        /* T_static */
static int hf_t124_channelId;                     /* StaticChannelId */
static int hf_t124_userId;                        /* T_userId */
static int hf_t124_joined;                        /* BOOLEAN */
static int hf_t124_userId_01;                     /* UserId */
static int hf_t124_private;                       /* T_private */
static int hf_t124_channelId_01;                  /* PrivateChannelId */
static int hf_t124_manager;                       /* UserId */
static int hf_t124_admitted;                      /* SET_OF_UserId */
static int hf_t124_admitted_item;                 /* UserId */
static int hf_t124_assigned;                      /* T_assigned */
static int hf_t124_channelId_02;                  /* AssignedChannelId */
static int hf_t124_mergeChannels;                 /* SET_OF_ChannelAttributes */
static int hf_t124_mergeChannels_item;            /* ChannelAttributes */
static int hf_t124_purgeChannelIds;               /* SET_OF_ChannelId */
static int hf_t124_purgeChannelIds_item;          /* ChannelId */
static int hf_t124_detachUserIds;                 /* SET_OF_UserId */
static int hf_t124_detachUserIds_item;            /* UserId */
static int hf_t124_grabbed;                       /* T_grabbed */
static int hf_t124_tokenId;                       /* TokenId */
static int hf_t124_grabber;                       /* UserId */
static int hf_t124_inhibited;                     /* T_inhibited */
static int hf_t124_inhibitors;                    /* SET_OF_UserId */
static int hf_t124_inhibitors_item;               /* UserId */
static int hf_t124_giving;                        /* T_giving */
static int hf_t124_recipient;                     /* UserId */
static int hf_t124_ungivable;                     /* T_ungivable */
static int hf_t124_given;                         /* T_given */
static int hf_t124_mergeTokens;                   /* SET_OF_TokenAttributes */
static int hf_t124_mergeTokens_item;              /* TokenAttributes */
static int hf_t124_purgeTokenIds;                 /* SET_OF_TokenId */
static int hf_t124_purgeTokenIds_item;            /* TokenId */
static int hf_t124_reason;                        /* Reason */
static int hf_t124_diagnostic;                    /* Diagnostic */
static int hf_t124_initialOctets;                 /* OCTET_STRING */
static int hf_t124_result_01;                     /* Result */
static int hf_t124_initiator;                     /* UserId */
static int hf_t124_userIds;                       /* SET_OF_UserId */
static int hf_t124_userIds_item;                  /* UserId */
static int hf_t124_channelId_03;                  /* ChannelId */
static int hf_t124_requested;                     /* ChannelId */
static int hf_t124_channelIds;                    /* SET_OF_ChannelId */
static int hf_t124_channelIds_item;               /* ChannelId */
static int hf_t124_dataPriority;                  /* DataPriority */
static int hf_t124_segmentation;                  /* Segmentation */
static int hf_t124_userData;                      /* T_userData */
static int hf_t124_userData_01;                   /* T_userData_01 */
static int hf_t124_userData_02;                   /* OCTET_STRING */
static int hf_t124_tokenStatus;                   /* TokenStatus */
static int hf_t124_plumbDomainIndication;         /* PlumbDomainIndication */
static int hf_t124_erectDomainRequest;            /* ErectDomainRequest */
static int hf_t124_mergeChannelsRequest;          /* MergeChannelsRequest */
static int hf_t124_mergeChannelsConfirm;          /* MergeChannelsConfirm */
static int hf_t124_purgeChannelsIndication;       /* PurgeChannelsIndication */
static int hf_t124_mergeTokensRequest;            /* MergeTokensRequest */
static int hf_t124_mergeTokensConfirm;            /* MergeTokensConfirm */
static int hf_t124_purgeTokensIndication;         /* PurgeTokensIndication */
static int hf_t124_disconnectProviderUltimatum;   /* DisconnectProviderUltimatum */
static int hf_t124_rejectMCSPDUUltimatum;         /* RejectMCSPDUUltimatum */
static int hf_t124_attachUserRequest;             /* AttachUserRequest */
static int hf_t124_attachUserConfirm;             /* AttachUserConfirm */
static int hf_t124_detachUserRequest;             /* DetachUserRequest */
static int hf_t124_detachUserIndication;          /* DetachUserIndication */
static int hf_t124_channelJoinRequest;            /* ChannelJoinRequest */
static int hf_t124_channelJoinConfirm;            /* ChannelJoinConfirm */
static int hf_t124_channelLeaveRequest;           /* ChannelLeaveRequest */
static int hf_t124_channelConveneRequest;         /* ChannelConveneRequest */
static int hf_t124_channelConveneConfirm;         /* ChannelConveneConfirm */
static int hf_t124_channelDisbandRequest;         /* ChannelDisbandRequest */
static int hf_t124_channelDisbandIndication;      /* ChannelDisbandIndication */
static int hf_t124_channelAdmitRequest;           /* ChannelAdmitRequest */
static int hf_t124_channelAdmitIndication;        /* ChannelAdmitIndication */
static int hf_t124_channelExpelRequest;           /* ChannelExpelRequest */
static int hf_t124_channelExpelIndication;        /* ChannelExpelIndication */
static int hf_t124_sendDataRequest;               /* SendDataRequest */
static int hf_t124_sendDataIndication;            /* SendDataIndication */
static int hf_t124_uniformSendDataRequest;        /* UniformSendDataRequest */
static int hf_t124_uniformSendDataIndication;     /* UniformSendDataIndication */
static int hf_t124_tokenGrabRequest;              /* TokenGrabRequest */
static int hf_t124_tokenGrabConfirm;              /* TokenGrabConfirm */
static int hf_t124_tokenInhibitRequest;           /* TokenInhibitRequest */
static int hf_t124_tokenInhibitConfirm;           /* TokenInhibitConfirm */
static int hf_t124_tokenGiveRequest;              /* TokenGiveRequest */
static int hf_t124_tokenGiveIndication;           /* TokenGiveIndication */
static int hf_t124_tokenGiveResponse;             /* TokenGiveResponse */
static int hf_t124_tokenGiveConfirm;              /* TokenGiveConfirm */
static int hf_t124_tokenPleaseRequest;            /* TokenPleaseRequest */
static int hf_t124_tokenPleaseIndication;         /* TokenPleaseIndication */
static int hf_t124_tokenReleaseRequest;           /* TokenReleaseRequest */
static int hf_t124_tokenReleaseConfirm;           /* TokenReleaseConfirm */
static int hf_t124_tokenTestRequest;              /* TokenTestRequest */
static int hf_t124_tokenTestConfirm;              /* TokenTestConfirm */
/* named bits */
static int hf_t124_Segmentation_begin;
static int hf_t124_Segmentation_end;

/* Initialize the subtree pointers */
static int ett_t124;
static int ett_t124_connectGCCPDU;

static int hf_t124_ConnectData;
static int hf_t124_connectGCCPDU;
static int hf_t124_DomainMCSPDU_PDU;

static uint32_t channelId = -1;

static dissector_table_t t124_ns_dissector_table;
static dissector_table_t t124_sd_dissector_table;

static int ett_t124_Key;
static int ett_t124_NonStandardParameter;
static int ett_t124_UserData;
static int ett_t124_UserData_item;
static int ett_t124_Password;
static int ett_t124_PasswordSelector;
static int ett_t124_ChallengeResponseItem;
static int ett_t124_ChallengeResponseAlgorithm;
static int ett_t124_ChallengeItem;
static int ett_t124_ChallengeRequest;
static int ett_t124_SET_OF_ChallengeItem;
static int ett_t124_ChallengeResponse;
static int ett_t124_PasswordChallengeRequestResponse;
static int ett_t124_T_challengeRequestResponse;
static int ett_t124_ConferenceName;
static int ett_t124_ConferenceNameSelector;
static int ett_t124_ConferencePriorityScheme;
static int ett_t124_ConferencePriority;
static int ett_t124_NodeCategory;
static int ett_t124_ConferenceMode;
static int ett_t124_NetworkAddress;
static int ett_t124_NetworkAddress_item;
static int ett_t124_T_aggregatedChannel;
static int ett_t124_T_transferModes;
static int ett_t124_T_highLayerCompatibility;
static int ett_t124_T_transportConnection;
static int ett_t124_AsymmetryIndicator;
static int ett_t124_ConferenceDescriptor;
static int ett_t124_ConferenceCreateRequest;
static int ett_t124_SET_OF_Privilege;
static int ett_t124_ConferenceCreateResponse;
static int ett_t124_ConferenceQueryRequest;
static int ett_t124_ConferenceQueryResponse;
static int ett_t124_SET_OF_ConferenceDescriptor;
static int ett_t124_ConferenceJoinRequest;
static int ett_t124_ConferenceJoinResponse;
static int ett_t124_ConferenceInviteRequest;
static int ett_t124_ConferenceInviteResponse;
static int ett_t124_ConnectData;
static int ett_t124_ConnectGCCPDU;
static int ett_t124_Segmentation;
static int ett_t124_PlumbDomainIndication;
static int ett_t124_ErectDomainRequest;
static int ett_t124_ChannelAttributes;
static int ett_t124_T_static;
static int ett_t124_T_userId;
static int ett_t124_T_private;
static int ett_t124_SET_OF_UserId;
static int ett_t124_T_assigned;
static int ett_t124_MergeChannelsRequest;
static int ett_t124_SET_OF_ChannelAttributes;
static int ett_t124_SET_OF_ChannelId;
static int ett_t124_MergeChannelsConfirm;
static int ett_t124_PurgeChannelsIndication;
static int ett_t124_TokenAttributes;
static int ett_t124_T_grabbed;
static int ett_t124_T_inhibited;
static int ett_t124_T_giving;
static int ett_t124_T_ungivable;
static int ett_t124_T_given;
static int ett_t124_MergeTokensRequest;
static int ett_t124_SET_OF_TokenAttributes;
static int ett_t124_SET_OF_TokenId;
static int ett_t124_MergeTokensConfirm;
static int ett_t124_PurgeTokensIndication;
static int ett_t124_DisconnectProviderUltimatum;
static int ett_t124_RejectMCSPDUUltimatum;
static int ett_t124_AttachUserRequest;
static int ett_t124_AttachUserConfirm;
static int ett_t124_DetachUserRequest;
static int ett_t124_DetachUserIndication;
static int ett_t124_ChannelJoinRequest;
static int ett_t124_ChannelJoinConfirm;
static int ett_t124_ChannelLeaveRequest;
static int ett_t124_ChannelConveneRequest;
static int ett_t124_ChannelConveneConfirm;
static int ett_t124_ChannelDisbandRequest;
static int ett_t124_ChannelDisbandIndication;
static int ett_t124_ChannelAdmitRequest;
static int ett_t124_ChannelAdmitIndication;
static int ett_t124_ChannelExpelRequest;
static int ett_t124_ChannelExpelIndication;
static int ett_t124_SendDataRequest;
static int ett_t124_SendDataIndication;
static int ett_t124_UniformSendDataRequest;
static int ett_t124_UniformSendDataIndication;
static int ett_t124_TokenGrabRequest;
static int ett_t124_TokenGrabConfirm;
static int ett_t124_TokenInhibitRequest;
static int ett_t124_TokenInhibitConfirm;
static int ett_t124_TokenGiveRequest;
static int ett_t124_TokenGiveIndication;
static int ett_t124_TokenGiveResponse;
static int ett_t124_TokenGiveConfirm;
static int ett_t124_TokenPleaseRequest;
static int ett_t124_TokenPleaseIndication;
static int ett_t124_TokenReleaseRequest;
static int ett_t124_TokenReleaseConfirm;
static int ett_t124_TokenTestRequest;
static int ett_t124_TokenTestConfirm;
static int ett_t124_DomainMCSPDU;



static int
dissect_t124_DynamicChannelID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1001U, 65535U, NULL, false);

  return offset;
}



static int
dissect_t124_UserID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelID(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_H221NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

      offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 255, false, (tvbuff_t**)&actx->private_data);




  return offset;
}



static int
dissect_t124_T_object(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &actx->external.direct_reference);

  return offset;
}


static const value_string t124_Key_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t Key_choice[] = {
  {   0, &hf_t124_object         , ASN1_NO_EXTENSIONS     , dissect_t124_T_object },
  {   1, &hf_t124_h221NonStandard, ASN1_NO_EXTENSIONS     , dissect_t124_H221NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_Key(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_Key, Key_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_t124_key            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_data           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}



static int
dissect_t124_TextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          0, 255, false);

  return offset;
}



static int
dissect_t124_SimpleTextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          0, 255, false);

  return offset;
}



static int
dissect_t124_SimpleNumericString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_DiallingString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 16, false, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_SubAddressString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 40, false, "0123456789", 10,
                                                      NULL);

  return offset;
}



static int
dissect_t124_ExtraDiallingString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_size_constrained_type(tvb, offset, actx, tree, hf_index, dissect_t124_TextString,
                                                "TextString", 1, 255, false);

  return offset;
}



static int
dissect_t124_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *next_tvb = NULL;
    tvbuff_t *t124NSIdentifier = (tvbuff_t*)actx->private_data;
    uint8_t  *ns = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &next_tvb);


	if(next_tvb && t124NSIdentifier) {

	ns = tvb_get_string_enc(actx->pinfo->pool, t124NSIdentifier, 0, tvb_reported_length(t124NSIdentifier), ENC_ASCII|ENC_NA);
	if(ns != NULL) {
		dissector_try_string_with_data(t124_ns_dissector_table, ns, next_tvb, actx->pinfo, top_tree, false, NULL);
	}
	}


  return offset;
}


static const per_sequence_t UserData_item_sequence[] = {
  { &hf_t124_key            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_value          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UserData_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UserData_item, UserData_item_sequence);

  return offset;
}


static const per_sequence_t UserData_set_of[1] = {
  { &hf_t124_UserData_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserData_item },
};

static int
dissect_t124_UserData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_UserData, UserData_set_of);

  return offset;
}


static const per_sequence_t Password_sequence[] = {
  { &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SimpleNumericString },
  { &hf_t124_text           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SimpleTextString },
  { &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_Password(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_Password, Password_sequence);

  return offset;
}


static const value_string t124_PasswordSelector_vals[] = {
  {   0, "numeric" },
  {   1, "text" },
  {   2, "unicodeText" },
  { 0, NULL }
};

static const per_choice_t PasswordSelector_choice[] = {
  {   0, &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleNumericString },
  {   1, &hf_t124_text           , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleTextString },
  {   2, &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, dissect_t124_TextString },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_PasswordSelector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_PasswordSelector, PasswordSelector_choice,
                                 NULL);

  return offset;
}


static const value_string t124_ChallengeResponseItem_vals[] = {
  {   0, "passwordString" },
  {   1, "responseData" },
  { 0, NULL }
};

static const per_choice_t ChallengeResponseItem_choice[] = {
  {   0, &hf_t124_passwordString , ASN1_EXTENSION_ROOT    , dissect_t124_PasswordSelector },
  {   1, &hf_t124_responseData   , ASN1_EXTENSION_ROOT    , dissect_t124_UserData },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChallengeResponseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChallengeResponseItem, ChallengeResponseItem_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string t124_ChallengeResponseAlgorithm_vals[] = {
  {   0, "passwordInTheClear" },
  {   1, "nonStandardAlgorithm" },
  { 0, NULL }
};

static const per_choice_t ChallengeResponseAlgorithm_choice[] = {
  {   0, &hf_t124_passwordInTheClear, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_nonStandardAlgorithm, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChallengeResponseAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChallengeResponseAlgorithm, ChallengeResponseAlgorithm_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ChallengeItem_sequence[] = {
  { &hf_t124_responseAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseAlgorithm },
  { &hf_t124_challengeData  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeItem, ChallengeItem_sequence);

  return offset;
}



static int
dissect_t124_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t SET_OF_ChallengeItem_set_of[1] = {
  { &hf_t124_challengeSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeItem },
};

static int
dissect_t124_SET_OF_ChallengeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChallengeItem, SET_OF_ChallengeItem_set_of);

  return offset;
}


static const per_sequence_t ChallengeRequest_sequence[] = {
  { &hf_t124_challengeTag   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_challengeSet   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChallengeItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeRequest, ChallengeRequest_sequence);

  return offset;
}


static const per_sequence_t ChallengeResponse_sequence[] = {
  { &hf_t124_challengeTag   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_responseAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseAlgorithm },
  { &hf_t124_responseItem   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ChallengeResponseItem },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChallengeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChallengeResponse, ChallengeResponse_sequence);

  return offset;
}


static const per_sequence_t T_challengeRequestResponse_sequence[] = {
  { &hf_t124_challengeRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChallengeRequest },
  { &hf_t124_challengeResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ChallengeResponse },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_challengeRequestResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_challengeRequestResponse, T_challengeRequestResponse_sequence);

  return offset;
}


static const value_string t124_PasswordChallengeRequestResponse_vals[] = {
  {   0, "passwordInTheClear" },
  {   1, "challengeRequestResponse" },
  { 0, NULL }
};

static const per_choice_t PasswordChallengeRequestResponse_choice[] = {
  {   0, &hf_t124_passwordInTheClear_01, ASN1_EXTENSION_ROOT    , dissect_t124_PasswordSelector },
  {   1, &hf_t124_challengeRequestResponse, ASN1_EXTENSION_ROOT    , dissect_t124_T_challengeRequestResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_PasswordChallengeRequestResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_PasswordChallengeRequestResponse, PasswordChallengeRequestResponse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConferenceName_sequence[] = {
  { &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SimpleNumericString },
  { &hf_t124_text           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SimpleTextString },
  { &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceName, ConferenceName_sequence);

  return offset;
}


static const value_string t124_ConferenceNameSelector_vals[] = {
  {   0, "numeric" },
  {   1, "text" },
  {   2, "unicodeText" },
  { 0, NULL }
};

static const per_choice_t ConferenceNameSelector_choice[] = {
  {   0, &hf_t124_numeric        , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleNumericString },
  {   1, &hf_t124_text           , ASN1_EXTENSION_ROOT    , dissect_t124_SimpleTextString },
  {   2, &hf_t124_unicodeText    , ASN1_NOT_EXTENSION_ROOT, dissect_t124_TextString },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferenceNameSelector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferenceNameSelector, ConferenceNameSelector_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_ConferenceNameModifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_SimpleNumericString(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string t124_Privilege_vals[] = {
  {   0, "terminate" },
  {   1, "ejectUser" },
  {   2, "add" },
  {   3, "lockUnlock" },
  {   4, "transfer" },
  { 0, NULL }
};


static int
dissect_t124_Privilege(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string t124_TerminationMethod_vals[] = {
  {   0, "automatic" },
  {   1, "manual" },
  { 0, NULL }
};


static int
dissect_t124_TerminationMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string t124_ConferencePriorityScheme_vals[] = {
  {   0, "nonStandardScheme" },
  { 0, NULL }
};

static const per_choice_t ConferencePriorityScheme_choice[] = {
  {   0, &hf_t124_nonStandardScheme, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferencePriorityScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferencePriorityScheme, ConferencePriorityScheme_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t ConferencePriority_sequence[] = {
  { &hf_t124_priority       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_65535 },
  { &hf_t124_scheme         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferencePriorityScheme },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferencePriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferencePriority, ConferencePriority_sequence);

  return offset;
}


static const value_string t124_NodeCategory_vals[] = {
  {   0, "conventional" },
  {   1, "counted" },
  {   2, "anonymous" },
  {   3, "nonStandardCategory" },
  { 0, NULL }
};

static const per_choice_t NodeCategory_choice[] = {
  {   0, &hf_t124_conventional   , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_counted        , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   2, &hf_t124_anonymous      , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_nonStandardCategory, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_NodeCategory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NodeCategory, NodeCategory_choice,
                                 NULL);

  return offset;
}


static const value_string t124_ConferenceMode_vals[] = {
  {   0, "conventional-only" },
  {   1, "counted-only" },
  {   2, "anonymous-only" },
  {   3, "conventional-control" },
  {   4, "unrestricted-mode" },
  {   5, "non-standard-mode" },
  { 0, NULL }
};

static const per_choice_t ConferenceMode_choice[] = {
  {   0, &hf_t124_conventional_only, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   1, &hf_t124_counted_only   , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   2, &hf_t124_anonymous_only , ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   3, &hf_t124_conventional_control, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   4, &hf_t124_unrestricted_mode, ASN1_EXTENSION_ROOT    , dissect_t124_NULL },
  {   5, &hf_t124_non_standard_mode, ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ConferenceMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConferenceMode, ConferenceMode_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_transferModes_sequence[] = {
  { &hf_t124_speech         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_voice_band     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_56k    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_64k    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_128k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_192k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_256k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_320k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_384k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_512k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_768k   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1152k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1472k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1536k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_digital_1920k  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_packet_mode    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_frame_mode     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_atm            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_transferModes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_transferModes, T_transferModes_sequence);

  return offset;
}


static const per_sequence_t T_highLayerCompatibility_sequence[] = {
  { &hf_t124_telephony3kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_telephony7kHz  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videotelephony , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_videoconference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiographic   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_audiovisual    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_multimedia     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_highLayerCompatibility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_highLayerCompatibility, T_highLayerCompatibility_sequence);

  return offset;
}


static const per_sequence_t T_aggregatedChannel_sequence[] = {
  { &hf_t124_transferModes  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_transferModes },
  { &hf_t124_internationalNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_DiallingString },
  { &hf_t124_subAddress     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SubAddressString },
  { &hf_t124_extraDialling  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ExtraDiallingString },
  { &hf_t124_highLayerCompatibility, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_T_highLayerCompatibility },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_aggregatedChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_aggregatedChannel, T_aggregatedChannel_sequence);

  return offset;
}



static int
dissect_t124_OCTET_STRING_SIZE_1_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, false, NULL);

  return offset;
}


static const per_sequence_t T_transportConnection_sequence[] = {
  { &hf_t124_nsapAddress    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING_SIZE_1_20 },
  { &hf_t124_transportSelector, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_transportConnection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_transportConnection, T_transportConnection_sequence);

  return offset;
}


static const value_string t124_NetworkAddress_item_vals[] = {
  {   0, "aggregatedChannel" },
  {   1, "transportConnection" },
  {   2, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t NetworkAddress_item_choice[] = {
  {   0, &hf_t124_aggregatedChannel, ASN1_EXTENSION_ROOT    , dissect_t124_T_aggregatedChannel },
  {   1, &hf_t124_transportConnection, ASN1_EXTENSION_ROOT    , dissect_t124_T_transportConnection },
  {   2, &hf_t124_nonStandard    , ASN1_EXTENSION_ROOT    , dissect_t124_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_NetworkAddress_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_NetworkAddress_item, NetworkAddress_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NetworkAddress_sequence_of[1] = {
  { &hf_t124_NetworkAddress_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_NetworkAddress_item },
};

static int
dissect_t124_NetworkAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_t124_NetworkAddress, NetworkAddress_sequence_of,
                                                  1, 64, false);

  return offset;
}


static const value_string t124_NodeType_vals[] = {
  {   0, "terminal" },
  {   1, "multiportTerminal" },
  {   2, "mcu" },
  { 0, NULL }
};


static int
dissect_t124_NodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_t124_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const value_string t124_AsymmetryIndicator_vals[] = {
  {   0, "callingNode" },
  {   1, "calledNode" },
  {   2, "unknown" },
  { 0, NULL }
};

static const per_choice_t AsymmetryIndicator_choice[] = {
  {   0, &hf_t124_callingNode    , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   1, &hf_t124_calledNode     , ASN1_NO_EXTENSIONS     , dissect_t124_NULL },
  {   2, &hf_t124_unknown        , ASN1_NO_EXTENSIONS     , dissect_t124_INTEGER_0_4294967295 },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_AsymmetryIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_AsymmetryIndicator, AsymmetryIndicator_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConferenceDescriptor_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_conferenceNameModifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameModifier },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_networkAddress , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_NetworkAddress },
  { &hf_t124_defaultConferenceFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceDescriptor, ConferenceDescriptor_sequence);

  return offset;
}


static const per_sequence_t SET_OF_Privilege_set_of[1] = {
  { &hf_t124_conductorPrivileges_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Privilege },
};

static int
dissect_t124_SET_OF_Privilege(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_Privilege, SET_OF_Privilege_set_of);

  return offset;
}


static const per_sequence_t ConferenceCreateRequest_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_convenerPassword, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_Password },
  { &hf_t124_password       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_Password },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_conferencePriority, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferencePriority },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceCreateRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceCreateRequest, ConferenceCreateRequest_sequence);

  return offset;
}


static const value_string t124_T_result_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  {   2, "resourcesNotAvailable" },
  {   3, "rejectedForSymmetryBreaking" },
  {   4, "lockedConferenceNotSupported" },
  { 0, NULL }
};


static int
dissect_t124_T_result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceCreateResponse_sequence[] = {
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_result         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_T_result },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceCreateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceCreateResponse, ConferenceCreateResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceQueryRequest_sequence[] = {
  { &hf_t124_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeType },
  { &hf_t124_asymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_AsymmetryIndicator },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceQueryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceQueryRequest, ConferenceQueryRequest_sequence);

  return offset;
}


static const per_sequence_t SET_OF_ConferenceDescriptor_set_of[1] = {
  { &hf_t124_conferenceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceDescriptor },
};

static int
dissect_t124_SET_OF_ConferenceDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ConferenceDescriptor, SET_OF_ConferenceDescriptor_set_of);

  return offset;
}


static const value_string t124_QueryResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  { 0, NULL }
};


static int
dissect_t124_QueryResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceQueryResponse_sequence[] = {
  { &hf_t124_nodeType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_NodeType },
  { &hf_t124_asymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_AsymmetryIndicator },
  { &hf_t124_conferenceList , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ConferenceDescriptor },
  { &hf_t124_queryResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_QueryResponseResult },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_waitForInvitationFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_BOOLEAN },
  { &hf_t124_noUnlistedConferenceFlag, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceQueryResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceQueryResponse, ConferenceQueryResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceJoinRequest_sequence[] = {
  { &hf_t124_conferenceName_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameSelector },
  { &hf_t124_conferenceNameModifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameModifier },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_INTEGER },
  { &hf_t124_password_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordChallengeRequestResponse },
  { &hf_t124_convenerPassword_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordSelector },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceJoinRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceJoinRequest, ConferenceJoinRequest_sequence);

  return offset;
}


static const value_string t124_JoinResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  {   2, "invalidConference" },
  {   3, "invalidPassword" },
  {   4, "invalidConvenerPassword" },
  {   5, "challengeResponseRequired" },
  {   6, "invalidChallengeResponse" },
  { 0, NULL }
};


static int
dissect_t124_JoinResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceJoinResponse_sequence[] = {
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserID },
  { &hf_t124_topNodeID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_conferenceNameAlias, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_ConferenceNameSelector },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_password_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_PasswordChallengeRequestResponse },
  { &hf_t124_joinResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_JoinResponseResult },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceJoinResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceJoinResponse, ConferenceJoinResponse_sequence);

  return offset;
}


static const per_sequence_t ConferenceInviteRequest_sequence[] = {
  { &hf_t124_conferenceName , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_ConferenceName },
  { &hf_t124_nodeID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_topNodeID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_UserID },
  { &hf_t124_tag            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER },
  { &hf_t124_passwordInTheClearRequired, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_lockedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_listedConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_conductibleConference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_terminationMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_TerminationMethod },
  { &hf_t124_conductorPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_nonConductedPrivileges, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_SET_OF_Privilege },
  { &hf_t124_conferenceDescription, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_callerIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_TextString },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { &hf_t124_conferencePriority, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferencePriority },
  { &hf_t124_nodeCategory   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_NodeCategory },
  { &hf_t124_conferenceMode , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_t124_ConferenceMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceInviteRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceInviteRequest, ConferenceInviteRequest_sequence);

  return offset;
}


static const value_string t124_InviteResponseResult_vals[] = {
  {   0, "success" },
  {   1, "userRejected" },
  { 0, NULL }
};


static int
dissect_t124_InviteResponseResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ConferenceInviteResponse_sequence[] = {
  { &hf_t124_inviteResponseResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t124_InviteResponseResult },
  { &hf_t124_userData_set_of, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t124_UserData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ConferenceInviteResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConferenceInviteResponse, ConferenceInviteResponse_sequence);

  return offset;
}



static int
dissect_t124_T_connectPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t	*next_tvb = NULL;
    proto_tree	*next_tree = NULL;
    int		old_offset = 0;

    old_offset = offset;
      offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &next_tvb);

    if(next_tvb) {
      /* "2a -> ConnectData::connectPDU length = 42 bytes */
      /* This length MUST be ignored by the client." */

      /* Not sure why - but lets ignore the length. */
      /* We assume the OCTET STRING is all of the remaining bytes */

      if(tvb_reported_length(next_tvb) == 42) {
         /* this is perhaps a naive ... */
	 next_tvb = tvb_new_subset_remaining(tvb, (old_offset>>3)+1);
      }

	 next_tree = proto_item_add_subtree(actx->created_item, ett_t124_connectGCCPDU);

       dissect_t124_ConnectGCCPDU(next_tvb, 0, actx, next_tree, hf_t124_connectGCCPDU);

    }

  return offset;
}


static const per_sequence_t ConnectData_sequence[] = {
  { &hf_t124_t124Identifier , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { &hf_t124_connectPDU     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_connectPDU },
  { NULL, 0, 0, NULL }
};

int
dissect_t124_ConnectData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ConnectData, ConnectData_sequence);

  return offset;
}


const value_string t124_ConnectGCCPDU_vals[] = {
  {   0, "conferenceCreateRequest" },
  {   1, "conferenceCreateResponse" },
  {   2, "conferenceQueryRequest" },
  {   3, "conferenceQueryResponse" },
  {   4, "conferenceJoinRequest" },
  {   5, "conferenceJoinResponse" },
  {   6, "conferenceInviteRequest" },
  {   7, "conferenceInviteResponse" },
  { 0, NULL }
};

static const per_choice_t ConnectGCCPDU_choice[] = {
  {   0, &hf_t124_conferenceCreateRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceCreateRequest },
  {   1, &hf_t124_conferenceCreateResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceCreateResponse },
  {   2, &hf_t124_conferenceQueryRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceQueryRequest },
  {   3, &hf_t124_conferenceQueryResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceQueryResponse },
  {   4, &hf_t124_conferenceJoinRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceJoinRequest },
  {   5, &hf_t124_conferenceJoinResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceJoinResponse },
  {   6, &hf_t124_conferenceInviteRequest, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceInviteRequest },
  {   7, &hf_t124_conferenceInviteResponse, ASN1_EXTENSION_ROOT    , dissect_t124_ConferenceInviteResponse },
  { 0, NULL, 0, NULL }
};

int
dissect_t124_ConnectGCCPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ConnectGCCPDU, ConnectGCCPDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_t124_ChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

      offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &channelId, false);


    if(hf_index == hf_t124_channelId_03)
        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%d", channelId);



  return offset;
}



static int
dissect_t124_StaticChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000U, NULL, false);

  return offset;
}



static int
dissect_t124_DynamicChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1001U, 65535U, NULL, false);

  return offset;
}



static int
dissect_t124_UserId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_PrivateChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_AssignedChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_t124_DynamicChannelId(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_t124_TokenId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, false);

  return offset;
}


static const value_string t124_TokenStatus_vals[] = {
  {   0, "notInUse" },
  {   1, "selfGrabbed" },
  {   2, "otherGrabbed" },
  {   3, "selfInhibited" },
  {   4, "otherInhibited" },
  {   5, "selfRecipient" },
  {   6, "selfGiving" },
  {   7, "otherGiving" },
  { 0, NULL }
};


static int
dissect_t124_TokenStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const value_string t124_DataPriority_vals[] = {
  {   0, "top" },
  {   1, "high" },
  {   2, "medium" },
  {   3, "low" },
  { 0, NULL }
};


static int
dissect_t124_DataPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static int * const Segmentation_bits[] = {
  &hf_t124_Segmentation_begin,
  &hf_t124_Segmentation_end,
  NULL
};

static int
dissect_t124_Segmentation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, false, Segmentation_bits, 2, NULL, NULL);

  return offset;
}



static int
dissect_t124_INTEGER_0_MAX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, NO_BOUND, NULL, false);

  return offset;
}


static const per_sequence_t PlumbDomainIndication_sequence[] = {
  { &hf_t124_heightLimit    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PlumbDomainIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PlumbDomainIndication, PlumbDomainIndication_sequence);

  return offset;
}


static const per_sequence_t ErectDomainRequest_sequence[] = {
  { &hf_t124_subHeight      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { &hf_t124_subInterval    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_INTEGER_0_MAX },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ErectDomainRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ErectDomainRequest, ErectDomainRequest_sequence);

  return offset;
}


static const per_sequence_t T_static_sequence[] = {
  { &hf_t124_channelId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_StaticChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_static(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_static, T_static_sequence);

  return offset;
}


static const per_sequence_t T_userId_sequence[] = {
  { &hf_t124_joined         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_userId_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_userId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_userId, T_userId_sequence);

  return offset;
}


static const per_sequence_t SET_OF_UserId_set_of[1] = {
  { &hf_t124_admitted_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
};

static int
dissect_t124_SET_OF_UserId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_UserId, SET_OF_UserId_set_of);

  return offset;
}


static const per_sequence_t T_private_sequence[] = {
  { &hf_t124_joined         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_BOOLEAN },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_manager        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_admitted       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_private(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_private, T_private_sequence);

  return offset;
}


static const per_sequence_t T_assigned_sequence[] = {
  { &hf_t124_channelId_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_AssignedChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_assigned(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_assigned, T_assigned_sequence);

  return offset;
}


static const value_string t124_ChannelAttributes_vals[] = {
  {   0, "static" },
  {   1, "userId" },
  {   2, "private" },
  {   3, "assigned" },
  { 0, NULL }
};

static const per_choice_t ChannelAttributes_choice[] = {
  {   0, &hf_t124_static         , ASN1_NO_EXTENSIONS     , dissect_t124_T_static },
  {   1, &hf_t124_userId         , ASN1_NO_EXTENSIONS     , dissect_t124_T_userId },
  {   2, &hf_t124_private        , ASN1_NO_EXTENSIONS     , dissect_t124_T_private },
  {   3, &hf_t124_assigned       , ASN1_NO_EXTENSIONS     , dissect_t124_T_assigned },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_ChannelAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_ChannelAttributes, ChannelAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_OF_ChannelAttributes_set_of[1] = {
  { &hf_t124_mergeChannels_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelAttributes },
};

static int
dissect_t124_SET_OF_ChannelAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChannelAttributes, SET_OF_ChannelAttributes_set_of);

  return offset;
}


static const per_sequence_t SET_OF_ChannelId_set_of[1] = {
  { &hf_t124_purgeChannelIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
};

static int
dissect_t124_SET_OF_ChannelId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_ChannelId, SET_OF_ChannelId_set_of);

  return offset;
}


static const per_sequence_t MergeChannelsRequest_sequence[] = {
  { &hf_t124_mergeChannels  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelAttributes },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeChannelsRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeChannelsRequest, MergeChannelsRequest_sequence);

  return offset;
}


static const per_sequence_t MergeChannelsConfirm_sequence[] = {
  { &hf_t124_mergeChannels  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelAttributes },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeChannelsConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeChannelsConfirm, MergeChannelsConfirm_sequence);

  return offset;
}


static const per_sequence_t PurgeChannelsIndication_sequence[] = {
  { &hf_t124_detachUserIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { &hf_t124_purgeChannelIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PurgeChannelsIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PurgeChannelsIndication, PurgeChannelsIndication_sequence);

  return offset;
}


static const per_sequence_t T_grabbed_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_grabbed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_grabbed, T_grabbed_sequence);

  return offset;
}


static const per_sequence_t T_inhibited_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_inhibitors     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_inhibited(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_inhibited, T_inhibited_sequence);

  return offset;
}


static const per_sequence_t T_giving_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_giving(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_giving, T_giving_sequence);

  return offset;
}


static const per_sequence_t T_ungivable_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_grabber        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_ungivable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_ungivable, T_ungivable_sequence);

  return offset;
}


static const per_sequence_t T_given_sequence[] = {
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_T_given(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_T_given, T_given_sequence);

  return offset;
}


static const value_string t124_TokenAttributes_vals[] = {
  {   0, "grabbed" },
  {   1, "inhibited" },
  {   2, "giving" },
  {   3, "ungivable" },
  {   4, "given" },
  { 0, NULL }
};

static const per_choice_t TokenAttributes_choice[] = {
  {   0, &hf_t124_grabbed        , ASN1_NO_EXTENSIONS     , dissect_t124_T_grabbed },
  {   1, &hf_t124_inhibited      , ASN1_NO_EXTENSIONS     , dissect_t124_T_inhibited },
  {   2, &hf_t124_giving         , ASN1_NO_EXTENSIONS     , dissect_t124_T_giving },
  {   3, &hf_t124_ungivable      , ASN1_NO_EXTENSIONS     , dissect_t124_T_ungivable },
  {   4, &hf_t124_given          , ASN1_NO_EXTENSIONS     , dissect_t124_T_given },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_TokenAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_TokenAttributes, TokenAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_OF_TokenAttributes_set_of[1] = {
  { &hf_t124_mergeTokens_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenAttributes },
};

static int
dissect_t124_SET_OF_TokenAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_TokenAttributes, SET_OF_TokenAttributes_set_of);

  return offset;
}


static const per_sequence_t SET_OF_TokenId_set_of[1] = {
  { &hf_t124_purgeTokenIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
};

static int
dissect_t124_SET_OF_TokenId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_t124_SET_OF_TokenId, SET_OF_TokenId_set_of);

  return offset;
}


static const per_sequence_t MergeTokensRequest_sequence[] = {
  { &hf_t124_mergeTokens    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenAttributes },
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeTokensRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeTokensRequest, MergeTokensRequest_sequence);

  return offset;
}


static const per_sequence_t MergeTokensConfirm_sequence[] = {
  { &hf_t124_mergeTokens    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenAttributes },
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_MergeTokensConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_MergeTokensConfirm, MergeTokensConfirm_sequence);

  return offset;
}


static const per_sequence_t PurgeTokensIndication_sequence[] = {
  { &hf_t124_purgeTokenIds  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_PurgeTokensIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_PurgeTokensIndication, PurgeTokensIndication_sequence);

  return offset;
}


static const value_string t124_Reason_vals[] = {
  {   0, "rn-domain-disconnected" },
  {   1, "rn-provider-initiated" },
  {   2, "rn-token-purged" },
  {   3, "rn-user-requested" },
  {   4, "rn-channel-purged" },
  { 0, NULL }
};


static int
dissect_t124_Reason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t DisconnectProviderUltimatum_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DisconnectProviderUltimatum(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DisconnectProviderUltimatum, DisconnectProviderUltimatum_sequence);

  return offset;
}


static const value_string t124_Diagnostic_vals[] = {
  {   0, "dc-inconsistent-merge" },
  {   1, "dc-forbidden-PDU-downward" },
  {   2, "dc-forbidden-PDU-upward" },
  {   3, "dc-invalid-BER-encoding" },
  {   4, "dc-invalid-PER-encoding" },
  {   5, "dc-misrouted-user" },
  {   6, "dc-unrequested-confirm" },
  {   7, "dc-wrong-transport-priority" },
  {   8, "dc-channel-id-conflict" },
  {   9, "dc-token-id-conflict" },
  {  10, "dc-not-user-id-channel" },
  {  11, "dc-too-many-channels" },
  {  12, "dc-too-many-tokens" },
  {  13, "dc-too-many-users" },
  { 0, NULL }
};


static int
dissect_t124_Diagnostic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t RejectMCSPDUUltimatum_sequence[] = {
  { &hf_t124_diagnostic     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Diagnostic },
  { &hf_t124_initialOctets  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_RejectMCSPDUUltimatum(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_RejectMCSPDUUltimatum, RejectMCSPDUUltimatum_sequence);

  return offset;
}


static const per_sequence_t AttachUserRequest_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_AttachUserRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_AttachUserRequest, AttachUserRequest_sequence);

  return offset;
}


static const value_string t124_Result_vals[] = {
  {   0, "rt-successful" },
  {   1, "rt-domain-merging" },
  {   2, "rt-domain-not-hierarchical" },
  {   3, "rt-no-such-channel" },
  {   4, "rt-no-such-domain" },
  {   5, "rt-no-such-user" },
  {   6, "rt-not-admitted" },
  {   7, "rt-other-user-id" },
  {   8, "rt-parameters-unacceptable" },
  {   9, "rt-token-not-available" },
  {  10, "rt-token-not-possessed" },
  {  11, "rt-too-many-channels" },
  {  12, "rt-too-many-tokens" },
  {  13, "rt-too-many-users" },
  {  14, "rt-unspecified-failure" },
  {  15, "rt-user-rejected" },
  { 0, NULL }
};


static int
dissect_t124_Result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t AttachUserConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_AttachUserConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_AttachUserConfirm, AttachUserConfirm_sequence);

  return offset;
}


static const per_sequence_t DetachUserRequest_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DetachUserRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DetachUserRequest, DetachUserRequest_sequence);

  return offset;
}


static const per_sequence_t DetachUserIndication_sequence[] = {
  { &hf_t124_reason         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Reason },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_DetachUserIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_DetachUserIndication, DetachUserIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelJoinRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelJoinRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelJoinRequest, ChannelJoinRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelJoinConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_requested      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelJoinConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelJoinConfirm, ChannelJoinConfirm_sequence);

  return offset;
}


static const per_sequence_t ChannelLeaveRequest_sequence[] = {
  { &hf_t124_channelIds     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_ChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelLeaveRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelLeaveRequest, ChannelLeaveRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelConveneRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelConveneRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelConveneRequest, ChannelConveneRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelConveneConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelConveneConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelConveneConfirm, ChannelConveneConfirm_sequence);

  return offset;
}


static const per_sequence_t ChannelDisbandRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelDisbandRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelDisbandRequest, ChannelDisbandRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelDisbandIndication_sequence[] = {
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelDisbandIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelDisbandIndication, ChannelDisbandIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelAdmitRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelAdmitRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelAdmitRequest, ChannelAdmitRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelAdmitIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelAdmitIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelAdmitIndication, ChannelAdmitIndication_sequence);

  return offset;
}


static const per_sequence_t ChannelExpelRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelExpelRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelExpelRequest, ChannelExpelRequest_sequence);

  return offset;
}


static const per_sequence_t ChannelExpelIndication_sequence[] = {
  { &hf_t124_channelId_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_PrivateChannelId },
  { &hf_t124_userIds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_SET_OF_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_ChannelExpelIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_ChannelExpelIndication, ChannelExpelIndication_sequence);

  return offset;
}



static int
dissect_t124_T_userData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t	*next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &next_tvb);


	if(next_tvb) {

	     dissector_try_uint_with_data(t124_sd_dissector_table, channelId, next_tvb, actx->pinfo, top_tree, false, NULL);

	}


  return offset;
}


static const per_sequence_t SendDataRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_userData },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_SendDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_SendDataRequest, SendDataRequest_sequence);

  return offset;
}



static int
dissect_t124_T_userData_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t	*next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &next_tvb);


	if(next_tvb) {

	     dissector_try_uint(t124_sd_dissector_table, channelId, next_tvb, actx->pinfo, top_tree);

	}


  return offset;
}


static const per_sequence_t SendDataIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_T_userData_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_SendDataIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_SendDataIndication, SendDataIndication_sequence);

  return offset;
}


static const per_sequence_t UniformSendDataRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_02    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UniformSendDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UniformSendDataRequest, UniformSendDataRequest_sequence);

  return offset;
}


static const per_sequence_t UniformSendDataIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_channelId_03   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_ChannelId },
  { &hf_t124_dataPriority   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_DataPriority },
  { &hf_t124_segmentation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Segmentation },
  { &hf_t124_userData_02    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_UniformSendDataIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_UniformSendDataIndication, UniformSendDataIndication_sequence);

  return offset;
}


static const per_sequence_t TokenGrabRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGrabRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGrabRequest, TokenGrabRequest_sequence);

  return offset;
}


static const per_sequence_t TokenGrabConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGrabConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGrabConfirm, TokenGrabConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenInhibitRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenInhibitRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenInhibitRequest, TokenInhibitRequest_sequence);

  return offset;
}


static const per_sequence_t TokenInhibitConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenInhibitConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenInhibitConfirm, TokenInhibitConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenGiveRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveRequest, TokenGiveRequest_sequence);

  return offset;
}


static const per_sequence_t TokenGiveIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveIndication, TokenGiveIndication_sequence);

  return offset;
}


static const per_sequence_t TokenGiveResponse_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_recipient      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveResponse, TokenGiveResponse_sequence);

  return offset;
}


static const per_sequence_t TokenGiveConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenGiveConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenGiveConfirm, TokenGiveConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenPleaseRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenPleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenPleaseRequest, TokenPleaseRequest_sequence);

  return offset;
}


static const per_sequence_t TokenPleaseIndication_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenPleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenPleaseIndication, TokenPleaseIndication_sequence);

  return offset;
}


static const per_sequence_t TokenReleaseRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenReleaseRequest, TokenReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t TokenReleaseConfirm_sequence[] = {
  { &hf_t124_result_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Result },
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenReleaseConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenReleaseConfirm, TokenReleaseConfirm_sequence);

  return offset;
}


static const per_sequence_t TokenTestRequest_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenTestRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenTestRequest, TokenTestRequest_sequence);

  return offset;
}


static const per_sequence_t TokenTestConfirm_sequence[] = {
  { &hf_t124_initiator      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_UserId },
  { &hf_t124_tokenId        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenId },
  { &hf_t124_tokenStatus    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_TokenStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_t124_TokenTestConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_t124_TokenTestConfirm, TokenTestConfirm_sequence);

  return offset;
}


static const value_string t124_DomainMCSPDU_vals[] = {
  {   0, "plumbDomainIndication" },
  {   1, "erectDomainRequest" },
  {   2, "mergeChannelsRequest" },
  {   3, "mergeChannelsConfirm" },
  {   4, "purgeChannelsIndication" },
  {   5, "mergeTokensRequest" },
  {   6, "mergeTokensConfirm" },
  {   7, "purgeTokensIndication" },
  {   8, "disconnectProviderUltimatum" },
  {   9, "rejectMCSPDUUltimatum" },
  {  10, "attachUserRequest" },
  {  11, "attachUserConfirm" },
  {  12, "detachUserRequest" },
  {  13, "detachUserIndication" },
  {  14, "channelJoinRequest" },
  {  15, "channelJoinConfirm" },
  {  16, "channelLeaveRequest" },
  {  17, "channelConveneRequest" },
  {  18, "channelConveneConfirm" },
  {  19, "channelDisbandRequest" },
  {  20, "channelDisbandIndication" },
  {  21, "channelAdmitRequest" },
  {  22, "channelAdmitIndication" },
  {  23, "channelExpelRequest" },
  {  24, "channelExpelIndication" },
  {  25, "sendDataRequest" },
  {  26, "sendDataIndication" },
  {  27, "uniformSendDataRequest" },
  {  28, "uniformSendDataIndication" },
  {  29, "tokenGrabRequest" },
  {  30, "tokenGrabConfirm" },
  {  31, "tokenInhibitRequest" },
  {  32, "tokenInhibitConfirm" },
  {  33, "tokenGiveRequest" },
  {  34, "tokenGiveIndication" },
  {  35, "tokenGiveResponse" },
  {  36, "tokenGiveConfirm" },
  {  37, "tokenPleaseRequest" },
  {  38, "tokenPleaseIndication" },
  {  39, "tokenReleaseRequest" },
  {  40, "tokenReleaseConfirm" },
  {  41, "tokenTestRequest" },
  {  42, "tokenTestConfirm" },
  { 0, NULL }
};

static const per_choice_t DomainMCSPDU_choice[] = {
  {   0, &hf_t124_plumbDomainIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PlumbDomainIndication },
  {   1, &hf_t124_erectDomainRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ErectDomainRequest },
  {   2, &hf_t124_mergeChannelsRequest, ASN1_NO_EXTENSIONS     , dissect_t124_MergeChannelsRequest },
  {   3, &hf_t124_mergeChannelsConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_MergeChannelsConfirm },
  {   4, &hf_t124_purgeChannelsIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PurgeChannelsIndication },
  {   5, &hf_t124_mergeTokensRequest, ASN1_NO_EXTENSIONS     , dissect_t124_MergeTokensRequest },
  {   6, &hf_t124_mergeTokensConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_MergeTokensConfirm },
  {   7, &hf_t124_purgeTokensIndication, ASN1_NO_EXTENSIONS     , dissect_t124_PurgeTokensIndication },
  {   8, &hf_t124_disconnectProviderUltimatum, ASN1_NO_EXTENSIONS     , dissect_t124_DisconnectProviderUltimatum },
  {   9, &hf_t124_rejectMCSPDUUltimatum, ASN1_NO_EXTENSIONS     , dissect_t124_RejectMCSPDUUltimatum },
  {  10, &hf_t124_attachUserRequest, ASN1_NO_EXTENSIONS     , dissect_t124_AttachUserRequest },
  {  11, &hf_t124_attachUserConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_AttachUserConfirm },
  {  12, &hf_t124_detachUserRequest, ASN1_NO_EXTENSIONS     , dissect_t124_DetachUserRequest },
  {  13, &hf_t124_detachUserIndication, ASN1_NO_EXTENSIONS     , dissect_t124_DetachUserIndication },
  {  14, &hf_t124_channelJoinRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelJoinRequest },
  {  15, &hf_t124_channelJoinConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelJoinConfirm },
  {  16, &hf_t124_channelLeaveRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelLeaveRequest },
  {  17, &hf_t124_channelConveneRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelConveneRequest },
  {  18, &hf_t124_channelConveneConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelConveneConfirm },
  {  19, &hf_t124_channelDisbandRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelDisbandRequest },
  {  20, &hf_t124_channelDisbandIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelDisbandIndication },
  {  21, &hf_t124_channelAdmitRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelAdmitRequest },
  {  22, &hf_t124_channelAdmitIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelAdmitIndication },
  {  23, &hf_t124_channelExpelRequest, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelExpelRequest },
  {  24, &hf_t124_channelExpelIndication, ASN1_NO_EXTENSIONS     , dissect_t124_ChannelExpelIndication },
  {  25, &hf_t124_sendDataRequest, ASN1_NO_EXTENSIONS     , dissect_t124_SendDataRequest },
  {  26, &hf_t124_sendDataIndication, ASN1_NO_EXTENSIONS     , dissect_t124_SendDataIndication },
  {  27, &hf_t124_uniformSendDataRequest, ASN1_NO_EXTENSIONS     , dissect_t124_UniformSendDataRequest },
  {  28, &hf_t124_uniformSendDataIndication, ASN1_NO_EXTENSIONS     , dissect_t124_UniformSendDataIndication },
  {  29, &hf_t124_tokenGrabRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGrabRequest },
  {  30, &hf_t124_tokenGrabConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGrabConfirm },
  {  31, &hf_t124_tokenInhibitRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenInhibitRequest },
  {  32, &hf_t124_tokenInhibitConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenInhibitConfirm },
  {  33, &hf_t124_tokenGiveRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveRequest },
  {  34, &hf_t124_tokenGiveIndication, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveIndication },
  {  35, &hf_t124_tokenGiveResponse, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveResponse },
  {  36, &hf_t124_tokenGiveConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenGiveConfirm },
  {  37, &hf_t124_tokenPleaseRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenPleaseRequest },
  {  38, &hf_t124_tokenPleaseIndication, ASN1_NO_EXTENSIONS     , dissect_t124_TokenPleaseIndication },
  {  39, &hf_t124_tokenReleaseRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenReleaseRequest },
  {  40, &hf_t124_tokenReleaseConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenReleaseConfirm },
  {  41, &hf_t124_tokenTestRequest, ASN1_NO_EXTENSIONS     , dissect_t124_TokenTestRequest },
  {  42, &hf_t124_tokenTestConfirm, ASN1_NO_EXTENSIONS     , dissect_t124_TokenTestConfirm },
  { 0, NULL, 0, NULL }
};

static int
dissect_t124_DomainMCSPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	int domainmcs_value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_t124_DomainMCSPDU, DomainMCSPDU_choice,
                                 &domainmcs_value);

	switch(domainmcs_value) {
	case 25: /* sendDataRequest */
	case 26: /* sendDataIndication */
	case 27: /* uniformSendDataRequest */
	case 28: /* uniformSendDataIndication */
		/* Do nothing */
		break;
	default:
                col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                                 val_to_str_const(domainmcs_value, t124_DomainMCSPDU_vals, "Unknown"));
		break;
	}


  return offset;
}


static const per_sequence_t t124Heur_sequence[] = {
  { &hf_t124_t124Identifier , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t124_Key },
  { NULL, 0, 0, NULL }
};

void
register_t124_ns_dissector(const char *nsKey, dissector_t dissector, int proto)
{
  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_string("t124.ns", nsKey, dissector_handle);
}

void register_t124_sd_dissector(packet_info *pinfo _U_, uint32_t channelId_param, dissector_t dissector, int proto)
{
  /* XXX: we should keep the sub-dissectors list per conversation
     as the same channels may be used.
     While we are just using RDP over T.124, then we can get away with it.
  */

  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_uint("t124.sd", channelId_param, dissector_handle);

}

uint32_t t124_get_last_channelId(void)
{
  return channelId;
}

void t124_set_top_tree(proto_tree *tree)
{
  top_tree = tree;
}

int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);

  offset = dissect_t124_DomainMCSPDU(tvb, offset, &asn1_ctx, tree, hf_t124_DomainMCSPDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

static int
dissect_t124(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  asn1_ctx_t asn1_ctx;

  top_tree = parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.124");
  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(parent_tree, proto_t124, tvb, 0, tvb_captured_length(tvb), ENC_NA);
  tree = proto_item_add_subtree(item, ett_t124);

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  dissect_t124_ConnectData(tvb, 0, &asn1_ctx, tree, hf_t124_ConnectData);

  return tvb_captured_length(tvb);
}

static bool
dissect_t124_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
  asn1_ctx_t asn1_ctx;
  volatile bool failed = false;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);

  /*
   * We must catch all the "ran past the end of the packet" exceptions
   * here and, if we catch one, just return false.  It's too painful
   * to have a version of dissect_per_sequence() that checks all
   * references to the tvbuff before making them and returning "no"
   * if they would fail.
   *
   * We (ab)use hf_t124_connectGCCPDU here just to give a valid entry...
   */
  TRY {
    (void) dissect_per_sequence(tvb, 0, &asn1_ctx, NULL, hf_t124_connectGCCPDU, -1, t124Heur_sequence);
  } CATCH_BOUNDS_ERRORS {
    failed = true;
  } ENDTRY;

  if (!failed && ((asn1_ctx.external.direct_reference != NULL) &&
                  (strcmp(asn1_ctx.external.direct_reference, "0.0.20.124.0.1") == 0))) {
    dissect_t124(tvb, pinfo, parent_tree, data);

    return true;
  }

  return false;
}

/*--- proto_register_t124 -------------------------------------------*/
void proto_register_t124(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_t124_ConnectData,
      { "ConnectData", "t124.ConnectData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_connectGCCPDU,
      { "connectGCCPDU", "t124.connectGCCPDU",
        FT_UINT32, BASE_DEC, VALS(t124_ConnectGCCPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t124_DomainMCSPDU_PDU,
      { "DomainMCSPDU", "t124.DomainMCSPDU",
        FT_UINT32, BASE_DEC, VALS(t124_DomainMCSPDU_vals), 0,
        NULL, HFILL }},
    { &hf_t124_object,
      { "object", "t124.object",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_h221NonStandard,
      { "h221NonStandard", "t124.h221NonStandard",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H221NonStandardIdentifier", HFILL }},
    { &hf_t124_key,
      { "key", "t124.key",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        NULL, HFILL }},
    { &hf_t124_data,
      { "data", "t124.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_UserData_item,
      { "UserData item", "t124.UserData_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_value,
      { "value", "t124.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_numeric,
      { "numeric", "t124.numeric",
        FT_STRING, BASE_NONE, NULL, 0,
        "SimpleNumericString", HFILL }},
    { &hf_t124_text,
      { "text", "t124.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "SimpleTextString", HFILL }},
    { &hf_t124_unicodeText,
      { "unicodeText", "t124.unicodeText",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_passwordString,
      { "passwordString", "t124.passwordString",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_responseData,
      { "responseData", "t124.responseData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserData", HFILL }},
    { &hf_t124_passwordInTheClear,
      { "passwordInTheClear", "t124.passwordInTheClear_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardAlgorithm,
      { "nonStandardAlgorithm", "t124.nonStandardAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_responseAlgorithm,
      { "responseAlgorithm", "t124.responseAlgorithm",
        FT_UINT32, BASE_DEC, VALS(t124_ChallengeResponseAlgorithm_vals), 0,
        "ChallengeResponseAlgorithm", HFILL }},
    { &hf_t124_challengeData,
      { "challengeData", "t124.challengeData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserData", HFILL }},
    { &hf_t124_challengeTag,
      { "challengeTag", "t124.challengeTag",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_t124_challengeSet,
      { "challengeSet", "t124.challengeSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChallengeItem", HFILL }},
    { &hf_t124_challengeSet_item,
      { "ChallengeItem", "t124.ChallengeItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_responseItem,
      { "responseItem", "t124.responseItem",
        FT_UINT32, BASE_DEC, VALS(t124_ChallengeResponseItem_vals), 0,
        "ChallengeResponseItem", HFILL }},
    { &hf_t124_passwordInTheClear_01,
      { "passwordInTheClear", "t124.passwordInTheClear",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_challengeRequestResponse,
      { "challengeRequestResponse", "t124.challengeRequestResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_challengeRequest,
      { "challengeRequest", "t124.challengeRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_challengeResponse,
      { "challengeResponse", "t124.challengeResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardScheme,
      { "nonStandardScheme", "t124.nonStandardScheme_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_priority,
      { "priority", "t124.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_t124_scheme,
      { "scheme", "t124.scheme",
        FT_UINT32, BASE_DEC, VALS(t124_ConferencePriorityScheme_vals), 0,
        "ConferencePriorityScheme", HFILL }},
    { &hf_t124_conventional,
      { "conventional", "t124.conventional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_counted,
      { "counted", "t124.counted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_anonymous,
      { "anonymous", "t124.anonymous_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nonStandardCategory,
      { "nonStandardCategory", "t124.nonStandardCategory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_conventional_only,
      { "conventional-only", "t124.conventional_only_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_counted_only,
      { "counted-only", "t124.counted_only_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_anonymous_only,
      { "anonymous-only", "t124.anonymous_only_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conventional_control,
      { "conventional-control", "t124.conventional_control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_unrestricted_mode,
      { "unrestricted-mode", "t124.unrestricted_mode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_non_standard_mode,
      { "non-standard-mode", "t124.non_standard_mode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_NetworkAddress_item,
      { "NetworkAddress item", "t124.NetworkAddress_item",
        FT_UINT32, BASE_DEC, VALS(t124_NetworkAddress_item_vals), 0,
        NULL, HFILL }},
    { &hf_t124_aggregatedChannel,
      { "aggregatedChannel", "t124.aggregatedChannel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_transferModes,
      { "transferModes", "t124.transferModes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_speech,
      { "speech", "t124.speech",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_voice_band,
      { "voice-band", "t124.voice_band",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_56k,
      { "digital-56k", "t124.digital_56k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_64k,
      { "digital-64k", "t124.digital_64k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_128k,
      { "digital-128k", "t124.digital_128k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_192k,
      { "digital-192k", "t124.digital_192k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_256k,
      { "digital-256k", "t124.digital_256k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_320k,
      { "digital-320k", "t124.digital_320k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_384k,
      { "digital-384k", "t124.digital_384k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_512k,
      { "digital-512k", "t124.digital_512k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_768k,
      { "digital-768k", "t124.digital_768k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1152k,
      { "digital-1152k", "t124.digital_1152k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1472k,
      { "digital-1472k", "t124.digital_1472k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1536k,
      { "digital-1536k", "t124.digital_1536k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_digital_1920k,
      { "digital-1920k", "t124.digital_1920k",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_packet_mode,
      { "packet-mode", "t124.packet_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_frame_mode,
      { "frame-mode", "t124.frame_mode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_atm,
      { "atm", "t124.atm",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_internationalNumber,
      { "internationalNumber", "t124.internationalNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "DiallingString", HFILL }},
    { &hf_t124_subAddress,
      { "subAddress", "t124.subAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubAddressString", HFILL }},
    { &hf_t124_extraDialling,
      { "extraDialling", "t124.extraDialling",
        FT_STRING, BASE_NONE, NULL, 0,
        "ExtraDiallingString", HFILL }},
    { &hf_t124_highLayerCompatibility,
      { "highLayerCompatibility", "t124.highLayerCompatibility_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_telephony3kHz,
      { "telephony3kHz", "t124.telephony3kHz",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_telephony7kHz,
      { "telephony7kHz", "t124.telephony7kHz",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_videotelephony,
      { "videotelephony", "t124.videotelephony",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_videoconference,
      { "videoconference", "t124.videoconference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_audiographic,
      { "audiographic", "t124.audiographic",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_audiovisual,
      { "audiovisual", "t124.audiovisual",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_multimedia,
      { "multimedia", "t124.multimedia",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_transportConnection,
      { "transportConnection", "t124.transportConnection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nsapAddress,
      { "nsapAddress", "t124.nsapAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_t124_transportSelector,
      { "transportSelector", "t124.transportSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_nonStandard,
      { "nonStandard", "t124.nonStandard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_t124_callingNode,
      { "callingNode", "t124.callingNode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_calledNode,
      { "calledNode", "t124.calledNode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_unknown,
      { "unknown", "t124.unknown",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_t124_conferenceName,
      { "conferenceName", "t124.conferenceName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceNameModifier,
      { "conferenceNameModifier", "t124.conferenceNameModifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceDescription,
      { "conferenceDescription", "t124.conferenceDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_lockedConference,
      { "lockedConference", "t124.lockedConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_passwordInTheClearRequired,
      { "passwordInTheClearRequired", "t124.passwordInTheClearRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_networkAddress,
      { "networkAddress", "t124.networkAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_defaultConferenceFlag,
      { "defaultConferenceFlag", "t124.defaultConferenceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conferenceMode,
      { "conferenceMode", "t124.conferenceMode",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceMode_vals), 0,
        NULL, HFILL }},
    { &hf_t124_convenerPassword,
      { "convenerPassword", "t124.convenerPassword_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Password", HFILL }},
    { &hf_t124_password,
      { "password", "t124.password_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_listedConference,
      { "listedConference", "t124.listedConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conductibleConference,
      { "conductibleConference", "t124.conductibleConference",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_terminationMethod,
      { "terminationMethod", "t124.terminationMethod",
        FT_UINT32, BASE_DEC, VALS(t124_TerminationMethod_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conductorPrivileges,
      { "conductorPrivileges", "t124.conductorPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_conductorPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conductedPrivileges,
      { "conductedPrivileges", "t124.conductedPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_conductedPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_nonConductedPrivileges,
      { "nonConductedPrivileges", "t124.nonConductedPrivileges",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Privilege", HFILL }},
    { &hf_t124_nonConductedPrivileges_item,
      { "Privilege", "t124.Privilege",
        FT_UINT32, BASE_DEC, VALS(t124_Privilege_vals), 0,
        NULL, HFILL }},
    { &hf_t124_callerIdentifier,
      { "callerIdentifier", "t124.callerIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_t124_userData_set_of,
      { "userData", "t124.userData_set_of",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferencePriority,
      { "conferencePriority", "t124.conferencePriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_nodeID,
      { "nodeID", "t124.nodeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_tag,
      { "tag", "t124.tag",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_t124_result,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_T_result_vals), 0,
        NULL, HFILL }},
    { &hf_t124_nodeType,
      { "nodeType", "t124.nodeType",
        FT_UINT32, BASE_DEC, VALS(t124_NodeType_vals), 0,
        NULL, HFILL }},
    { &hf_t124_asymmetryIndicator,
      { "asymmetryIndicator", "t124.asymmetryIndicator",
        FT_UINT32, BASE_DEC, VALS(t124_AsymmetryIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_t124_conferenceList,
      { "conferenceList", "t124.conferenceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ConferenceDescriptor", HFILL }},
    { &hf_t124_conferenceList_item,
      { "ConferenceDescriptor", "t124.ConferenceDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_queryResponseResult,
      { "result", "t124.queryResponseResult",
        FT_UINT32, BASE_DEC, VALS(t124_QueryResponseResult_vals), 0,
        "QueryResponseResult", HFILL }},
    { &hf_t124_waitForInvitationFlag,
      { "waitForInvitationFlag", "t124.waitForInvitationFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_noUnlistedConferenceFlag,
      { "noUnlistedConferenceFlag", "t124.noUnlistedConferenceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_conferenceName_01,
      { "conferenceName", "t124.conferenceName",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceNameSelector_vals), 0,
        "ConferenceNameSelector", HFILL }},
    { &hf_t124_password_01,
      { "password", "t124.password",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordChallengeRequestResponse_vals), 0,
        "PasswordChallengeRequestResponse", HFILL }},
    { &hf_t124_convenerPassword_01,
      { "convenerPassword", "t124.convenerPassword",
        FT_UINT32, BASE_DEC, VALS(t124_PasswordSelector_vals), 0,
        "PasswordSelector", HFILL }},
    { &hf_t124_nodeCategory,
      { "nodeCategory", "t124.nodeCategory",
        FT_UINT32, BASE_DEC, VALS(t124_NodeCategory_vals), 0,
        NULL, HFILL }},
    { &hf_t124_topNodeID,
      { "topNodeID", "t124.topNodeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserID", HFILL }},
    { &hf_t124_conferenceNameAlias,
      { "conferenceNameAlias", "t124.conferenceNameAlias",
        FT_UINT32, BASE_DEC, VALS(t124_ConferenceNameSelector_vals), 0,
        "ConferenceNameSelector", HFILL }},
    { &hf_t124_joinResponseResult,
      { "result", "t124.joinResponseResult",
        FT_UINT32, BASE_DEC, VALS(t124_JoinResponseResult_vals), 0,
        "JoinResponseResult", HFILL }},
    { &hf_t124_inviteResponseResult,
      { "result", "t124.inviteResponseResult",
        FT_UINT32, BASE_DEC, VALS(t124_InviteResponseResult_vals), 0,
        "InviteResponseResult", HFILL }},
    { &hf_t124_t124Identifier,
      { "t124Identifier", "t124.t124Identifier",
        FT_UINT32, BASE_DEC, VALS(t124_Key_vals), 0,
        "Key", HFILL }},
    { &hf_t124_connectPDU,
      { "connectPDU", "t124.connectPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceCreateRequest,
      { "conferenceCreateRequest", "t124.conferenceCreateRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceCreateResponse,
      { "conferenceCreateResponse", "t124.conferenceCreateResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceQueryRequest,
      { "conferenceQueryRequest", "t124.conferenceQueryRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceQueryResponse,
      { "conferenceQueryResponse", "t124.conferenceQueryResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceJoinRequest,
      { "conferenceJoinRequest", "t124.conferenceJoinRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceJoinResponse,
      { "conferenceJoinResponse", "t124.conferenceJoinResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceInviteRequest,
      { "conferenceInviteRequest", "t124.conferenceInviteRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_conferenceInviteResponse,
      { "conferenceInviteResponse", "t124.conferenceInviteResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_heightLimit,
      { "heightLimit", "t124.heightLimit",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_subHeight,
      { "subHeight", "t124.subHeight",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_subInterval,
      { "subInterval", "t124.subInterval",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_t124_static,
      { "static", "t124.static_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StaticChannelId", HFILL }},
    { &hf_t124_userId,
      { "userId", "t124.userId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_joined,
      { "joined", "t124.joined",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_t124_userId_01,
      { "userId", "t124.userId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_private,
      { "private", "t124.private_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_01,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateChannelId", HFILL }},
    { &hf_t124_manager,
      { "manager", "t124.manager",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_admitted,
      { "admitted", "t124.admitted",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_admitted_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_assigned,
      { "assigned", "t124.assigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_02,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AssignedChannelId", HFILL }},
    { &hf_t124_mergeChannels,
      { "mergeChannels", "t124.mergeChannels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelAttributes", HFILL }},
    { &hf_t124_mergeChannels_item,
      { "ChannelAttributes", "t124.ChannelAttributes",
        FT_UINT32, BASE_DEC, VALS(t124_ChannelAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t124_purgeChannelIds,
      { "purgeChannelIds", "t124.purgeChannelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t124_purgeChannelIds_item,
      { "ChannelId", "t124.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserIds,
      { "detachUserIds", "t124.detachUserIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_detachUserIds_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_grabbed,
      { "grabbed", "t124.grabbed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenId,
      { "tokenId", "t124.tokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_grabber,
      { "grabber", "t124.grabber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_inhibited,
      { "inhibited", "t124.inhibited_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_inhibitors,
      { "inhibitors", "t124.inhibitors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_inhibitors_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_giving,
      { "giving", "t124.giving_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_recipient,
      { "recipient", "t124.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_ungivable,
      { "ungivable", "t124.ungivable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_given,
      { "given", "t124.given_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokens,
      { "mergeTokens", "t124.mergeTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenAttributes", HFILL }},
    { &hf_t124_mergeTokens_item,
      { "TokenAttributes", "t124.TokenAttributes",
        FT_UINT32, BASE_DEC, VALS(t124_TokenAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_t124_purgeTokenIds,
      { "purgeTokenIds", "t124.purgeTokenIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_TokenId", HFILL }},
    { &hf_t124_purgeTokenIds_item,
      { "TokenId", "t124.TokenId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_reason,
      { "reason", "t124.reason",
        FT_UINT32, BASE_DEC, VALS(t124_Reason_vals), 0,
        NULL, HFILL }},
    { &hf_t124_diagnostic,
      { "diagnostic", "t124.diagnostic",
        FT_UINT32, BASE_DEC, VALS(t124_Diagnostic_vals), 0,
        NULL, HFILL }},
    { &hf_t124_initialOctets,
      { "initialOctets", "t124.initialOctets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_result_01,
      { "result", "t124.result",
        FT_UINT32, BASE_DEC, VALS(t124_Result_vals), 0,
        NULL, HFILL }},
    { &hf_t124_initiator,
      { "initiator", "t124.initiator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserId", HFILL }},
    { &hf_t124_userIds,
      { "userIds", "t124.userIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserId", HFILL }},
    { &hf_t124_userIds_item,
      { "UserId", "t124.UserId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelId_03,
      { "channelId", "t124.channelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_requested,
      { "requested", "t124.requested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChannelId", HFILL }},
    { &hf_t124_channelIds,
      { "channelIds", "t124.channelIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ChannelId", HFILL }},
    { &hf_t124_channelIds_item,
      { "ChannelId", "t124.ChannelId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_dataPriority,
      { "dataPriority", "t124.dataPriority",
        FT_UINT32, BASE_DEC, VALS(t124_DataPriority_vals), 0,
        NULL, HFILL }},
    { &hf_t124_segmentation,
      { "segmentation", "t124.segmentation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_userData,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_userData_01,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userData_01", HFILL }},
    { &hf_t124_userData_02,
      { "userData", "t124.userData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_t124_tokenStatus,
      { "tokenStatus", "t124.tokenStatus",
        FT_UINT32, BASE_DEC, VALS(t124_TokenStatus_vals), 0,
        NULL, HFILL }},
    { &hf_t124_plumbDomainIndication,
      { "plumbDomainIndication", "t124.plumbDomainIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_erectDomainRequest,
      { "erectDomainRequest", "t124.erectDomainRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeChannelsRequest,
      { "mergeChannelsRequest", "t124.mergeChannelsRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeChannelsConfirm,
      { "mergeChannelsConfirm", "t124.mergeChannelsConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_purgeChannelsIndication,
      { "purgeChannelsIndication", "t124.purgeChannelsIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokensRequest,
      { "mergeTokensRequest", "t124.mergeTokensRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_mergeTokensConfirm,
      { "mergeTokensConfirm", "t124.mergeTokensConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_purgeTokensIndication,
      { "purgeTokensIndication", "t124.purgeTokensIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_disconnectProviderUltimatum,
      { "disconnectProviderUltimatum", "t124.disconnectProviderUltimatum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_rejectMCSPDUUltimatum,
      { "rejectMCSPDUUltimatum", "t124.rejectMCSPDUUltimatum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_attachUserRequest,
      { "attachUserRequest", "t124.attachUserRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_attachUserConfirm,
      { "attachUserConfirm", "t124.attachUserConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserRequest,
      { "detachUserRequest", "t124.detachUserRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_detachUserIndication,
      { "detachUserIndication", "t124.detachUserIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelJoinRequest,
      { "channelJoinRequest", "t124.channelJoinRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelJoinConfirm,
      { "channelJoinConfirm", "t124.channelJoinConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelLeaveRequest,
      { "channelLeaveRequest", "t124.channelLeaveRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelConveneRequest,
      { "channelConveneRequest", "t124.channelConveneRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelConveneConfirm,
      { "channelConveneConfirm", "t124.channelConveneConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelDisbandRequest,
      { "channelDisbandRequest", "t124.channelDisbandRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelDisbandIndication,
      { "channelDisbandIndication", "t124.channelDisbandIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelAdmitRequest,
      { "channelAdmitRequest", "t124.channelAdmitRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelAdmitIndication,
      { "channelAdmitIndication", "t124.channelAdmitIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelExpelRequest,
      { "channelExpelRequest", "t124.channelExpelRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_channelExpelIndication,
      { "channelExpelIndication", "t124.channelExpelIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_sendDataRequest,
      { "sendDataRequest", "t124.sendDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_sendDataIndication,
      { "sendDataIndication", "t124.sendDataIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_uniformSendDataRequest,
      { "uniformSendDataRequest", "t124.uniformSendDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_uniformSendDataIndication,
      { "uniformSendDataIndication", "t124.uniformSendDataIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGrabRequest,
      { "tokenGrabRequest", "t124.tokenGrabRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGrabConfirm,
      { "tokenGrabConfirm", "t124.tokenGrabConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenInhibitRequest,
      { "tokenInhibitRequest", "t124.tokenInhibitRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenInhibitConfirm,
      { "tokenInhibitConfirm", "t124.tokenInhibitConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveRequest,
      { "tokenGiveRequest", "t124.tokenGiveRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveIndication,
      { "tokenGiveIndication", "t124.tokenGiveIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveResponse,
      { "tokenGiveResponse", "t124.tokenGiveResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenGiveConfirm,
      { "tokenGiveConfirm", "t124.tokenGiveConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenPleaseRequest,
      { "tokenPleaseRequest", "t124.tokenPleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenPleaseIndication,
      { "tokenPleaseIndication", "t124.tokenPleaseIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenReleaseRequest,
      { "tokenReleaseRequest", "t124.tokenReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenReleaseConfirm,
      { "tokenReleaseConfirm", "t124.tokenReleaseConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenTestRequest,
      { "tokenTestRequest", "t124.tokenTestRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_tokenTestConfirm,
      { "tokenTestConfirm", "t124.tokenTestConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_t124_Segmentation_begin,
      { "begin", "t124.Segmentation.begin",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_t124_Segmentation_end,
      { "end", "t124.Segmentation.end",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_t124,
	  &ett_t124_connectGCCPDU,
    &ett_t124_Key,
    &ett_t124_NonStandardParameter,
    &ett_t124_UserData,
    &ett_t124_UserData_item,
    &ett_t124_Password,
    &ett_t124_PasswordSelector,
    &ett_t124_ChallengeResponseItem,
    &ett_t124_ChallengeResponseAlgorithm,
    &ett_t124_ChallengeItem,
    &ett_t124_ChallengeRequest,
    &ett_t124_SET_OF_ChallengeItem,
    &ett_t124_ChallengeResponse,
    &ett_t124_PasswordChallengeRequestResponse,
    &ett_t124_T_challengeRequestResponse,
    &ett_t124_ConferenceName,
    &ett_t124_ConferenceNameSelector,
    &ett_t124_ConferencePriorityScheme,
    &ett_t124_ConferencePriority,
    &ett_t124_NodeCategory,
    &ett_t124_ConferenceMode,
    &ett_t124_NetworkAddress,
    &ett_t124_NetworkAddress_item,
    &ett_t124_T_aggregatedChannel,
    &ett_t124_T_transferModes,
    &ett_t124_T_highLayerCompatibility,
    &ett_t124_T_transportConnection,
    &ett_t124_AsymmetryIndicator,
    &ett_t124_ConferenceDescriptor,
    &ett_t124_ConferenceCreateRequest,
    &ett_t124_SET_OF_Privilege,
    &ett_t124_ConferenceCreateResponse,
    &ett_t124_ConferenceQueryRequest,
    &ett_t124_ConferenceQueryResponse,
    &ett_t124_SET_OF_ConferenceDescriptor,
    &ett_t124_ConferenceJoinRequest,
    &ett_t124_ConferenceJoinResponse,
    &ett_t124_ConferenceInviteRequest,
    &ett_t124_ConferenceInviteResponse,
    &ett_t124_ConnectData,
    &ett_t124_ConnectGCCPDU,
    &ett_t124_Segmentation,
    &ett_t124_PlumbDomainIndication,
    &ett_t124_ErectDomainRequest,
    &ett_t124_ChannelAttributes,
    &ett_t124_T_static,
    &ett_t124_T_userId,
    &ett_t124_T_private,
    &ett_t124_SET_OF_UserId,
    &ett_t124_T_assigned,
    &ett_t124_MergeChannelsRequest,
    &ett_t124_SET_OF_ChannelAttributes,
    &ett_t124_SET_OF_ChannelId,
    &ett_t124_MergeChannelsConfirm,
    &ett_t124_PurgeChannelsIndication,
    &ett_t124_TokenAttributes,
    &ett_t124_T_grabbed,
    &ett_t124_T_inhibited,
    &ett_t124_T_giving,
    &ett_t124_T_ungivable,
    &ett_t124_T_given,
    &ett_t124_MergeTokensRequest,
    &ett_t124_SET_OF_TokenAttributes,
    &ett_t124_SET_OF_TokenId,
    &ett_t124_MergeTokensConfirm,
    &ett_t124_PurgeTokensIndication,
    &ett_t124_DisconnectProviderUltimatum,
    &ett_t124_RejectMCSPDUUltimatum,
    &ett_t124_AttachUserRequest,
    &ett_t124_AttachUserConfirm,
    &ett_t124_DetachUserRequest,
    &ett_t124_DetachUserIndication,
    &ett_t124_ChannelJoinRequest,
    &ett_t124_ChannelJoinConfirm,
    &ett_t124_ChannelLeaveRequest,
    &ett_t124_ChannelConveneRequest,
    &ett_t124_ChannelConveneConfirm,
    &ett_t124_ChannelDisbandRequest,
    &ett_t124_ChannelDisbandIndication,
    &ett_t124_ChannelAdmitRequest,
    &ett_t124_ChannelAdmitIndication,
    &ett_t124_ChannelExpelRequest,
    &ett_t124_ChannelExpelIndication,
    &ett_t124_SendDataRequest,
    &ett_t124_SendDataIndication,
    &ett_t124_UniformSendDataRequest,
    &ett_t124_UniformSendDataIndication,
    &ett_t124_TokenGrabRequest,
    &ett_t124_TokenGrabConfirm,
    &ett_t124_TokenInhibitRequest,
    &ett_t124_TokenInhibitConfirm,
    &ett_t124_TokenGiveRequest,
    &ett_t124_TokenGiveIndication,
    &ett_t124_TokenGiveResponse,
    &ett_t124_TokenGiveConfirm,
    &ett_t124_TokenPleaseRequest,
    &ett_t124_TokenPleaseIndication,
    &ett_t124_TokenReleaseRequest,
    &ett_t124_TokenReleaseConfirm,
    &ett_t124_TokenTestRequest,
    &ett_t124_TokenTestConfirm,
    &ett_t124_DomainMCSPDU,
  };

  /* Register protocol */
  proto_t124 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t124, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  t124_ns_dissector_table = register_dissector_table("t124.ns", "T.124 H.221 Non Standard Dissectors", proto_t124, FT_STRING, STRING_CASE_SENSITIVE);
  t124_sd_dissector_table = register_dissector_table("t124.sd", "T.124 H.221 Send Data Dissectors", proto_t124, FT_UINT32, BASE_HEX);

  register_dissector("t124", dissect_t124, proto_t124);

}

void
proto_reg_handoff_t124(void) {

  register_ber_oid_dissector("0.0.20.124.0.1", dissect_t124, proto_t124, "Generic Conference Control");

  heur_dissector_add("t125", dissect_t124_heur, "T.124 over T.125", "t124_t125", proto_t124, HEURISTIC_ENABLE);

}
