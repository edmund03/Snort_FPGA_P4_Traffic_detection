/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#ifndef _P4_TYPES_
#define _P4_TYPES_

// ----------------------------------------------------------------------------
// Common protocols/types
//-----------------------------------------------------------------------------
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_MPLS 0x8847
#define ETHERTYPE_PTP  0x88F7
#define ETHERTYPE_FCOE 0x8906
#define ETHERTYPE_ROCE 0x8915
#define ETHERTYPE_BFN  0x9000
//#define ETHERTYPE_QINQ 0x88A8 // Note: uncomment once ptf/scapy-vxlan are fixed
#define ETHERTYPE_QINQ 0x8100
#define ETHERTYPE_PFC  0x8808

#define IP_PROTOCOLS_ICMP   1
#define IP_PROTOCOLS_IGMP   2
#define IP_PROTOCOLS_IPV4   4
#define IP_PROTOCOLS_TCP    6
#define IP_PROTOCOLS_UDP    17
#define IP_PROTOCOLS_IPV6   41
#define IP_PROTOCOLS_GRE    47
#define IP_PROTOCOLS_SRV6   43
#define IP_PROTOCOLS_GRE    47
#define IP_PROTOCOLS_ROUTING 43
#define IP_PROTOCOLS_ICMPV6 58
#define IP_PROTOCOLS_NONXT 59

#define UDP_PORT_VXLAN_GPE 4788
#define UDP_PORT_VXLAN  4789
#define UDP_PORT_ROCEV2 4791
#define UDP_PORT_GENEVE 6081
#define UDP_PORT_SFLOW  6343
#define UDP_PORT_MPLS   6635
#define UDP_PORT_GTP_U   2123
#define UDP_PORT_GTP_C   2152
#define UDP_PORT_SFC_PAUSE  1674
#define UDP_PORT_BFD_1HOP   3784
#define UDP_PORT_BFD_ECHO   3785
#define UDP_PORT_BFD_MHOP   4784
#define TCP_FLAGS_SFC_PAUSE 1

#define GRE_PROTOCOLS_ERSPAN_TYPE_3 0x22EB
#define GRE_PROTOCOLS_NVGRE         0x6558
#define GRE_PROTOCOLS_IP            0x0800
#define GRE_PROTOCOLS_ERSPAN_TYPE_2 0x88BE
#define GRE_PROTOCOLS_IPV6          0x86dd
#define GRE_FLAGS_PROTOCOL_NVGRE    0x20006558

#define IPV6_EXT_TYPE_HBH 0
#define IPV6_EXT_TYPE_DST 0x3C
#define IPV6_EXT_TYPE_ROUTING 0x2B
#define IPV6_EXT_TYPE_FRAGMENT 0x2C
#define IPV6_EXT_TYPE_ESP 0x32
#define IPV6_EXT_TYPE_AH 0x33

#define VLAN_DEPTH 2
#define MPLS_DEPTH 3
#define SEGMENT_DEPTH 2
#define IPV6_FLOW_LABEL_IN_HASH_ENABLE
#define INGRESS_ACL_BD_LABEL_ENABLE

// ----------------------------------------------------------------------------
// Common table sizes
//-----------------------------------------------------------------------------

const bit<32> MIN_TABLE_SIZE = 512;

const bit<32> LAG_TABLE_SIZE = 1024;
const bit<32> LAG_GROUP_TABLE_SIZE = 256;
const bit<32> LAG_MAX_MEMBERS_PER_GROUP = 64;
const bit<32> LAG_SELECTOR_TABLE_SIZE = 16384;  // 256 * 64

const bit<32> DTEL_GROUP_TABLE_SIZE = 4;
const bit<32> DTEL_MAX_MEMBERS_PER_GROUP = 64;
const bit<32> DTEL_SELECTOR_TABLE_SIZE = 256;

const bit<32> IPV4_DST_VTEP_TABLE_SIZE = 512;
const bit<32> IPV6_DST_VTEP_TABLE_SIZE = 512;
#ifdef L2_VXLAN_ENABLE
const bit<32> VNI_MAPPING_TABLE_SIZE = 5*1024; // 4K VLAN + 1K VRF maps
#else
const bit<32> VNI_MAPPING_TABLE_SIZE = 1024; // 1K VRF maps
#endif /* L2_VXLAN_ENABLE */

// ----------------------------------------------------------------------------
// LPM
//-----------------------------------------------------------------------------

#ifdef IPV4_ALPM_OPT_EN
#define ipv4_lpm_subset_width 18
#define ipv4_lpm_shift_granularity 1
@pa_container_size("ingress", "local_md.lkp.ip_dst_addr", 32)
@pa_container_size("ingress", "_ipv4_lpm_partition_key", 32)
@pa_container_size("ingress", "hdr.ipv4.dst_addr", 32)
@pa_container_size("ingress", "hdr.ipv6.dst_addr", 32)
@pa_container_size("ingress", "hdr.inner_ipv4.dst_addr", 32)
@pa_container_size("ingress", "hdr.inner_ipv6.dst_addr", 32)
#endif

#ifndef ipv4_lpm_number_partitions
#if __TARGET_TOFINO__ == 1
#define ipv4_lpm_number_partitions 1024
#else
#define ipv4_lpm_number_partitions 2048
#endif
#endif

#ifndef ipv4_lpm_subtrees_per_partition
#define ipv4_lpm_subtrees_per_partition 2
#endif

#ifdef IPV6_ALPM_OPT_EN
#define ipv6_lpm64_subset_width 32
#define ipv6_lpm64_shift_granularity 2
#endif

#ifndef ipv6_lpm128_number_partitions
#ifdef IPV6_LPM64_ENABLE
#define ipv6_lpm128_number_partitions 1024
#else
#define ipv6_lpm128_number_partitions 1024
#endif
#endif

#ifndef ipv6_lpm128_subtrees_per_partition
#ifdef IPV6_LPM64_ENABLE
#define ipv6_lpm128_subtrees_per_partition 1
#else
#define ipv6_lpm128_subtrees_per_partition 2
#endif
#endif

#ifndef ipv6_lpm64_number_partitions
#define ipv6_lpm64_number_partitions 2048
#endif

#ifndef ipv6_lpm64_subtrees_per_partition
#define ipv6_lpm64_subtrees_per_partition 2
#endif

#ifndef ip_lpm64_number_partitions
#define ip_lpm64_number_partitions 2048
#endif

#ifndef ip_lpm64_subtrees_per_partition
#define ip_lpm64_subtrees_per_partition 2
#endif

#if !defined(IPV6_HOST64_ENABLE) && !defined(IPV6_HOST64_TABLE_SIZE)
#define IPV6_HOST64_TABLE_SIZE 64
#endif

// ----------------------------------------------------------------------------
// Common types
//-----------------------------------------------------------------------------
typedef bit<32> switch_uint32_t;
typedef bit<16> switch_uint16_t;
typedef bit<8> switch_uint8_t;

#ifndef switch_counter_width
#define switch_counter_width 32
#endif

typedef PortId_t switch_port_t;
#if __TARGET_TOFINO__ == 3
const switch_port_t SWITCH_PORT_INVALID = 11w0x1ff;
typedef bit<5> switch_port_padding_t;
#else
const switch_port_t SWITCH_PORT_INVALID = 9w0x1ff;
typedef bit<7> switch_port_padding_t;
#endif

typedef QueueId_t switch_qid_t;

typedef ReplicationId_t switch_rid_t;
const switch_rid_t SWITCH_RID_DEFAULT = 0xffff;

typedef bit<3> switch_ingress_cos_t;

typedef bit<3> switch_digest_type_t;
const switch_digest_type_t SWITCH_DIGEST_TYPE_INVALID = 0;
const switch_digest_type_t SWITCH_DIGEST_TYPE_MAC_LEARNING = 1;

typedef bit<16> switch_ifindex_t;
typedef bit<10> switch_port_lag_index_t;
const switch_port_lag_index_t SWITCH_FLOOD = 0x3ff;
typedef bit<8> switch_isolation_group_t;

typedef bit<16> switch_bd_t;
const switch_bd_t SWITCH_DEFAULT_BD = 16w1;
const switch_bd_t SWITCH_BD_DEFAULT_VRF = 4097; // bd allocated for default vrf

#ifndef switch_vrf_width
#define switch_vrf_width 8
#endif
const bit<32> VRF_TABLE_SIZE = 1 << switch_vrf_width;
typedef bit<switch_vrf_width> switch_vrf_t;
const switch_vrf_t SWITCH_DEFAULT_VRF = 1;

#ifndef switch_nexthop_width
#define switch_nexthop_width 16
#endif
typedef bit<switch_nexthop_width> switch_nexthop_t;

#ifndef switch_user_metadata_width
#define switch_user_metadata_width 10
#endif
typedef bit<switch_user_metadata_width> switch_user_metadata_t;

#ifdef RESILIENT_ECMP_HASH_ENABLE
#define switch_hash_width 64
#else
#define switch_hash_width 32
#endif
typedef bit<switch_hash_width> switch_hash_t;

typedef bit<128> srv6_sid_t;

#ifndef egress_dtel_drop_report_width
#define egress_dtel_drop_report_width 17
#endif

#ifdef TUNNEL_ENABLE
#define TUNNEL_ENCAP_ENABLE
#define INDEPENDENT_TUNNEL_NEXTHOP_ENABLE
#endif

typedef bit<16> switch_xid_t;
typedef L2ExclusionId_t switch_yid_t;

#ifdef NAT_ENABLE
typedef bit<24> switch_ig_port_lag_label_t;
#else
typedef bit<32> switch_ig_port_lag_label_t;
#endif
#ifdef EGRESS_DSCP_MIRROR_ACL_ENABLE
typedef bit<20> switch_eg_port_lag_label_t;
#else
typedef bit<16> switch_eg_port_lag_label_t;
#endif
typedef bit<16> switch_bd_label_t;

typedef bit<16> switch_mtu_t;

typedef bit<12> switch_stats_index_t;

typedef bit<16> switch_cpu_reason_t;
const switch_cpu_reason_t SWITCH_CPU_REASON_PTP = 0x8;
const switch_cpu_reason_t SWITCH_CPU_REASON_BFD = 0x9;

typedef bit<8> switch_fib_label_t;

struct switch_cpu_port_value_set_t {
    bit<16> ether_type;
    switch_port_t port;
}

// ----------------------------------------------------------------------------
// BFD
// ----------------------------------------------------------------------------

typedef bit<2> bfd_pkt_action_t;
const bfd_pkt_action_t BFD_PKT_ACTION_NORMAL    = 0x00;
const bfd_pkt_action_t BFD_PKT_ACTION_TIMEOUT   = 0x01;
const bfd_pkt_action_t BFD_PKT_ACTION_DROP      = 0x02;
const bfd_pkt_action_t BFD_PKT_ACTION_INVALID   = 0x03;

#define bfd_timer_width 8
#define bfd_multiplier_width 8
#define bfd_session_width 12
typedef bit<bfd_multiplier_width> bfd_multiplier_t;
typedef bit<bfd_session_width> bfd_session_t;
typedef bit<4> bfd_pipe_t;
typedef bit<bfd_timer_width> bfd_timer_t;

struct switch_bfd_metadata_t {
	bfd_multiplier_t tx_mult;
	bfd_multiplier_t rx_mult;
	bfd_pkt_action_t pkt_action;
	bfd_pipe_t pktgen_pipe;
	bfd_session_t session_id;
	bit<1> tx_timer_expired;
	bit<1> session_offload;
	bit<1> rx_recirc;
	bit<1> pkt_tx;
}


// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
#define switch_drop_reason_width 8
typedef bit<switch_drop_reason_width> switch_drop_reason_t;
const switch_drop_reason_t SWITCH_DROP_REASON_UNKNOWN = 0;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_SRC_MAC_ZERO = 10;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_SRC_MAC_MULTICAST = 11;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_DST_MAC_ZERO = 12;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_ETHERNET_MISS = 13;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_SAME_MAC_CHECK = 17;
const switch_drop_reason_t SWITCH_DROP_REASON_SRC_MAC_ZERO = 14;
const switch_drop_reason_t SWITCH_DROP_REASON_SRC_MAC_MULTICAST = 15;
const switch_drop_reason_t SWITCH_DROP_REASON_DST_MAC_ZERO = 16;
const switch_drop_reason_t SWITCH_DROP_REASON_DST_MAC_MCAST_DST_IP_UCAST = 18;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_VERSION_INVALID = 25;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_TTL_ZERO = 26;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_SRC_MULTICAST = 27;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_SRC_LOOPBACK = 28;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_MISS = 29;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_IHL_INVALID = 30;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_INVALID_CHECKSUM = 31;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_DST_LOOPBACK = 32;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_SRC_UNSPECIFIED = 33;
const switch_drop_reason_t SWITCH_DROP_REASON_OUTER_IP_SRC_CLASS_E = 34;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_VERSION_INVALID = 40;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_TTL_ZERO = 41;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_SRC_MULTICAST = 42;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_SRC_LOOPBACK = 43;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_IHL_INVALID = 44;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_INVALID_CHECKSUM = 45;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_SRC_CLASS_E = 46;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_DST_LINK_LOCAL = 47;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_SRC_LINK_LOCAL = 48;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_DST_UNSPECIFIED = 49;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_SRC_UNSPECIFIED = 50;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_LPM4_MISS = 51;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_LPM6_MISS = 52;
const switch_drop_reason_t SWITCH_DROP_REASON_IP_BLACKHOLE_ROUTE = 53;
const switch_drop_reason_t SWITCH_DROP_REASON_L3_PORT_RMAC_MISS = 54;
const switch_drop_reason_t SWITCH_DROP_REASON_PORT_VLAN_MAPPING_MISS = 55;
const switch_drop_reason_t SWITCH_DROP_REASON_STP_STATE_LEARNING = 56;
const switch_drop_reason_t SWITCH_DROP_REASON_STP_STATE_BLOCKING = 57;
const switch_drop_reason_t SWITCH_DROP_REASON_SAME_IFINDEX = 58;
const switch_drop_reason_t SWITCH_DROP_REASON_MULTICAST_SNOOPING_ENABLED = 59;
const switch_drop_reason_t SWITCH_DROP_REASON_MTU_CHECK_FAIL = 70;
const switch_drop_reason_t SWITCH_DROP_REASON_TRAFFIC_MANAGER = 71;
const switch_drop_reason_t SWITCH_DROP_REASON_STORM_CONTROL = 72;
const switch_drop_reason_t SWITCH_DROP_REASON_WRED = 73;
const switch_drop_reason_t SWITCH_DROP_REASON_INGRESS_PORT_METER = 75;
const switch_drop_reason_t SWITCH_DROP_REASON_INGRESS_ACL_METER = 76;
const switch_drop_reason_t SWITCH_DROP_REASON_EGRESS_PORT_METER = 77;
const switch_drop_reason_t SWITCH_DROP_REASON_EGRESS_ACL_METER = 78;
const switch_drop_reason_t SWITCH_DROP_REASON_ACL_DENY = 80;
const switch_drop_reason_t SWITCH_DROP_REASON_RACL_DENY = 81;
const switch_drop_reason_t SWITCH_DROP_REASON_URPF_CHECK_FAIL = 82;
const switch_drop_reason_t SWITCH_DROP_REASON_IPSG_MISS = 83;
const switch_drop_reason_t SWITCH_DROP_REASON_IFINDEX = 84;
const switch_drop_reason_t SWITCH_DROP_REASON_CPU_COLOR_YELLOW = 85;
const switch_drop_reason_t SWITCH_DROP_REASON_CPU_COLOR_RED = 86;
const switch_drop_reason_t SWITCH_DROP_REASON_STORM_CONTROL_COLOR_YELLOW = 87;
const switch_drop_reason_t SWITCH_DROP_REASON_STORM_CONTROL_COLOR_RED = 88;
const switch_drop_reason_t SWITCH_DROP_REASON_L2_MISS_UNICAST = 89;
const switch_drop_reason_t SWITCH_DROP_REASON_L2_MISS_MULTICAST = 90;
const switch_drop_reason_t SWITCH_DROP_REASON_L2_MISS_BROADCAST = 91;
const switch_drop_reason_t SWITCH_DROP_REASON_EGRESS_ACL_DENY = 92;
const switch_drop_reason_t SWITCH_DROP_REASON_NEXTHOP = 93;
const switch_drop_reason_t SWITCH_DROP_REASON_NON_IP_ROUTER_MAC = 94;
const switch_drop_reason_t SWITCH_DROP_REASON_MLAG_MEMBER = 95;
const switch_drop_reason_t SWITCH_DROP_REASON_L3_IPV4_DISABLE = 99;
const switch_drop_reason_t SWITCH_DROP_REASON_L3_IPV6_DISABLE = 100;
const switch_drop_reason_t SWITCH_DROP_REASON_INGRESS_PFC_WD_DROP = 101;
const switch_drop_reason_t SWITCH_DROP_REASON_EGRESS_PFC_WD_DROP = 102;
const switch_drop_reason_t SWITCH_DROP_REASON_MPLS_LABEL_DROP = 103;
const switch_drop_reason_t SWITCH_DROP_REASON_SRV6_MY_SID_DROP = 104;
const switch_drop_reason_t SWITCH_DROP_REASON_PORT_ISOLATION_DROP = 105;
const switch_drop_reason_t SWITCH_DROP_REASON_DMAC_RESERVED = 106;
const switch_drop_reason_t SWITCH_DROP_REASON_NON_ROUTABLE = 107;
const switch_drop_reason_t SWITCH_DROP_REASON_MPLS_DISABLE = 108;
const switch_drop_reason_t SWITCH_DROP_REASON_BFD = 109;

typedef bit<1> switch_port_type_t;
const switch_port_type_t SWITCH_PORT_TYPE_NORMAL = 0;
const switch_port_type_t SWITCH_PORT_TYPE_CPU = 1;

typedef bit<2> switch_ip_type_t;
const switch_ip_type_t SWITCH_IP_TYPE_NONE = 0;
const switch_ip_type_t SWITCH_IP_TYPE_IPV4 = 1;
const switch_ip_type_t SWITCH_IP_TYPE_IPV6 = 2;
const switch_ip_type_t SWITCH_IP_TYPE_MPLS = 3; // Consider renaming ip_type to l3_type

typedef bit<2> switch_ip_frag_t;
const switch_ip_frag_t SWITCH_IP_FRAG_NON_FRAG = 0b00; // Not fragmented.
const switch_ip_frag_t SWITCH_IP_FRAG_HEAD = 0b10; // First fragment of the fragmented packets.
const switch_ip_frag_t SWITCH_IP_FRAG_NON_HEAD = 0b11; // Fragment with non-zero offset.

typedef bit<2> switch_packet_action_t;
const switch_packet_action_t SWITCH_PACKET_ACTION_PERMIT = 0b00;
const switch_packet_action_t SWITCH_PACKET_ACTION_DROP = 0b01;
const switch_packet_action_t SWITCH_PACKET_ACTION_COPY = 0b10;
const switch_packet_action_t SWITCH_PACKET_ACTION_TRAP = 0b11;

// Bypass flags ---------------------------------------------------------------
typedef bit<16> switch_ingress_bypass_t;
#define bypass_l2_bit 0
#define bypass_l3_bit 1
#define bypass_acl_bit 2
#define bypass_system_acl_bit 3
#define bypass_qos_bit 4
#define bypass_meter_bit 5
#define bypass_storm_control_bit 6
#define bypass_stp_bit 7
#define bypass_smac_bit 8
#define bypass_nat_bit 9
#define bypass_routing_check_bit 10
#define bypass_pv_bit 11
#define bypass_bfd_tx_bit 15

const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_L2            = 16w0x0001 << bypass_l2_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_L3            = 16w0x0001 << bypass_l3_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_ACL           = 16w0x0001 << bypass_acl_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_SYSTEM_ACL    = 16w0x0001 << bypass_system_acl_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_QOS           = 16w0x0001 << bypass_qos_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_METER         = 16w0x0001 << bypass_meter_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_STORM_CONTROL = 16w0x0001 << bypass_storm_control_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_STP           = 16w0x0001 << bypass_stp_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_SMAC          = 16w0x0001 << bypass_smac_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_NAT           = 16w0x0001 << bypass_nat_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_ROUTING_CHECK = 16w0x0001 << bypass_routing_check_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_PV            = 16w0x0001 << bypass_pv_bit;
const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_BFD_TX        = 16w0x0001 << bypass_bfd_tx_bit;
// Add more ingress bypass flags here.

const switch_ingress_bypass_t SWITCH_INGRESS_BYPASS_ALL = 16w0x7fff;
#define INGRESS_BYPASS(t) (local_md.bypass & SWITCH_INGRESS_BYPASS_##t != 0)

// PKT ------------------------------------------------------------------------
typedef bit<16> switch_pkt_length_t;

typedef bit<8> switch_pkt_src_t;
const switch_pkt_src_t SWITCH_PKT_SRC_BRIDGED = 0;
const switch_pkt_src_t SWITCH_PKT_SRC_CLONED_INGRESS = 1; // mirror original ingress packet
const switch_pkt_src_t SWITCH_PKT_SRC_CLONED_EGRESS = 2;  // mirror final egress packet
const switch_pkt_src_t SWITCH_PKT_SRC_DEFLECTED = 3;
const switch_pkt_src_t SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT= 4;  // mirror packet ingressing from TM to egress parser

typedef bit<2> switch_pkt_color_t;
const switch_pkt_color_t SWITCH_METER_COLOR_GREEN = 0;
const switch_pkt_color_t SWITCH_METER_COLOR_YELLOW = 1;
const switch_pkt_color_t SWITCH_METER_COLOR_RED = 3;

typedef bit<2> switch_pkt_type_t;
const switch_pkt_type_t SWITCH_PKT_TYPE_UNICAST = 0;
const switch_pkt_type_t SWITCH_PKT_TYPE_MULTICAST = 1;
const switch_pkt_type_t SWITCH_PKT_TYPE_BROADCAST = 2;

// LOU ------------------------------------------------------------------------
#define switch_l4_port_label_width 8
typedef bit<switch_l4_port_label_width> switch_l4_port_label_t;

// STP ------------------------------------------------------------------------
typedef bit<2> switch_stp_state_t;
const switch_stp_state_t SWITCH_STP_STATE_FORWARDING = 0;
const switch_stp_state_t SWITCH_STP_STATE_BLOCKING = 1;
const switch_stp_state_t SWITCH_STP_STATE_LEARNING = 2;

typedef bit<10> switch_stp_group_t;

struct switch_stp_metadata_t {
    switch_stp_group_t group;
    switch_stp_state_t state_;
}

// Nexthop --------------------------------------------------------------------
typedef bit<2> switch_nexthop_type_t;
const switch_nexthop_type_t SWITCH_NEXTHOP_TYPE_IP = 0;
const switch_nexthop_type_t SWITCH_NEXTHOP_TYPE_MPLS = 1;
const switch_nexthop_type_t SWITCH_NEXTHOP_TYPE_TUNNEL_ENCAP = 2;

// Sflow ----------------------------------------------------------------------
typedef bit<8> switch_sflow_id_t;
const switch_sflow_id_t SWITCH_SFLOW_INVALID_ID = 8w0xff;

struct switch_sflow_metadata_t {
    switch_sflow_id_t session_id;
    bit<1> sample_packet;
}

typedef bit<8> switch_hostif_trap_t;

// Metering -------------------------------------------------------------------
#define switch_copp_meter_id_width 8
typedef bit<switch_copp_meter_id_width> switch_copp_meter_id_t;

#define switch_meter_index_width 10
typedef bit<switch_meter_index_width> switch_meter_index_t;

#define switch_mirror_meter_id_width 8
typedef bit<switch_mirror_meter_id_width> switch_mirror_meter_id_t;

// QoS ------------------------------------------------------------------------
typedef bit<2> switch_qos_trust_mode_t;
const switch_qos_trust_mode_t SWITCH_QOS_TRUST_MODE_UNTRUSTED = 0;
const switch_qos_trust_mode_t SWITCH_QOS_TRUST_MODE_TRUST_DSCP = 1;
const switch_qos_trust_mode_t SWITCH_QOS_TRUST_MODE_TRUST_PCP = 2;

typedef bit<5> switch_qos_group_t;

#define switch_tc_width 8
typedef bit<switch_tc_width> switch_tc_t;
typedef bit<3> switch_cos_t;

#define switch_etrap_index_width 11
typedef bit<switch_etrap_index_width> switch_etrap_index_t;

//MYIP type
typedef bit<2> switch_myip_type_t;
const switch_myip_type_t SWITCH_MYIP_NONE = 0;
const switch_myip_type_t SWITCH_MYIP = 1;
const switch_myip_type_t SWITCH_MYIP_SUBNET = 2;


struct switch_qos_metadata_t {
    switch_qos_trust_mode_t trust_mode; // Ingress only.
    switch_qos_group_t group;
    switch_tc_t tc;
    switch_pkt_color_t color;
    switch_pkt_color_t acl_meter_color;
    switch_pkt_color_t port_color;
    switch_pkt_color_t flow_color;
    switch_pkt_color_t storm_control_color;
    switch_meter_index_t port_meter_index;
    switch_meter_index_t acl_meter_index;
    switch_qid_t qid;
    switch_ingress_cos_t icos; // Ingress only.
    bit<19> qdepth; // Egress only.
    switch_etrap_index_t etrap_index;
    switch_pkt_color_t etrap_color;
    switch_tc_t etrap_tc;
    bit<1> etrap_state;
#if defined(TUNNEL_QOS_MODE_ENABLE)
    bit<2> outer_ecn; // Egress only.
#endif
}

// Learning -------------------------------------------------------------------
typedef bit<1> switch_learning_mode_t;
const switch_learning_mode_t SWITCH_LEARNING_MODE_DISABLED = 0;
const switch_learning_mode_t SWITCH_LEARNING_MODE_LEARN = 1;

struct switch_learning_digest_t {
    switch_bd_t bd;
    switch_port_lag_index_t port_lag_index;
    mac_addr_t src_addr;
}

struct switch_learning_metadata_t {
    switch_learning_mode_t bd_mode;
    switch_learning_mode_t port_mode;
    switch_learning_digest_t digest;
}

// Multicast ------------------------------------------------------------------
typedef bit<2> switch_multicast_mode_t;
const switch_multicast_mode_t SWITCH_MULTICAST_MODE_NONE = 0;
const switch_multicast_mode_t SWITCH_MULTICAST_MODE_PIM_SM = 1; // Sparse mode
const switch_multicast_mode_t SWITCH_MULTICAST_MODE_PIM_BIDIR = 2; // Bidirectional

typedef MulticastGroupId_t switch_mgid_t;

typedef bit<16> switch_multicast_rpf_group_t;

struct switch_multicast_metadata_t {
    switch_mgid_t id;
    bit<2> mode;
    switch_multicast_rpf_group_t rpf_group;
}

// URPF -----------------------------------------------------------------------
typedef bit<2> switch_urpf_mode_t;
const switch_urpf_mode_t SWITCH_URPF_MODE_NONE = 0;
const switch_urpf_mode_t SWITCH_URPF_MODE_LOOSE = 1;
const switch_urpf_mode_t SWITCH_URPF_MODE_STRICT = 2;

// WRED/ECN -------------------------------------------------------------------
#define switch_wred_index_width 10
typedef bit<switch_wred_index_width> switch_wred_index_t;

typedef bit<2> switch_ecn_codepoint_t;
const switch_ecn_codepoint_t SWITCH_ECN_CODEPOINT_NON_ECT = 0b00; // Non ECN-capable transport
const switch_ecn_codepoint_t SWITCH_ECN_CODEPOINT_ECT0 = 0b10; // ECN capable transport
const switch_ecn_codepoint_t SWITCH_ECN_CODEPOINT_ECT1 = 0b01; // ECN capable transport
const switch_ecn_codepoint_t SWITCH_ECN_CODEPOINT_CE = 0b11; // Congestion encountered
const switch_ecn_codepoint_t NON_ECT = 0b00; // Non ECN-capable transport
const switch_ecn_codepoint_t ECT0 = 0b10; // ECN capable transport
const switch_ecn_codepoint_t ECT1 = 0b01; // ECN capable transport
const switch_ecn_codepoint_t CE = 0b11; // Congestion encountered

// Mirroring ------------------------------------------------------------------
typedef MirrorId_t switch_mirror_session_t; // Defined in tna.p4
const switch_mirror_session_t SWITCH_MIRROR_SESSION_CPU = 250;

// Using same mirror type for both Ingress/Egress to simplify the parser.
typedef bit<8> switch_mirror_type_t;
#define SWITCH_MIRROR_TYPE_INVALID 0
#define SWITCH_MIRROR_TYPE_PORT 1
#define SWITCH_MIRROR_TYPE_CPU 2
#define SWITCH_MIRROR_TYPE_DTEL_DROP 3
#define SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL 4
#define SWITCH_MIRROR_TYPE_SIMPLE 5
#define SWITCH_MIRROR_TYPE_SFC 6
#define SWITCH_MIRROR_TYPE_PORT_WITH_B_MD  7
/* Although strictly speaking deflected packets are not mirrored packets,
 * need a mirror_type codepoint for packet length adjustment.
 * Pick a large value since this is not used by mirror logic.
 */
#define SWITCH_MIRROR_TYPE_DTEL_DEFLECT 255

// Common metadata used for mirroring.
struct switch_mirror_metadata_t {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
    switch_mirror_session_t session_id;
    switch_mirror_meter_id_t meter_index;
}

header switch_port_mirror_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
#if __TARGET_TOFINO__ == 1
    bit<6> _pad;
#endif
    switch_mirror_session_t session_id;
}


// add include app_id mirror header
header switch_port_mirror_appid_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
#if __TARGET_TOFINO__ == 1
    bit<6> _pad;
#endif
    switch_mirror_session_t session_id;

    //add app_id
    bit<16> app_id;
}


header switch_cpu_mirror_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
    switch_port_padding_t _pad1;
    switch_port_t port;
    switch_bd_t bd;
    bit<6> _pad2;
    switch_port_lag_index_t port_lag_index;
    switch_cpu_reason_t reason_code;
}

// Tunneling ------------------------------------------------------------------
typedef bit<1> switch_tunnel_mode_t;
const switch_tunnel_mode_t SWITCH_TUNNEL_MODE_PIPE = 0;
const switch_tunnel_mode_t SWITCH_TUNNEL_MODE_UNIFORM = 1;

typedef bit<4> switch_tunnel_type_t;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_NONE = 0;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_VXLAN = 1;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_IPINIP = 2;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_GRE = 3;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_NVGRE = 4;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_MPLS = 5;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_SRV6 = 6;
const switch_tunnel_type_t SWITCH_INGRESS_TUNNEL_TYPE_NVGRE_ST = 7;

const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_NONE = 0;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN = 1;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN = 2;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV4_IPINIP = 3;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV6_IPINIP = 4;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE = 5;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE = 6;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_MPLS = 7;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP = 8;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT = 9;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GRE = 10;
const switch_tunnel_type_t SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GRE = 11;

enum switch_tunnel_term_mode_t { P2P, P2MP };

#if defined(VXLAN_ENABLE) || defined(NVGRE_ENABLE)
#define INNER_L2_ENABLE
#endif

#define USID_BLOCK_MASK 0xffffffff000000000000000000000000
#define USID_BLOCK_LEN 32
#define USID_ID_LEN 16

#ifndef switch_tunnel_index_width
#define switch_tunnel_index_width 4
#endif
typedef bit<switch_tunnel_index_width> switch_tunnel_index_t;
#ifndef switch_tunnel_ip_index_width
#define switch_tunnel_ip_index_width 16
#endif
typedef bit<switch_tunnel_ip_index_width> switch_tunnel_ip_index_t;
#ifndef switch_tunnel_nexthop_width
#define switch_tunnel_nexthop_width 16
#endif
typedef bit<switch_tunnel_nexthop_width> switch_tunnel_nexthop_t;
typedef bit<24> switch_tunnel_vni_t;

struct switch_tunnel_metadata_t {
    switch_tunnel_type_t type;
    switch_tunnel_index_t index; // Egress only.
    switch_tunnel_ip_index_t dip_index;
    switch_tunnel_vni_t vni;
    switch_ifindex_t ifindex;
    switch_tunnel_mode_t qos_mode;
    switch_tunnel_mode_t ttl_mode;
    bit<8> encap_ttl;
    bit<8> encap_dscp;
    bit<16> hash;
    bool terminate;
    bit<8> nvgre_flow_id;
    bit<2> mpls_pop_count;
    bit<3> mpls_push_count;
    bit<8> mpls_encap_ttl;
    bit<3> mpls_encap_exp;
    bit<1> mpls_swap;
    bit<128> srh_next_sid;
    bit<8> srh_seg_left;
    bit<8> srh_next_hdr;
    bit<3> srv6_seg_len;
    bit<6> srh_hdr_len;
    bool remove_srh;
    bool pop_active_segment;
    bool srh_decap_forward;
}

struct switch_nvgre_value_set_t {
    bit<32> vsid_flowid;
}

// Data-plane telemetry (DTel) ------------------------------------------------
/* report_type bits for drop and flow reflect dtel_acl results,
 * i.e. whether drop reports and flow reports may be triggered by this packet.
 * report_type bit for queue is not used by bridged / deflected packets,
 * reflects whether queue report is triggered by this packet in cloned packets.
 */
typedef bit<8> switch_dtel_report_type_t;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_NONE = 0b000;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_DROP = 0b100;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_QUEUE = 0b010;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_FLOW = 0b001;

const switch_dtel_report_type_t SWITCH_DTEL_SUPPRESS_REPORT = 0b1000;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_IFA_CLONE = 0b10000;
const switch_dtel_report_type_t SWITCH_DTEL_IFA_EDGE = 0b100000;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_ETRAP_CHANGE = 0b1000000;
const switch_dtel_report_type_t SWITCH_DTEL_REPORT_TYPE_ETRAP_HIT = 0b10000000;

typedef bit<8> switch_ifa_sample_id_t;

#ifdef INT_V2
#define switch_dtel_hw_id_width 4
#define switch_dtel_switch_id_width 32
#else
#define switch_dtel_hw_id_width 6
#define switch_dtel_switch_id_width 32
#endif
typedef bit<switch_dtel_hw_id_width> switch_dtel_hw_id_t;
typedef bit<switch_dtel_switch_id_width> switch_dtel_switch_id_t;

// Outer header sizes for DTEL Reports
/* Up to the beginning of the DTEL Report v0.5 header
 * 14 (Eth) + 20 (IPv4) + 8 (UDP) + 4 (CRC) = 46 bytes */
const bit<16> DTEL_REPORT_V0_5_OUTER_HEADERS_LENGTH = 46;
/* Outer headers + part of DTEL Report v2 length not included in report_length
 * 14 (Eth) + 20 (IPv4) + 8 (UDP) + 12 (DTEL) + 4 (CRC) = 58 bytes */
const bit<16> DTEL_REPORT_V2_OUTER_HEADERS_LENGTH = 58;

struct switch_dtel_metadata_t {
    switch_dtel_report_type_t report_type;
    bit<1> ifa_gen_clone; // Ingress only, indicates desire to clone this packet
    bit<1> ifa_cloned; // Egress only, indicates this is an ifa cloned packet
    bit<32> latency; // Egress only.
    switch_mirror_session_t session_id;
    switch_mirror_session_t clone_session_id; // Used for IFA interop
    bit<32> hash;
    bit<2> drop_report_flag; // Egress only.
    bit<2> flow_report_flag; // Egress only.
    bit<1> queue_report_flag; // Egress only.
}

typedef bit<4> switch_ingress_nat_hit_type_t;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_NONE = 0;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_FLOW_NONE = 1;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_FLOW_NAPT = 2;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_FLOW_NAT = 3;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_DEST_NONE = 4;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_DEST_NAPT = 5;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_DEST_NAT = 6;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_SRC_NONE = 7;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_SRC_NAPT = 8;
const switch_ingress_nat_hit_type_t SWITCH_NAT_HIT_TYPE_SRC_NAT = 9;

typedef bit<1> switch_nat_zone_t;
const switch_nat_zone_t SWITCH_NAT_INSIDE_ZONE_ID = 0;
const switch_nat_zone_t SWITCH_NAT_OUTSIDE_ZONE_ID = 1;

struct switch_nat_ingress_metadata_t {
  switch_ingress_nat_hit_type_t hit;
  switch_nat_zone_t ingress_zone;
  bit<16> dnapt_index;
  bit<16> snapt_index;
  bool nat_disable;
  bool dnat_pool_hit;
}

header switch_dtel_switch_local_mirror_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
#if __TARGET_TOFINO__ == 1
    bit<6> _pad;
#endif
    switch_mirror_session_t session_id;
    bit<32> hash;
    switch_dtel_report_type_t report_type;
    switch_port_padding_t _pad2;
    switch_port_t ingress_port;
    switch_port_padding_t _pad3;
    switch_port_t egress_port;
#if __TARGET_TOFINO__ == 1
    bit<3> _pad4;
#else
    bit<1> _pad4;
#endif
    switch_qid_t qid;
    bit<5> _pad5;
    bit<19> qdepth;
#ifdef INT_V2
    bit<48> egress_timestamp;
#else
    bit<32> egress_timestamp;
#endif
}

header switch_dtel_drop_mirror_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
#if __TARGET_TOFINO__ == 1
    bit<6> _pad;
#endif
    switch_mirror_session_t session_id;
    bit<32> hash;
    switch_dtel_report_type_t report_type;
    switch_port_padding_t _pad2;
    switch_port_t ingress_port;
    switch_port_padding_t _pad3;
    switch_port_t egress_port;
#if __TARGET_TOFINO__ == 1
    bit<3> _pad4;
#else
    bit<1> _pad4;
#endif
    switch_qid_t qid;
    switch_drop_reason_t drop_reason;
}

// Used for dtel truncate_only and ifa_clone mirror sessions
header switch_simple_mirror_metadata_h {
    switch_pkt_src_t src;
    switch_mirror_type_t type;
#if __TARGET_TOFINO__ == 1
    bit<6> _pad;
#endif
    switch_mirror_session_t session_id;
}

@flexible
struct switch_bridged_metadata_dtel_extension_t {
    switch_dtel_report_type_t report_type;
    switch_mirror_session_t session_id;
    bit<32> hash;
    switch_port_t egress_port;
}

// Source Flow Control related types (SFC) ------------------------------------------------

enum bit<2> LinkToType {
    Unknown = 0,
    Switch = 1,
    Server = 2
}

const bit<32> msb_set_32b = 32w0x80000000;

#ifdef SFC_ENABLE
typedef bit<1> ping_pong_t;
typedef bit<32> const_t;

#define SFC_QUEUE_IDX_BITS 8
#define SFC_QUEUE_THRESHOLD_IDX_BITS 3
#define SFC_BUFFER_POOL_IDX_BITS 2
#define SFC_BUFFER_POOL_IDX_PAD_8BIT_BITS 6

// Allow combinations of ingress pipe 9bit egress port + 7bit egress queue
typedef bit<16> sfc_ingress_queue_idx_t;
// This applies to: sfc_queue_idx_t, sfc_buffer_pool_idx_t
typedef bit<SFC_QUEUE_IDX_BITS> sfc_queue_idx_t;
//typedef bit<SFC_QUEUE_IDX_PAD_16BIT_BITS> sfc_queue_idx_pad_16bit_t;
typedef bit<SFC_BUFFER_POOL_IDX_BITS> sfc_buffer_pool_idx_t;
typedef bit<SFC_BUFFER_POOL_IDX_PAD_8BIT_BITS> sfc_buffer_pool_idx_pad_8bit_t;

typedef bit<SFC_SUPPRESSION_FILTER_WIDTH> sfc_suppression_filter_idx_t;

typedef bit<16> buffer_memory_egress_t;
typedef bit<16> buffer_memory_ghost_t;
typedef bit<5>  buffer_memory_pad_24bit_t;
typedef bit<11> tm_hw_queue_id_t;
typedef bit<2>  pipe_id_t;
typedef bit<16> sfc_pause_duration_us_t;
typedef bit<SFC_QUEUE_THRESHOLD_IDX_BITS>  sfc_queue_threshold_idx_t;

enum bit<3> SfcPacketType {
    Unset           = 0,
    None            = 1,  // No SFC packet
    Data            = 2,  // Normal SFC data packet, SFC is enabled
    Trigger         = 3,  // SFC pause packet after mirroring, SFC is enabled
    Signal          = 4,  // SFC pause packet after SFC pause packet construction, SFC is enabled
    TcSignalEnabled = 5   // No SFC packet, but a packet on a SignalingEnabledTC
}
typedef bit<5> SfcPacketType_pad_8bit_t;

struct sfc_qd_threshold_register_t {
    bit<32> qdepth_drain_cells;
    bit<32> target_qdepth;
}

struct sfc_pause_epoch_register_t {
    bit<32>     current_epoch_start;
    bit<32>     bank_idx_changed;
}

struct sfc_ghost_threshold_debug_register_t {
    bit<32> first_value_over_threshold;
    bit<32> over_threshold_counter;
}

// Metadata for SFC used in ghost thread
struct sfc_ghost_metadata_t {
    sfc_ingress_queue_idx_t ingress_port_queue_idx;
    buffer_memory_ghost_t   qdepth_threshold_remainder;
}

// Metadata for SFC used in ingress thread
struct switch_sfc_local_metadata_t {
    SfcPacketType               type;
    // [1:1]: switch bank
    // [0:0]: bank idx
    bit<2>                      switch_bank_idx;
    MirrorId_t                  signaling_mirror_session_id;
    bool                        qlength_over_threshold;
    bit<16>                     suppression_hash_0;
    bit<16>                     suppression_hash_1;
    sfc_queue_idx_t             queue_register_idx;

    buffer_memory_egress_t      q_drain_length;
    bit<8>                      pause_dscp;
    // Calculate in egress
    sfc_pause_duration_us_t     pause_duration_us;
    LinkToType                  link_to_type;
    bit<16>                     multiplier_second_part;
    bit<8>                      sfc_pause_packet_dscp;
}

@flexible
struct switch_bridged_metadata_sfc_extension_t {
    SfcPacketType               type;
    sfc_queue_idx_t             queue_register_idx;
}

// Metadata for SFC used in egress thread
// @flexible
// struct switch_sfc_egress_metadata_t {
//     // Pick up from bridged or bridge md
//     SfcPacketType               type;
//     sfc_queue_idx_t             queue_register_idx;
//     // Set in egress
//     buffer_memory_egress_t      q_drain_length;
//     bit<8>                      pause_dscp;
//     // Calculate in egress
//     sfc_pause_duration_us_t     pause_duration_us;
//     LinkToType                  link_to_type;
//     bit<16>                     multiplier_second_part;
//     bit<8>                      sfc_pause_packet_dscp;
//     // bit<16>                     ingress_port;
//     // bit<16>                     port_lag_index;
// }

header switch_sfc_pause_mirror_metadata_h {
    switch_pkt_src_t        src;
    switch_mirror_type_t    type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
    sfc_queue_idx_t         queue_register_idx;
    switch_nexthop_t        nexthop;
    bit<16>                 ingress_port;
    bit<16>                 port_lag_index;
}
#endif

//-----------------------------------------------------------------------------
// Other Metadata Definitions
//-----------------------------------------------------------------------------
// Flags
//XXX Force the fields that are XORd to NOT share containers.
@pa_container_size("ingress", "local_md.checks.same_if", 16)
#ifdef L3_UNICAST_SELF_FORWARDING_CHECK
@pa_container_size("ingress", "local_md.checks.same_bd", 16)
#endif
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ip_src_addr")
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ip_dst_addr")
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ipv6_flow_label")
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ip_proto")
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ip_ttl")
@pa_mutually_exclusive("ingress", "lkp.arp_opcode", "lkp.ip_tos")
#ifdef MPLS_ENABLE
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ip_src_addr")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ip_dst_addr")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ipv6_flow_label")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ip_proto")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ip_ttl")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.ip_tos")
@pa_mutually_exclusive("ingress", "lkp.mpls_lookup_label", "lkp.arp_opcode")
@pa_mutually_exclusive("egress", "hdr.mpls[2].label", "hdr.ipv6.dst_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].exp",   "hdr.ipv6.dst_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].bos",   "hdr.ipv6.dst_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].label", "hdr.ipv6.src_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].exp",   "hdr.ipv6.src_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].bos",   "hdr.ipv6.src_addr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].label", "hdr.ipv6.flow_label")
@pa_mutually_exclusive("egress", "hdr.mpls[2].exp",   "hdr.ipv6.flow_label")
@pa_mutually_exclusive("egress", "hdr.mpls[2].bos",   "hdr.ipv6.flow_label")
@pa_mutually_exclusive("egress", "hdr.mpls[2].label", "hdr.ipv6.next_hdr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].exp",   "hdr.ipv6.next_hdr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].bos",   "hdr.ipv6.next_hdr")
@pa_mutually_exclusive("egress", "hdr.mpls[2].label", "hdr.ipv6.payload_len")
@pa_mutually_exclusive("egress", "hdr.mpls[2].exp",   "hdr.ipv6.payload_len")
@pa_mutually_exclusive("egress", "hdr.mpls[2].bos",   "hdr.ipv6.payload_len")
#endif

struct switch_flags_t {
    bool ipv4_checksum_err;
    bool inner_ipv4_checksum_err;
    bool inner2_ipv4_checksum_err;
    bool link_local;
    bool routed;
    bool acl_deny;
    bool racl_deny;
    bool port_vlan_miss;
    bool rmac_hit;
    bool dmac_miss;
    switch_myip_type_t myip;
    bool glean;
    bool storm_control_drop;
    bool port_meter_drop;
    bool flood_to_multicast_routers;
    bool peer_link;
    bool capture_ts;
    bool mac_pkt_class;
    bool pfc_wd_drop;
    bool bypass_egress;
    bool mpls_trap;
    bool srv6_trap;
    bool mlag_member;
    bool wred_drop;
    bool port_isolation_packet_drop;
    bool bport_isolation_packet_drop;
    bool fib_lpm_miss;
    bool fib_drop;
    switch_packet_action_t meter_packet_action;
    bool bfd_to_cpu;
    // Add more flags here.
}

//struct switch_egress_flags_t {
//    bool routed;
//    bool bypass_egress;
//    bool acl_deny;
//    bool mlag_member;
//    bool peer_link;
//    bool capture_ts;
//    bool port_meter_drop;
//    bool acl_meter_drop;
//    bool pfc_wd_drop;
//    bool isolation_packet_drop;
//
//    // Add more flags here.
//}
//

// Checks
struct switch_checks_t {
    switch_port_lag_index_t same_if;
    bool mrpf;
    bool urpf;
    switch_nat_zone_t same_zone_check;
    switch_bd_t same_bd;
    switch_mtu_t mtu;
    bool stp;
    // Add more checks here.
}

//struct switch_egress_checks_t {
//    switch_bd_t same_bd;
//    switch_mtu_t mtu;
//    bool stp;
//
//    // Add more checks here.
//}

// IP
struct switch_ip_metadata_t {
    bool unicast_enable;
    bool multicast_enable;
    bool multicast_snooping;
    // switch_urpf_mode_t urpf_mode;
}

struct switch_lookup_fields_t {
    switch_pkt_type_t pkt_type;

    //mac_addr_t mac_src_addr;
    mac_addr_t mac_dst_addr;
    bit<16> mac_type;
    bit<3> pcp;

    // 1 for ARP request, 2 for ARP reply.
    bit<16> arp_opcode;

    switch_ip_type_t ip_type;
    bit<8> ip_proto;
    bit<8> ip_ttl;
    bit<8> ip_tos;
    switch_ip_frag_t ip_frag;
    bit<128> ip_src_addr;
    bit<128> ip_dst_addr;
    bit<20> ipv6_flow_label;

    bit<8> tcp_flags;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<16> hash_l4_src_port;
    bit<16> hash_l4_dst_port;

    bool mpls_pkt;
    bit<1> mpls_router_alert_label;
    bit<20> mpls_lookup_label;
}

struct switch_hash_fields_t {
    mac_addr_t mac_src_addr;
    mac_addr_t mac_dst_addr;
    bit<16> mac_type;
    switch_ip_type_t ip_type;
    bit<8> ip_proto;
    bit<128> ip_src_addr;
    bit<128> ip_dst_addr;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<20> ipv6_flow_label;
    bit<32> outer_ip_src_addr;
    bit<32> outer_ip_dst_addr;
}

// Header types used by ingress/egress deparsers.
@flexible
struct switch_bridged_metadata_t {
    // user-defined metadata carried over from ingress to egress.
    switch_port_t ingress_port;
    switch_port_lag_index_t ingress_port_lag_index;
    switch_bd_t ingress_bd;
    switch_nexthop_t nexthop;
    switch_pkt_type_t pkt_type;
    bool routed;
    bool bypass_egress;
    //TODO(msharif) : Fix the bridged metadata fields for PTP.
#if defined(PTP_ENABLE)
    bool capture_ts;
#endif
#ifdef MLAG_ENABLE
    bool peer_link;
#endif
    switch_cpu_reason_t cpu_reason;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
    switch_tc_t tc;
    switch_qid_t qid;
    switch_pkt_color_t color;
    switch_vrf_t vrf;
#ifdef BFD_OFFLOAD_ENABLE
	bit<1> bfd_rx_recirc;
#endif
    // Add more fields here.
}

@flexible
struct switch_bridged_metadata_acl_extension_t {
#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE)
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<8> tcp_flags;
#if defined(EGRESS_ACL_PORT_RANGE_ENABLE) && !defined(L4_PORT_EGRESS_LOU_ENABLE)
    switch_l4_port_label_t l4_src_port_label;
    switch_l4_port_label_t l4_dst_port_label;
#endif // EGRESS_ACL_PORT_RANGE_ENABLE && !L4_PORT_EGRESS_LOU_ENABLE
#ifdef ACL_USER_META_ENABLE
    switch_user_metadata_t user_metadata;
#endif
#else
    bit<8> tcp_flags;
#endif
}

@flexible
struct switch_bridged_metadata_tunnel_extension_t {
//    switch_tunnel_index_t index;
    switch_tunnel_nexthop_t tunnel_nexthop;
#if defined(VXLAN_ENABLE) && !defined(DTEL_ENABLE)
    bit<16> hash;
#endif
#ifdef MPLS_ENABLE
    bit<2> mpls_pop_count;
#endif
#ifdef TUNNEL_TTL_MODE_ENABLE
    switch_tunnel_mode_t ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
    switch_tunnel_mode_t qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
    bool terminate;
}

#ifdef DTEL_ENABLE
@pa_atomic("ingress", "hdr.bridged_md.base_qid")
@pa_container_size("ingress", "hdr.bridged_md.base_qid", 8)
@pa_container_size("ingress", "hdr.bridged_md.dtel_report_type", 8)
@pa_no_overlay("ingress", "hdr.bridged_md.base_qid")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_0")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_1")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_2")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_3")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_4")
@pa_no_overlay("ingress", "hdr.bridged_md.__pad_5")
@pa_no_overlay("egress", "hdr.dtel_report.ingress_port")
@pa_no_overlay("egress", "hdr.dtel_report.egress_port")
@pa_no_overlay("egress", "hdr.dtel_report.queue_id")
@pa_no_overlay("egress", "hdr.dtel_drop_report.drop_reason")
@pa_no_overlay("egress", "hdr.dtel_drop_report.reserved")
#ifdef INT_V2
@pa_no_overlay("egress", "hdr.dtel_metadata_1.ingress_port")
@pa_no_overlay("egress", "hdr.dtel_metadata_1.egress_port")
@pa_no_overlay("egress", "hdr.dtel_metadata_3.queue_id")
@pa_no_overlay("egress", "hdr.dtel_metadata_4.ingress_timestamp")
@pa_no_overlay("egress", "hdr.dtel_metadata_5.egress_timestamp")
@pa_no_overlay("egress", "hdr.dtel_metadata_3.queue_occupancy")
#endif
@pa_no_overlay("egress", "hdr.dtel_switch_local_report.queue_occupancy")
#endif

#ifdef TUNNEL_ENABLE
/* TTL and DSCP must not be overlaid when tunnel mode uniform is supported.
 * Whichever one goes first will break the other for either v6 in v4, or
 * v4 in v6.
 */
@pa_no_overlay("egress", "hdr.ipv4.ttl", "hdr.ipv6.traffic_class")
@pa_no_overlay("egress", "hdr.ipv6.hop_limit", "hdr.ipv4.diffserv")
#endif

#if defined(VXLAN_ENABLE) && defined(ERSPAN_ENABLE)
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.vxlan.flags")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.vxlan.reserved")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.vxlan.vni")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.vxlan.reserved2")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.vxlan.flags")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.vxlan.reserved")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.vxlan.vni")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.vxlan.reserved2")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.vxlan.flags")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.vxlan.reserved")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.vxlan.vni")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.vxlan.reserved2")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.vxlan.flags")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.vxlan.reserved")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.vxlan.vni")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.vxlan.reserved2")
#endif
#if defined(ERSPAN_TYPE2_ENABLE)
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.erspan_type2.index")
#endif
#if defined(SRV6_ENABLE) && defined(ERSPAN_ENABLE)
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.next_hdr")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.hdr_ext_len")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.routing_type")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.seg_left")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.last_entry")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.flags")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.srh_base.tag")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp",  "hdr.srh_seg_list[0].sid")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.srh_seg_list[0].sid")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan",     "hdr.srh_seg_list[0].sid")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id",       "hdr.srh_seg_list[0].sid")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp",  "hdr.srh_seg_list[1].sid")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.srh_seg_list[1].sid")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan",     "hdr.srh_seg_list[1].sid")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id",       "hdr.srh_seg_list[1].sid")
#endif
#if defined(DTEL_ENABLE) && defined(ERSPAN_ENABLE)
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.udp.src_port")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.udp.dst_port")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.udp.length")
@pa_mutually_exclusive("egress", "hdr.gre.proto", "hdr.udp.checksum")
@pa_mutually_exclusive("egress", "hdr.gre.flags_version", "hdr.udp.src_port")
@pa_mutually_exclusive("egress", "hdr.gre.flags_version", "hdr.udp.dst_port")
@pa_mutually_exclusive("egress", "hdr.gre.flags_version", "hdr.udp.length")
@pa_mutually_exclusive("egress", "hdr.gre.flags_version", "hdr.udp.checksum")

@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.erspan.version_vlan", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.erspan.session_id", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.timestamp", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.erspan_type3.ft_d_other", "hdr.dtel_report.egress_port")
#endif

#if defined(DTEL_ENABLE) && defined(VXLAN_ENABLE)
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.vxlan.flags", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.vxlan.vni", "hdr.dtel_report.egress_port")

@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.version")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.next_proto")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.hw_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.d_q_f")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.seq_number")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.switch_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel.timestamp")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_drop_report.drop_reason")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_switch_local_report.pad3")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_switch_local_report.queue_occupancy")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.pad0")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.pad1")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.pad2")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.queue_id")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.ingress_port")
@pa_mutually_exclusive("egress", "hdr.vxlan.reserved2", "hdr.dtel_report.egress_port")
#endif

typedef bit<8> switch_bridge_type_t;

header switch_bridged_metadata_h {
    switch_pkt_src_t src;
    switch_bridge_type_t type;
    switch_bridged_metadata_t base;
#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE) \
    || defined(DTEL_FLOW_REPORT_ENABLE)
    switch_bridged_metadata_acl_extension_t acl;
#endif
#ifdef TUNNEL_ENABLE
    switch_bridged_metadata_tunnel_extension_t tunnel;
#endif
#ifdef DTEL_ENABLE
    switch_bridged_metadata_dtel_extension_t dtel;
#endif
#ifdef SFC_ENABLE
    switch_bridged_metadata_sfc_extension_t sfc;
#endif
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
    switch_mirror_metadata_t mirror;
#endif
}

struct switch_port_metadata_t {
    switch_port_lag_index_t port_lag_index;
    switch_ig_port_lag_label_t port_lag_label;
#ifdef ASYMMETRIC_FOLDED_PIPELINE
    switch_port_t ext_ingress_port;
#endif
#ifdef IN_PORTS_IN_ACL_KEY_ENABLE
    switch_ig_port_lag_label_t in_ports_group_label;
#endif
}

// consistent hash - calculation of v6 high/low ip is
// multi-stage process. So this variable tracks the
// v6 ip sequence for crc hash - must be one of the below
//   - none
//   - low-ip is sip, high-ip is dip
//   - low-ip is dip, high-ip is sip
typedef bit<2> switch_cons_hash_ip_seq_t;
const switch_cons_hash_ip_seq_t SWITCH_CONS_HASH_IP_SEQ_NONE = 0;
const switch_cons_hash_ip_seq_t SWITCH_CONS_HASH_IP_SEQ_SIPDIP = 1;
const switch_cons_hash_ip_seq_t SWITCH_CONS_HASH_IP_SEQ_DIPSIP = 2;

@pa_auto_init_metadata

@pa_container_size("ingress", "local_md.mirror.src", 8)
@pa_container_size("ingress", "local_md.mirror.type", 8)
@pa_container_size("ingress", "smac_src_move", 16)
@pa_alias("ingress", "local_md.egress_port", "ig_intr_md_for_tm.ucast_egress_port")
#if !((defined(DTEL_DROP_REPORT_ENABLE) || defined(DTEL_QUEUE_REPORT_ENABLE)) && __TARGET_TOFINO__ == 1)
@pa_alias("ingress", "local_md.multicast.id", "ig_intr_md_for_tm.mcast_grp_b")
#endif
@pa_alias("ingress", "local_md.qos.qid", "ig_intr_md_for_tm.qid")
@pa_alias("ingress", "local_md.qos.icos", "ig_intr_md_for_tm.ingress_cos")
@pa_alias("ingress", "ig_intr_md_for_dprsr.mirror_type", "local_md.mirror.type")
@pa_container_size("ingress", "local_md.egress_port_lag_index", 16)
#ifdef NAT_ENABLE
// Prevent container_size 32 which doubles src_napt action ram
@pa_container_size("ingress", "local_md.nat.snapt_index", 16)
#endif
@pa_container_size("egress", "local_md.mirror.src", 8)
@pa_container_size("egress", "local_md.mirror.type", 8)
#ifdef DTEL_ENABLE
@pa_container_size("egress", "hdr.dtel_drop_report.drop_reason", 8)
#endif
#if !defined(TUNNEL_ENABLE)
@pa_alias("ingress", "local_md.ingress_outer_bd", "local_md.bd")
#endif

// Ingress/Egress metadata
struct switch_local_metadata_t {
    switch_port_t ingress_port;                            /* ingress port */
    switch_port_t egress_port;                             /* egress port */
    switch_port_lag_index_t ingress_port_lag_index;        /* ingress port/lag index */
    switch_port_lag_index_t egress_port_lag_index;         /* egress port/lag index */
    switch_bd_t bd;
    switch_bd_t ingress_outer_bd;
    switch_vrf_t vrf;
    switch_nexthop_t nexthop;
    switch_tunnel_nexthop_t tunnel_nexthop;
    switch_nexthop_t acl_nexthop;
    bool acl_port_redirect;
    switch_nexthop_t unused_nexthop;

    // add protocol flag , 1 tcp , 2 udp
    bit<8> tcp_or_udp;

    //add payload32 metadata (16B)
    bit<16> payload_length;
    bit<32> payload32_0;
    bit<32> payload32_1;
    bit<32> payload32_2;
    bit<32> payload32_3;
    //bit<32> payload32_4;
    //bit<32> payload32_5;
    //bit<32> payload32_6;
    //bit<32> payload32_7;

    // add flag app_id
    bit<12> app_id;

#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> timestamp;
#else
    bit<32> timestamp;
#endif
    switch_hash_t hash;
    switch_hash_t lag_hash;

    switch_flags_t flags;
    switch_checks_t checks;
    switch_ingress_bypass_t bypass;

#ifdef MPLS_ENABLE
    bool mpls_enable;
#endif
    switch_ip_metadata_t ipv4;
    switch_ip_metadata_t ipv6;
    switch_ig_port_lag_label_t ingress_port_lag_label;
    switch_bd_label_t bd_label;
    switch_l4_port_label_t l4_src_port_label;
    switch_l4_port_label_t l4_dst_port_label;

    switch_drop_reason_t l2_drop_reason;
    switch_drop_reason_t drop_reason;
    switch_cpu_reason_t cpu_reason;

    switch_lookup_fields_t lkp;
    switch_hostif_trap_t hostif_trap_id;
    switch_hash_fields_t hash_fields;
    switch_multicast_metadata_t multicast;
    switch_stp_metadata_t stp;
    switch_qos_metadata_t qos;
    switch_sflow_metadata_t sflow;
    switch_tunnel_metadata_t tunnel;
    switch_learning_metadata_t learning;
    switch_mirror_metadata_t mirror;
    switch_dtel_metadata_t dtel;
#ifdef SFC_ENABLE
    //switch_sfc_ingress_metadata_t sfc;
    switch_sfc_local_metadata_t sfc;
#endif
    mac_addr_t same_mac;

    switch_user_metadata_t user_metadata;
#ifdef NAT_ENABLE
    bit<16> tcp_udp_checksum;
    switch_nat_ingress_metadata_t nat;
#endif
    bit<10> partition_key;
    bit<12> partition_index;
    switch_fib_label_t fib_label;

    switch_cons_hash_ip_seq_t cons_hash_v6_ip_seq;
    switch_pkt_src_t pkt_src;
    switch_pkt_length_t pkt_length;
    switch_pkt_type_t pkt_type;
#if defined(PTP_ENABLE) || defined(INT_V2)
    bit<48> egress_timestamp;
    bit<48> ingress_timestamp;
#else
    bit<32> egress_timestamp;
    bit<32> ingress_timestamp;
#endif
    switch_eg_port_lag_label_t egress_port_lag_label;
    switch_nexthop_type_t nexthop_type;
    bool inner_ipv4_checksum_update_en;
#ifdef PORT_ISOLATION_ENABLE
    switch_isolation_group_t port_isolation_group;
    switch_isolation_group_t bport_isolation_group;
#endif
#ifdef BFD_OFFLOAD_ENABLE
	switch_bfd_metadata_t bfd;
#endif
#ifdef IN_PORTS_IN_ACL_KEY_ENABLE
    switch_ig_port_lag_label_t in_ports_group_label;
#endif
#ifdef OUT_PORTS_IN_ACL_KEY_ENABLE
    switch_eg_port_lag_label_t out_ports_group_label;
#endif
}

// Header format for mirrored metadata fields
struct switch_mirror_metadata_h {
    switch_port_mirror_metadata_h port;
    switch_cpu_mirror_metadata_h cpu;
    switch_dtel_drop_mirror_metadata_h dtel_drop;
    switch_dtel_switch_local_mirror_metadata_h dtel_switch_local;
    switch_simple_mirror_metadata_h simple_mirror;
}


struct switch_header_t {
    switch_bridged_metadata_h bridged_md;
    // switch_mirror_metadata_h mirror;
    ethernet_h ethernet;
    fabric_h fabric;
    cpu_h cpu;
    timestamp_h timestamp;
    vlan_tag_h[VLAN_DEPTH] vlan_tag;
    mpls_h[MPLS_DEPTH] mpls;
#ifdef SFC_ENABLE
    pfc_h pfc;
#endif
    ipv4_h ipv4;
    ipv4_option_h ipv4_option;
    ipv6_h ipv6;
    arp_h arp;
    ipv6_srh_h srh_base;
    ipv6_segment_h[SEGMENT_DEPTH] srh_seg_list;
    udp_h udp;
    icmp_h icmp;
    igmp_h igmp;
    tcp_h tcp;
#ifdef INT_V2
    dtel_report_v20_h dtel;
    dtel_metadata_1_h dtel_metadata_1;
    dtel_metadata_2_h dtel_metadata_2;
    dtel_metadata_3_h dtel_metadata_3;
    dtel_metadata_4_h dtel_metadata_4;
    dtel_metadata_5_h dtel_metadata_5;
    dtel_report_metadata_15_h dtel_drop_report;
#else
    dtel_report_v05_h dtel;
    dtel_report_base_h dtel_report;
    dtel_switch_local_report_h dtel_switch_local_report;
    dtel_drop_report_h dtel_drop_report;
#endif
    rocev2_bth_h rocev2_bth;
    gtpu_h gtp;
#ifdef SFC_ENABLE
    sfc_pause_h sfc_pause;
    padding_112b_h pad_112b;
    padding_96b_h pad_96b;
	#endif
#ifdef BFD_OFFLOAD_ENABLE
	bfd_h bfd;
#endif
    vxlan_h vxlan;
    gre_h gre;
    nvgre_h nvgre;
    geneve_h geneve;
    erspan_h erspan;
    erspan_type2_h erspan_type2;
    erspan_type3_h erspan_type3;
    erspan_platform_h erspan_platform;
    ethernet_h inner_ethernet;
    ipv4_h inner_ipv4;
    ipv6_h inner_ipv6;
    udp_h inner_udp;
    tcp_h inner_tcp;
    icmp_h inner_icmp;
    ipv4_h inner2_ipv4;
    ipv6_h inner2_ipv6;
    udp_h inner2_udp;
    tcp_h inner2_tcp;
    icmp_h inner2_icmp;
    pad_h pad;

    payload1_h payload1;
    payload2_h payload2;
    payload3_h payload3;
    payload4_h payload4;
    payload5_h payload5;
    payload6_h payload6;
    payload7_h payload7;
    // add header payload16
    payload8_h payload8;
    payload9_h payload9;
    payload10_h payload10;
    payload11_h payload11;
    payload12_h payload12;
    payload13_h payload13;
    payload14_h payload14;
    payload15_h payload15;
    // add header payload32
    payload16_h payload16;
    
}

#endif /* _P4_TYPES_ */
