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


//-----------------------------------------------------------------------------
// Protocol Header Definitions
//-----------------------------------------------------------------------------

#ifndef _P4_HEADERS_
#define _P4_HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;
const int PAD_SIZE = 32;
const int MIN_SIZE = 64;

@pa_container_size("ingress", "hdr.ethernet.src_addr", 16, 32)
@pa_container_size("ingress", "hdr.ethernet.dst_addr", 16, 32)
@pa_container_size("ingress", "hdr.ethernet.$valid", 16)
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

// Router Alert IP option -- RFC 2113, RFC 2711
header router_alert_option_h {
    bit<8> type;
    bit<8> length;
    bit<16> value;
}

header ipv4_option_h {
    bit<8> type;
    bit<8> length;
    bit<16> value;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

header payload1_h{
    bit<8> payload1_0;
}

header payload2_h{
    bit<16> payload2_0;
}

header payload3_h{
    bit<24> payload3_0;
}

header payload4_h{
    bit<32> payload4_0;
}

header payload5_h{
    bit<32> payload5_0;
    bit<8> payload5_1;
}

header payload6_h{
    bit<32> payload6_0;
    bit<16> payload6_1;
}

header payload7_h{
    bit<32> payload7_0;
    bit<24> payload7_1;
}

// add payload payload8 (8B)
header payload8_h{
    bit<32> payload8_0;
    bit<32> payload8_1;
}

header payload9_h{
    bit<32> payload9_0;
    bit<32> payload9_1;
    bit<8> payload9_2;
}

header payload10_h{
    bit<32> payload10_0;
    bit<32> payload10_1;
    bit<16> payload10_2;
}

header payload11_h{
    bit<32> payload11_0;
    bit<32> payload11_1;
    bit<24> payload11_2;
}

header payload12_h{
    bit<32> payload12_0;
    bit<32> payload12_1;
    bit<32> payload12_2;
}

header payload13_h{
    bit<32> payload13_0;
    bit<32> payload13_1;
    bit<32> payload13_2;
    bit<8> payload13_3;
}

header payload14_h{
    bit<32> payload14_0;
    bit<32> payload14_1;
    bit<32> payload14_2;
    bit<16> payload14_3;
}

header payload15_h{
    bit<32> payload15_0;
    bit<32> payload15_1;
    bit<32> payload15_2;
    bit<24> payload15_3;
}

// add header payload16 (16B)
header payload16_h {
    bit<32> payload16_0;
    bit<32> payload16_1;
    bit<32> payload16_2;
    bit<32> payload16_3;
}

header icmp_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    // ...
}

header igmp_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    // ...
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
#ifdef PARSE_FULL_ARP_HEADER
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
#endif
}

// RDMA over Converged Ethernet (RoCEv2)
header rocev2_bth_h {
    bit<8> opcodee;
    bit<1> se;
    bit<1> migration_req;
    bit<2> pad_count;
    bit<4> transport_version;
    bit<16> partition_key;
    bit<1> f_res1;
    bit<1> b_res1;
    bit<6> reserved;
    bit<24> dst_qp;
    bit<1> ack_req;
    bit<7> reserved2;
    // ...
}

// Fiber Channel over Ethernet (FCoE)
header fcoe_fc_h {
    bit<4> version;
    bit<100> reserved;
    bit<8> sof;        // Start of frame

    bit<8> r_ctl;      // Routing control
    bit<24> d_id;      // Destination identifier
    bit<8> cs_ctl;     // Class specific control
    bit<24> s_id;      // Source identifier
    bit<8> type;
    bit<24> f_ctl;     // Frame control
    bit<8> seq_id;
    bit<8> df_ctl;
    bit<16> seq_cnt;   // Sequence count
    bit<16> ox_id;     // Originator exchange id
    bit<16> rx_id;     // Responder exchange id
    // ...
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

header ipv6_segment_h {
    bit<128> sid;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Protocol Extension for VXLAN -- IETFv4
header vxlan_gpe_h {
    bit<8> flags;
    bit<16> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    /*
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    */
    bit<16> flags_version;
    bit<16> proto;
    bit<32> sequence_number;
}

// Network Virtualisation using GRE (NVGRE) -- RFC 7637
header nvgre_h {
    bit<32> vsid_flowid;    // vsid(24) + flowid(8)
}

// ERSPAN common header for type 2/3
header erspan_h {
    bit<16> version_vlan;
    bit<16> session_id;    // include cos_en_t(6) and session_id(10)
}

// ERSPAN Type II -- IETFv3
header erspan_type2_h {
    bit<32> index;        // include reserved(12) and index(20)
}

// ERSPAN Type III -- IETFv3
header erspan_type3_h {
    bit<32> timestamp;
    bit<32> ft_d_other;
    /*
    bit<16> sgt;    // Security group tag
    bit<1>  p;
    bit<5> ft;      // Frame type
    bit<6> hw_id;
    bit<1> d;       // Direction
    bit<2> gra;     // Timestamp granularity
    bit<1> o;       // Optional sub-header
    */
}

// ERSPAN platform specific subheader -- IETFv3
header erspan_platform_h {
    bit<6> id;
    bit<58> info;
}

// GTP V2
header gtpu_h {
    bit<3> version;
    bit<1> p;
    bit<1> t;
    bit<3> spare0;
    bit<8> mesg_type;
    bit<16> mesg_len;
    bit<32> teid;
    bit<24> seq_num;
    bit<8> spare1;
}

// Generic Network Virtualization Encapsulation (Geneve)
header geneve_h {
    bit<2> version;
    bit<6> opt_len;
    bit<1> oam;
    bit<1> critical;
    bit<6> reserved;
    bit<16> proto_type;
    bit<24> vni;
    bit<8> reserved2;
}

header geneve_option_h {
    bit<16> opt_class;
    bit<8> opt_type;
    bit<3> reserved;
    bit<5> opt_len;
}

// Bidirectional Forwarding Detection (BFD) -- RFC 5880
header bfd_h {
    bit<3> version;
    bit<5> diag;
    bit<8> flags;
    bit<8> detect_multi;
    bit<8> len;
    bit<32> my_discriminator;
    bit<32> your_discriminator;
    bit<32> desired_min_tx_interval;
    bit<32> req_min_rx_interval;
    bit<32> req_min_echo_rx_interval;
}

// Telemetry report header -- version 0.5
// See https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v0_5.pdf
header dtel_report_v05_h {
    bit<4> version;
    bit<4> next_proto;
    bit<3> d_q_f;
    bit<15> reserved;
    bit<6> hw_id;
    bit<32> seq_number;
    bit<32> timestamp;
    bit<32> switch_id;
}

// DTel report base header
header dtel_report_base_h {
#if __TARGET_TOFINO__ == 3
    bit<5> pad0;
#else
    bit<7> pad0;
#endif
    PortId_t ingress_port;
#if __TARGET_TOFINO__ == 3
    bit<5> pad1;
#else
    bit<7> pad1;
#endif
    PortId_t egress_port;
#if __TARGET_TOFINO__ == 1
    bit<3> pad2;
    bit<5> queue_id;
#else
    bit<1> pad2;
    bit<7> queue_id;
#endif
}

// DTel drop report header
header dtel_drop_report_h {
    bit<8> drop_reason;
    bit<16> reserved;
}

// DTel switch local report header
header dtel_switch_local_report_h {
    bit<5> pad3;
    bit<19> queue_occupancy;
    bit<32> timestamp;
}

// Telemetry report header -- version 1.0
// See https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v1_0.pdf
header dtel_report_v10_h {
    bit<4> version;
    bit<4> length;
    bit<3> next_proto;
    bit<6> metadata_bits;
    bit<6> reserved;
    bit<3> d_q_f;
    bit<6> hw_id;
    bit<32> switch_id;
    bit<32> seq_number;
    bit<32> timestamp;
}

// Telemetry report header -- version 2.0
// See https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v2_0.pdf
header dtel_report_v20_h {
    bit<4> version;
    // Telemetry Report v2.0 hw_id is 6 bits, however due to p4 constraints,
    // shrinking it to 4 bits
    bit<4> hw_id;
    // Telemetry Report v2.0 seq_number is 22 bits, however due to p4
    // constraints, expanding it to 24 bits, always leaving the top 2 bits as 0
    bit<24> seq_number;
    bit<32> switch_id;
    // Due to p4 constraints, need to treat the following as one field:
    // bit<4> rep_type;
    // bit<4> in_type;
    // bit<16> report_length;
    bit<16> report_length;
    bit<8> md_length;
    bit<3> d_q_f;
    bit<5> reserved;
    bit<16> rep_md_bits;
    bit<16> domain_specific_id;
    bit<16> ds_md_bits;
    bit<16> ds_md_status;
}

// Optional metadata present in the telemetry report.
header dtel_metadata_1_h {
#if __TARGET_TOFINO__ == 3
    bit<5> pad0;
#else
    bit<7> pad0;
#endif
    PortId_t ingress_port;
#if __TARGET_TOFINO__ == 3
    bit<5> pad1;
#else
    bit<7> pad1;
#endif
    PortId_t egress_port;
}

header dtel_metadata_2_h {
    bit<32> hop_latency;
}

header dtel_metadata_3_h {
#if __TARGET_TOFINO__ == 1
    bit<3> pad2;
    bit<5> queue_id;
#else
    bit<1> pad2;
    bit<7> queue_id;
#endif
    bit<5> pad3;
    bit<19> queue_occupancy;
}

header dtel_metadata_4_h {
    bit<16> pad;
    bit<48> ingress_timestamp;
}

header dtel_metadata_5_h {
    bit<16> pad;
    bit<48> egress_timestamp;
}

header dtel_report_metadata_15_h {
#if __TARGET_TOFINO__ == 1
    bit<3> pad;
    bit<5> queue_id;
#else
    bit<1> pad;
    bit<7> queue_id;
#endif
    bit<8> drop_reason;
    bit<16> reserved;
}

// Barefoot Specific Headers.
header fabric_h {
    bit<8> reserved;
    bit<3> color;
    bit<5> qos;
    bit<8> reserved2;
}

// CPU header
header cpu_h {
    bit<1> tx_bypass;
    bit<1> capture_ts;
    bit<1> reserved;
    bit<5> egress_queue;
    bit<16> ingress_port;
    bit<16> port_lag_index;
    bit<16> ingress_bd;
    bit<16> reason_code; // Also used as a 16-bit bypass flag.
    bit<16> ether_type;
}

// SFC header
// TODO: add header here
header sfc_pause_h {
    bit<8> version;
    bit<8> dscp;
    bit<16> duration_us;
    // TODO: padding to 64-byte packet
    // Ethernet + IP + UDP + required fields = 14 + 20 + 8 + 4 = 46
}

header padding_112b_h {
    bit<112> pad_0;
}

header padding_96b_h {
    bit<96> pad;
}

header pfc_h {
    bit<16> opcode;
    bit<8> reserved_zero;
    bit<8> class_enable_vec;
    bit<16> tstamp0;
    bit<16> tstamp1;
    bit<16> tstamp2;
    bit<16> tstamp3;
    bit<16> tstamp4;
    bit<16> tstamp5;
    bit<16> tstamp6;
    bit<16> tstamp7;
}

header timestamp_h {
    bit<48> timestamp;
}

header pad_h {
  bit<(PAD_SIZE*8)> data;
}

#endif /* _P4_HEADERS_ */
