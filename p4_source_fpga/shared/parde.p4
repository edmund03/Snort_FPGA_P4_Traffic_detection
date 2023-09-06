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


#include "headers.p4"
#include "types.p4"

//=============================================================================
// Ingress parser
//=============================================================================
parser SwitchIngressParser(
        packet_in pkt,
        out switch_header_t hdr,
        out switch_local_metadata_t local_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    Checksum() ipv4_checksum;
    Checksum() inner_ipv4_checksum;
    Checksum() inner2_ipv4_checksum;
    value_set<bit<16>>(1) udp_port_vxlan;
    value_set<switch_cpu_port_value_set_t>(1) cpu_port;
#ifdef SFC_ENABLE
    value_set<switch_cpu_port_value_set_t>(4) recirc_port_cpu_hdr;
#endif
    value_set<switch_nvgre_value_set_t>(1) nvgre_st_key;
#ifdef NAT_ENABLE
    Checksum() tcp_checksum;
    Checksum() udp_checksum;
#endif

    state start {
        pkt.extract(ig_intr_md);
        local_md.ingress_port = ig_intr_md.ingress_port;
#if defined(PTP_ENABLE) || defined(INT_V2)
        local_md.timestamp = ig_intr_md.ingress_mac_tstamp;
#else
        local_md.timestamp = ig_intr_md.ingress_mac_tstamp[31:0];
#endif
        // Check for resubmit flag if packet is resubmitted.
        // transition select(ig_intr_md.resubmit_flag) {
        //    1 : parse_resubmit;
        //    0 : parse_port_metadata;
        // }
        transition parse_port_metadata;
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition accept;
    }

    state parse_port_metadata {
        // Parse port metadata produced by ibuf
        switch_port_metadata_t port_md = port_metadata_unpack<switch_port_metadata_t>(pkt);
        local_md.ingress_port_lag_index = port_md.port_lag_index;
        local_md.ingress_port_lag_label = port_md.port_lag_label;
#ifdef IN_PORTS_IN_ACL_KEY_ENABLE
        local_md.in_ports_group_label = port_md.in_ports_group_label;
#endif
#ifdef ASYMMETRIC_FOLDED_PIPELINE
        local_md.ingress_port = port_md.ext_ingress_port;
#endif
        transition parse_packet;
    }

    state parse_packet {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type, local_md.ingress_port) {
            cpu_port  : parse_cpu;
#ifdef SFC_ENABLE
            recirc_port_cpu_hdr  : parse_recirc_cpu;
#endif
            (ETHERTYPE_IPV4, _) : parse_ipv4;
            (ETHERTYPE_ARP, _)  : parse_arp;
            (ETHERTYPE_IPV6, _) : parse_ipv6;
            (ETHERTYPE_VLAN, _) : parse_vlan;
            (ETHERTYPE_QINQ, _) : parse_vlan;
#ifdef MPLS_ENABLE
            (ETHERTYPE_MPLS, _) : parse_mpls;
#endif /* MPLS_ENABLE */
#ifdef SFC_ENABLE
            (ETHERTYPE_PFC, _) : parse_pfc;
#endif
            default : accept;
        }
    }

#ifdef SUBMIT_TO_INGRESS_ENABLE
    state parse_cpu {
        pkt.extract(hdr.fabric);
        pkt.extract(hdr.cpu);
        local_md.bypass = hdr.cpu.reason_code;
#if defined(PTP_ENABLE)
        local_md.flags.capture_ts = (bool) hdr.cpu.capture_ts;
#endif
        transition select(hdr.cpu.reason_code) {
            SWITCH_INGRESS_BYPASS_ALL : parse_cpu_etype;
            default : parse_cpu_submit_to_ingress;
        }
    }

    state parse_cpu_submit_to_ingress {
        local_md.vrf = SWITCH_DEFAULT_VRF;
        local_md.ipv4.unicast_enable = true;
        local_md.ipv6.unicast_enable = true;
        local_md.flags.rmac_hit = true;
        transition parse_cpu_etype;
    }

    state parse_cpu_etype {
        transition select(hdr.cpu.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_QINQ : parse_vlan;
#ifdef MPLS_ENABLE
            ETHERTYPE_MPLS : parse_mpls;
#endif /* MPLS_ENABLE */
            default : accept;
        }
    }

#else
    state parse_cpu {
        pkt.extract(hdr.fabric);
        pkt.extract(hdr.cpu);
        local_md.bypass = hdr.cpu.reason_code;
#if defined(PTP_ENABLE)
        local_md.flags.capture_ts = (bool) hdr.cpu.capture_ts;
#endif
        transition select(hdr.cpu.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_QINQ : parse_vlan;
#ifdef MPLS_ENABLE
            ETHERTYPE_MPLS : parse_mpls;
#endif /* MPLS_ENABLE */
            default : accept;
        }
    }
#endif /* SUBMIT_TO_INGRESS_ENABLE */

#ifdef SFC_ENABLE
    state parse_recirc_cpu{
        pkt.extract(hdr.fabric);
        pkt.extract(hdr.cpu);
        local_md.ingress_port_lag_index = hdr.cpu.port_lag_index[9:0];
        local_md.ingress_port = hdr.cpu.ingress_port[8:0];
        hdr.ethernet.ether_type = hdr.cpu.ether_type;
#if defined(PTP_ENABLE)
        local_md.flags.capture_ts = (bool) hdr.cpu.capture_ts;
#endif
        transition select(hdr.cpu.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_QINQ : parse_vlan;
#ifdef MPLS_ENABLE
            ETHERTYPE_MPLS : parse_mpls;
#endif /* MPLS_ENABLE */
            default : accept;
        }
    }
#endif

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV4;
        local_md.hash_fields.ip_src_addr[95:64] = hdr.ipv4.src_addr;
        local_md.hash_fields.ip_dst_addr[95:64] = hdr.ipv4.dst_addr;
        local_md.hash_fields.ip_proto = hdr.ipv4.protocol;
#endif /* INNER_HASH_ENABLE */
        ipv4_checksum.add(hdr.ipv4);
#ifdef NAT_ENABLE
        tcp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        udp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
#endif
        transition select(hdr.ipv4.ihl) {
            5 : parse_ipv4_no_options;
            6 : parse_ipv4_options;
            default : accept;
        }
    }

    state parse_ipv4_options {
        // Only a single 32-bit option (e.g. router alert) is supported.
        pkt.extract(hdr.ipv4_option);
        ipv4_checksum.add(hdr.ipv4_option);
        transition parse_ipv4_no_options;
    }

#ifdef SFC_ENABLE
    state parse_pfc {
        pkt.extract(hdr.pfc);
        local_md.bypass = 16w0xfffb; // Don't skip ACL
        transition accept;
    }
#endif

    state parse_ipv4_no_options {
        local_md.flags.ipv4_checksum_err = ipv4_checksum.verify();
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_IGMP : parse_igmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
            IP_PROTOCOLS_GRE : parse_ip_gre;
#endif /* GRE_ENABLE || NVGRE_ENABLE */
#ifdef IPINIP_ENABLE
            IP_PROTOCOLS_IPV4 : parse_ipinip;
            IP_PROTOCOLS_IPV6 : parse_ipv6inip;
#endif
            // Do NOT parse the next header if IP packet is fragmented.
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV6 : parse_ipv6;
#ifdef MPLS_ENABLE
            ETHERTYPE_MPLS : parse_mpls;
#endif /* MPLS_ENABLE */
            default : accept;
        }
    }

    state parse_ipv6 {
#ifdef IPV6_ENABLE
        pkt.extract(hdr.ipv6);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV6;
        local_md.hash_fields.ip_src_addr = hdr.ipv6.src_addr;
        local_md.hash_fields.ip_dst_addr = hdr.ipv6.dst_addr;
        local_md.hash_fields.ip_proto = hdr.ipv6.next_hdr;
        local_md.hash_fields.ipv6_flow_label = hdr.ipv6.flow_label;
#endif /* INNER_HASH_ENABLE */
#ifdef NAT_ENABLE
        tcp_checksum.subtract({hdr.ipv6.src_addr,hdr.ipv6.dst_addr});
        udp_checksum.subtract({hdr.ipv6.src_addr,hdr.ipv6.dst_addr});
#endif
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_ICMPV6 : parse_icmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
            IP_PROTOCOLS_GRE : parse_ip_gre;
#endif /* GRE_ENABLE || NVGRE_ENABLE */
#ifdef IPINIP_ENABLE
            IP_PROTOCOLS_IPV4 : parse_ipinip;
            IP_PROTOCOLS_IPV6 : parse_ipv6inip;
#endif
#ifdef SRV6_ENABLE
            IP_PROTOCOLS_ROUTING : parse_srh_base;
#endif /* SRV6_ENABLE */
            default : accept;
        }
#else
        transition accept;
#endif
    }

#ifdef MPLS_ENABLE
    state parse_mpls {
        pkt.extract(hdr.mpls.next);
        transition select(hdr.mpls.last.bos) {
            0 : parse_mpls;
            1 : parse_mpls_bos;
        }
    }

    state parse_mpls_bos {
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS;
        transition select(pkt.lookahead<bit<4>>()) {
            0x4 : parse_inner_ipv4;
            0x6 : parse_inner_ipv6;
            default : accept;
//            default : parse_inner_ethernet; // Inner L2 is not supported
        }
    }
#endif /* MPLS_ENABLE */

#ifdef SRV6_ENABLE
    state parse_srh_base {
        pkt.extract(hdr.srh_base);
        local_md.tunnel.srh_seg_left = hdr.srh_base.seg_left;
        local_md.tunnel.srh_next_hdr = hdr.srh_base.next_hdr;
        transition select(hdr.srh_base.last_entry, hdr.srh_base.seg_left) {
            (0, 1) : parse_srh_active_and_done_0; // active and the last segment in the segment list
            (0, _) : parse_srh_done_0;            // last segment
            (_, 1) : parse_srh_active_and_continue_0; // active segment
            default : parse_srh_continue_0;           // continue parsing
        }
    }

    state parse_srh_active_and_done_0 {
        pkt.extract(hdr.srh_seg_list[0]);
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[0].sid;
        transition parse_srh_next_hdr;
    }

    state parse_srh_done_0 {
        pkt.extract(hdr.srh_seg_list[0]);
        // local_md.tunnel.srh_next_sid is not populated since ip_da is assumed to be carrying the last segment
        transition parse_srh_next_hdr;
    }

    state parse_srh_active_and_continue_0 {
        pkt.extract(hdr.srh_seg_list[0]);
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[0].sid;
        transition parse_srh_segment_1;
    }

    state parse_srh_continue_0 {
        pkt.extract(hdr.srh_seg_list[0]);
//        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[0].sid;
        transition parse_srh_segment_1;
    }

    state parse_srh_segment_1 {
        transition select(hdr.srh_base.last_entry, hdr.srh_base.seg_left) {
            (1, 2) : parse_srh_active_and_done_1; // active and the last segment in the segment list
            (1, _) : parse_srh_done_1;            // last segment
            (0, _) : parse_srh_done_1;            // last segment
            default : accept;
        }
    }

    state parse_srh_active_and_done_1 {
        pkt.extract(hdr.srh_seg_list[1]);
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[1].sid;
        transition parse_srh_next_hdr;
    }

    state parse_srh_done_1 {
        pkt.extract(hdr.srh_seg_list[1]);
        transition parse_srh_next_hdr;
    }

    #define PARSE_SRH_SEGMENT(curr, next) \
    state parse_srh_segment_##curr { \
        transition select(hdr.srh_base.last_entry, hdr.srh_base.seg_left) { \
            (##curr, ##next) : parse_srh_active_and_done_##curr; \
            (##curr, _) : parse_srh_done_##curr; \
            (_, 1) : parse_srh_active_and_continue_##curr; \
            default : parse_srh_continue_##curr; \
        } \
    } \
    state parse_srh_active_and_done_##curr { \
        pkt.extract(hdr.srh_seg_list[##curr]); \
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[##curr].sid; \
        transition parse_srh_next_hdr; \
    } \
    state parse_srh_done_##curr { \
        pkt.extract(hdr.srh_seg_list[##curr]);\
        transition parse_srh_next_hdr; \
    } \
    state parse_srh_active_and_continue_##curr { \
        pkt.extract(hdr.srh_seg_list[##curr]); \
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[##curr].sid; \
        transition parse_srh_segment_##next; \
    } \
    state parse_srh_continue_##curr { \
        pkt.extract(hdr.srh_seg_list[##curr]); \
        local_md.tunnel.srh_next_sid = hdr.srh_seg_list[##curr].sid; \
        transition parse_srh_segment_##next; \
    } \
    /*
    PARSE_SRH_SEGMENT(1,2)
    PARSE_SRH_SEGMENT(2,3)
    */
    state parse_srh_next_hdr {
        // TODO : Parse TLV
        // TLV is present if (hdr.srh_base.last_entry+1)*2 < hdr.srh_base.hdr_ext_len
        transition select(hdr.srh_base.next_hdr) {
            IP_PROTOCOLS_IPV6 : parse_inner_ipv6;
            IP_PROTOCOLS_IPV4 : parse_inner_ipv4;
//            IP_PROTOCOLS_NONXT : parse_inner_ethernet;
            default: accept;
        }
    }
#endif /* SRV6_ENABLE */


#ifdef NVGRE_ENABLE
    // With outer IP as V4/V6
    // nvgre key is 32 bits i.e. combination of both vsid[24 bit], flow_id [8 bit]
    // nvgre-st format  - ipv4/ipv6 -> gre -> nvgre[key==config-key] -> ipv4/ipv6
    // nvgre format     - ipv4/ipv6 -> gre -> nvgre[key!=config-key] -> ipv4/ipv6
    state parse_ip_nvgre {
        pkt.extract(hdr.nvgre);
        local_md.tunnel.vni = hdr.nvgre.vsid_flowid[31:8];
        local_md.tunnel.nvgre_flow_id = hdr.nvgre.vsid_flowid[7:0];

        // nvgre-st will have config key value or 0x6400
        transition select(hdr.nvgre.vsid_flowid) {
            nvgre_st_key : parse_nvgre_st;     // nvgre-st
            default : parse_nvgre;             // nvgre
        }
    }

    // nvgre format - ipv4/ipv6 -> gre -> nvgre[key!=config-key] -> ipv4/ipv6
    state parse_nvgre {
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
        transition parse_inner_ethernet;
    }

    // nvgre-st format - ipv4/ipv6 -> gre -> nvgre[key=config-key] -> ipv4/ipv6
    state parse_nvgre_st {
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE_ST;
        transition parse_inner_ethernet;
    }
#endif

#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
    state parse_ip_gre {
        pkt.extract(hdr.gre);
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_GRE;
        transition select(hdr.gre.flags_version, hdr.gre.proto) {
#ifdef NVGRE_ENABLE
            (0x2000, GRE_PROTOCOLS_NVGRE) : parse_ip_nvgre;
#endif
            (_, GRE_PROTOCOLS_IP) : parse_inner_ipv4;
            (_, GRE_PROTOCOLS_IPV6) : parse_inner_ipv6;
            default : accept;
        }
    }
#endif /* GRE_ENABLE || NVGRE_ENABLE */

    state parse_udp {
        pkt.extract(hdr.udp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.udp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.udp.dst_port;
#endif /* INNER_HASH_ENABLE */
#ifdef NAT_ENABLE
        udp_checksum.subtract_all_and_deposit(local_md.tcp_udp_checksum);
        udp_checksum.subtract({hdr.udp.checksum});
        udp_checksum.subtract({hdr.udp.src_port, hdr.udp.dst_port});
#endif
        
        transition select(hdr.udp.dst_port) {
            UDP_PORT_GTP_U : parse_gtp_u;
#ifdef VXLAN_ENABLE
            udp_port_vxlan : parse_vxlan;
#endif
#ifdef BFD_OFFLOAD_ENABLE
            UDP_PORT_BFD_1HOP : parse_bfd;
            UDP_PORT_BFD_MHOP : parse_bfd;
            UDP_PORT_BFD_ECHO : parse_bfd;
#endif /* BFD_OFFLOAD_ENABLE */
            UDP_PORT_ROCEV2 : parse_rocev2;
                default : parse_payload16;
            }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.tcp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.tcp.dst_port;
#endif /* INNER_HASH_ENABLE */
#ifdef NAT_ENABLE
        tcp_checksum.subtract_all_and_deposit(local_md.tcp_udp_checksum);
        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port});
#endif
         transition select(hdr.ipv4.total_len,hdr.ipv4.ihl){
            (40,5)  :   accept;
            (41,5)  :   parse_payload1;
            (42,5)  :   parse_payload2;
            (43,5)  :   parse_payload3;
            (44,5)  :   parse_payload4;
            (45,5)  :   parse_payload5;
            (46,5)  :   parse_payload6;
            (47,5)  :   parse_payload7;
            (48,5)  :   parse_payload8;
            (49,5)  :   parse_payload9;
            (50,5)  :   parse_payload10;
            (51,5)  :   parse_payload11;
            (52,5)  :   parse_payload12;
            (53,5)  :   parse_payload13;
            (54,5)  :   parse_payload14;
            (55,5)  :   parse_payload15;
            (56,5)  :   parse_payload16;
            (44,6)  :   accept;
            (45,6)  :   parse_payload1;
            (46,6)  :   parse_payload2;
            (47,6)  :   parse_payload3;
            (48,6)  :   parse_payload4;
            (49,6)  :   parse_payload5;
            (50,6)  :   parse_payload6;
            (51,6)  :   parse_payload7;
            (52,6)  :   parse_payload8;
            (53,6)  :   parse_payload9;
            (54,6)  :   parse_payload10;
            (55,6)  :   parse_payload11;
            (56,6)  :   parse_payload12;
            (57,6)  :   parse_payload13;
            (58,6)  :   parse_payload14;
            (59,6)  :   parse_payload15;
            (60,6)  :   parse_payload16;
            default  :   parse_payload16;
        }
        //transition accept;
    }

    state parse_payload1 {
        pkt.extract(hdr.payload1);
        local_md.payload32_0[31:24] = hdr.payload1.payload1_0;
        transition accept;
    }

    state parse_payload2 {
        pkt.extract(hdr.payload2);
        local_md.payload32_0[31:16] = hdr.payload2.payload2_0;
        transition accept;
    }

    state parse_payload3 {
        pkt.extract(hdr.payload3);
        local_md.payload32_0[31:8] = hdr.payload3.payload3_0;
        transition accept;
    }

    state parse_payload4 {
        pkt.extract(hdr.payload4);
        local_md.payload32_0 = hdr.payload4.payload4_0;
        transition accept;
    }

    state parse_payload5 {
        pkt.extract(hdr.payload5);
        local_md.payload32_0 = hdr.payload5.payload5_0;
        local_md.payload32_1[31:24] = hdr.payload5.payload5_1;
        transition accept;
    }

    state parse_payload6 {
        pkt.extract(hdr.payload6);
        local_md.payload32_0 = hdr.payload6.payload6_0;
        local_md.payload32_1[31:16] = hdr.payload6.payload6_1;
        transition accept;
    }

    state parse_payload7 {
        pkt.extract(hdr.payload7);
        local_md.payload32_0 = hdr.payload7.payload7_0;
        local_md.payload32_1[31:8] = hdr.payload7.payload7_1;
        transition accept;
    }

    state parse_payload8 {
        pkt.extract(hdr.payload8);
        local_md.payload32_0 = hdr.payload8.payload8_0;
        local_md.payload32_1 = hdr.payload8.payload8_1;
        transition accept;
    }

    state parse_payload9 {
        pkt.extract(hdr.payload9);
        local_md.payload32_0 = hdr.payload9.payload9_0;
        local_md.payload32_1 = hdr.payload9.payload9_1;
        local_md.payload32_2[31:24] = hdr.payload9.payload9_2;
        transition accept;
    }

    state parse_payload10 {
        pkt.extract(hdr.payload10);
        local_md.payload32_0 = hdr.payload10.payload10_0;
        local_md.payload32_1 = hdr.payload10.payload10_1;
        local_md.payload32_2[31:16] = hdr.payload10.payload10_2;
        transition accept;
    }

    state parse_payload11 {
        pkt.extract(hdr.payload11);
        local_md.payload32_0 = hdr.payload11.payload11_0;
        local_md.payload32_1 = hdr.payload11.payload11_1;
        local_md.payload32_2[31:8] = hdr.payload11.payload11_2;
        transition accept;
    }

    state parse_payload12 {
        pkt.extract(hdr.payload12);
        local_md.payload32_0 = hdr.payload12.payload12_0;
        local_md.payload32_1 = hdr.payload12.payload12_1;
        local_md.payload32_2 = hdr.payload12.payload12_2;
        transition accept;
    }

    state parse_payload13 {
        pkt.extract(hdr.payload13);
        local_md.payload32_0 = hdr.payload13.payload13_0;
        local_md.payload32_1 = hdr.payload13.payload13_1;
        local_md.payload32_2 = hdr.payload13.payload13_2;
        local_md.payload32_3[31:24] = hdr.payload13.payload13_3;
        transition accept;
    }

    state parse_payload14 {
        pkt.extract(hdr.payload14);
        local_md.payload32_0 = hdr.payload14.payload14_0;
        local_md.payload32_1 = hdr.payload14.payload14_1;
        local_md.payload32_2 = hdr.payload14.payload14_2;
        local_md.payload32_3[31:16] = hdr.payload14.payload14_3;
        transition accept;
    }

    state parse_payload15 {
        pkt.extract(hdr.payload15);
        local_md.payload32_0 = hdr.payload15.payload15_0;
        local_md.payload32_1 = hdr.payload15.payload15_1;
        local_md.payload32_2 = hdr.payload15.payload15_2;
        local_md.payload32_3[31:8] = hdr.payload15.payload15_3;
        transition accept;
    }

    state parse_payload16 {
        pkt.extract(hdr.payload16);
        local_md.payload32_0 = hdr.payload16.payload16_0;
        local_md.payload32_1 = hdr.payload16.payload16_1;
        local_md.payload32_2 = hdr.payload16.payload16_2;
        local_md.payload32_3 = hdr.payload16.payload16_3;
        transition accept;
    }


    state parse_icmp {
        pkt.extract(hdr.icmp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port[7:0] = hdr.icmp.type;
        local_md.hash_fields.l4_src_port[15:8] = hdr.icmp.code;
#endif /* INNER_HASH_ENABLE */
        transition accept;
    }

    state parse_igmp {
        pkt.extract(hdr.igmp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port[7:0] = hdr.igmp.type;
        local_md.hash_fields.l4_src_port[15:8] = hdr.igmp.code;
#endif /* INNER_HASH_ENABLE */
        transition accept;
    }

    state parse_gtp_u {
        // TODO : is there a need to parse inner headers
        pkt.extract(hdr.gtp);
        // transition parse_payload32;
        transition accept;
    }

    state parse_rocev2 {
#ifdef ROCEV2_ACL_ENABLE
        pkt.extract(hdr.rocev2_bth);
#endif
        // transition parse_payload32;
        transition accept;
    }

    state parse_vxlan {
        pkt.extract(hdr.vxlan);
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
        local_md.tunnel.vni = hdr.vxlan.vni;
        transition parse_inner_ethernet;
    }

#ifdef BFD_OFFLOAD_ENABLE
    state parse_bfd {
	pkt.extract(hdr.bfd);
	// transition parse_payload32;
    transition accept;
    }
#endif

    state parse_ipinip {
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_IPINIP;
        transition parse_inner_ipv4;
    }

    state parse_ipv6inip {
        local_md.tunnel.type = SWITCH_INGRESS_TUNNEL_TYPE_IPINIP;
        transition parse_inner_ipv6;
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            default : accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV4;
        local_md.hash_fields.ip_src_addr[95:64] = hdr.inner_ipv4.src_addr;
        local_md.hash_fields.ip_dst_addr[95:64] = hdr.inner_ipv4.dst_addr;
        local_md.hash_fields.ip_proto = hdr.inner_ipv4.protocol;
#endif /* INNER_HASH_ENABLE */
        inner_ipv4_checksum.add(hdr.inner_ipv4);
        local_md.flags.inner_ipv4_checksum_err = inner_ipv4_checksum.verify();
        transition select(hdr.inner_ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_inner_icmp;
            IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
#ifdef INNER_HASH_ENABLE
            IP_PROTOCOLS_IPV4 : parse_inner2_ipv4;
            IP_PROTOCOLS_IPV6 : parse_inner2_ipv6;
#endif /* INNER_HASH_ENABLE */
            default : accept;
        }
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV6;
        local_md.hash_fields.ip_src_addr = hdr.inner_ipv6.src_addr;
        local_md.hash_fields.ip_dst_addr = hdr.inner_ipv6.dst_addr;
        local_md.hash_fields.ip_proto = hdr.inner_ipv6.next_hdr;
        local_md.hash_fields.ipv6_flow_label = hdr.inner_ipv6.flow_label;
#endif /* INNER_HASH_ENABLE */
        transition select(hdr.inner_ipv6.next_hdr) {
            IP_PROTOCOLS_ICMPV6 : parse_inner_icmp;
            IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default : accept;
        }
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.inner_udp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.inner_udp.dst_port;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.inner_tcp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.inner_tcp.dst_port;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port[7:0] = hdr.inner_icmp.type;
        local_md.hash_fields.l4_src_port[15:8] = hdr.inner_icmp.code;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

#ifdef INNER_HASH_ENABLE
    state parse_inner2_ipv4 {
        pkt.extract(hdr.inner2_ipv4);
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV4;
        local_md.hash_fields.ip_src_addr[95:64] = hdr.inner2_ipv4.src_addr;
        local_md.hash_fields.ip_dst_addr[95:64] = hdr.inner2_ipv4.dst_addr;
        local_md.hash_fields.ip_proto = hdr.inner2_ipv4.protocol;
        inner2_ipv4_checksum.add(hdr.inner2_ipv4);
        local_md.flags.inner2_ipv4_checksum_err = inner2_ipv4_checksum.verify();
        transition select(hdr.inner2_ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_inner2_icmp;
            IP_PROTOCOLS_TCP : parse_inner2_tcp;
            IP_PROTOCOLS_UDP : parse_inner2_udp;
            default : accept;
        }
    }

    state parse_inner2_ipv6 {
        pkt.extract(hdr.inner2_ipv6);
        local_md.hash_fields.ip_type = SWITCH_IP_TYPE_IPV6;
        local_md.hash_fields.ip_src_addr = hdr.inner2_ipv6.src_addr;
        local_md.hash_fields.ip_dst_addr = hdr.inner2_ipv6.dst_addr;
        local_md.hash_fields.ip_proto = hdr.inner2_ipv6.next_hdr;
        local_md.hash_fields.ipv6_flow_label = hdr.inner2_ipv6.flow_label;
        transition select(hdr.inner2_ipv6.next_hdr) {
            IP_PROTOCOLS_ICMPV6 : parse_inner2_icmp;
            IP_PROTOCOLS_TCP : parse_inner2_tcp;
            IP_PROTOCOLS_UDP : parse_inner2_udp;
            default : accept;
        }
    }

    state parse_inner2_udp {
        pkt.extract(hdr.inner2_udp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.inner2_udp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.inner2_udp.dst_port;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

    state parse_inner2_tcp {
        pkt.extract(hdr.inner2_tcp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port = hdr.inner2_tcp.src_port;
        local_md.hash_fields.l4_dst_port = hdr.inner2_tcp.dst_port;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

    state parse_inner2_icmp {
        pkt.extract(hdr.inner2_icmp);
#ifdef INNER_HASH_ENABLE
        local_md.hash_fields.l4_src_port[7:0] = hdr.inner2_icmp.type;
        local_md.hash_fields.l4_src_port[15:8] = hdr.inner2_icmp.code;
#endif /* INNER_HASH_ENABLE */
        // transition parse_payload32;
        transition accept;
    }

#endif /* INNER_HASH_ENABLE */

}

//----------------------------------------------------------------------------
// Egress parser
//----------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out switch_header_t hdr,
        out switch_local_metadata_t local_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    value_set<bit<16>>(1) udp_port_vxlan;
    value_set<switch_cpu_port_value_set_t>(1) cpu_port;
    value_set<switch_nvgre_value_set_t>(1) nvgre_st_key;

    @critical
    state start {
        pkt.extract(eg_intr_md);
        local_md.pkt_length = eg_intr_md.pkt_length;
        local_md.egress_port = eg_intr_md.egress_port;
        local_md.qos.qdepth = eg_intr_md.deq_qdepth;

#ifdef MIRROR_ENABLE
        switch_port_mirror_appid_metadata_h mirror_md = pkt.lookahead<switch_port_mirror_appid_metadata_h>();
        //switch_port_mirror_metadata_h mirror_md = pkt.lookahead<switch_port_mirror_metadata_h>();
        transition select(eg_intr_md.deflection_flag, mirror_md.src, mirror_md.type) {
            (1, _, _) : parse_deflected_pkt;
            (_, SWITCH_PKT_SRC_BRIDGED, _) : parse_bridged_pkt;
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
            (_, SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT, SWITCH_MIRROR_TYPE_PORT_WITH_B_MD) : parse_port_mirrored_with_bridged_metadata;
#endif
            (_, _, SWITCH_MIRROR_TYPE_PORT) : parse_port_mirrored_metadata;
            (_, SWITCH_PKT_SRC_CLONED_EGRESS, SWITCH_MIRROR_TYPE_CPU) : parse_cpu_mirrored_metadata;
            (_, SWITCH_PKT_SRC_CLONED_INGRESS, SWITCH_MIRROR_TYPE_DTEL_DROP) : parse_dtel_drop_metadata_from_ingress;
#ifdef SFC_ENABLE
            (_, SWITCH_PKT_SRC_CLONED_INGRESS, SWITCH_MIRROR_TYPE_SFC) : parse_sfc_pause_metadata_from_ingress;
#endif
            (_, _, SWITCH_MIRROR_TYPE_DTEL_DROP) : parse_dtel_drop_metadata_from_egress;
            (_, _, SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL) : parse_dtel_switch_local_metadata;
            (_, _, SWITCH_MIRROR_TYPE_SIMPLE) : parse_simple_mirrored_metadata;
        }
#else
        transition parse_bridged_pkt;
#endif
    }

    state parse_bridged_pkt {
        pkt.extract(hdr.bridged_md);
        local_md.pkt_src = SWITCH_PKT_SRC_BRIDGED;
        local_md.ingress_port = hdr.bridged_md.base.ingress_port;
        local_md.egress_port_lag_index = hdr.bridged_md.base.ingress_port_lag_index;
        local_md.bd = hdr.bridged_md.base.ingress_bd;
        local_md.nexthop = hdr.bridged_md.base.nexthop;
        local_md.cpu_reason = hdr.bridged_md.base.cpu_reason;
        local_md.flags.routed = hdr.bridged_md.base.routed;
        local_md.flags.bypass_egress = hdr.bridged_md.base.bypass_egress;

#if defined(MLAG_ENABLE)
        local_md.flags.peer_link = hdr.bridged_md.base.peer_link;
#endif
#if defined(PTP_ENABLE)
        local_md.flags.capture_ts = hdr.bridged_md.base.capture_ts;
#endif
        local_md.pkt_type = hdr.bridged_md.base.pkt_type;
        local_md.ingress_timestamp = hdr.bridged_md.base.timestamp;
        local_md.qos.tc = hdr.bridged_md.base.tc;
        local_md.qos.qid = hdr.bridged_md.base.qid;
        local_md.qos.color = hdr.bridged_md.base.color;
        local_md.vrf = hdr.bridged_md.base.vrf;
#ifdef BFD_OFFLOAD_ENABLE
	local_md.bfd.rx_recirc = hdr.bridged_md.base.bfd_rx_recirc;
#endif /* BFD_OFFLOAD_ENABLE */

#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE)
#if defined(EGRESS_ACL_PORT_RANGE_ENABLE) && !defined(L4_PORT_EGRESS_LOU_ENABLE)
        local_md.l4_src_port_label = hdr.bridged_md.acl.l4_src_port_label;
        local_md.l4_dst_port_label = hdr.bridged_md.acl.l4_dst_port_label;
#endif // EGRESS_ACL_PORT_RANGE_ENABLE && !L4_PORT_EGRESS_LOU_ENABLE
        local_md.lkp.l4_src_port = hdr.bridged_md.acl.l4_src_port;
        local_md.lkp.l4_dst_port = hdr.bridged_md.acl.l4_dst_port;
        local_md.lkp.tcp_flags = hdr.bridged_md.acl.tcp_flags;
#ifdef ACL_USER_META_ENABLE
        local_md.user_metadata = hdr.bridged_md.acl.user_metadata;
#endif // ACL_USER_META_ENABLE
#elif defined (DTEL_FLOW_REPORT_ENABLE)
        local_md.lkp.tcp_flags = hdr.bridged_md.acl.tcp_flags;
#endif // EGRESS_IP_ACL_ENABLE || EGRESS_MIRROR_ACL_ENABLE
#ifdef TUNNEL_ENABLE
        local_md.tunnel_nexthop = hdr.bridged_md.tunnel.tunnel_nexthop;
#if defined(VXLAN_ENABLE) && !defined(DTEL_ENABLE)
       local_md.tunnel.hash = hdr.bridged_md.tunnel.hash;
#endif /* VXLAN_ENABLE && !DTEL_ENABLE */
#ifdef MPLS_ENABLE
        local_md.tunnel.mpls_pop_count = hdr.bridged_md.tunnel.mpls_pop_count;
#endif
#ifdef TUNNEL_TTL_MODE_ENABLE
        local_md.tunnel.ttl_mode = hdr.bridged_md.tunnel.ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.tunnel.qos_mode = hdr.bridged_md.tunnel.qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
        local_md.tunnel.terminate = hdr.bridged_md.tunnel.terminate;
#endif /* TUNNEL_ENABLE */
#ifdef DTEL_ENABLE
        local_md.dtel.report_type = hdr.bridged_md.dtel.report_type;
        local_md.dtel.hash = hdr.bridged_md.dtel.hash;
        local_md.dtel.session_id = hdr.bridged_md.dtel.session_id;
#endif
#ifdef SFC_ENABLE
        local_md.sfc.type = hdr.bridged_md.sfc.type;
        local_md.sfc.queue_register_idx = hdr.bridged_md.sfc.queue_register_idx;
#endif
#ifdef BFD_OFFLOAD_ENABLE
	local_md.bfd.rx_recirc = hdr.bridged_md.base.bfd_rx_recirc;
#endif /* BFD_OFFLOAD_ENABLE */
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
        local_md.mirror.type = hdr.bridged_md.mirror.type;
        local_md.mirror.src = hdr.bridged_md.mirror.src;
        local_md.mirror.session_id = hdr.bridged_md.mirror.session_id;
        local_md.mirror.meter_index = hdr.bridged_md.mirror.meter_index;
#endif
        transition parse_ethernet;
    }

    state parse_deflected_pkt {
#ifdef DTEL_ENABLE
        pkt.extract(hdr.bridged_md);
        local_md.pkt_src = SWITCH_PKT_SRC_DEFLECTED;
#ifdef PACKET_LENGTH_ADJUSTMENT
        local_md.mirror.type = SWITCH_MIRROR_TYPE_DTEL_DEFLECT;
#endif
        local_md.flags.bypass_egress = true;
        local_md.dtel.report_type = hdr.bridged_md.dtel.report_type;
        local_md.dtel.hash = hdr.bridged_md.dtel.hash;
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
        local_md.mirror.session_id = hdr.bridged_md.dtel.session_id;
        local_md.qos.qid = hdr.bridged_md.base.qid;
#ifdef INT_V2
        hdr.dtel_metadata_1 = {
            0,
            hdr.bridged_md.base.ingress_port,
            0,
            hdr.bridged_md.dtel.egress_port};
        hdr.dtel_metadata_4 = {
            0,
            hdr.bridged_md.base.timestamp};
        hdr.dtel_drop_report = {
            0,
            hdr.bridged_md.base.qid,
            SWITCH_DROP_REASON_TRAFFIC_MANAGER,
            0};
#else
        local_md.ingress_timestamp = hdr.bridged_md.base.timestamp;
        hdr.dtel_report = {
            0,
            hdr.bridged_md.base.ingress_port,
            0,
            hdr.bridged_md.dtel.egress_port,
            0,
            hdr.bridged_md.base.qid};
        hdr.dtel_drop_report = {
            SWITCH_DROP_REASON_TRAFFIC_MANAGER,
            0};
#endif /* INT_V2 */
        transition accept;
#else
        transition reject;
#endif /* DTEL_ENABLE */
    }

    /* Below state is for mirror packet with
       Format <mirror_hd> <bridged MD> <packet> ----> SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT
       When mirror stage is egress, io_select set to 0 i.e. mirror packet ingressing from TM to egress parser
    */
    state parse_port_mirrored_with_bridged_metadata {
        switch_port_mirror_appid_metadata_h port_md;
        //switch_port_mirror_metadata_h port_md;
        switch_bridged_metadata_h b_md;
        pkt.extract(port_md);
        pkt.extract(b_md);
        pkt.extract(hdr.ethernet);
        local_md.pkt_src = port_md.src;
        local_md.mirror.session_id = port_md.session_id;
        local_md.ingress_timestamp = port_md.timestamp;
        local_md.flags.bypass_egress = true;
#ifdef PACKET_LENGTH_ADJUSTMENT
        local_md.mirror.type = port_md.type;
#endif
#ifdef DTEL_ENABLE
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
#endif
        transition accept;
    }

    /* Below state is for mirror packet with below format
        1) Format <mirror_hd> <in_packet> ----> SWITCH_PKT_SRC_CLONED_INGRESS
           Happens when mirror stage is ingress, io_select set to 0 i.e. mirror original ingress packet
        2) Format <mirror_hd> <out_packet> ----> SWITCH_PKT_SRC_CLONED_EGRESS
           Happens when mirror stage is egress, io_select set to 1 i.e. mirror final egress packet
    */
    state parse_port_mirrored_metadata {
        switch_port_mirror_appid_metadata_h port_md;
        // switch_port_mirror_metadata_h port_md;
        pkt.extract(port_md);
        pkt.extract(hdr.ethernet);
        local_md.pkt_src = port_md.src;
        local_md.mirror.session_id = port_md.session_id;
        local_md.ingress_timestamp = port_md.timestamp;
        local_md.flags.bypass_egress = true;
#ifdef PACKET_LENGTH_ADJUSTMENT
        local_md.mirror.type = port_md.type;
#endif
#ifdef DTEL_ENABLE
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
#endif
        local_md.app_id = (bit<12>)port_md.app_id;
        transition accept;
    }

    state parse_cpu_mirrored_metadata {
        switch_cpu_mirror_metadata_h cpu_md;
        pkt.extract(cpu_md);
        pkt.extract(hdr.ethernet);
        local_md.pkt_src = cpu_md.src;
        local_md.flags.bypass_egress = true;
        local_md.bd = cpu_md.bd;
        // local_md.ingress_port = cpu_md.md.port;
        local_md.cpu_reason = cpu_md.reason_code;
#ifdef PACKET_LENGTH_ADJUSTMENT
        local_md.mirror.type = cpu_md.type;
#endif
#ifdef DTEL_ENABLE
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
#endif
        transition accept;
    }

    state parse_dtel_drop_metadata_from_egress {
#ifdef DTEL_ENABLE
        switch_dtel_drop_mirror_metadata_h dtel_md;
        pkt.extract(dtel_md);
        local_md.pkt_src = dtel_md.src;
        local_md.mirror.type = dtel_md.type;
        local_md.flags.bypass_egress = true;
        local_md.dtel.report_type = dtel_md.report_type;
        local_md.dtel.hash = dtel_md.hash;
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
        local_md.mirror.session_id = dtel_md.session_id;
#ifdef INT_V2
        hdr.dtel_metadata_1 = {
            0,
            dtel_md.ingress_port,
            0,
            dtel_md.egress_port};
        hdr.dtel_metadata_4 = {
            0,
            dtel_md.timestamp};
        hdr.dtel_drop_report = {
            0,
            dtel_md.qid,
            dtel_md.drop_reason,
            0};
#else
        local_md.ingress_timestamp = dtel_md.timestamp;
        hdr.dtel_report = {
            0,
            dtel_md.ingress_port,
            0,
            dtel_md.egress_port,
            0,
            dtel_md.qid};
        hdr.dtel_drop_report = {
            dtel_md.drop_reason,
            0};
#endif /* INT_V2 */
        transition accept;
#else
        transition reject;
#endif /* DTEL_ENABLE */
    }

    /* Separate parse state for drop metadata from ingress, in order to set
     * hdr.dtel_report.egress_port to SWITCH_PORT_INVALID */
    state parse_dtel_drop_metadata_from_ingress {
#ifdef DTEL_ENABLE
        switch_dtel_drop_mirror_metadata_h dtel_md;
        pkt.extract(dtel_md);
        local_md.pkt_src = dtel_md.src;
        local_md.mirror.type = dtel_md.type;
        local_md.flags.bypass_egress = true;
        local_md.dtel.report_type = dtel_md.report_type;
        local_md.dtel.hash = dtel_md.hash;
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
        local_md.mirror.session_id = dtel_md.session_id;
#ifdef INT_V2
        hdr.dtel_metadata_1 = {
            0,
            dtel_md.ingress_port,
            0,
            SWITCH_PORT_INVALID};
        hdr.dtel_metadata_4 = {
            0,
            dtel_md.timestamp};
        hdr.dtel_drop_report = {
            0,
            dtel_md.qid,
            dtel_md.drop_reason,
            0};
#else
        local_md.ingress_timestamp = dtel_md.timestamp;
        hdr.dtel_report = {
            0,
            dtel_md.ingress_port,
            0,
            SWITCH_PORT_INVALID,
            0,
            dtel_md.qid};
        hdr.dtel_drop_report = {
            dtel_md.drop_reason,
            0};
#endif /* INT_V2 */
        transition accept;
#else
        transition reject;
#endif /* DTEL_ENABLE */
    }

#ifdef SFC_ENABLE
    state parse_sfc_pause_metadata_from_ingress {
        switch_sfc_pause_mirror_metadata_h sfc_md;
        pkt.extract(sfc_md);

        local_md.pkt_src = sfc_md.src;
        local_md.sfc.type = SfcPacketType.Trigger;
        local_md.sfc.queue_register_idx = sfc_md.queue_register_idx;
        local_md.nexthop = sfc_md.nexthop;
        local_md.flags.routed = true;
        local_md.ingress_port_lag_index = sfc_md.port_lag_index[9:0];
        local_md.ingress_port = sfc_md.ingress_port[8:0];

        transition parse_ethernet;
    }
#endif

    state parse_dtel_switch_local_metadata {
#ifdef DTEL_ENABLE
        switch_dtel_switch_local_mirror_metadata_h dtel_md;
        pkt.extract(dtel_md);
        local_md.pkt_src = dtel_md.src;
        local_md.mirror.type = dtel_md.type;
        local_md.flags.bypass_egress = true;
        local_md.dtel.report_type = dtel_md.report_type;
        local_md.dtel.hash = dtel_md.hash;
        // Initialize local_md.dtel.session_id to prevent it from being marked @pa_no_init.
        local_md.dtel.session_id = 0;
        local_md.mirror.session_id = dtel_md.session_id;
#ifdef INT_V2
        hdr.dtel_metadata_1 = {
            0,
            dtel_md.ingress_port,
            0,
            dtel_md.egress_port};
        //TODO: Preserve latency as well as quantized latency
        //      and add to mirror metadata
        //hdr.dtel_metadata_2 = {
        //    dtel_md.latency};
        hdr.dtel_metadata_3 = {
            0,
            dtel_md.qid,
            0,
            dtel_md.qdepth};
        hdr.dtel_metadata_4 = {
            0,
            dtel_md.timestamp};
        hdr.dtel_metadata_5 = {
            0,
            dtel_md.egress_timestamp};
#else
        local_md.ingress_timestamp = dtel_md.timestamp;
        hdr.dtel_report = {
            0,
            dtel_md.ingress_port,
            0,
            dtel_md.egress_port,
            0,
            dtel_md.qid};
        hdr.dtel_switch_local_report = {
            0,
            dtel_md.qdepth,
            dtel_md.egress_timestamp};
#endif /* INT_V2 */
        transition accept;
#else
        transition reject;
#endif /* DTEL_ENABLE */
    }

    state parse_simple_mirrored_metadata {
#ifdef DTEL_ENABLE
        switch_simple_mirror_metadata_h simple_mirror_md;
        pkt.extract(simple_mirror_md);
        local_md.pkt_src = simple_mirror_md.src;
        local_md.mirror.type = simple_mirror_md.type;
        local_md.mirror.session_id = simple_mirror_md.session_id;
        local_md.flags.bypass_egress = true;
        transition parse_ethernet;
#else
        transition reject;
#endif
    }

    state parse_packet {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type, eg_intr_md.egress_port) {
            cpu_port : parse_cpu;
            (ETHERTYPE_IPV4, _) : parse_ipv4;
            (ETHERTYPE_IPV6, _) : parse_ipv6;
            (ETHERTYPE_VLAN, _) : parse_vlan;
            (ETHERTYPE_QINQ, _) : parse_vlan;
#ifdef MPLS_ENABLE
            (ETHERTYPE_MPLS, _) : parse_mpls;
#endif /* MPLS_ENABLE */
#ifdef SFC_ENABLE
            (ETHERTYPE_PFC, _)  : parse_pfc;
#endif
            default : parse_pad;
        }
    }

    state parse_cpu {
        local_md.flags.bypass_egress = true;
        transition parse_pad;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.frag_offset) {
#if defined(TUNNEL_ENABLE) \
    || (defined(DTEL_ENABLE) && __TARGET_TOFINO__ == 1) \
    || defined(SFC_ENABLE)
            (IP_PROTOCOLS_UDP, 5, 0) : parse_udp;
#ifdef IPINIP_ENABLE
            (IP_PROTOCOLS_IPV4, 5, 0) : parse_inner_ipv4;
            (IP_PROTOCOLS_IPV6, 5, 0) : parse_inner_ipv6;
#endif
#endif
#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
            (IP_PROTOCOLS_GRE, 5, 0) : parse_ip_gre;
#endif /* GRE_ENABLE || NVGRE_ENABLE */
            (_, 6, _) : parse_ipv4_options;
#if defined(SFC_ENABLE)
            (IP_PROTOCOLS_TCP, 5,   0) : parse_tcp;
#endif
            default : parse_pad;
        }
    }

    state parse_ipv4_options {
        pkt.extract(hdr.ipv4_option);
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
#if defined(TUNNEL_ENABLE) || (defined(DTEL_ENABLE) && __TARGET_TOFINO__ == 1)
            (IP_PROTOCOLS_UDP, 0) : parse_udp;
#ifdef IPINIP_ENABLE
            (IP_PROTOCOLS_IPV4, 0) : parse_inner_ipv4;
            (IP_PROTOCOLS_IPV6, 0) : parse_inner_ipv6;
#endif
#endif
#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
            (IP_PROTOCOLS_GRE, 0) : parse_ip_gre;
#endif /* GRE_ENABLE || NVGRE_ENABLE */
            default : parse_pad;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV6 : parse_ipv6;
#ifdef MPLS_ENABLE
            ETHERTYPE_MPLS : parse_mpls;
#endif /* MPLS_ENABLE */
            default : parse_pad;
        }
    }

#ifdef SFC_ENABLE
    state parse_pfc {
        pkt.extract(hdr.pfc);
        transition parse_pad;
    }
#endif

    state parse_ipv6 {
#ifdef IPV6_ENABLE
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
#ifdef IPV6_TUNNEL_ENABLE
            // IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
#ifdef IPINIP_ENABLE
            IP_PROTOCOLS_IPV4 : parse_inner_ipv4;
            IP_PROTOCOLS_IPV6 : parse_inner_ipv6;
#endif /* IPINIP_ENABLE */
#endif /* IPV6_TUNNEL_ENABLE */
#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
            IP_PROTOCOLS_GRE : parse_ip_gre;
#endif /* GRE_ENABLE || NVGRE_ENABLE */
            default : parse_pad;
        }
#else
        transition parse_pad;
#endif /* IPV6_ENABLE */
    }

#ifdef MPLS_ENABLE
    state parse_mpls {
        pkt.extract(hdr.mpls.next);
        transition select(hdr.mpls.last.bos) {
            0 : parse_mpls;
            1 : parse_mpls_bos;
        }
    }

    state parse_mpls_bos {
        transition select(pkt.lookahead<bit<4>>()) {
            0x4 : parse_inner_ipv4;
            0x6 : parse_inner_ipv6;
            default : parse_pad;
        }
    }
#endif /* MPLS_ENABLE */

#ifdef NVGRE_ENABLE
    // nvgre key is 32 bits i.e. combination of both vsid[24 bit], flow_id [8 bit]
    // nvgre-st format  - ipv4/ipv6 -> gre -> nvgre[key==config-key] -> ipv4/ipv6
    // nvgre format     - ipv4/ipv6 -> gre -> nvgre[key!=config-key] -> ipv4/ipv6
    state parse_ip_nvgre {
        pkt.extract(hdr.nvgre);
        // nvgre-st will have config key value or 0x6400
        transition select(hdr.nvgre.vsid_flowid) {
            nvgre_st_key : parse_inner_ethernet;      // nvgre-st
            default  : parse_inner_ethernet;          // nvgre
        }
    }
#endif

#if defined(GRE_ENABLE) || defined(NVGRE_ENABLE)
    state parse_ip_gre {
        pkt.extract(hdr.gre);
        transition select(hdr.gre.flags_version, hdr.gre.proto) {
#ifdef NVGRE_ENABLE
            (0x2000, GRE_PROTOCOLS_NVGRE) : parse_ip_nvgre;
#endif
            (_, GRE_PROTOCOLS_IP) : parse_inner_ipv4;
            (_, GRE_PROTOCOLS_IPV6) : parse_inner_ipv6;
            default : parse_pad;
        }
    }
#endif /* GRE_ENABLE || NVGRE_ENABLE */

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
#ifdef VXLAN_ENABLE
            udp_port_vxlan : parse_vxlan;
#endif
#ifdef SFC_ENABLE
            UDP_PORT_SFC_PAUSE : egress_parse_sfc_pause;
#endif
#ifdef BFD_OFFLOAD_ENABLE
            UDP_PORT_BFD_1HOP : parse_bfd;
            UDP_PORT_BFD_MHOP : parse_bfd;
            UDP_PORT_BFD_ECHO : parse_bfd;
#endif /* BFD_OFFLOAD_ENABLE */
            default : parse_pad;
        }
    }

    state egress_parse_sfc_pause {
#ifdef SFC_ENABLE
        pkt.extract(hdr.sfc_pause);
        local_md.sfc.pause_dscp = hdr.sfc_pause.dscp;
        local_md.sfc.pause_duration_us = hdr.sfc_pause.duration_us;
#endif
        transition parse_pad;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition parse_pad;
    }

    state parse_vxlan {
        pkt.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

#ifdef BFD_OFFLOAD_ENABLE
    state parse_bfd {
	pkt.extract(hdr.bfd);
	transition accept;
    }
#endif

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            default : parse_pad;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        transition parse_pad;
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
        transition parse_pad;
    }

    state parse_pad {
#if __TARGET_TOFINO__ == 2
#if TOFINO2_PADDING_ENABLE
      hdr.pad.setValid();
      hdr.pad = pkt.lookahead<pad_h>();
#endif /* TOFINO2_PADDING_ENABLE */
#endif
      transition accept;
    }
}


//----------------------------------------------------------------------------
// Mirror packet deparser
//-----------------------------------------------------------------------------
control IngressMirror(
    inout switch_header_t hdr,
    in switch_local_metadata_t local_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
// Ingress deparser create a copy of the original ingress packet and prepend the prepend the mirror
// header.
    Mirror() mirror;

    apply {
#ifdef MIRROR_ENABLE
        if (ig_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_PORT) {
            mirror.emit<switch_port_mirror_appid_metadata_h>(
            //mirror.emit<switch_port_mirror_metadata_h>(
                local_md.mirror.session_id,
                {local_md.mirror.src,
                 local_md.mirror.type,
                 local_md.timestamp,
#if __TARGET_TOFINO__ == 1
                 0,
#endif
                 local_md.mirror.session_id
                 ,(bit<16>)local_md.app_id});
                //});

        } else if (ig_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_DTEL_DROP) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_dtel_drop_mirror_metadata_h>(local_md.dtel.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                local_md.timestamp,
#if __TARGET_TOFINO__ == 1
                 0,
#endif
                local_md.dtel.session_id,
                local_md.lag_hash,
                local_md.dtel.report_type,
                0,
                local_md.ingress_port,
                0,
                local_md.egress_port,
                0,
                local_md.qos.qid,
                local_md.drop_reason
            });

#endif /* DTEL_ENABLE */
        } else if (ig_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_SFC) {
#ifdef SFC_ENABLE
            mirror.emit<switch_sfc_pause_mirror_metadata_h>(local_md.mirror.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                //ig_md.timestamp,
                0, // We don't use this timestamp, so we can skip
                local_md.sfc.queue_register_idx,
                local_md.nexthop,
                (bit<16>)local_md.ingress_port,
                (bit<16>)local_md.ingress_port_lag_index
            });
#endif /* SFC_ENABLE */
        }
#endif /* MIRROR_ENABLE */
    }
}

control EgressMirror(
    inout switch_header_t hdr,
    in switch_local_metadata_t local_md,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
// Egress deparser first construct the output packet and then prepend the mirror header.
    Mirror() mirror;

    apply {
#ifdef MIRROR_ENABLE
        if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_PORT) {
            mirror.emit<switch_port_mirror_metadata_h>(local_md.mirror.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                local_md.ingress_timestamp,
#if __TARGET_TOFINO__ == 1
                0,
#endif
                local_md.mirror.session_id});
        }
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
        else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_PORT_WITH_B_MD) {
            mirror.emit<switch_port_mirror_metadata_h>(local_md.mirror.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                local_md.ingress_timestamp,
                local_md.mirror.session_id});
        }
#endif
        else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_CPU) {
            mirror.emit<switch_cpu_mirror_metadata_h>(local_md.mirror.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                0,
                local_md.ingress_port,
                local_md.bd,
                0,
                local_md.egress_port_lag_index,
                local_md.cpu_reason});
        } else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_dtel_switch_local_mirror_metadata_h>(local_md.dtel.session_id, {
                local_md.mirror.src, local_md.mirror.type,
                local_md.ingress_timestamp,
#if __TARGET_TOFINO__ == 1
                0,
#endif
                local_md.dtel.session_id,
                local_md.dtel.hash,
                local_md.dtel.report_type,
                0,
                local_md.ingress_port,
                0,
                local_md.egress_port,
                0,
                local_md.qos.qid,
                0,
                local_md.qos.qdepth,
                local_md.egress_timestamp
            });
#endif /* DTEL_ENABLE */
        } else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_DTEL_DROP) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_dtel_drop_mirror_metadata_h>(local_md.dtel.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
                local_md.ingress_timestamp,
#if __TARGET_TOFINO__ == 1
                 0,
#endif
                local_md.dtel.session_id,
                local_md.dtel.hash,
                local_md.dtel.report_type,
                0,
                local_md.ingress_port,
                0,
                local_md.egress_port,
                0,
                local_md.qos.qid,
                local_md.drop_reason
            });
#endif /* DTEL_ENABLE */
        } else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_SIMPLE) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_simple_mirror_metadata_h>(local_md.dtel.session_id, {
                local_md.mirror.src,
                local_md.mirror.type,
#if __TARGET_TOFINO__ == 1
                0,
#endif
                local_md.dtel.session_id
            });
#endif /* DTEL_ENABLE */
        }
#endif /* MIRROR_ENABLE */
    }
}

control IngressNatChecksum(
    inout switch_header_t hdr,
    in switch_local_metadata_t local_md) {
    Checksum() tcp_checksum;
    Checksum() udp_checksum;
    apply {
#ifdef NAT_ENABLE
        if(hdr.tcp.isValid()) {
          hdr.tcp.checksum = tcp_checksum.update({
                  local_md.lkp.ip_src_addr,
                  local_md.lkp.ip_dst_addr,
                  hdr.tcp.src_port,
                  hdr.tcp.dst_port,
                  local_md.tcp_udp_checksum});
        } else if(hdr.udp.isValid()) {
          hdr.udp.checksum = udp_checksum.update({
                  local_md.lkp.ip_src_addr,
                  local_md.lkp.ip_dst_addr,
                  hdr.udp.src_port,
                  hdr.udp.dst_port,
                  local_md.tcp_udp_checksum});
        }
#endif
    }
}

//-----------------------------------------------------------------------------
// Ingress Deparser
//-----------------------------------------------------------------------------
control SwitchIngressDeparser(
    packet_out pkt,
    inout switch_header_t hdr,
    in switch_local_metadata_t local_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    IngressMirror() mirror;
    Digest<switch_learning_digest_t>() digest;
#ifdef NAT_ENABLE
    Checksum() tcp_checksum;
    Checksum() udp_checksum;
    Checksum() v6_checksum;
    IngressNatChecksum() nat_checksum;
#endif

    apply {
        mirror.apply(hdr, local_md, ig_intr_md_for_dprsr);

        if (ig_intr_md_for_dprsr.digest_type == SWITCH_DIGEST_TYPE_MAC_LEARNING) {
            digest.pack({local_md.ingress_outer_bd, local_md.ingress_port_lag_index, hdr.ethernet.src_addr});
        }
#ifdef NAT_ENABLE
        nat_checksum.apply(hdr,local_md);
#endif

        pkt.emit(hdr.bridged_md); // Ingress only.
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.arp); // Ingress only.
#ifdef SFC_ENABLE
        pkt.emit(hdr.pfc); // Ingress only
#endif
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option);
        pkt.emit(hdr.ipv6);
#ifdef SRV6_ENABLE
        pkt.emit(hdr.srh_base);
        pkt.emit(hdr.srh_seg_list);
#endif /* SRV6_ENABLE */
#ifdef MPLS_ENABLE
        pkt.emit(hdr.mpls);
#endif /* MPLS_ENABLE */
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp); // Ingress only.
        pkt.emit(hdr.icmp); // Ingress only.
        pkt.emit(hdr.igmp); // Ingress only.
        pkt.emit(hdr.rocev2_bth); // Ingress only.
#ifdef VXLAN_ENABLE
        pkt.emit(hdr.vxlan);
#endif
        pkt.emit(hdr.gre);
#ifdef NVGRE_ENABLE
        pkt.emit(hdr.nvgre);
#endif
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.inner_tcp);
        pkt.emit(hdr.inner_icmp);

        pkt.emit(hdr.payload1);
        pkt.emit(hdr.payload2);
        pkt.emit(hdr.payload3);
        pkt.emit(hdr.payload4);
        pkt.emit(hdr.payload5);
        pkt.emit(hdr.payload6);
        pkt.emit(hdr.payload7);
        pkt.emit(hdr.payload8);
        pkt.emit(hdr.payload9);
        pkt.emit(hdr.payload10);
        pkt.emit(hdr.payload11);
        pkt.emit(hdr.payload12);
        pkt.emit(hdr.payload13);
        pkt.emit(hdr.payload14);
        pkt.emit(hdr.payload15);
        pkt.emit(hdr.payload16);
    }
}


//-----------------------------------------------------------------------------
// Egress Deparser
//-----------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout switch_header_t hdr,
        in switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    EgressMirror() mirror;
    Checksum() ipv4_checksum;
    Checksum() inner_ipv4_checksum;

    apply {
        mirror.apply(hdr, local_md, eg_intr_md_for_dprsr);

#if !defined(IPV4_CSUM_IN_MAU)
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.ipv4_option.type,
            hdr.ipv4_option.length,
            hdr.ipv4_option.value});

#ifdef TUNNEL_ENABLE
        if (local_md.inner_ipv4_checksum_update_en) {
            hdr.inner_ipv4.hdr_checksum = inner_ipv4_checksum.update({
                hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.diffserv,
                hdr.inner_ipv4.total_len,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flags,
                hdr.inner_ipv4.frag_offset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.src_addr,
                hdr.inner_ipv4.dst_addr});
        }
#endif /* TUNNEL_ENABLE */
#endif /* IPV4_CSUM_IN_MAU */

        pkt.emit(hdr.ethernet);
#ifdef SFC_ENABLE
        pkt.emit(hdr.pfc); //egress only
#endif
        pkt.emit(hdr.fabric); // Egress only.
        pkt.emit(hdr.cpu); // Egress only.
        pkt.emit(hdr.timestamp); // Egress only.
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option);
        pkt.emit(hdr.ipv6);
#ifdef SRV6_ENABLE
        pkt.emit(hdr.srh_base);
        pkt.emit(hdr.srh_seg_list);
#endif /* SRV6_ENABLE */
#ifdef MPLS_ENABLE
        pkt.emit(hdr.mpls);
#endif /* MPLS_ENABLE */
        pkt.emit(hdr.udp);
#ifdef SFC_ENABLE
        pkt.emit(hdr.sfc_pause);
        pkt.emit(hdr.pad_112b);
        pkt.emit(hdr.pad_96b);
        pkt.emit(hdr.tcp);
#endif
        pkt.emit(hdr.dtel); // Egress only.
#ifdef INT_V2
        pkt.emit(hdr.dtel_metadata_1); // Egress only.
        pkt.emit(hdr.dtel_metadata_2); // Egress only.
        pkt.emit(hdr.dtel_metadata_3); // Egress only.
        pkt.emit(hdr.dtel_metadata_4); // Egress only.
        pkt.emit(hdr.dtel_metadata_5); // Egress only.
#else
        pkt.emit(hdr.dtel_report); // Egress only.
        pkt.emit(hdr.dtel_switch_local_report); // Egress only.
#endif
        pkt.emit(hdr.dtel_drop_report); // Egress only.
#ifdef VXLAN_ENABLE
        pkt.emit(hdr.vxlan);
#endif
        pkt.emit(hdr.gre);
#ifdef NVGRE_ENABLE
        pkt.emit(hdr.nvgre);
#endif
        pkt.emit(hdr.erspan); // Egress only.
        pkt.emit(hdr.erspan_type2); // Egress only.
        pkt.emit(hdr.erspan_type3); // Egress only.
        pkt.emit(hdr.erspan_platform); // Egress only.
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_udp);
#if __TARGET_TOFINO__ == 2
	pkt.emit(hdr.pad);
#endif
    }
}
