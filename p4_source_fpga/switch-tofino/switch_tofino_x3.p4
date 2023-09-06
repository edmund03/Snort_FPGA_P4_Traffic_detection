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


#include <core.p4>
#include <tna.p4>

//-----------------------------------------------------------------------------
// Features.
//-----------------------------------------------------------------------------
// L2 Unicast
#define COPP_ENABLE
#define STORM_CONTROL_ENABLE

// L3 Unicast
#define IPV6_ENABLE

// ACLs
#define L4_PORT_LOU_ENABLE
#define EGRESS_IP_ACL_ENABLE
#define EGRESS_COPP_DISABLE

// Mirror
#define MIRROR_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define INGRESS_MIRROR_ACL_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define PACKET_LENGTH_ADJUSTMENT

// QoS
#define QOS_ENABLE
#define WRED_ENABLE

//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------
// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 16384;

// IP Hosts/Routes
const bit<32> IPV4_HOST_TABLE_SIZE = 65536;
const bit<32> IPV4_LPM_TABLE_SIZE = 32768;
const bit<32> IPV6_HOST_TABLE_SIZE = 16384;
const bit<32> IPV6_LPM_TABLE_SIZE = 16384;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 256;
const bit<32> ECMP_SELECT_TABLE_SIZE = 16384;
const bit<32> NEXTHOP_TABLE_SIZE = 65536;

// Ingress ACLs
const bit<32> INGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 1024;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IP_MIRROR_ACL_TABLE_SIZE = 512;

const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 512;

#include "headers.p4"
#include "types.p4"
#include "util.p4"
#include "hash.p4"

#include "l3.p4"
#include "nexthop.p4"
#include "parde.p4"
#include "port.p4"
#include "validation.p4"
#include "mirror_rewrite.p4"
#include "multicast.p4"
#include "qos.p4"
#include "meter.p4"
#include "wred.p4"
#include "tunnel.p4"
#include "acl.p4"

control SwitchIngress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
    IngressPortMapping(PORT_VLAN_TABLE_SIZE, BD_TABLE_SIZE) ingress_port_mapping;
    PktValidation() pkt_validation;
    SMAC(MAC_TABLE_SIZE) smac;
    DMAC(MAC_TABLE_SIZE) dmac;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    EnableFragHash() enable_frag_hash;
    Ipv4Hash() ipv4_hash;
    Ipv6Hash() ipv6_hash;
    NonIpHash() non_ip_hash;
    Lagv4Hash() lagv4_hash;
    Lagv6Hash() lagv6_hash;
    LOU() lou;
    Fibv4(IPV4_HOST_TABLE_SIZE, IPV4_LPM_TABLE_SIZE) ipv4_fib;
    Fibv6(IPV6_HOST_TABLE_SIZE, IPV6_HOST64_TABLE_SIZE, IPV6_LPM_TABLE_SIZE) ipv6_fib;
    IngressIpv4Acl(INGRESS_IPV4_ACL_TABLE_SIZE) ingress_ipv4_acl;
    IngressIpv6Acl(INGRESS_IPV6_ACL_TABLE_SIZE) ingress_ipv6_acl;
    IngressMacAcl(INGRESS_MAC_ACL_TABLE_SIZE) ingress_mac_acl;
    IngressIpAcl(INGRESS_IP_MIRROR_ACL_TABLE_SIZE) ingress_ip_mirror_acl;
    ECNAcl() ecn_acl;
    IngressQoSMap() qos_map;
    IngressTC() traffic_class;
    PPGStats() ppg_stats;
    StormControl() storm_control;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;

   action vip_hit(switch_port_t port) {
        // Send the packet to the other pipe and bypass rest of the lookups.
        //TODO(msharif): Load balance across all the ports in the other pipelines using the flow
        // hash.
        ig_intr_md_for_tm.ucast_egress_port = port;
        local_md.egress_port_lag_index = 0;
        local_md.bypass = SWITCH_INGRESS_BYPASS_ALL;
    }

    table vip {
        key = {
            hdr.ipv4.dst_addr : exact;
            local_md.lkp.l4_dst_port   : exact;
            local_md.lkp.ip_proto : exact;
        }

        actions = {
            NoAction;
            vip_hit;
        }

        const default_action = NoAction;
    }

    apply {
        pkt_validation.apply(hdr, local_md);
        ingress_port_mapping.apply(hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        smac.apply(hdr.ethernet.src_addr, local_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(local_md.bd, local_md.lkp.pkt_type);
        if (local_md.flags.rmac_hit) {
          if (!INGRESS_BYPASS(L3)) {
            if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV6 && local_md.ipv6.unicast_enable) {
              ipv6_fib.apply(local_md);
            } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4 && local_md.ipv4.unicast_enable) {
              ipv4_fib.apply(local_md);
            } else {
              // Non-ip packets with router MAC address will be dropped by system ACL.
            }
          }
        } else {
          dmac.apply(local_md.lkp.mac_dst_addr, local_md);
        }
        vip.apply();

        if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV6) {
            ingress_ipv4_acl.apply(local_md, local_md.unused_nexthop);
        } else if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
            ingress_ipv6_acl.apply(local_md, local_md.unused_nexthop);
        }
        ingress_ip_mirror_acl.apply(local_md, local_md.unused_nexthop);

        enable_frag_hash.apply(local_md.lkp);
        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_NONE) {
            non_ip_hash.apply(hdr, local_md, local_md.lag_hash);
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            lagv4_hash.apply(local_md.lkp, local_md.lag_hash);
        } else {
            lagv6_hash.apply(local_md.lkp, local_md.lag_hash);
        }

        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            ipv4_hash.apply(local_md.lkp, local_md.hash[31:0]);
        } else {
            ipv6_hash.apply(local_md.lkp, local_md.hash[31:0]);
        }

        nexthop.apply(local_md);
        qos_map.apply(hdr, local_md);
        storm_control.apply(local_md, local_md.lkp.pkt_type, local_md.flags.storm_control_drop);
        traffic_class.apply(local_md);

        if (local_md.egress_port_lag_index == SWITCH_FLOOD) {
            flood.apply(local_md);
        } else {
            lag.apply(local_md, local_md.lag_hash, ig_intr_md_for_tm.ucast_egress_port);
        }

        ecn_acl.apply(local_md, local_md.lkp, ig_intr_md_for_tm.packet_color);
        system_acl.apply(
            hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        ppg_stats.apply(local_md);

        // Only add bridged metadata if we are NOT bypassing egress pipeline.
        if (ig_intr_md_for_tm.bypass_egress == 1w0) {
            add_bridged_md(hdr.bridged_md, local_md);
        }

        set_ig_intr_md(local_md, ig_intr_md_for_dprsr, ig_intr_md_for_tm);
    }
}

control SwitchEgress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    EgressPortMapping() egress_port_mapping;
    EgressPortMirror(288) port_mirror;
    EgressIpv4Acl(EGRESS_IPV4_ACL_TABLE_SIZE) egress_ipv4_acl;
    EgressIpv6Acl(EGRESS_IPV6_ACL_TABLE_SIZE) egress_ipv6_acl;
    EgressQoS() qos;
    EgressQueue() queue;
    EgressSystemAcl() system_acl;
    EgressVRF() egress_vrf;
    EgressBD() egress_bd;
    OuterNexthop() outer_nexthop;
    EgressBDStats() egress_bd_stats;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    MTU() mtu;
    WRED() wred;
    EgressCpuRewrite() cpu_rewrite;
    Neighbor() neighbor;
    SetEgIntrMd() set_eg_intr_md;

    apply {
        egress_port_mapping.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        if (local_md.pkt_src != SWITCH_PKT_SRC_BRIDGED) {
            mirror_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr);
        } else {
            port_mirror.apply(eg_intr_md.egress_port, local_md.mirror);
            vlan_decap.apply(hdr, local_md);
            qos.apply(hdr, eg_intr_md.egress_port, local_md);
            wred.apply(hdr, local_md, eg_intr_md, local_md.flags.wred_drop);
            egress_vrf.apply(hdr, local_md);
            outer_nexthop.apply(hdr, local_md);
            egress_bd.apply(hdr, local_md);
            if (hdr.ipv4.isValid()) {
                egress_ipv4_acl.apply(hdr, local_md);
            } else if (hdr.ipv6.isValid()) {
                egress_ipv6_acl.apply(hdr, local_md);
            }
            neighbor.apply(hdr, local_md);
            egress_bd_stats.apply(hdr, local_md);
            mtu.apply(hdr, local_md);
            vlan_xlate.apply(hdr, local_md);
	}
        system_acl.apply(hdr, local_md, eg_intr_md, eg_intr_md_for_dprsr);
        cpu_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        set_eg_intr_md.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
        queue.apply(eg_intr_md.egress_port, local_md);
    }
}

control L4LB(inout switch_header_t hdr,
             inout switch_local_metadata_t local_md)(
             switch_uint32_t conn_table_size,
             switch_uint32_t vip_table_size,
             switch_uint32_t dip_pool_table_size) {
// Base on
// R Miao, H Zeng, C Kim, J Lee, M Yu, "SilkRoad: Making Stateful Layer-4 Load Balancing Fast and
// Cheap Using Switching ASICs", SIGCOMM'17
//
// Notable missing features:
// - Learning
// - Transit table

    bit<6> pool_version;

    bit<16> digest;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) digest_hash;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) selector_hash;
    ActionSelector(1024, selector_hash, SelectorMode_t.FAIR) dip_selector;

    action set_pool_version(bit<6> version) {
        pool_version = version;
    }

    @pragma proxy_hash_width 16
    //TODO(msharif): This table (or part of it) can be moved to switch pipeline to reduce latency.
    table conn {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.ipv4.protocol : exact;
            local_md.lkp.l4_src_port : exact;
            local_md.lkp.l4_dst_port : exact;
        }

        actions = {
            NoAction;
            set_pool_version;
        }

        const default_action = NoAction;
        size = conn_table_size;
        idle_timeout = true;
    }

    table vip {
        key = {
            hdr.ipv4.dst_addr : exact @name("vip");
            local_md.lkp.l4_dst_port : exact;
            local_md.lkp.ip_proto : exact;
        }

        actions = {
            NoAction;
            set_pool_version;
        }

        const default_action = NoAction;
    }

    action set_dip(ipv4_addr_t dip, bit<16> dst_port) {
        hdr.ipv4.dst_addr = dip;
        local_md.lkp.l4_dst_port = dst_port;
    }

    table dip_pool {
        key = {
            pool_version : exact;
            hdr.ipv4.dst_addr : exact @name("vip");
            local_md.lkp.l4_dst_port : exact;
            hdr.ipv4.src_addr : selector;
            local_md.lkp.l4_src_port : selector;
        }

        actions = {
            NoAction;
            set_dip;
        }

        size = dip_pool_table_size;
        implementation = dip_selector;
    }

    apply {
        if (!conn.apply().hit) {
            vip.apply();

            if (pool_version != 0) {
                // Generate digest.
            }
        }

        dip_pool.apply();

        if (hdr.tcp.isValid()) {
            hdr.tcp.dst_port = local_md.lkp.l4_dst_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.dst_port = local_md.lkp.l4_dst_port;
        }
    }
}

control L4LBIngress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action fib_hit(mac_addr_t dmac, switch_port_t port) {
        hdr.ethernet.dst_addr = dmac;
        ig_intr_md_for_tm.ucast_egress_port = port;
        ig_intr_md_for_tm.bypass_egress = 1w1;
        ig_intr_md_for_dprsr.drop_ctl = 0x0;
    }

    action fib_miss() {
        ig_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    table fib {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            fib_hit;
            fib_miss;
        }

        const default_action = fib_miss;
    }

    apply {
        fib.apply();
    }
}

control L4LBEgress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    L4LB(conn_table_size=1 << 18,
         vip_table_size=16384,
         dip_pool_table_size=16384) l4lb;

    apply {
        l4lb.apply(hdr, local_md);
    }
}


//-----------------------------------------------------------------------------
// Parser
//-----------------------------------------------------------------------------
parser PacketParser(packet_in pkt, inout switch_header_t hdr) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

parser L4LBIngressParser(packet_in pkt,
                        out switch_header_t hdr,
                        out switch_local_metadata_t local_md,
                        out ingress_intrinsic_metadata_t ig_intr_md) {

    PacketParser() packet_parser;
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        packet_parser.apply(pkt, hdr);
        transition accept;
    }
}

parser L4LBEgressParser(packet_in pkt,
                        out switch_header_t hdr,
                        out switch_local_metadata_t local_md,
                        out egress_intrinsic_metadata_t eg_intr_md) {

    PacketParser() packet_parser;
    state start {
        pkt.extract(eg_intr_md);
        transition parse_bridged_metadata;
    }

    state parse_bridged_metadata {
        pkt.extract(hdr.bridged_md);
        local_md.lkp.l4_src_port = hdr.bridged_md.acl.l4_src_port;
        local_md.lkp.l4_dst_port = hdr.bridged_md.acl.l4_dst_port;
        packet_parser.apply(pkt, hdr);
        transition accept;
    }
}

//-----------------------------------------------------------------------------
// Deparser
//-----------------------------------------------------------------------------
control L4LBIngressDeparser(
    packet_out pkt,
    inout switch_header_t hdr,
    in switch_local_metadata_t local_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

control L4LBEgressDeparser(
        packet_out pkt,
        inout switch_header_t hdr,
        in switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

Pipeline <switch_header_t, switch_local_metadata_t, switch_header_t, switch_local_metadata_t> (L4LBIngressParser(),
         L4LBIngress(),
         L4LBIngressDeparser(),
         L4LBEgressParser(),
         L4LBEgress(),
         L4LBEgressDeparser()) lb;

Pipeline <switch_header_t, switch_local_metadata_t, switch_header_t, switch_local_metadata_t> (SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe, lb) main;
