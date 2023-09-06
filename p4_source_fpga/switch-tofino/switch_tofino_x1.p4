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
#define IPV6_LPM64_ENABLE

// ACLs
#define L4_PORT_LOU_ENABLE
#define ETYPE_IN_IP_ACL_KEY_ENABLE
#define EGRESS_IP_ACL_ENABLE
#define ACL_REDIRECT_PORT_ENABLE
#define ACL_REDIRECT_NEXTHOP_ENABLE
#define EGRESS_COPP_DISABLE
#define L4_PORT_EGRESS_LOU_ENABLE
#define EGRESS_ACL_PORT_RANGE_ENABLE
//To enable port_group in ingress ACLs.
//#define PORT_GROUP_IN_ACL_KEY_ENABLE

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
// #define QOS_ACL_ENABLE
#define WRED_ENABLE
#define PFC_ENABLE

// DTEL
#define DTEL_ENABLE
#define DTEL_QUEUE_REPORT_ENABLE
#define DTEL_DROP_REPORT_ENABLE
#define DTEL_FLOW_REPORT_ENABLE
#define DTEL_ACL_ENABLE

// SFLOW
#define INGRESS_SFLOW_ENABLE

#define PORT_ISOLATION_ENABLE

//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------
#define switch_counter_width 64

const bit<32> PORT_TABLE_SIZE = 288 * 2;

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
#define ipv4_lpm_number_partitions 2048
#define ipv6_lpm_number_partitions 1024
#define ipv6_lpm64_number_partitions 1024
#define ipv6_lpm64_subtrees_per_partition 2
const bit<32> IPV4_HOST_TABLE_SIZE = 64*1024;
const bit<32> IPV4_LPM_TABLE_SIZE = 128*1024;
const bit<32> IPV4_LOCAL_HOST_TABLE_SIZE = 16*1024;
const bit<32> IPV6_HOST_TABLE_SIZE = 32*1024;
const bit<32> IPV6_LPM_TABLE_SIZE = 10*1024;
const bit<32> IPV6_LPM64_TABLE_SIZE = 32*1024;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 512;
const bit<32> ECMP_SELECT_TABLE_SIZE = 64*ECMP_GROUP_TABLE_SIZE;
const bit<32> NEXTHOP_TABLE_SIZE = 65536;

// Ingress ACLs
const bit<32> PRE_INGRESS_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 2048;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 1024;
const bit<32> INGRESS_IP_MIRROR_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IP_DTEL_ACL_TABLE_SIZE = 512;

// Egress ACLs
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;

// Storm Control
const bit<32> STORM_CONTROL_TABLE_SIZE = 256;

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
#include "acl.p4"
#include "dtel.p4"
#include "sflow.p4"

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
    IngressSflow() sflow;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    EnableFragHash() enable_frag_hash;
    Ipv4Hash() ipv4_hash;
    Ipv6Hash() ipv6_hash;
    NonIpHash() non_ip_hash;
    Lagv4Hash() lagv4_hash;
    Lagv6Hash() lagv6_hash;
    LOU() lou;
    Fibv4(IPV4_HOST_TABLE_SIZE,
        IPV4_LPM_TABLE_SIZE,
        true,
        IPV4_LOCAL_HOST_TABLE_SIZE) ipv4_fib;
    Fibv6(IPV6_HOST_TABLE_SIZE, IPV6_HOST64_TABLE_SIZE, IPV6_LPM_TABLE_SIZE, IPV6_LPM64_TABLE_SIZE) ipv6_fib;
    PreIngressAcl(PRE_INGRESS_ACL_TABLE_SIZE) pre_ingress_acl;
    IngressIpv4Acl(INGRESS_IPV4_ACL_TABLE_SIZE) ingress_ipv4_acl;
    IngressIpv6Acl(INGRESS_IPV6_ACL_TABLE_SIZE) ingress_ipv6_acl;
    IngressIpAcl(INGRESS_IP_MIRROR_ACL_TABLE_SIZE) ingress_ip_mirror_acl;
    IngressIpDtelSampleAcl(INGRESS_IP_DTEL_ACL_TABLE_SIZE) ingress_ip_dtel_acl;
    ECNAcl() ecn_acl;
    IngressPFCWd(512) pfc_wd;
    IngressQoSMap() qos_map;
    IngressTC() traffic_class;
    PPGStats() ppg_stats;
    StormControl() storm_control;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;
    IngressDtel() dtel;
    SameMacCheck() same_mac_check;

    apply {
        pkt_validation.apply(hdr, local_md);
        ingress_port_mapping.apply(hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        pre_ingress_acl.apply(hdr, local_md);
        lou.apply(local_md);
        enable_frag_hash.apply(local_md.lkp);
        smac.apply(hdr.ethernet.src_addr, local_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(local_md.bd, local_md.lkp.pkt_type);
        same_mac_check.apply(hdr, local_md);
        if (local_md.flags.rmac_hit) {
            if (!INGRESS_BYPASS(L3) && local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4 && local_md.ipv4.unicast_enable) {
                ipv4_fib.apply(local_md);
                ingress_ipv4_acl.apply(local_md, local_md.nexthop);
                // this is a workaround to always make v6_acl the default next table for v4_acl
                if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
                    ingress_ipv6_acl.apply(local_md, local_md.nexthop);
                }
            } else if (!INGRESS_BYPASS(L3) && local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV6 && local_md.ipv6.unicast_enable) {
                ipv6_fib.apply(local_md);
                ingress_ipv6_acl.apply(local_md, local_md.nexthop);
            } else {
                dmac.apply(local_md.lkp.mac_dst_addr, local_md);
                if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV6) {
                    ingress_ipv4_acl.apply(local_md, local_md.nexthop);
                }
                if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
                    ingress_ipv6_acl.apply(local_md, local_md.nexthop);
                }
            }
        } else {
            dmac.apply(local_md.lkp.mac_dst_addr, local_md);
            if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV6) {
                ingress_ipv4_acl.apply(local_md, local_md.nexthop);
            }
            if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
                ingress_ipv6_acl.apply(local_md, local_md.nexthop);
            }
        }
        ingress_ip_mirror_acl.apply(local_md, local_md.unused_nexthop);
        sflow.apply(local_md);

        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_NONE) {
            non_ip_hash.apply(hdr, local_md, local_md.lag_hash);
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            lagv4_hash.apply(local_md.lkp, local_md.lag_hash);
        } else {
            lagv6_hash.apply(local_md.lkp, local_md.lag_hash);
        }

        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            ipv4_hash.apply(local_md.lkp, local_md.hash);
        } else {
            ipv6_hash.apply(local_md.lkp, local_md.hash);
        }

        nexthop.apply(local_md);
        qos_map.apply(hdr, local_md);
        traffic_class.apply(local_md);
        storm_control.apply(local_md, local_md.lkp.pkt_type, local_md.flags.storm_control_drop);
        ppg_stats.apply(local_md);

        if (local_md.egress_port_lag_index == SWITCH_FLOOD) {
            flood.apply(local_md);
        } else {
            lag.apply(local_md, local_md.lag_hash, ig_intr_md_for_tm.ucast_egress_port);
        }

        ecn_acl.apply(local_md, local_md.lkp, ig_intr_md_for_tm.packet_color);
        pfc_wd.apply(local_md.ingress_port, local_md.qos.qid, local_md.flags.pfc_wd_drop);

        system_acl.apply(hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        ingress_ip_dtel_acl.apply(local_md, local_md.unused_nexthop);
        dtel.apply(
            hdr, local_md.lkp, local_md, local_md.lag_hash[15:0], ig_intr_md_for_dprsr, ig_intr_md_for_tm);

        add_bridged_md(hdr.bridged_md, local_md);

        set_ig_intr_md(local_md, ig_intr_md_for_dprsr, ig_intr_md_for_tm);
    }
}

control SwitchEgress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    EgressPortMapping() egress_port_mapping;
    EgressPortMirror(288) port_mirror;
    EgressLOU() lou;
    EgressIpv4Acl(EGRESS_IPV4_ACL_TABLE_SIZE) egress_ipv4_acl;
    EgressIpv6Acl(EGRESS_IPV6_ACL_TABLE_SIZE) egress_ipv6_acl;
    EgressQoS() qos;
    EgressQueue() queue;
    EgressSystemAcl() system_acl;
    EgressPFCWd(512) pfc_wd;
    EgressVRF() egress_vrf;
    EgressBD() egress_bd;
    OuterNexthop() outer_nexthop;
    EgressBDStats() egress_bd_stats;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    MTU() mtu;
    WRED() wred;
    EgressDtel() dtel;
    DtelConfig() dtel_config;
    EgressCpuRewrite() cpu_rewrite;
    EgressPortIsolation() port_isolation;
    Neighbor() neighbor;
    SetEgIntrMd() set_eg_intr_md;

    apply {
        egress_port_mapping.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        if (local_md.pkt_src != SWITCH_PKT_SRC_BRIDGED) {
            mirror_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr);
        } else {
            port_mirror.apply(eg_intr_md.egress_port, local_md.mirror);
	}
        vlan_decap.apply(hdr, local_md);
        qos.apply(hdr, eg_intr_md.egress_port, local_md);
        wred.apply(hdr, local_md, eg_intr_md, local_md.flags.wred_drop);
        egress_vrf.apply(hdr, local_md);
        outer_nexthop.apply(hdr, local_md);
        egress_bd.apply(hdr, local_md);
        lou.apply(local_md);
        if (hdr.ipv4.isValid()) {
            egress_ipv4_acl.apply(hdr, local_md);
        } else if (hdr.ipv6.isValid()) {
            egress_ipv6_acl.apply(hdr, local_md);
        }
        neighbor.apply(hdr, local_md);
        egress_bd_stats.apply(hdr, local_md);
        mtu.apply(hdr, local_md);
        vlan_xlate.apply(hdr, local_md);
        pfc_wd.apply(eg_intr_md.egress_port, local_md.qos.qid, local_md.flags.pfc_wd_drop);
        dtel.apply(hdr, local_md, eg_intr_md, eg_intr_md_from_prsr, local_md.dtel.hash);
        port_isolation.apply(local_md, eg_intr_md);
        system_acl.apply(hdr, local_md, eg_intr_md, eg_intr_md_for_dprsr);
        dtel_config.apply(hdr, local_md, eg_intr_md_for_dprsr);
        cpu_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        set_eg_intr_md.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
        queue.apply(eg_intr_md.egress_port, local_md);
    }
}

Pipeline <switch_header_t, switch_local_metadata_t, switch_header_t, switch_local_metadata_t> (SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;

Switch(pipe) main;
