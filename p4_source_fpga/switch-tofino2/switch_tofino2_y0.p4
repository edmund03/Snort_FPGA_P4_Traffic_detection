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
#include <t2na.p4>

//-----------------------------------------------------------------------------
// Features.
//-----------------------------------------------------------------------------
// L2 Unicast
#define COPP_ENABLE
#define STP_ENABLE

// L3 Unicast
#define IPV6_ENABLE
#define L3_UNICAST_SELF_FORWARDING_CHECK
#define SHARED_IP_LPM64_TABLE

// Multicast
#define MULTICAST_ENABLE

// ACLs
#define L4_PORT_LOU_ENABLE
#define EGRESS_IP_ACL_ENABLE
#define ETYPE_IN_IP_ACL_KEY_ENABLE
#define QOS_ACTIONS_IN_IP_ACL_ENABLE
//#define TCP_FLAGS_LOU_ENABLE
//#define RACL_ENABLE
//#define ACL_REDIRECT_NEXTHOP_ENABLE
//#define ACL_REDIRECT_PORT_ENABLE
//#define PBR_ENABLE
#define EGRESS_ACL_BD_LABEL_ENABLE

// Mirror
#define MIRROR_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define INGRESS_MIRROR_ACL_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define PACKET_LENGTH_ADJUSTMENT
#define DEPARSER_TRUNCATE

// QoS
#define QOS_ENABLE
#define INGRESS_QOS_ACL_ENABLE
#define INGRESS_PORT_METER_ENABLE
#define EGRESS_PORT_METER_ENABLE
#define INGRESS_ACL_METER_ENABLE
#define EGRESS_ACL_METER_ENABLE
//#define WRED_ENABLE
//#define PFC_ENABLE

// DTEL
#define DTEL_ENABLE
#define DTEL_QUEUE_REPORT_ENABLE
#define DTEL_DROP_REPORT_ENABLE
#define DTEL_FLOW_REPORT_ENABLE
#define DTEL_ETRAP_REPORT_ENABLE
#define DTEL_ACL_ENABLE
#define DTEL_IFA_CLONE
#define DTEL_IFA_EDGE
#define INT_V2

// Misc
#define MLAG_ENABLE
#define PTP_ENABLE
#define BFD_OFFLOAD_ENABLE

//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------
const bit<32> PORT_TABLE_SIZE = 288 * 2;

// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 4K (port, vlan[0], vlan[1]) <--> BD
const bit<32> DOUBLE_TAG_TABLE_SIZE = 4096;

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 16384;

// IP Hosts/Routes
const bit<32> IPV4_HOST_TABLE_SIZE = 16384;  // 32768
const bit<32> IPV6_HOST_TABLE_SIZE = 8192; // 16384;
const bit<32> IP_LPM64_TABLE_SIZE = 16384;
const bit<32> IPV6_LPM_TABLE_SIZE = 512;
#define IPv6_LPM128_TCAM

// Multicast
const bit<32> IPV4_MULTICAST_STAR_G_TABLE_SIZE = 2048;
const bit<32> IPV4_MULTICAST_S_G_TABLE_SIZE = 4096;
const bit<32> IPV6_MULTICAST_STAR_G_TABLE_SIZE = 512;
const bit<32> IPV6_MULTICAST_S_G_TABLE_SIZE = 512;
const bit<32> RID_TABLE_SIZE = 4096;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 256;
const bit<32> ECMP_SELECT_TABLE_SIZE = 16384;
#define switch_nexthop_width 14
const bit<32> NEXTHOP_TABLE_SIZE = 16384; // 32768

// Ingress ACLs
const bit<32> INGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IP_MIRROR_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IP_QOS_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IP_DTEL_ACL_TABLE_SIZE = 512;

// Egress ACL
const bit<32> EGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;

// QoS
const bit<32> DSCP_TO_TC_TABLE_SIZE = 1024;
const bit<32> PCP_TO_TC_TABLE_SIZE = 1024;
const bit<32> QUEUE_TABLE_SIZE = 1024;
const bit<32> EGRESS_QOS_MAP_TABLE_SIZE = 1024;

// Storm Control
const bit<32> STORM_CONTROL_TABLE_SIZE = 256;

// System ACL
const bit<32> INGRESS_SYSTEM_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_SYSTEM_ACL_TABLE_SIZE = 512;

const bit<32> L3_MTU_TABLE_SIZE = 1024;

// BFD
const bit<32> BFD_SESSION_SIZE = 4096;
const bit<32> BFD_PER_PIPE_SESSION_SIZE = 1024;

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
#include "etrap.p4"
#include "bfd.p4"

control SwitchIngress(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    IngressPortMapping(PORT_VLAN_TABLE_SIZE,
                       BD_TABLE_SIZE,
                       DOUBLE_TAG_TABLE_SIZE) ingress_port_mapping;
    PktValidation() pkt_validation;
    IngressSTP() stp;
    SMAC(MAC_TABLE_SIZE) smac;
    DMAC(MAC_TABLE_SIZE) dmac;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    IngressMulticast(IPV4_MULTICAST_S_G_TABLE_SIZE,
                     IPV4_MULTICAST_STAR_G_TABLE_SIZE,
                     IPV6_MULTICAST_S_G_TABLE_SIZE,
                     IPV6_MULTICAST_STAR_G_TABLE_SIZE) multicast;
    EnableFragHash() enable_frag_hash;
    Ipv4Hash() ipv4_hash;
    Ipv6Hash() ipv6_hash;
    NonIpHash() non_ip_hash;
    Lagv4Hash() lagv4_hash;
    Lagv6Hash() lagv6_hash;
    LOU() lou;
    Fib() ip_fib;
    IngressIpv4Acl(INGRESS_IPV4_ACL_TABLE_SIZE) ingress_ipv4_acl;
    IngressIpv6Acl(INGRESS_IPV6_ACL_TABLE_SIZE) ingress_ipv6_acl;
    IngressMacAcl(INGRESS_MAC_ACL_TABLE_SIZE) ingress_mac_acl;
    IngressIpAcl(INGRESS_IP_QOS_ACL_TABLE_SIZE) ingress_ip_qos_acl;
    IngressIpDtelSampleAcl(INGRESS_IP_DTEL_ACL_TABLE_SIZE) ingress_ip_dtel_acl;

    IngressQoSMap() qos_map;
    IngressTC() traffic_class;
    PPGStats() ppg_stats;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;
    IngressDtel() dtel;
    ETrap() etrap;
    ETrapState() etrap_state;
    IngressPortMeter() port_meter;
    IngressAclMeter() acl_meter;
    BfdTxSession() bfd_tx_session;
    BfdRxSession() bfd_rx_session;
    BfdRxTimer() bfd_rx_timer;
    BfdPktAction() bfd_pkt_action;

    apply {
        pkt_validation.apply(hdr, local_md);
        ingress_port_mapping.apply(hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        port_meter.apply(local_md);
        stp.apply(local_md, local_md.stp);

        ingress_mac_acl.apply(hdr, local_md, local_md.unused_nexthop);
        if (hdr.bfd.isValid() && INGRESS_BYPASS(BFD_TX)) {
	    bfd_tx_session.apply(hdr, local_md);
	}
        lou.apply(local_md);

	bfd_rx_session.apply(hdr, local_md, ig_intr_md_for_tm);
	bfd_rx_timer.apply(local_md);

        smac.apply(hdr.ethernet.src_addr, local_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(local_md.bd, local_md.lkp.pkt_type);
        if (local_md.lkp.pkt_type == SWITCH_PKT_TYPE_UNICAST ||
            local_md.lkp.pkt_type == SWITCH_PKT_TYPE_BROADCAST) {
          if (local_md.flags.rmac_hit) {
            if (!INGRESS_BYPASS(L3)) {
                ip_fib.apply(local_md);
            }
          } else {
            dmac.apply(local_md.lkp.mac_dst_addr, local_md);
          }
        } else if (local_md.lkp.pkt_type == SWITCH_PKT_TYPE_MULTICAST &&
                local_md.lkp.ip_type != SWITCH_IP_TYPE_NONE) {
            // IP multicast packets.
            multicast.apply(local_md.lkp, local_md);
        }
        if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
            ingress_ipv6_acl.apply(local_md, local_md.unused_nexthop);
        }
        if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV6) {
            ingress_ipv4_acl.apply(local_md, local_md.unused_nexthop);
        }
        if (!local_md.flags.port_meter_drop) {
            acl_meter.apply(local_md);
        }
	bfd_pkt_action.apply(local_md);

        enable_frag_hash.apply(local_md.lkp);
        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            ipv4_hash.apply(local_md.lkp, local_md.hash[31:0]);
        } else {
            ipv6_hash.apply(local_md.lkp, local_md.hash[31:0]);
        }

        nexthop.apply(local_md);
#ifdef INGRESS_QOS_ACL_ENABLE
        ingress_ip_qos_acl.apply(local_md, local_md.unused_nexthop);
#else
        qos_map.apply(hdr, local_md);
#endif
        etrap.apply(local_md);
        etrap_state.apply(local_md);
        traffic_class.apply(local_md);
        ppg_stats.apply(local_md);

        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_NONE) {
            non_ip_hash.apply(hdr, local_md, local_md.lag_hash);
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            lagv4_hash.apply(local_md.lkp, local_md.lag_hash);
        } else {
            lagv6_hash.apply(local_md.lkp, local_md.lag_hash);
        }

        if (local_md.egress_port_lag_index == SWITCH_FLOOD) {
            flood.apply(local_md);
        } else {
            lag.apply(local_md, local_md.lag_hash, ig_intr_md_for_tm.ucast_egress_port);
        }

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
    EgressPortMapping(PORT_TABLE_SIZE) egress_port_mapping;
    EgressPortMirror(288) port_mirror;
    EgressSTP() stp;
    EgressQoS() qos;
    EgressQueue() queue;
    EgressIpv4Acl(EGRESS_IPV4_ACL_TABLE_SIZE) egress_ipv4_acl;
    EgressSystemAcl() system_acl;
    EgressVRF() egress_vrf;
    EgressBD() egress_bd;
    OuterNexthop() outer_nexthop;
    EgressBDStats() egress_bd_stats;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    MTU() mtu;
    MulticastReplication(RID_TABLE_SIZE) multicast_replication;
    EgressDtel() dtel;
    DtelConfig() dtel_config;
    EgressPortMeter() port_meter;
    EgressAclMeter() acl_meter;
    EgressCpuRewrite() cpu_rewrite;
    Neighbor() neighbor;
    SetEgIntrMd() set_eg_intr_md;
    BfdTxTimer() bfd_tx_timer;

    apply {
        egress_port_mapping.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
	bfd_tx_timer.apply(hdr, local_md, eg_intr_md_for_dprsr);
        if (local_md.pkt_src != SWITCH_PKT_SRC_BRIDGED) {
            mirror_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr);
        } else {
            port_mirror.apply(eg_intr_md.egress_port, local_md.mirror);
            port_meter.apply(local_md);
            multicast_replication.apply(eg_intr_md.egress_rid, eg_intr_md.egress_port, local_md);
            stp.apply(local_md, eg_intr_md.egress_port, local_md.checks.stp);
            vlan_decap.apply(hdr, local_md);
            qos.apply(hdr, eg_intr_md.egress_port, local_md);
            if (hdr.ipv4.isValid()) {
                egress_ipv4_acl.apply(hdr, local_md);
            }
            egress_vrf.apply(hdr, local_md);
            outer_nexthop.apply(hdr, local_md);
            egress_bd.apply(hdr, local_md);
            neighbor.apply(hdr, local_md);
            egress_bd_stats.apply(hdr, local_md);
            mtu.apply(hdr, local_md);
            vlan_xlate.apply(hdr, local_md);
        }
        dtel.apply(hdr, local_md, eg_intr_md, eg_intr_md_from_prsr, local_md.dtel.hash);
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
