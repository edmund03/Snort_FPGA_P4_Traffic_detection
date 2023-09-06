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

// L3 Unicast
#define IPV6_ENABLE
#define IPV6_LPM64_ENABLE
#define IPV6_HOST64_ENABLE
#define IPV6_LPM128_TCAM
#define IPV4_ALPM_OPT_EN
#define IPV6_ALPM_OPT_EN

// ACLs
#define L4_PORT_LOU_ENABLE
#define ETYPE_IN_IP_ACL_KEY_ENABLE
#define EGRESS_IP_ACL_ENABLE
#define ACL_REDIRECT_PORT_ENABLE
#define ACL_REDIRECT_NEXTHOP_ENABLE
#undef EGRESS_ACL_BD_LABEL_ENABLE
#define EGRESS_COPP_DISABLE
#define L4_PORT_EGRESS_LOU_ENABLE
#define EGRESS_ACL_PORT_RANGE_ENABLE
#define INGRESS_DSCP_MIRROR_ACL_ENABLE
#define EGRESS_DSCP_MIRROR_ACL_ENABLE
#define DIFFSERV_IN_EGRESS_ACL_ENABLE
#define IN_PORTS_IN_ACL_KEY_ENABLE
#define OUT_PORTS_IN_ACL_KEY_ENABLE

// Mirror
#define MIRROR_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define INGRESS_MIRROR_ACL_ENABLE
#define EGRESS_MIRROR_ACL_ENABLE
#define MIRROR_METER_ENABLE
#define INGRESS_MIRROR_METER_ENABLE
#define EGRESS_MIRROR_METER_ENABLE
#define INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
#define EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
//#define INGRESS_MIRROR_METER_ENABLE
//#define EGRESS_MIRROR_METER_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define PACKET_LENGTH_ADJUSTMENT

// QoS
#define QOS_ENABLE
#define WRED_ENABLE
#define PFC_ENABLE

// Tunnel
#define TUNNEL_ENABLE
#define IPINIP_ENABLE
#define IPV6_TUNNEL_ENABLE
#define L2_VXLAN_ENABLE
#define VXLAN_ENABLE
//#define MPLS_ENABLE
#define TUNNEL_TTL_MODE_ENABLE
#define TUNNEL_QOS_MODE_ENABLE

// NAT
#define NAT_ENABLE

// SFLOW
#define INGRESS_SFLOW_ENABLE

#define PORT_ISOLATION_ENABLE

//#define USE_HASH_ACTION_FOR_EGRESS_BD

//#define BFD_OFFLOAD_ENABLE
//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------

// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 4K (port, vlan[0], vlan[1]) <--> BD
const bit<32> DOUBLE_TAG_TABLE_SIZE = 4096;

// 1K VRF
#define switch_vrf_width 10

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 16384;

// IP Hosts/Routes
#define ipv4_lpm_number_partitions 4096
#define ipv6_lpm64_number_partitions 4096
const bit<32> IPV4_HOST_TABLE_SIZE = 256 * 1024;
const bit<32> IPV4_LPM_TABLE_SIZE = 256 * 1024;
const bit<32> IPV6_HOST_TABLE_SIZE = 4 * 1024;
const bit<32> IPV6_HOST64_TABLE_SIZE = 256 * 1024;
const bit<32> IPV6_LPM_TABLE_SIZE = 512;
const bit<32> IPV6_LPM64_TABLE_SIZE = 256 * 1024;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> ECMP_SELECT_TABLE_SIZE = 65536;
#define switch_nexthop_width 16
const bit<32> NEXTHOP_TABLE_SIZE = 1 << switch_nexthop_width;
#define switch_tunnel_nexthop_width 16
const bit<32> TUNNEL_NEXTHOP_TABLE_SIZE = 32 * 1024;
//const bit<32> TUNNEL_NEXTHOP_TABLE_SIZE = 1 << switch_tunnel_nexthop_width;

// Tunnels
#define switch_tunnel_index_width 8
const bit<32> TUNNEL_OBJECT_SIZE = 1 << switch_tunnel_index_width;
#define switch_tunnel_ip_index_width 15
const bit<32> TUNNEL_ENCAP_IPV4_SIZE = 32 * 1024;
const bit<32> TUNNEL_ENCAP_IPV6_SIZE = 32 * 1024;
const bit<32> TUNNEL_ENCAP_IP_SIZE = TUNNEL_ENCAP_IPV4_SIZE + TUNNEL_ENCAP_IPV6_SIZE;
const bit<32> RID_TABLE_SIZE = 16384;

// Ingress ACLs
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 2 * 1024;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 1024;
const bit<32> INGRESS_IP_MIRROR_ACL_TABLE_SIZE = 1024;

// Egress ACL
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 1024;
const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV4_MIRROR_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV6_MIRROR_ACL_TABLE_SIZE = 512;

// NAT
const bit<32> FLOW_NAT_TABLE_SIZE = 4 * 1024;
const bit<32> FLOW_NAPT_TABLE_SIZE = 4 * 1024;
const bit<32> DNAPT_TABLE_SIZE = 32 * 1024;
const bit<32> DNAT_POOL_TABLE_SIZE = DNAPT_TABLE_SIZE;
const bit<32> DNAT_TABLE_SIZE = 4 * 1024;
const bit<32> INGRESS_NAT_REWRITE_TABLE_SIZE = 1024;
const bit<32> SNAPT_TABLE_SIZE = 32 * 1024;
const bit<32> SNAT_TABLE_SIZE = 4 * 1024;

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
#include "tunnel.p4"
#include "multicast.p4"
#include "qos.p4"
#include "meter.p4"
#include "wred.p4"
#include "acl.p4"
#include "nat.p4"
#include "bfd.p4"
#include "sflow.p4"

@pa_no_overlay("ingress", "local_md.learning.port_mode")
@pa_no_overlay("ingress", "smac_src_move")
@pa_container_size("ingress", "hdr.bridged_md.base_bypass_egress", 8)
@pa_no_overlay("egress", "local_md.checks.mtu")
@pa_container_type("ingress", "hdr.bridged_md.base_vrf", "normal")

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
    IngressTunnel() tunnel;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    EnableFragHash() enable_frag_hash;
    Ipv4Hash() ipv4_hash;
    Ipv6Hash() ipv6_hash;
    NonIpHash() non_ip_hash;
    Lagv4Hash() lagv4_hash;
    Lagv6Hash() lagv6_hash;
    LOU() lou;
    Fibv4(IPV4_HOST_TABLE_SIZE, IPV4_LPM_TABLE_SIZE) ipv4_fib;
    Fibv6(IPV6_HOST_TABLE_SIZE, IPV6_HOST64_TABLE_SIZE, IPV6_LPM_TABLE_SIZE, IPV6_LPM64_TABLE_SIZE) ipv6_fib;
//    PreIngressAcl(PRE_INGRESS_ACL_TABLE_SIZE) pre_ingress_acl;
    IngressIpv4Acl(INGRESS_IPV4_ACL_TABLE_SIZE) ingress_ipv4_acl;
    IngressIpv6Acl(INGRESS_IPV6_ACL_TABLE_SIZE) ingress_ipv6_acl;
    IngressIpAcl(INGRESS_IP_MIRROR_ACL_TABLE_SIZE) ingress_ip_mirror_acl;
    IngressMirrorMeter() ingress_mirror_meter;
    IngressQoSMap() qos_map;
    IngressTC() traffic_class;
    PPGStats() ppg_stats;
    IngressPFCWd(512) pfc_wd;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    OuterFib() outer_fib;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;
    IngressNat() ingress_nat;
    SourceNat() source_nat;
    IngressDestNatPool() ingress_dnat_pool;
    IngressNatRewrite() ingress_nat_rewrite;
//    BfdTxSession() bfd_tx_session;
//    BfdRxSession() bfd_rx_session;
//    BfdRxTimer() bfd_rx_timer;
//    BfdPktAction() bfd_pkt_action;
    IngressTosMirrorAcl() ingress_tos_mirror_acl;
    IngressSflow() sflow;
//    IngressPortStats() port_stats;

    apply {
        pkt_validation.apply(hdr, local_md);
        ingress_port_mapping.apply(hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        smac.apply(hdr.ethernet.src_addr, local_md, ig_intr_md_for_dprsr.digest_type);

//        if (hdr.bfd.isValid() && INGRESS_BYPASS(BFD_TX)) {
//	    bfd_tx_session.apply(hdr, local_md);
//	} else {
            tunnel.apply(hdr, local_md, local_md.lkp);
//	}
        lou.apply(local_md);

//	bfd_rx_session.apply(hdr, local_md, ig_intr_md_for_tm);
//	bfd_rx_timer.apply(local_md);

        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            ingress_dnat_pool.apply(local_md);
            ingress_ipv4_acl.apply(local_md, local_md.acl_nexthop);
            if(!INGRESS_BYPASS(NAT) && local_md.tunnel.terminate == false) {
              ingress_nat.apply(local_md);
              source_nat.apply(local_md);
            }
            if (!INGRESS_BYPASS(L3) && local_md.ipv4.unicast_enable && local_md.flags.rmac_hit) {
                ipv4_fib.apply(local_md);
            } else {
                dmac.apply(local_md.lkp.mac_dst_addr, local_md);
            }
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
            ingress_ipv6_acl.apply(local_md, local_md.acl_nexthop);
            if (!INGRESS_BYPASS(L3) && local_md.ipv6.unicast_enable && local_md.flags.rmac_hit) {
                ipv6_fib.apply(local_md);
            } else {
                dmac.apply(local_md.lkp.mac_dst_addr, local_md);
            }
        } else {
            if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV6) {
                ingress_ipv4_acl.apply(local_md, local_md.acl_nexthop);
            }
            if (local_md.lkp.ip_type != SWITCH_IP_TYPE_IPV4) {
                ingress_ipv6_acl.apply(local_md, local_md.acl_nexthop);
            }
            dmac.apply(local_md.lkp.mac_dst_addr, local_md);
        }

        ingress_ip_mirror_acl.apply(local_md, local_md.unused_nexthop);
        if(local_md.mirror.session_id == 0) {
          ingress_tos_mirror_acl.apply(local_md);
        }
        ingress_mirror_meter.apply(local_md);

        sflow.apply(local_md);
        bd_stats.apply(local_md.bd, local_md.lkp.pkt_type);

//	bfd_pkt_action.apply(local_md);

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
#ifdef MPLS_ENABLE
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_MPLS) {
            mpls_hash.apply(hdr, local_md.lkp, local_md.hash[31:0]);
#endif
        } else {
            ipv6_hash.apply(local_md.lkp, local_md.hash);
        }

        nexthop.apply(local_md);
        qos_map.apply(hdr, local_md);
        traffic_class.apply(local_md);
        ppg_stats.apply(local_md);
        outer_fib.apply(local_md);
        if (local_md.egress_port_lag_index == SWITCH_FLOOD) {
            flood.apply(local_md);
        } else {
            lag.apply(local_md, local_md.lag_hash, ig_intr_md_for_tm.ucast_egress_port);
        }

        pfc_wd.apply(local_md.ingress_port, local_md.qos.qid, local_md.flags.pfc_wd_drop);

        system_acl.apply(
            hdr, local_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);

//	port_stats.apply(hdr, local_md.ingress_port,
//	    ig_intr_md_for_dprsr.drop_ctl[0:0], ig_intr_md_for_tm.copy_to_cpu);


        add_bridged_md(hdr.bridged_md, local_md);
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
        if (local_md.mirror.src == SWITCH_PKT_SRC_CLONED_EGRESS) {
            copy_mirror_to_bridged_md(hdr.bridged_md, local_md);
        }
#endif

        if(local_md.nat.hit != SWITCH_NAT_HIT_NONE) {
          ingress_nat_rewrite.apply(hdr,local_md);
        }
        set_ig_intr_md(local_md, ig_intr_md_for_dprsr, ig_intr_md_for_tm);
#ifdef L2_VXLAN_ENABLE
        // Set L1_XID to a non-zero value for tunnel termination case
        if (local_md.tunnel.terminate) {
            ig_intr_md_for_tm.level1_exclusion_id = 16w1;
        }
#endif /* L2_VXLAN_ENABLE */
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
    EgressQoS() qos;
    EgressQueue() queue;
    EgressIpv4Acl(EGRESS_IPV4_ACL_TABLE_SIZE) egress_ipv4_acl;
    EgressIpv6Acl(EGRESS_IPV6_ACL_TABLE_SIZE) egress_ipv6_acl;
    EgressIpv4Acl(EGRESS_IPV4_MIRROR_ACL_TABLE_SIZE) egress_ipv4_mirror_acl;
    EgressIpv6Acl(EGRESS_IPV6_MIRROR_ACL_TABLE_SIZE) egress_ipv6_mirror_acl;
    EgressMirrorMeter() egress_mirror_meter;
    EgressSystemAcl() system_acl;
    EgressPFCWd(512) pfc_wd;
    EgressVRF() egress_vrf;
    EgressBD() egress_bd;
    OuterNexthop() outer_nexthop;
    EgressBDStats() egress_bd_stats;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    TunnelDecap() tunnel_decap;
    TunnelNexthop() tunnel_nexthop;
    TunnelEncap() tunnel_encap;
    TunnelRewrite() tunnel_rewrite;
    MTU() mtu;
    WRED() wred;
    EgressCpuRewrite() cpu_rewrite;
    EgressPortIsolation() port_isolation;
    Neighbor() neighbor;
    TunnelReplication() tunnel_replication;
    L2VniMap() l2_vni_map;
    SetEgIntrMd() set_eg_intr_md;
//    BfdTxTimer() bfd_tx_timer;
    EgressTosMirrorAcl() egress_tos_mirror_acl;


    apply {
        egress_port_mapping.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        tunnel_replication.apply(eg_intr_md, local_md);
//	bfd_tx_timer.apply(hdr, local_md, eg_intr_md_for_dprsr);
        if (local_md.pkt_src == SWITCH_PKT_SRC_BRIDGED) {
            port_mirror.apply(eg_intr_md.egress_port, local_md.mirror);
            if (local_md.tunnel.terminate) {
                tunnel_decap.apply(hdr, local_md);
            } else {
                vlan_decap.apply(hdr, local_md);
            }
            if (local_md.flags.routed) {
                egress_vrf.apply(hdr, local_md);
            } else {
                l2_vni_map.apply(hdr, local_md);
            }
            lou.apply(local_md);
            wred.apply(hdr, local_md, eg_intr_md, local_md.flags.wred_drop);
            qos.apply(hdr, eg_intr_md.egress_port, local_md);
            if (hdr.ipv4.isValid()) {
                egress_ipv4_acl.apply(hdr, local_md);
                egress_ipv4_mirror_acl.apply(hdr, local_md);
            } else if (hdr.ipv6.isValid()) {
                egress_ipv6_acl.apply(hdr, local_md);
                egress_ipv6_mirror_acl.apply(hdr, local_md);
            }
            if(local_md.mirror.session_id == 0) {
              egress_tos_mirror_acl.apply(hdr, local_md);
            }
            tunnel_nexthop.apply(hdr, local_md);
            outer_nexthop.apply(hdr, local_md);
            tunnel_encap.apply(hdr, local_md);
            egress_bd.apply(hdr, local_md);
            egress_mirror_meter.apply(local_md);
            tunnel_rewrite.apply(hdr, local_md);
            neighbor.apply(hdr, local_md);
        } else {
            mirror_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr);
        }
        egress_bd_stats.apply(hdr, local_md);
        mtu.apply(hdr, local_md);
        vlan_xlate.apply(hdr, local_md);
        pfc_wd.apply(eg_intr_md.egress_port, local_md.qos.qid, local_md.flags.pfc_wd_drop);
        port_isolation.apply(local_md, eg_intr_md);
        system_acl.apply(hdr, local_md, eg_intr_md, eg_intr_md_for_dprsr);
        cpu_rewrite.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        set_eg_intr_md.apply(hdr, local_md, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
        queue.apply(eg_intr_md.egress_port, local_md);
//	port_stats.apply(hdr, eg_intr_md.egress_port,
//	    eg_intr_md_for_dprsr.drop_ctl[0:0], 0b0);

    }
}

Pipeline <switch_header_t, switch_local_metadata_t, switch_header_t, switch_local_metadata_t> (SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;

Switch(pipe) main;
