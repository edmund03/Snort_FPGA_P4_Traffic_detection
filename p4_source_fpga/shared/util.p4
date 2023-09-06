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


#include "types.p4"

// Bridged metadata fields for Egress pipeline.
action add_bridged_md(
        inout switch_bridged_metadata_h bridged_md, in switch_local_metadata_t local_md) {
    bridged_md.setValid();
    bridged_md.src = SWITCH_PKT_SRC_BRIDGED;
    bridged_md.base.ingress_port = local_md.ingress_port;
    bridged_md.base.ingress_port_lag_index = local_md.ingress_port_lag_index;
    bridged_md.base.ingress_bd = local_md.bd;
    bridged_md.base.nexthop = local_md.nexthop;
    bridged_md.base.pkt_type = local_md.lkp.pkt_type;
    bridged_md.base.routed = local_md.flags.routed;
    bridged_md.base.bypass_egress = local_md.flags.bypass_egress;
#if defined(PTP_ENABLE)
    bridged_md.base.capture_ts = local_md.flags.capture_ts;
#endif
#if defined(MLAG_ENABLE)
    bridged_md.base.peer_link = local_md.flags.peer_link;
#endif
    bridged_md.base.cpu_reason = local_md.cpu_reason;
    bridged_md.base.timestamp = local_md.timestamp;
    bridged_md.base.tc = local_md.qos.tc;
    bridged_md.base.qid = local_md.qos.qid;
    bridged_md.base.color = local_md.qos.color;
    bridged_md.base.vrf = local_md.vrf;

#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE)
    bridged_md.acl.l4_src_port = local_md.lkp.l4_src_port;
    bridged_md.acl.l4_dst_port = local_md.lkp.l4_dst_port;
#ifdef ACL_USER_META_ENABLE
    bridged_md.acl.user_metadata = local_md.user_metadata;
#endif // ACL_USER_META_ENABLE
#if defined(EGRESS_ACL_PORT_RANGE_ENABLE) && !defined(L4_PORT_EGRESS_LOU_ENABLE)
    bridged_md.acl.l4_src_port_label = local_md.l4_src_port_label;
    bridged_md.acl.l4_dst_port_label = local_md.l4_dst_port_label;
#endif // EGRESS_ACL_PORT_RANGE_ENABLE && !L4_PORT_EGRESS_LOU_ENABLE
    bridged_md.acl.tcp_flags = local_md.lkp.tcp_flags;
#elif defined(DTEL_FLOW_REPORT_ENABLE)
    bridged_md.acl.tcp_flags = local_md.lkp.tcp_flags;
#endif // EGRESS_IP_ACL_ENABLE || EGRESS_MIRROR_ACL_ENABLE

#ifdef TUNNEL_ENABLE
    bridged_md.tunnel.tunnel_nexthop = local_md.tunnel_nexthop;
#if defined(VXLAN_ENABLE) && !defined(DTEL_ENABLE)
    bridged_md.tunnel.hash = local_md.lag_hash[15:0];
#endif /* VXLAN_ENABLE && !DTEL_ENABLE */
#ifdef MPLS_ENABLE
    bridged_md.tunnel.mpls_pop_count = local_md.tunnel.mpls_pop_count;
#endif
#ifdef TUNNEL_TTL_MODE_ENABLE
    bridged_md.tunnel.ttl_mode = local_md.tunnel.ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
    bridged_md.tunnel.qos_mode = local_md.tunnel.qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
    bridged_md.tunnel.terminate = local_md.tunnel.terminate;
#endif

#ifdef DTEL_ENABLE
    bridged_md.dtel.report_type = local_md.dtel.report_type;
    bridged_md.dtel.session_id = local_md.dtel.session_id;
    bridged_md.dtel.hash = local_md.lag_hash;
    bridged_md.dtel.egress_port = local_md.egress_port;
#endif
#ifdef SFC_ENABLE
    bridged_md.sfc = {local_md.sfc.type,
                      local_md.sfc.queue_register_idx};
#endif
#ifdef BFD_OFFLOAD_ENABLE
    bridged_md.base.bfd_rx_recirc = local_md.bfd.rx_recirc;
#endif
}

action set_ig_intr_md(in switch_local_metadata_t local_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
                      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
    ig_intr_md_for_tm.mcast_grp_b = local_md.multicast.id;
// Set PRE hash values
    ig_intr_md_for_tm.level2_mcast_hash = local_md.lag_hash[28:16];
    ig_intr_md_for_tm.rid = local_md.bd;

#ifdef QOS_ENABLE
    ig_intr_md_for_tm.qid = local_md.qos.qid;
    ig_intr_md_for_tm.ingress_cos = local_md.qos.icos;
#endif
}

#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
action copy_mirror_to_bridged_md(
        inout switch_bridged_metadata_h bridged_md, inout switch_local_metadata_t local_md) {
    bridged_md.mirror.type = local_md.mirror.type;
    bridged_md.mirror.src = local_md.mirror.src;
    bridged_md.mirror.session_id = local_md.mirror.session_id;
    bridged_md.mirror.meter_index = local_md.mirror.meter_index;

    // reset local mirror type if mirror src is egress,
    // so that Ingress Mirror control block is skipped
    local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    // resetting below are not must, can ignore as well
    local_md.mirror.src = SWITCH_PKT_SRC_BRIDGED;
    local_md.mirror.session_id = 0;
    local_md.mirror.meter_index = 0;
}

#endif
control SetEgIntrMd(inout switch_header_t hdr,
                    in switch_local_metadata_t local_md,
                    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
                    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    apply {
#if __TARGET_TOFINO__ == 2
#if TOFINO2_PADDING_ENABLE
      if (local_md.pkt_src == SWITCH_PKT_SRC_BRIDGED) {
          if (local_md.pkt_length >= MIN_SIZE) {
              hdr.pad.setInvalid();
              /* Truncation will not be enabled */
          } else {
              /* Padding will be emitted (setValid() was done in the parser */
              eg_intr_md_for_dprsr.mtu_trunc_len = MIN_SIZE;
          }
      }
#endif /* TOFINO2_PADDING_ENABLE */
#endif /* __TARGET_TOFINO__ == 2 */

#ifdef PTP_ENABLE
        eg_intr_md_for_oport.capture_tstamp_on_tx = (bit<1>)local_md.flags.capture_ts;
#endif
#ifdef MIRROR_ENABLE
        if (local_md.mirror.type != SWITCH_MIRROR_TYPE_INVALID) {
#if __TARGET_TOFINO__ == 1
            eg_intr_md_for_dprsr.mirror_type = (bit<3>) local_md.mirror.type;
#else
            eg_intr_md_for_dprsr.mirror_type = (bit<4>) local_md.mirror.type;
            if (local_md.mirror.src == SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT) {
                eg_intr_md_for_dprsr.mirror_io_select = 0;
            } else {
                eg_intr_md_for_dprsr.mirror_io_select = 1;
            }
#endif
        }
#endif
    }
}

