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


#include "mirror_rewrite.p4"
#include "rmac.p4"

//-----------------------------------------------------------------------------
// Ingress port mirroring
//-----------------------------------------------------------------------------
control IngressPortMirror(
        in switch_port_t port,
        inout switch_mirror_metadata_t mirror_md)(
        switch_uint32_t table_size=288) {

    @name(".set_ingress_mirror_id")
    action set_ingress_mirror_id(switch_mirror_session_t session_id, switch_mirror_meter_id_t meter_index) {
        mirror_md.type = SWITCH_MIRROR_TYPE_PORT;
        mirror_md.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        mirror_md.session_id = session_id;
#ifdef MIRROR_METER_ENABLE
        mirror_md.meter_index = meter_index;
#endif
    }

    @name(".ingress_port_mirror")
    table ingress_port_mirror {
        key = { port : exact; }
        actions = {
            NoAction;
            set_ingress_mirror_id;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        ingress_port_mirror.apply();
    }
}

//-----------------------------------------------------------------------------
// Egress port mirroring
//-----------------------------------------------------------------------------
control EgressPortMirror(
        in switch_port_t port,
        inout switch_mirror_metadata_t mirror_md)(
        switch_uint32_t table_size=288) {

    @name(".set_egress_mirror_id")
    action set_egress_mirror_id(switch_mirror_session_t session_id, switch_mirror_meter_id_t meter_index) {
        mirror_md.type = SWITCH_MIRROR_TYPE_PORT;
        mirror_md.src = SWITCH_PKT_SRC_CLONED_EGRESS;
        mirror_md.session_id = session_id;
#ifdef MIRROR_METER_ENABLE
        mirror_md.meter_index = meter_index;
#endif
    }

    @name(".egress_port_mirror")
    table egress_port_mirror {
        key = { port : exact; }
        actions = {
            NoAction;
            set_egress_mirror_id;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        egress_port_mirror.apply();
    }
}

control IngressPortMapping(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr)(
        switch_uint32_t port_vlan_table_size,
        switch_uint32_t bd_table_size,
        switch_uint32_t port_table_size=288,
        switch_uint32_t vlan_table_size=4096,
        switch_uint32_t double_tag_table_size=1024) {

    //IngressPortMirror(port_table_size) port_mirror;
    IngressRmac(port_vlan_table_size, vlan_table_size) rmac;
    @name(".bd_action_profile")
    ActionProfile(bd_table_size) bd_action_profile;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) hash;

    // This register is used to check whether a port is a mermber of a vlan (bd)
    // or not. (port << 12 | vid) is used as the index to read the membership
    // status.To save resources, only 7-bit local port id is used to calculate
    // the indes.
    const bit<32> vlan_membership_size = 1 << 19;
    @name(".vlan_membership")
    Register<bit<1>, bit<32>>(vlan_membership_size, 0) vlan_membership;
    RegisterAction<bit<1>, bit<32>, bit<1>>(vlan_membership) check_vlan_membership = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = ~val;
        }
    };

    action terminate_cpu_packet() {
        local_md.ingress_port = (switch_port_t) hdr.cpu.ingress_port;
        local_md.egress_port_lag_index =
            (switch_port_lag_index_t) hdr.cpu.port_lag_index;
        ig_intr_md_for_tm.qid = (switch_qid_t) hdr.cpu.egress_queue;
        local_md.flags.bypass_egress = (bool) hdr.cpu.tx_bypass;
        hdr.ethernet.ether_type = hdr.cpu.ether_type;
    }

    @name(".set_cpu_port_properties")
    action set_cpu_port_properties(
            switch_port_lag_index_t port_lag_index,
            switch_ig_port_lag_label_t port_lag_label,
            switch_yid_t exclusion_id,
            switch_qos_trust_mode_t trust_mode,
            switch_qos_group_t qos_group,
            switch_pkt_color_t color,
            switch_tc_t tc) {
        local_md.ingress_port_lag_index = port_lag_index;
        local_md.ingress_port_lag_label = port_lag_label;
        local_md.qos.trust_mode = trust_mode;
        local_md.qos.group = qos_group;
        local_md.qos.color = color;
        local_md.qos.tc = tc;
        ig_intr_md_for_tm.level2_exclusion_id = exclusion_id;

        terminate_cpu_packet();
    }

    @name(".set_port_properties")
    action set_port_properties(
            switch_yid_t exclusion_id,
            switch_learning_mode_t learning_mode,
            switch_qos_trust_mode_t trust_mode,
            switch_qos_group_t qos_group,
            switch_pkt_color_t color,
            switch_tc_t tc,
            switch_meter_index_t meter_index,
            switch_sflow_id_t sflow_session_id,
            bool mac_pkt_class) {
        local_md.qos.trust_mode = trust_mode;
        local_md.qos.group = qos_group;
        local_md.qos.color = color;
        local_md.qos.tc = tc;
        ig_intr_md_for_tm.level2_exclusion_id = exclusion_id;
        local_md.learning.port_mode = learning_mode;
        local_md.checks.same_if = SWITCH_FLOOD;
        local_md.flags.mac_pkt_class = mac_pkt_class;
#if defined(INGRESS_PORT_METER_ENABLE)
        local_md.qos.port_meter_index = meter_index;
#endif /* INGRESS_PORT_METER_ENABLE */
#if defined(INGRESS_SFLOW_ENABLE)
        local_md.sflow.session_id = sflow_session_id;
#endif
    }

    @placement_priority(2)
    @name(".ingress_port_mapping")
    table port_mapping {
        key = {
            local_md.ingress_port : exact;
#ifdef CPU_BD_MAP_ENABLE
            hdr.cpu.isValid() : exact;
            hdr.cpu.ingress_port : exact;
#endif
        }

        actions = {
            set_port_properties;
            set_cpu_port_properties;
        }

#ifdef CPU_BD_MAP_ENABLE
        size = port_table_size * 2;
#else
        size = port_table_size;
#endif
    }

    @name(".port_vlan_miss")
    action port_vlan_miss() {
        //local_md.flags.port_vlan_miss = true;
    }

    @name(".set_bd_properties")
    action set_bd_properties(switch_bd_t bd,
                             switch_vrf_t vrf,
                             switch_bd_label_t bd_label,
                             switch_stp_group_t stp_group,
                             switch_learning_mode_t learning_mode,
                             bool ipv4_unicast_enable,
                             bool ipv4_multicast_enable,
                             bool igmp_snooping_enable,
                             bool ipv6_unicast_enable,
                             bool ipv6_multicast_enable,
                             bool mld_snooping_enable,
                             bool mpls_enable,
                             switch_multicast_rpf_group_t mrpf_group,
                             switch_nat_zone_t zone) {
        local_md.bd = bd;
        local_md.ingress_outer_bd = bd;
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
        local_md.bd_label = bd_label;
#endif
        local_md.vrf = vrf;
        local_md.stp.group = stp_group;
        local_md.multicast.rpf_group = mrpf_group;
        local_md.learning.bd_mode = learning_mode;
        local_md.ipv4.unicast_enable = ipv4_unicast_enable;
        local_md.ipv4.multicast_enable = ipv4_multicast_enable;
        local_md.ipv4.multicast_snooping = igmp_snooping_enable;
        local_md.ipv6.unicast_enable = ipv6_unicast_enable;
        local_md.ipv6.multicast_enable = ipv6_multicast_enable;
        local_md.ipv6.multicast_snooping = mld_snooping_enable;
#ifdef MPLS_ENABLE
        local_md.mpls_enable = mpls_enable;
#endif
#ifdef NAT_ENABLE
        local_md.nat.ingress_zone = zone;
#endif
    }


#ifdef QINQ_RIF_ENABLE
    // (port, vlan[0], vlan[1]) --> bd mapping
    @name(".port_double_tag_to_bd_mapping")
    table port_double_tag_to_bd_mapping {
        key = {
            local_md.ingress_port_lag_index : exact;
            hdr.vlan_tag[0].isValid() : exact;
            hdr.vlan_tag[0].vid : exact;
            hdr.vlan_tag[1].isValid() : exact;
            hdr.vlan_tag[1].vid : exact;
        }

        actions = {
            NoAction;
            port_vlan_miss;
            set_bd_properties;
        }

        const default_action = NoAction;
        implementation = bd_action_profile;
        size = double_tag_table_size;
    }
#endif /* QINQ_RIF_ENABLE */

    // (port, vlan) --> bd mapping -- Following set of entres are needed:
    //   (port, 0, *)    L3 interface.
    //   (port, 1, vlan) L3 sub-interface.
    //   (port, 0, *)    Access port + untagged packet.
    //   (port, 1, vlan) Access port + packets tagged with access-vlan.
    //   (port, 1, 0)    Access port + .1p tagged packets.
    //   (port, 1, vlan) L2 sub-port.
    //   (port, 0, *)    Trunk port if native-vlan is not tagged.

    @placement_priority(2)
    @name(".port_vlan_to_bd_mapping")
    table port_vlan_to_bd_mapping {
        key = {
            local_md.ingress_port_lag_index : ternary;
            hdr.vlan_tag[0].isValid() : ternary;
            hdr.vlan_tag[0].vid : ternary;
        }

        actions = {
            NoAction;
            port_vlan_miss;
            set_bd_properties;
        }

        const default_action = NoAction;
        implementation = bd_action_profile;
        size = port_vlan_table_size;
    }

    // (*, vlan) --> bd mapping
    @placement_priority(2)
    @name(".vlan_to_bd_mapping")
    table vlan_to_bd_mapping {
        key = {
            hdr.vlan_tag[0].vid : exact;
        }

        actions = {
            NoAction;
            port_vlan_miss;
            set_bd_properties;
        }

        const default_action = port_vlan_miss;
        implementation = bd_action_profile;
        size = vlan_table_size;
    }

    @name(".cpu_to_bd_mapping")
    table cpu_to_bd_mapping {
        key = { hdr.cpu.ingress_bd : exact; }

        actions = {
            NoAction;
            port_vlan_miss;
            set_bd_properties;
        }

        const default_action = port_vlan_miss;
        implementation = bd_action_profile;
        size = bd_table_size;
    }

    @name(".set_peer_link_properties")
    action set_peer_link_properties() {
        local_md.flags.peer_link = true;
    }

    @name(".peer_link")
    table peer_link {
        key = { local_md.ingress_port_lag_index : exact; }
        actions = {
            NoAction;
            set_peer_link_properties;
        }

        const default_action = NoAction;
        size = port_table_size;
    }


    apply {
#ifdef INGRESS_PORT_MIRROR_ENABLE
        port_mirror.apply(local_md.ingress_port, local_md.mirror);
#endif
        switch (port_mapping.apply().action_run) {
#ifdef CPU_BD_MAP_ENABLE
            set_cpu_port_properties : {
                cpu_to_bd_mapping.apply();
            }
#endif

            set_port_properties : {
#ifdef QINQ_RIF_ENABLE
                if (!port_double_tag_to_bd_mapping.apply().hit) {
#endif
                    if (!port_vlan_to_bd_mapping.apply().hit) {
                        if (hdr.vlan_tag[0].isValid())
                            vlan_to_bd_mapping.apply();
                    }
#ifdef QINQ_RIF_ENABLE
                }
#endif
#ifdef SUBMIT_TO_INGRESS_ENABLE
                // Router MAC Check
                if (!INGRESS_BYPASS(ROUTING_CHECK)) {
                    rmac.apply(hdr, local_md);
                }
#else
                rmac.apply(hdr, local_md);
#endif /* SUBMIT_TO_INGRESS_ENABLE */
          }
        }

        // Check vlan membership
        if (hdr.vlan_tag[0].isValid() && !hdr.vlan_tag[1].isValid() && (bit<1>) local_md.flags.port_vlan_miss == 0) {
            bit<32> pv_hash_ = hash.get({local_md.ingress_port[6:0], hdr.vlan_tag[0].vid});
            local_md.flags.port_vlan_miss =
                (bool)check_vlan_membership.execute(pv_hash_);
        }

#ifdef MLAG_ENABLE
        peer_link.apply();
#endif
    }
}

#define SNAKE                                      \
    @name(".set_egress_port")                      \
    action set_egress_port(switch_port_t port) {   \
        ig_intr_md_for_tm.ucast_egress_port = port;\
    }                                              \
                                                   \
    @name(".snake")                                \
    table snake {                                  \
        key = { local_md.ingress_port : exact; }   \
        actions = { set_egress_port; }             \
        size = SNAKE_TABLE_SIZE;                   \
    }

/* programming notes:
 *  - Program one set of entry for every local port on the pipe
 *  - I/G bit is bit 40 of eth.dst_addr.
 *  - Entries are in decreasing order of priority
 *  - ipv4 received = discards + non_uc + uc
 *  - ipv6 received = discards + bc + mc + uc
 *  - ipv6 non_uc = bc + mc

 *  { is_ipv4, is_ipv6, drop, copy_to_cpu, eth.dst_addr } = counter_name
 *  {  true, false,  true, false, X        } = ipv4 discards
 *  {  true, false, false,     X, ig_bit=1 } = ipv4 non_uc
 *  {  true, false, false,     X, ig_bit=0 } = ipv4 uc

 *  { false,  true,  true, false, X        } = ipv6 discards
 *  { false,  true, false,     X, all_1s   } = ipv6 bc
 *  { false,  true, false,     X, ig_bit=1 } = ipv6 mc
 *  { false,  true, false,     X,        X } = ipv6 uc
 */

//---------------------------------------------------------------------------------------------------------
// Ingress Port IP statistics
//---------------------------------------------------------------------------------------------------------
control IngressPortStats(
    in switch_header_t hdr,
    in switch_port_t port,
    in bit<1> drop, in bit<1> copy_to_cpu) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".ingress_ip_stats_count")
    action no_action() {
        stats.count();
    }

    @name(".ingress_ip_port_stats")
    table ingress_ip_port_stats {
        key = {
            port : exact;
            hdr.ipv4.isValid() : ternary;
            hdr.ipv6.isValid() : ternary;
            drop : ternary;
            copy_to_cpu : ternary;
            hdr.ethernet.dst_addr : ternary;
        }
        actions = { no_action; }
        const default_action = no_action;
        size = 512;
        counters = stats;
    }

    apply {
        ingress_ip_port_stats.apply();
    }
}

//---------------------------------------------------------------------------------------------------------
// Egress Port IP statistics
//---------------------------------------------------------------------------------------------------------
control EgressPortStats(
    in switch_header_t hdr,
    in switch_port_t port,
    in bit<1> drop, in bit<1> copy_to_cpu) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".egress_ip_stats_count")
    action no_action() {
        stats.count();
    }

    @name(".egress_ip_port_stats")
    table egress_ip_port_stats {
        key = {
            port : exact;
            hdr.ipv4.isValid() : ternary;
            hdr.ipv6.isValid() : ternary;
            drop : ternary;
            copy_to_cpu : ternary;
            hdr.ethernet.dst_addr : ternary;
        }
        actions = { no_action; }
        const default_action = no_action;
        size = 512;
        counters = stats;
    }

    apply {
        egress_ip_port_stats.apply();
    }
}

// --------------------------------------------------------------------------------------------------------
// Fold - Use below table to 2-fold, 4-fold or arbitary-fold switch pipeline
//
// Pipeline folding involves sending packets from
// ingress pipeline X -> egress pipeline Y -> ingress pipeline Y -> egress pipeline Z ..
//
// To achieve above forwarding behavior two things are needed
// 1. Ability to send Packet from Port x in ingress pipeline X to Port y in egress pipeline Y
// 2. Ability to loopback packet on egress pipeline Y port y to ingress pipeline Y port y
//
// The below table helps achievethe first of these two tasks.
// Specifically it allows for below behavior
// fold_4_pipe:
// ===========
// On a 4-pipe system 1:1 (same port on ingress/egress pipes) forwarding across pipe <N=X> -> Pipe <N=X+1>,
// where N > 0 and N < 4. The value of N wraps around so N goes from 0,1,2,3 -> 0
//
// fold_2_pipe:
// ===========
// On a 2-pipe system 1:1 forwarding across pipe <N=X> -> Pipe <N=X+1>,
// where N > 0 and N < 2. The value of N wraps around so N goes from 0,1 -> 0
//
// set_egress_port: Arbitary/User defined forwarding/folding
// ===============
// Match on any incoming ingress port and send packet to user defined egress Pipe/Port
//
// The Fold table should be added at the end of Switching Ingress Pipeline to override port forwarding
// ---------------------------------------------------------------------------------------------------------

#define FOLD                                                                                \
    action fold_4_pipe() {                                                                  \
        ig_intr_md_for_tm.ucast_egress_port = (ig_intr_md.ingress_port + 0x80);             \
    }                                                                                       \
                                                                                            \
    action fold_2_pipe() {                                                                  \
        ig_intr_md_for_tm.ucast_egress_port = (ig_intr_md.ingress_port ^ 0x80);             \
    }                                                                                       \
                                                                                            \
    action set_egress_port(switch_port_t dev_port) {                                        \
        ig_intr_md_for_tm.ucast_egress_port = dev_port;                                     \
    }                                                                                       \
                                                                                            \
    table fold {                                                                            \
        key = { ig_intr_md.ingress_port : exact; }                                          \
        actions = {                                                                         \
                    fold_2_pipe;                                                            \
                    fold_4_pipe;                                                            \
                    set_egress_port;                                                        \
                    }                                                                       \
        size = MIN_TABLE_SIZE;                                                              \
        default_action = fold_4_pipe;                                                       \
    }

// ----------------------------------------------------------------------------
// Link Aggregation (LAG) resolution
//
// @param local_md : Ingress metadata fields.
// @param hash : Hash value used for port selection.
// @param egress_port : Egress port.
//
// @flag MLAG_ENABLE : Enable multi-chassis LAG.
// ----------------------------------------------------------------------------

control LAG(inout switch_local_metadata_t local_md,
            in switch_hash_t hash,
            out switch_port_t egress_port) {

#ifdef SHARED_ECMP_LAG_HASH_CALCULATION
    Hash<switch_uint16_t>(HashAlgorithm_t.IDENTITY) selector_hash;
#else
    Hash<switch_uint16_t>(HashAlgorithm_t.CRC16) selector_hash;
#endif
    @name(".lag_action_profile")
    ActionProfile(LAG_SELECTOR_TABLE_SIZE) lag_action_profile;
    @name(".lag_selector")
    ActionSelector(lag_action_profile,
                   selector_hash,
                   SelectorMode_t.FAIR,
                   LAG_MAX_MEMBERS_PER_GROUP,
                   LAG_GROUP_TABLE_SIZE) lag_selector;

    @name(".set_lag_port")
    action set_lag_port(switch_port_t port) {
        egress_port = port;
    }

    @name(".set_peer_link_port")
    action set_peer_link_port(switch_port_t port, switch_port_lag_index_t port_lag_index) {
        egress_port = port;
        local_md.egress_port_lag_index = port_lag_index;
        local_md.checks.same_if = local_md.ingress_port_lag_index ^ port_lag_index;
    }

    @name(".lag_miss")
    action lag_miss() { }

    @name(".lag")
    table lag {
        key = {
#ifdef MLAG_ENABLE
            local_md.egress_port_lag_index : ternary @name("port_lag_index");
#else
            local_md.egress_port_lag_index : exact @name("port_lag_index");
#endif
            hash : selector;
        }

        actions = {
            lag_miss;
            set_lag_port;
#ifdef MLAG_ENABLE
            set_peer_link_port;
#endif
        }

        const default_action = lag_miss;
        size = LAG_TABLE_SIZE;
        implementation = lag_selector;
    }

    apply {
        lag.apply();
    }
}

//-----------------------------------------------------------------------------
// Egress port lookup
//
// @param hdr : Parsed headers.
// @param local_md : Egress metadata fields.
// @param port : Egress port.
//
//-----------------------------------------------------------------------------
control EgressPortMapping(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        in switch_port_t port)(
        switch_uint32_t table_size=288) {

    @name(".set_port_normal")
    action set_port_normal(switch_port_lag_index_t port_lag_index,
                           switch_eg_port_lag_label_t port_lag_label,
                           switch_qos_group_t qos_group,
                           switch_meter_index_t meter_index,
                           switch_sflow_id_t sflow_session_id,
                           bool mlag_member,
                           switch_eg_port_lag_label_t acl_out_ports) {
        local_md.egress_port_lag_index = port_lag_index;
        local_md.egress_port_lag_label = port_lag_label;
        local_md.qos.group = qos_group;
#ifdef MLAG_ENABLE
        local_md.flags.mlag_member = mlag_member;
#endif
#if defined(EGRESS_PORT_METER_ENABLE)
        local_md.qos.port_meter_index = meter_index;
#endif /* EGRESS_PORT_METER_ENABLE */
#if defined(EGRESS_SFLOW_ENABLE)
        local_md.sflow.session_id = sflow_session_id;
#endif
#ifdef OUT_PORTS_IN_ACL_KEY_ENABLE
        local_md.out_ports_group_label = acl_out_ports;
#endif
    }

    @name(".egress_port_mapping")
    table port_mapping {
        key = { port : exact; }

        actions = {
            set_port_normal;
        }

        size = table_size;
    }

#ifdef PORT_ISOLATION_ENABLE
    @name(".set_egress_ingress_port_properties")
    action set_egress_ingress_port_properties(switch_isolation_group_t port_isolation_group, switch_isolation_group_t bport_isolation_group) {
        local_md.port_isolation_group = port_isolation_group;
        local_md.bport_isolation_group = bport_isolation_group;
    }

    @name(".egress_ingress_port_mapping")
    table egress_ingress_port_mapping {
        key = {
            local_md.ingress_port : exact;
        }

        actions = {
            NoAction;
            set_egress_ingress_port_properties;
        }

        const default_action = NoAction;
        size = table_size;
    }
#endif

    apply {
        port_mapping.apply();

#ifdef PORT_ISOLATION_ENABLE
        egress_ingress_port_mapping.apply();
#endif
    }
}

#ifdef PORT_ISOLATION_ENABLE
//-----------------------------------------------------------------------------
// Egress port isolation
//
// @param hdr : Parsed headers.
// @param local_md : Egress metadata fields.
// @param port : Egress port.
//
//-----------------------------------------------------------------------------
control EgressPortIsolation(
        inout switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_t eg_intr_md)(
        switch_uint32_t table_size=288) {

    @name(".isolate_packet_port")
    action isolate_packet_port() {
        local_md.flags.port_isolation_packet_drop = true;
    }

    @name(".egress_port_isolation")
    table egress_port_isolation {
        key = {
            eg_intr_md.egress_port : exact;
            local_md.port_isolation_group : exact;
        }

        actions = {
            NoAction;
            isolate_packet_port;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @name(".isolate_packet_bport")
    action isolate_packet_bport() {
        local_md.flags.bport_isolation_packet_drop = true;
    }

    @name(".egress_bport_isolation")
    table egress_bport_isolation {
        key = {
            eg_intr_md.egress_port : exact;
            local_md.flags.routed : exact;
            local_md.bport_isolation_group : exact;
        }

        actions = {
            NoAction;
            isolate_packet_bport;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        egress_port_isolation.apply();
        egress_bport_isolation.apply();
    }
}
#endif

//-----------------------------------------------------------------------------
// CPU-RX Header Insertion
//-----------------------------------------------------------------------------
control EgressCpuRewrite(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        in switch_port_t port)(
        switch_uint32_t table_size=288) {

    @name(".cpu_rewrite")
    action cpu_rewrite() {
        hdr.fabric.setValid();
        hdr.fabric.reserved = 0;
        hdr.fabric.color = 0;
        hdr.fabric.qos = 0;
        hdr.fabric.reserved2 = 0;

        hdr.cpu.setValid();
        hdr.cpu.egress_queue = 0;
        hdr.cpu.tx_bypass = 0;
        hdr.cpu.capture_ts = 0;
        hdr.cpu.reserved = 0;
        hdr.cpu.ingress_port = (bit<16>) local_md.ingress_port;
        hdr.cpu.port_lag_index = (bit<16>) local_md.egress_port_lag_index;
        hdr.cpu.ingress_bd = (bit<16>) local_md.bd;
        hdr.cpu.reason_code = local_md.cpu_reason;
        hdr.cpu.ether_type = hdr.ethernet.ether_type;

        hdr.ethernet.ether_type = ETHERTYPE_BFN;
    }

    @name(".cpu_port_rewrite")
    table cpu_port_rewrite {
        key = { port : exact; }

        actions = {
            cpu_rewrite;
        }

        size = table_size;
    }

    apply {
        cpu_port_rewrite.apply();
    }
}
