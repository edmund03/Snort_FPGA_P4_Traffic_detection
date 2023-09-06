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


#ifndef _P4_L2_
#define _P4_L2_

//-----------------------------------------------------------------------------
// Spanning Tree Protocol
// @param local_md : Ingress metadata fields.
// @param stp_md : Spanning tree metadata.
// @param multiple_stp_enable : Allows to map a group of VLAN?s into a single spanning
// tree instance, for which spanning tree is applied independently.
// @param table_size : Size of the mstp table. Only used if multiple stp is enabled.
//
// @flag MULTIPLE_STP: Allows to map a group of VLAN?s into a single spanning
// tree instance, for which spanning tree is applied independently.
//-----------------------------------------------------------------------------
control IngressSTP(in switch_local_metadata_t local_md,
                   inout switch_stp_metadata_t stp_md)(
                   bool multiple_stp_enable=false,
                   switch_uint32_t table_size=4096) {
    // This register is used to check the stp state of the ingress port.
    // (bd << 7 | port) is used as the index to read the stp state. To save
    // resources, only 7-bit local port id is used to construct the indes.
    const bit<32> stp_state_size = 1 << 19;
    @name(".ingress_stp.stp")
    Register<bit<1>, bit<32>>(stp_state_size, 0) stp;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) hash;
    RegisterAction<bit<1>, bit<32>, bit<1>>(stp) stp_check = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
        }
    };

    @name(".ingress_stp.set_stp_state")
    action set_stp_state(switch_stp_state_t stp_state) {
        stp_md.state_ = stp_state;
    }

    @name(".ingress_stp.mstp")
    table mstp {
        key = {
            local_md.ingress_port : exact;
            stp_md.group: exact;
        }

        actions = {
            NoAction;
            set_stp_state;
        }

        size = table_size;
        const default_action = NoAction;
    }

    apply {
#ifdef STP_ENABLE
        if (!INGRESS_BYPASS(STP)) {
            if (multiple_stp_enable) {
                mstp.apply();
            } else {
                // First 4K BDs which are reserved for VLANs
                if (local_md.bd[15:12] == 0) {
                    stp_md.state_[0:0] = stp_check.execute(
                        hash.get({local_md.bd[11:0], local_md.ingress_port[6:0]}));
                }
            }
        }
#endif /* STP_ENABLE */
    }
}

//-----------------------------------------------------------------------------
// Spanning Tree Protocol
// @param local_md : Egress metadata fields.
// @param port : Egress port.
// @param stp_state : Spanning tree state.
//-----------------------------------------------------------------------------
control EgressSTP(in switch_local_metadata_t local_md, in switch_port_t port, out bool stp_state) {
    // This register is used to check the stp state of the egress port.
    // (bd << 7 | port) is used as the index to read the stp state. To save
    // resources, only 7-bit local port id is used to construct the index.
    @name(".egress_stp.stp")
    Register<bit<1>, bit<32>>(1 << 19, 0) stp;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) hash;
    RegisterAction<bit<1>, bit<32>, bit<1>>(stp) stp_check = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
        }
    };

    apply {
#ifdef STP_ENABLE
        if (!local_md.flags.bypass_egress) {
            // First 4K BDs which are reserved for VLANs
            if (local_md.bd[15:12] == 0) {
                bit<32> stp_hash_ = hash.get({local_md.bd[11:0], port[6:0]});
                stp_state = (bool) stp_check.execute(stp_hash_);
            }
        }
#endif /* STP_ENABLE */
    }
}


//-----------------------------------------------------------------------------
// Source MAC lookup
//
// @param src_addr : Source MAC address.
// @param local_md : Ingress metadata
// @param table_size : Size of SMAC table.
//
// MAC learning
// - Trigger a new MAC learn if MAC address is unknown.
// - Trigger a new MAC learn if MAC address is known but attached to a different interface.
//-----------------------------------------------------------------------------
control SMAC(in mac_addr_t src_addr,
             inout switch_local_metadata_t local_md,
             inout switch_digest_type_t digest_type)(
             switch_uint32_t table_size) {
    // local variables for MAC learning
    bool src_miss;
    switch_port_lag_index_t src_move;

    @name(".smac_miss")
    action smac_miss() { src_miss = true; }

    @name(".smac_hit")
    action smac_hit(switch_port_lag_index_t port_lag_index) {
        src_move = local_md.ingress_port_lag_index ^ port_lag_index;
    }

    @name(".smac") table smac {
        key = {
            local_md.bd : exact;
            src_addr : exact;
        }

        actions = {
            @defaultonly smac_miss;
            smac_hit;
        }

        const default_action = smac_miss;
        size = table_size;
        idle_timeout = true;
    }

    action notify() {
        digest_type = SWITCH_DIGEST_TYPE_MAC_LEARNING;
    }

    table learning {
        key = {
            src_miss : exact;
            src_move : ternary;
        }

        actions = {
            NoAction;
            notify;
        }

        const default_action = NoAction;
        const entries = {
            (true, _) : notify();
            (false, 0 &&& 0x3FF) : NoAction();
            (false, _) : notify();
        }
        size = MIN_TABLE_SIZE;
    }


    apply {
        if (!INGRESS_BYPASS(SMAC)) {
                smac.apply();
        }

        if (local_md.learning.bd_mode == SWITCH_LEARNING_MODE_LEARN &&
                local_md.learning.port_mode == SWITCH_LEARNING_MODE_LEARN) {
            learning.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Destination MAC lookup
//
// Performs a lookup on bd and destination MAC address.
// - Bridge out the packet of the interface in the MAC entry.
// - Flood the packet out of all ports within the ingress BD.
//
// @param dst_addr : destination MAC address.
// @param local_md : Ingess metadata
// @param ig_intr_md_for_tm
// @param table_size : Size of the dmac table.
//-----------------------------------------------------------------------------
control DMAC_t(in mac_addr_t dst_addr, inout switch_local_metadata_t local_md);

control DMAC(
        in mac_addr_t dst_addr, inout switch_local_metadata_t local_md)(switch_uint32_t table_size) {

    @name(".dmac_miss")
    action dmac_miss() {
        local_md.egress_port_lag_index = SWITCH_FLOOD;
        local_md.flags.dmac_miss = true;
    }

    @name(".dmac_hit")
    action dmac_hit(switch_port_lag_index_t port_lag_index) {
        local_md.egress_port_lag_index = port_lag_index;
        local_md.checks.same_if = local_md.ingress_port_lag_index ^ port_lag_index;
    }

#ifdef MULTICAST_ENABLE
    @name(".dmac_multicast")
    action dmac_multicast(switch_mgid_t index) {
        local_md.multicast.id = index;
    }
#endif /* MULTICAST_ENABLE */

    @name(".dmac_redirect")
    action dmac_redirect(switch_nexthop_t nexthop_index) {
        local_md.nexthop = nexthop_index;
    }

    
    @pack(2)
    @name(".dmac")
    table dmac {
        key = {
            local_md.bd : exact;
            dst_addr : exact;
        }

        actions = {
            dmac_miss;
            dmac_hit;
#ifdef MULTICAST_ENABLE
            dmac_multicast;
#endif /* MULTICAST_ENABLE */
            dmac_redirect;
        }

        const default_action = dmac_miss;
        size = table_size;
    }

    apply {
#ifdef ACL_REDIRECT_PORT_ENABLE
        if (!INGRESS_BYPASS(L2) && local_md.acl_port_redirect == false) {
#else
        if (!INGRESS_BYPASS(L2)) {
#endif
            dmac.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress BD (VLAN, RIF) Stats
//
//-----------------------------------------------------------------------------
control IngressBd(in switch_bd_t bd, in switch_pkt_type_t pkt_type)(switch_uint32_t table_size) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    // cannot give .count cuz of a bfrt issue
    @name(".ingress_bd_stats_count") action count() { stats.count(); }

    @name(".ingress_bd_stats")
    table bd_stats {
        key = {
            bd : exact;
            pkt_type : exact;
        }

        actions = {
            count;
            @defaultonly NoAction;
        }

        const default_action = NoAction;

        // 3 entries per bridge domain for unicast/broadcast/multicast packets.
        size = 3 * table_size;
        counters = stats;
    }

    apply {
        bd_stats.apply();
    }
}
//-----------------------------------------------------------------------------
// Egress BD Stats
//      -- Outer BD for encap cases
//
//-----------------------------------------------------------------------------
control EgressBDStats(inout switch_header_t hdr,
                 inout switch_local_metadata_t local_md) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".egress_bd_stats_count") action count() { stats.count(); }

    @name(".egress_bd_stats")
    table bd_stats {
        key = {
            local_md.bd[12:0] : exact;
            local_md.pkt_type : exact;
        }

        actions = {
            count;
            @defaultonly NoAction;
        }

        size = 3 * BD_TABLE_SIZE;
        counters = stats;
    }

    apply {
        if (local_md.pkt_src == SWITCH_PKT_SRC_BRIDGED) {
          bd_stats.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Egress BD Properties
//      -- Outer BD for encap cases
//
//-----------------------------------------------------------------------------
control EgressBD(inout switch_header_t hdr,
                 inout switch_local_metadata_t local_md) {

#ifdef EGRESS_ACL_BD_LABEL_ENABLE
    @name(".set_egress_bd_mapping")
    action set_bd_properties(mac_addr_t smac, switch_mtu_t mtu, switch_bd_label_t bd_label) {
        local_md.bd_label = bd_label;
#else
    @name(".set_egress_bd_mapping")
    action set_bd_properties(mac_addr_t smac, switch_mtu_t mtu) {
#endif // EGRESS_ACL_BD_LABEL_ENABLE
        hdr.ethernet.src_addr = smac;
        local_md.checks.mtu = mtu;
    }

#ifdef USE_HASH_ACTION_FOR_EGRESS_BD
    @use_hash_action(1)
#endif
    @name(".egress_bd_mapping")
    table bd_mapping {
        key = { local_md.bd[12:0] : exact; }
        actions = {
            set_bd_properties;
        }

#ifdef EGRESS_ACL_BD_LABEL_ENABLE
        const default_action = set_bd_properties(0, 0x3fff, 0);
#else
        const default_action = set_bd_properties(0, 0x3fff);
#endif // EGRESS_ACL_BD_LABEL_ENABLE
        
#ifdef USE_HASH_ACTION_FOR_EGRESS_BD
        size = 8192;
#else
        size = 5120;
#endif
    }

    apply {
        if (!local_md.flags.bypass_egress && local_md.flags.routed) {
            bd_mapping.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// VLAN tag decapsulation
// Removes the vlan tag by default or selectively based on the ingress port if QINQ_ENABLE flag
// is defined.
//
// @param hdr : Parsed headers.
// @param local_md : Egress metadata fields.
// @param port : Ingress port.
// @flag QINQ_ENABLE
//-----------------------------------------------------------------------------
control VlanDecap(inout switch_header_t hdr, inout switch_local_metadata_t local_md) {
    @name(".remove_vlan_tag")
    action remove_vlan_tag() {
        hdr.ethernet.ether_type = hdr.vlan_tag[0].ether_type;
        hdr.vlan_tag.pop_front(1);
    }

#ifdef QINQ_RIF_ENABLE
    @name(".remove_double_tag")
    action remove_double_tag() {
        hdr.ethernet.ether_type = hdr.vlan_tag[1].ether_type;
        hdr.vlan_tag.pop_front(2);
    }
#endif

    @name(".vlan_decap")
    table vlan_decap {
        key = {
#ifdef QINQ_ENABLE
            local_md.ingress_port : ternary @name("ingress_port");
#endif
            hdr.vlan_tag[0].isValid() : ternary;
#ifdef QINQ_RIF_ENABLE
            hdr.vlan_tag[1].isValid() : ternary;
#endif
        }

        actions = {
            NoAction;
            remove_vlan_tag;
#ifdef QINQ_RIF_ENABLE
            remove_double_tag;
#endif
        }

        const default_action = NoAction;
    }

    apply {
        if (!local_md.flags.bypass_egress) {
#if defined(QINQ_ENABLE) || defined(QINQ_RIF_ENABLE)
            vlan_decap.apply();
#else
            // Remove the vlan tag by default.
            if (hdr.vlan_tag[0].isValid()) {
                hdr.ethernet.ether_type = hdr.vlan_tag[0].ether_type;
                hdr.vlan_tag[0].setInvalid();
                local_md.pkt_length = local_md.pkt_length - 4;
            }
#endif
        }
    }
}

//-----------------------------------------------------------------------------
// Vlan translation
//
// @param hdr : Parsed headers.
// @param local_md : Egress metadata fields.
// @flag QINQ_ENABLE
//-----------------------------------------------------------------------------
control VlanXlate(inout switch_header_t hdr,
                  in switch_local_metadata_t local_md)(
                  switch_uint32_t bd_table_size,
                  switch_uint32_t port_bd_table_size) {
    @name(".set_vlan_untagged")
    action set_vlan_untagged() {
        //NoAction.
    }

#ifdef QINQ_RIF_ENABLE
    @name(".set_double_tagged")
    action set_double_tagged(vlan_id_t vid0, vlan_id_t vid1) {
        hdr.vlan_tag[0].setValid();
        hdr.vlan_tag[0].pcp = 0;
        hdr.vlan_tag[0].cfi = 0;
        hdr.vlan_tag[0].vid =  vid0;
        hdr.vlan_tag[0].ether_type = ETHERTYPE_VLAN;
        hdr.vlan_tag[1].setValid();
        hdr.vlan_tag[1].pcp = 0;
        hdr.vlan_tag[1].cfi = 0;
        hdr.vlan_tag[1].vid =  vid1;
        hdr.vlan_tag[1].ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_QINQ;
   }
#endif

    @name(".set_vlan_tagged")
    action set_vlan_tagged(vlan_id_t vid) {
#ifdef QINQ_ENABLE
        hdr.vlan_tag.push_front(1);
#else
        hdr.vlan_tag[0].setValid();
        hdr.vlan_tag[0].ether_type = hdr.ethernet.ether_type;
#endif
        hdr.vlan_tag[0].cfi = 0;
        hdr.vlan_tag[0].vid =  vid;
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
    }

    @name(".port_bd_to_vlan_mapping")
    table port_bd_to_vlan_mapping {
        key = {
            local_md.egress_port_lag_index : exact @name("port_lag_index");
            local_md.bd : exact @name("bd");
        }

        actions = {
            set_vlan_untagged;
            set_vlan_tagged;
#ifdef QINQ_RIF_ENABLE
            set_double_tagged;
#endif
        }

        const default_action = set_vlan_untagged;
        size = port_bd_table_size;
        //TODO : fix table size once scale requirements for double tag is known
    }

    @name(".bd_to_vlan_mapping")
    table bd_to_vlan_mapping {
        key = { local_md.bd : exact @name("bd"); }
        actions = {
            set_vlan_untagged;
            set_vlan_tagged;
        }

        const default_action = set_vlan_untagged;
        size = bd_table_size;
    }

#ifdef QINQ_ENABLE
    action set_type_vlan() {
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
    }

    action set_type_qinq() {
        hdr.ethernet.ether_type = ETHERTYPE_QINQ;
    }

    table set_ether_type {
        key = {
            hdr.vlan_tag[0].isValid() : exact;
            hdr.vlan_tag[1].isValid() : exact;
        }

        actions = {
            NoAction;
            set_type_vlan;
            set_type_qinq;
        }

        const default_action = NoAction;
        const entries = {
            (true, false) : set_type_vlan();
            (true, true) : set_type_qinq();
        }
    }
#endif /* QINQ_ENABLE */

    apply {
        if (!local_md.flags.bypass_egress) {
            if (!port_bd_to_vlan_mapping.apply().hit) {
                bd_to_vlan_mapping.apply();
            }

#ifdef QINQ_ENABLE
            set_ether_type.apply();
#endif
        }
    }
}

#endif /* _P4_L2_ */
