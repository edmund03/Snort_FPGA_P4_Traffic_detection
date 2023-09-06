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


#ifndef _P4_MULTICAST_
#define _P4_MULTICAST_

#ifdef MULTICAST_ENABLE
//-----------------------------------------------------------------------------
// IP Multicast
// @param src_addr : IP source address.
// @param grp_addr : IP group address.
// @param bd : Bridge domain.
// @param group_id : Multicast group id.
// @param s_g_table_size : (s, g) table size.
// @param star_g_table_size : (*, g) table size.
//-----------------------------------------------------------------------------
control MulticastBridge<T>(
        in ipv4_addr_t src_addr,
        in ipv4_addr_t grp_addr,
        in switch_bd_t bd,
        out switch_mgid_t group_id,
        out bit<1> multicast_hit)(
        switch_uint32_t s_g_table_size,
        switch_uint32_t star_g_table_size) {
    @name(".multicast_bridge_s_g_hit")
    action s_g_hit(switch_mgid_t mgid) {
        group_id = mgid;
        multicast_hit = 1;
    }

    @name(".multicast_bridge_star_g_hit")
    action star_g_hit(switch_mgid_t mgid) {
        group_id = mgid;
        multicast_hit = 1;
    }

    action star_g_miss() {
        multicast_hit = 0;
    }

    @name(".multicast_bridge_s_g")
    table s_g {
        key =  {
            bd : exact;
            src_addr : exact;
            grp_addr : exact;
        }

        actions = {
            NoAction;
            s_g_hit;
        }

        const default_action = NoAction;
        size = s_g_table_size;
    }

    @name(".multicast_bridge_star_g")
    table star_g {
        key = {
            bd : exact;
            grp_addr : exact;
        }

        actions = {
            star_g_miss;
            star_g_hit;
        }

        const default_action = star_g_miss;
        size = star_g_table_size;
    }

    apply {
#ifdef MULTICAST_ENABLE
        switch(s_g.apply().action_run) {
            NoAction : { star_g.apply(); }
        }
#endif
    }
}

control MulticastBridgev6<T>(
        in ipv6_addr_t src_addr,
        in ipv6_addr_t grp_addr,
        in switch_bd_t bd,
        out switch_mgid_t group_id,
        out bit<1> multicast_hit)(
        switch_uint32_t s_g_table_size,
        switch_uint32_t star_g_table_size) {
    action s_g_hit(switch_mgid_t mgid) {
        group_id = mgid;
        multicast_hit = 1;
    }

    action star_g_hit(switch_mgid_t mgid) {
        group_id = mgid;
        multicast_hit = 1;
    }

    action star_g_miss() {
        multicast_hit = 0;
    }

    table s_g {
        key =  {
            bd : exact;
            src_addr : exact;
            grp_addr : exact;
        }

        actions = {
            NoAction;
            s_g_hit;
        }

        const default_action = NoAction;
        size = s_g_table_size;
    }

    table star_g {
        key = {
            bd : exact;
            grp_addr : exact;
        }

        actions = {
            star_g_miss;
            star_g_hit;
        }

        const default_action = star_g_miss;
        size = star_g_table_size;
    }

    apply {
#ifdef MULTICAST_ENABLE
        switch(s_g.apply().action_run) {
            NoAction : { star_g.apply(); }
        }
#endif
    }
}

control MulticastRoute<T>(
        in ipv4_addr_t src_addr,
        in ipv4_addr_t grp_addr,
        in switch_vrf_t vrf,
        inout switch_multicast_metadata_t multicast_md,
        out switch_multicast_rpf_group_t rpf_check,
        out switch_mgid_t multicast_group_id,
        out bit<1> multicast_hit)(
        switch_uint32_t s_g_table_size,
        switch_uint32_t star_g_table_size) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) s_g_stats;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) star_g_stats;

    @name(".multicast_route_s_g_hit")
    action s_g_hit(
            switch_mgid_t mgid, switch_multicast_rpf_group_t  rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        rpf_check = rpf_group ^ multicast_md.rpf_group;
        multicast_md.mode = SWITCH_MULTICAST_MODE_PIM_SM;
        s_g_stats.count();
    }

    @name(".multicast_route_star_g_hit_bidir")
    action star_g_hit_bidir(
            switch_mgid_t mgid, switch_multicast_rpf_group_t rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        // rpf check passes if rpf_check != 0
        rpf_check = rpf_group & multicast_md.rpf_group;
        multicast_md.mode = SWITCH_MULTICAST_MODE_PIM_BIDIR;
        star_g_stats.count();
    }

    @name(".multicast_route_star_g_hit_sm")
    action star_g_hit_sm(
            switch_mgid_t mgid, switch_multicast_rpf_group_t rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        // rpf check passes if rpf_check == 0
        rpf_check = rpf_group ^ multicast_md.rpf_group;
        multicast_md.mode = SWITCH_MULTICAST_MODE_PIM_SM;
        star_g_stats.count();
    }

    // Source and Group address pair (S, G) lookup
    @name(".multicast_route_s_g")
    table s_g {
        key =  {
            vrf : exact;
            src_addr : exact;
            grp_addr : exact;
        }

        actions = {
            @defaultonly NoAction;
            s_g_hit;
        }

        const default_action = NoAction;
        size = s_g_table_size;
        counters = s_g_stats;
    }

    // Group address (*, G) lookup
    @name(".multicast_route_star_g")
    table star_g {
        key = {
            vrf : exact;
            grp_addr : exact;
        }

        actions = {
            @defaultonly NoAction;
            star_g_hit_sm;
            star_g_hit_bidir;
        }

        const default_action = NoAction;
        size = star_g_table_size;
        counters = star_g_stats;
    }

    apply {
#ifdef MULTICAST_ENABLE
        if (!s_g.apply().hit) {
            star_g.apply();
        }
#endif
    }
}


control MulticastRoutev6<T>(
        in ipv6_addr_t src_addr,
        in ipv6_addr_t grp_addr,
        in switch_vrf_t vrf,
        inout switch_multicast_metadata_t multicast_md,
        out switch_multicast_rpf_group_t rpf_check,
        out switch_mgid_t multicast_group_id,
        out bit<1> multicast_hit)(
        switch_uint32_t s_g_table_size,
        switch_uint32_t star_g_table_size) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) s_g_stats;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) star_g_stats;

    action s_g_hit(
            switch_mgid_t mgid, switch_multicast_rpf_group_t  rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        rpf_check = rpf_group ^ multicast_md.rpf_group;
        s_g_stats.count();
    }

    action star_g_hit_bidir(
            switch_mgid_t mgid, switch_multicast_rpf_group_t rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        // rpf check passes if rpf_check != 0
        rpf_check = rpf_group & multicast_md.rpf_group;
        multicast_md.mode = SWITCH_MULTICAST_MODE_PIM_BIDIR;
        star_g_stats.count();
    }

    action star_g_hit_sm(
            switch_mgid_t mgid, switch_multicast_rpf_group_t rpf_group) {
        multicast_group_id = mgid;
        multicast_hit = 1;
        // rpf check passes if rpf_check == 0
        rpf_check = rpf_group ^ multicast_md.rpf_group;
        multicast_md.mode = SWITCH_MULTICAST_MODE_PIM_SM;
        star_g_stats.count();
    }

    // Source and Group address pair (S, G) lookup
    table s_g {
        key =  {
            vrf : exact;
            src_addr : exact;
            grp_addr : exact;
        }

        actions = {
            @defaultonly NoAction;
            s_g_hit;
        }

        const default_action = NoAction;
        size = s_g_table_size;
        counters = s_g_stats;
    }

    // Group address (*, G) lookup
    table star_g {
        key = {
            vrf : exact;
            grp_addr : exact;
        }

        actions = {
            @defaultonly NoAction;
            star_g_hit_sm;
            star_g_hit_bidir;
        }

        const default_action = NoAction;
        size = star_g_table_size;
        counters = star_g_stats;
    }

    apply {
#ifdef MULTICAST_ENABLE
        if (!s_g.apply().hit) {
            star_g.apply();
        }
#endif
    }
}

control IngressMulticast(
        in switch_lookup_fields_t lkp,
        inout switch_local_metadata_t local_md)(
        switch_uint32_t ipv4_s_g_table_size,
        switch_uint32_t ipv4_star_g_table_size,
        switch_uint32_t ipv6_s_g_table_size,
        switch_uint32_t ipv6_star_g_table_size) {

    // For each rendezvous point (RP), there is a list of interfaces for which
    // the switch is the designated forwarder (DF).

    MulticastBridge<ipv4_addr_t>(ipv4_s_g_table_size, ipv4_star_g_table_size) ipv4_multicast_bridge;
    MulticastRoute<ipv4_addr_t>(ipv4_s_g_table_size, ipv4_star_g_table_size) ipv4_multicast_route;
    MulticastBridgev6<ipv6_addr_t>(
        ipv6_s_g_table_size, ipv6_star_g_table_size) ipv6_multicast_bridge;
    MulticastRoutev6<ipv6_addr_t>(ipv6_s_g_table_size, ipv6_star_g_table_size) ipv6_multicast_route;

    switch_multicast_rpf_group_t rpf_check;
    bit<1> multicast_hit;

    @name(".set_multicast_route")
    action set_multicast_route() {
        local_md.egress_port_lag_index = 0;
        local_md.checks.mrpf = true;
        local_md.flags.routed = true;
    }

    @name(".set_multicast_bridge")
    action set_multicast_bridge(bool mrpf) {
        local_md.egress_port_lag_index = 0;
        local_md.checks.mrpf = mrpf;
        local_md.flags.routed = false;
    }

    @name(".set_multicast_flood")
    action set_multicast_flood(bool mrpf, bool flood) {
        local_md.egress_port_lag_index = SWITCH_FLOOD;
        local_md.checks.mrpf = mrpf;
        local_md.flags.routed = false;
        local_md.flags.flood_to_multicast_routers = flood;
    }

    @name(".multicast_fwd_result")
    table fwd_result {
        key = {
            multicast_hit : ternary;
            lkp.ip_type : ternary;
            local_md.ipv4.multicast_snooping : ternary;
            local_md.ipv6.multicast_snooping : ternary;
            local_md.multicast.mode : ternary;
            rpf_check : ternary;
        }

        actions = {
            set_multicast_bridge;
            set_multicast_route;
            set_multicast_flood;
        }
    }

    apply {
#ifdef MULTICAST_ENABLE
        if (lkp.ip_type == SWITCH_IP_TYPE_IPV4 && local_md.ipv4.multicast_enable) {
            ipv4_multicast_route.apply(lkp.ip_src_addr[95:64],
                                       lkp.ip_dst_addr[95:64],
                                       local_md.vrf,
                                       local_md.multicast,
                                       rpf_check,
                                       local_md.multicast.id,
                                       multicast_hit);
        } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6 && local_md.ipv6.multicast_enable) {
#ifdef IPV6_ENABLE
            ipv6_multicast_route.apply(lkp.ip_src_addr,
                                       lkp.ip_dst_addr,
                                       local_md.vrf,
                                       local_md.multicast,
                                       rpf_check,
                                       local_md.multicast.id,
                                       multicast_hit);
#endif /* IPV6_ENABLE */
        }

        if (multicast_hit == 0 ||
            (local_md.multicast.mode == SWITCH_MULTICAST_MODE_PIM_SM && rpf_check != 0) ||
            (local_md.multicast.mode == SWITCH_MULTICAST_MODE_PIM_BIDIR && rpf_check == 0)) {

            if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                ipv4_multicast_bridge.apply(lkp.ip_src_addr[95:64],
                                            lkp.ip_dst_addr[95:64],
                                            local_md.bd,
                                            local_md.multicast.id,
                                            multicast_hit);
            } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_ENABLE
                ipv6_multicast_bridge.apply(lkp.ip_src_addr,
                                            lkp.ip_dst_addr,
                                            local_md.bd,
                                            local_md.multicast.id,
                                            multicast_hit);
#endif /* IPV6_ENABLE */
            }
        }

        fwd_result.apply();
#endif /* MULTICAST_ENABLE */
    }
}
#endif /* MULTICAST_ENABLE */


//-----------------------------------------------------------------------------
// Multicast flooding
//-----------------------------------------------------------------------------
control MulticastFlooding(inout switch_local_metadata_t local_md)(switch_uint32_t table_size) {

    @name(".flood")
    action flood(switch_mgid_t mgid) {
        local_md.multicast.id = mgid;
    }

    @name(".bd_flood")
    table bd_flood {
        key = {
            local_md.bd : exact @name("bd");
            local_md.lkp.pkt_type : exact @name("pkt_type");
#ifdef MULTICAST_ENABLE
            local_md.flags.flood_to_multicast_routers : exact @name("flood_to_multicast_routers");
#endif
        }

        actions = { flood; }
        size = table_size;
    }

    apply {
        bd_flood.apply();
    }
}

//-----------------------------------------------------------------------------
// Egress Multicast Replication DB
//-----------------------------------------------------------------------------
control MulticastReplication(in switch_rid_t replication_id,
                             in switch_port_t port,
                             inout switch_local_metadata_t local_md)(
                             switch_uint32_t table_size=4096) {
    @name(".multicast_rid_hit")
    action rid_hit(switch_bd_t bd) {
        local_md.checks.same_bd = bd ^ local_md.bd;
        local_md.bd = bd;
    }

    action rid_miss() {
        local_md.flags.routed = false;
    }

    @name(".multicast_rid")
    table rid {
        key = { replication_id : exact; }
        actions = {
            rid_miss;
            rid_hit;
        }

        size = table_size;
        const default_action = rid_miss;
    }

    apply {
#ifdef MULTICAST_ENABLE
        if (replication_id != 0)
            rid.apply();
        else
            local_md.checks.same_bd = 0xFF;

        if (local_md.checks.same_bd == 0)
            local_md.flags.routed = false;
#endif
    }
}

#endif /* _P4_MULTICAST_ */
