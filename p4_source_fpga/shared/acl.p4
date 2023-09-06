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


#ifndef _P4_ACL_
#define _P4_ACL_

//-----------------------------------------------------------------------------
// Common Ingress ACL match keys and Actions
//-----------------------------------------------------------------------------
#define INGRESS_MAC_ACL_KEY                    \
    hdr.ethernet.src_addr : ternary;           \
    hdr.ethernet.dst_addr : ternary;           \
    local_md.lkp.mac_type : ternary;

#define INGRESS_IP_ACL_COMMON_KEY              \
    local_md.lkp.ip_proto : ternary;              \
    local_md.lkp.ip_tos : ternary;                \
    local_md.lkp.l4_src_port : ternary;           \
    local_md.lkp.l4_dst_port : ternary;           \
    local_md.lkp.ip_ttl : ternary;                \
    local_md.lkp.ip_frag : ternary;               \
    local_md.lkp.tcp_flags : ternary;             \
    local_md.l4_src_port_label : ternary;         \
    local_md.l4_dst_port_label : ternary;

#define INGRESS_IPV4_ACL_KEY                   \
    local_md.lkp.ip_src_addr[95:64] : ternary;     \
    local_md.lkp.ip_dst_addr[95:64] : ternary;     \
    INGRESS_IP_ACL_COMMON_KEY

#define INGRESS_IPV6_UPPER64_ACL_KEY            \
    local_md.lkp.ip_src_addr[127:96] : ternary; \
    local_md.lkp.ip_src_addr[95:64] : ternary;  \
    local_md.lkp.ip_dst_addr[127:96] : ternary; \
    local_md.lkp.ip_dst_addr[95:64] : ternary;  \
    INGRESS_IP_ACL_COMMON_KEY

#define INGRESS_IPV6_ACL_KEY                    \
    local_md.lkp.ip_src_addr : ternary;         \
    local_md.lkp.ip_dst_addr : ternary;         \
    INGRESS_IP_ACL_COMMON_KEY

#define INGRESS_IP_UPPER64_ACL_KEY              \
    local_md.lkp.ip_src_addr[127:96] : ternary; \
    local_md.lkp.ip_src_addr[95:64] : ternary;  \
    local_md.lkp.ip_dst_addr[127:96] : ternary; \
    local_md.lkp.ip_dst_addr[95:64] : ternary;  \
    INGRESS_IP_ACL_COMMON_KEY

#define INGRESS_IP_ACL_KEY                      \
    local_md.lkp.ip_src_addr : ternary;         \
    local_md.lkp.ip_dst_addr : ternary;         \
    INGRESS_IP_ACL_COMMON_KEY

#define INGRESS_INNER_IPV4_ACL_KEY               \
    hdr.inner_ipv4.src_addr : ternary;           \
    hdr.inner_ipv4.dst_addr : ternary;           \
    hdr.inner_ipv4.protocol : ternary;           \
    hdr.inner_ipv4.diffserv : ternary;           \
    hdr.inner_tcp.src_port : ternary;            \
    hdr.inner_tcp.dst_port : ternary;            \
    hdr.inner_udp.src_port : ternary;            \
    hdr.inner_udp.dst_port : ternary;            \
    hdr.inner_ipv4.ttl : ternary;                \
    hdr.inner_tcp.flags : ternary;               \
    local_md.tunnel.vni : ternary;

#define INGRESS_INNER_IPV6_ACL_KEY               \
    hdr.inner_ipv6.src_addr : ternary;           \
    hdr.inner_ipv6.dst_addr : ternary;           \
    hdr.inner_ipv6.next_hdr : ternary;           \
    hdr.inner_ipv6.traffic_class : ternary;      \
    hdr.inner_tcp.src_port : ternary;            \
    hdr.inner_tcp.dst_port : ternary;            \
    hdr.inner_udp.src_port : ternary;            \
    hdr.inner_udp.dst_port : ternary;            \
    hdr.inner_ipv6.hop_limit : ternary;          \
    hdr.inner_tcp.flags : ternary;               \
    local_md.tunnel.vni : ternary;

//-----------------------------------------------------------------------------
// Common Egress ACL match keys and Actions
//-----------------------------------------------------------------------------
#ifdef EGRESS_ACL_BD_LABEL_ENABLE
#define EGRESS_ACL_LABEL_KEY                   \
    local_md.egress_port_lag_label: ternary;             \
    local_md.bd_label : ternary;
#else
#define EGRESS_ACL_LABEL_KEY                   \
    local_md.egress_port_lag_label: ternary;
#endif

#define EGRESS_MAC_ACL_KEY \
            hdr.ethernet.src_addr : ternary;      \
            hdr.ethernet.dst_addr : ternary;      \
            hdr.ethernet.ether_type : ternary;    \
            EGRESS_ACL_LABEL_KEY

#define EGRESS_IPV4_ACL_KEY              \
    hdr.ipv4.src_addr : ternary;         \
    hdr.ipv4.dst_addr : ternary;         \
    hdr.ipv4.protocol : ternary;         \
    local_md.lkp.tcp_flags : ternary;       \
    local_md.lkp.l4_src_port : ternary;     \
    local_md.lkp.l4_dst_port : ternary;     \
    EGRESS_ACL_LABEL_KEY

#define EGRESS_IPV6_UPPER64_ACL_KEY      \
    hdr.ipv6.src_addr[127:96] : ternary; \
    hdr.ipv6.src_addr[95:64] : ternary;  \
    hdr.ipv6.dst_addr[127:96] : ternary; \
    hdr.ipv6.dst_addr[95:64] : ternary;  \
    local_md.lkp.tcp_flags : ternary;    \
    local_md.lkp.l4_src_port : ternary;  \
    local_md.lkp.l4_dst_port : ternary;  \
    EGRESS_ACL_LABEL_KEY

#define EGRESS_IPV6_ACL_KEY                                    \
    hdr.ipv6.src_addr : ternary;                               \
    hdr.ipv6.dst_addr : ternary;                               \
    hdr.ipv6.next_hdr : ternary;                               \
    local_md.lkp.tcp_flags : ternary;                          \
    local_md.lkp.l4_src_port : ternary;                        \
    local_md.lkp.l4_dst_port : ternary;                        \
    EGRESS_ACL_LABEL_KEY

#define EGRESS_ACL_ACTION_LIST           \
            deny();                      \
            permit();                    \
            mirror_out();                \
            no_action;

//-----------------------------------------------------------------------------
// Common Ingress ACL actions.
//-----------------------------------------------------------------------------

#define INGRESS_ACL_PACKET_ACTIONS                                            \
action no_action() {                                                          \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action permit(switch_user_metadata_t user_metadata,                           \
              switch_hostif_trap_t trap_id,                                   \
              switch_meter_index_t meter_index) {                             \
    local_md.flags.acl_deny = false;                                          \
    local_md.user_metadata = user_metadata;                                   \
    local_md.hostif_trap_id = trap_id;                                        \
    local_md.qos.acl_meter_index = meter_index;                               \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action deny() {                                                               \
    local_md.flags.acl_deny = true;                                           \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action copy_to_cpu(switch_hostif_trap_t trap_id,                              \
                   switch_meter_index_t meter_index) {                        \
    local_md.hostif_trap_id = trap_id;                                        \
    local_md.qos.acl_meter_index = meter_index;                               \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action trap(switch_hostif_trap_t trap_id,                                     \
            switch_meter_index_t meter_index) {                               \
    local_md.hostif_trap_id = trap_id;                                        \
    local_md.qos.acl_meter_index = meter_index;                               \
    deny();                                                                   \
}

#define INGRESS_ACL_ACTIONS                                                   \
action set_tc(switch_tc_t tc) {                                               \
    local_md.qos.tc = tc;                                                     \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action set_color(switch_pkt_color_t color) {                                  \
    local_md.qos.color = color;                                               \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action redirect_port(switch_user_metadata_t user_metadata,                    \
                     switch_port_lag_index_t egress_port_lag_index) {         \
    local_md.flags.acl_deny =  false;                                         \
    local_md.egress_port_lag_index = egress_port_lag_index;                   \
    local_md.acl_port_redirect = true;                                        \
    local_md.user_metadata = user_metadata;                                   \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action mirror_in(switch_mirror_meter_id_t meter_index,                        \
              switch_mirror_session_t session_id) {                           \
    local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;                           \
    local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;                      \
    local_md.mirror.session_id = session_id;                                  \
    local_md.mirror.meter_index = meter_index;                                \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action set_dtel_report_type(switch_dtel_report_type_t type) {                 \
    local_md.dtel.report_type = local_md.dtel.report_type | type;             \
    stats.count();                                                            \
}

// fib_lpm_miss reset in nexthop.p4 for TF2
#if __TARGET_TOFINO__ == 1
#define INGRESS_ACL_REDIRECT_NEXTHOP_ACTION                                   \
action redirect_nexthop(switch_user_metadata_t user_metadata,                 \
                        switch_nexthop_t nexthop_index) {                     \
    acl_nexthop = nexthop_index;                                              \
    local_md.flags.fib_lpm_miss = false;                                      \
    local_md.user_metadata = user_metadata;                                   \
    stats.count();                                                            \
}
#else
#define INGRESS_ACL_REDIRECT_NEXTHOP_ACTION                                   \
action redirect_nexthop(switch_user_metadata_t user_metadata,                 \
                        switch_nexthop_t nexthop_index) {                     \
    acl_nexthop = nexthop_index;                                              \
    local_md.user_metadata = user_metadata;                                   \
    stats.count();                                                            \
}
#endif

#define INGRESS_ACL_NO_NAT_ACTION                                             \
action disable_nat(bool nat_dis) {                                            \
    local_md.nat.nat_disable = nat_dis;                                       \
    stats.count();                                                            \
}                                                                             \

#define INGRESS_ACL_ACTION_MIRROR_OUT                                         \
action mirror_out(switch_mirror_meter_id_t meter_index,                       \
                  switch_mirror_session_t session_id) {                       \
    local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;                           \
    local_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;                       \
    local_md.mirror.session_id = session_id;                                  \
    local_md.mirror.meter_index = meter_index;                                \
    stats.count();                                                            \
}                                                                             \
//-----------------------------------------------------------------------------
// Common Egress ACL actions.
//-----------------------------------------------------------------------------
#define EGRESS_ACL_ACTIONS                                                    \
action no_action() {                                                          \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action deny() {                                                               \
    local_md.flags.acl_deny = true;                                           \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action permit(switch_meter_index_t meter_index) {                             \
    local_md.flags.acl_deny = false;                                          \
    local_md.qos.acl_meter_index = meter_index;                               \
    stats.count();                                                            \
}                                                                             \
                                                                              \
action mirror_out(switch_mirror_meter_id_t meter_index,                       \
              switch_mirror_session_t session_id) {                           \
    local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;                           \
    local_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;                       \
    local_md.mirror.session_id = session_id;                                  \
    local_md.mirror.meter_index = meter_index;                                \
    stats.count();                                                            \
}

#define EGRESS_ACL_ACTION_MIRROR_IN                                           \
action mirror_in(switch_mirror_meter_id_t meter_index,                        \
                 switch_mirror_session_t session_id) {                        \
    local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT_WITH_B_MD;                 \
    local_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT;                \
    local_md.mirror.session_id = session_id;                                  \
    local_md.mirror.meter_index = meter_index;                                \
    stats.count();                                                            \
}


//-----------------------------------------------------------------------------
// Pre Ingress ACL
//-----------------------------------------------------------------------------
control PreIngressAcl(in switch_header_t hdr, inout switch_local_metadata_t local_md)(
        switch_uint32_t table_size=512) {

    bool is_acl_enabled;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".set_acl_status")
    action set_acl_status(bool enabled) {
        is_acl_enabled = enabled;
    }

    @name(".device_to_acl")
    table device_to_acl {
        actions = {
            set_acl_status;
        }
        default_action = set_acl_status(false);
        size = 1;
    }

    // cannot use INGRESS_ACL_ACTIONS above to avoid dependencies
    @name(".pre_ingress_acl_no_action")
    action no_action() {
        stats.count();
    }
    @name(".pre_ingress_acl_deny")
    action deny() {
        local_md.flags.acl_deny = true;
        stats.count();
    }
    @name(".pre_ingress_acl_set_vrf")
    action set_vrf(switch_vrf_t vrf) {
        local_md.vrf = vrf;
        stats.count();
    }

    @name(".pre_ingress_acl")
    table acl {
        key = {
            hdr.ethernet.src_addr : ternary;
            hdr.ethernet.dst_addr : ternary;
            local_md.lkp.mac_type : ternary;
#ifdef IPV6_ACL_UPPER64_ENABLE
            local_md.lkp.ip_src_addr[127:96] : ternary;
            local_md.lkp.ip_src_addr[95:64] : ternary;
            local_md.lkp.ip_dst_addr[127:96] : ternary;
            local_md.lkp.ip_dst_addr[95:64] : ternary;
#else
            local_md.lkp.ip_src_addr : ternary;
            local_md.lkp.ip_dst_addr : ternary;
#endif
            local_md.lkp.ip_tos : ternary;
            local_md.ingress_port : ternary;
        }

        actions = {
            set_vrf;
            deny;
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        device_to_acl.apply();
        if (!INGRESS_BYPASS(ACL) && is_acl_enabled == true) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress Shared IP ACL
//-----------------------------------------------------------------------------
control IngressIpAcl(inout switch_local_metadata_t local_md,
                     out switch_nexthop_t acl_nexthop,
                     in switch_header_t hdr)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) payload_stats;

    INGRESS_ACL_ACTIONS
    INGRESS_ACL_PACKET_ACTIONS
    INGRESS_ACL_REDIRECT_NEXTHOP_ACTION
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
    INGRESS_ACL_ACTION_MIRROR_OUT
#endif

    action port_collection(switch_mirror_meter_id_t meter_index, switch_mirror_session_t session_id,bit<12> app_id) {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        local_md.mirror.session_id = session_id;
        local_md.mirror.meter_index = meter_index;
        // add app_id
        local_md.app_id = app_id;
        stats.count();  
    }

    action port_snort3() {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        local_md.mirror.session_id = 0x01;
        local_md.mirror.meter_index = 0;
        local_md.app_id = 0xfff;
    }

    action payload_port_collection(switch_mirror_meter_id_t meter_index, switch_mirror_session_t session_id,bit<12> app_id) {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        local_md.mirror.session_id = session_id;
        local_md.mirror.meter_index = meter_index;
        // add app_id
        local_md.app_id = app_id;
        payload_stats.count();
    }

    action payload_port_snort3() {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        local_md.mirror.session_id = 0x01;
        local_md.mirror.meter_index = 0;
        local_md.app_id = 0xfff;
        payload_stats.count();            
    }


    table acl {
        key = {
#ifdef IPV6_ACL_UPPER64_ENABLE
            INGRESS_IP_UPPER64_ACL_KEY
#else
            INGRESS_IP_ACL_KEY
#endif
            local_md.payload32_0  : ternary;
            //local_md.payload32_1  : ternary;
            local_md.ingress_port   : ternary;
            local_md.lkp.mac_dst_addr : ternary;
            local_md.lkp.mac_type     : ternary;
            // vlan 
            hdr.vlan_tag[0].isValid()   : ternary;
            // QinQ
            hdr.vlan_tag[1].isValid()   : ternary;
            // vlan id
            hdr.vlan_tag[0].vid : ternary;
            hdr.vlan_tag[1].vid : ternary;
        }

        actions = {
            deny;
            trap;
            copy_to_cpu;
            permit;
#ifdef ACL_REDIRECT_NEXTHOP_ENABLE
            redirect_nexthop;
#endif
#ifdef ACL_REDIRECT_PORT_ENABLE
            redirect_port;
#endif
            mirror_in;
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
            mirror_out;
#endif
#ifdef QOS_ACTIONS_IN_IP_ACL_ENABLE
            set_tc;
            set_color;
#endif
#ifdef DTEL_ACTIONS_IN_IP_ACL_ENABLE
            set_dtel_report_type;
#endif
            no_action;

            //add action port_collection
            port_collection;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    table payload_classification {
        key = {
            local_md.lkp.l4_src_port : ternary;
            local_md.lkp.l4_dst_port : ternary;
            // protocol ,1 tcp ,2 udp
            local_md.tcp_or_udp      : ternary;
            // add payload key
            local_md.payload32_0     : ternary;
            local_md.payload32_1     : ternary;
            local_md.payload32_2     : ternary;
            local_md.payload32_3     : ternary;
            //local_md.payload32_4     : ternary;
            //local_md.payload32_5     : ternary;
            //local_md.payload32_6     : ternary;
            //local_md.payload32_7     : ternary;
            local_md.payload_length  : range;
            local_md.ingress_port   : ternary;
        }

        actions = {
            //add action port_snort3、port_collection
            payload_port_collection;
            payload_port_snort3;
        }
        const default_action = payload_port_snort3;
        counters = payload_stats;
        size = table_size;
    }

    apply {
        local_md.payload_length = 0;
        if (!INGRESS_BYPASS(ACL)) {
            switch(acl.apply().action_run) {
                deny : { }
                port_collection : { }
                default: { 
                    if ((hdr.tcp.isValid() || hdr.udp.isValid())){
                    // Calculate the payload length
                        if (hdr.tcp.isValid()){     // tcp
                            local_md.tcp_or_udp = 1;
                            if (!hdr.ipv4_option.isValid()){    // don't have ipv4_option
                                local_md.payload_length =  hdr.ipv4.total_len - 40; // ipv4_total_len - ipv4_h_len(20) - tcp_h_len(20)
                            } else {       //  have ipv4_option
                                local_md.payload_length =  hdr.ipv4.total_len - 44; // ipv4_total_len - ipv4_h_len(20) - ipv4_option_h_len(4) - tcp_h_len(20)
                            }
                        } else {    // udp
                            local_md.tcp_or_udp = 2;
                            if (!hdr.ipv4_option.isValid()){    // don't have ipv4_option
                                local_md.payload_length =  hdr.ipv4.total_len - 28; // ipv4_total_len - ipv4_h_len(20) - tcp_h_len(8)
                            } else {       //  have ipv4_option
                                local_md.payload_length =  hdr.ipv4.total_len - 32; // ipv4_total_len - ipv4_h_len(20) - ipv4_option_h_len(4) - tcp_h_len(8)
                            }
                        }
                        // classification
                        payload_classification.apply();
                    } else {
                        port_snort3();
                    }
                }
            }
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress Inner IPv4 ACL
//-----------------------------------------------------------------------------
control IngressInnerIpv4Acl(in switch_header_t hdr,
                     inout switch_local_metadata_t local_md)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    action set_dtel_report_type(switch_dtel_report_type_t type) {
        local_md.dtel.report_type = local_md.dtel.report_type | type;
        stats.count();
    }

    action no_action() {
        stats.count();
    }

    table acl {
        key = {
            INGRESS_INNER_IPV4_ACL_KEY
            local_md.ingress_port_lag_index : ternary;
        }

        actions = {
            set_dtel_report_type;
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress Inner IPv6 ACL
//-----------------------------------------------------------------------------
control IngressInnerIpv6Acl(in switch_header_t hdr,
                     inout switch_local_metadata_t local_md)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    action set_dtel_report_type(switch_dtel_report_type_t type) {
        local_md.dtel.report_type = local_md.dtel.report_type | type;
        stats.count();
    }

    action no_action() {
        stats.count();
    }

    table acl {
        key = {
            INGRESS_INNER_IPV6_ACL_KEY
            local_md.ingress_port_lag_index : ternary;
        }

        actions = {
            set_dtel_report_type;
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress IPv4 ACL
//-----------------------------------------------------------------------------
control IngressIpv4Acl(inout switch_local_metadata_t local_md,
                     out switch_nexthop_t acl_nexthop)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    INGRESS_ACL_ACTIONS
    INGRESS_ACL_PACKET_ACTIONS
    INGRESS_ACL_REDIRECT_NEXTHOP_ACTION
#ifdef NAT_ENABLE
    INGRESS_ACL_NO_NAT_ACTION
#endif
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
    INGRESS_ACL_ACTION_MIRROR_OUT
#endif
    table acl {
        key = {
            INGRESS_IPV4_ACL_KEY
#ifdef FIB_ACL_LABEL_ENABLE
            local_md.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
            local_md.lkp.mac_type : ternary;
#endif
#ifdef IN_PORT_IN_IP_ACL_KEY_ENABLE
            local_md.ingress_port : ternary;
#endif
#ifdef PORT_GROUP_IN_ACL_KEY_ENABLE
            local_md.ingress_port_lag_index : ternary;
            local_md.ingress_port_lag_label[7:0] : ternary;
#else
            local_md.ingress_port_lag_label : ternary;
#endif
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
            local_md.bd_label : ternary;
#else
            local_md.bd : ternary;
#endif
#ifdef IN_PORTS_IN_ACL_KEY_ENABLE
            local_md.in_ports_group_label[7:0] : ternary;
#endif
        }

        actions = {
            deny;
            trap;
            copy_to_cpu;
            permit;
#ifdef NAT_ENABLE
            disable_nat;
#endif
#ifdef ACL_REDIRECT_NEXTHOP_ENABLE
            redirect_nexthop;
#endif
#ifdef ACL_REDIRECT_PORT_ENABLE
            redirect_port;
#endif
            mirror_in;
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
            mirror_out;
#endif
#ifdef QOS_ACTIONS_IN_IP_ACL_ENABLE
            set_tc;
            set_color;
#endif
#ifdef DTEL_ACTIONS_IN_IP_ACL_ENABLE
            set_dtel_report_type;
#endif
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress IPv6 ACL
//-----------------------------------------------------------------------------
control IngressIpv6Acl(inout switch_local_metadata_t local_md,
                     out switch_nexthop_t acl_nexthop)(
                       switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    INGRESS_ACL_ACTIONS
    INGRESS_ACL_PACKET_ACTIONS
    INGRESS_ACL_REDIRECT_NEXTHOP_ACTION
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
    INGRESS_ACL_ACTION_MIRROR_OUT
#endif

    table acl {
        key = {
#ifdef IPV6_ACL_UPPER64_ENABLE
            INGRESS_IPV6_UPPER64_ACL_KEY
#else
            INGRESS_IPV6_ACL_KEY
#endif

#ifdef FIB_ACL_LABEL_ENABLE
            local_md.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
            local_md.lkp.mac_type : ternary;
#endif
#ifdef IN_PORT_IN_IP_ACL_KEY_ENABLE
            local_md.ingress_port : ternary;
#endif
#ifdef PORT_GROUP_IN_ACL_KEY_ENABLE
            local_md.ingress_port_lag_index : ternary;
            local_md.ingress_port_lag_label[15:8] : ternary;
#else
            local_md.ingress_port_lag_label : ternary;
#endif
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
            local_md.bd_label : ternary;
#else
            local_md.bd : ternary;
#endif
#ifdef IN_PORTS_IN_ACL_KEY_ENABLE
            local_md.in_ports_group_label[15:8] : ternary;
#endif
        }

        actions = {
            deny;
            trap;
            copy_to_cpu;
            permit;
#ifdef ACL_REDIRECT_NEXTHOP_ENABLE
            redirect_nexthop;
#endif
#ifdef ACL_REDIRECT_PORT_ENABLE
            redirect_port;
#endif
            mirror_in;
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
            mirror_out;
#endif
#ifdef QOS_ACTIONS_IN_IP_ACL_ENABLE
            set_tc;
            set_color;
#endif
#ifdef DTEL_ACTIONS_IN_IP_ACL_ENABLE
            set_dtel_report_type;
#endif
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

control IngressTosMirrorAcl(inout switch_local_metadata_t local_md)(switch_uint32_t table_size=512) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    action no_action() {
        stats.count();
    }
    action mirror_in(switch_mirror_meter_id_t meter_index, switch_mirror_session_t session_id) {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        local_md.mirror.session_id = session_id;
        local_md.mirror.meter_index = meter_index;
        stats.count();
    }
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
    INGRESS_ACL_ACTION_MIRROR_OUT
#endif

    table acl {
        key = {
            local_md.lkp.ip_tos : ternary;
            local_md.ingress_port_lag_label : ternary;
        }

        actions = {
            mirror_in;
#ifdef INGRESS_ACL_ACTION_MIRROR_OUT_ENABLE
            mirror_out;
#endif
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress MAC ACL (For outer header only)
//-----------------------------------------------------------------------------
control IngressMacAcl(in switch_header_t hdr, inout switch_local_metadata_t local_md,
                     out switch_nexthop_t acl_nexthop)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    INGRESS_ACL_ACTIONS
    INGRESS_ACL_PACKET_ACTIONS
    INGRESS_ACL_REDIRECT_NEXTHOP_ACTION

    table acl {
        key = {
            INGRESS_MAC_ACL_KEY
            local_md.ingress_port_lag_label : ternary;
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
            local_md.bd_label : ternary;
#else
            local_md.bd : ternary;
#endif
        }

        actions = {
            deny;
            permit;
#ifdef ACL_REDIRECT_NEXTHOP_ENABLE
            redirect_nexthop;
#endif
#ifdef ACL_REDIRECT_PORT_ENABLE
            redirect_port;
#endif
            mirror_in;
#ifdef QOS_ACTIONS_IN_IP_ACL_ENABLE
            set_tc;
            set_color;
#endif
#ifdef DTEL_ACTIONS_IN_IP_ACL_ENABLE
            set_dtel_report_type;
#endif
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Ingress Shared IP DTEL Sample ACL
// Typically a DTEL ACL slice should use the normal shared IP ACL definition
// This is an alternate definition that adds sampling and IFA clone support
//-----------------------------------------------------------------------------
struct switch_acl_sample_info_t {
    bit<32> current;
    bit<32> rate;
}

control IngressIpDtelSampleAcl(inout switch_local_metadata_t local_md,
                         out switch_nexthop_t acl_nexthop)(
        switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    const bit<32> acl_sample_session_size = 256;

    Register<switch_acl_sample_info_t, bit<32>>(acl_sample_session_size) samplers;
    RegisterAction<switch_acl_sample_info_t, bit<8>, bit<1>>(samplers) sample_packet = {
        void apply(inout switch_acl_sample_info_t reg, out bit<1> flag) {
            if (reg.current > 0) {
                reg.current = reg.current - 1;
            } else {
                reg.current = reg.rate;
                flag = 1;
            }
        }
    };

    INGRESS_ACL_ACTIONS
    INGRESS_ACL_PACKET_ACTIONS

    action ifa_clone_sample(switch_ifa_sample_id_t ifa_sample_session) {
        local_md.dtel.ifa_gen_clone = sample_packet.execute(ifa_sample_session);
        stats.count();
    }

    action ifa_clone_sample_and_set_dtel_report_type(
            switch_ifa_sample_id_t ifa_sample_session,
            switch_dtel_report_type_t type) {
        local_md.dtel.report_type = type;
        local_md.dtel.ifa_gen_clone = sample_packet.execute(ifa_sample_session);
        stats.count();
    }

    table acl {
        key = {
#ifdef IPV6_ACL_UPPER64_ENABLE
            INGRESS_IP_UPPER64_ACL_KEY
#else
            INGRESS_IP_ACL_KEY
#endif

#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
            local_md.lkp.mac_type : ternary;
#endif
#ifdef PORT_GROUP_IN_ACL_KEY_ENABLE
            local_md.ingress_port_lag_index : ternary;
            local_md.ingress_port_lag_label[7:0] : ternary;
#else
            local_md.ingress_port_lag_label : ternary;
#endif
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
            local_md.bd_label : ternary;
#else
            local_md.bd : ternary;
#endif
        }

        actions = {
            set_dtel_report_type;
#ifdef DTEL_IFA_CLONE
            ifa_clone_sample;
            ifa_clone_sample_and_set_dtel_report_type;
#endif
            no_action;
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!INGRESS_BYPASS(ACL)) {
            acl.apply();
        }
#ifdef DTEL_IFA_CLONE
        if (local_md.dtel.ifa_gen_clone == 1) {
            local_md.dtel.report_type[4:4] = local_md.dtel.ifa_gen_clone;
        }
#endif
    }
}

// ----------------------------------------------------------------------------
// Comparison/Logical operation unit (LOU)
// LOU can perform logical operationis such AND and OR on tcp flags as well as comparison
// operations such as LT, GT, EQ, and NE for src/dst UDP/TCP ports.
//
// @param table_size : Total number of supported ranges for src/dst ports.
// ----------------------------------------------------------------------------
control LOU(inout switch_local_metadata_t local_md) {

    const switch_uint32_t table_size = switch_l4_port_label_width;

    //TODO(msharif): Change this to bitwise OR so we can allocate bits to src/dst ports at runtime.
    @name(".set_ingress_src_port_label")
    action set_src_port_label(bit<8> label) {
        local_md.l4_src_port_label = label;
    }

    @name(".set_ingress_dst_port_label")
    action set_dst_port_label(bit<8> label) {
        local_md.l4_dst_port_label = label;
    }

    @entries_with_ranges(table_size)
    @name(".ingress_l4_dst_port")
    table l4_dst_port {
        key = {
            local_md.lkp.l4_dst_port : range;
        }

        actions = {
            NoAction;
            set_dst_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @entries_with_ranges(table_size)
    @name(".ingress_l4_src_port")
    table l4_src_port {
        key = {
            local_md.lkp.l4_src_port : range;
        }

        actions = {
            NoAction;
            set_src_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @name(".set_tcp_flags")
    action set_tcp_flags(bit<8> flags) {
        local_md.lkp.tcp_flags = flags;
    }

    @name(".ingress_lou_tcp")
    table tcp {
        key = { local_md.lkp.tcp_flags : exact; }
        actions = {
            NoAction;
            set_tcp_flags;
        }

        size = 256;
    }

    apply {
#ifdef L4_PORT_LOU_ENABLE
        l4_src_port.apply();
        l4_dst_port.apply();
#endif

#ifdef TCP_FLAGS_LOU_ENABLE
        tcp.apply();
#endif
    }
}

//-----------------------------------------------------------------------------
//
// Ingress System ACL
//
//-----------------------------------------------------------------------------
control IngressSystemAcl(
        in switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr)(
        switch_uint32_t table_size=512) {

    const switch_uint32_t drop_stats_table_size = 8192;

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) stats;

    @name(".ingress_copp_meter")
    Meter<bit<8>>(1 << switch_copp_meter_id_width, MeterType_t.PACKETS) copp_meter;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) copp_stats;

    switch_copp_meter_id_t copp_meter_id;

    @name(".ingress_system_acl_permit")
    action permit() {
        local_md.drop_reason = SWITCH_DROP_REASON_UNKNOWN;
    }
    @name(".ingress_system_acl_drop")
    action drop(switch_drop_reason_t drop_reason, bool disable_learning) {
        ig_intr_md_for_dprsr.drop_ctl = 0x1;
        ig_intr_md_for_dprsr.digest_type =
            disable_learning ? SWITCH_DIGEST_TYPE_INVALID : ig_intr_md_for_dprsr.digest_type;
        local_md.drop_reason = drop_reason;
#ifdef NAT_ENABLE
        local_md.nat.hit = SWITCH_NAT_HIT_NONE;
#endif
    }

    @name(".ingress_system_acl_copy_to_cpu")
    action copy_to_cpu(switch_cpu_reason_t reason_code,
                       switch_qid_t qid,
                       switch_copp_meter_id_t meter_id,
                       bool disable_learning, bool overwrite_qid) {
        local_md.qos.qid = overwrite_qid ? qid : local_md.qos.qid;
        // local_md.qos.icos = icos;
        ig_intr_md_for_tm.copy_to_cpu = 1w1;
        ig_intr_md_for_dprsr.digest_type =
            disable_learning ? SWITCH_DIGEST_TYPE_INVALID : ig_intr_md_for_dprsr.digest_type;
        ig_intr_md_for_tm.packet_color = (bit<2>) copp_meter.execute(meter_id);
        copp_meter_id = meter_id;
        local_md.cpu_reason = reason_code;
#ifdef NAT_ENABLE
        local_md.nat.hit = SWITCH_NAT_HIT_NONE;
#endif
        local_md.drop_reason = SWITCH_DROP_REASON_UNKNOWN;
    }

#ifdef INGRESS_SFLOW_ENABLE
    @name(".ingress_system_acl_copy_sflow_to_cpu")
    action copy_sflow_to_cpu(switch_cpu_reason_t reason_code,
                             switch_qid_t qid,
                             switch_copp_meter_id_t meter_id,
                             bool disable_learning, bool overwrite_qid) {
        copy_to_cpu(reason_code + (bit<16>)local_md.sflow.session_id, qid, meter_id, disable_learning, overwrite_qid);
    }
#endif /* INGRESS_SFLOW_ENABLE */

    @name(".ingress_system_acl_redirect_to_cpu")
    action redirect_to_cpu(switch_cpu_reason_t reason_code,
                           switch_qid_t qid,
                           switch_copp_meter_id_t meter_id,
                           bool disable_learning, bool overwrite_qid) {
        ig_intr_md_for_dprsr.drop_ctl = 0b1;
        copy_to_cpu(reason_code, qid, meter_id, disable_learning, overwrite_qid);
    }

#ifdef INGRESS_SFLOW_ENABLE
    @name(".ingress_system_acl_redirect_sflow_to_cpu")
    action redirect_sflow_to_cpu(switch_cpu_reason_t reason_code,
                                 switch_qid_t qid,
                                 switch_copp_meter_id_t meter_id,
                                 bool disable_learning, bool overwrite_qid) {
        ig_intr_md_for_dprsr.drop_ctl = 0b1;
        copy_sflow_to_cpu(reason_code, qid, meter_id, disable_learning, overwrite_qid);
    }
#endif /* INGRESS_SFLOW_ENABLE */

#ifdef BFD_OFFLOAD_ENABLE
    @name(".ingress_system_acl_redirect_bfd_to_cpu")
    action redirect_bfd_to_cpu(switch_cpu_reason_t reason_code,
                               switch_qid_t qid,
                               switch_copp_meter_id_t meter_id,
                               bool disable_learning) {
        ig_intr_md_for_dprsr.drop_ctl = 0b1;
        copy_to_cpu(reason_code + (bit<16>)local_md.bfd.session_id, qid, meter_id, disable_learning);
    }
#endif /* BFD_OFFLOAD_ENABLE */

    @name(".ingress_system_acl")
    table system_acl {
        key = {
            local_md.ingress_port_lag_label : ternary;
            local_md.bd : ternary;
            local_md.ingress_port_lag_index : ternary;

            // Lookup fields
            local_md.lkp.pkt_type : ternary;
            local_md.lkp.mac_type : ternary;
            local_md.lkp.mac_dst_addr : ternary;
            local_md.lkp.ip_type : ternary;
            local_md.lkp.ip_ttl : ternary;
            local_md.lkp.ip_proto : ternary;
            local_md.lkp.ip_frag : ternary;
            local_md.lkp.ip_dst_addr : ternary;
            local_md.lkp.l4_src_port : ternary;
            local_md.lkp.l4_dst_port : ternary;
            local_md.lkp.arp_opcode : ternary;

            // Flags
            local_md.flags.port_vlan_miss : ternary;
            local_md.flags.acl_deny : ternary;
            local_md.flags.racl_deny : ternary;
            local_md.flags.rmac_hit : ternary;
            local_md.flags.dmac_miss : ternary;
            local_md.flags.myip : ternary;
            local_md.flags.glean : ternary;
            local_md.flags.routed : ternary;
            local_md.flags.fib_lpm_miss : ternary;
            local_md.flags.fib_drop : ternary;
#ifdef INGRESS_ACL_METER_ENABLE
            local_md.flags.meter_packet_action : ternary;
#endif
#ifdef STORM_CONTROL_ENABLE
            local_md.qos.storm_control_color : ternary;
#endif
            local_md.flags.link_local : ternary;

#ifdef INGRESS_PORT_METER_ENABLE
            local_md.flags.port_meter_drop : ternary;
#endif

            local_md.checks.same_if : ternary;
#ifdef L3_UNICAST_SELF_FORWARDING_CHECK
            local_md.checks.same_bd : ternary;
#endif

#ifdef STP_ENABLE
            local_md.stp.state_ : ternary;
#endif
#ifdef PFC_ENABLE
            local_md.flags.pfc_wd_drop : ternary;
#endif
            local_md.ipv4.unicast_enable : ternary;
            local_md.ipv6.unicast_enable : ternary;

#ifdef MULTICAST_ENABLE
            local_md.checks.mrpf : ternary;
            local_md.ipv4.multicast_enable : ternary;
            local_md.ipv4.multicast_snooping : ternary;
            local_md.ipv6.multicast_enable : ternary;
            local_md.ipv6.multicast_snooping : ternary;
#endif
#ifdef INGRESS_SFLOW_ENABLE
            local_md.sflow.sample_packet : ternary;
#endif
            local_md.l2_drop_reason : ternary;
            local_md.drop_reason : ternary;
#ifdef NAT_ENABLE
            // punt packets to cpu if nat.hit == SWITCH_NAT_HIT_TYPE_DEST_NONE
            local_md.nat.hit : ternary;
            local_md.checks.same_zone_check : ternary;
#endif
#ifdef TUNNEL_ENABLE
            local_md.tunnel.terminate : ternary;
#endif
#ifdef MPLS_ENABLE
            hdr.mpls[0].ttl : ternary;
            hdr.mpls[0].isValid() :  ternary;
            local_md.mpls_enable : ternary;
            local_md.flags.mpls_trap : ternary;
            local_md.lkp.mpls_router_alert_label : ternary;
#endif /* MPLS_ENABLE */
#ifdef SRV6_ENABLE
            local_md.flags.srv6_trap : ternary;
#endif
#ifdef BFD_OFFLOAD_ENABLE
	    local_md.flags.bfd_to_cpu : ternary;
#endif /* BFD_OFFLOAD_ENABLE */
            local_md.hostif_trap_id : ternary;
        }

        actions = {
            permit;
            drop;
            copy_to_cpu;
            redirect_to_cpu;
#ifdef INGRESS_SFLOW_ENABLE
            copy_sflow_to_cpu;
            redirect_sflow_to_cpu;
#endif
        }

        const default_action = permit;
        size = table_size;
    }

    @name(".ingress_copp_drop")
    action copp_drop() {
        ig_intr_md_for_tm.copy_to_cpu = 1w0;
        copp_stats.count();
    }

    @name(".ingress_copp_permit")
    action copp_permit() {
        copp_stats.count();
    }

    @name(".ingress_copp")
    table copp {
        key = {
            ig_intr_md_for_tm.packet_color : ternary;
            copp_meter_id : ternary;
        }

        actions = {
            copp_permit;
            copp_drop;
        }

        const default_action = copp_permit;
        size = (1 << switch_copp_meter_id_width + 1);
        counters = copp_stats;
    }

    @name(".ingress_drop_stats_count")
    action count() { stats.count(); }

    @name(".ingress_drop_stats")
    table drop_stats {
        key = {
            local_md.drop_reason : exact @name("drop_reason");
            local_md.ingress_port : exact @name("port");
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        counters = stats;
        size = drop_stats_table_size;
    }

    apply {
        if (!INGRESS_BYPASS(SYSTEM_ACL)) {
            switch(system_acl.apply().action_run) {
#ifdef COPP_ENABLE
                copy_to_cpu : { copp.apply(); }
                redirect_to_cpu : { copp.apply(); }
#endif
                default: {}
            }
        }
        drop_stats.apply();
    }
}

// ----------------------------------------------------------------------------
// Comparison/Logical operation unit (LOU)
// LOU can perform logical operationis such AND and OR on tcp flags as well as comparison
// operations such as LT, GT, EQ, and NE for src/dst UDP/TCP ports.
//
// @param table_size : Total number of supported ranges for src/dst ports.
// ----------------------------------------------------------------------------
control EgressLOU(inout switch_local_metadata_t local_md) {

    const switch_uint32_t table_size = switch_l4_port_label_width;

    //TODO(msharif): Change this to bitwise OR so we can allocate bits to src/dst ports at runtime.
    @name(".set_egress_src_port_label")
    action set_src_port_label(bit<8> label) {
        local_md.l4_src_port_label = label;
    }

    @name(".set_egress_dst_port_label")
    action set_dst_port_label(bit<8> label) {
        local_md.l4_dst_port_label = label;
    }

    @entries_with_ranges(table_size)
    @name(".egress_l4_dst_port")
    table l4_dst_port {
        key = {
            local_md.lkp.l4_dst_port : range;
        }

        actions = {
            NoAction;
            set_dst_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @entries_with_ranges(table_size)
    @name(".egress_l4_src_port")
    table l4_src_port {
        key = {
            local_md.lkp.l4_src_port : range;
        }

        actions = {
            NoAction;
            set_src_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
#if defined(EGRESS_ACL_PORT_RANGE_ENABLE) && defined(L4_PORT_EGRESS_LOU_ENABLE)
        l4_src_port.apply();
        l4_dst_port.apply();
#endif
    }
}

//-----------------------------------------------------------------------------
// Egress MAC ACL
//-----------------------------------------------------------------------------
control EgressMacAcl(in switch_header_t hdr,
                     inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    EGRESS_ACL_ACTIONS

    table acl {
        key = {
            EGRESS_MAC_ACL_KEY
        }

        actions = {
            EGRESS_ACL_ACTION_LIST
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!local_md.flags.bypass_egress) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Egress IPv4 ACL
//-----------------------------------------------------------------------------
control EgressIpv4Acl(in switch_header_t hdr,
                      inout switch_local_metadata_t local_md)(
                      switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    EGRESS_ACL_ACTIONS
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
    EGRESS_ACL_ACTION_MIRROR_IN
#endif

    table acl {
        key = {
            EGRESS_IPV4_ACL_KEY
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
            hdr.ethernet.ether_type : ternary;
#endif
#ifdef ACL_USER_META_ENABLE
            local_md.user_metadata : ternary;
#endif
#ifdef EGRESS_ACL_PORT_RANGE_ENABLE
            local_md.l4_src_port_label : ternary;
            local_md.l4_dst_port_label : ternary;
#endif
#ifdef DIFFSERV_IN_EGRESS_ACL_ENABLE
            hdr.ipv4.diffserv : ternary;
#endif
#ifdef OUT_PORTS_IN_ACL_KEY_ENABLE
            local_md.out_ports_group_label[7:0] : ternary;
#endif
        }

        actions = {
            EGRESS_ACL_ACTION_LIST
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
            mirror_in();
#endif
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!local_md.flags.bypass_egress) {
            acl.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Egress IPv6 ACL
//-----------------------------------------------------------------------------
control EgressIpv6Acl(in switch_header_t hdr,
                      inout switch_local_metadata_t local_md)(
                      switch_uint32_t table_size=512) {

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    EGRESS_ACL_ACTIONS
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
    EGRESS_ACL_ACTION_MIRROR_IN
#endif

    table acl {
        key = {
#ifdef IPV6_ACL_UPPER64_ENABLE
            EGRESS_IPV6_UPPER64_ACL_KEY
#else
            EGRESS_IPV6_ACL_KEY
#endif

#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
            hdr.ethernet.ether_type : ternary;
#endif
#ifdef ACL_USER_META_ENABLE
            local_md.user_metadata : ternary;
#endif
#ifdef EGRESS_ACL_PORT_RANGE_ENABLE
            local_md.l4_src_port_label : ternary;
            local_md.l4_dst_port_label : ternary;
#endif
#ifdef DIFFSERV_IN_EGRESS_ACL_ENABLE
            hdr.ipv6.traffic_class : ternary;
#endif
#ifdef OUT_PORTS_IN_ACL_KEY_ENABLE
            local_md.out_ports_group_label[15:8] : ternary;
#endif
        }

        actions = {
            EGRESS_ACL_ACTION_LIST
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
            mirror_in();
#endif
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!local_md.flags.bypass_egress) {
            acl.apply();
        }
    }
}

control EgressTosMirrorAcl(in switch_header_t hdr,
                           inout switch_local_metadata_t local_md)(
                           switch_uint32_t table_size=512) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    action no_action() {
      stats.count();
    }

    action mirror_out(switch_mirror_meter_id_t meter_index,
                  switch_mirror_session_t session_id) {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;
        local_md.mirror.session_id = session_id;
        local_md.mirror.meter_index = meter_index;
        stats.count();
    }
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
    EGRESS_ACL_ACTION_MIRROR_IN
#endif

    table acl {
        key = {
            hdr.ipv4.diffserv : ternary;
            hdr.ipv6.traffic_class : ternary;
            hdr.ipv4.isValid() : ternary;
            hdr.ipv6.isValid() : ternary;
            local_md.egress_port_lag_label : ternary;
        }

        actions = {
            mirror_out;
            no_action;
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
            mirror_in();
#endif
        }

        const default_action = no_action;
        counters = stats;
        size = table_size;
    }

    apply {
        if (!local_md.flags.bypass_egress) {
            acl.apply();
        }
    }
}
//-----------------------------------------------------------------------------
//
// Egress System ACL
//
//-----------------------------------------------------------------------------
control EgressSystemAcl(
        inout switch_header_t hdr,
        inout switch_local_metadata_t local_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        out egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr)(
        switch_uint32_t table_size=512) {

    const switch_uint32_t drop_stats_table_size = 8192;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) stats;

    @name(".egress_copp_meter")
    Meter<bit<8>>(1 << switch_copp_meter_id_width, MeterType_t.PACKETS) copp_meter;
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) copp_stats;

    switch_copp_meter_id_t copp_meter_id;
    switch_pkt_color_t copp_color;

    @name(".egress_system_acl_drop")
    action drop(switch_drop_reason_t reason_code) {
        local_md.drop_reason = reason_code;
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }

#ifndef EGRESS_COPP_DISABLE
    @name(".egress_system_acl_copy_to_cpu")
    action copy_to_cpu(switch_cpu_reason_t reason_code,
                       switch_copp_meter_id_t meter_id) {
        local_md.cpu_reason = reason_code;
        eg_intr_md_for_dprsr.mirror_type = SWITCH_MIRROR_TYPE_CPU;
        local_md.mirror.type = SWITCH_MIRROR_TYPE_CPU;
        local_md.mirror.session_id = SWITCH_MIRROR_SESSION_CPU;
        local_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;
        copp_color = (bit<2>) copp_meter.execute(meter_id);
        copp_meter_id = meter_id;
    }

    @name(".egress_system_acl_redirect_to_cpu")
    action redirect_to_cpu(switch_cpu_reason_t reason_code,
                           switch_copp_meter_id_t meter_id) {
        copy_to_cpu(reason_code, meter_id);
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }
#endif /* EGRESS_COPP_DISABLE */

    @name(".egress_system_acl_ingress_timestamp")
    action insert_timestamp() {
#ifdef PTP_ENABLE
        hdr.timestamp.setValid();
        hdr.timestamp.timestamp = local_md.ingress_timestamp;
#endif
    }

    @name(".egress_system_acl")
    table system_acl {
        key = {
            eg_intr_md.egress_port : ternary;
            local_md.flags.acl_deny : ternary;

#ifdef MLAG_ENABLE
            local_md.flags.mlag_member : ternary;
            local_md.flags.peer_link : ternary;
#endif
            local_md.checks.mtu : ternary;

#ifdef STP_ENABLE
            local_md.checks.stp : ternary;
#endif
#ifdef WRED_ENABLE
            local_md.flags.wred_drop : ternary;
#endif
#ifdef PFC_ENABLE
            local_md.flags.pfc_wd_drop : ternary;
#endif
#ifdef EGRESS_ACL_METER_ENABLE
            local_md.flags.meter_packet_action : ternary;
#endif
#ifdef EGRESS_PORT_METER_ENABLE
            local_md.flags.port_meter_drop : ternary;
#endif
#ifdef EGRESS_SFLOW_ENABLE
            local_md.sflow.sample_packet : ternary;
#endif
#ifdef PORT_ISOLATION_ENABLE
            local_md.flags.port_isolation_packet_drop : ternary;
            local_md.flags.bport_isolation_packet_drop : ternary;
#endif
            //TODO add more
        }

        actions = {
            NoAction;
            drop;
#ifndef EGRESS_COPP_DISABLE
            copy_to_cpu;
            redirect_to_cpu;
#endif /* EGRESS_COPP_DISABLE */
            insert_timestamp;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @name(".egress_drop_stats_count")
    action count() { stats.count(); }

    @name(".egress_drop_stats")
    table drop_stats {
        key = {
            local_md.drop_reason : exact @name("drop_reason");
            eg_intr_md.egress_port : exact @name("port");
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        counters = stats;
        size = drop_stats_table_size;
    }

#ifndef EGRESS_COPP_DISABLE
    @name(".egress_copp_drop")
    action copp_drop() {
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
        copp_stats.count();
    }

    @name(".egress_copp_permit")
    action copp_permit() {
        copp_stats.count();
    }

    @ways(2)
    @name(".egress_copp")
    table copp {
        key = {
            copp_color : exact;
            copp_meter_id : exact;
        }

        actions = {
            copp_permit;
            copp_drop;
        }

        const default_action = copp_permit;
        size = (1 << switch_copp_meter_id_width + 1);
        counters = copp_stats;
    }
#endif

    apply {
        if (!local_md.flags.bypass_egress) {
            switch(system_acl.apply().action_run) {
#ifndef EGRESS_COPP_DISABLE
                copy_to_cpu : { copp.apply(); }
                redirect_to_cpu : { copp.apply(); }
#endif
                default: {}
            }
        }
        drop_stats.apply();
    }
}

#endif /* _P4_ACL_ */
