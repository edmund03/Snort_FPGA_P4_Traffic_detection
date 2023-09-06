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


#ifndef _P4_METER_
#define _P4_METER_

#include "acl.p4"

//-------------------------------------------------------------------------------------------------
// Storm Control
//
// Monitors incoming traffic and prevents the excessive traffic on a particular interface by
// dropping the traffic. Each port has a single storm control levels for all types of traffic
// (broadcast, multicast, and unicast).
//
// @param local_md : Ingress metadata fields
// @param pkt_type : One of Unicast, Multicast, or Broadcast packet types.
// @param flag : Indicating whether the packet should get dropped or not.
// @param table_size : Size of the storm control table [per pipe]
// @param meter_size : Size of storm control meters [global pool]
// Stats table size must be 512 per pipe - each port with 6 stat entries [2 colors per pkt-type]
//-------------------------------------------------------------------------------------------------
control StormControl(inout switch_local_metadata_t local_md,
                     in switch_pkt_type_t pkt_type,
                     out bool flag)(
                     switch_uint32_t table_size=256,
                     switch_uint32_t meter_size=1024) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS) storm_control_stats;
    @name(".storm_control.meter")
    Meter<bit<16>>(meter_size, MeterType_t.PACKETS) meter;

    @name(".storm_control.count")
    action count() {
        storm_control_stats.count();
        flag = false;
    }

    @name(".storm_control.drop_and_count")
    action drop_and_count() {
        storm_control_stats.count();
        flag = true;
    }

    @name(".storm_control.stats")
    table stats {
        key = {
            local_md.qos.storm_control_color: exact;
            pkt_type : ternary;
            local_md.ingress_port: exact;
            local_md.flags.dmac_miss : ternary;
        }

        actions = {
            @defaultonly NoAction;
            count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size*2;
        counters = storm_control_stats;
    }

    @name(".storm_control.set_meter")
    action set_meter(bit<16> index) {
        local_md.qos.storm_control_color = (bit<2>) meter.execute(index);
    }

    @name(".storm_control.storm_control")
    table storm_control {
        key =  {
            local_md.ingress_port : exact;
            pkt_type : ternary;
            local_md.flags.dmac_miss : ternary;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
#ifdef STORM_CONTROL_ENABLE
        if (!INGRESS_BYPASS(STORM_CONTROL))
            storm_control.apply();

        if (!INGRESS_BYPASS(STORM_CONTROL))
            stats.apply();
#endif
    }
}

//-------------------------------------------------------------------------------------------------
// Ingress Mirror Meter
//-------------------------------------------------------------------------------------------------
control IngressMirrorMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".ingress_mirror_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.PACKETS) meter;
    switch_pkt_color_t color;

    @name(".ingress_mirror_meter.mirror_and_count")
    action mirror_and_count() {
        stats.count();
    }

    @name(".ingress_mirror_meter.no_mirror_and_count")
    action no_mirror_and_count() {
        stats.count();
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }

    @ways(2)
    @name(".ingress_mirror_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.mirror.meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            mirror_and_count;
            no_mirror_and_count;
        }

        const default_action = NoAction;
        size = table_size*2;
        counters = stats;
    }

    @name(".ingress_mirror_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".ingress_mirror_meter.meter_index")
    table meter_index {
        key =  {
            local_md.mirror.meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
#ifdef INGRESS_MIRROR_METER_ENABLE
            meter_index.apply();
            meter_action.apply();
#endif
    }
}

//-------------------------------------------------------------------------------------------------
// Egress Mirror Meter
//-------------------------------------------------------------------------------------------------
control EgressMirrorMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    @name(".egress_mirror_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.PACKETS) meter;
    switch_pkt_color_t color;

    @name(".egress_mirror_meter.mirror_and_count")
    action mirror_and_count() {
        stats.count();
    }

    @name(".egress_mirror_meter.no_mirror_and_count")
    action no_mirror_and_count() {
        stats.count();
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }

    @ways(2)
    @name(".egress_mirror_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.mirror.meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            mirror_and_count;
            no_mirror_and_count;
        }

        const default_action = NoAction;
        size = table_size*2;
        counters = stats;
    }

    @name(".egress_mirror_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".egress_mirror_meter.meter_index")
    table meter_index {
        key =  {
            local_md.mirror.meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
#ifdef EGRESS_MIRROR_METER_ENABLE
            meter_index.apply();
            meter_action.apply();
#endif
    }
}

#ifdef INGRESS_PORT_METER_ENABLE
//-------------------------------------------------------------------------------------------------
// Ingress Port Meter
//-------------------------------------------------------------------------------------------------
control IngressPortMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    @name(".ingress_port_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    @name(".ingress_port_meter.count")
    action count() {
        stats.count();
        local_md.flags.port_meter_drop = false;
    }

    @name(".ingress_port_meter.drop_and_count")
    action drop_and_count() {
        stats.count();
        local_md.flags.port_meter_drop = true;
    }

    @name(".ingress_port_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.qos.port_meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size*3;
        counters = stats;
    }

    @name(".ingress_port_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".ingress_port_meter.meter_index")
    table meter_index {
        key =  {
            local_md.qos.port_meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}
#endif

#ifdef EGRESS_PORT_METER_ENABLE
//-------------------------------------------------------------------------------------------------
// Egress Port Meter
//-------------------------------------------------------------------------------------------------
control EgressPortMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    @name(".egress_port_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    @name(".egress_port_meter.count")
    action count() {
        stats.count();
        local_md.flags.port_meter_drop = false;
    }

    @name(".egress_port_meter.drop_and_count")
    action drop_and_count() {
        stats.count();
        local_md.flags.port_meter_drop = true;
    }

    @name(".egress_port_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.qos.port_meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size*3;
        counters = stats;
    }

    @name(".egress_port_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".egress_port_meter.meter_index")
    table meter_index {
        key =  {
            local_md.qos.port_meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}
#endif

#ifdef INGRESS_ACL_METER_ENABLE
//-------------------------------------------------------------------------------------------------
// Ingress ACL Meter
//-------------------------------------------------------------------------------------------------
control IngressAclMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    @name(".ingress_acl_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    @name(".ingress_acl_meter.count")
    action count(switch_packet_action_t packet_action) {
        stats.count();
        local_md.flags.meter_packet_action = packet_action;
    }

    @name(".ingress_acl_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.qos.acl_meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        size = table_size*3;
        counters = stats;
    }

    @name(".ingress_acl_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".ingress_acl_meter.meter_index")
    table meter_index {
        key =  {
            local_md.qos.acl_meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}
#endif

#ifdef EGRESS_ACL_METER_ENABLE
//-------------------------------------------------------------------------------------------------
// Egress ACL Meter
//-------------------------------------------------------------------------------------------------
control EgressAclMeter(inout switch_local_metadata_t local_md)(
                     switch_uint32_t table_size=256) {
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;
    @name(".egress_acl_meter.meter")
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    @name(".egress_acl_meter.count")
    action count(switch_packet_action_t packet_action) {
        stats.count();
        local_md.flags.meter_packet_action = packet_action;
    }

    @name(".egress_acl_meter.meter_action")
    table meter_action {
        key = {
            color: exact;
            local_md.qos.acl_meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        size = table_size*3;
        counters = stats;
    }

    @name(".egress_acl_meter.set_meter")
    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    @name(".egress_acl_meter.meter_index")
    table meter_index {
        key =  {
            local_md.qos.acl_meter_index : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}
#endif

#endif /* _P4_METER_ */
