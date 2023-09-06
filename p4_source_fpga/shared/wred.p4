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


//-------------------------------------------------------------------------------------------------
// Weighted Random Early Dropping (WRED)
//
// @param hdr : Parse headers. Only ipv4.diffserv or ipv6.traffic_class are modified.
// @param local_md : Egress metadata fields.
// @param eg_intr_md
// @param flag : A flag indicating that the packet should get dropped by system ACL.
//-------------------------------------------------------------------------------------------------
control WRED(inout switch_header_t hdr,
             in switch_local_metadata_t local_md,
             in egress_intrinsic_metadata_t eg_intr_md,
             out bool wred_drop) {

    switch_wred_index_t index;

    // Flag indicating that the packet needs to be marked/dropped.
    bit<1> wred_flag;
    const switch_uint32_t wred_size = 1 << switch_wred_index_width;

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".egress_wred.wred")
    Wred<bit<19>, switch_wred_index_t>(wred_size, 1 /* drop value*/, 0 /* no drop value */) wred;

    // -----------------------------------------------------------
    // Select a profile and apply wred filter
    // A total of 1k profiles are supported.
    // -----------------------------------------------------------
    @name(".egress_wred.set_wred_index")
    action set_wred_index(switch_wred_index_t wred_index) {
        index = wred_index;
        wred_flag = (bit<1>) wred.execute(local_md.qos.qdepth, wred_index);
    }

    // Asymmetric table to get the attached WRED profile.
    @name(".egress_wred.wred_index")
    table wred_index {
        key = {
           eg_intr_md.egress_port : exact @name("port");
           local_md.qos.qid : exact @name("qid");
           local_md.qos.color : exact @name("color");
        }

        actions = {
            NoAction;
            set_wred_index;
        }

        const default_action = NoAction;
        size = wred_size;
    }

    // -----------------------------------------------------------
    // Mark or Drop packet based on WRED profile and ECN bits
    // -----------------------------------------------------------
    @name(".egress_wred.set_ipv4_ecn")
    action set_ipv4_ecn() {
        hdr.ipv4.diffserv[1:0] = SWITCH_ECN_CODEPOINT_CE;
        wred_drop = false;
    }

    @name(".egress_wred.set_ipv6_ecn")
    action set_ipv6_ecn() {
        hdr.ipv6.traffic_class[1:0] = SWITCH_ECN_CODEPOINT_CE;
        wred_drop = false;
    }

    // Packets from flows that are not ECN capable will continue to be dropped by RED (as was the
    // case before ECN) -- RFC2884
    @name(".egress_wred.drop")
    action drop() {
        wred_drop = true;
    }

    @name(".egress_wred.v4_wred_action")
    table v4_wred_action {
        key = {
            index : exact;
            hdr.ipv4.diffserv[1:0] : exact;
        }

        actions = {
            NoAction;
            drop;
            set_ipv4_ecn;
        }

        // Requires 3 entries per WRED profile to drop or mark IPv4 packets.
        size = 3 * wred_size;
    }

    @name(".egress_wred.v6_wred_action")
    table v6_wred_action {
        key = {
            index : exact;
            hdr.ipv6.traffic_class[1:0] : exact;
        }

        actions = {
            NoAction;
            drop;
            set_ipv6_ecn;
        }

        // Requires 3 entries per WRED profile to drop or mark IPv6 packets.
        size = 3 * wred_size;
    }

    // -----------------------------------------------------------------------------------------------
    // Counts packets marked or dropped by WRED. Packets "allowed" by wred logic are not counted here.
    // -----------------------------------------------------------------------------------------------
    @name(".egress_wred.count")
    action count() { stats.count(); }

    @ways(2)
    @name(".egress_wred.wred_stats")
    table wred_stats {
        key = {
            eg_intr_md.egress_port : exact @name("port");
            local_md.qos.qid : exact @name("qid");
            local_md.qos.color : exact @name("color");
            wred_drop : exact;
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        size = 2 * wred_size;
        counters = stats;
    }

    apply {
#ifdef WRED_ENABLE
        if (!local_md.flags.bypass_egress)
            wred_index.apply();

        if (!local_md.flags.bypass_egress && wred_flag == 1) {
            if(hdr.ipv4.isValid()) {
                switch(v4_wred_action.apply().action_run) {
                    NoAction : {}
                    default : { wred_stats.apply(); }
                }
            } else if(hdr.ipv6.isValid()) {
                switch(v6_wred_action.apply().action_run) {
                    NoAction : {}
                    default : { wred_stats.apply(); }
                }
            }
        }
#endif
    }
}
