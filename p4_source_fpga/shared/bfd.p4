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


#ifdef BFD_OFFLOAD_ENABLE

//###################################################################################
//
// Ingress Pipe
//   1.0 BFD packets from front-panel/recirc ports (bfd_tx==0)
//      1.1 First identify the session associated with the received packet
//      1.2 If the session is not offloaded, send the packet to CPU
//      1.3 Else if session is offloaded, check if the current pipe is the designated
//          pipe for the session. If not, recirculate the packet to current pipe.
//      1.4 Else, get session parameters
//          1.4.1 Set the timer value to rx_mult
//          1.4.2 Drop the packet
//
//    2.0 BFD packets from PktGen (bfd_tx==1)
//        2.1 Get session parameters
//        2.2 Set VRF, rmac_hit and other metadata to route the packet
//        2.3 Check the RX timer value associated with the session
//            2.3.1 If timer is expired, set the timeout action
//            2.3.2 else decrement the timer
//            2.3.3 If timer value is zero, session is not offloaded, drop the packet
//        2.4 Modify the packet headers and other metadata based on session info
//            so tx packet can be routed to BFD neighbor
//
//    3.0 Based on previous lookups and timer checks, set the pkt_action for rest
//        of the pipeline

//###################################################################################

//-----------------------------------------------------------------------------
// For BFD packets received from packetgen:
//     -- If BFD session exists on this pipe, get session parameters
//     -- else, drop the packet
//-----------------------------------------------------------------------------
control BfdTxSession(
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md) {

    action bfd_tx_drop_pkt() {
        local_md.bfd.pkt_action = BFD_PKT_ACTION_DROP;
        local_md.bypass = SWITCH_INGRESS_BYPASS_ALL;
    }

    action bfd_tx_session_info(
        bfd_multiplier_t rx_mult, bfd_multiplier_t tx_mult,
        bfd_session_t session_id, switch_vrf_t vrf
    ) {
        local_md.bfd.session_id = session_id;
        local_md.bfd.rx_mult = rx_mult;
        local_md.bfd.tx_mult = tx_mult;
        local_md.bfd.session_offload = 1;
        local_md.vrf = vrf;
        local_md.flags.rmac_hit = true;
        local_md.bfd.pkt_action = BFD_PKT_ACTION_INVALID;
        local_md.bypass = ~SWITCH_INGRESS_BYPASS_L3;
    }

    action bfd_tx_session_v4(
        bfd_multiplier_t rx_mult, bfd_multiplier_t tx_mult,
        bfd_session_t session_id, switch_vrf_t vrf,
        bit<32> sip, bit<32> dip, bit<16> sport, bit<16> dport)
    {
        bfd_tx_session_info(rx_mult, tx_mult, session_id, vrf);
        hdr.ipv4.dst_addr = dip;
        local_md.lkp.ip_dst_addr[95:64] = dip;

	/* Assuming that sip/sport/dport are common across all bfd sessions
        hdr.ipv4.src_addr = sip;
        hdr.udp.src_port = sport;
        hdr.udp.dst_port = dport;
        local_md.lkp.ip_src_addr[95:64] = sip;
        local_md.lkp.l4_src_port = sport;
        local_md.lkp.l4_dst_port = dport; */
    }

    action bfd_tx_session_v6(
        bfd_multiplier_t rx_mult, bfd_multiplier_t tx_mult,
        bfd_session_t session_id, switch_vrf_t vrf,
        bit<128> sip, bit<128> dip, bit<16> sport, bit<16> dport)
    {
        bfd_tx_session_info(rx_mult, tx_mult, session_id, vrf);
        local_md.lkp.ip_dst_addr = dip;
        hdr.ipv6.dst_addr = dip;
//      hdr.ipv6.src_addr = sip;
//      hdr.udp.src_port = sport;
//      hdr.udp.dst_port = dport;
//      local_md.lkp.ip_src_addr = sip;
//      local_md.lkp.l4_src_port = sport;
//      local_md.lkp.l4_dst_port = dport;
    }

    table bfd_tx_session {
        key = {
            local_md.bypass : exact;
            /* Lower 12-bits of bypass are overloaded to carry
               session_id. Actions from this table will overwrite the
               local_md.bypass with the bypass info for rest of the pipeline */
        }
        actions = {
            /* session_id and other info for session that is handled on this pipe */
            bfd_tx_session_v4;
            bfd_tx_session_v6;
            /* Drop packets not handled by this pipe */
            bfd_tx_drop_pkt;
        }
        const default_action = bfd_tx_drop_pkt;
        size = BFD_PER_PIPE_SESSION_SIZE;
//      counters = stats;
    }

    apply {
        /* Get session information for BFD Tx packets from packet_gen */
        bfd_tx_session.apply();;
    }
}


//-----------------------------------------------------------------------------
// For BFD Rx packets: Lookup BFD header fields to identify the session
//     -- If BFD session exists on this pipe, get session parameters
//     -- else, if session is offloaded, route to the correct pipeline
//     -- else, if session is not offloaded, send the packet to local CPU
//
//  Rx Sessions are programmed on all the pipes since rx packet can
//  arrive on any pipe
//  If any of the session parameters have changed, lookup will miss in this
//  table and packet will be sent to CPU. System_ACL is expected to have an
//  entry to trap BFD packets.
//-----------------------------------------------------------------------------

control BfdRxSession(in switch_header_t hdr,
    inout switch_local_metadata_t local_md,
    out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action bfd_rx_session_miss() {
    }

    action bfd_rx_session_info(bfd_multiplier_t rx_mult, bfd_session_t session_id,
        bfd_pipe_t pktgen_pipe, switch_port_t recirc_port) {
        local_md.bfd.session_id = session_id;
        local_md.bfd.rx_mult = rx_mult;
        local_md.bfd.pktgen_pipe = pktgen_pipe;
        local_md.bfd.session_offload = 1;
	/* even though recirc_port is set here, packets for the sessions offloaded
           on this pipe will be dropped later in the pipeline */
        ig_intr_md_for_tm.ucast_egress_port = recirc_port;
        /* skip rest of the pipeline */
	local_md.bypass = SWITCH_INGRESS_BYPASS_ALL;
        local_md.flags.bypass_egress = true;
    }

    table bfd_rx_session {
        key = {
            hdr.bfd.my_discriminator : exact;
            hdr.bfd.your_discriminator : exact;
            hdr.bfd.version : exact;
            hdr.bfd.flags : exact;
            hdr.bfd.desired_min_tx_interval : exact;
            hdr.bfd.req_min_rx_interval : exact;
//            hdr.ipv4.isValid() : exact;
        }
        actions = {
            bfd_rx_session_info;
            bfd_rx_session_miss;
        }
	const default_action = bfd_rx_session_miss;
        size = BFD_SESSION_SIZE;
    }

    apply {
        if (hdr.bfd.isValid()) {
            bfd_rx_session.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Check and reset BFD Rx timers
//     -- RX timers check is triggered by BFD_TX packets from the packet_gen
//     -- RX timers reset is triggered by BFD_RX packets from the front-panel
//     -- only the sessions which are handled on this pipe are programmed
//-----------------------------------------------------------------------------

control BfdRxTimer(inout switch_local_metadata_t local_md) {

    /* Register to store timer value per session
     * register value -
     *  0 => reserved value to indicate no-offload
     *  1 => rx timeout
     * >1 => remaining rx multiplier
    */

    Register<bfd_timer_t, bfd_session_t>(BFD_SESSION_SIZE, 0) timer_reg;

    // If offload is in effect, set the detection multiplier count to
    // sessions's rx_mult
    RegisterAction<bfd_timer_t, bfd_session_t, bfd_pkt_action_t>(timer_reg) timer_reset = {
        void apply(inout bfd_timer_t reg, out bit<2> rv) {
            /* 0x0 = no offload */
            if (reg != 0) {
                reg = local_md.bfd.rx_mult;
            }
        }
    };

    // If offload is in effect, check and decrement the counter
    RegisterAction<bfd_timer_t, bfd_session_t, bfd_pkt_action_t>(timer_reg) timer_check = {
        void apply(inout bfd_timer_t reg, out bfd_pkt_action_t rv) {
            if (reg == 0) {
                rv = BFD_PKT_ACTION_DROP;
            } else if (reg == 1) {
		reg = reg - 1; // Stop offload
                rv = BFD_PKT_ACTION_TIMEOUT;
            } else if (reg != 0x0) {
                reg = reg - 1;
            }
        }
    };

    action bfd_rx_timer_check(bfd_session_t session_id) {
        /* Check and decrement timer for rx session */
        local_md.bfd.pkt_action = timer_check.execute(session_id);
    }

    action bfd_rx_timer_reset(bfd_session_t session_id) {
        /* Reset timer if a bfd packet was received */
        timer_reset.execute(session_id);
    }

    table bfd_rx_timer {
        key = {
            /*
            * offload is a GW condition before executing this table
            *
            * offload  pkt_tx  session_id  action
            *  0       X       X           nop (default)
            *  1       0       id          timer_reset
            *  1       1       id          timer_check
            */
            local_md.bfd.pkt_tx : exact;
            local_md.bfd.session_id : exact;
        }
        actions = {
            bfd_rx_timer_reset;
            bfd_rx_timer_check;
        }
        size = 2*BFD_PER_PIPE_SESSION_SIZE;
    }

    apply {
        if (local_md.bfd.session_offload==1) {
            bfd_rx_timer.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Decision table for final packet action
//-----------------------------------------------------------------------------

control BfdPktAction(inout switch_local_metadata_t local_md) {

    action bfd_pkt_to_cpu() {
        local_md.flags.bfd_to_cpu = true;
        /* session_id in carried in the reason_code field of cpu header. 
           see redirect_bfd_to_cpu action in acl.p4 for details */
    }

    action bfd_recirc_to_pktgen_pipe() {
        local_md.bfd.rx_recirc = 1;
    }

    action bfd_tx_pkt() {
        /* route packet as usual */
    }

    action bfd_drop_pkt() {
        local_md.drop_reason = SWITCH_DROP_REASON_BFD;
    }

    table bfd_pkt_action {
        key = {
            /*
            * offload is a GW condition before executing this table
            * offload  pkt_tx  pkt_action  pktgen_pipe action
            *    0     X       X           X           N/A
            *    1     0       NORMAL      this_pipe   drop
            *    1     0       NORMAL      X           recirc - !this_pipe
            *    1     0       TIMEOUT     X           nop // ?? who sets action==timeout for rx packets
            *    1     1       NORMAL      X           bfd_tx_pkt
            *    1     1       TIMEOUT     X           to_cpu (timeout)
            *          all the rest - drop
            */
            local_md.bfd.pkt_tx : exact;
            local_md.bfd.pkt_action : exact;
            local_md.bfd.pktgen_pipe : ternary;
        }
        actions = {
            bfd_pkt_to_cpu;
            bfd_recirc_to_pktgen_pipe;
            bfd_tx_pkt;
            bfd_drop_pkt;
        }
        size = MIN_TABLE_SIZE;
    }

    apply {
        if (local_md.bfd.session_offload == 1) {
            bfd_pkt_action.apply();
        }
    }
}

//###################################################################################
//
// Egress Pipe
// Two kinds of BFD packets need to be handled in egress pipe
//     - BFD Rx packets that need to be recirculated to the designated pipe
//     - BFD Tx packets that need to be transmitted after checking the timer
//
//###################################################################################

control BfdTxTimer(
    inout switch_header_t hdr,
    inout switch_local_metadata_t local_md,
    out egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    // Register to store timer value per session
    Register<bfd_timer_t, bfd_session_t>(BFD_SESSION_SIZE, 0) timer_reg;

    RegisterAction<bfd_timer_t, bfd_session_t, bit<1>>(timer_reg) timer_check = {
        void apply(inout bfd_timer_t reg, out bit<1> rv) {
            /* Increment register if it is less than tx_mult
               Once it reaches tx_mult, reset the register and output TRUE */
            if (reg < local_md.bfd.tx_mult) {
                reg = reg + 1;
            } else {
                rv  = 1;
                reg = 0;
            }
        }
    };

    action bfd_drop_pkt() {
        local_md.drop_reason = SWITCH_DROP_REASON_BFD;
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    action bfd_tx_timer_check(bfd_session_t session_id,
        bit<8> detect_multi,
        bit<32> my_discriminator,
        bit<32> your_discriminator,
        bit<32> desired_min_tx_interval,
        bit<32> req_min_rx_interval
    ) {
        /* Check timer for tx session */
        local_md.bfd.tx_timer_expired = timer_check.execute(session_id);
        /* Modify bfd tx packet based on session info */
        hdr.bfd.detect_multi = detect_multi;
        hdr.bfd.my_discriminator = my_discriminator;
        hdr.bfd.your_discriminator = your_discriminator;
        hdr.bfd.desired_min_tx_interval = desired_min_tx_interval;
        hdr.bfd.req_min_rx_interval = req_min_rx_interval;
        hdr.bfd.req_min_echo_rx_interval = req_min_rx_interval;
        /* Note: outgoing TTL value in IP header needs to be 255. Assuming that
           appropriate value of ttl has been set correctly in the pktgen itself */
    }

    table bfd_tx_timer {
        key = {
            local_md.bfd.pkt_action : exact;
            local_md.bfd.session_id : exact;
        }
        actions = {
            bfd_tx_timer_check;
            bfd_drop_pkt;
        }
        size = BFD_SESSION_SIZE;
    }

    apply {
        if ((local_md.bfd.session_offload==1) && (local_md.bfd.pkt_tx != 0)) {
            bfd_tx_timer.apply();
            if (local_md.bfd.tx_timer_expired == 0) {
                bfd_drop_pkt();
            }
        }
    }
}

#endif /* BFD_OFFLOAD_ENABLE */
