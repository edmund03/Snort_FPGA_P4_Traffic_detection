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


control IngressSfcEpochInit(in bit<32> timestamp_us,
                            out switch_sfc_local_metadata_t sfc) {

   /*
    * Dependencies:
    *   before:
    *     - IngressSfcTrigger
    *   after
    *     - N/A
    */

    Register<sfc_pause_epoch_register_t, bit<1>>(32w1, {32w0, 32w0}) reg_filter_epoch;

    /**
     * Determine if the epoch is run out and if the filter banks should be switched.
     *
     * @param tstamp: the current timestamp
     * @param epoch_duration: the duration of a new epoch
     * @return rv_bank_switch_idx: Two values in the two lsbs:
                                    [1:1] = switch bank, yes(1) or no(0)
                                    [0:0] = bank idx to use, 0 or 1
     **/
    RegisterParam<bit<32>>(0xffffffff) suppression_epoch_duration;
    RegisterAction<sfc_pause_epoch_register_t, bit<1>, bit<2>>(reg_filter_epoch) get_bank_switch_idx = {
        void apply(inout sfc_pause_epoch_register_t value, out bit<2> rv_bank_switch_idx){
            if (((timestamp_us - value.current_epoch_start)
                  > suppression_epoch_duration.read())
                || (timestamp_us < value.current_epoch_start)) {
                value.current_epoch_start = timestamp_us;
                // Invert value.bank_idx_changed[0:0]
                // Set value.bank_idx_changed[1:1] = 1
                value.bank_idx_changed = ~(value.bank_idx_changed & 32w1);
            } else {
                // Keep value.bank_idx_changed[0:0]
                // Set value.bank_idx_changed[1:1] = 0
                value.bank_idx_changed = value.bank_idx_changed & 32w1;
            }
            rv_bank_switch_idx = value.bank_idx_changed[1:0];
        }
    };

    action do_get_switch_bank_idx() {
        sfc.switch_bank_idx = get_bank_switch_idx.execute(1w0);
    }

    apply {
        do_get_switch_bank_idx();
  }
}


/*
 *
 * Dependencies:
 *   before:
 *     - IngressSfcTrigger
 *     - add_bridged_md
 *   after:
 *     - nexthop
 *     - qos_map
 *     - traffic_class
 */
control IngressSfcPrepare(in ghost_intrinsic_metadata_t g_intr_md,
                          inout switch_header_t hdr,
                          inout switch_local_metadata_t ig_md)
                          (const_t queue_idx_size) {

#ifndef SFC_GHOST_DISABLE
    IngressReadOverThreshold() ghost_read_q_over_threshold;
#endif

    Hash<bit<16>>(HashAlgorithm_t.CRC16) suppression_hash_0;
    Hash<bit<16>>(HashAlgorithm_t.RANDOM) suppression_hash_1;
    DirectCounter<bit<8>>(CounterType_t.PACKETS_AND_BYTES) stats_classify;

    action do_update_stats_classify() {
        stats_classify.count();
    }
    
    // Important: traffic on RDMA control TCs has to be marked
    // as ig_md.sfc.type=SfcPacketType.TcSignalEnabled
    action do_set_sfc(SfcPacketType sfc_packet_type) {
        ig_md.sfc.type = sfc_packet_type;
        do_update_stats_classify();
    }

    action do_set_no_sfc() {
        ig_md.sfc.type = SfcPacketType.None;
        do_update_stats_classify();
    }
    /* we can keep adding the header check to limit SFC takes effect only at ipv4 rocev2. */
    /* rocev2_bth is only parsed with the outer header. Checking the EtherType
       for 0x800 ensures IPv4 and the absence of VLAN tags. */
    table classify_sfc {
        key = {
            ig_md.qos.tc             : exact@name("tc");
            hdr.rocev2_bth.isValid() : exact@name("bth");
            hdr.ethernet.ether_type  : exact@name("ethertype");
            ig_md.flags.routed       : exact@name("routed");
        }
        actions = {
            do_set_sfc;
            do_set_no_sfc;
        }
        const default_action = do_set_no_sfc;
        size = 256;
        counters = stats_classify;
    }

    action do_get_suppression_hash() {
        ig_md.sfc.suppression_hash_0 = suppression_hash_0.get({ig_md.lkp.ip_src_addr,
                                                           ig_md.lkp.ip_dst_addr,
                                                           // Yes, the next line is dscp
                                                           ig_md.lkp.ip_tos[7:2]});
        ig_md.sfc.suppression_hash_1 = suppression_hash_1.get({ig_md.lkp.ip_src_addr,
                                                           ig_md.lkp.ip_dst_addr,
                                                           // Yes, the next line is dscp
                                                           ig_md.lkp.ip_tos[7:2]});
    }

    action do_set_queue_register_idx(sfc_queue_idx_t queue_register_idx) {
        ig_md.sfc.queue_register_idx = queue_register_idx;
    }

    table set_queue_register_idx {
        key = {
            ig_md.egress_port : exact@name("port");
            ig_md.qos.qid : exact@name("qid");
        }
        actions = {
            do_set_queue_register_idx;
            NoAction;
        }
        default_action = NoAction;
        size = queue_idx_size;
    }

    apply {
#ifdef SFC_ENABLE
        do_get_suppression_hash();
#ifndef SFC_GHOST_DISABLE
        ghost_read_q_over_threshold.apply(ig_md.egress_port,
                                          ig_md.qos.qid,
                                          g_intr_md,
                                          ig_md.sfc);
#endif
        classify_sfc.apply();
        // Set the queue index for egress processing
        set_queue_register_idx.apply();
#endif
    }
}


/*
 *
 * Dependencies:
 *   before:
 *     - N/A
 *   after:
 *     - IngressSfcEpochInit
 *     - IngressSfcPrepare
 *     - SystemAcl
 */
control IngressSfcTrigger(inout switch_local_metadata_t ig_md) {

    DirectCounter<bit<8>>(CounterType_t.PACKETS_AND_BYTES) stats_suppression;
    DirectCounter<bit<8>>(CounterType_t.PACKETS_AND_BYTES) stats_mirror;

    bit<1> fr0 = 0;
    bit<1> fr1 = 0;

    Register<bit<1>, sfc_suppression_filter_idx_t>(sfc_suppression_filter_cnt, 0) pause_filter_bank0_filter0;
    Register<bit<1>, sfc_suppression_filter_idx_t>(sfc_suppression_filter_cnt, 0) pause_filter_bank0_filter1;

    Register<bit<1>, sfc_suppression_filter_idx_t>(sfc_suppression_filter_cnt, 0) pause_filter_bank1_filter0;
    Register<bit<1>, sfc_suppression_filter_idx_t>(sfc_suppression_filter_cnt, 0) pause_filter_bank1_filter1;

    RegisterAction<bit<1>, sfc_suppression_filter_idx_t, bit<1>>(pause_filter_bank0_filter0) bank0_filter0 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 0b1;
        }
    };

    RegisterAction<bit<1>, sfc_suppression_filter_idx_t, bit<1>>(pause_filter_bank0_filter1) bank0_filter1 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 0b1;
        }
    };

    RegisterAction<bit<1>, sfc_suppression_filter_idx_t, bit<1>>(pause_filter_bank1_filter0) bank1_filter0 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 0b1;
        }
    };

    RegisterAction<bit<1>, sfc_suppression_filter_idx_t, bit<1>>(pause_filter_bank1_filter1) bank1_filter1 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 0b1;
        }
    };

    action do_update_stats_suppression() {
        stats_suppression.count();
    }

    /* Putting both register accesses in the same action fails, the compiler complains:
      The action sfc_trigger_do_check_suppression_bank0 uses Register SwitchIngress.sfc_trigger.pause_filter_bank0_filter1 but does not use Register SwitchIngress.sfc_trigger.pause_filter_bank1_filter1.
      The action sfc_trigger_do_check_suppression_bank1 uses Register SwitchIngress.sfc_trigger.pause_filter_bank1_filter1 but does not use Register SwitchIngress.sfc_trigger.pause_filter_bank0_filter1.
        The Tofino architecture requires all indirect externs to be addressed with the same expression across all actions they are used in.
        You can also try to distribute individual indirect externs into separate tables.

      Therefore, the switch statement is used to the same effect, see below.
    */
    action do_check_suppression_bank0() {
        do_update_stats_suppression();
    }
    action do_check_suppression_bank1() {
        do_update_stats_suppression();
    }

    table decide_suppression {
        key = {
            ig_md.sfc.type : ternary@name("sfc_type");
            ig_md.mirror.type : ternary@name("mirror_type");
            ig_md.drop_reason : ternary@name("drop_reason");
            ig_md.sfc.qlength_over_threshold : ternary@name("qlength_over_threshold");
            ig_md.sfc.switch_bank_idx[0:0] : ternary@name("bank_idx");

        }
        actions = {
            do_update_stats_suppression;
            do_check_suppression_bank0;
            do_check_suppression_bank1;
        }
        default_action = do_update_stats_suppression;
        size = 16;
        counters = stats_suppression;
    }

    action do_update_stats_mirror() {
        stats_mirror.count();
    }

    Register<bit<32>, bit<9>>(512,0) recirculation_port_pkt_count;
    RegisterAction<bit<32>, bit<9>, bit<32>>(recirculation_port_pkt_count) recirculation_port_pkt_count_increase = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    // Trigger the switch.p4 mirror logic
    action do_set_mirroring(switch_mirror_session_t sid) {
        ig_md.mirror.session_id = sid;
        // These variables trigger the switch.p4 mirror logic
        ig_md.mirror.type = SWITCH_MIRROR_TYPE_SFC;
        ig_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
        // Statistics
        do_update_stats_mirror();
        recirculation_port_pkt_count_increase.execute(ig_md.egress_port);
    }

    table decide_mirroring {
        key = {
            ig_md.egress_port[8:7] : ternary@name("pipe_id");
            ig_md.sfc.type : ternary@name("sfc_type");
            ig_md.mirror.type : ternary@name("mirror_type");
            ig_md.drop_reason : ternary@name("drop_reason");
            ig_md.sfc.qlength_over_threshold : ternary@name("qlength_over_threshold");
            fr0 : ternary;
            fr1 : ternary;
            
        }
        actions = {
            do_update_stats_mirror;
            do_set_mirroring;
        }
        default_action = do_update_stats_mirror;
        size = 16;
        counters = stats_mirror;
    }

    apply {
#ifdef SFC_ENABLE
        /* Always clear the register banks independently of the packet
           type to avoid clock overflows from having an impact on the
           suppression. */

        // switch_bank_idx[1:1]: switch bank
        // switch_bank_idx[0:0]: bank idx to use
        if (ig_md.sfc.switch_bank_idx == 2w0b10) {
            // We switched filters, clear the old one
            pause_filter_bank1_filter0.clear(1w0,1w0);
            pause_filter_bank1_filter1.clear(1w0,1w0);
        } else if (ig_md.sfc.switch_bank_idx == 2w0b11) {
            // We switched filters, clear the old one
            pause_filter_bank0_filter0.clear(1w0,1w0);
            pause_filter_bank0_filter1.clear(1w0,1w0);
        }

        // Decide if suppression filter should be run
        switch (decide_suppression.apply().action_run) {
            do_check_suppression_bank0: {
                fr0 = bank0_filter0.execute(ig_md.sfc.suppression_hash_0);
                fr1 = bank0_filter1.execute(ig_md.sfc.suppression_hash_1);
            }
            do_check_suppression_bank1: {
                fr0 = bank1_filter0.execute(ig_md.sfc.suppression_hash_0);
                fr1 = bank1_filter1.execute(ig_md.sfc.suppression_hash_1);
            }
            default: { }
        }

        // Decide to send a trigger via mirror
        decide_mirroring.apply();
#endif
    }
}


/*
 *
 * Dependencies:
 *   after:
 *     - EgressPortMapping
 */
control EgressSfc(in egress_intrinsic_metadata_t eg_intr_md,
                  in switch_qos_metadata_t qos,
                  inout switch_header_t hdr,
                  inout switch_sfc_local_metadata_t sfc)
                 (const_t queue_idx_size) {

    DirectCounter<bit<8>>(CounterType_t.PACKETS_AND_BYTES) stats_time_conversion;

    // Egress thread: queue depth value
    Register<sfc_qd_threshold_register_t, sfc_queue_idx_t>(queue_idx_size) reg_qdepth;

    /*
     * SfcPacketType.Data packet: write queue depth
     * How set qdepth_drain_cells for testing:
     * Override qdepth_drain_cells only if in the existing value the msb is not set.
     * Since the qdepth value in eg_md is 19 bits only, and the register is 32 bit,
     * the msb can only be set through the control plane. For testing, the control
     * has to write a qdepth_drain_cells value with the msb set, then data packets
     * will not override the value in the register. If the msb is not set, they will,
     * as is expected for operating SFC.
     */
    RegisterAction<sfc_qd_threshold_register_t, sfc_queue_idx_t, int<32>>(reg_qdepth) qd_write = {
        void apply(inout sfc_qd_threshold_register_t value) {
            // For testing: if the msb is set, keep the existing value.
            // Since qdepth is bit<19> it should never set this bit just by writing a normal value.
            if (value.qdepth_drain_cells < msb_set_32b) {
                value.qdepth_drain_cells = (bit<32>)(qos.qdepth |-| (bit<19>)value.target_qdepth);
            }
        }
    };

    action data_qd_write() {
        qd_write.execute(sfc.queue_register_idx);
    }

    // SfcPacketType.Trigger: read queue depth
    RegisterAction<sfc_qd_threshold_register_t, sfc_queue_idx_t, buffer_memory_egress_t>(reg_qdepth) qd_read = {
        void apply(inout sfc_qd_threshold_register_t value, out buffer_memory_egress_t rv) {
            // Cut off the testing indicator bit at [31:31]
            rv = (buffer_memory_egress_t)value.qdepth_drain_cells[18:3];
        }
    };

    action trigger_qd_read() {
        sfc.q_drain_length = qd_read.execute(sfc.queue_register_idx);
    }

    action do_time_conversion_count() {
        stats_time_conversion.count();
    }
    /*
     * 176 bytes per cell, converting draining time to 1us precision
     * 25GBE => 25,000,000,000/8/1,000,000/176 = 17.76 cells/us
     * 50GBE => 50,000,000,000/8/1,000,000/176 = 35.5 cells/us
     * 100GBE => 100,000,000,000/8/1,000,000/176 = 71 cells/us
     * Approximation of dividers
     * 25GBE: 16
     * 50GBE: 32
     * 100GBE: 64
     * 200GBE: 128
     * 400GBE: 256
     * For all conversions, the resulting value is guaranteed to be smaller than
     * 16 bits, which means the type case should be lossless.
     * we think 16 bit with microseconds as the unit is enough. 
     * The maximum switch buffer can support with this pause_duration_us are as follows:
     * 25GBE: 65535 us *25GBE/8.0 = 204,796KB
     * 50GBE: 65535 us *50GBE/8.0 = 409,593KB
     * 100GBE: 65535 us *100GBE/8.0 = 819,187KB  
     * As long as the switch buffer size is less than the above values, we are safe to use 16-bit pause_duration_us.
     */
    action do_calc_cells_to_pause_25g() {
        do_time_conversion_count();
        sfc.pause_duration_us = (sfc_pause_duration_us_t)(sfc.q_drain_length >> 1);
        sfc.pause_dscp = hdr.ipv4.diffserv >> 2;
    }
    action do_calc_cells_to_pause_50g() {
        do_time_conversion_count();
        sfc.pause_duration_us = (sfc_pause_duration_us_t)(sfc.q_drain_length >> 2);
        sfc.pause_dscp = hdr.ipv4.diffserv >> 2;
    }
    action do_calc_cells_to_pause_100g() {
        do_time_conversion_count();
        sfc.pause_duration_us = (sfc_pause_duration_us_t)(sfc.q_drain_length >> 3);
        sfc.pause_dscp = hdr.ipv4.diffserv >> 2;
    }
    action do_calc_cells_to_pause_200g() {
        do_time_conversion_count();
        sfc.pause_duration_us = (sfc_pause_duration_us_t)(sfc.q_drain_length >> 3);
        sfc.pause_dscp = hdr.ipv4.diffserv >> 2;
    }
    action do_calc_cells_to_pause_400g() {
        do_time_conversion_count();
        sfc.pause_duration_us = (sfc_pause_duration_us_t)(sfc.q_drain_length >> 3);
        sfc.pause_dscp = hdr.ipv4.diffserv >> 2;
    }

    /*
     * time_conversion_factor = 1000/(512*linkspeed)
     * if link speed is 25Gbps, time_conversion_factor = 48.8
     * if link speed is 50Gbps, time_conversion_factor = 97.6
     * if link speed is 100Gbps, time_conversion_factor = 195.2
     * Approximation of multipliers
     * 25GBE: 48 = 32 + 16
     * 50GBE: 92 = 64 + 32
     * 100GBE: 196 = 128 + 64
     * 25GBE: 48 = 32 + 16; the max pause_time_us to avoid overflow is 1365; for safety, 1200;
     * 50GBE: 92 = 64 + 32; the max pause_time_us to avoid overflow is 712; for safety, 700;
     * 100GBE: 196 = 128 + 64; the max pause_time_us to avoid overflow is 334; for safety, 320;
     */

    action do_calc_pause_to_pfc_time_25g(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.multiplier_second_part = sfc.pause_duration_us << 4;
        sfc.pause_duration_us = sfc.pause_duration_us << 5;
        sfc.link_to_type = _link_to_type;
    }
    action do_calc_pause_to_pfc_time_50g(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.multiplier_second_part = sfc.pause_duration_us << 5;
        sfc.pause_duration_us = sfc.pause_duration_us << 6;
	    sfc.link_to_type = _link_to_type;
    }
    action do_calc_pause_to_pfc_time_100g(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.multiplier_second_part = sfc.pause_duration_us << 6;
        sfc.pause_duration_us = sfc.pause_duration_us << 7;
	    sfc.link_to_type = _link_to_type;
   }
    action do_calc_pause_to_pfc_time_200g(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.multiplier_second_part = sfc.pause_duration_us << 7;
        sfc.pause_duration_us = sfc.pause_duration_us << 8;
	    sfc.link_to_type = _link_to_type;
   }
    action do_calc_pause_to_pfc_time_400g(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.multiplier_second_part = sfc.pause_duration_us << 8;
        sfc.pause_duration_us = sfc.pause_duration_us << 9;
	    sfc.link_to_type = _link_to_type;
   }

    // Todo, this is hardcode
    action testing_conversion(sfc_pause_duration_us_t _pause_duration){
        do_time_conversion_count();
        sfc.pause_duration_us = _pause_duration;   	
    }	

    action do_cal_pause_to_pfc_time_overflow_conversion(LinkToType _link_to_type){
        do_time_conversion_count();
        sfc.pause_duration_us = 0xffff;
        sfc.link_to_type = _link_to_type;	
    }	

    table pause_time_conversion{
        key = {
            sfc.type : exact@name("sfc_type");
            sfc.queue_register_idx: exact@name("queue_register_index");
            sfc.pause_duration_us: range@name("pause_duration_us");
        }

        actions = {
            do_time_conversion_count;
            do_calc_cells_to_pause_25g;
            do_calc_cells_to_pause_50g;
            do_calc_cells_to_pause_100g;
            do_calc_cells_to_pause_200g;
            do_calc_cells_to_pause_400g;
            do_calc_pause_to_pfc_time_25g;
            do_calc_pause_to_pfc_time_50g;
            do_calc_pause_to_pfc_time_100g;
            do_calc_pause_to_pfc_time_200g;
            do_calc_pause_to_pfc_time_400g;
            do_cal_pause_to_pfc_time_overflow_conversion;
            testing_conversion;
        }
        const default_action = do_time_conversion_count;
        counters = stats_time_conversion;
        size = queue_idx_size * (6 + 2);
        // for every queue_idx, we have one entry per type,
        // for trigger packets we have 1 special entry,
        // for signaling packets we have 2 special entries.
        // 8 entries per type should be the upper limit.
    }

    Register<bit<32>, bit<9>>(512,0) recirculation_port_pkt_count;
    RegisterAction<bit<32>, bit<9>, bit<32>>(recirculation_port_pkt_count) recirculation_port_pkt_count_increase = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    action do_set_sfc_pause_dscp(bit<8> _sfc_pause_dscp) {
        sfc.sfc_pause_packet_dscp = _sfc_pause_dscp;
    }

    table set_sfc_pause_dscp {
        actions = {
            do_set_sfc_pause_dscp;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
#ifdef SFC_ENABLE
        if(sfc.type == SfcPacketType.TcSignalEnabled && hdr.sfc_pause.isValid()){
            sfc.type = SfcPacketType.Signal;
        }
        recirculation_port_pkt_count_increase.execute(eg_intr_md.egress_port);
        if (sfc.type == SfcPacketType.Data) {
            data_qd_write();
        } else if (sfc.type == SfcPacketType.Trigger) {
            trigger_qd_read();
        }

        switch (pause_time_conversion.apply().action_run) {
            do_calc_cells_to_pause_25g:
            do_calc_cells_to_pause_50g:
            do_calc_cells_to_pause_100g: { set_sfc_pause_dscp.apply(); }
            default: {}
        }
#endif
    }
}


/*
 *
 * Dependencies:
 *   after:
 *     - EgressPortMapping
 */
control EgressSfcPacket(in egress_intrinsic_metadata_t eg_intr_md,
                        inout switch_local_metadata_t eg_md,
                        inout switch_header_t hdr,
                        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
                        inout switch_sfc_local_metadata_t sfc) {

    action do_convert_to_pfc_pause(bit<8> pfc_prio_enable_bitmap) {
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.sfc_pause.setInvalid();

        /*
         * PFC pkts (802.1Qbb 66B)
         *   dstmac(6B),srcmac(6B),
         *   TYPE(2B8808),Opcode(2B0101),
         *   CEV(2B),
         *   Time0-7(8*2B),Pad(28B),CRC(4B)
         */
        hdr.ethernet.src_addr = 0x000000000000; // ori_dst_mac;
        hdr.ethernet.ether_type = ETHERTYPE_PFC;

        hdr.pfc.setValid();
        hdr.pad_112b.setValid();
        hdr.pad_96b.setValid();
        hdr.pfc.opcode = 16w0x0101;
        hdr.pfc.class_enable_vec = pfc_prio_enable_bitmap;
        hdr.pfc.reserved_zero = 0x0;
        hdr.pfc.tstamp0 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp1 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp2 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp3 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp4 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp5 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp6 = sfc.pause_duration_us + sfc.multiplier_second_part;
        hdr.pfc.tstamp7 = sfc.pause_duration_us + sfc.multiplier_second_part;
        eg_intr_md_for_dprsr.mtu_trunc_len = 64;
    }

    table convert_to_pfc_pause {
        key = {
            eg_intr_md.egress_port: ternary@name("egress_port");
            sfc.pause_dscp : ternary@name("pause_dscp");
        }
        actions = {
            NoAction;
            do_convert_to_pfc_pause;
        }
        default_action = NoAction;
        size = SFC_QUEUE_IDX_SIZE * 2;
    }

    action gen_sfc_pause_for_rocev2(){
        hdr.fabric.setValid();
        // hdr.fabric.reserved = 0;
        // hdr.fabric.color = 0;
        // hdr.fabric.qos = 0;
        // hdr.fabric.reserved2 = 0;

        hdr.cpu.setValid();
        // hdr.cpu.egress_queue = 0;
        // hdr.cpu.tx_bypass = 0;
        // hdr.cpu.capture_ts = 0;
        // hdr.cpu.reserved = 0;
        hdr.cpu.ingress_port = (bit<16>) eg_md.ingress_port;
        hdr.cpu.port_lag_index = (bit<16>) eg_md.ingress_port_lag_index;
        //hdr.cpu.ingress_bd = (bit<16>) eg_md.bd;
        hdr.cpu.ingress_bd = 0;
        //hdr.cpu.reason_code = 0; //16w0x0002; //eg_md.cpu_reason;
        hdr.cpu.ether_type = hdr.ethernet.ether_type;

        hdr.ethernet.ether_type = ETHERTYPE_BFN;

        bit<48> ori_src_mac;
        bit<48> ori_dst_mac;
        ori_src_mac = hdr.ethernet.src_addr;
        ori_dst_mac = hdr.ethernet.dst_addr;
        hdr.ethernet.src_addr = ori_dst_mac;
        hdr.ethernet.dst_addr = ori_src_mac;
        //hdr.ethernet.src_addr = hdr.ethernet.dst_addr;

        //L3
        bit<32> orig_src_ip;
        bit<32> orig_dst_ip;

	    orig_src_ip = hdr.ipv4.src_addr;
        orig_dst_ip = hdr.ipv4.dst_addr;
        hdr.ipv4.src_addr = orig_dst_ip;
        hdr.ipv4.dst_addr = orig_src_ip;

        hdr.ipv4.total_len = 46;
        hdr.ipv4.hdr_checksum = 0;
        hdr.ipv4.diffserv = sfc.sfc_pause_packet_dscp;
        hdr.ipv4_option.setInvalid();

        // udp
        hdr.udp.length = 26;
        hdr.udp.dst_port = UDP_PORT_SFC_PAUSE;

        //TODO: update udp checksum sometime
        hdr.udp.checksum = 0;

        // sfc pause packet format
        hdr.sfc_pause.setValid();
        hdr.pad_112b.setValid();
        hdr.sfc_pause.dscp = sfc.pause_dscp;
        hdr.sfc_pause.duration_us = sfc.pause_duration_us;
        eg_intr_md_for_dprsr.mtu_trunc_len = 78 ;  //64 bytes (sfc packet ) + 14 bytes (cpu header)
    }

    action gen_sfc_pause_for_tcp(){
        bit<48> ori_src_mac;
        bit<48> ori_dst_mac;
        ori_src_mac = hdr.ethernet.src_addr;
        ori_dst_mac = hdr.ethernet.dst_addr;
        hdr.ethernet.src_addr = ori_dst_mac;
        hdr.ethernet.dst_addr = ori_src_mac;

        //L3
        bit<32> orig_src_ip;
        bit<32> orig_dst_ip;
        orig_src_ip = hdr.ipv4.src_addr;
        orig_dst_ip = hdr.ipv4.dst_addr;
        hdr.ipv4.src_addr = orig_dst_ip;
        hdr.ipv4.dst_addr = orig_src_ip;
        hdr.ipv4.total_len = 46;
        hdr.ipv4.hdr_checksum = 0;
        hdr.ipv4_option.setInvalid();
        hdr.ipv4.diffserv = 0;

        //tcp header
        bit<16> orig_src_port;
        bit<16> orig_dst_port;
        orig_src_port = hdr.tcp.src_port;
        orig_dst_port = hdr.tcp.dst_port;
        hdr.tcp.src_port = orig_dst_port;
        hdr.tcp.dst_port = orig_src_port;
        hdr.tcp.checksum = 0;

        //yle: use the last bit in the reservation field to let tcp stack know
        // this is an SFC packet.
        // TCP_FLAGS_SFC_PAUSE = 1
        hdr.tcp.res = TCP_FLAGS_SFC_PAUSE;
        //yle: reuse seq_no as the pause_time
        hdr.tcp.seq_no = (bit<32>)sfc.pause_duration_us;
        eg_intr_md_for_dprsr.mtu_trunc_len = 64;
    }
    Register<bit<32>, bit<9>>(512,0) sfc_count;
    RegisterAction<bit<32>, bit<9>, bit<32>>(sfc_count) sfc_count_increase = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1;
        }
    };

    apply {
#ifdef SFC_ENABLE
        if (sfc.type == SfcPacketType.Trigger) {
            if (hdr.udp.isValid()) {
                gen_sfc_pause_for_rocev2();
            } else {
                gen_sfc_pause_for_tcp();
            }
            sfc_count_increase.execute(eg_intr_md.egress_port);
        } else if (sfc.type == SfcPacketType.Signal
                   && sfc.link_to_type == LinkToType.Server) {
            convert_to_pfc_pause.apply();
        }
    #endif
    }
}
