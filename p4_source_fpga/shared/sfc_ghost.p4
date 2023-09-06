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


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const bit<1> ghost_total_cnt_idx = 1;

// TODO: This is Tofino2 only (9 bit per port, 7 bit per queue)
const const_t sfc_ingress_queue_idx_cnt = 32w0xffff;
//const const_t sfc_queue_threshold_idx_cnt = 1 << SFC_QUEUE_THRESHOLD_IDX_BITS;
const const_t sfc_queue_threshold_idx_cnt = 8;

// ---------------------------------------------------------------------------
// Common registers and variables for ping-pong tables
// ---------------------------------------------------------------------------

Register<bit<1>, sfc_ingress_queue_idx_t>(sfc_ingress_queue_idx_cnt) sfc_reg_qdepth;

//-----------------------------------------------------------------------------
// Initialize the ghost_metadata by copying the values form the intrinsic meta
// data header (this seems to be required because of a bug as of 2020-11-03.
// Set the queue and buffer pool index for the incoming ghost packet.
//
// @param g_intr_md: the ghost intrinsic meta data
// @return g_md : The ghost meta data
//-----------------------------------------------------------------------------
control GhostSfcInit(in ghost_intrinsic_metadata_t g_intr_md,
                     out sfc_ghost_metadata_t g_md)
                    (const_t queue_idx_size) {

    buffer_memory_ghost_t qlength;

    DirectRegister<bit<32>>() reg_ghost_counter;

    DirectRegisterAction<bit<32>, bool>(reg_ghost_counter) ghost_counter = {
        void apply(inout bit<32> counter){
            counter = counter + 1;
        }
    };

    action do_update_stats() {
        ghost_counter.execute();
    }

    action do_check_threshold_set_q_idx(sfc_ingress_queue_idx_t ingress_port_queue_idx,
                                        buffer_memory_ghost_t qdepth_threshold) {
        do_update_stats();
        g_md.ingress_port_queue_idx = ingress_port_queue_idx;
        g_md.qdepth_threshold_remainder = qdepth_threshold |-| qlength;
    }

    action set_qlength(sfc_ingress_queue_idx_t ingress_port_queue_idx,
                       buffer_memory_ghost_t qdepth_threshold_remainder) {
        do_update_stats();
        g_md.ingress_port_queue_idx = ingress_port_queue_idx;
        g_md.qdepth_threshold_remainder = qdepth_threshold_remainder;
    }

    table ghost_set_register_idx_tbl {
        key = {
            g_intr_md.pipe_id : exact@name("tm_pipe_id");
            g_intr_md.qid : exact@name("tm_absqid");
        }
        actions = {
            do_update_stats;
            set_qlength;
            do_check_threshold_set_q_idx;
        }
        registers = reg_ghost_counter;
        const default_action = do_update_stats();
        size = queue_idx_size;
    }

    apply {
        qlength = g_intr_md.qlength[17:2];
        ghost_set_register_idx_tbl.apply();
    }
}

control GhostSfc(in ghost_intrinsic_metadata_t g_intr_md)
                  (const_t queue_idx_size) {

    /*
    DirectRegister<bit<32>>(queue_idx_size) reg_ghost_counter;

    DirectRegisterAction<bit<32>, bool>(reg_ghost_counter) ghost_counter = {
        void apply(inout bit<32> counter){
            counter = counter + 1;
        }
    };
    */

    // Ghost thread: queue depth value
    RegisterAction<bit<1>, sfc_ingress_queue_idx_t, int<1>>(sfc_reg_qdepth) qdepth_write_over = {
        void apply(inout bit<1> value) {
            value = 1w1;
        }
    };
    RegisterAction<bit<1>, sfc_ingress_queue_idx_t, int<1>>(sfc_reg_qdepth) qdepth_write_under = {
        void apply(inout bit<1> value) {
            value = 1w0;
        }
    };

    action do_set_under_threshold(sfc_ingress_queue_idx_t ingress_port_queue_idx) {
        qdepth_write_over.execute(ingress_port_queue_idx);
    }

    action do_set_over_threshold(sfc_ingress_queue_idx_t ingress_port_queue_idx) {
        qdepth_write_under.execute(ingress_port_queue_idx);
    }

    table ghost_check_threshold_tbl {
        key = {
            g_intr_md.pipe_id : exact@name("tm_pipe_id");
            g_intr_md.qid : exact@name("tm_qid");
            g_intr_md.qlength : range@name("qdepth");
        }
        actions = {
            do_set_under_threshold;
            do_set_over_threshold;
        }
        const default_action = do_set_under_threshold(0);
        size = queue_idx_size;
    }

    apply {
        ghost_check_threshold_tbl.apply();
    }
}

//-----------------------------------------------------------------------------
// Write the per-queue and per-buffer pool utilization to the shared ping-pong
// registers from the Ghost thread.
//
// @param g_md : The ghost meta data
//-----------------------------------------------------------------------------
control GhostWriteOverThreshold(in ghost_intrinsic_metadata_t g_intr_md,
                                in sfc_ghost_metadata_t g_md) {

    // Ghost thread: queue depth value
    RegisterAction<bit<1>, sfc_ingress_queue_idx_t, int<1>>(sfc_reg_qdepth) qdepth_write_over = {
        void apply(inout bit<1> value) {
            value = 1w1;
        }
    };
    RegisterAction<bit<1>, sfc_ingress_queue_idx_t, int<1>>(sfc_reg_qdepth) qdepth_write_under = {
        void apply(inout bit<1> value) {
            value = 1w0;
        }
    };

    apply {
        if (g_md.qdepth_threshold_remainder == 0) {
            qdepth_write_over.execute(g_md.ingress_port_queue_idx);
        } else {
            qdepth_write_under.execute(g_md.ingress_port_queue_idx);
        }
    }
}




//-----------------------------------------------------------------------------
// Read the per-queue and per-buffer pool utilization to the shared ping-pong
// registers from the Ingress thread. While doing so, compare with the queue
// depth with the threshold provided in sfc and return the threshold-crossing.
//
// @param sfc : The sfc meta data
//----------------------------------------------------------------------------
control IngressReadOverThreshold(in switch_port_t egress_port,
                                 in switch_qid_t qid,
                                 in ghost_intrinsic_metadata_t g_intr_md,
                                 inout switch_sfc_local_metadata_t sfc) {


    // Ghost thread: queue depth value
    RegisterAction<bit<1>, sfc_ingress_queue_idx_t, bool>(sfc_reg_qdepth) qdepth_read = {
        void apply(inout bit<1> queue_over_threshold, out bool rv) {
            rv = (bool)queue_over_threshold;
        }
    };

    apply {
        sfc.qlength_over_threshold = qdepth_read.execute(egress_port ++ qid);
    }
}
