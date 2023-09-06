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


struct switch_sflow_info_t {
    bit<32> current;
    bit<32> rate;
}

//------------------------------------------------------------------------------
// Ingress Sample Packet (sflow)
// @param local_md : Ingress metadata fields.
//------------------------------------------------------------------------------
control IngressSflow(inout switch_local_metadata_t local_md) {
    const bit<32> sflow_session_size = 256;

    @name(".ingress_sflow_samplers")
    Register<switch_sflow_info_t, bit<32>>(sflow_session_size) samplers;
    RegisterAction<switch_sflow_info_t, bit<8>, bit<1>>(samplers) sample_packet = {
        void apply(inout switch_sflow_info_t reg, out bit<1> flag) {
            if (reg.current > 0) {
                reg.current = reg.current - 1;
            } else {
                reg.current = reg.rate;
                flag = 1;
            }
        }
    };

    apply {
#ifdef INGRESS_SFLOW_ENABLE
      if (local_md.sflow.session_id != SWITCH_SFLOW_INVALID_ID) {
        local_md.sflow.sample_packet =
            sample_packet.execute(local_md.sflow.session_id);
      }
#endif
    }
}

//------------------------------------------------------------------------------
// Egress Sample Packet (sflow)
// @param local_md : Egress metadata fields.
//------------------------------------------------------------------------------
control EgressSflow(inout switch_local_metadata_t local_md) {
    const bit<32> sflow_session_size = 256;

    Register<switch_sflow_info_t, bit<32>>(sflow_session_size) samplers;
    RegisterAction<switch_sflow_info_t, bit<8>, bit<1>>(samplers) sample_packet = {
        void apply(inout switch_sflow_info_t reg, out bit<1> flag) {
            if (reg.current > 0) {
                reg.current = reg.current - 1;
            } else {
                reg.current = reg.rate;
                flag = 1;
            }
        }
    };

    apply {
#ifdef EGRESS_SFLOW_ENABLE
      if (local_md.sflow.session_id != SWITCH_SFLOW_INVALID_ID) {
        local_md.sflow.sample_packet =
            sample_packet.execute(local_md.sflow.session_id);
      }
#endif
    }
}
