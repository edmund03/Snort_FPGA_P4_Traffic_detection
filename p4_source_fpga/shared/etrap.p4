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


#ifndef _P4_ETRAP_
#define _P4_ETRAP_

//-------------------------------------------------------------------------------------------------
// Heavy-Hitter or Elephant Detection
// Identify source or desitnation IP with traffic rate exceeding a programmable threshold
//-------------------------------------------------------------------------------------------------

#define ETRAP_TABLE_SIZE (1<<switch_etrap_index_width)

control ETrap(inout switch_local_metadata_t local_md) {

    Meter<switch_etrap_index_t>(ETRAP_TABLE_SIZE, (MeterType_t.BYTES))  meter;

    @name(".set_meter_and_tc") action set_meter_and_tc(
        switch_etrap_index_t index,
        switch_tc_t tc) {
        local_md.qos.etrap_index = index;
        local_md.qos.etrap_tc = tc;
    }

    @name(".etrap_ipv4_flow") table ipv4_acl {
        key = {
            local_md.lkp.ip_src_addr[95:64] : ternary @name("src_addr");
            local_md.lkp.ip_dst_addr[95:64] : ternary @name("dst_addr");
        }
        actions = {
            set_meter_and_tc;
        }
        size = ETRAP_TABLE_SIZE/2;
    }

    @name(".etrap_ipv6_flow") table ipv6_acl {
        key = {
            local_md.lkp.ip_src_addr[63:0] : ternary @name("src_addr");
            local_md.lkp.ip_dst_addr[63:0] : ternary @name("dst_addr");
        }
        actions = {
            set_meter_and_tc;
        }
        size = ETRAP_TABLE_SIZE/2;
    }

    @name(".meter_action") action meter_action(switch_etrap_index_t index) {
        local_md.qos.etrap_color = (bit<2>) meter.execute(index);
    }

    @name(".etrap_meter_index") table meter_index {
        key = {
            local_md.qos.etrap_index : exact @name("etrap_index");
        }
        actions = {
            meter_action;
        }
        size = ETRAP_TABLE_SIZE;
    }

    DirectRegister<bit<8>>() meter_state_reg;
    DirectRegisterAction<bit<8>, bit<8>>(meter_state_reg) meter_state_change = {
        void apply(inout bit<8> value, out bit<8> rv) {
            if (value > (bit<8>) local_md.qos.etrap_color) {
                rv = SWITCH_DTEL_REPORT_TYPE_ETRAP_CHANGE;
            } else if (value < (bit<8>) local_md.qos.etrap_color) {
                rv = SWITCH_DTEL_REPORT_TYPE_ETRAP_CHANGE |
                     SWITCH_DTEL_REPORT_TYPE_ETRAP_HIT;
            }
            value = (bit<8>) local_md.qos.etrap_color;
        }
    };

    action meter_state_action() {
        local_md.dtel.report_type = meter_state_change.execute();
    }

    table meter_state {
        key = {
            local_md.qos.etrap_index : exact @name("etrap_index");
        }
        actions = {
            meter_state_action;
        }
        size = ETRAP_TABLE_SIZE;
        registers = meter_state_reg;
    }

    apply {
        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
            ipv6_acl.apply();
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
            ipv4_acl.apply();
        }
        meter_index.apply();
#ifdef DTEL_ENABLE
        meter_state.apply();
#endif
    }
}

control ETrapState(inout switch_local_metadata_t local_md) {

    Register<bit<8>, bit<11>>(ETRAP_TABLE_SIZE, 0) etrap_state_reg;
    RegisterAction<bit<8>, bit<11>, bit<8>>(etrap_state_reg) etrap_state_red_action = {
        void apply(inout bit<8> val, out bit<8> rv) {
            rv = local_md.qos.etrap_tc;
            val = 0x1;
        }
    };

    RegisterAction<bit<8>, bit<11>, bit<8>>(etrap_state_reg) etrap_state_green_action = {
        void apply(inout bit<8> val, out bit<8> rv) {
            bit<8> temp;
            if (val == 0x1) {
                temp = local_md.qos.etrap_tc;
            } else {
                temp = local_md.qos.tc;
            }
            rv = temp;
        }
    };

    @name(".etrap_red_state") action etrap_red_state() {
        local_md.qos.tc = etrap_state_red_action.execute(local_md.qos.etrap_index);
    }

    @name(".etrap_green_state") action etrap_green_state() {
        local_md.qos.tc = etrap_state_green_action.execute(local_md.qos.etrap_index);
    }

    @name(".etrap_state") table etrap_state {
        key = {
            local_md.qos.etrap_color : exact @name("etrap_color");
        }
        actions = {
            etrap_red_state;
            etrap_green_state;
        }
        const entries = {
          (SWITCH_METER_COLOR_GREEN) : etrap_green_state();
          (SWITCH_METER_COLOR_RED) : etrap_red_state();
        }
        size = 3;
    }

    apply {
        etrap_state.apply();
    }
}

#endif /* _P4_ETRAP_ */
