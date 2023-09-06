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


control IngressRmac(inout switch_header_t hdr,
                    inout switch_local_metadata_t local_md)(
                    switch_uint32_t port_vlan_table_size,
                    switch_uint32_t vlan_table_size=4096) {
    //
    // **************** Router MAC Check ************************
    //
    @name(".rmac_miss")
    action rmac_miss() {
        local_md.flags.rmac_hit = false;
    }
    @name(".rmac_hit")
    action rmac_hit() {
        local_md.flags.rmac_hit = true;
    }

    @name(".pv_rmac")
    table pv_rmac {
        key = {
            local_md.ingress_port_lag_index : ternary;
            hdr.vlan_tag[0].isValid() : ternary;
            hdr.vlan_tag[0].vid : ternary;
            hdr.ethernet.dst_addr : ternary;
        }

        actions = {
            rmac_miss;
            rmac_hit;
        }

        const default_action = rmac_miss;
        size = port_vlan_table_size;
    }

    @name(".vlan_rmac")
    table vlan_rmac {
        key = {
            hdr.vlan_tag[0].vid : exact;
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            @defaultonly rmac_miss;
            rmac_hit;
        }

        const default_action = rmac_miss;
        size = vlan_table_size;
    }

    apply {
        switch (pv_rmac.apply().action_run) {
            rmac_miss : {
                if (hdr.vlan_tag[0].isValid())
                    vlan_rmac.apply();
            }
        }
    }
}
