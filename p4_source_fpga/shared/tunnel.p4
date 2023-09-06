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


#if defined(IPV6_TUNNEL_ENABLE) && !defined(IPV6_ENABLE)
#error "IPv6 tunneling cannot be enabled without enabling IPv6"
#endif

#ifdef TUNNEL_ENABLE
//-----------------------------------------------------------------------------
// Tunnel Termination processing
// Outer router MAC
// Destination VTEP, Insegment and Local SID lookups
//-----------------------------------------------------------------------------
control IngressTunnel(inout switch_header_t hdr,
                      inout switch_local_metadata_t local_md,
                      inout switch_lookup_fields_t lkp)() {
    InnerPktValidation() pkt_validation;

    //
    // **************** Router MAC Check ************************
    //
    @name(".tunnel_rmac_miss")
    action rmac_miss() {
        local_md.flags.rmac_hit = false;
    }
    @name(".tunnel_rmac_hit")
    action rmac_hit() {
        local_md.flags.rmac_hit = true;
    }

    @name(".vxlan_rmac")
    table vxlan_rmac {
        key = {
            local_md.tunnel.vni : exact;
            hdr.inner_ethernet.dst_addr : exact;
        }

        actions = {
            @defaultonly rmac_miss;
            rmac_hit;
        }

        const default_action = rmac_miss;
        size = VNI_MAPPING_TABLE_SIZE;
    }

    @name(".vxlan_device_rmac")
    table vxlan_device_rmac {
        key = {
            hdr.inner_ethernet.dst_addr : exact;
        }

        actions = {
            @defaultonly rmac_miss;
            rmac_hit;
        }

        const default_action = rmac_miss;
        size = 128;
    }

    //
    // **************** Tunnel Termination Table  ************************
    //
    @name(".dst_vtep_hit")
    action dst_vtep_hit(switch_tunnel_mode_t ttl_mode,
                        switch_tunnel_mode_t qos_mode) {
#ifdef TUNNEL_TTL_MODE_ENABLE
        local_md.tunnel.ttl_mode = ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.tunnel.qos_mode = qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
    }

    @name(".set_inner_bd_properties_base")
    action set_inner_bd_properties_base(
            switch_bd_t bd,
            switch_vrf_t vrf,
            switch_bd_label_t bd_label,
            switch_learning_mode_t learning_mode,
            bool ipv4_unicast_enable,
            bool ipv6_unicast_enable) {
	local_md.ingress_outer_bd = local_md.bd;
        local_md.bd = bd;
#ifdef INGRESS_ACL_BD_LABEL_ENABLE
        local_md.bd_label = bd_label;
#endif
        local_md.vrf = vrf;
        local_md.learning.bd_mode = learning_mode;
        local_md.ipv4.unicast_enable = ipv4_unicast_enable;
        local_md.ipv4.multicast_enable = false;
        local_md.ipv4.multicast_snooping = false;
        local_md.ipv6.unicast_enable = ipv6_unicast_enable;
        local_md.ipv6.multicast_enable = false;
        local_md.ipv6.multicast_snooping = false;
        local_md.tunnel.terminate = true;
    }

    @name(".set_inner_bd_properties")
    action set_inner_bd_properties(
            switch_bd_t bd,
            switch_vrf_t vrf,
            switch_bd_label_t bd_label,
            switch_learning_mode_t learning_mode,
            bool ipv4_unicast_enable,
            bool ipv6_unicast_enable,
            switch_tunnel_mode_t ttl_mode,
            switch_tunnel_mode_t qos_mode) {
        set_inner_bd_properties_base(bd, vrf, bd_label, learning_mode,
                                     ipv4_unicast_enable, ipv6_unicast_enable);
#ifdef TUNNEL_TTL_MODE_ENABLE
        local_md.tunnel.ttl_mode = ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.tunnel.qos_mode = qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
    }

    @name(".dst_vtep")
    table dst_vtep {
        key = {
            lkp.ip_src_addr[95:64] : ternary @name("src_addr");
            lkp.ip_dst_addr[95:64] : ternary @name("dst_addr");
            local_md.vrf : exact;
            local_md.tunnel.type : exact;
        }

        actions = {
            NoAction;
#ifdef VXLAN_ENABLE
            dst_vtep_hit;
#endif /* VXLAN_ENABLE */
            set_inner_bd_properties;
        }

        size = IPV4_DST_VTEP_TABLE_SIZE;
        const default_action = NoAction;
        requires_versioning = false;
    }

#ifdef IPV6_TUNNEL_ENABLE
    @name(".dst_vtepv6")
    table dst_vtepv6 {
        key = {
            lkp.ip_src_addr : ternary @name("src_addr");
            lkp.ip_dst_addr : ternary @name("dst_addr");
            local_md.vrf : exact;
            local_md.tunnel.type : exact;
        }

        actions = {
            NoAction;
            dst_vtep_hit;
            set_inner_bd_properties;
        }

        size = IPV6_DST_VTEP_TABLE_SIZE;
        const default_action = NoAction;
        requires_versioning = false;
    }
#endif /* IPV6_TUNNEL_ENABLE */

#ifdef TUNNEL_QOS_MODE_ENABLE
    action set_ip_tos_outer_ipv4() {
        lkp.ip_tos = hdr.ipv4.diffserv;
    }

    action set_ip_tos_outer_ipv6() {
        lkp.ip_tos = hdr.ipv6.traffic_class;
    }

    table lkp_ip_tos_outer {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }
        actions = {
            NoAction;
            set_ip_tos_outer_ipv4;
            set_ip_tos_outer_ipv6;
        }
        size = 4;
        const entries = {
            (true, false) : set_ip_tos_outer_ipv4;
            (false, true) : set_ip_tos_outer_ipv6;
        }
        const default_action = NoAction;
    }
#endif

#ifdef VXLAN_ENABLE
    //
    // ***************** tunnel.vni -> VRF Translation *****************
    //
    @name(".vni_to_bd_mapping")
    table vni_to_bd_mapping {
        key = { local_md.tunnel.vni : exact; }

        actions = {
            NoAction;
            set_inner_bd_properties_base;
        }

        default_action = NoAction;
        size = VNI_MAPPING_TABLE_SIZE;
    }
#endif /* VXLAN_ENABLE */

#ifdef SRV6_ENABLE

    //
    // ***************** Calculate SRH Header Length  *****************
    //

    action set_srh_len(bit<6> len) {
        local_md.tunnel.srh_hdr_len = len;
    }

    table srh_len {
        key = {
            hdr.srh_base.isValid() : exact;
            hdr.srh_seg_list[0].isValid() : exact;
            hdr.srh_seg_list[1].isValid() : exact;
        }
        actions = {
            set_srh_len;
        }
        size = 8;
        const entries = {
            (true, true, false) : set_srh_len(24);
            (true, true, true)  : set_srh_len(40);
        }
    }

    //
    // ***************** My SID Table *****************
    //

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    @name(".end")
    action end() {
        // Prefix SID. Forward based on next segment in the SID list
        local_md.lkp.ip_dst_addr = local_md.tunnel.srh_next_sid;
        // Move next sid to ip_da and decrement ttl
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        hdr.srh_base.seg_left = hdr.srh_base.seg_left - 1;
        stats.count();
    }

    @name(".end_with_psp")
    action end_with_psp() {
        // Prefix SID with SL=1. Remove SRH and Forward based on next segment in the SID list
        local_md.lkp.ip_dst_addr = local_md.tunnel.srh_next_sid;
        // Move next sid to ip_da and decrement ttl
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_with_usd")
    action end_with_usd() {
        local_md.tunnel.terminate = true;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_uN")
    action end_uN() {
        // Prefix SID with uSID compression.
        // If next uSID is end-of-carrier:
        //       - perform regular END operation with PSP/USD flavors (end/end_with_psp/end_with_usd actions)
        // Else
        //       -- Shift and Lookup operation with end_uN action

        // Pop the active uSID i.e. ID_LEN bits starting at offset BLOCK_LEN from the left
        // shift the DA to the right of offset (BLOCK_LEN + ID_LEN) by ID_LEN bits to the left
        // Fill the rightmost ID_LEN bits by 0's
        // For BLOCK_LEN=32b and ID_LEN=16b. Assuming that 128b address is divided into 8 words of 16b each
        //  -- Leave first two words unchanged.
        //  -- Shift next 5 words to the left by 16b
        //  -- zero out the last word
        funnel_shift_right(local_md.lkp.ip_dst_addr[95:64], local_md.lkp.ip_dst_addr[95:64], local_md.lkp.ip_dst_addr[63:32], USID_ID_LEN);
        funnel_shift_right(local_md.lkp.ip_dst_addr[63:32], local_md.lkp.ip_dst_addr[63:32], local_md.lkp.ip_dst_addr[31:0], USID_ID_LEN);
        local_md.lkp.ip_dst_addr[31:0] =  local_md.lkp.ip_dst_addr[31:0] << USID_ID_LEN;

        funnel_shift_right(hdr.ipv6.dst_addr[95:64], hdr.ipv6.dst_addr[95:64], hdr.ipv6.dst_addr[63:32], USID_ID_LEN);
        funnel_shift_right(hdr.ipv6.dst_addr[63:32], hdr.ipv6.dst_addr[63:32], hdr.ipv6.dst_addr[31:0], USID_ID_LEN);
        hdr.ipv6.dst_addr[31:0] =  hdr.ipv6.dst_addr[31:0] << USID_ID_LEN;
        stats.count();
    }

    @name(".end_x")
    action end_x(switch_nexthop_t nexthop) {
        // Adjacency SID
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        local_md.flags.routed = true;
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        hdr.srh_base.seg_left = hdr.srh_base.seg_left - 1;
        stats.count();
    }

    @name(".end_x_with_psp")
    action end_x_with_psp(switch_nexthop_t nexthop) {
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        local_md.nexthop = nexthop;
        local_md.flags.routed = true;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_x_with_usd")
    action end_x_with_usd(switch_nexthop_t nexthop) {
        local_md.tunnel.remove_srh = true;;
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.flags.routed = true;
        local_md.tunnel.terminate = true;
        stats.count();
    }

    @name(".end_uA")
    action end_uA(switch_nexthop_t nexthop) {
        // Adjacency SID with uSID compression.
        // If next uSID is not-end-of-carrier, perform Shift and Xconnect
        funnel_shift_right(hdr.ipv6.dst_addr[95:64], hdr.ipv6.dst_addr[95:64], hdr.ipv6.dst_addr[63:32], USID_ID_LEN);
        funnel_shift_right(hdr.ipv6.dst_addr[63:32], hdr.ipv6.dst_addr[63:32], hdr.ipv6.dst_addr[31:0], USID_ID_LEN);
        hdr.ipv6.dst_addr[31:0] =  hdr.ipv6.dst_addr[31:0] << USID_ID_LEN;
        local_md.flags.routed = true;
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        stats.count();
    }

    @name(".end_t")
    action end_t(switch_vrf_t vrf) {
        // END function with a new VRF
        local_md.vrf = vrf;
        local_md.lkp.ip_dst_addr = local_md.tunnel.srh_next_sid;
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        hdr.srh_base.seg_left = hdr.srh_base.seg_left - 1;
        stats.count();
    }

    @name(".end_dt4")
    action end_dt4(switch_vrf_t vrf) {
        // Decap and lookup inner
        local_md.vrf = vrf;
        local_md.tunnel.terminate = true;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_dt6")
    action end_dt6(switch_vrf_t vrf) {
        // Decap and lookup inner
        local_md.vrf = vrf;
        local_md.tunnel.terminate = true;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_dt46")
    action end_dt46(switch_vrf_t vrf) {
        // Decap and lookup inner
        local_md.vrf = vrf;
        local_md.tunnel.terminate = true;
        local_md.tunnel.remove_srh = true;;
        stats.count();
    }

    @name(".end_dx4")
    action end_dx4(switch_nexthop_t nexthop) {
        // Decap and forward
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.tunnel.remove_srh = true;;
        local_md.flags.routed = true;
        local_md.tunnel.terminate = true;
        stats.count();
    }

    @name(".end_dx6")
    action end_dx6(switch_nexthop_t nexthop) {
        // Decap and forward
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.tunnel.remove_srh = true;;
        local_md.flags.routed = true;
        local_md.tunnel.terminate = true;
        stats.count();
    }

    @name(".end_b6_encaps_red")
    action end_b6_encaps_red(switch_nexthop_t nexthop) {
        // END + a new Encap
        // Move next sid to ip_da and decrement ttl
        hdr.ipv6.dst_addr = local_md.tunnel.srh_next_sid;
        hdr.srh_base.seg_left = hdr.srh_base.seg_left - 1;
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.flags.routed = true;
        stats.count();
    }

    @name(".end_b6_insert_red")
    action end_b6_insert_red(switch_nexthop_t nexthop) {
        // END + Insert a new SRH
        // The new SRH will be inserted between IPv6 header and the existing SRH.
        local_md.nexthop = nexthop;
        local_md.bypass = local_md.bypass | SWITCH_INGRESS_BYPASS_L3;
        local_md.flags.routed = true;
        stats.count();
    }

    @name(".srv6_trap")
    action srv6_trap() {
        local_md.flags.routed = false;
        local_md.flags.srv6_trap = true;
        stats.count();
    }

    @name(".srv6_drop")
    action srv6_drop() {
        local_md.flags.routed = false;
        local_md.drop_reason = SWITCH_DROP_REASON_SRV6_MY_SID_DROP;
        stats.count();
    }

    @name(".my_sid")
    table my_sid {
        key = {
            hdr.srh_base.seg_left : ternary;
            hdr.ipv6.dst_addr : ternary;
            local_md.vrf : exact;
            hdr.srh_base.isValid() : exact;
        }
        actions = {
            end;
            end_with_psp;
            end_with_usd;
            end_x;
            end_x_with_psp;
            end_x_with_usd;
            end_t;
            end_dt4;
            end_dt6;
            end_dt46; // Can be used for End.uDT as well
            end_dx4;  // Can be used for End.uDX4 as well
            end_dx6;  // Can be used for End.uDX6 as well
            end_b6_encaps_red;
            end_b6_insert_red;
            end_uN;
            end_uA;
            srv6_trap;
            srv6_drop;
        }
        size = MY_SID_TABLE_SIZE;
        counters = stats;
    }

    //
    // ***************** Remove SRH if present  *****************
    //
    action invalidate_srh() {
        hdr.ipv6.next_hdr = hdr.srh_base.next_hdr;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - (bit<16>)local_md.tunnel.srh_hdr_len;
        hdr.srh_base.setInvalid();
        hdr.srh_seg_list[0].setInvalid();
        hdr.srh_seg_list[1].setInvalid();
    }

    table remove_srh {
      key = {
        hdr.srh_base.isValid() : exact;
        local_md.tunnel.remove_srh : exact;
      }
      actions = {
        invalidate_srh;
      }
      const entries = {
          (true, true) : invalidate_srh;
        }
      size = 2;
    }

#endif /* SRV6_ENABLE */

#ifdef MPLS_ENABLE
    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) mpls_stats;
    //
    // ***************** MPLS FIB *****************
    //

    // Terminate MPLS and lookup inner IP
    @name(".mpls_term")
    action mpls_term (
        switch_bd_t bd,
        switch_vrf_t vrf,
        switch_bd_label_t bd_label,
        switch_learning_mode_t learning_mode,
        bool ipv4_unicast_enable,
        bool ipv6_unicast_enable,
        switch_tunnel_mode_t ttl_mode,
        switch_tunnel_mode_t qos_mode,
        bit<2> pop_count) {
        local_md.tunnel.mpls_pop_count = pop_count;
        local_md.tunnel.terminate = true;
        local_md.flags.routed = true;
        mpls_stats.count();
        set_inner_bd_properties(
            bd,
            vrf,
            bd_label,
            learning_mode,
            ipv4_unicast_enable,
            ipv6_unicast_enable,
            ttl_mode,
            qos_mode);
    }

    // MPLS Nexthop
    @name(".mpls_swap")
    action mpls_swap(switch_nexthop_t nexthop_index, bit<2> pop_count) {
        local_md.tunnel.mpls_pop_count = pop_count;
        local_md.nexthop = nexthop_index;
        local_md.flags.routed = true;
        mpls_stats.count();
    }

    // IP Nexhtop
    @name(".mpls_php")
    action mpls_php(switch_nexthop_t nexthop_index, bit<2> pop_count,
                    switch_tunnel_mode_t ttl_mode,
                    switch_tunnel_mode_t qos_mode) {
        local_md.tunnel.mpls_pop_count = pop_count;
        local_md.nexthop = nexthop_index;
        local_md.flags.routed = true;
#ifdef TUNNEL_TTL_MODE_ENABLE
        local_md.tunnel.ttl_mode = ttl_mode;
#endif /* TUNNEL_TTL_MODE_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.tunnel.qos_mode = qos_mode;
#endif /* TUNNEL_QOS_MODE_ENABLE */
        mpls_stats.count();
    }

    @name(".mpls_drop")
    action mpls_drop() {
        local_md.flags.routed = false;
        local_md.drop_reason = SWITCH_DROP_REASON_MPLS_LABEL_DROP;
        mpls_stats.count();
    }

    @name(".mpls_trap")
    action mpls_trap() {
        local_md.flags.routed = false;
        local_md.flags.mpls_trap = true;
        mpls_stats.count();
    }

    @name(".mpls_fib")
    table mpls_fib {
        key = { lkp.mpls_lookup_label : exact; } // lookup 2nd label if topmost label is explicit null

        actions = {
            mpls_term;  // inseg with nh_type==rif
            mpls_php;   // inseg with nh_type=ip
            mpls_swap;  // inseg with nh_type==mpls
            mpls_drop;
            mpls_trap;  //router_alert_label
        }
        default_action = mpls_drop;
        size = MPLS_FIB_TABLE_SIZE;
        counters = mpls_stats;
    }
#endif /* MPLS_ENABLE */

    //
    // ***************** Control Flow *****************
    //
    apply {
//-----------------------------------------------------------------------
#if defined(SRV6_ENABLE) /* SRV6, IP-in-IP and MPLS */
//-----------------------------------------------------------------------
#if __TARGET_TOFINO__ == 1
        srh_len.apply();
        if (local_md.flags.rmac_hit) {
                if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                    dst_vtep.apply();
                } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_TUNNEL_ENABLE
                    if(!dst_vtepv6.apply().hit) {
                      my_sid.apply();
                      remove_srh.apply();
                    }
#endif
                } else if (lkp.mpls_pkt == true) {
#ifdef MPLS_ENABLE
                    if (local_md.mpls_enable) {
                        mpls_fib.apply();
                    }
#endif /* MPLS_ENABLE */
                }
        }
        if(local_md.tunnel.terminate == true) {
            pkt_validation.apply(hdr, local_md);
        }

#else
        srh_len.apply();
        if (local_md.flags.rmac_hit) {
                if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                    if (dst_vtep.apply().hit) {
                        pkt_validation.apply(hdr, local_md);
                    }
                } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
                    if (dst_vtepv6.apply().hit) {
                        pkt_validation.apply(hdr, local_md);
                    } else {
                        switch(my_sid.apply().action_run) {
                            end_dt4 : { pkt_validation.apply(hdr, local_md); }
                            end_dt6 : { pkt_validation.apply(hdr, local_md); }
                            end_dt46 : { pkt_validation.apply(hdr, local_md); }
                            end_dx4 : { pkt_validation.apply(hdr, local_md); }
                            end_dx6 : { pkt_validation.apply(hdr, local_md); }
                            end_with_usd : { pkt_validation.apply(hdr, local_md); }
                            end_x_with_usd : { pkt_validation.apply(hdr, local_md); }
                        }
                        remove_srh.apply();
                    }
                } else if (lkp.mpls_pkt == true) {
#ifdef MPLS_ENABLE
                    if (local_md.mpls_enable) {
                        switch(mpls_fib.apply().action_run) {
                            mpls_term : {
                                // MPLS->IP
                                pkt_validation.apply(hdr, local_md);
                            }
                        }
                    }
#endif /* MPLS_ENABLE */
                }
        }
#endif // TOFINO1
//-----------------------------------------------------------------------
#elif defined(VXLAN_ENABLE) /* VXLAN and IP-in-IP */
//-----------------------------------------------------------------------
        // outer RMAC lookup for tunnel termination.
        if (local_md.flags.rmac_hit) {
                if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                    switch(dst_vtep.apply().action_run) {
                        dst_vtep_hit : {
                            // Vxlan
                            if (vni_to_bd_mapping.apply().hit) {
                                if (!vxlan_rmac.apply().hit) {
                                  vxlan_device_rmac.apply();
                                };
                                pkt_validation.apply(hdr, local_md);
                            }
                        }

                        set_inner_bd_properties : {
                            // IPinIP or IPinGRE
                            pkt_validation.apply(hdr, local_md);
                        }
                    }
                } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_TUNNEL_ENABLE
                    switch(dst_vtepv6.apply().action_run) {
                        dst_vtep_hit : {
                            // Vxlan
                            if (vni_to_bd_mapping.apply().hit) {
                                if (!vxlan_rmac.apply().hit) {
                                  vxlan_device_rmac.apply();
                                };
                                pkt_validation.apply(hdr, local_md);
                            }
                        }

                        set_inner_bd_properties : {
                            // IPinIP
                            pkt_validation.apply(hdr, local_md);
                        }
                    }
#endif /* IPV6_TUNNEL_ENABLE */
                }
        }
//-----------------------------------------------------------------------
#else /* IP-in-IP and MPLS */
//-----------------------------------------------------------------------
        // outer RMAC lookup for tunnel termination.
        if (local_md.flags.rmac_hit) {
                if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                    if (dst_vtep.apply().hit) {
                        pkt_validation.apply(hdr, local_md);
                    }
                } else if (lkp.mpls_pkt == true) {
#ifdef MPLS_ENABLE
                    if (local_md.mpls_enable) {
                        switch(mpls_fib.apply().action_run) {
                            mpls_term : {
                                // MPLS->IP
                                pkt_validation.apply(hdr, local_md);
                            }
                        }
                    }
#endif /* MPLS_ENABLE */
                } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_TUNNEL_ENABLE
                    if (dst_vtepv6.apply().hit) {
                        pkt_validation.apply(hdr, local_md);
                    }
#endif /* IPV6_TUNNEL_ENABLE */
                }
        }
#endif /* VXLAN_ENABLE */

#ifdef TUNNEL_QOS_MODE_ENABLE
        if (local_md.tunnel.terminate &&
            local_md.tunnel.qos_mode == SWITCH_TUNNEL_MODE_UNIFORM) {
            lkp_ip_tos_outer.apply();
        }
#endif
    }
}

//-----------------------------------------------------------------------------
// Tunnel decapsulation
//
//-----------------------------------------------------------------------------
control TunnelDecap(inout switch_header_t hdr,
                    inout switch_local_metadata_t local_md)() {

    action copy_ipv4_header() {
        hdr.ipv4.setValid();
        hdr.ipv4.version = hdr.inner_ipv4.version;
        hdr.ipv4.ihl = hdr.inner_ipv4.ihl;
        hdr.ipv4.total_len = hdr.inner_ipv4.total_len;
        hdr.ipv4.identification = hdr.inner_ipv4.identification;
        hdr.ipv4.flags = hdr.inner_ipv4.flags;
        hdr.ipv4.frag_offset = hdr.inner_ipv4.frag_offset;
        hdr.ipv4.protocol = hdr.inner_ipv4.protocol;
        // hdr.ipv4.hdr_checksum = hdr.inner_ipv4.hdr_checksum;
        hdr.ipv4.src_addr = hdr.inner_ipv4.src_addr;
        hdr.ipv4.dst_addr = hdr.inner_ipv4.dst_addr;

#ifndef TUNNEL_TTL_MODE_ENABLE
        hdr.ipv4.ttl = hdr.inner_ipv4.ttl;
#endif /* TUNNEL_TTL_MODE_ENABLE */

        hdr.inner_ipv4.setInvalid();
    }

    action copy_ipv6_header() {
        hdr.ipv6.setValid();
        hdr.ipv6.version = hdr.inner_ipv6.version;
        hdr.ipv6.flow_label = hdr.inner_ipv6.flow_label;
        hdr.ipv6.payload_len = hdr.inner_ipv6.payload_len;
        hdr.ipv6.next_hdr = hdr.inner_ipv6.next_hdr;
        hdr.ipv6.src_addr = hdr.inner_ipv6.src_addr;
        hdr.ipv6.dst_addr = hdr.inner_ipv6.dst_addr;

#ifndef TUNNEL_TTL_MODE_ENABLE
        hdr.ipv6.hop_limit = hdr.inner_ipv6.hop_limit;
#endif /* TUNNEL_TTL_MODE_ENABLE */

        hdr.inner_ipv6.setInvalid();
    }

    action invalidate_vxlan_header() {
        hdr.vxlan.setInvalid();
    }

    action invalidate_vlan_tag0() {
        hdr.vlan_tag[0].setInvalid();
    }

    action decap_inner_ethernet_ipv4() {
        invalidate_vlan_tag0();
        hdr.ethernet = hdr.inner_ethernet;
        copy_ipv4_header();
        hdr.ipv6.setInvalid();
        hdr.udp.setInvalid();
        hdr.inner_ethernet.setInvalid();
        invalidate_vxlan_header();
    }

    action decap_inner_ethernet_ipv6() {
        invalidate_vlan_tag0();
        hdr.ethernet = hdr.inner_ethernet;
        copy_ipv6_header();
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.inner_ethernet.setInvalid();
        invalidate_vxlan_header();
    }

    action decap_inner_ethernet_non_ip() {
        invalidate_vlan_tag0();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.udp.setInvalid();
        hdr.inner_ethernet.setInvalid();
        invalidate_vxlan_header();
    }

    action decap_inner_ipv4() {
        invalidate_vlan_tag0();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        copy_ipv4_header();
        hdr.ipv6.setInvalid();
#ifdef GRE_ENABLE
	hdr.gre.setInvalid();
#endif /* GRE_ENABLE */
    }

    action decap_inner_ipv6() {
        invalidate_vlan_tag0();
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
        copy_ipv6_header();
        hdr.ipv4.setInvalid();
#ifdef GRE_ENABLE
	hdr.gre.setInvalid();
#endif /* GRE_ENABLE */
    }

    table decap_tunnel_hdr {
        key = {
            hdr.udp.isValid() : exact;
            hdr.inner_ethernet.isValid() : exact;
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
#if defined(MPLS_ENABLE)
            hdr.mpls[0].isValid() : exact;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].isValid() : exact;
            local_md.tunnel.mpls_pop_count : exact;
#endif
        }

        actions = {
            decap_inner_ethernet_ipv4;
            decap_inner_ethernet_ipv6;
            decap_inner_ethernet_non_ip;
            decap_inner_ipv4;
            decap_inner_ipv6;
        }

        const entries = {
#if defined(MPLS_ENABLE)
	    // Eth-in-IP-UDP tunnels
            (true, true, true, false, false, false, false, 0) : decap_inner_ethernet_ipv4;
            (true, true, false, true, false, false, false, 0) : decap_inner_ethernet_ipv6;
            (true, true, false, false, false, false, false, 0) : decap_inner_ethernet_non_ip;
	    // IP-in-IP or IP-in-IP-GRE
            (false, false, true, false, false, false, false, 0) : decap_inner_ipv4;
            (false, false, false, true, false, false, false, 0) : decap_inner_ipv6;
	    // IP-in-MPLS
            (false, false, true, false, true, false, false, 1) : decap_inner_ipv4;
            (false, false, false, true, true, false, false, 1) : decap_inner_ipv6;
            (false, false, true, false, true, true, false, 2) : decap_inner_ipv4;
            (false, false, false, true, true, true, false, 2) : decap_inner_ipv6;
            (false, false, true, false, true, true, true, 3) : decap_inner_ipv4;
            (false, false, false, true, true, true, true, 3) : decap_inner_ipv6;
#else
            (true, true, true, false) : decap_inner_ethernet_ipv4;
            (true, true, false, true) : decap_inner_ethernet_ipv6;
            (true, true, false, false) : decap_inner_ethernet_non_ip;
            (false, false, true, false) : decap_inner_ipv4;
            (false, false, false, true) : decap_inner_ipv6;
#endif
        }
        size = MIN_TABLE_SIZE;
    }

#if __TARGET_TOFINO__ == 2

    // Pkt length adjustment

    action decap_outer_ipv4_udp() {
        // IPv4 (20) + UDP (8) + VXLAN (8)+ Inner Ethernet (14)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv4.minSizeInBytes() -
        hdr.udp.minSizeInBytes() - hdr.vxlan.minSizeInBytes() - hdr.inner_ethernet.minSizeInBytes();
    }

    action decap_outer_ipv6_udp() {
        // IPv6 (40) + UDP (8) + VXLAN (8)+ Inner Ethernet (14)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv6.minSizeInBytes() -
        hdr.udp.minSizeInBytes() - hdr.vxlan.minSizeInBytes() - hdr.inner_ethernet.minSizeInBytes();
    }

    action decap_outer_ipv4() {
        // IPv4 (20)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv4.minSizeInBytes();
    }

    action decap_outer_ipv6() {
        // IPv6 (40)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv6.minSizeInBytes();
    }

    action decap_outer_qtag_ipv4_udp() {
        // Qtag(4) + IPv4 (20) + UDP (8) + VXLAN (8)+ Inner Ethernet (14)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv4.minSizeInBytes() - hdr.vlan_tag[0].minSizeInBytes() -
        hdr.udp.minSizeInBytes() - hdr.vxlan.minSizeInBytes() - hdr.inner_ethernet.minSizeInBytes();
    }

    action decap_outer_qtag_ipv6_udp() {
        // Qtag(4) + IPv6 (40) + UDP (8) + VXLAN (8)+ Inner Ethernet (14)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv6.minSizeInBytes() - hdr.vlan_tag[0].minSizeInBytes() -
        hdr.udp.minSizeInBytes() - hdr.vxlan.minSizeInBytes() - hdr.inner_ethernet.minSizeInBytes();
    }

    action decap_outer_qtag_ipv4() {
        // Qtag(4) + IPv4 (20)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv4.minSizeInBytes() - hdr.vlan_tag[0].minSizeInBytes();
    }

    action decap_outer_qtag_ipv6() {
        // Qtag(4) + IPv6 (40)
      local_md.pkt_length = local_md.pkt_length - hdr.ipv6.minSizeInBytes() - hdr.vlan_tag[0].minSizeInBytes();
    }

    table decap_len_adjust {
        key = {
            hdr.udp.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
            hdr.vlan_tag[0].isValid() : exact;
        }

        actions = {
            decap_outer_ipv4_udp;
            decap_outer_ipv6_udp;
            decap_outer_ipv6;
            decap_outer_ipv4;
            decap_outer_qtag_ipv4_udp;
            decap_outer_qtag_ipv6_udp;
            decap_outer_qtag_ipv6;
            decap_outer_qtag_ipv4;
        }

        const entries = {
          (true,   true, false, false) : decap_outer_ipv4_udp;
          (true,  false,  true, false) : decap_outer_ipv6_udp;
          (false,  true, false, false) : decap_outer_ipv4;
          (false, false,  true, false) : decap_outer_ipv6;
          (true,   true, false,  true) : decap_outer_qtag_ipv4_udp;
          (true,  false,  true,  true) : decap_outer_qtag_ipv6_udp;
          (false,  true, false,  true) : decap_outer_qtag_ipv4;
          (false, false,  true,  true) : decap_outer_qtag_ipv6;
        }
        size = MIN_TABLE_SIZE;
    }
#endif /* __TARGET_TOFINO__ == 2 */

#ifdef TUNNEL_TTL_MODE_ENABLE
    // ******** TTL - Outer for Uniform, Inner for Pipe mode ****************
    action decap_ttl_v4_pipe() {
        hdr.ipv4.ttl = hdr.inner_ipv4.ttl;
    }
    action decap_ttl_v6_pipe() {
        hdr.ipv6.hop_limit = hdr.inner_ipv6.hop_limit;
    }

//    action decap_ttl_v4_in_v4_uniform() {
//        hdr.ipv4.ttl = hdr.ipv4.ttl;
//    }
    action decap_ttl_v4_in_v6_uniform() {
        hdr.ipv4.ttl = hdr.ipv6.hop_limit;
    }
    action decap_ttl_v6_in_v4_uniform() {
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
    }
//    action decap_ttl_v6_in_v6_uniform() {
//        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit;
//    }

#ifdef MPLS_ENABLE
    action decap_ttl_v4_in_mpls_uniform() {
        hdr.ipv4.ttl = hdr.mpls[0].ttl;
    }
    action decap_ttl_v6_in_mpls_uniform() {
        hdr.ipv6.hop_limit = hdr.mpls[0].ttl;
    }
    action decap_ttl_mpls_1_uniform() {
        hdr.mpls[1].ttl = hdr.mpls[0].ttl;
    }
    action decap_ttl_mpls_2_uniform() {
        hdr.mpls[2].ttl = hdr.mpls[0].ttl;
    }
#endif

    table decap_ttl {
        key = {
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
#ifdef MPLS_ENABLE
            hdr.mpls[0].isValid() : exact;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].isValid() : exact;
            local_md.tunnel.mpls_pop_count : exact;
#endif
            local_md.tunnel.ttl_mode : exact;
        }
        actions = {
            NoAction;
            decap_ttl_v4_pipe;
            decap_ttl_v6_pipe;
// nop      decap_ttl_v4_in_v4_uniform;
            decap_ttl_v4_in_v6_uniform;
            decap_ttl_v6_in_v4_uniform;
// nop      decap_ttl_v6_in_v6_uniform;
#ifdef MPLS_ENABLE
            decap_ttl_v4_in_mpls_uniform;
            decap_ttl_v6_in_mpls_uniform;
            decap_ttl_mpls_1_uniform;
            decap_ttl_mpls_2_uniform;
#endif
        }
        const entries = {
#ifdef MPLS_ENABLE
            (true, false, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (true, false, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (false, true, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
            (false, true, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
//          (true, false, true, false, false, false, false, 0,
//           SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_v4_uniform;
            (true, false, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_v6_uniform;
            (false, true, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_v4_uniform;
//          (false, true, false, true, false, false, false, 0,
//           SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_v6_uniform;
            (true, false, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (true, false, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (true, false, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (false, true, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
            (false, true, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
            (false, true, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
            (true, false, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_mpls_uniform;
            (true, false, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_mpls_uniform;
            (true, false, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_mpls_uniform;
            (false, true, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_mpls_uniform;
            (false, true, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_mpls_uniform;
            (false, true, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_mpls_uniform;
            (true, false, false, false, true, true, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_1_uniform;
            (true, false, false, false, true, true, true, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_1_uniform;
            (false, true, false, false, true, true, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_1_uniform;
            (false, true, false, false, true, true, true, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_1_uniform;
            (true, false, false, false, true, true, true, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_2_uniform;
            (false, true, false, false, true, true, true, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_mpls_2_uniform;
#else
            (true, false, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (true, false, false, true,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v4_pipe;
            (false, true, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
            (false, true, false, true,
             SWITCH_TUNNEL_MODE_PIPE) : decap_ttl_v6_pipe;
//          (true, false, true, false,
//           SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_v4_uniform;
            (true, false, false, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v4_in_v6_uniform;
            (false, true, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_v4_uniform;
//          (false, true, false, true,
//           SWITCH_TUNNEL_MODE_UNIFORM) : decap_ttl_v6_in_v6_uniform;
#endif
        }
        const default_action = NoAction;
        size = 32;
    }
#endif /* TUNNEL_TTL_MODE_ENABLE */

    // ******** DSCP - Outer for Uniform, Inner for Pipe mode ****************
#ifdef TUNNEL_QOS_MODE_ENABLE
    action decap_dscp_v4_in_v4_pipe() {
        local_md.qos.outer_ecn = hdr.ipv4.diffserv[1:0];
        hdr.ipv4.diffserv = hdr.inner_ipv4.diffserv;
    }
    action decap_dscp_v4_in_v6_pipe() {
        @in_hash { local_md.qos.outer_ecn = hdr.ipv6.traffic_class[1:0]; }
        hdr.ipv4.diffserv = hdr.inner_ipv4.diffserv;
    }
    action decap_dscp_v6_in_v4_pipe() {
        local_md.qos.outer_ecn = hdr.ipv4.diffserv[1:0];
        hdr.ipv6.traffic_class = hdr.inner_ipv6.traffic_class;
    }
    action decap_dscp_v6_in_v6_pipe() {
        @in_hash { local_md.qos.outer_ecn = hdr.ipv6.traffic_class[1:0]; }
        hdr.ipv6.traffic_class = hdr.inner_ipv6.traffic_class;
    }
#endif

    action decap_dscp_v4_in_v4_uniform() {
#if defined(TUNNEL_QOS_MODE_ENABLE)
        local_md.qos.outer_ecn = hdr.ipv4.diffserv[1:0];
#endif
// nop  hdr.ipv4.diffserv = hdr.ipv4.diffserv;
    }
    action decap_dscp_v4_in_v6_uniform() {
#if defined(TUNNEL_QOS_MODE_ENABLE)
        @in_hash { local_md.qos.outer_ecn = hdr.ipv6.traffic_class[1:0]; }
#endif
        @in_hash { hdr.ipv4.diffserv = hdr.ipv6.traffic_class; }
    }
    action decap_dscp_v6_in_v4_uniform() {
#if defined(TUNNEL_QOS_MODE_ENABLE)
        local_md.qos.outer_ecn = hdr.ipv4.diffserv[1:0];
#endif
        @in_hash { hdr.ipv6.traffic_class = hdr.ipv4.diffserv; }
    }
    action decap_dscp_v6_in_v6_uniform() {
#if defined(TUNNEL_QOS_MODE_ENABLE)
        @in_hash { local_md.qos.outer_ecn = hdr.ipv6.traffic_class[1:0]; }
#endif
// nop  hdr.ipv6.traffic_class = hdr.ipv6.traffic_class;
    }

#ifdef MPLS_ENABLE
#ifdef TUNNEL_QOS_MODE_ENABLE
    action decap_dscp_v4_in_mpls_pipe() {
        local_md.qos.outer_ecn = 0;
        hdr.ipv4.diffserv = hdr.inner_ipv4.diffserv;
    }
    action decap_dscp_v6_in_mpls_pipe() {
        local_md.qos.outer_ecn = 0;
        hdr.ipv6.traffic_class = hdr.inner_ipv6.traffic_class;
    }
#endif /* TUNNEL_QOS_MODE_ENABLE */
    action decap_dscp_v4_in_mpls_uniform() {
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.qos.outer_ecn = 0;
#endif
        @in_hash { hdr.ipv4.diffserv[7:5] = hdr.mpls[0].exp; }
        hdr.ipv4.diffserv[4:0] = 0;
    }
    action decap_dscp_v6_in_mpls_uniform() {
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.qos.outer_ecn = 0;
#endif
        @in_hash { hdr.ipv6.traffic_class[7:5] = hdr.mpls[0].exp; }
        hdr.ipv6.traffic_class[4:0] = 0;
    }
    action decap_dscp_mpls_1_uniform() {
        hdr.mpls[1].exp = hdr.mpls[0].exp;
    }
    action decap_dscp_mpls_2_uniform() {
        hdr.mpls[2].exp = hdr.mpls[0].exp;
    }
#endif /* MPLS_ENABLE */

    table decap_dscp {
        key = {
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
#ifdef MPLS_ENABLE
            hdr.mpls[0].isValid() : exact;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].isValid() : exact;
            local_md.tunnel.mpls_pop_count : exact;
#endif
#ifdef TUNNEL_QOS_MODE_ENABLE
            local_md.tunnel.qos_mode : exact;
#endif
        }
        actions = {
            NoAction;
#ifdef TUNNEL_QOS_MODE_ENABLE
            decap_dscp_v4_in_v4_pipe;
            decap_dscp_v4_in_v6_pipe;
            decap_dscp_v6_in_v4_pipe;
            decap_dscp_v6_in_v6_pipe;
#endif /* TUNNEL_QOS_MODE_ENABLE */
            decap_dscp_v4_in_v4_uniform;
            decap_dscp_v4_in_v6_uniform;
            decap_dscp_v6_in_v4_uniform;
            decap_dscp_v6_in_v6_uniform;
#ifdef MPLS_ENABLE
#ifdef TUNNEL_QOS_MODE_ENABLE
            decap_dscp_v4_in_mpls_pipe;
            decap_dscp_v6_in_mpls_pipe;
#endif /* TUNNEL_QOS_MODE_ENABLE */
            decap_dscp_v4_in_mpls_uniform;
            decap_dscp_v6_in_mpls_uniform;
            decap_dscp_mpls_1_uniform;
            decap_dscp_mpls_2_uniform;
#endif /* MPLS_ENABLE */
        }
        const entries = {
#ifdef MPLS_ENABLE
#ifdef TUNNEL_QOS_MODE_ENABLE
            (true, false, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_v4_pipe;
            (true, false, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_v6_pipe;
            (false, true, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_v4_pipe;
            (false, true, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_v6_pipe;
            (true, false, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_v4_uniform;
            (true, false, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_v6_uniform;
            (false, true, true, false, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_v4_uniform;
            (false, true, false, true, false, false, false, 0,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_v6_uniform;
            (true, false, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_mpls_pipe;
            (true, false, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_mpls_pipe;
            (true, false, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_mpls_pipe;
            (false, true, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_mpls_pipe;
            (false, true, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_mpls_pipe;
            (false, true, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_mpls_pipe;
            (true, false, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_mpls_uniform;
            (true, false, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_mpls_uniform;
            (true, false, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_mpls_uniform;
            (false, true, false, false, true, false, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_mpls_uniform;
            (false, true, false, false, true, true, false, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_mpls_uniform;
            (false, true, false, false, true, true, true, 3,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_mpls_uniform;
            (true, false, false, false, true, true, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_1_uniform;
            (true, false, false, false, true, true, true, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_1_uniform;
            (false, true, false, false, true, true, false, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_1_uniform;
            (false, true, false, false, true, true, true, 1,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_1_uniform;
            (true, false, false, false, true, true, true, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_2_uniform;
            (false, true, false, false, true, true, true, 2,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_mpls_2_uniform;
#else /* !TUNNEL_QOS_MODE_ENABLE */
            (true, false, true, false, false, false, false,
             0) : decap_dscp_v4_in_v4_uniform;
            (true, false, false, true, false, false, false,
             0) : decap_dscp_v4_in_v6_uniform;
            (false, true, true, false, false, false, false,
             0) : decap_dscp_v6_in_v4_uniform;
            (false, true, false, true, false, false, false,
             0) : decap_dscp_v6_in_v6_uniform;
            (true, false, false, false, true, false, false,
             1) : decap_dscp_v4_in_mpls_uniform;
            (true, false, false, false, true, true, false,
             2) : decap_dscp_v4_in_mpls_uniform;
            (true, false, false, false, true, true, true,
             3) : decap_dscp_v4_in_mpls_uniform;
            (false, true, false, false, true, false, false,
             1) : decap_dscp_v6_in_mpls_uniform;
            (false, true, false, false, true, true, false,
             2) : decap_dscp_v6_in_mpls_uniform;
            (false, true, false, false, true, true, true,
             3) : decap_dscp_v6_in_mpls_uniform;
            (true, false, false, false, true, true, false,
             1) : decap_dscp_mpls_1_uniform;
            (true, false, false, false, true, true, true,
             1) : decap_dscp_mpls_1_uniform;
            (false, true, false, false, true, true, false,
             1) : decap_dscp_mpls_1_uniform;
            (false, true, false, false, true, true, true,
             1) : decap_dscp_mpls_1_uniform;
            (true, false, false, false, true, true, true,
             2) : decap_dscp_mpls_2_uniform;
            (false, true, false, false, true, true, true,
             2) : decap_dscp_mpls_2_uniform;
#endif /* TUNNEL_QOS_MODE_ENABLE */
#else /* !MPLS_ENABLE */
#ifdef TUNNEL_QOS_MODE_ENABLE
            (true, false, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_v4_pipe;
            (true, false, false, true,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v4_in_v6_pipe;
            (false, true, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_v4_pipe;
            (false, true, false, true,
             SWITCH_TUNNEL_MODE_PIPE) : decap_dscp_v6_in_v6_pipe;
            (true, false, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_v4_uniform;
            (true, false, false, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v4_in_v6_uniform;
            (false, true, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_v4_uniform;
            (false, true, false, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : decap_dscp_v6_in_v6_uniform;
#else /* !TUNNEL_QOS_MODE_ENABLE */
            (true, false, true, false) : decap_dscp_v4_in_v4_uniform;
            (true, false, false, true) : decap_dscp_v4_in_v6_uniform;
            (false, true, true, false) : decap_dscp_v6_in_v4_uniform;
            (false, true, false, true) : decap_dscp_v6_in_v6_uniform;
#endif /* TUNNEL_QOS_MODE_ENABLE */
#endif /* MPLS_ENABLE */
        }
        const default_action = decap_dscp_v4_in_v4_uniform;
        size = 32;
    }

#ifndef TUNNEL_ECN_RFC_6040_DISABLE
    // When RFC 6040 ECN tunneling is disabled, then the behavior is:
    // - In case of uniform mode, the new ECN value is the incoming outer ECN
    // - In case of pipe mode, the new ECN value is the incoming inner ECN
    // RFC 6040 ECN tunneling should not be disabled when qos_mode is enabled.
    // RFC 6040 ECN tunneling should not be disabled when MPLS is enabled
    // and uniform mode is supported, since the ECN bits will always be 0.

    // ******** ECN update according to RFC 6040 ************
    action set_ipv4_ecn_bits(switch_ecn_codepoint_t ecn) {
        hdr.ipv4.diffserv[1:0] = ecn;
    }

    table decap_ipv4_ecn {
        key = {
#if defined(TUNNEL_QOS_MODE_ENABLE)
            local_md.qos.outer_ecn : exact;
#else
            hdr.ipv4.diffserv[1:0] : exact;
#endif
            hdr.inner_ipv4.diffserv[1:0] : exact;
        }
        actions = {
            set_ipv4_ecn_bits;
        }
        const entries = {
            {NON_ECT, NON_ECT} : set_ipv4_ecn_bits(NON_ECT);
            {NON_ECT, ECT0   } : set_ipv4_ecn_bits(ECT0);
            {NON_ECT, ECT1   } : set_ipv4_ecn_bits(ECT1);
            {NON_ECT, CE     } : set_ipv4_ecn_bits(CE);
            {ECT0   , NON_ECT} : set_ipv4_ecn_bits(NON_ECT);
            {ECT0   , ECT0   } : set_ipv4_ecn_bits(ECT0);
            {ECT0   , ECT1   } : set_ipv4_ecn_bits(ECT1);
            {ECT0   , CE     } : set_ipv4_ecn_bits(CE);
            {ECT1   , NON_ECT} : set_ipv4_ecn_bits(NON_ECT);
            {ECT1   , ECT0   } : set_ipv4_ecn_bits(ECT1);
            {ECT1   , ECT1   } : set_ipv4_ecn_bits(ECT1);
            {ECT1   , CE     } : set_ipv4_ecn_bits(CE);
//todo      {CE     , NON_ECT} : set_ipv4_ecn_bits(Drop);
            {CE     , ECT0   } : set_ipv4_ecn_bits(CE);
            {CE     , ECT1   } : set_ipv4_ecn_bits(CE);
            {CE     , CE     } : set_ipv4_ecn_bits(CE);
        }
        size = 16;
    }

    action set_ipv6_ecn_bits(switch_ecn_codepoint_t ecn) {
        hdr.ipv6.traffic_class[1:0] = ecn;
    }

    table decap_ipv6_ecn {
        key = {
#if defined(TUNNEL_QOS_MODE_ENABLE)
            local_md.qos.outer_ecn : exact;
#else
            hdr.ipv6.traffic_class[1:0] : exact;
#endif
            hdr.inner_ipv6.traffic_class[1:0] : exact;
        }
        actions = {
            set_ipv6_ecn_bits;
        }
        const entries = {
            {NON_ECT, NON_ECT} : set_ipv6_ecn_bits(NON_ECT);
            {NON_ECT, ECT0   } : set_ipv6_ecn_bits(ECT0);
            {NON_ECT, ECT1   } : set_ipv6_ecn_bits(ECT1);
            {NON_ECT, CE     } : set_ipv6_ecn_bits(CE);
            {ECT0   , NON_ECT} : set_ipv6_ecn_bits(NON_ECT);
            {ECT0   , ECT0   } : set_ipv6_ecn_bits(ECT0);
            {ECT0   , ECT1   } : set_ipv6_ecn_bits(ECT1);
            {ECT0   , CE     } : set_ipv6_ecn_bits(CE);
            {ECT1   , NON_ECT} : set_ipv6_ecn_bits(NON_ECT);
            {ECT1   , ECT0   } : set_ipv6_ecn_bits(ECT1);
            {ECT1   , ECT1   } : set_ipv6_ecn_bits(ECT1);
            {ECT1   , CE     } : set_ipv6_ecn_bits(CE);
//todo      {CE     , NON_ECT} : set_ipv6_ecn_bits(Drop);
            {CE     , ECT0   } : set_ipv6_ecn_bits(CE);
            {CE     , ECT1   } : set_ipv6_ecn_bits(CE);
            {CE     , CE     } : set_ipv6_ecn_bits(CE);
        }
        size = 16;
    }
#endif /* !TUNNEL_ECN_RFC_6040_DISABLE */

    apply {
        if (!local_md.flags.bypass_egress) {
            // Copy inner L2/L3 headers into outer headers.
#ifdef TUNNEL_TTL_MODE_ENABLE
            decap_ttl.apply();
#endif /* TUNNEL_TTL_MODE_ENABLE */
            decap_dscp.apply();
#if __TARGET_TOFINO__ == 2
            decap_len_adjust.apply();
#endif /* __TARGET_TOFINO__ == 2 */
            decap_tunnel_hdr.apply();
#ifndef TUNNEL_ECN_RFC_6040_DISABLE
            if (hdr.inner_ipv4.isValid() && hdr.ipv4.isValid()) {
                decap_ipv4_ecn.apply();
            } else if (hdr.inner_ipv6.isValid() && hdr.ipv6.isValid()) {
                decap_ipv6_ecn.apply();
            }
#endif /* !TUNNEL_ECN_RFC_6040_DISABLE */
        }
    }
}

#ifdef MPLS_ENABLE
//-----------------------------------------------------------------------------
//
// POP MPLS Labels
//
//-----------------------------------------------------------------------------

control MplsPop(inout switch_header_t hdr,
                inout switch_local_metadata_t local_md) {

    @name(".mpls_pop1")
    action mpls_pop1() {
        hdr.mpls.pop_front(1);
        local_md.pkt_length = local_md.pkt_length - hdr.mpls[0].minSizeInBytes();
    }
    @name(".mpls_pop2")
    action mpls_pop2() {
        hdr.mpls.pop_front(2);
        local_md.pkt_length = local_md.pkt_length - hdr.mpls[0].minSizeInBytes() - hdr.mpls[1].minSizeInBytes();
    }
    @name(".mpls_pop3")
    action mpls_pop3() {
        hdr.mpls.pop_front(3);
        local_md.pkt_length = local_md.pkt_length - hdr.mpls[0].minSizeInBytes() - hdr.mpls[1].minSizeInBytes() - hdr.mpls[2].minSizeInBytes();
    }
    action mpls_invalid1() {
        hdr.mpls[0].setInvalid();
    }
    action mpls_invalid2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
    }
    action mpls_invalid3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
    }

    // Pop MPLS Label(s)
    @name(".pop_mpls")
    table pop_mpls {
        key = {
            local_md.tunnel.mpls_pop_count : exact;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].isValid() : exact;
        }

        actions = {
            mpls_pop1;
            mpls_pop2;
            mpls_invalid1;
            mpls_invalid2;
            mpls_invalid3;
        }
        const entries = {
            (1, false, false) : mpls_invalid1;
            (1, true, false)  : mpls_pop1;
            (1, true, true)   : mpls_pop1;
            (2, true, false)  : mpls_invalid2;
            (2, true, true)   : mpls_pop2;
            (3, true, true)   : mpls_invalid3;
        }
        size = 8;
    }

    apply {
        // Pop MPLS labels
        if (!local_md.flags.bypass_egress)
            pop_mpls.apply();
    }
}
#endif /* MPLS_ENABLE */

#ifdef TUNNEL_ENCAP_ENABLE
//-------------------------------------------------------------
// IP Tunnel Encapsulation - Step 1
//
// Tunnel Nexthop
//-------------------------------------------------------------

control TunnelNexthop(inout switch_header_t hdr,
                      inout switch_local_metadata_t local_md) {
    // **************** Tunnel Nexthop table  *************************

    @name(".l2_tunnel_encap")
    action l2_tunnel_encap(
                                  switch_tunnel_type_t type,
                                  switch_tunnel_ip_index_t dip_index,
                                  switch_tunnel_index_t tunnel_index) {
        local_md.tunnel.type = type;
        local_md.tunnel.index = tunnel_index;
        local_md.tunnel.dip_index = dip_index;
        // While the inner headers are L2 forwarded, the outer headers are
        // routed. In order to properly process the outer ethernet header,
        // local_md.flags.routed must be set to true. This assumes that inner
        // header operations (e.g. egress_vrf) have already been completed
        // while local_md.flags.routed was false, and outer header operations
        // (e.g. outer_nexthop, neighbor, egress_bd.bd_mapping) have not yet
        // started.
        local_md.flags.routed = true;
    }

    @name(".l3_tunnel_encap")
    action l3_tunnel_encap(
                                  mac_addr_t dmac,
                                  switch_tunnel_type_t type,
                                  switch_tunnel_ip_index_t dip_index,
                                  switch_tunnel_index_t tunnel_index) {
        local_md.flags.routed = true;
        local_md.tunnel.type = type;
        local_md.tunnel.dip_index = dip_index; // Index of IP address from the nexthop object
        local_md.tunnel.index = tunnel_index; // programing_note: id of the tunnel from the nexthop object
        hdr.ethernet.dst_addr = dmac; // programming_note: program switch global dmac if nexthop doesn't provide dmac
    }

    @name(".l3_tunnel_encap_with_vni")
    action l3_tunnel_encap_with_vni(
                                      mac_addr_t dmac,
                                      switch_tunnel_type_t type,
                                      switch_tunnel_vni_t vni,
                                      switch_tunnel_ip_index_t dip_index,
                                      switch_tunnel_index_t tunnel_index) {
        local_md.flags.routed = true;
        local_md.tunnel.type = type;
        local_md.tunnel.index = tunnel_index;
        local_md.tunnel.dip_index = dip_index;
        hdr.ethernet.dst_addr = dmac;
        local_md.tunnel.vni = vni;       // programming_note: call this action only if nexthop provides vni OR for asymmetric IRB (rif->vlan>vni)
    }

#ifdef MPLS_ENABLE
    @name(".mpls_push")
    action mpls_push(bit<3> label_count, bit<1> swap, bit<1> ttl_mode,
                     bit<8> encap_ttl, bit<1> qos_mode, bit<3> encap_exp) {
        local_md.tunnel.type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS;
        local_md.tunnel.mpls_push_count = label_count; // programming_note: from nexthop_attr
        local_md.tunnel.mpls_encap_ttl = encap_ttl;
        local_md.tunnel.mpls_encap_exp = encap_exp;
        local_md.tunnel.ttl_mode = ttl_mode;
        local_md.tunnel.qos_mode = qos_mode;
        local_md.tunnel.mpls_swap = swap;
    }
#endif /* MPLS_ENABLE */

    @name(".srv6_encap")
    action srv6_encap(switch_tunnel_index_t tunnel_index, bit<3> seg_len) {
        local_md.flags.routed = true;
        local_md.tunnel.type = SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP;
        local_md.tunnel.index = tunnel_index;
        local_md.tunnel.srv6_seg_len = seg_len;
    }

    @name(".srv6_insert")
    action srv6_insert(bit<3> seg_len) {
        local_md.flags.routed = true;
        local_md.tunnel.type = SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT;
        local_md.tunnel.srv6_seg_len = seg_len;
    }

    @name(".tunnel_nexthop")
    table tunnel_nexthop {
        //Note: Nexthop table for type == Tunnel Encap | MPLS | SRv6
        key = { local_md.tunnel_nexthop : exact; }
        actions = {
            NoAction;
            l2_tunnel_encap;
            l3_tunnel_encap;
            l3_tunnel_encap_with_vni;
#ifdef MPLS_ENABLE
            mpls_push;
#endif
#ifdef SRV6_ENABLE
            srv6_encap;
            srv6_insert;
#endif
        }

        const default_action = NoAction;
        size = TUNNEL_NEXTHOP_TABLE_SIZE;
    }


    // **************** Control Flow  *************************
    apply {
        if (!local_md.flags.bypass_egress) {
            tunnel_nexthop.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// IP/MPLS Tunnel encapsulation - Step 2
//         -- Copy Outer Headers to inner
//         -- Add Tunnel Header (VXLAN, GRE etc)
//         -- MPLS Label Push
//-----------------------------------------------------------------------------
control TunnelEncap(inout switch_header_t hdr,
                    inout switch_local_metadata_t local_md)() {
    bit<16> payload_len;
    bit<8> ip_proto;
    bit<16> gre_proto;

    //
    // ************ Copy outer to inner **************************
    //
    action copy_ipv4_header() {
        // Copy all of the IPv4 header fields.
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4.version = hdr.ipv4.version;
        hdr.inner_ipv4.ihl = hdr.ipv4.ihl;
        hdr.inner_ipv4.diffserv = hdr.ipv4.diffserv;
        hdr.inner_ipv4.total_len = hdr.ipv4.total_len;
        hdr.inner_ipv4.identification = hdr.ipv4.identification;
        hdr.inner_ipv4.flags = hdr.ipv4.flags;
        hdr.inner_ipv4.frag_offset = hdr.ipv4.frag_offset;
        hdr.inner_ipv4.ttl = hdr.ipv4.ttl;
        hdr.inner_ipv4.protocol = hdr.ipv4.protocol;
        // hdr.inner_ipv4.hdr_checksum = hdr.ipv4.hdr_checksum;
        hdr.inner_ipv4.src_addr = hdr.ipv4.src_addr;
        hdr.inner_ipv4.dst_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.setInvalid();
        local_md.inner_ipv4_checksum_update_en = true;
    }

    action copy_ipv6_header() {
        hdr.inner_ipv6.version = hdr.ipv6.version;
        hdr.inner_ipv6.flow_label = hdr.ipv6.flow_label;
        hdr.inner_ipv6.payload_len = hdr.ipv6.payload_len;
        hdr.inner_ipv6.src_addr = hdr.ipv6.src_addr;
        hdr.inner_ipv6.dst_addr = hdr.ipv6.dst_addr;
        hdr.inner_ipv6.hop_limit = hdr.ipv6.hop_limit;
        hdr.inner_ipv6.traffic_class = hdr.ipv6.traffic_class;
        hdr.ipv6.setInvalid();
    }

    action copy_inner_ipv4_udp() {
        payload_len = hdr.ipv4.total_len;
        copy_ipv4_header();
        hdr.inner_udp = hdr.udp;
        hdr.udp.setInvalid();
        ip_proto = IP_PROTOCOLS_IPV4;
	gre_proto = GRE_PROTOCOLS_IP;
    }

/*
    action copy_inner_ipv4_tcp() {
        payload_len = hdr.ipv4.total_len;
        copy_ipv4_header();
        hdr.inner_tcp = hdr.tcp;
        hdr.tcp.setInvalid();
        ip_proto = IP_PROTOCOLS_IPV4;
	gre_proto = GRE_PROTOCOLS_IP;
    }
*/
    action copy_inner_ipv4_unknown() {
        payload_len = hdr.ipv4.total_len;
        copy_ipv4_header();
        ip_proto = IP_PROTOCOLS_IPV4;
	gre_proto = GRE_PROTOCOLS_IP;
    }

    action copy_inner_ipv6_udp() {
        payload_len = hdr.ipv6.payload_len + 16w40;
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.inner_udp = hdr.udp;
        hdr.udp.setInvalid();
        hdr.ipv6.setInvalid();
        ip_proto = IP_PROTOCOLS_IPV6;
	gre_proto = GRE_PROTOCOLS_IPV6;
    }

/*
    action copy_inner_ipv6_tcp() {
        payload_len = hdr.ipv6.payload_len + 16w40;
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.inner_tcp = hdr.tcp;
        hdr.tcp.setInvalid();
        hdr.ipv6.setInvalid();
        ip_proto = IP_PROTOCOLS_IPV6;
	gre_proto = GRE_PROTOCOLS_IPV6;
    }
*/
    action copy_inner_ipv6_unknown() {
        payload_len = hdr.ipv6.payload_len + 16w40;
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.ipv6.setInvalid();
        ip_proto = IP_PROTOCOLS_IPV6;
	gre_proto = GRE_PROTOCOLS_IPV6;
    }

    action copy_inner_non_ip() {
        payload_len = local_md.pkt_length - 16w14;
    }


    table tunnel_encap_0 {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
            hdr.udp.isValid() : exact;
            // hdr.tcp.isValid() : exact; uncomment and add tcp actions if tcp header is parsed in egress
        }

        actions = {
            copy_inner_ipv4_udp;
            copy_inner_ipv4_unknown;
            copy_inner_ipv6_udp;
            copy_inner_ipv6_unknown;
	    copy_inner_non_ip;
        }

        const entries = {
            (true, false, false) : copy_inner_ipv4_unknown();
            (false, true, false) : copy_inner_ipv6_unknown();
            (true, false, true) : copy_inner_ipv4_udp();
            (false, true, true) : copy_inner_ipv6_udp();
            (false, false, false) : copy_inner_non_ip();
        }
        size = 8;
    }

    //
    // ************ Add outer IP encapsulation **************************
    //
    action add_udp_header(bit<16> src_port, bit<16> dst_port) {
        hdr.udp.setValid();
        hdr.udp.src_port = src_port;
        hdr.udp.dst_port = dst_port;
        hdr.udp.checksum = 0;
        // hdr.udp.length = 0;
    }

    action add_vxlan_header(bit<24> vni) {
#ifdef VXLAN_ENABLE
        hdr.vxlan.setValid();
        hdr.vxlan.flags = 8w0x08;
        // hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = vni;
        // hdr.vxlan.reserved2 = 0;
#endif
    }

    action add_gre_header(bit<16> proto) {
#ifdef GRE_ENABLE
        hdr.gre.setValid();
        hdr.gre.proto = proto;
        hdr.gre.flags_version = 0;
#endif
    }

    action add_ipv4_header(bit<8> proto) {
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4w4;
        hdr.ipv4.ihl = 4w5;
        // hdr.ipv4.total_len = 0;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.frag_offset = 0;
        hdr.ipv4.protocol = proto;
    }

    action add_ipv6_header(bit<8> proto) {
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4w6;
        hdr.ipv6.flow_label = 0;
        // hdr.ipv6.payload_len = 0;
        hdr.ipv6.next_hdr = proto;
    }

#ifdef VXLAN_ENABLE
    @name(".encap_ipv4_vxlan")
    action encap_ipv4_vxlan(bit<16> vxlan_port) {
        hdr.inner_ethernet = hdr.ethernet;
        add_ipv4_header(IP_PROTOCOLS_UDP);
        hdr.ipv4.flags = 0x2;
        // Total length = packet length + 50
        //   IPv4 (20) + UDP (8) + VXLAN (8)+ Inner Ethernet (14)
        hdr.ipv4.total_len = payload_len + hdr.ipv4.minSizeInBytes() +
        hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();
        add_udp_header(local_md.tunnel.hash, vxlan_port);
        // UDP length = packet length + 30
        //   UDP (8) + VXLAN (8)+ Inner Ethernet (14)
        hdr.udp.length = payload_len + hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv4.minSizeInBytes() +
        hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();

        add_vxlan_header(local_md.tunnel.vni);
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }
    @name(".encap_ipv6_vxlan")
    action encap_ipv6_vxlan(bit<16> vxlan_port) {
#ifdef IPV6_TUNNEL_ENABLE
        hdr.inner_ethernet = hdr.ethernet;
        add_ipv6_header(IP_PROTOCOLS_UDP);
        // Payload length = packet length + 50
        //   UDP (8) + VXLAN (8)+ Inner Ethernet (14)
        hdr.ipv6.payload_len = payload_len + hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();
        add_udp_header(local_md.tunnel.hash, vxlan_port);
        // UDP length = packet length + 30
        //   UDP (8) + VXLAN (8)+ Inner Ethernet (14)
        hdr.udp.length = payload_len + hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv6.minSizeInBytes() +
        hdr.udp.minSizeInBytes() + hdr.vxlan.minSizeInBytes() + hdr.inner_ethernet.minSizeInBytes();

        add_vxlan_header(local_md.tunnel.vni);
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
#endif
    }
#endif /* VXLAN_ENABLE */

    @name(".encap_ipv4_ip")
    action encap_ipv4_ip() {
        add_ipv4_header(ip_proto);
        // Total length = packet length + 20
        //   IPv4 (20)
        hdr.ipv4.total_len = payload_len + hdr.ipv4.minSizeInBytes();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv4.minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    @name(".encap_ipv6_ip")
    action encap_ipv6_ip() {
#ifdef IPV6_TUNNEL_ENABLE
        add_ipv6_header(ip_proto);
        // Payload length = packet length
        hdr.ipv6.payload_len = payload_len;
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv6.minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
#endif
    }

#ifdef GRE_ENABLE
    @name(".encap_ipv4_gre")
    action encap_ipv4_gre() {
	add_gre_header(gre_proto);
        add_ipv4_header(IP_PROTOCOLS_GRE);
        hdr.ipv4.total_len = payload_len + hdr.ipv4.minSizeInBytes() + hdr.gre.minSizeInBytes();
        local_md.pkt_length = local_md.pkt_length + hdr.ipv4.minSizeInBytes() + hdr.gre.minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    @name(".encap_ipv6_gre")
    action encap_ipv6_gre() {
#ifdef IPV6_TUNNEL_ENABLE
	add_gre_header(gre_proto);
        add_ipv6_header(IP_PROTOCOLS_GRE);
        hdr.ipv6.payload_len = payload_len + hdr.gre.minSizeInBytes();
        local_md.pkt_length = local_md.pkt_length + hdr.ipv6.minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
#endif
    }
#endif /* GRE_ENABLE */


#ifdef SRV6_ENABLE
    action add_srh_base(
        bit<8> seg_left,
        bit<8> last_entry,
        bit<8> hdr_ext_len,
        bit<8> next_hdr)
    {
        hdr.srh_base.setValid();
        hdr.srh_base.next_hdr = next_hdr;
        hdr.srh_base.hdr_ext_len = hdr_ext_len;
        hdr.srh_base.routing_type = 0x4;
        hdr.srh_base.seg_left = seg_left;
        hdr.srh_base.last_entry = last_entry;
        hdr.srh_base.flags = 0x0;
        hdr.srh_base.tag = 0x0;
    }

    action encap_srv6_seglen1() {
        encap_ipv6_ip();
    }

    action encap_srv6_seglen2() {
        add_srh_base(8w1, 8w0, 8w2, ip_proto);
        add_ipv6_header(IP_PROTOCOLS_SRV6);
        hdr.ipv6.payload_len = payload_len + hdr.srh_base.minSizeInBytes() + hdr.srh_seg_list[0].minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
        hdr.srh_seg_list[0].setValid();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv6.minSizeInBytes() + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes();
    }

    action encap_srv6_seglen3() {
        add_srh_base(8w2, 8w1, 8w4, ip_proto);
        add_ipv6_header(IP_PROTOCOLS_SRV6);
        hdr.ipv6.payload_len = payload_len + hdr.srh_base.minSizeInBytes() + hdr.srh_seg_list[0].minSizeInBytes() +
	   hdr.srh_seg_list[1].minSizeInBytes();
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
        hdr.srh_seg_list[0].setValid();
        hdr.srh_seg_list[1].setValid();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.ipv6.minSizeInBytes() + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes() + hdr.srh_seg_list[1].minSizeInBytes();
    }

    // Insert SRH into an IPv6 packet with no existing SRH (H.insert.Red)
    // Inserting SRH into a packet with a pre-existing SRH will be handled later (End.B6.Encaps.Red).
    action insert_srv6_seglen1() {
        add_srh_base(8w1, 8w0, 8w2, hdr.ipv6.next_hdr);
        hdr.ipv6.next_hdr = IP_PROTOCOLS_SRV6;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes();
        hdr.srh_seg_list[0].setValid();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes();
    }

    action insert_srv6_seglen2() {
        add_srh_base(8w2, 8w1, 8w4, hdr.ipv6.next_hdr);
        hdr.ipv6.next_hdr = IP_PROTOCOLS_SRV6;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes() + hdr.srh_seg_list[1].minSizeInBytes();
        hdr.srh_seg_list[0].setValid();
        hdr.srh_seg_list[1].setValid();
        // Pkt length
        local_md.pkt_length = local_md.pkt_length + hdr.srh_base.minSizeInBytes() +
          hdr.srh_seg_list[0].minSizeInBytes() + hdr.srh_seg_list[1].minSizeInBytes();
    }

#endif /* SRV6_ENABLE */

#ifdef SRV6_ENABLE
    @name(".tunnel_encap_1")
    table tunnel_encap_1 {
        key = {
            local_md.tunnel.type : ternary;
            local_md.tunnel.srv6_seg_len : ternary;
        }

        actions = {
            NoAction;
            encap_ipv4_ip;
            encap_ipv6_ip;
            encap_srv6_seglen1;
            encap_srv6_seglen2;
            encap_srv6_seglen3;
            insert_srv6_seglen1;
            insert_srv6_seglen2;
#ifdef GRE_ENABLE
            encap_ipv4_gre;
            encap_ipv6_gre;
#endif /* GRE_ENABLE */
        }

        const default_action = NoAction;
        size = MIN_TABLE_SIZE;
        const entries = {
            (SWITCH_EGRESS_TUNNEL_TYPE_IPV4_IPINIP, _) : encap_ipv4_ip();
            (SWITCH_EGRESS_TUNNEL_TYPE_IPV6_IPINIP, _) : encap_ipv6_ip();
            (SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP, 1) : encap_srv6_seglen1;
            (SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP, 2) : encap_srv6_seglen2;
            (SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP, 3) : encap_srv6_seglen3;
            (SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT, 1) : insert_srv6_seglen1;
            (SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT, 2) : insert_srv6_seglen2;
#ifdef GRE_ENABLE
            (SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GRE, _) : encap_ipv4_gre();
            (SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GRE, _) : encap_ipv6_gre();
#endif /* GRE_ENABLE */
        }
    }

#else
    @name(".tunnel_encap_1")
    table tunnel_encap_1 {
        key = {
            local_md.tunnel.type : exact;
        }

        actions = {
            NoAction;
#ifdef VXLAN_ENABLE
            encap_ipv4_vxlan;
            encap_ipv6_vxlan;
#endif /* VXLAN_ENABLE */
            encap_ipv4_ip;
            encap_ipv6_ip;
#ifdef GRE_ENABLE
            encap_ipv4_gre;
            encap_ipv6_gre;
#endif /* GRE_ENABLE */
        }

        const default_action = NoAction;
        size = MIN_TABLE_SIZE;
    }
#endif /* SRV6_ENABLE */

#ifdef MPLS_ENABLE
    //
    // ***************** MPLS Push/Encap ********************
    //
    action mpls_push_1() {
        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].bos = 0;
        local_md.pkt_length = local_md.pkt_length - hdr.mpls[0].minSizeInBytes();
    }
    action mpls_push_2() {
        hdr.mpls.push_front(2);
        hdr.mpls[0].setValid();
        hdr.mpls[1].setValid();
        hdr.mpls[0].bos = 0;
        hdr.mpls[1].bos = 0;
        local_md.pkt_length = local_md.pkt_length + hdr.mpls[0].minSizeInBytes() +
          hdr.mpls[1].minSizeInBytes();
    }
    action mpls_push_3() {
        hdr.mpls.push_front(3);
        hdr.mpls[0].setValid();
        hdr.mpls[1].setValid();
        hdr.mpls[2].setValid();
        hdr.mpls[0].bos = 0;
        hdr.mpls[1].bos = 0;
        hdr.mpls[2].bos = 0;
        local_md.pkt_length = local_md.pkt_length + hdr.mpls[0].minSizeInBytes() +
          hdr.mpls[1].minSizeInBytes() + hdr.mpls[2].minSizeInBytes();
    }

    @name(".mpls_encap_1")
    action mpls_encap_1() {
        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].bos = 1;
        hdr.ethernet.ether_type = ETHERTYPE_MPLS;
        local_md.pkt_length = local_md.pkt_length - hdr.mpls[0].minSizeInBytes();
    }
    @name(".mpls_encap_2")
    action mpls_encap_2() {
        hdr.mpls.push_front(2);
        hdr.mpls[0].setValid();
        hdr.mpls[1].setValid();
        hdr.mpls[0].bos = 0;
        hdr.mpls[1].bos = 1;
        hdr.ethernet.ether_type = ETHERTYPE_MPLS;
        local_md.pkt_length = local_md.pkt_length + hdr.mpls[0].minSizeInBytes() +
          hdr.mpls[1].minSizeInBytes();
    }
    @name(".mpls_encap_3")
    action mpls_encap_3() {
        hdr.mpls.push_front(3);
        hdr.mpls[0].setValid();
        hdr.mpls[1].setValid();
        hdr.mpls[2].setValid();
        hdr.mpls[0].bos = 0;
        hdr.mpls[1].bos = 0;
        hdr.mpls[2].bos = 1;
        hdr.ethernet.ether_type = ETHERTYPE_MPLS;
        local_md.pkt_length = local_md.pkt_length + hdr.mpls[0].minSizeInBytes() +
          hdr.mpls[1].minSizeInBytes() + hdr.mpls[2].minSizeInBytes();
    }

    @name(".mpls_encap")
    table mpls_encap {
        key = {
            hdr.mpls[0].isValid() : exact;
            local_md.tunnel.mpls_push_count : exact;
        }

        actions = {
            NoAction;
            mpls_push_1;
            mpls_push_2;
            mpls_push_3;
            mpls_encap_1;
            mpls_encap_2;
            mpls_encap_3;
        }
        const entries = {
            (true, 1) : mpls_push_1;
            (true, 2) : mpls_push_2;
            (true, 3) : mpls_push_3;
            (false, 1) : mpls_encap_1;
            (false, 2) : mpls_encap_2;
            (false, 3) : mpls_encap_3;
        }
        const default_action = NoAction;
        size = 16;
    }

    @name(".mpls_push_1_label")
    action mpls_push_1_label(bit<20> label0) {
        hdr.mpls[0].label = label0;
    }
    @name(".mpls_push_2_label")
    action mpls_push_2_label(bit<20> label0, bit<20> label1) {
        hdr.mpls[0].label = label0;
        hdr.mpls[1].label = label1;
    }
    @name(".mpls_push_3_label")
    action mpls_push_3_label(bit<20> label0, bit<20> label1, bit<20> label2) {
        hdr.mpls[0].label = label0;
        hdr.mpls[1].label = label1;
        hdr.mpls[2].label = label2;
    }

    @name(".mpls_swap_label")
    action mpls_swap_label(bit<20> label0) {
        hdr.mpls[0].label = label0;
    }

    @name(".mpls_label")
    table mpls_label {
        key = {
            local_md.tunnel_nexthop : exact;
        }

        actions = {
            NoAction;
            mpls_push_1_label;
            mpls_push_2_label;
            mpls_push_3_label;
            mpls_swap_label;
        }
        const default_action = NoAction;
        size = TUNNEL_NEXTHOP_TABLE_SIZE;
    }
#endif /* MPLS_ENABLE */

    apply {
        if (local_md.tunnel.type != SWITCH_EGRESS_TUNNEL_TYPE_NONE) {
            // Copy L3/L4 header into inner headers.
            if (local_md.tunnel.type != SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT) {
                tunnel_encap_0.apply();
            }
            if (local_md.tunnel.type == SWITCH_EGRESS_TUNNEL_TYPE_MPLS) {
#ifdef MPLS_ENABLE
                // Add MPLS labels
                if(local_md.tunnel.mpls_swap != 1) {
                    mpls_encap.apply();
                }
                mpls_label.apply();
#endif /* MPLS_ENABLE */
            } else {
                // Add outer IP encapsulation
                tunnel_encap_1.apply();
            }
        }
    }
}

//-----------------------------------------------------------------------------
// IP Tunnel Encapsulation - Step 3
//         -- Outer SIP Rewrite
//         -- Outer DIP Rewrite
//         -- TTL QoS Rewrite
//         -- MPLS TTL/EXP Rewrite
//-----------------------------------------------------------------------------
control TunnelRewrite(inout switch_header_t hdr, inout switch_local_metadata_t local_md)() {
    //
    // ***************** Outer SIP Rewrite **********************
    //
    @name(".ipv4_sip_rewrite")
    action ipv4_sip_rewrite(ipv4_addr_t src_addr, bit<8> ttl_val, bit<6> dscp_val) {
        hdr.ipv4.src_addr = src_addr;
#ifndef TUNNEL_TTL_MODE_ENABLE
        hdr.ipv4.ttl = ttl_val;
#endif
#ifdef TUNNEL_QOS_MODE_ENABLE
        // Handle pipe mode set of dscp_val here rather than encap_dscp, since
        // set of ipv4.diffserv[7:2] from action param must be done in a
        // different table than set of ipv4.diffserv[1:0] from phv
        hdr.ipv4.diffserv[7:2] = dscp_val;
#endif
    }

    @name(".ipv6_sip_rewrite")
    action ipv6_sip_rewrite(ipv6_addr_t src_addr, bit<8> ttl_val, bit<6> dscp_val) {
        hdr.ipv6.src_addr = src_addr;
#ifndef TUNNEL_TTL_MODE_ENABLE
        hdr.ipv6.hop_limit = ttl_val;
#endif
#ifdef TUNNEL_QOS_MODE_ENABLE
        // Handle pipe mode set of dscp_val here rather than encap_dscp, since
        // set of ipv6.traffic_class[7:2] from action param must be done in
        // a different table than set of ipv6.traffic_class[1:0] from phv
        hdr.ipv6.traffic_class[7:2] = dscp_val;
#endif
    }

    @name(".src_addr_rewrite")
    table src_addr_rewrite {
        key = {
            local_md.tunnel.index : exact;
        }
        actions = {
            ipv4_sip_rewrite;
#ifdef IPV6_TUNNEL_ENABLE
            ipv6_sip_rewrite;
#endif /* IPV6_TUNNEL_ENABLE */
        }
        size = TUNNEL_OBJECT_SIZE;
    }

    //
    // ******** TTL - original header value for uniform mode, new configuration value for Pipe mode ******
    //
    @name(".encap_ttl_v4_in_v4_pipe")
    action encap_ttl_v4_in_v4_pipe(bit<8> ttl_val) {
        hdr.ipv4.ttl = ttl_val;
    }
    @name(".encap_ttl_v4_in_v6_pipe")
    action encap_ttl_v4_in_v6_pipe(bit<8> ttl_val) {
        hdr.ipv6.hop_limit = ttl_val;
    }
    @name(".encap_ttl_v6_in_v4_pipe")
    action encap_ttl_v6_in_v4_pipe(bit<8> ttl_val) {
        hdr.ipv4.ttl = ttl_val;
    }
    @name(".encap_ttl_v6_in_v6_pipe")
    action encap_ttl_v6_in_v6_pipe(bit<8> ttl_val) {
        hdr.ipv6.hop_limit = ttl_val;
    }
//    action encap_ttl_v4_in_v4_uniform() {
//        hdr.ipv4.ttl = hdr.ipv4.ttl;
//    }
    @name(".encap_ttl_v4_in_v6_uniform")
    action encap_ttl_v4_in_v6_uniform() {
        hdr.ipv6.hop_limit = hdr.ipv4.ttl;
    }
    @name(".encap_ttl_v6_in_v4_uniform")
    action encap_ttl_v6_in_v4_uniform() {
        hdr.ipv4.ttl = hdr.ipv6.hop_limit;
    }
//    action encap_ttl_v6_in_v6_uniform() {
//        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit;
//    }

    @name(".tunnel_rewrite_encap_ttl")
    table encap_ttl {
        key = {
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
            local_md.tunnel.index : exact;
        }
        actions = {
            NoAction;
            encap_ttl_v4_in_v4_pipe;
            encap_ttl_v4_in_v6_pipe;
            encap_ttl_v6_in_v4_pipe;
            encap_ttl_v6_in_v6_pipe;
// nop      encap_ttl_v4_in_v4_uniform;
            encap_ttl_v4_in_v6_uniform;
            encap_ttl_v6_in_v4_uniform;
// nop      encap_ttl_v6_in_v6_uniform;
        }
        const default_action = NoAction;
        size = TUNNEL_OBJECT_SIZE * 3;
    }

    //
    // ********************* DSCP/ ECN **************************
    // DSCP - original header value for uniform mode, new configuration value for Pipe mode
    // ECN - always copy inner to outer
    //
#ifdef TUNNEL_QOS_MODE_ENABLE
    @name(".encap_dscp_v4_in_v4_ecn")
    action encap_dscp_v4_in_v4_ecn() {
// nop  hdr.ipv4.diffserv[1:0] = hdr.ipv4.diffserv[1:0];
    }
    @name(".encap_dscp_v4_in_v6_ecn")
    action encap_dscp_v4_in_v6_ecn() {
        @in_hash { hdr.ipv6.traffic_class[1:0] = hdr.inner_ipv4.diffserv[1:0]; }
    }
    @name(".encap_dscp_v6_in_v4_ecn")
    action encap_dscp_v6_in_v4_ecn() {
        @in_hash { hdr.ipv4.diffserv[1:0] = hdr.inner_ipv6.traffic_class[1:0]; }
    }
    @name(".encap_dscp_v6_in_v6_ecn")
    action encap_dscp_v6_in_v6_ecn() {
// nop  hdr.ipv6.traffic_class[1:0] = hdr.ipv6.traffic_class[1:0];
    }
#endif

    @name(".encap_dscp_v4_in_v4_uniform")
    action encap_dscp_v4_in_v4_uniform() {
#ifdef TUNNEL_QOS_MODE_ENABLE
        // Note: When pipe mode is supported, ipv4.diffserv was overwritten
        //       in src_addr_rewrite with pipe value, now needs to be put back
        hdr.ipv4.diffserv = hdr.inner_ipv4.diffserv;
#else
// nop  hdr.ipv4.diffserv = hdr.ipv4.diffserv;
#endif
    }
    @name(".encap_dscp_v4_in_v6_uniform")
    action encap_dscp_v4_in_v6_uniform() {
        // Note: Use inner_ipv4 since outer ipv4.diffserv is clobbered by
        //       new ipv6.flow_label due to different offset
        @in_hash { hdr.ipv6.traffic_class = hdr.inner_ipv4.diffserv; }
    }
    @name(".encap_dscp_v6_in_v4_uniform")
    action encap_dscp_v6_in_v4_uniform() {
        @in_hash { hdr.ipv4.diffserv = hdr.inner_ipv6.traffic_class; }
    }
    @name(".encap_dscp_v6_in_v6_uniform")
    action encap_dscp_v6_in_v6_uniform() {
#ifdef TUNNEL_QOS_MODE_ENABLE
        // Note: When pipe mode is supported, ipv6.traffic_class was overwritten
        //       in src_addr_rewrite with pipe value, now needs to be put back
        hdr.ipv6.traffic_class = hdr.inner_ipv6.traffic_class;
#else
// nop  hdr.ipv6.traffic_class = hdr.ipv6.traffic_class;
#endif
    }

#ifdef L2_VXLAN_ENABLE
    // Setting pipe mode for non-ip traffic, where ecn value should be 0.
    // This applies even when TUNNEL_QOS_MODE_ENABLE is not defined.
    // For ip traffic with pipe mode, instead rely on write of dscp value in
    // src_addr_rewrite, along with encap_dscp_..._ecn actions above.
    @name(".encap_dscp_v4_pipe_mode")
    action encap_dscp_v4_pipe_mode(bit<6> dscp_val) {
          hdr.ipv4.diffserv[1:0] = 0;
          hdr.ipv4.diffserv[7:2] = dscp_val;
    }

    @name(".encap_dscp_v6_pipe_mode")
    action encap_dscp_v6_pipe_mode(bit<6> dscp_val) {
        hdr.ipv6.traffic_class[1:0] = 0;
        hdr.ipv6.traffic_class[7:2] = dscp_val;
    }
#endif

    @name(".tunnel_rewrite_encap_dscp")
    table encap_dscp {
        key = {
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
            local_md.tunnel.index : exact;
        }
        actions = {
            NoAction;
#ifdef TUNNEL_QOS_MODE_ENABLE
            encap_dscp_v4_in_v4_ecn;
            encap_dscp_v4_in_v6_ecn;
            encap_dscp_v6_in_v4_ecn;
            encap_dscp_v6_in_v6_ecn;
#endif
            encap_dscp_v4_in_v4_uniform;
            encap_dscp_v4_in_v6_uniform;
            encap_dscp_v6_in_v4_uniform;
            encap_dscp_v6_in_v6_uniform;

#ifdef L2_VXLAN_ENABLE
            encap_dscp_v4_pipe_mode;
            encap_dscp_v6_pipe_mode;
#endif
        }

        const default_action = NoAction;
        size = TUNNEL_OBJECT_SIZE * 3;
    }

    //
    // ************ Tunnel destination IP rewrite *******************
    //
    @name(".ipv4_dip_rewrite")
    action ipv4_dip_rewrite(ipv4_addr_t dst_addr) {
        hdr.ipv4.dst_addr = dst_addr;
    }

    @name(".ipv6_dip_rewrite")
    action ipv6_dip_rewrite(ipv6_addr_t dst_addr) {
        hdr.ipv6.dst_addr = dst_addr;
    }

    @name(".dst_addr_rewrite")
    table dst_addr_rewrite {
        key = { local_md.tunnel.dip_index : exact; }
        actions = {
            ipv4_dip_rewrite;
#ifdef IPV6_TUNNEL_ENABLE
            ipv6_dip_rewrite;
#endif
        }
        const default_action = ipv4_dip_rewrite(0);
        size = TUNNEL_ENCAP_IP_SIZE;
    }

#ifdef SRV6_ENABLE
    //
    // *********** SRv6 SID rewrite  **********************
    //

    DirectCounter<bit<switch_counter_width>>(CounterType_t.PACKETS_AND_BYTES) stats;

    // H.Encaps.Red
    @name(".srv6_encaps_sid_rewrite_0")
    action srv6_encaps_sid_rewrite_0(srv6_sid_t s0) {
        hdr.ipv6.dst_addr = s0;
        stats.count();
    }
    @name(".srv6_encaps_sid_rewrite_1")
    action srv6_encaps_sid_rewrite_1(srv6_sid_t s0, srv6_sid_t s1) {
        hdr.ipv6.dst_addr = s0;
        hdr.srh_seg_list[0].sid = s1;
        stats.count();
    }
    @name(".srv6_encaps_sid_rewrite_2")
    action srv6_encaps_sid_rewrite_2(srv6_sid_t s0, srv6_sid_t s1, srv6_sid_t s2) {
        hdr.ipv6.dst_addr = s0;
        hdr.srh_seg_list[1].sid = s1;
        hdr.srh_seg_list[0].sid = s2;
        stats.count();
    }

    // H.Insert.Red
    @name(".srv6_insert_sid_rewrite_0")
    action srv6_insert_sid_rewrite_0(srv6_sid_t s0) {
        hdr.srh_seg_list[0].sid = hdr.ipv6.dst_addr;
        hdr.ipv6.dst_addr = s0;
        stats.count();
    }
    @name(".srv6_insert_sid_rewrite_1")
    action srv6_insert_sid_rewrite_1(srv6_sid_t s0, srv6_sid_t s1) {
        hdr.srh_seg_list[1].sid = s1;
        hdr.srh_seg_list[0].sid = hdr.ipv6.dst_addr;
        hdr.ipv6.dst_addr = s0;
        stats.count();
    }

    @name(".sid_rewrite")
    table sid_rewrite {
        key = {
            local_md.tunnel_nexthop : exact;
        }
        actions = {
            srv6_encaps_sid_rewrite_0;
            srv6_encaps_sid_rewrite_1;
            srv6_encaps_sid_rewrite_2;
            srv6_insert_sid_rewrite_0;
            srv6_insert_sid_rewrite_1;
        }
        size = SRV6_NEXTHOP_TABLE_SIZE;
        counters = stats;
    }
#endif

#ifdef MPLS_ENABLE
    // *********** MPLS TTL/EXP Fields Rewrite **********************
    //
    @name(".mpls_ttl_1_pipe")
    action mpls_ttl_1_pipe() {
        hdr.mpls[0].ttl = local_md.tunnel.mpls_encap_ttl;
    }
    action mpls_ttl_1_from_ipv4() {
        hdr.mpls[0].ttl = hdr.inner_ipv4.ttl;
    }
    action mpls_ttl_1_from_ipv6() {
        hdr.mpls[0].ttl = hdr.inner_ipv6.hop_limit;
    }
    action mpls_ttl_1_from_mpls() {
        hdr.mpls[0].ttl = hdr.mpls[1].ttl;
    }
    @name(".mpls_ttl_2_pipe")
    action mpls_ttl_2_pipe() {
        hdr.mpls[0].ttl = local_md.tunnel.mpls_encap_ttl;
        hdr.mpls[1].ttl = local_md.tunnel.mpls_encap_ttl;
    }
    action mpls_ttl_2_from_ipv4() {
        hdr.mpls[0].ttl = hdr.inner_ipv4.ttl;
        hdr.mpls[1].ttl = hdr.inner_ipv4.ttl;
    }
    action mpls_ttl_2_from_ipv6() {
        hdr.mpls[0].ttl = hdr.inner_ipv6.hop_limit;
        hdr.mpls[1].ttl = hdr.inner_ipv6.hop_limit;
    }
    action mpls_ttl_2_from_mpls() {
        hdr.mpls[0].ttl = hdr.mpls[2].ttl;
        hdr.mpls[1].ttl = hdr.mpls[2].ttl;
    }
    @name(".mpls_ttl_3_pipe")
    action mpls_ttl_3_pipe() {
        hdr.mpls[0].ttl = local_md.tunnel.mpls_encap_ttl;
        hdr.mpls[1].ttl = local_md.tunnel.mpls_encap_ttl;
        hdr.mpls[2].ttl = local_md.tunnel.mpls_encap_ttl;
    }
    action mpls_ttl_3_from_ipv4() {
        hdr.mpls[0].ttl = hdr.inner_ipv4.ttl;
        hdr.mpls[1].ttl = hdr.inner_ipv4.ttl;
        hdr.mpls[2].ttl = hdr.inner_ipv4.ttl;
    }
    action mpls_ttl_3_from_ipv6() {
        hdr.mpls[0].ttl = hdr.inner_ipv6.hop_limit;
        hdr.mpls[1].ttl = hdr.inner_ipv6.hop_limit;
        hdr.mpls[2].ttl = hdr.inner_ipv6.hop_limit;
    }

    @name(".mpls_ttl_decrement")
    action mpls_ttl_decrement() {
        hdr.mpls[0].ttl = hdr.mpls[0].ttl - 1;
    }

    @name(".mpls_ttl_rewrite")
    table mpls_ttl_rewrite {
        key = {
            local_md.tunnel.mpls_push_count : exact;
            local_md.tunnel.mpls_swap : exact;
#ifdef TUNNEL_TTL_MODE_ENABLE
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].isValid() : exact;
            local_md.tunnel.ttl_mode : exact;
#endif
        }

        actions = {
            NoAction;
            mpls_ttl_1_pipe;
            mpls_ttl_2_pipe;
            mpls_ttl_3_pipe;
#ifdef TUNNEL_TTL_MODE_ENABLE
            mpls_ttl_1_from_ipv4;
            mpls_ttl_1_from_ipv6;
            mpls_ttl_1_from_mpls;
            mpls_ttl_2_from_ipv4;
            mpls_ttl_2_from_ipv6;
            mpls_ttl_2_from_mpls;
            mpls_ttl_3_from_ipv4;
            mpls_ttl_3_from_ipv6;
#endif
            mpls_ttl_decrement;
        }
        const entries = {
#ifdef TUNNEL_TTL_MODE_ENABLE
            (1, 0, true, false, false, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (1, 0, true, false, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (1, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (1, 0, false, true, false, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (1, 0, false, true, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (1, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_1_pipe;
            (2, 0, true, false, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_2_pipe;
            (2, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_2_pipe;
            (2, 0, false, true, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_2_pipe;
            (2, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_2_pipe;
            (3, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_3_pipe;
            (3, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_3_pipe;
            (1, 0, true, false, false, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_ipv4;
            (1, 0, true, false, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_mpls;
            (1, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_mpls;
            (1, 0, false, true, false, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_ipv6;
            (1, 0, false, true, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_mpls;
            (1, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_1_from_mpls;
            (2, 0, true, false, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_2_from_ipv4;
            (2, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_2_from_mpls;
            (2, 0, false, true, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_2_from_ipv6;
            (2, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_2_from_mpls;
            (3, 0, true, false, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_3_from_ipv4;
            (3, 0, false, true, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_3_from_ipv6;
            (1, 1, true, false, false, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, true, false, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, true, false, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, false, true, false, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, false, true, true, false,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, false, true, true, true,
             SWITCH_TUNNEL_MODE_PIPE) : mpls_ttl_decrement;
            (1, 1, true, false, false, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
            (1, 1, true, false, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
            (1, 1, true, false, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
            (1, 1, false, true, false, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
            (1, 1, false, true, true, false,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
            (1, 1, false, true, true, true,
             SWITCH_TUNNEL_MODE_UNIFORM) : mpls_ttl_decrement;
#else
            (1, 0) : mpls_ttl_1_pipe;
            (2, 0) : mpls_ttl_2_pipe;
            (3, 0) : mpls_ttl_3_pipe;
            (1, 1) : mpls_ttl_decrement;
#endif
        }
        const default_action = NoAction;
        size = 64;
    }
    action mpls_exp_1_pipe() {
      hdr.mpls[0].exp = local_md.tunnel.mpls_encap_exp;
    }
    action mpls_exp_1_from_ipv4() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv4.diffserv[7:5]; }
    }
    action mpls_exp_1_from_ipv6() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv6.traffic_class[7:5]; }
    }
    action mpls_exp_1_from_mpls() {
      hdr.mpls[0].exp = hdr.mpls[1].exp;
    }
    action mpls_exp_2_pipe() {
      hdr.mpls[0].exp = local_md.tunnel.mpls_encap_exp;
      hdr.mpls[1].exp = local_md.tunnel.mpls_encap_exp;
    }
    action mpls_exp_2_from_ipv4() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv4.diffserv[7:5]; }
      @in_hash { hdr.mpls[1].exp = hdr.inner_ipv4.diffserv[7:5]; }
    }
    action mpls_exp_2_from_ipv6() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv6.traffic_class[7:5]; }
      @in_hash { hdr.mpls[1].exp = hdr.inner_ipv6.traffic_class[7:5]; }
    }
    action mpls_exp_2_from_mpls() {
      hdr.mpls[0].exp = hdr.mpls[2].exp;
      hdr.mpls[1].exp = hdr.mpls[2].exp;
    }
    action mpls_exp_3_pipe() {
      hdr.mpls[0].exp = local_md.tunnel.mpls_encap_exp;
      hdr.mpls[1].exp = local_md.tunnel.mpls_encap_exp;
      hdr.mpls[2].exp = local_md.tunnel.mpls_encap_exp;
    }
    action mpls_exp_3_from_ipv4() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv4.diffserv[7:5]; }
      @in_hash { hdr.mpls[1].exp = hdr.inner_ipv4.diffserv[7:5]; }
      @in_hash { hdr.mpls[2].exp = hdr.inner_ipv4.diffserv[7:5]; }
    }
    action mpls_exp_3_from_ipv6() {
      @in_hash { hdr.mpls[0].exp = hdr.inner_ipv6.traffic_class[7:5]; }
      @in_hash { hdr.mpls[1].exp = hdr.inner_ipv6.traffic_class[7:5]; }
      @in_hash { hdr.mpls[2].exp = hdr.inner_ipv6.traffic_class[7:5]; }
    }
    @name(".mpls_exp_rewrite")
    table mpls_exp_rewrite {
      key = {
        local_md.tunnel.mpls_push_count : exact;
        hdr.inner_ipv4.isValid() : exact;
        hdr.inner_ipv6.isValid() : exact;
        hdr.mpls[1].isValid() : exact;
        hdr.mpls[2].isValid() : exact;
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.tunnel.qos_mode : exact;
#endif
      }
      actions = {
        NoAction;
#ifdef TUNNEL_QOS_MODE_ENABLE
        mpls_exp_1_pipe;
        mpls_exp_2_pipe;
        mpls_exp_3_pipe;
#endif
        mpls_exp_1_from_ipv4;
        mpls_exp_1_from_ipv6;
        mpls_exp_1_from_mpls;
        mpls_exp_2_from_ipv4;
        mpls_exp_2_from_ipv6;
        mpls_exp_2_from_mpls;
        mpls_exp_3_from_ipv4;
        mpls_exp_3_from_ipv6;
      }
      const entries = {
#ifdef TUNNEL_QOS_MODE_ENABLE
          (1, true, false, false, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (1, true, false, true, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (1, true, false, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (1, false, true, false, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (1, false, true, true, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (1, false, true, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_1_pipe;
          (2, true, false, true, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_2_pipe;
          (2, true, false, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_2_pipe;
          (2, false, true, true, false,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_2_pipe;
          (2, false, true, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_2_pipe;
          (3, true, false, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_3_pipe;
          (3, false, true, true, true,
           SWITCH_TUNNEL_MODE_PIPE) : mpls_exp_3_pipe;
          (1, true, false, false, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_ipv4;
          (1, true, false, true, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_mpls;
          (1, true, false, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_mpls;
          (1, false, true, false, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_ipv6;
          (1, false, true, true, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_mpls;
          (1, false, true, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_1_from_mpls;
          (2, true, false, true, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_2_from_ipv4;
          (2, true, false, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_2_from_mpls;
          (2, false, true, true, false,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_2_from_ipv6;
          (2, false, true, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_2_from_mpls;
          (3, true, false, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_3_from_ipv4;
          (3, false, true, true, true,
           SWITCH_TUNNEL_MODE_UNIFORM) : mpls_exp_3_from_ipv6;
#else
          (1, true, false, false, false) : mpls_exp_1_from_ipv4;
          (1, true, false, true, false) : mpls_exp_1_from_mpls;
          (1, true, false, true, true) : mpls_exp_1_from_mpls;
          (1, false, true, false, false) : mpls_exp_1_from_ipv6;
          (1, false, true, true, false) : mpls_exp_1_from_mpls;
          (1, false, true, true, true) : mpls_exp_1_from_mpls;
          (2, true, false, true, false) : mpls_exp_2_from_ipv4;
          (2, true, false, true, true) : mpls_exp_2_from_mpls;
          (2, false, true, true, false) : mpls_exp_2_from_ipv6;
          (2, false, true, true, true) : mpls_exp_2_from_mpls;
          (3, true, false, true, true) : mpls_exp_3_from_ipv4;
          (3, false, true, true, true) : mpls_exp_3_from_ipv6;
#endif
        }
      const default_action = NoAction;
      size = 32;
    }
#endif /* MPLS_ENABLE */

    //
    // ***************** Control Flow ***********************
    //
    apply {
        if (local_md.tunnel.type != SWITCH_EGRESS_TUNNEL_TYPE_NONE) {
            if (local_md.tunnel.type == SWITCH_EGRESS_TUNNEL_TYPE_MPLS) {
#ifdef MPLS_ENABLE
                mpls_ttl_rewrite.apply();
                if (local_md.tunnel.mpls_swap != 1) {
                    mpls_exp_rewrite.apply();
                }
#endif /*  MPLS_ENABLE */
#ifdef SRV6_ENABLE
            } else if (local_md.tunnel.type == SWITCH_EGRESS_TUNNEL_TYPE_SRV6_ENCAP || local_md.tunnel.type == SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT) {
                sid_rewrite.apply();
#endif /* SRV6_ENABLE */
            } else {
                dst_addr_rewrite.apply();
            }
            if ((local_md.tunnel.type != SWITCH_EGRESS_TUNNEL_TYPE_SRV6_INSERT) && (local_md.tunnel.type != SWITCH_EGRESS_TUNNEL_TYPE_MPLS)) {
                src_addr_rewrite.apply();
#ifdef TUNNEL_TTL_MODE_ENABLE
                encap_ttl.apply();
#endif /* TUNNEL_TTL_MODE_ENABLE */
                encap_dscp.apply();
            }
        }
    }
}

#ifdef L2_VXLAN_ENABLE
//-----------------------------------------------------------------------------
// Ingress Replication DB for tunnels
//-----------------------------------------------------------------------------
control TunnelReplication(in egress_intrinsic_metadata_t eg_intr_md,
                          inout switch_local_metadata_t local_md) {
    @name(".tunnel_rid_hit")
    action rid_hit(switch_bd_t bd, switch_nexthop_t nexthop, switch_nexthop_t tunnel_nexthop) {
        local_md.nexthop = nexthop;
        local_md.tunnel_nexthop = tunnel_nexthop;
    }

    @name(".tunnel_rid_miss")
    action rid_miss() {
    }

    @name(".tunnel_rid")
    table rid {
        key = { eg_intr_md.egress_rid : exact; }
        actions = {
            rid_miss;
            rid_hit;
        }

        size = RID_TABLE_SIZE;
        const default_action = rid_miss;
    }

    apply {
        if (eg_intr_md.egress_rid != 0)
            rid.apply();
    }
}

//-----------------------------------------------------------------------------
// Egress BD to VNI translation
//      -- local_md.bd carries the ingress_bd at this place in the pipeline.
//
//-----------------------------------------------------------------------------
control L2VniMap(inout switch_header_t hdr,
                   inout switch_local_metadata_t local_md) {

    @name(".set_l2_vni")
    action set_l2_vni(switch_tunnel_vni_t vni) {
        local_md.tunnel.vni = vni;
    }

    @name(".bd_to_vni_mapping")
    table bd_to_vni_mapping {
        key = {
            local_md.bd : exact;
        }
        actions = {
            NoAction;
            set_l2_vni;
        }

        const default_action = NoAction;
        size = 4096;
    }

    apply {
        bd_to_vni_mapping.apply();
    }
}
#endif /* L2_VXLAN_ENABLE */

#endif /* TUNNEL_ENCAP_ENABLE */
#endif /* TUNNEL_ENABLE */
