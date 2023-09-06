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


#include "acl.p4"
#include "l2.p4"

//-----------------------------------------------------------------------------
// FIB lookup
//
// @param dst_addr : Destination IPv4 address.
// @param vrf
// @param flags
// @param nexthop : Nexthop index.
// @param host_table_size : Size of the host table.
// @param lpm_table_size : Size of the IPv4 route table.
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Common FIB  actions.
//-----------------------------------------------------------------------------
    action fib_hit(inout switch_local_metadata_t local_md, switch_nexthop_t nexthop_index, switch_fib_label_t fib_label) {
        local_md.nexthop = nexthop_index;
#ifdef FIB_ACL_LABEL_ENABLE
        local_md.fib_label = fib_label;
#endif /* FIB_ACL_LABEL_ENABLE */
        local_md.flags.routed = true;
    }

    action fib_miss(inout switch_local_metadata_t local_md) {
        local_md.flags.routed = false;
    }

    action fib_miss_lpm4(inout switch_local_metadata_t local_md) {
        local_md.flags.routed = false;
        local_md.flags.fib_lpm_miss = true;
    }

    action fib_miss_lpm6(inout switch_local_metadata_t local_md) {
        local_md.flags.routed = false;
        local_md.flags.fib_lpm_miss = true;
    }

    action fib_drop(inout switch_local_metadata_t local_md) {
        local_md.flags.routed = false;
        local_md.flags.fib_drop = true;
    }

    action fib_myip(inout switch_local_metadata_t local_md, switch_myip_type_t myip) {
        local_md.flags.myip = myip;
    }

#ifndef SHARED_IP_LPM64_TABLE
//
// *************************** IPv4 FIB **************************************
//
control Fibv4(inout switch_local_metadata_t local_md)(
              switch_uint32_t host_table_size,
              switch_uint32_t lpm_table_size,
              bool local_host_enable=false,
              switch_uint32_t local_host_table_size=1024) {

    
    @pack(2)
    @name(".ipv4_host") table host {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[95:64] : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = host_table_size;
    }

    @name(".ipv4_local_host") table local_host {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[95:64] : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = local_host_table_size;
    }

#ifdef IPV4_ALPM_OPT_EN
    Alpm(number_partitions = ipv4_lpm_number_partitions,
         subtrees_per_partition = ipv4_lpm_subtrees_per_partition,
         atcam_subset_width = ipv4_lpm_subset_width,
         shift_granularity = ipv4_lpm_shift_granularity) algo_lpm;
#else
    Alpm(number_partitions = ipv4_lpm_number_partitions, subtrees_per_partition = ipv4_lpm_subtrees_per_partition) algo_lpm;
#endif
    @name(".ipv4_lpm") table lpm32 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[95:64] : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss_lpm4(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss_lpm4(local_md);
        size = lpm_table_size;
        implementation = algo_lpm;
        requires_versioning = false;
    }

    apply {
        if (local_host_enable) {
            if (!local_host.apply().hit) {
                if (!host.apply().hit) {
                    lpm32.apply();
                }
            }
        } else {
            if (!host.apply().hit) {
                lpm32.apply();
            }
        }
    }
}
//
// *************************** IPv6 FIB **************************************
//
control Fibv6(inout switch_local_metadata_t local_md)(
              switch_uint32_t host_table_size,
              switch_uint32_t host64_table_size,
              switch_uint32_t lpm_table_size,
              switch_uint32_t lpm64_table_size=1024) {

    
    @immediate(0)
    @name(".ipv6_host") table host {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = host_table_size;
    }

#ifdef IPV6_HOST64_ENABLE
    
    @immediate(0)
    @name(".ipv6_host64") table host64 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[127:64] : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = host64_table_size;
    }
#endif /* IPV6_HOST64_ENABLE */

#ifndef IPV6_LPM128_TCAM
#ifdef IPV6_LPM64_ENABLE
    Alpm(number_partitions = ipv6_lpm128_number_partitions, subtrees_per_partition = ipv6_lpm128_subtrees_per_partition) algo_lpm128;
#else
    Alpm(number_partitions = ipv6_lpm128_number_partitions, subtrees_per_partition = ipv6_lpm128_subtrees_per_partition) algo_lpm128;
#endif /* IPV6_LPM64_ENABLE */
    @name(".ipv6_lpm128") table lpm128 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = lpm_table_size;
        implementation = algo_lpm128;
        requires_versioning = false;
    }
#endif /* IPV6_LPM128_TCAM */

#ifdef IPV6_LPM64_ENABLE
#ifdef IPV6_LPM128_TCAM
    @name(".ipv6_lpm_tcam") table lpm_tcam {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = lpm_table_size;
    }
#endif /* IPV6_LPM128_TCAM */

#ifdef IPV6_ALPM_OPT_EN
    Alpm(number_partitions = ipv6_lpm64_number_partitions,
         subtrees_per_partition = ipv6_lpm64_subtrees_per_partition,
         atcam_subset_width = ipv6_lpm64_subset_width,
         shift_granularity = ipv6_lpm64_shift_granularity) algo_lpm64;
#else
    Alpm(number_partitions = ipv6_lpm64_number_partitions, subtrees_per_partition = ipv6_lpm64_subtrees_per_partition) algo_lpm64;
#endif
    @name(".ipv6_lpm64") table lpm64 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[127:64] : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss_lpm6(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss_lpm6(local_md);
        size = lpm64_table_size;
        implementation = algo_lpm64;
        requires_versioning = false;
    }
#endif /* IPV6_LPM64_ENABLE */

    apply {
#ifdef IPV6_ENABLE
        if (!host.apply().hit) {
#ifdef IPV6_LPM128_TCAM
            if (!lpm_tcam.apply().hit)
#else
            if (!lpm128.apply().hit)
#endif /* IPV6_LPM128_TCAM */
            {
#ifdef IPV6_HOST64_ENABLE
                if(!host64.apply().hit) {
#endif /* IPV6_HOST64_ENABLE */
#ifdef IPV6_LPM64_ENABLE
                    lpm64.apply();
#endif /* IPV6_LPM64_ENABLE */
#ifdef IPV6_HOST64_ENABLE
                }
#endif /* IPV6_HOST64_ENABLE */
            }
        }
#endif /* IPV6_ENABLE */
    }
}

#else /* SHARED_IP_LPM64_TABLE */

//
// *************************** Shared IPv4/v6 LPM ********************************
//
control Fib(inout switch_local_metadata_t local_md)() {

    // IPv4 Host table
    @name(".ipv4_host") table v4_host {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[95:64] : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = IPV4_HOST_TABLE_SIZE;
    }

    // IPv6 Host table
    @name(".ipv6_host") table v6_host {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = IPV6_HOST_TABLE_SIZE;
    }

#ifdef IPV6_HOST64_ENABLE
    
    @immediate(0)
    @name(".ipv6_host64") table v6_host64 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[127:64] : exact @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = host64_table_size;
    }
#endif /* IPV6_HOST64_ENABLE */

    // IPv6 LPM - 128b
#ifdef IPV6_LPM128_TCAM
    @name(".ipv6_lpm_tcam") table lpm128 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = IPV6_LPM_TABLE_SIZE;
        requires_versioning = false;
    }

#else
    Alpm(number_partitions = ipv6_lpm128_number_partitions, subtrees_per_partition = ipv6_lpm128_subtrees_per_partition) algo_lpm128;
    @name(".ipv6_lpm128") table lpm128 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss(local_md);
        size = IPV6_LPM_TABLE_SIZE;
        implementation = algo_lpm128;
        requires_versioning = false;
    }
#endif /* IPV6_LPM128_TCAM */

    // Shared IPv4/IPv6-64b LPM
    Alpm(number_partitions = ip_lpm64_number_partitions, subtrees_per_partition = ip_lpm64_subtrees_per_partition) algo_lpm64;
    @name(".ip_lpm64") table lpm64 {
        key = {
            local_md.vrf : exact @name("vrf");
            local_md.lkp.ip_dst_addr[127:64] : lpm @name("ip_dst_addr");
        }

        actions = {
            fib_miss_lpm6(local_md);
            fib_hit(local_md);
            fib_myip(local_md);
            fib_drop(local_md);
        }

        const default_action = fib_miss_lpm6(local_md);
        size = IP_LPM64_TABLE_SIZE;
        implementation = algo_lpm64;
        requires_versioning = false;
    }

    apply {
        if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV4 && local_md.ipv4.unicast_enable) {
            if (!v4_host.apply().hit) {
                lpm64.apply();
            }
        } else if (local_md.lkp.ip_type == SWITCH_IP_TYPE_IPV6 && local_md.ipv6.unicast_enable) {
            if (!v6_host.apply().hit) {
                if (!lpm128.apply().hit) {
#ifdef IPV6_HOST64_ENABLE
		    if (!v6_host64.apply().hit) {
#endif /* IPV6_HOST64_ENABLE */
			lpm64.apply();
#ifdef IPV6_HOST64_ENABLE
		    }
#endif /* IPV6_HOST64_ENABLE */
                }
            }
        } else {
            // Non-ip packets with router MAC address will be dropped by system ACL.
        }
    }
}
#endif /* SHARED_IP_LPM64_TABLE */

//-----------------------------------------------------------------------------
// VRF Properties
//       -- Inner VRF for encap cases
//
//-----------------------------------------------------------------------------

control EgressVRF(inout switch_header_t hdr,
                 inout switch_local_metadata_t local_md) {

    @name(".set_vrf_properties")
    action set_vrf_properties(switch_tunnel_vni_t vni, mac_addr_t smac) {
        local_md.tunnel.vni = vni;
        hdr.ethernet.src_addr = smac;
    }

    @use_hash_action(1)
    @name(".vrf_mapping") table vrf_mapping {
        key = {
            local_md.vrf : exact @name("vrf");
        }
        actions = {
            set_vrf_properties;
        }

        const default_action = set_vrf_properties(0, 0);
        size = VRF_TABLE_SIZE;
    }

    apply {
        if (!local_md.flags.bypass_egress && local_md.flags.routed) {
            vrf_mapping.apply();
            if (hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            } else if (hdr.ipv6.isValid()) {
                hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
            }
        }
    }
}
//-----------------------------------------------------------------------------
// Egress pipeline : MTU Check
//-----------------------------------------------------------------------------
control MTU(in switch_header_t hdr,
            inout switch_local_metadata_t local_md)(
            switch_uint32_t table_size=16) {

    action ipv4_mtu_check() {
        local_md.checks.mtu = local_md.checks.mtu |-| hdr.ipv4.total_len;
    }

    action ipv6_mtu_check() {
        local_md.checks.mtu = local_md.checks.mtu |-| hdr.ipv6.payload_len;
    }

    action mtu_miss() {
        local_md.checks.mtu = 16w0xffff;
    }

    table mtu {
        key = {
            local_md.flags.bypass_egress : exact;
            local_md.flags.routed : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }

        actions = {
            ipv4_mtu_check;
            ipv6_mtu_check;
            mtu_miss;
        }

        const default_action = mtu_miss;
        const entries = {
            (false, true, true, false) : ipv4_mtu_check();
            (false, true, false, true) : ipv6_mtu_check();
        }
        size = table_size;
    }

    apply {
        mtu.apply();
    }
}
