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


// ============================================================================
// Packet validaion
// Validate ethernet, Ipv4 or Ipv6 headers and set the common lookup fields.
// ============================================================================
control PktValidation(
        in switch_header_t hdr,
        inout switch_local_metadata_t local_md) {
//-----------------------------------------------------------------------------
// Validate outer L2 header
// - Drop the packet if src addr is zero or multicast or dst addr is zero.
//-----------------------------------------------------------------------------
    const switch_uint32_t table_size = MIN_TABLE_SIZE;

    action valid_ethernet_pkt(switch_pkt_type_t pkt_type) {
        local_md.lkp.pkt_type = pkt_type;
        local_md.lkp.mac_dst_addr = hdr.ethernet.dst_addr;
    }

    @name(".malformed_eth_pkt")
    action malformed_eth_pkt(bit<8> reason) {
        local_md.lkp.mac_dst_addr = hdr.ethernet.dst_addr;
        local_md.lkp.mac_type = hdr.ethernet.ether_type;
        local_md.l2_drop_reason = reason;
    }

    @name(".valid_pkt_untagged")
    action valid_pkt_untagged(switch_pkt_type_t pkt_type) {
        local_md.lkp.mac_type = hdr.ethernet.ether_type;
        valid_ethernet_pkt(pkt_type);
    }

    @name(".valid_pkt_tagged")
    action valid_pkt_tagged(switch_pkt_type_t pkt_type) {
        local_md.lkp.mac_type = hdr.vlan_tag[0].ether_type;
        local_md.lkp.pcp = hdr.vlan_tag[0].pcp;
        valid_ethernet_pkt(pkt_type);
    }

#ifdef QINQ_RIF_ENABLE
    @name(".valid_pkt_double_tagged")
    action valid_pkt_double_tagged(switch_pkt_type_t pkt_type) {
        local_md.lkp.mac_type = hdr.vlan_tag[1].ether_type;
        local_md.lkp.pcp = hdr.vlan_tag[1].pcp;
        valid_ethernet_pkt(pkt_type);
    }
#endif /* QINQ_RIF_ENABLE */

    @name(".validate_ethernet")
    table validate_ethernet {
        key = {
            hdr.ethernet.src_addr : ternary;
            hdr.ethernet.dst_addr : ternary;
            hdr.vlan_tag[0].isValid() : ternary;
#ifdef QINQ_RIF_ENABLE
            hdr.vlan_tag[1].isValid() : ternary;
#endif /* QINQ_RIF_ENABLE */
        }

        actions = {
            malformed_eth_pkt;
            valid_pkt_untagged;
            valid_pkt_tagged;
#ifdef QINQ_RIF_ENABLE
            valid_pkt_double_tagged;
#endif /* QINQ_RIF_ENABLE */
        }

        size = table_size;
    }

//-----------------------------------------------------------------------------
// Validate outer L3 header
// - Drop the packet if src addr is zero or multicast or dst addr is zero.
//-----------------------------------------------------------------------------

    @name(".valid_arp_pkt")
    action valid_arp_pkt() {
#ifdef PARSE_FULL_ARP_HEADER
        local_md.lkp.ip_dst_addr[63:0]   = 64w0;
        local_md.lkp.ip_dst_addr[95:64]  = hdr.arp.target_proto_addr;
        local_md.lkp.ip_dst_addr[127:96] = 32w0;
#endif
        local_md.lkp.arp_opcode = hdr.arp.opcode;
    }

    // IP Packets
    @name(".valid_ipv6_pkt")
    action valid_ipv6_pkt(bool is_link_local) {
        // Set common lookup fields
        local_md.lkp.ip_type = SWITCH_IP_TYPE_IPV6;
        local_md.lkp.ip_tos = hdr.ipv6.traffic_class;
        local_md.lkp.ip_proto = hdr.ipv6.next_hdr;
        local_md.lkp.ip_ttl = hdr.ipv6.hop_limit;
        local_md.lkp.ip_src_addr = hdr.ipv6.src_addr;
        local_md.lkp.ip_dst_addr = hdr.ipv6.dst_addr;
        local_md.lkp.ipv6_flow_label = hdr.ipv6.flow_label;
        local_md.flags.link_local = is_link_local;
    }

    @name(".valid_ipv4_pkt")
    action valid_ipv4_pkt(switch_ip_frag_t ip_frag, bool is_link_local) {
        // Set common lookup fields
        local_md.lkp.ip_type = SWITCH_IP_TYPE_IPV4;
        local_md.lkp.ip_tos = hdr.ipv4.diffserv;
        local_md.lkp.ip_proto = hdr.ipv4.protocol;
        local_md.lkp.ip_ttl = hdr.ipv4.ttl;
        local_md.lkp.ip_src_addr[63:0]   = 64w0;
        local_md.lkp.ip_src_addr[95:64]  = hdr.ipv4.src_addr;
        local_md.lkp.ip_src_addr[127:96] = 32w0;
        local_md.lkp.ip_dst_addr[63:0]   = 64w0;
        local_md.lkp.ip_dst_addr[95:64]  = hdr.ipv4.dst_addr;
        local_md.lkp.ip_dst_addr[127:96] = 32w0;
        local_md.lkp.ip_frag = ip_frag;
        local_md.flags.link_local = is_link_local;
    }

    @name(".malformed_ipv4_pkt")
    action malformed_ipv4_pkt(bit<8> reason, switch_ip_frag_t ip_frag) {
        // Set common lookup fields just for dtel acl and hash purposes
        valid_ipv4_pkt(ip_frag, false);
        local_md.drop_reason = reason;
    }

    @name(".malformed_ipv6_pkt")
    action malformed_ipv6_pkt(bit<8> reason) {
        // Set common lookup fields just for dtel acl and hash purposes
        valid_ipv6_pkt(false);
        local_md.drop_reason = reason;
    }

#ifdef MPLS_ENABLE
    // MPLS Packets
    action set_mpls_pkt() {
        local_md.lkp.ip_type = SWITCH_IP_TYPE_MPLS;
        local_md.lkp.mpls_pkt = true;
    }

    @name(".valid_mpls_pkt")
    action valid_mpls_pkt() {
        local_md.lkp.mpls_lookup_label = hdr.mpls[0].label;
        set_mpls_pkt();
    }

    @name(".valid_mpls_null_pkt")
    action valid_mpls_null_pkt() {
        local_md.lkp.mpls_lookup_label = hdr.mpls[1].label;
        set_mpls_pkt();
    }

    // TODO: Fix parser to branch into parsing outer IP headers for null+IP case
    @name(".valid_mpls_null_ipv4_pkt")
    action valid_mpls_null_ipv4_pkt(switch_ip_frag_t ip_frag) {
        local_md.lkp.mpls_lookup_label = hdr.mpls[0].label;
        set_mpls_pkt();
    }

    @name(".valid_mpls_null_ipv6_pkt")
    action valid_mpls_null_ipv6_pkt(bool is_link_local) {
        local_md.lkp.mpls_lookup_label = hdr.mpls[0].label;
        set_mpls_pkt();
    }

    @name(".valid_mpls_router_alert_label")
    action valid_mpls_router_alert_label() {
      local_md.lkp.mpls_router_alert_label = 1;
    }
#endif

    @name(".validate_ip")
    table validate_ip {
        key = {
            hdr.arp.isValid() : ternary;
            hdr.ipv4.isValid() : ternary;
            local_md.flags.ipv4_checksum_err : ternary;
            hdr.ipv4.version : ternary;
            hdr.ipv4.ihl : ternary;
            hdr.ipv4.flags : ternary;
            hdr.ipv4.frag_offset : ternary;
            hdr.ipv4.ttl : ternary;
            hdr.ipv4.src_addr[31:0] : ternary;

            hdr.ipv6.isValid() : ternary;
            hdr.ipv6.version : ternary;
            hdr.ipv6.hop_limit : ternary;
            hdr.ipv6.src_addr[127:0] : ternary;
#ifdef MPLS_ENABLE
            hdr.mpls[0].isValid() : ternary;
            hdr.mpls[0].label : ternary;
            hdr.mpls[1].isValid() : ternary; //To determine MPLS NULL + another label
            hdr.inner_ipv4.isValid() : ternary; // To derermine MPLS NULL + inner IPV4
            hdr.inner_ipv6.isValid() : ternary; // To derermine MPLS NULL + inner IPV6
#endif
        }

        actions = {
            malformed_ipv4_pkt;
            malformed_ipv6_pkt;
            valid_arp_pkt;
            valid_ipv4_pkt;
            valid_ipv6_pkt;
#ifdef MPLS_ENABLE
            valid_mpls_pkt;
            valid_mpls_null_pkt;
            valid_mpls_null_ipv4_pkt;
            valid_mpls_null_ipv6_pkt;
            valid_mpls_router_alert_label;
#endif
        }

        size = table_size;
    }

//-----------------------------------------------------------------------------
// Set L4 and other lookup fields
//-----------------------------------------------------------------------------
    action set_tcp_ports() {
        local_md.lkp.l4_src_port = hdr.tcp.src_port;
        local_md.lkp.l4_dst_port = hdr.tcp.dst_port;
        local_md.lkp.tcp_flags = hdr.tcp.flags;
    }

    action set_udp_ports() {
        local_md.lkp.l4_src_port = hdr.udp.src_port;
        local_md.lkp.l4_dst_port = hdr.udp.dst_port;
        local_md.lkp.tcp_flags = 0;
    }

    action set_icmp_type() {
        local_md.lkp.l4_src_port[7:0] = hdr.icmp.type;
        local_md.lkp.l4_src_port[15:8] = hdr.icmp.code;
        local_md.lkp.l4_dst_port = 0;
        local_md.lkp.tcp_flags = 0;
    }

    action set_igmp_type() {
        local_md.lkp.l4_src_port[7:0] = hdr.igmp.type;
        local_md.lkp.l4_src_port[15:8] = 0;
        local_md.lkp.l4_dst_port = 0;
        local_md.lkp.tcp_flags = 0;
    }

    // Not much of a validation as it only sets the lookup fields.
    table validate_other {
        key = {
            hdr.tcp.isValid() : exact;
            hdr.udp.isValid() : exact;
            hdr.icmp.isValid() : exact;
            hdr.igmp.isValid() : exact;
        }

        actions = {
            NoAction;
            set_tcp_ports;
            set_udp_ports;
            set_icmp_type;
#ifdef MULTICAST_ENABLE
            set_igmp_type;
#endif
        }

        const default_action = NoAction;
        const entries = {
            (true, false, false, false) : set_tcp_ports();
            (false, true, false, false) : set_udp_ports();
            (false, false, true, false) : set_icmp_type();
#ifdef MULTICAST_ENABLE
            (false, false, false, true) : set_igmp_type();
#endif
        }
        size = 16;
    }

    apply {
        validate_ethernet.apply();
        validate_ip.apply();
        validate_other.apply();
    }
}

// ============================================================================
// Same MAC Check
// Checks if source mac address matches with destination mac address
// ============================================================================
control SameMacCheck(in switch_header_t hdr, inout switch_local_metadata_t local_md) {

    @name(".compute_same_mac_check")
    action compute_same_mac_check() {
        local_md.drop_reason = SWITCH_DROP_REASON_OUTER_SAME_MAC_CHECK;
    }

    @ways(1)
    @name(".same_smac_check")
    table same_mac_check {
        key = {
            local_md.same_mac : exact;
        }
        actions = {
            NoAction;
            compute_same_mac_check;
        }
        const default_action = NoAction;
        const entries = {
            (48w0x0) : compute_same_mac_check();
        }
    }

    apply {
        local_md.same_mac = hdr.ethernet.src_addr ^ hdr.ethernet.dst_addr;
        same_mac_check.apply();
    }
}

// ============================================================================
// Inner packet validaion
// Validate ethernet, Ipv4 or Ipv6 common lookup fields.
// NOTE:
// For IPinIP packets, the actions are valid_ipv*. This would set the L2
// lookup fields to 0. The RMAC table is setup to ignore the dmac to process
// these packets
// ============================================================================
control InnerPktValidation(
        in switch_header_t hdr,
        inout switch_local_metadata_t local_md) {

    @name(".valid_inner_ethernet_pkt")
    action valid_ethernet_pkt(switch_pkt_type_t pkt_type) {
#ifdef INNER_L2_ENABLE
        local_md.lkp.mac_dst_addr = hdr.inner_ethernet.dst_addr;
        local_md.lkp.mac_type = hdr.inner_ethernet.ether_type;
#endif /* INNER_L2_ENABLE */
        local_md.lkp.pkt_type = pkt_type;
    }

    @name(".valid_inner_ipv4_pkt")
    action valid_ipv4_pkt(switch_pkt_type_t pkt_type) {
        // Set the common IP lookup fields
#ifdef INNER_L2_ENABLE
        local_md.lkp.mac_dst_addr = hdr.inner_ethernet.dst_addr;
#endif /* INNER_L2_ENABLE */
        local_md.lkp.mac_type = ETHERTYPE_IPV4;
        local_md.lkp.pkt_type = pkt_type;
        local_md.lkp.ip_type = SWITCH_IP_TYPE_IPV4;
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.lkp.ip_tos = hdr.inner_ipv4.diffserv;
#endif
        local_md.lkp.ip_ttl = hdr.inner_ipv4.ttl;
        local_md.lkp.ip_proto = hdr.inner_ipv4.protocol;
        local_md.lkp.ip_src_addr[63:0]   = 64w0;
        local_md.lkp.ip_src_addr[95:64]  = hdr.inner_ipv4.src_addr;
        local_md.lkp.ip_src_addr[127:96] = 32w0;
        local_md.lkp.ip_dst_addr[63:0]   = 64w0;
        local_md.lkp.ip_dst_addr[95:64]  = hdr.inner_ipv4.dst_addr;
        local_md.lkp.ip_dst_addr[127:96] = 32w0;
    }

    @name(".valid_inner_ipv6_pkt")
    action valid_ipv6_pkt(switch_pkt_type_t pkt_type) {
#ifdef IPV6_ENABLE
        // Set the common IP lookup fields
#ifdef INNER_L2_ENABLE
        local_md.lkp.mac_dst_addr = hdr.inner_ethernet.dst_addr;
#endif /* INNER_L2_ENABLE */
        local_md.lkp.mac_type = ETHERTYPE_IPV6;
        local_md.lkp.pkt_type = pkt_type;
        local_md.lkp.ip_type = SWITCH_IP_TYPE_IPV6;
#ifdef TUNNEL_QOS_MODE_ENABLE
        local_md.lkp.ip_tos = hdr.inner_ipv6.traffic_class;
#endif
        local_md.lkp.ip_ttl = hdr.inner_ipv6.hop_limit;
        local_md.lkp.ip_proto = hdr.inner_ipv6.next_hdr;
        local_md.lkp.ip_src_addr = hdr.inner_ipv6.src_addr;
        local_md.lkp.ip_dst_addr = hdr.inner_ipv6.dst_addr;
        local_md.lkp.ipv6_flow_label = hdr.inner_ipv6.flow_label;
        local_md.flags.link_local = false;
#endif
    }

    action set_tcp_ports() {
        local_md.lkp.l4_src_port = hdr.inner_tcp.src_port;
        local_md.lkp.l4_dst_port = hdr.inner_tcp.dst_port;
    }

    action set_udp_ports() {
        local_md.lkp.l4_src_port = hdr.inner_udp.src_port;
        local_md.lkp.l4_dst_port = hdr.inner_udp.dst_port;
    }

    @name(".valid_inner_ipv4_tcp_pkt")
    action valid_ipv4_tcp_pkt(switch_pkt_type_t pkt_type) {
        // Set the common L2 lookup fields
        valid_ipv4_pkt(pkt_type);
        set_tcp_ports();
    }

    @name(".valid_inner_ipv4_udp_pkt")
    action valid_ipv4_udp_pkt(switch_pkt_type_t pkt_type) {
        // Set the common L2 lookup fields
        valid_ipv4_pkt(pkt_type);
        set_udp_ports();
    }

    @name(".valid_inner_ipv6_tcp_pkt")
    action valid_ipv6_tcp_pkt(switch_pkt_type_t pkt_type) {
        // Set the common L2 lookup fields
        valid_ipv6_pkt(pkt_type);
        set_tcp_ports();
    }

    @name(".valid_inner_ipv6_udp_pkt")
    action valid_ipv6_udp_pkt(switch_pkt_type_t pkt_type) {
        // Set the common L2 lookup fields
        valid_ipv6_pkt(pkt_type);
        set_udp_ports();
    }

    @name(".malformed_inner_pkt")
    action malformed_pkt(bit<8> reason) {
        local_md.drop_reason = reason;
    }

    @name(".validate_inner_ethernet")
    table validate_ethernet {
        key = {
            hdr.inner_ethernet.isValid() : ternary;
#ifdef INNER_L2_ENABLE
            hdr.inner_ethernet.dst_addr : ternary;
#endif /* INNER_L2_ENABLE */

            hdr.inner_ipv6.isValid() : ternary;
            hdr.inner_ipv6.version : ternary;
            hdr.inner_ipv6.hop_limit : ternary;

            hdr.inner_ipv4.isValid() : ternary;
            local_md.flags.inner_ipv4_checksum_err : ternary;
            hdr.inner_ipv4.version : ternary;
            hdr.inner_ipv4.ihl : ternary;
            hdr.inner_ipv4.ttl : ternary;

            hdr.inner_tcp.isValid() : ternary;
            hdr.inner_udp.isValid() : ternary;

        }

        actions = {
            NoAction;
            valid_ipv4_tcp_pkt;
            valid_ipv4_udp_pkt;
            valid_ipv4_pkt;
            valid_ipv6_tcp_pkt;
            valid_ipv6_udp_pkt;
            valid_ipv6_pkt;
#ifdef INNER_L2_ENABLE
            valid_ethernet_pkt;
#endif /* INNER_L2_ENABLE */
            malformed_pkt;
        }
        size = MIN_TABLE_SIZE;
    }

    apply {
        validate_ethernet.apply();
    }
}
