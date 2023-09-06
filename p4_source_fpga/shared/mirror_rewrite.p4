
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


#ifndef _P4_REWRITE_
#define _P4_REWRITE_

#include "l2.p4"

//-----------------------------------------------------------------------------
// @param hdr : Parsed headers. For mirrored packet only Ethernet header is parsed.
// @param local_md : Egress metadata fields.
// @param table_size : Number of mirror sessions.
//
// @flags PACKET_LENGTH_ADJUSTMENT : For mirrored packet, the length of the mirrored
// metadata fields is also accounted in the packet length. This flags enables the
// calculation of the packet length excluding the mirrored metadata fields.
//-----------------------------------------------------------------------------
control MirrorRewrite(inout switch_header_t hdr,
                      inout switch_local_metadata_t local_md,
                      out egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr)(
                      switch_uint32_t table_size=1024) {
    bit<16> length;

    // Common actions
    action add_ethernet_header(in mac_addr_t src_addr,
                               in mac_addr_t dst_addr,
                               in bit<16> ether_type) {
        hdr.ethernet.setValid();
        hdr.ethernet.ether_type = ether_type;
        hdr.ethernet.src_addr = src_addr;
        hdr.ethernet.dst_addr = dst_addr;
    }

    action add_vlan_tag(vlan_id_t vid, bit<3> pcp, bit<16> ether_type) {
        hdr.vlan_tag[0].setValid();
        hdr.vlan_tag[0].pcp = pcp;
        // hdr.vlan_tag[0].cfi = 0;
        hdr.vlan_tag[0].vid = vid;
        hdr.vlan_tag[0].ether_type = ether_type;
    }

    // update add vlan
    action add_rspan_vlan_tag(bit<16> ether_type) {
        hdr.vlan_tag[0].setValid();
        //hdr.vlan_tag[0].pcp = pcp;
        //hdr.vlan_tag[0].cfi = 0;
        hdr.vlan_tag[0].vid = local_md.app_id;
        hdr.vlan_tag[0].ether_type = ether_type;
    }

    action add_ipv4_header(in bit<8> diffserv,
                           in bit<8> ttl,
                           in bit<8> protocol,
                           in ipv4_addr_t src_addr,
                           in ipv4_addr_t dst_addr) {
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4w4;
        hdr.ipv4.ihl = 4w5;
        hdr.ipv4.diffserv = diffserv;
        // hdr.ipv4.total_len = 0;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.frag_offset = 0;
        hdr.ipv4.ttl = ttl;
        hdr.ipv4.protocol = protocol;
        hdr.ipv4.src_addr = src_addr;
        hdr.ipv4.dst_addr = dst_addr;
    }

    action add_gre_header(in bit<16> proto) {
        hdr.gre.setValid();
        hdr.gre.proto = proto;
        hdr.gre.flags_version = 0;
        hdr.gre.sequence_number = 0;
    }

    action add_erspan_common(bit<16> version_vlan, bit<10> session_id) {
        hdr.erspan.setValid();
        hdr.erspan.version_vlan = version_vlan;
        hdr.erspan.session_id = (bit<16>) session_id;
    }

    action add_erspan_type2(bit<10> session_id) {
        add_erspan_common(0x1000, session_id);
        hdr.erspan_type2.setValid();
        hdr.erspan_type2.index = 0;
    }

    action add_erspan_type3(bit<10> session_id, bit<32> timestamp, bool opt_sub_header) {
        add_erspan_common(0x2000, session_id);
        hdr.erspan_type3.setValid();
        hdr.erspan_type3.timestamp = timestamp;
        hdr.erspan_type3.ft_d_other = 0x4;  // timestamp granularity IEEE 1588
        if (opt_sub_header) {
#ifdef ERSPAN_PLATFORM_ENABLE
            hdr.erspan_platform.setValid();
            hdr.erspan_platform.id = 0;
            hdr.erspan_platform.info = 0;
#endif /* ERSPAN_PLATFORM_ENABLE */
        }
    }

    //
    // ----------------  QID rewrite ----------------
    //
    @name(".rewrite_")
    action rewrite_(switch_qid_t qid) {
        local_md.qos.qid = qid;
    }

#ifdef RSPAN_ENABLE
    //
    // ----------------  Remote SPAN  ---------------- 
    //
    @name(".rewrite_rspan")
    action rewrite_rspan(switch_qid_t qid) {
        local_md.qos.qid = qid;
        //add_vlan_tag(vid, pcp, hdr.ethernet.ether_type);
        add_rspan_vlan_tag(hdr.ethernet.ether_type);
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
    }
#endif /* RSPAN_ENABLE */

#ifdef ERSPAN_TYPE2_ENABLE
    //
    // ---------------- ERSPAN Type II ---------------- 
    //
    @name(".rewrite_erspan_type2")
    action rewrite_erspan_type2(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        //GRE sequence number is not supported
        local_md.qos.qid = qid;
        add_erspan_type2((bit<10>)local_md.mirror.session_id);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_2);
        hdr.gre.flags_version = 0x1000;

        // Total length = packet length + 32
        //   IPv4 (20) + GRE (4) + Erspan (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        //hdr.ipv4.total_len = local_md.pkt_length + 16w32;
        hdr.ipv4.total_len = local_md.pkt_length + 16w36;
#else
        //hdr.ipv4.total_len = local_md.pkt_length + 16w20;
        hdr.ipv4.total_len = local_md.pkt_length + 16w24;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
    }

    @name(".rewrite_erspan_type2_with_vlan")
    action rewrite_erspan_type2_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        local_md.qos.qid = qid;
        add_erspan_type2((bit<10>) local_md.mirror.session_id);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_2);

        // Total length = packet length + 32
        //   IPv4 (20) + GRE (4) + Erspan (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        //hdr.ipv4.total_len = local_md.pkt_length + 16w32;
        hdr.ipv4.total_len = local_md.pkt_length + 16w36;
#else
        //hdr.ipv4.total_len = local_md.pkt_length + 16w20;
        hdr.ipv4.total_len = local_md.pkt_length + 16w24;
#endif
        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
    }
#endif /* ERSPAN_TYPE2_ENABLE */

#ifdef ERSPAN_ENABLE
    //
    // --------- ERSPAN Type III ---------------
    //
    @name(".rewrite_erspan_type3")
    action rewrite_erspan_type3(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        local_md.qos.qid = qid;
        add_erspan_type3((bit<10>)local_md.mirror.session_id, (bit<32>)local_md.ingress_timestamp, false);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 36
        //   IPv4 (20) + GRE (4) + Erspan (12)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = local_md.pkt_length + 16w36;
#else
        hdr.ipv4.total_len = local_md.pkt_length + 16w24;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
    }

    @name(".rewrite_erspan_type3_with_vlan")
    action rewrite_erspan_type3_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        local_md.qos.qid = qid;
        add_erspan_type3((bit<10>)local_md.mirror.session_id, (bit<32>)local_md.ingress_timestamp, false);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 36
        //   IPv4 (20) + GRE (4) + Erspan (12)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = local_md.pkt_length + 16w36;
#else
        hdr.ipv4.total_len = local_md.pkt_length + 16w24;
#endif
        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
    }
#endif /* ERSPAN_ENABLE */

#ifdef ERSPAN_PLATFORM_ENABLE
    //
    // --------- Platform Extensions for ERSPAN Type III ---------------
    //
    @name(".rewrite_erspan_type3_platform_specific")
    action rewrite_erspan_type3_platform_specific(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        local_md.qos.qid = qid;
        add_erspan_type3((bit<10>)local_md.mirror.session_id, (bit<32>)local_md.ingress_timestamp, true);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 44
        //   IPv4 (20) + GRE (4) + Erspan (12) + Platform Specific (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = local_md.pkt_length + 16w44;
#else
        hdr.ipv4.total_len = local_md.pkt_length + 16w32;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
    }

    @name(".rewrite_erspan_type3_platform_specific_with_vlan")
    action rewrite_erspan_type3_platform_specific_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        local_md.qos.qid = qid;

        add_erspan_type3((bit<10>)local_md.mirror.session_id, (bit<32>)local_md.ingress_timestamp, true);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 44
        //   IPv4 (20) + GRE (4) + Erspan (12) + Platform Specific (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = local_md.pkt_length + 16w44;
#else
        hdr.ipv4.total_len = local_md.pkt_length + 16w32;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
    }
#endif /* ERSPAN_PLATFORM_ENABLE */

#ifdef DTEL_ENABLE
    //
    // ----------------  DTEL Report  ---------------- 
    //
    action rewrite_dtel_report(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port, switch_mirror_session_t session_id,
            bit<16> max_pkt_len) {
        // Dtel report header is added later in the pipeline.
        hdr.udp.setValid();
        hdr.udp.dst_port = udp_dst_port;
        hdr.udp.checksum = 0;

        // Total length = packet length + 28
        //   Add outer IPv4 (20) + UDP (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_UDP, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
#ifdef INT_V2
        hdr.ipv4.total_len = local_md.pkt_length + 16w40;
        hdr.udp.length = local_md.pkt_length + 16w20;
        hdr.dtel.report_length = local_md.pkt_length >> 2;
#else
        hdr.ipv4.total_len = local_md.pkt_length + 16w28;
        hdr.udp.length = local_md.pkt_length + 16w8;
#endif /* INT_V2 */
#else
#error "Packet length adjustment is required for DTel"
#endif /* PACKET_LENGTH_ADJUSTMENT */
        hdr.ipv4.flags = 2;

        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);

#if __TARGET_TOFINO__ == 1
        // May be used by deflected packets for truncation
        local_md.dtel.session_id = session_id;
#ifdef INT_V2
        // Use local_md.pkt_length to store max dod report_length in 4-byte words
        local_md.pkt_length = max_pkt_len;
#endif /* INT_V2 */
#endif /* __TARGET_TOFINO__ == 1 */

#ifdef DEPARSER_TRUNCATE
        eg_intr_md_for_dprsr.mtu_trunc_len = (bit<14>)max_pkt_len;

#ifdef INT_V2
        local_md.pkt_length = local_md.pkt_length +
                           DTEL_REPORT_V2_OUTER_HEADERS_LENGTH;
#else
        local_md.pkt_length = local_md.pkt_length +
                           DTEL_REPORT_V0_5_OUTER_HEADERS_LENGTH;
#endif /* INT_V2 */
#endif /* DEPARSER_TRUNCATE */
    }

    @name(".rewrite_dtel_report_with_entropy")
    action rewrite_dtel_report_with_entropy(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port, switch_mirror_session_t session_id,
            bit<16> max_pkt_len) {
        rewrite_dtel_report(smac, dmac, sip, dip, tos, ttl, udp_dst_port,
                            session_id, max_pkt_len);
        hdr.udp.src_port = local_md.dtel.hash[15:0];
    }

    @name(".rewrite_dtel_report_without_entropy")
    action rewrite_dtel_report_without_entropy(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port, bit<16> udp_src_port,
            switch_mirror_session_t session_id, bit<16> max_pkt_len) {
        rewrite_dtel_report(smac, dmac, sip, dip, tos, ttl, udp_dst_port,
                            session_id, max_pkt_len);
        hdr.udp.src_port = udp_src_port;
    }

    @name(".rewrite_ip_udp_lengths")
    action rewrite_ip_udp_lengths() {
#ifdef PACKET_LENGTH_ADJUSTMENT
        // Subtract outer ethernet
        hdr.ipv4.total_len = local_md.pkt_length - 16w14;
        hdr.udp.length = local_md.pkt_length - 16w34;
#else
#error "Packet length adjustment is required for DTel"
#endif
    }

    @name(".rewrite_dtel_ifa_clone")
    action rewrite_dtel_ifa_clone() {
        /* Indicates that IFA clone rewrite needs to occur.
         * For IFA identification using DSCP, not done in place here since
         * the rewrite differs for IPv4 and IPv6 packets. */
        local_md.dtel.ifa_cloned = 1;
    }
#endif /* DTEL_ENABLE */

#if __TARGET_TOFINO__ == 1
    @ways(2)
#endif
    @name(".mirror_rewrite")
    table rewrite {
        key = { local_md.mirror.session_id : exact; }
        actions = {
            NoAction;
            rewrite_;
#ifdef RSPAN_ENABLE
            rewrite_rspan;
#endif
#ifdef ERSPAN_TYPE2_ENABLE
            rewrite_erspan_type2;
            rewrite_erspan_type2_with_vlan;
#endif
#ifdef ERSPAN_ENABLE
            rewrite_erspan_type3;
            rewrite_erspan_type3_with_vlan;
#endif
#ifdef ERSPAN_PLATFORM_ENABLE
            rewrite_erspan_type3_platform_specific;
            rewrite_erspan_type3_platform_specific_with_vlan;
#endif
#ifdef DTEL_ENABLE
            rewrite_dtel_report_with_entropy;
            rewrite_dtel_report_without_entropy;
#if __TARGET_TOFINO__ == 1
            rewrite_ip_udp_lengths;
#endif
#ifdef DTEL_IFA_CLONE
            rewrite_dtel_ifa_clone;
#endif
#endif /* DTEL_ENABLE */
        }

        const default_action = NoAction;
        size = table_size;
    }


    //------------------------------------------------------------------------------------------
    // Length Adjustment
    //------------------------------------------------------------------------------------------

    action adjust_length(bit<16> length_offset) {
        local_md.pkt_length = local_md.pkt_length + length_offset;
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }

#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
    /*
        Mirror stage egress - io_select set to 0 i.e. mirror packet ingressing from TM to egress parser
        Mirror packet format <mirror_hd> <bridged MD> <packet> ----> SWITCH_PKT_SRC_CLONED_EGRESS_IN_PKT
        Egress deparser strips these headers, but IP packet length adjustment happens here
    */
    action adjust_length_with_b_md() {
        switch_bridged_metadata_h b_md;
#ifdef INT_V2
        // -13[switch_port_mirror_metadata_h - 4 bytes of CRC]
        // -[len of switch_bridged_metadata_h]
        switch_pkt_length_t length_offset = 0xFFF3 - (bit<16>)sizeInBytes(b_md);
#else
        // -11[switch_port_mirror_metadata_h - 4 bytes of CRC] 
        // -[len of switch_bridged_metadata_h]
        switch_pkt_length_t length_offset = 0xFFF5 - (bit<16>)sizeInBytes(b_md);
#endif
        local_md.pkt_length = local_md.pkt_length + length_offset;
        local_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }
#endif

    table pkt_length {
        key = { local_md.mirror.type : exact; }
        actions = {
                adjust_length;
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
                adjust_length_with_b_md;
#endif
        }
        const entries = {
            //-14
            SWITCH_MIRROR_TYPE_CPU : adjust_length(0xFFF2);
#if __TARGET_TOFINO__ == 1
#ifdef INT_V2
            /* - len(switch_port_mirror_metadata_h) - 4 bytes of CRC */
            //-14
            SWITCH_MIRROR_TYPE_PORT : adjust_length(0xFFF2);
            /* Set local_md.pkt_length to telemetry report v2 report_length
             * (in bytes) rather than udp payload length */
            /* len(telemetry report v2.0 header included in report_length)
             * + len(telemetry drop metadata)
             * - len(switch_dtel_drop_mirror_metadata_h) - 4 bytes of CRC */
            //-1
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(0xFFFF);
            /* len(telemetry report v2.0 header included in report_length)
             * + len(telemetry switch local metadata)
             * - len(switch_dtel_switch_local_mirror_metadata_h)
             * - 4 bytes of CRC */
            //-1
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(0xFFFF);
#else
            /* - len(switch_port_mirror_metadata_h) - 4 bytes of CRC */
            //-12
            SWITCH_MIRROR_TYPE_PORT : adjust_length(0xFFF4);
            /* len(telemetry report v0.5 header)
             * + len(telemetry drop report header)
             * - len(switch_dtel_drop_mirror_metadata_h) - 4 bytes of CRC */
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(0x1);
            /* len(telemetry report v0.5 header)
             * + len(telemetry switch local report header)
             * - len(switch_dtel_switch_local_mirror_metadata_h)
             * - 4 bytes of CRC */
            //-1
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(0xFFFF);
#endif /* INT_V2 */
            /* - len(switch_simple_mirror_metadata_h) - 4 bytes of CRC */
            //-8
            SWITCH_MIRROR_TYPE_SIMPLE: adjust_length(0xFFF8);
#else
#ifdef INT_V2
            //-13
            SWITCH_MIRROR_TYPE_PORT : adjust_length(0xFFF3);
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(0);
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(0);
#else
            //-11
            SWITCH_MIRROR_TYPE_PORT : adjust_length(0xFFF5);
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(2);
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(0x0);
#endif /* INT_V2 */
            //-7
            SWITCH_MIRROR_TYPE_SIMPLE: adjust_length(0xFFF9);
#ifdef EGRESS_ACL_ACTION_MIRROR_IN_ENABLE
            SWITCH_MIRROR_TYPE_PORT_WITH_B_MD : adjust_length_with_b_md();
#endif
#endif /* __TARGET_TOFINO__ == 1 */
#ifdef INT_V2
            /* len(telemetry report v2.0 header included in report_length)
             * + len(telemetry drop metadata) - 4 bytes of CRC */
            SWITCH_MIRROR_TYPE_DTEL_DEFLECT: adjust_length(20);
#else
            /* len(telemetry report v0.5 header)
             * + len(telemetry drop report header) - 4 bytes of CRC */
            SWITCH_MIRROR_TYPE_DTEL_DEFLECT: adjust_length(20);
#endif /* INT_V2 */
        }
    }

    action rewrite_ipv4_udp_len_truncate() {
#ifdef DEPARSER_TRUNCATE
        // (eth + crc) = 18
        hdr.ipv4.total_len = (bit<16>)eg_intr_md_for_dprsr.mtu_trunc_len - 16w18;
        // (eth + ipv4 + crc) = 38
        hdr.udp.length = (bit<16>)eg_intr_md_for_dprsr.mtu_trunc_len - 16w38;

#ifdef INT_V2
        hdr.dtel.report_length = (bit<16>)eg_intr_md_for_dprsr.mtu_trunc_len -
                                 DTEL_REPORT_V2_OUTER_HEADERS_LENGTH;
#endif /* INT_V2 */
#endif /* DEPARSER_TRUNCATE */
    }

    table pkt_len_trunc_adjustment {
        key = {
                hdr.udp.isValid() : exact ;
                hdr.ipv4.isValid() : exact;
        }

        actions = {
                NoAction;
                rewrite_ipv4_udp_len_truncate;
        }

        const default_action = NoAction;
        const entries = {
            (true, true) : rewrite_ipv4_udp_len_truncate();
        }
    }

    apply {
#if defined(MIRROR_ENABLE)
#ifdef PACKET_LENGTH_ADJUSTMENT
        pkt_length.apply();
#endif
        rewrite.apply();

#ifdef DEPARSER_TRUNCATE
        local_md.pkt_length = local_md.pkt_length |-| (bit<16>)eg_intr_md_for_dprsr.mtu_trunc_len;
        if (local_md.pkt_length > 0 && eg_intr_md_for_dprsr.mtu_trunc_len > 0) {
            pkt_len_trunc_adjustment.apply();
#ifdef INT_V2
            hdr.dtel.report_length = hdr.dtel.report_length >> 2;
#endif
        }
#endif /* DEPARSER_TRUNCATE */

#endif /* MIRROR_ENABLE */
    }
}

#endif /* _P4_REWRITE_ */
