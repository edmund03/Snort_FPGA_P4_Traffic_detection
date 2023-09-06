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


#include "types.p4"

// Flow hash calculation.

#ifdef RESILIENT_ECMP_HASH_ENABLE
Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv4_hash0;
Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_hash0;
Hash<bit<32>>(HashAlgorithm_t.CRC32) non_ip_hash;
Hash<bit<32>>(HashAlgorithm_t.CRC32) mpls_hash;
Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv4_hash1;
Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_hash1;

action compute_ipv4_hash0(in switch_lookup_fields_t lkp, out bit<32> hash) {
    bit<32> ip_src_addr = lkp.ip_src_addr[95:64];
    bit<32> ip_dst_addr = lkp.ip_dst_addr[95:64];
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;

    hash[31:0] = ipv4_hash0.get({ip_src_addr,
                                 ip_dst_addr,
                                 ip_proto,
                                 l4_dst_port,
                                 l4_src_port});
}

action compute_ipv6_hash0(in switch_lookup_fields_t lkp, out bit<32> hash) {
    bit<128> ip_src_addr = lkp.ip_src_addr;
    bit<128> ip_dst_addr = lkp.ip_dst_addr;
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;
    bit<20> ipv6_flow_label = lkp.ipv6_flow_label;

    hash[31:0] = ipv6_hash0.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                 ipv6_flow_label,
#endif
                                 ip_src_addr,
                                 ip_dst_addr,
                                 ip_proto,
                                 l4_dst_port,
                                 l4_src_port});
}

action compute_non_ip_hash(in switch_header_t hdr, in switch_lookup_fields_t lkp, out bit<32> hash) {
    mac_addr_t mac_dst_addr = hdr.ethernet.dst_addr;
    mac_addr_t mac_src_addr = hdr.ethernet.src_addr;
    bit<16> mac_type = hdr.ethernet.ether_type;

    hash[31:0] = non_ip_hash.get({mac_type, mac_src_addr, mac_dst_addr});
}

action compute_ipv4_hash1(in switch_lookup_fields_t lkp, out bit<32> hash) {
    bit<32> ip_src_addr = lkp.ip_src_addr[95:64];
    bit<32> ip_dst_addr = lkp.ip_dst_addr[95:64];
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;

    hash[31:0] = ipv4_hash1.get({ip_proto,
                                 l4_src_port,
                                 ip_dst_addr,
                                 l4_dst_port,
                                 ip_src_addr});
}

action compute_ipv6_hash1(in switch_lookup_fields_t lkp, out bit<32> hash) {
    bit<128> ip_src_addr = lkp.ip_src_addr;
    bit<128> ip_dst_addr = lkp.ip_dst_addr;
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;
    bit<20> ipv6_flow_label = lkp.ipv6_flow_label;

    hash[31:0] = ipv6_hash1.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                 ipv6_flow_label,
#endif
                                 ip_proto,
                                 l4_src_port,
                                 ip_dst_addr,
                                 l4_dst_port,
                                 ip_src_addr});
}

#endif

// If fragments, then reset hash l4 port values to zero
// For non fragments, hash l4 ports will be init to l4 port values
control EnableFragHash(inout switch_lookup_fields_t lkp) {
    apply {
        if (lkp.ip_frag != SWITCH_IP_FRAG_NON_FRAG) {
            lkp.hash_l4_dst_port = 0;
            lkp.hash_l4_src_port = 0;
        } else {
            lkp.hash_l4_dst_port = lkp.l4_dst_port;
            lkp.hash_l4_src_port = lkp.l4_src_port;
        }
    }
}

control Ipv4Hash(in switch_lookup_fields_t lkp, out switch_hash_t hash) {
    @name(".ipv4_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv4_hash;
    bit<32> ip_src_addr = lkp.ip_src_addr[95:64];
    bit<32> ip_dst_addr = lkp.ip_dst_addr[95:64];
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;

    apply {
        hash [31:0] = ipv4_hash.get({ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
                                     l4_dst_port,
                                     l4_src_port});
    }
}

control Ipv6Hash(in switch_lookup_fields_t lkp, out switch_hash_t hash) {
    @name(".ipv6_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_hash;
    bit<128> ip_src_addr = lkp.ip_src_addr;
    bit<128> ip_dst_addr = lkp.ip_dst_addr;
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;
    bit<20> ipv6_flow_label = lkp.ipv6_flow_label;

    apply {
        hash[31:0] = ipv6_hash.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                    ipv6_flow_label,
#endif
                                    ip_src_addr,
                                    ip_dst_addr,
                                    ip_proto,
                                    l4_dst_port,
                                    l4_src_port});
    }
}
control NonIpHash(in switch_header_t hdr, in switch_local_metadata_t local_md, out switch_hash_t hash) {
    @name(".non_ip_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) non_ip_hash;
    mac_addr_t mac_dst_addr = hdr.ethernet.dst_addr;
    mac_addr_t mac_src_addr = hdr.ethernet.src_addr;
    bit<16> mac_type = hdr.ethernet.ether_type;
    switch_port_t port = local_md.ingress_port;

    apply {
        hash [31:0] = non_ip_hash.get({port,
                                       mac_type,
                                       mac_src_addr,
                                       mac_dst_addr});
    }
}
control Lagv4Hash(in switch_lookup_fields_t lkp, out switch_hash_t hash) {
    @name(".lag_v4_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) lag_v4_hash;
    bit<32> ip_src_addr = lkp.ip_src_addr[95:64];
    bit<32> ip_dst_addr = lkp.ip_dst_addr[95:64];
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;

    apply {
        hash[31:0] = lag_v4_hash.get({ip_src_addr,
                                   ip_dst_addr,
                                   ip_proto,
                                   l4_dst_port,
                                   l4_src_port});
    }
}
control Lagv6Hash(in switch_lookup_fields_t lkp, out switch_hash_t hash) {
    @name(".lag_v6_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) lag_v6_hash;
    bit<128> ip_src_addr = lkp.ip_src_addr;
    bit<128> ip_dst_addr = lkp.ip_dst_addr;
    bit<8> ip_proto = lkp.ip_proto;
    bit<16> l4_dst_port = lkp.hash_l4_dst_port;
    bit<16> l4_src_port = lkp.hash_l4_src_port;
    bit<20> ipv6_flow_label = lkp.ipv6_flow_label;

    apply {
        hash[31:0] = lag_v6_hash.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                   ipv6_flow_label,
#endif
                                   ip_src_addr,
                                   ip_dst_addr,
                                   ip_proto,
                                   l4_dst_port,
                                   l4_src_port});
    }
}

#ifdef MPLS_ENABLE
control MplsHash(in switch_header_t hdr, in switch_lookup_fields_t lkp, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) mpls_hash;
    apply {
        hash [31:0] = mpls_hash.get({hdr.mpls[0].label,
                                     hdr.mpls[1].label,
                                     hdr.mpls[2].label});
    }
}
#endif /* MPLS_ENABLE */

/******************************************************************************
// V4ConsistentHash generic control block
// This block compares v4 sip/dip & calculates low/high v4 IP
// Using the low/high v4-IP, it then calculates/returns V4 consistent hash
******************************************************************************/
control V4ConsistentHash(in bit<32> sip, in bit<32> dip,
                         in bit<16> low_l4_port, in bit<16> high_l4_port,
                         in bit<8> protocol,
                         inout switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv4_inner_hash;
    bit<32> high_ip;
    bit<32> low_ip;

    action step_v4() {
        high_ip = max(sip, dip);
        low_ip = min(sip, dip);
    }

    action v4_calc_hash() {
        hash[31:0] = ipv4_inner_hash.get({low_ip, high_ip,
                                          protocol,
                                          low_l4_port, high_l4_port});
    }

    apply {
        step_v4();
        v4_calc_hash();
    }
}

/**********************************************************************************************
// V6ConsistentHash64bIpSeq generic control block - This compares only higher 64 bits
// of V6 sip & dip, returns 2-bit v6 ip sequence tracker i.e. SWITCH_CONS_HASH_IP_SEQ_<value>
// v6 ip seq for crc hash calc tracker - cons_hash_v6_ip_seq will have below values:
//   i.e. none - SWITCH_CONS_HASH_IP_SEQ_NONE
//   i.e. low-ip is sip, high-ip is dip - SWITCH_CONS_HASH_IP_SEQ_SIPDIP
//   i.e. low-ip is dip, high-ip is sip - SWITCH_CONS_HASH_IP_SEQ_DIPSIP
//
// Below are the steps in this block
//   step 0 - Assume hash seq is SWITCH_CONS_HASH_IP_SEQ_SIPDIP - set the tracker value
//   step 1:
//      compare 32 bits starting from left to right of both src-ip, dst-ip
//      If 32 bit value of src-ip, dst-ip at the respective bit is not equal, apply step 2
//
//   step 2: working on the 32 bit value of both IP at respective position
//      Get high/max 32 bit value between src-ip, dst-ip
//      If high 32 bit value is same as src-ip 32 bit value at respective position
//        --> set value to SWITCH_CONS_HASH_IP_SEQ_DIPSIP
**********************************************************************************************/
control V6ConsistentHash64bIpSeq(in bit<64> sip, in bit<64> dip, inout switch_cons_hash_ip_seq_t ip_seq) {
    bit<32> high_63_32_ip;
    bit<32> src_63_32_ip;
    bit<32> high_31_0_ip;
    bit<32> src_31_0_ip;

    action step_63_32_v6() {
        high_63_32_ip = max(sip[63:32], dip[63:32]);
        src_63_32_ip = sip[63:32];
    }

    action step_31_0_v6() {
        high_31_0_ip = max(sip[31:0], dip[31:0]);
        src_31_0_ip = sip[31:0];
    }

    apply {
        // initialize to 1 i.e low-ip is sip, high-ip is dip
        ip_seq = SWITCH_CONS_HASH_IP_SEQ_SIPDIP;

        step_63_32_v6();
        step_31_0_v6();

        if (sip[63:32] != dip[63:32]) {
            if (high_63_32_ip == src_63_32_ip) {
                ip_seq = SWITCH_CONS_HASH_IP_SEQ_DIPSIP;
            }
        }
        else if (sip[31:0] != dip[31:0]) {
            if (high_31_0_ip == src_31_0_ip) {
                ip_seq = SWITCH_CONS_HASH_IP_SEQ_DIPSIP;
            }
        } else {
            // set 0 if we still have to compare further
            // or if sip & dip are equal
            ip_seq = SWITCH_CONS_HASH_IP_SEQ_NONE;
        }
    }
}

/***************************************************************************************
// V6ConsistentHash generic control block - call this after V6ConsistentHash64bIpSeq()
// Logic can be continuation from the earlier control block V6ConsistentHash64bIpSeq
// This block uses the 2 bit ip sequece tracker from V6ConsistentHash64bIpSeq &
// continues to compare lower 64 bits of v6 sip/dip [if req] to calculate low/high v6 IP
// Using the low/high v6 IP, it then calculates/returns the consistet hash
****************************************************************************************/
control V6ConsistentHash(in bit<128> sip, in bit<128> dip,
                         in switch_cons_hash_ip_seq_t ip_seq,
                         in bit<16> low_l4_port, in bit<16> high_l4_port,
                         in bit<8> protocol,
                         inout switch_hash_t hash) {
    bit<32> high_31_0_ip;
    bit<32> low_31_0_ip;
    bit<32> src_31_0_ip;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_inner_hash_1;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_inner_hash_2;
    bit<32> high_63_32_ip;
    bit<32> src_63_32_ip;

    action step_63_32_v6() {
        high_63_32_ip = max(sip[63:32], dip[63:32]);
        src_63_32_ip = sip[63:32];
    }

    action step_31_0_v6() {
        high_31_0_ip = max(sip[31:0], dip[31:0]);
        src_31_0_ip = sip[31:0];
    }

    // low ip - sip, high ip - dip i.e. SWITCH_CONS_HASH_IP_SEQ_SIPDIP
    action v6_calc_hash_sip_dip() {
        hash[31:0] = ipv6_inner_hash_1.get({sip, dip,
                                            protocol,
                                            low_l4_port, high_l4_port});
    }

    // low ip - dip, high ip - sip i.e. SWITCH_CONS_HASH_IP_SEQ_DIPSIP
    action v6_calc_hash_dip_sip() {
        hash[31:0] = ipv6_inner_hash_2.get({dip, sip,
                                            protocol,
                                            low_l4_port, high_l4_port});
    }

    apply {
        // steps to calculate low/high v6-ip i.e. step 1, step 2
        // Step 1 - Act on the tracker value from the earlier control block
        // if set, based on the comparison of higher 64 bits of sip, dip
        if (ip_seq == SWITCH_CONS_HASH_IP_SEQ_SIPDIP) {
            v6_calc_hash_sip_dip();
        } else if (ip_seq == SWITCH_CONS_HASH_IP_SEQ_DIPSIP) {
            v6_calc_hash_dip_sip();
        // step 2 - else continue comparing the lower 64 bits
        } else {
            step_63_32_v6();
            step_31_0_v6();

            if (sip[63:32] != dip[63:32]) {
                if (high_63_32_ip == src_63_32_ip) {
                    v6_calc_hash_dip_sip();
                } else {
                    v6_calc_hash_sip_dip();
                }
            } else if (high_31_0_ip == src_31_0_ip) {
                v6_calc_hash_dip_sip();
            } else {
                v6_calc_hash_sip_dip();
            }
        }
    }
}

/**********************************************************************************************
// Msft vxlan/nvgre/nvgre-st consistent hashing for tunnel
// If inner ip packet exists, always calculate inner ip hash

// Solution 1 - crc32 consistent hash [low-ip, high-ip, protocol, l4_src_port, l4_tgt_port]
// comparing & calculating low/high v4-ip, low/high l4-port involves not many steps
// But steps to compare/calculate low/high v6-ip [128 bits] involves multi-stage
//
// Stage 1 - Below are the steps for this stage
//
//  1) StartConsistentInnerHash() calls V6ConsistentHash64bIpSeq() if inner pkt is V6
//     ---> V6ConsistentHash64bIpSeq block compares only higher 64 bits of V6 sip & dip,
//           & returns 2-bit v6 ip sequence tracker i.e. SWITCH_CONS_HASH_IP_SEQ_<value>
//
//  2) Then ConsistentInnerHash() compares lower 64 bits for V6 if req & calculates hash
//     ---> For V6 hash, will invoke V6ConsistentHash block. This block uses the 2 bit ip
//          sequece tracker & also compares lower 64 bits if req
//     ---> For V4 hash, will invoke V4ConsistentHash block
//     ---> For nvgre-st, currently using only the lower 32 bit IP to calc hash
//          Running into fitting issues by using V4ConsistentHash block, so
//          calculating the hash directly within this block for now
//
// Multi-stage because  the entire logic wasnt fitting in one single control block
*********************************************************************************************/
control StartConsistentInnerHash(in switch_header_t hd, inout switch_local_metadata_t ig_m) {
    V6ConsistentHash64bIpSeq() compute_v6_cons_hash_64bit_ipseq;
    apply {
        // For nvgre-st, using only lower 32 bits for hash calculation for now
        if (hd.inner_ipv6.isValid() && ig_m.tunnel.type != SWITCH_INGRESS_TUNNEL_TYPE_NVGRE_ST) {
            compute_v6_cons_hash_64bit_ipseq.apply(hd.inner_ipv6.src_addr[127:64],
                                                   hd.inner_ipv6.dst_addr[127:64],
                                                   ig_m.cons_hash_v6_ip_seq);
        }
    }
}

/******************************************************************************************
// Stage 2 - This Logic continuation from the above control block StartConsistentInnerHash
// Below are the steps for this stage
//   1) continues to compare the lower 64 bits of the V6 to figure out low/high v6-ip
//   2) has logic to get low/high l4-port
//   3) has logic to get low/high v4-ip
//   4) calculates consistent crc hash for both inner v6/v4 packet

// Multi-stage because  the entire logic wasnt fitting in one single control block
******************************************************************************************/
control ConsistentInnerHash(in switch_header_t hd, inout switch_local_metadata_t ig_m) {
    bit<32> high_31_0_ip;
    bit<32> low_31_0_ip;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_inner_hash;

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) l4_tcp_src_p_hash;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) l4_udp_src_p_hash;
    bit<16> l4_src_port;    // Because src_port uses 2 8-bit containers
    bit<16> low_l4_port = 0;
    bit<16> high_l4_port = 0;

    // cant perform max/min operations since src_port uses 2 8-bit containers
    // so moving the src_port value to single 16 bit container
    action step_tcp_src_port() {
        l4_src_port = l4_tcp_src_p_hash.get({16w0 +++ hd.inner_tcp.src_port});
    }

    // cant perform max/min operations since src_port uses 2 8-bit containers
    // so moving the src_port value to single 16 bit container
    action step_udp_src_port() {
        l4_src_port = l4_udp_src_p_hash.get({16w0 +++ hd.inner_udp.src_port});
    }

    action step_tcp_l4_port() {
        high_l4_port = (bit<16>)max(l4_src_port, hd.inner_tcp.dst_port);
        low_l4_port = (bit<16>)min(l4_src_port, hd.inner_tcp.dst_port);
    }

    action step_udp_l4_port() {
        high_l4_port = (bit<16>)max(l4_src_port, hd.inner_udp.dst_port);
        low_l4_port = (bit<16>)min(l4_src_port, hd.inner_udp.dst_port);
    }

    action step_31_0_v6() {
        high_31_0_ip = max(hd.inner_ipv6.src_addr[31:0], hd.inner_ipv6.dst_addr[31:0]);
        low_31_0_ip = min(hd.inner_ipv6.src_addr[31:0], hd.inner_ipv6.dst_addr[31:0]);
    }

    action v6_calc_31_0_hash() {
        ig_m.hash[31:0] = ipv6_inner_hash.get({low_31_0_ip, high_31_0_ip,
                                              hd.inner_ipv6.next_hdr,
                                              low_l4_port, high_l4_port});
    }

    V6ConsistentHash() compute_v6_cons_hash;
    V4ConsistentHash() compute_v4_cons_hash;
    apply {
        // steps to calculate low/high l4-port
        if (hd.inner_udp.isValid()) {
            step_udp_src_port();
            step_udp_l4_port();
        } else if (hd.inner_tcp.isValid()) {
            step_tcp_src_port();
            step_tcp_l4_port();
        }

        if (hd.inner_ipv6.isValid()) {

            if (ig_m.tunnel.type != SWITCH_INGRESS_TUNNEL_TYPE_NVGRE_ST) {
                compute_v6_cons_hash.apply(hd.inner_ipv6.src_addr,
                                           hd.inner_ipv6.dst_addr,
                                           ig_m.cons_hash_v6_ip_seq,
                                           low_l4_port, high_l4_port,
                                           hd.inner_ipv6.next_hdr,
                                           ig_m.hash);
            } else {
                // Running into fitting issues by using V4ConsistentHash for this

                // For nvgre-st
                // currently using only lower 32 bits of v6 for hash calculation
                step_31_0_v6();
                v6_calc_31_0_hash();
            }
        } else if (hd.inner_ipv4.isValid()) {
            compute_v4_cons_hash.apply(hd.inner_ipv4.src_addr,
                                       hd.inner_ipv4.dst_addr,
                                       low_l4_port, high_l4_port,
                                       hd.inner_ipv4.protocol,
                                       ig_m.hash);
        }
    }
}

//***************************************************************************
//
// Vxlan packet hash calculated with inner L3 headers + Vxlan Source Port
//
//***************************************************************************

control InnerDtelv4Hash(in switch_header_t hdr,
                        in switch_local_metadata_t local_md, out switch_hash_t hash) {
    @name(".inner_dtelv4_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) inner_dtelv4_hash;
    bit<32> ip_src_addr = hdr.inner_ipv4.src_addr;
    bit<32> ip_dst_addr = hdr.inner_ipv4.dst_addr;
    bit<8> ip_proto = hdr.inner_ipv4.protocol;
    bit<16> l4_src_port = hdr.udp.src_port; // Entropy field from vxlan header
//    bit<16> l4_dst_port = hdr.inner_tcp.dst_port;
//    bit<16> l4_src_port = hdr.inner_tcp.src_port;

    apply {
        hash [31:0] = inner_dtelv4_hash.get({
                                     ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
//                                     l4_dst_port,
                                     l4_src_port});
    }
}

control InnerDtelv6Hash(in switch_header_t hdr,
                        in switch_local_metadata_t local_md, out switch_hash_t hash) {
    @name(".inner_dtelv6_hash")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) inner_dtelv6_hash;
    bit<128> ip_src_addr = hdr.ipv6.src_addr;
    bit<128> ip_dst_addr = hdr.ipv6.dst_addr;
    bit<8> ip_proto = hdr.ipv6.next_hdr;
    bit<16> l4_src_port = hdr.udp.src_port; // Entropy field from vxlan header
//    bit<16> l4_dst_port = hdr.inner_tcp.dst_port;
//    bit<16> l4_src_port = hdr.inner_tcp.src_port;
    bit<20> ipv6_flow_label = hdr.inner_ipv6.flow_label;

    apply {
        hash [31:0] = inner_dtelv6_hash.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                     ipv6_flow_label,
#endif
                                     ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
//                                     l4_dst_port,
                                     l4_src_port});
    }
}
/******************************************************************************
// RotateHash
// Rotate hash after caclulation
******************************************************************************/

control RotateHash(inout switch_local_metadata_t local_md) {

    @name(".rotate_by_0")
    action rotate_by_0() {
    }

    #define ROTATE_WITH_ANNOTATION(n, nm) \
    @name(#nm) \
    action rotate_by_##n() { \
        local_md.hash[15:0] = local_md.hash[##n-1:0] ++ local_md.hash[15:##n]; \
    } \

    #define ROTATE_BY_N(n) ROTATE_WITH_ANNOTATION(n, .rotate_by_##n)

    ROTATE_BY_N(1)
    ROTATE_BY_N(2)
    ROTATE_BY_N(3)
    ROTATE_BY_N(4)
    ROTATE_BY_N(5)
    ROTATE_BY_N(6)
    ROTATE_BY_N(7)
    ROTATE_BY_N(8)
    ROTATE_BY_N(9)
    ROTATE_BY_N(10)
    ROTATE_BY_N(11)
    ROTATE_BY_N(12)
    ROTATE_BY_N(13)
    ROTATE_BY_N(14)
    ROTATE_BY_N(15)

    @name(".rotate_hash")
    table rotate_hash {
        actions = {
            rotate_by_0;
            rotate_by_1;
            rotate_by_2;
            rotate_by_3;
            rotate_by_4;
            rotate_by_5;
            rotate_by_6;
            rotate_by_7;
            rotate_by_8;
            rotate_by_9;
            rotate_by_10;
            rotate_by_11;
            rotate_by_12;
            rotate_by_13;
            rotate_by_14;
            rotate_by_15;
        }
        size = 16;
        default_action = rotate_by_0;
    }

    apply {
        rotate_hash.apply();
    }
}
