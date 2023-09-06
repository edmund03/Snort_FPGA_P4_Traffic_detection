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

//***************************************************************************
// Inner packet hash using hash specific metadata fields extracted in parser
//***************************************************************************

// Flow hash calculation.
control InnerIpv4Hash(in switch_local_metadata_t local_md, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv4_hash;
    bit<32> ip_src_addr = local_md.hash_fields.ip_src_addr[95:64];
    bit<32> ip_dst_addr = local_md.hash_fields.ip_dst_addr[95:64];
    bit<8> ip_proto = local_md.hash_fields.ip_proto;
    bit<16> l4_dst_port = local_md.hash_fields.l4_dst_port;
    bit<16> l4_src_port = local_md.hash_fields.l4_src_port;

    action hash_get() {
        hash [31:0] = ipv4_hash.get({ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
                                     l4_dst_port,
                                     l4_src_port});
    }

    @placement_priority(-1)
    table dummy {
	actions = { hash_get; }
	default_action = hash_get;
	size = 1;
    }

    apply {
	dummy.apply();
    }
}

control InnerIpv6Hash(in switch_local_metadata_t local_md, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_hash;
    bit<128> ip_src_addr = local_md.hash_fields.ip_src_addr;
    bit<128> ip_dst_addr = local_md.hash_fields.ip_dst_addr;
    bit<8> ip_proto = local_md.hash_fields.ip_proto;
    bit<16> l4_dst_port = local_md.hash_fields.l4_dst_port;
    bit<16> l4_src_port = local_md.hash_fields.l4_src_port;
    bit<20> ipv6_flow_label = local_md.hash_fields.ipv6_flow_label;

    action hash_get() {
        hash [31:0] = ipv6_hash.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                     ipv6_flow_label,
#endif
                                     ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
                                     l4_dst_port,
                                     l4_src_port});
    }

    @placement_priority(-1)
    table dummy {
	actions = { hash_get; }
	default_action = hash_get;
	size = 1;
    }

    apply {
	dummy.apply();
    }
}

control NonIpHash(in switch_header_t hdr, in switch_local_metadata_t local_md, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) non_ip_hash;
    mac_addr_t mac_dst_addr = hdr.ethernet.dst_addr;
    mac_addr_t mac_src_addr = hdr.ethernet.src_addr;
    bit<16> mac_type = hdr.ethernet.ether_type;
    switch_port_t port = local_md.ingress_port;

    action hash_get() {
        hash [31:0] = non_ip_hash.get({port,
                                       mac_type,
                                       mac_src_addr,
                                       mac_dst_addr});
    }

    @placement_priority(-1)
    table dummy {
	actions = { hash_get; }
	default_action = hash_get;
	size = 1;
    }

    apply {
	dummy.apply();
    }
}

control InnerLagv4Hash(in switch_local_metadata_t local_md, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) lag_hash;
    bit<32> ip_src_addr = local_md.hash_fields.ip_src_addr[95:64];
    bit<32> ip_dst_addr = local_md.hash_fields.ip_dst_addr[95:64];
    bit<8> ip_proto = local_md.hash_fields.ip_proto;
    bit<16> l4_dst_port = local_md.hash_fields.l4_dst_port;
    bit<16> l4_src_port = local_md.hash_fields.l4_src_port;

    action hash_get() {
        hash [31:0] = lag_hash.get({ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
                                     l4_dst_port,
                                     l4_src_port});
    }

    @placement_priority(-1)
    table dummy {
	actions = { hash_get; }
	default_action = hash_get;
	size = 1;
    }

    apply {
	dummy.apply();
    }
}

control InnerLagv6Hash(in switch_local_metadata_t local_md, out switch_hash_t hash) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) lag_hash;
    bit<128> ip_src_addr = local_md.hash_fields.ip_src_addr;
    bit<128> ip_dst_addr = local_md.hash_fields.ip_dst_addr;
    bit<8> ip_proto = local_md.hash_fields.ip_proto;
    bit<16> l4_dst_port = local_md.hash_fields.l4_dst_port;
    bit<16> l4_src_port = local_md.hash_fields.l4_src_port;
    bit<20> ipv6_flow_label = local_md.hash_fields.ipv6_flow_label;

    action hash_get() {
        hash [31:0] = lag_hash.get({
#ifdef IPV6_FLOW_LABEL_IN_HASH_ENABLE
                                     ipv6_flow_label,
#endif
                                     ip_src_addr,
                                     ip_dst_addr,
                                     ip_proto,
                                     l4_dst_port,
                                     l4_src_port});
    }

    @placement_priority(-1)
    table dummy {
	actions = { hash_get; }
	default_action = hash_get;
	size = 1;
    }

    apply {
	dummy.apply();
    }
}
