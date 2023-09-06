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


#ifndef _P4_NAT_
#define _P4_NAT_

#define INGRESS_SRC_NAT_KEY                \
    local_md.lkp.ip_src_addr[95:64] : exact;     \

#define INGRESS_SRC_NAPT_KEY                \
    local_md.lkp.ip_src_addr[95:64] : exact;     \
    local_md.lkp.ip_proto : exact;              \
    local_md.lkp.l4_src_port : exact;           \

#define INGRESS_DEST_NAT_KEY                \
    local_md.lkp.ip_dst_addr[95:64] : exact;     \

#define INGRESS_DEST_NAPT_KEY                \
    local_md.lkp.ip_dst_addr[95:64] : exact;     \
    local_md.lkp.ip_proto : exact;              \
    local_md.lkp.l4_dst_port : exact;           \

#define INGRESS_FLOW_NAPT_KEY                \
    local_md.lkp.ip_src_addr[95:64] : exact;     \
    local_md.lkp.ip_dst_addr[95:64] : exact;     \
    local_md.lkp.ip_proto : exact;              \
    local_md.lkp.l4_dst_port : exact;           \
    local_md.lkp.l4_src_port : exact;           \

#define INGRESS_FLOW_NAT_KEY                 \
    local_md.lkp.ip_src_addr[95:64] : exact;     \
    local_md.lkp.ip_dst_addr[95:64] : exact;     \

control IngressDestNatPool(inout switch_local_metadata_t local_md)() {
  DirectCounter<bit<32>>(CounterType_t.PACKETS) dnat_pool_stats;
  @name(".set_dnat_pool_hit")
  action set_dnat_pool_hit() {
    local_md.nat.dnat_pool_hit = true;
    dnat_pool_stats.count();
  }

  @name(".set_dnat_pool_miss")
  action set_dnat_pool_miss() {
    local_md.nat.dnat_pool_hit = false;
    dnat_pool_stats.count();
  }

  @name(".dnat_pool")
  table dnat_pool {
    key = {
      INGRESS_DEST_NAT_KEY
    }
    actions = {
      set_dnat_pool_hit;
      set_dnat_pool_miss;
    }
    counters = dnat_pool_stats;
    const default_action = set_dnat_pool_miss;
    size = DNAT_POOL_TABLE_SIZE;
  }

  apply {
    dnat_pool.apply();
  }
}

control IngressDnaptIndex(inout switch_local_metadata_t local_md)(switch_uint32_t dnapt_table_size) {
  @name(".set_dnapt_index")
  action set_dnapt_index(bit<16> index) {
    local_md.nat.dnapt_index = index;
  }
  @name(".dest_napt_index")
  table dest_napt {
    key = {
      INGRESS_DEST_NAPT_KEY
    }
    actions = {
      set_dnapt_index;
      NoAction;
    }
    const default_action = NoAction;
    size = dnapt_table_size;
    idle_timeout = true;
  }
  apply {
    dest_napt.apply();
  }
}

control IngressSnaptIndex(inout switch_local_metadata_t local_md)(switch_uint32_t snapt_table_size) {
  @name(".set_snapt_index")
  action set_snapt_index(bit<16> index) {
    local_md.nat.snapt_index = index;
  }
  
  @name(".src_napt_index")
  @pack(2)
  table src_napt {
    key = {
      INGRESS_SRC_NAPT_KEY
    }
    actions = {
      set_snapt_index;
      NoAction;
    }
    const default_action = NoAction;
    size = snapt_table_size;
    idle_timeout = true;
  }
  apply {
    src_napt.apply();
  }
}

control IngressNat(inout switch_local_metadata_t local_md)() {

  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) flow_napt_stats;
  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) flow_nat_stats;
  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) dest_napt_stats;
  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) dest_nat_stats;

  @name(".flow_napt_miss")
  action flow_napt_miss() {
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_FLOW_NONE;
    flow_napt_stats.count();
  }
  @name(".dnapt_miss")
  action dnapt_miss() {
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_DEST_NONE;
    dest_napt_stats.count();
  }

  @name(".flow_nat_miss")
  action flow_nat_miss() {
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_FLOW_NONE;
    flow_nat_stats.count();
  }
  @name(".dnat_miss")
  action dnat_miss() {
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_DEST_NONE;
    dest_nat_stats.count();
  }

  @name(".set_flow_nat_rewrite")
  action set_flow_nat_rewrite(ipv4_addr_t sip, ipv4_addr_t dip) {
    local_md.lkp.ip_src_addr[95:64] = sip;
    local_md.lkp.ip_dst_addr[95:64] = dip;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_FLOW_NAT;
    flow_nat_stats.count();
  }

  @name(".set_flow_napt_rewrite")
  action set_flow_napt_rewrite(ipv4_addr_t sip, ipv4_addr_t dip, bit<16> sport, bit<16> dport) {
    local_md.lkp.ip_src_addr[95:64] = sip;
    local_md.lkp.ip_dst_addr[95:64] = dip;
    local_md.lkp.l4_src_port = sport;
    local_md.lkp.l4_dst_port = dport;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_FLOW_NAPT;
    flow_napt_stats.count();
  }
  @name(".set_dnapt_rewrite")
  action set_dnapt_rewrite(ipv4_addr_t dip, bit<16> dport) {
    local_md.lkp.ip_dst_addr[95:64] = dip;
    local_md.lkp.l4_dst_port = dport;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_DEST_NAPT;
    dest_napt_stats.count();
  }

  @name(".set_dnat_rewrite")
  action set_dnat_rewrite(ipv4_addr_t dip) {
    local_md.lkp.ip_dst_addr[95:64] = dip;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_DEST_NAT;
    dest_nat_stats.count();
  }

  @name(".dest_napt")
  table dest_napt {
    key = {
#if __TARGET_TOFINO__ == 1
      local_md.nat.dnapt_index : exact;
#else
      INGRESS_DEST_NAPT_KEY
#endif
    }
    actions = {
      set_dnapt_rewrite;
      dnapt_miss;
    }
    const default_action = dnapt_miss;
    size = DNAPT_TABLE_SIZE;
    counters = dest_napt_stats;
#if __TARGET_TOFINO__ != 1
    idle_timeout = true;
#endif
  }
#ifndef NAT_MAX_SCALE_ENABLE
  @name(".dest_nat")
  table dest_nat {
    key = {
      INGRESS_DEST_NAT_KEY
    }
    actions = {
      set_dnat_rewrite;
      dnat_miss;
    }
    const default_action = dnat_miss;
    size = DNAT_TABLE_SIZE;
    counters = dest_nat_stats;
    idle_timeout = true;
  }

  @name(".flow_napt")
  table flow_napt {
    key = {
      INGRESS_FLOW_NAPT_KEY
    }
    actions = {
      set_flow_napt_rewrite;
      flow_napt_miss;
    }
    const default_action = flow_napt_miss;
    size = FLOW_NAPT_TABLE_SIZE;
    counters = flow_napt_stats;
    idle_timeout = true;
  }
  @name(".flow_nat")
  table flow_nat {
    key = {
      INGRESS_FLOW_NAT_KEY
    }
    actions = {
      set_flow_nat_rewrite;
      flow_nat_miss;
    }
    const default_action = flow_nat_miss;
    size = FLOW_NAT_TABLE_SIZE;
    counters = flow_nat_stats;
    idle_timeout = true;
  }
#endif
  apply {
    if(local_md.nat.nat_disable == false) {
#ifdef NAT_MAX_SCALE_ENABLE
  if(local_md.nat.dnat_pool_hit == true && local_md.nat.ingress_zone == SWITCH_NAT_OUTSIDE_ZONE_ID) {
    dest_napt.apply();
  }
#else
#ifdef FLOW_NAT_ENABLE
      switch(flow_napt.apply().action_run) {
        set_flow_napt_rewrite: {}
        flow_napt_miss : {flow_nat.apply();}
      }
      if(local_md.nat.hit == SWITCH_NAT_HIT_TYPE_FLOW_NONE && local_md.nat.dnat_pool_hit == true && local_md.nat.ingress_zone == SWITCH_NAT_OUTSIDE_ZONE_ID) {
#else
      if(local_md.nat.dnat_pool_hit == true && local_md.nat.ingress_zone == SWITCH_NAT_OUTSIDE_ZONE_ID) {
        switch(dest_napt.apply().action_run) {
          set_dnapt_rewrite : {}
          dnapt_miss: {dest_nat.apply();}
        }
      }
#endif //FLOW_NAT_ENABLE
#endif
    }
  }
}

control SourceNat(inout switch_local_metadata_t local_md)() {
  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) src_napt_stats;
  DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) src_nat_stats;

  @name(".set_snapt_rewrite")
  action set_snapt_rewrite(ipv4_addr_t sip, bit<16> sport) {
    local_md.lkp.ip_src_addr[95:64] = sip;
    local_md.lkp.l4_src_port = sport;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_SRC_NAPT;
    src_napt_stats.count();
  }
  @name(".set_snat_rewrite")
  action set_snat_rewrite(ipv4_addr_t sip) {
    local_md.lkp.ip_src_addr[95:64] = sip;
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_SRC_NAT;
    src_nat_stats.count();
  }

  @name(".source_napt_miss")
  action source_napt_miss() {
    src_napt_stats.count();
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_SRC_NONE;
  }
  @name(".source_nat_miss")
  action source_nat_miss() {
    local_md.nat.hit = SWITCH_NAT_HIT_TYPE_SRC_NONE;
    src_nat_stats.count();
  }
#ifndef NAT_MAX_SCALE_ENABLE
#if __TARGET_TOFINO__ == 1
  @placement_priority(-1)
#endif
  @name(".source_nat")
  table source_nat {
    key = {
      INGRESS_SRC_NAT_KEY
    }
    actions = {
      set_snat_rewrite;
      source_nat_miss;
    }
    const default_action = source_nat_miss;
    size = SNAT_TABLE_SIZE;
    counters = src_nat_stats;
    idle_timeout = true;
  }
#endif

  @name(".source_napt")
  table source_napt {
    key = {
#if __TARGET_TOFINO__ == 1
      local_md.nat.snapt_index : exact;
#else
      INGRESS_SRC_NAPT_KEY
#endif
    }
    actions = {
      set_snapt_rewrite;
      source_napt_miss;
    }
    const default_action = source_napt_miss;
    size = SNAPT_TABLE_SIZE;
    counters = src_napt_stats;
#if __TARGET_TOFINO__ != 1
    idle_timeout = true;
#endif
  }

  apply {
#ifdef NAT_MAX_SCALE_ENABLE
  if(local_md.nat.ingress_zone == SWITCH_NAT_INSIDE_ZONE_ID && local_md.nat.nat_disable == false) {
    source_napt.apply();
  }
#else
#ifdef FLOW_NAT_ENABLE
    if((local_md.nat.ingress_zone == SWITCH_NAT_INSIDE_ZONE_ID && local_md.nat.hit == SWITCH_NAT_HIT_TYPE_FLOW_NONE) || (local_md.nat.ingress_zone == SWITCH_NAT_INSIDE_ZONE_ID && local_md.nat.hit == SWITCH_NAT_HIT_TYPE_DEST_NONE)) {
#else
  if(local_md.nat.ingress_zone == SWITCH_NAT_INSIDE_ZONE_ID && local_md.nat.nat_disable == false) {
#endif
      switch(source_napt.apply().action_run) {
        set_snapt_rewrite: {}
        source_napt_miss: {source_nat.apply();}
      }
    }
#endif
  }

}

control IngressNatRewrite(inout switch_header_t hdr, inout switch_local_metadata_t local_md)() {
  @name(".rewrite_tcp_flow")
  action rewrite_tcp_flow() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
    hdr.tcp.src_port = local_md.lkp.l4_src_port;
    hdr.tcp.dst_port = local_md.lkp.l4_dst_port;
  }
  @name(".rewrite_udp_flow")
  action rewrite_udp_flow() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
    hdr.udp.src_port = local_md.lkp.l4_src_port;
    hdr.udp.dst_port = local_md.lkp.l4_dst_port;
  }
  @name(".rewrite_ipsa_ipda")
  action rewrite_ipsa_ipda() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
  }
  @name(".rewrite_tcp_ipda")
  action rewrite_tcp_ipda() {
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
    hdr.tcp.dst_port = local_md.lkp.l4_dst_port;
  }
  @name(".rewrite_udp_ipda")
  action rewrite_udp_ipda() {
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
    hdr.udp.dst_port = local_md.lkp.l4_dst_port;
  }
  @name(".rewrite_ipda")
  action rewrite_ipda() {
    hdr.ipv4.dst_addr = local_md.lkp.ip_dst_addr[95:64];
  }
  @name(".rewrite_ipsa")
  action rewrite_ipsa() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
  }
  @name(".rewrite_tcp_ipsa")
  action rewrite_tcp_ipsa() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
    hdr.tcp.src_port = local_md.lkp.l4_src_port;
  }
  @name(".rewrite_udp_ipsa")
  action rewrite_udp_ipsa() {
    hdr.ipv4.src_addr = local_md.lkp.ip_src_addr[95:64];
    hdr.udp.src_port = local_md.lkp.l4_src_port;
  }
  @name(".ingress_nat_rewrite")
  table ingress_nat_rewrite {
    key = {
      local_md.nat.hit : exact;
      local_md.lkp.ip_proto : exact;
      local_md.checks.same_zone_check : ternary;
    }
    actions = {
      rewrite_tcp_flow;
      rewrite_udp_flow;
      rewrite_ipsa_ipda;
      rewrite_tcp_ipda;
      rewrite_udp_ipda;
      rewrite_ipda;
      rewrite_tcp_ipsa;
      rewrite_udp_ipsa;
      rewrite_ipsa;
    }
    size = INGRESS_NAT_REWRITE_TABLE_SIZE;
  }
  apply {
    ingress_nat_rewrite.apply();
  }
}


#endif /* _P4_NAT_ */
