/*
* This control implements an incremental IPv4 header checksum update when the
* TTL and DIFFSERV fields are updated.  The new values for TTL and DIFFSERV are
* inputs to this control and the header has the original values of the fields.
* This requires 10 stages and two 32 bit containers.
* Note that the double carry handling can be replaced with a single stage TCAM
* table lookup to reduce the number of stages required.  See the
* IPv4_Checksum_Compute control for an example. */
control IPv4_Checksum_Update_DIFFSERV_TTL(inout switch_header_t hdr,
in bit<8> new_diffserv,
in bit<8> new_ttl) {
    #if __TARGET_TOFINO__ == 1
    apply {
        hdr.ipv4.diffserv = new_diffserv;
        hdr.ipv4.ttl = new_ttl;
    }
    #else
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) identity_hash16;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_a;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_b;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_c;
    bit<32> cksm;
    bit<32> o_fields;
    bit<32> n_fields;
    bit<32> carry;

    /* Step 1: Prepare two temporary 32 bit variables for removing the original
    *         TOS byte and TTL from the checksum. */
    action step_1a() {
        cksm = identity_hash32_a.get({16w0 ++ hdr.ipv4.hdr_checksum});
    }
    action step_1b() {
        cksm = cksm ^ 0xFFFF;
    }
    action step_1c() {
        o_fields = identity_hash32_b.get({16w0 ++ hdr.ipv4.ttl ++ hdr.ipv4.diffserv});
    }
    /* Step 2: Remove the original TOS byte and TTL from the checksum and prepare
    *         a temporary variable to add the new values of these fields to the
    *         checksum. */
    action step_2() {
        cksm = cksm - o_fields;
        n_fields = identity_hash32_c.get({16w0 ++ new_ttl ++ new_diffserv});
    }
    /* Step 3: Add the new fields into the checksum. */
    action step_3() {
        cksm = cksm + n_fields;
    }
    /* Step 4: Move the upper 16 bits into a temporary so they can be added back
    *         into the checksum. */
    action step_4() {
        carry = cksm >> 16;
        cksm = cksm & 0xFFFF;
    }
    /* Step 5: Add the carry back into the checksum. */
    action step_5() {
        cksm = cksm + carry;
    }
    /* Step 6 and 7: Repeat steps 4 and 5 since step 5 may have generated another
    *               carry. */
    action step_6() {
        carry = cksm >> 16;
        cksm = cksm & 0xFFFF;
    }
    action step_7() {
        cksm = cksm + carry;
    }
    /* Step 8: Invert the checksum before writing it back to the IPv4 header. */
    action step_8() {
        cksm = ~cksm;
    }
    /* Step 9: Write the new header back into the packet. */
    action step_9() {
        hdr.ipv4.hdr_checksum = identity_hash16.get({cksm[15:0]});
        hdr.ipv4.diffserv = new_diffserv;
        hdr.ipv4.ttl  = new_ttl;
    }

    apply {
        step_1a();
        step_1b();
        step_1c();
        step_2();
        step_3();
        step_4();
        step_5();
        step_6();
        step_7();
        step_8();
        step_9();
    }
    #endif
}

/*
* This control implements a full recalculation of the IPv4 header checksum.
* The IPv4 header should contain final values for all fields (except the
* checksum) before calling this control.
* This requires 8 stages, a TCAM table, 9 32 bit containers. */
control IPv4_Checksum_Compute(inout switch_header_t hdr) {
#if __TARGET_TOFINO__ == 2 || __TARGET_TOFINO__ == 3
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) identity_hash16;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_a;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_b;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_c;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_d;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_e;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_f;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_g;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_h;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash32_i;
    bit<32> a;
    bit<32> b;
    bit<32> c;
    bit<32> d;
    bit<32> e;
    bit<32> f;
    bit<32> g;
    bit<32> h;
    bit<32> i;

    /* Step 1: Move fields from IPv4 header into 32 bit variables. */
    action step_1a() {
        a = identity_hash32_a.get({16w0 ++ hdr.ipv4.version ++ hdr.ipv4.ihl ++ hdr.ipv4.diffserv});
    }
    action step_1b() {
        b = identity_hash32_b.get({16w0 ++ hdr.ipv4.total_len});
    }
    action step_1c() {
        c = identity_hash32_c.get({16w0 ++ hdr.ipv4.identification});
    }
    action step_1d() {
        d = identity_hash32_d.get({16w0 ++ hdr.ipv4.flags ++ hdr.ipv4.frag_offset});
    }
    action step_1e() {
        e = identity_hash32_e.get({16w0 ++ hdr.ipv4.ttl ++ hdr.ipv4.protocol});
    }
    action step_1f() {
        f = identity_hash32_f.get({16w0 ++ hdr.ipv4.src_addr[31:16]});
    }
    action step_1g() {
        g = identity_hash32_g.get({16w0 ++ hdr.ipv4.src_addr[15: 0]});
    }
    action step_1h() {
        h = identity_hash32_h.get({16w0 ++ hdr.ipv4.dst_addr[31:16]});
    }
    action step_1i() {
        i = identity_hash32_i.get({16w0 ++ hdr.ipv4.dst_addr[15: 0]});
    }
    /* Step 2: Add the fields together to a single 32 bit value. */
    action step_2a() {
        a = a + b;
        c = c + d;
        e = e + f;
        g = g + h;
    }
    action step_2b() {
        a = a + c;
        e = e + g;
    }
    action step_2c() {
        a = a + e;
    }
    action step_2d() {
        a = a + i;
    }
    /* Step 3: Use a ternary table to handle the carry over in a single stage
    *         rather than two stages. */
    action update_carry(bit<32> carry_val) {
        a = a + carry_val;
    }
    table step_3 {
        key = { a[19:0] : ternary; }
        actions = { update_carry; }
        const default_action = update_carry(0);
        const entries = {
            #include "carry_entries.p4"
        }
    }
    /* Step 4: Invert the checksum before writing it back to the IPv4 header. */
    action a_step_4() {
        a = ~a;
    }
    table step_4 {
        actions = { a_step_4; }
        default_action = a_step_4();
    }
    /* Step 5: Update the IPv4 header. */
    action a_step_5() {
        hdr.ipv4.hdr_checksum = identity_hash16.get({a[15:0]});
    }
    table step_5 {
        actions = { a_step_5; }
        default_action = a_step_5();
    }


    apply {
        step_1a();
        step_1b();
        step_1c();
        step_1d();
        step_1e();
        step_1f();
        step_1g();
        step_1h();
        step_1i();
        step_2a();
        step_2b();
        step_2c();
        step_2d();
        step_3.apply();
        step_4.apply();
        if (hdr.ipv4.isValid()) {
            step_5.apply();
        }
    }
#endif
}
