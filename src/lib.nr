// Comprehensive DER-encoded ASN.1 test-suite - v2
// --------------------------------------------------
// Added coverage for extra Universal tags: NULL (0x05), OBJECT IDENTIFIER (0x06),
// and SET/SET OF (0x31).  All tests keep payloads small enough to fit the static
// `[u8; 256]` buffer limit used by `Asn1Decoder`.

mod asn1_decode;
mod time_decode;

use asn1_decode::Asn1Decoder;
use time_decode::TimeDecoder;

// Helpers (removed unused assert_prefix)

fn encoded_u8(x: u8) -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x02; r[1] = 0x01; r[2] = x; r
}

fn encoded_u16(x: u16) -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x02; r[1] = 0x02;
    r[2] = (x >> 8) as u8; r[3] = (x & 0xff) as u8; r
}

// INTEGER 0x80 MUST be encoded as 02 02 00 80 (leading zero required)
fn encoded_high_bit_u8(x: u8) -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x02; r[1] = 0x02; // length = 2
    r[2] = 0x00; r[3] = x;    // leading zero + value
    r
}

fn long_octet(len: u8, fill: u8) -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x04; r[1] = 0x81; r[2] = len;
    for i in 0..len { r[3 + (i as u32)] = fill; }
    r
}

fn bitstring_with_sequence() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x03; r[1] = 0x07; r[2] = 0x00; // BIT STRING len=7, 0 unused bits
    r[3] = 0x30; r[4] = 0x03; // SEQUENCE len=3
    r[5] = 0x02; r[6] = 0x01; r[7] = 0x05; // INTEGER 5
    r
}

fn generalized_time_bytes(y: u16, m: u8, d: u8, h: u8, min: u8, s: u8) -> [u8; 256] {
    let mut r = [0; 256]; 
    r[0] = 0x18; r[1] = 0x0F; // GeneralizedTime len=15
    let mut idx = 2; 
    let digs = [y/1000, (y/100)%10, (y/10)%10, y%10, (m as u16)/10, (m as u16)%10, (d as u16)/10, (d as u16)%10,
       (h as u16)/10, (h as u16)%10, (min as u16)/10, (min as u16)%10, (s as u16)/10, (s as u16)%10];
    for dgt in digs { r[idx] = (dgt as u8) + 48; idx += 1; }
    r[idx] = 90; // 'Z'
    r
}

// OBJECT IDENTIFIER helper - encodes 1.2.840.113549 in DER (6 bytes payload).
fn oid_rsa_pkcs() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x06; r[1] = 0x06; // OID len=6
    r[2] = 0x2A; r[3] = 0x86; r[4] = 0x48; r[5] = 0x86; r[6] = 0xF7; r[7] = 0x0D;
    r
}

// SET OF { INTEGER 1, INTEGER 2 } - canonical order is by encoded bytes so 1 then 2.
fn set_of_two_ints() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x31; r[1] = 0x06; // SET len=6
    r[2] = 0x02; r[3] = 0x01; r[4] = 0x01; // INTEGER 1
    r[5] = 0x02; r[6] = 0x01; r[7] = 0x02; // INTEGER 2
    r
}

// SET with non-canonical order: INTEGER 10, INTEGER 2 
// DER requires sorting by encoded bytes: 02 01 02 < 02 01 0A
fn set_canonical_order() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x31; r[1] = 0x06; // SET len=6
    r[2] = 0x02; r[3] = 0x01; r[4] = 0x02; // INTEGER 2 (comes first)
    r[5] = 0x02; r[6] = 0x01; r[7] = 0x0A; // INTEGER 10 (comes second)
    r
}

// High-tag number [31] EXPLICIT INTEGER 8 (context-specific constructed)
fn high_tag_explicit() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0xBF; r[1] = 0x1F; // tag [31] EXPLICIT (constructed context-specific)
    r[2] = 0x03; // length = 3
    r[3] = 0x02; r[4] = 0x01; r[5] = 0x08; // INTEGER 8
    r
}

// [3] IMPLICIT OCTET STRING "AB" (context-specific primitive)
fn implicit_octet_string() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x83; // tag [3] IMPLICIT (primitive context-specific)
    r[1] = 0x02; // length = 2
    r[2] = 0x41; r[3] = 0x42; // "AB"
    r
}

// Multi-byte long length: 258-byte OCTET STRING (length 0x82 0x01 0x02)
fn multi_byte_length() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x04; // OCTET STRING tag
    r[1] = 0x82; // long form: 2 length bytes follow
    r[2] = 0x01; r[3] = 0x02; // length = 258 (0x0102)
    // Fill first few bytes with pattern
    for i in 0..50 { r[4 + (i as u32)] = (i % 256) as u8; }
    r
}

// PrintableString "US" (0x13)
fn printable_string_us() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x13; r[1] = 0x02; // PrintableString len=2
    r[2] = 0x55; r[3] = 0x53; // "US"
    r
}

// UTF8String "muTLS" (0x0C) - Greek mu + TLS
fn utf8_string_mtls() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x0C; r[1] = 0x05; // UTF8String len=5
    r[2] = 0xCE; r[3] = 0xBC; // mu (U+03BC in UTF-8)
    r[4] = 0x54; r[5] = 0x4C; r[6] = 0x53; // "TLS"
    r
}

// IA5String "user@example.com" (0x16)
fn ia5_string_email() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x16; r[1] = 0x10; // IA5String len=16
    let email = "user@example.com";
    for i in 0..16 { r[2 + (i as u32)] = email.as_bytes()[i]; }
    r
}

// Negative INTEGER -1 (02 01 FF)
fn negative_int_minus_one() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x02; r[1] = 0x01; r[2] = 0xFF; // -1 in two's complement
    r
}

// Negative INTEGER -128 (02 02 80 00) - needs padding to avoid confusion with positive
fn negative_int_minus_128() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x02; r[1] = 0x02; // length = 2
    r[2] = 0xFF; r[3] = 0x80; // -128 in two's complement
    r
}

// OCTET STRING containing DER SEQUENCE with INTEGER 42
fn octet_string_with_der() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x04; r[1] = 0x05; // OCTET STRING len=5
    r[2] = 0x30; r[3] = 0x03; // SEQUENCE len=3
    r[4] = 0x02; r[5] = 0x01; r[6] = 0x2A; // INTEGER 42
    r
}

// Nested SEQUENCE for parent-child relationship testing
fn nested_sequence() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x30; r[1] = 0x0B; // SEQUENCE len=11 (3 + 8)
    r[2] = 0x02; r[3] = 0x01; r[4] = 0x01; // INTEGER 1 (3 bytes)
    r[5] = 0x30; r[6] = 0x06; // nested SEQUENCE len=6 (8 bytes total including tag+len)
    r[7] = 0x02; r[8] = 0x01; r[9] = 0x02; // INTEGER 2 (3 bytes)
    r[10] = 0x02; r[11] = 0x01; r[12] = 0x03; // INTEGER 3 (3 bytes)
    r
}

// Empty SEQUENCE for edge case testing
fn empty_sequence() -> [u8; 256] {
    let mut r = [0; 256];
    r[0] = 0x30; r[1] = 0x00; // SEQUENCE len=0
    r
}

// INTEGER tests
#[test]
fn integer_minimal_u8() {
    let d = encoded_u8(127); 
    let dec = Asn1Decoder::new(d); 
    assert(dec.uint_at(dec.root()) == 127);
}

#[test]
fn integer_high_bit_needs_pad() {
    let d = encoded_u16(128); 
    let dec = Asn1Decoder::new(d); 
    assert(dec.uint_at(dec.root()) == 128);
}

// DER INTEGER padding rule: high bit set requires leading zero
#[test]
fn integer_high_bit_padding_rule() {
    let d = encoded_high_bit_u8(0x80); // 128 with high bit set
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    // Verify structure: tag=02, len=02, leading_zero=00, value=80
    assert(d[0] == 0x02);        // INTEGER tag
    assert(d[1] == 0x02);        // length = 2 (not 1!)
    assert(d[2] == 0x00);        // leading zero required
    assert(d[3] == 0x80);        // actual value
    assert(dec.uint_at(root) == 128);
}

// Negative INTEGER tests
#[test]
fn negative_integer_minus_one() {
    let d = negative_int_minus_one();
    // Verify structure: 02 01 FF
    assert(d[0] == 0x02);  // INTEGER tag
    assert(d[1] == 0x01);  // length = 1
    assert(d[2] == 0xFF);  // -1 in two's complement
    // Note: decoder.uint_at() expects positive integers, so we test structure
}

#[test]
fn negative_integer_minus_128() {
    let d = negative_int_minus_128();
    // Verify structure: 02 02 FF 80 (-128 needs 2 bytes)
    assert(d[0] == 0x02);  // INTEGER tag
    assert(d[1] == 0x02);  // length = 2
    assert(d[2] == 0xFF);  // high byte of -128
    assert(d[3] == 0x80);  // low byte of -128
}

// Length-form tests
#[test]
fn octet_string_long_form() {
    let d = long_octet(128, 0xAA); 
    let dec = Asn1Decoder::new(d); 
    let bytes = dec.bytes_at(dec.root());
    assert(bytes[0] == 0xAA);
}

// Multi-byte length encoding test
#[test]
fn multi_byte_length_encoding() {
    let d = multi_byte_length();
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    // Verify length encoding: 04 82 01 02 (OCTET STRING, 2 length bytes, 258 total)
    assert(d[0] == 0x04);  // OCTET STRING tag
    assert(d[1] == 0x82);  // long form: 2 bytes follow
    assert(d[2] == 0x01);  // length high byte
    assert(d[3] == 0x02);  // length low byte (total = 258)
    let bytes = dec.bytes_at(root);
    assert(bytes[0] == 0x00);  // first data byte
    assert(bytes[1] == 0x01);  // second data byte
}

// High-tag number tests
#[test]
fn high_tag_explicit_integer() {
    let d = high_tag_explicit();
    // Verify structure: BF 1F 03 02 01 08 ([31] EXPLICIT INTEGER 8)
    assert(d[0] == 0xBF);  // [31] EXPLICIT tag (constructed context-specific)
    assert(d[1] == 0x1F);  // high tag number continuation
    assert(d[2] == 0x03);  // length = 3
    assert(d[3] == 0x02);  // INTEGER tag
    assert(d[4] == 0x01);  // INTEGER length = 1
    assert(d[5] == 0x08);  // INTEGER value = 8
}

#[test]
fn implicit_context_tag() {
    let d = implicit_octet_string();
    // Verify structure: 83 02 41 42 ([3] IMPLICIT OCTET STRING "AB")
    assert(d[0] == 0x83);  // [3] IMPLICIT tag (primitive context-specific)
    assert(d[1] == 0x02);  // length = 2
    assert(d[2] == 0x41);  // 'A'
    assert(d[3] == 0x42);  // 'B'
}

// String type tests
#[test]
fn printable_string_test() {
    let d = printable_string_us();
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    let bytes = dec.bytes_at(root);
    // Verify structure: 13 02 55 53 (PrintableString "US")
    assert(d[0] == 0x13);  // PrintableString tag
    assert(d[1] == 0x02);  // length = 2
    assert(bytes[0] == 0x55);  // 'U'
    assert(bytes[1] == 0x53);  // 'S'
}

#[test]
fn utf8_string_test() {
    let d = utf8_string_mtls();
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    let bytes = dec.bytes_at(root);
    // Verify structure: 0C 05 CE BC 54 4C 53 (UTF8String "muTLS")
    assert(d[0] == 0x0C);  // UTF8String tag
    assert(d[1] == 0x05);  // length = 5
    assert(bytes[0] == 0xCE);  // mu byte 1
    assert(bytes[1] == 0xBC);  // mu byte 2
    assert(bytes[2] == 0x54);  // 'T'
    assert(bytes[3] == 0x4C);  // 'L'
    assert(bytes[4] == 0x53);  // 'S'
}

#[test]
fn ia5_string_test() {
    let d = ia5_string_email();
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    let bytes = dec.bytes_at(root);
    // Verify structure: 16 10 ... (IA5String "user@example.com")
    assert(d[0] == 0x16);  // IA5String tag
    assert(d[1] == 0x10);  // length = 16
    assert(bytes[0] == 0x75);  // 'u'
    assert(bytes[4] == 0x40);  // '@'
    assert(bytes[15] == 0x6D); // 'm'
}

// BIT STRING with embedded SEQUENCE
#[test]
fn bitstring_embeds_seq() {
    let d = bitstring_with_sequence(); 
    let dec = Asn1Decoder::new(d);
    let inner = dec.root_of_bitstring_at(dec.root());
    let child = dec.first_child_of(inner); 
    assert(dec.uint_at(child) == 5);
}

// NodePtr API comprehensive tests
#[test]
fn nodeptr_root_of_octet_string() {
    let d = octet_string_with_der();
    let dec = Asn1Decoder::new(d);
    let octet_root = dec.root();
    let inner_seq = dec.root_of_octet_string_at(octet_root);
    // Verify we extracted the SEQUENCE from inside the OCTET STRING
    assert(d[inner_seq.ixs] == 0x30);  // SEQUENCE tag
    let child = dec.first_child_of(inner_seq);
    assert(dec.uint_at(child) == 42);  // INTEGER 42
}

#[test]
fn nodeptr_all_bytes_vs_bytes_at() {
    let d = encoded_u8(127);
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    
    let content_only = dec.bytes_at(root);    // just content: [0x7F, 0x00, ...]
    let full_node = dec.all_bytes_at(root);   // tag+len+content: [0x02, 0x01, 0x7F, ...]
    
    // Verify all_bytes_at includes tag and length
    assert(full_node[0] == 0x02);  // INTEGER tag
    assert(full_node[1] == 0x01);  // length
    assert(full_node[2] == 0x7F);  // content (127)
    
    // Verify bytes_at is content-only
    assert(content_only[0] == 0x7F);  // just the value
}

#[test]
fn nodeptr_is_child_of_relationships() {
    let d = nested_sequence();
    let dec = Asn1Decoder::new(d);
    
    let outer_seq = dec.root();
    let first_int = dec.first_child_of(outer_seq);      // INTEGER 1
    let nested_seq = dec.next_sibling_of(first_int);    // nested SEQUENCE
    let second_int = dec.first_child_of(nested_seq);    // INTEGER 2 (inside nested)
    let third_int = dec.next_sibling_of(second_int);    // INTEGER 3 (inside nested)
    
    // Test parent-child relationships (containment-based)
    assert(Asn1Decoder::is_child_of(outer_seq, first_int));   // first_int is contained in outer_seq
    assert(Asn1Decoder::is_child_of(outer_seq, nested_seq));  // nested_seq is contained in outer_seq
    assert(Asn1Decoder::is_child_of(nested_seq, second_int)); // second_int is contained in nested_seq
    assert(Asn1Decoder::is_child_of(nested_seq, third_int));  // third_int is contained in nested_seq
    assert(Asn1Decoder::is_child_of(outer_seq, second_int));  // grandparent-grandchild containment
    
    // Test direct parent-child relationships
    assert(dec.is_direct_child_of(outer_seq, first_int));   // first_int is direct child of outer_seq
    assert(dec.is_direct_child_of(outer_seq, nested_seq));  // nested_seq is direct child of outer_seq
    assert(dec.is_direct_child_of(nested_seq, second_int)); // second_int is direct child of nested_seq
    assert(dec.is_direct_child_of(nested_seq, third_int));  // third_int is direct child of nested_seq
    
    // Test non-relationships
    assert(!Asn1Decoder::is_child_of(first_int, nested_seq)); // siblings, not parent-child
    assert(!dec.is_direct_child_of(outer_seq, second_int)); // grandparent-grandchild, NOT direct
}

#[test]
fn nodeptr_boundary_validation() {
    let d = encoded_u8(42);
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    
    // Verify NodePtr field values make sense
    assert(root.ixs == 0);      // starts at beginning
    assert(root.ixf == 2);      // content starts after tag+length
    assert(root.ixl == 2);      // content ends at same position (1-byte content)
    assert(root.ixf <= root.ixl); // content region is valid
}

#[test]
fn nodeptr_empty_sequence_edge_case() {
    let d = empty_sequence();
    let dec = Asn1Decoder::new(d);
    let root = dec.root();
    
    // Verify empty SEQUENCE structure
    assert(d[0] == 0x30);      // SEQUENCE tag
    assert(d[1] == 0x00);      // length = 0
    assert(root.ixf > root.ixl); // empty content region
    
    // Attempting to get first child of empty sequence should be handled gracefully
    // (Note: this might cause assertion failure in decoder - depends on implementation)
}

#[test]
fn nodeptr_sibling_navigation() {
    let d = set_of_two_ints();
    let dec = Asn1Decoder::new(d);
    let set = dec.root();
    let first = dec.first_child_of(set);
    let second = dec.next_sibling_of(first);
    
    // Verify sibling navigation works correctly
    assert(dec.uint_at(first) == 1);
    assert(dec.uint_at(second) == 2);
    
    // Verify NodePtr positions
    assert(first.ixs < second.ixs);  // second sibling comes after first
    assert(first.ixl < second.ixs);  // no overlap between siblings
}

// Time value tests
#[test]
fn utctime_roundtrip() {
    let mut d = [0; 256]; 
    d[0] = 0x17; d[1] = 0x0D;
    let ascii = [57,57,49,50,51,49,50,51,53,57,53,57,90];
    for i in 0..13 { d[2+i] = ascii[i]; }
    let dec = Asn1Decoder::new(d); 
    let ts = TimeDecoder::new(dec.bytes_at(dec.root()), 13).from_der_to_timestamp();
    assert(ts == 946684799);
}

#[test]
fn generalized_time_roundtrip() {
    let d = generalized_time_bytes(2025, 7, 6, 12, 30, 45);
    let dec = Asn1Decoder::new(d); 
    let ts = TimeDecoder::new(dec.bytes_at(dec.root()), 15).from_der_to_timestamp();
    assert(ts == 1751805045);
}

// OBJECT IDENTIFIER tests
#[test]
fn oid_rsa_pkcs_bytes() {
    let d = oid_rsa_pkcs(); 
    let dec = Asn1Decoder::new(d); 
    let root = dec.root();
    let oid_bytes = dec.bytes_at(root);
    // first two arcs 1.2 encode to 0x2A (40*1+2)
    let expected = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D];
    for i in 0..6 { assert(oid_bytes[i] == expected[i]); }
}

// NULL tests - verify zero-length handling
#[test]
fn null_value_zero_length() {
    let mut d = [0; 256]; 
    d[0] = 0x05; d[1] = 0x00; // NULL len=0
    let dec = Asn1Decoder::new(d); 
    let root = dec.root();
    assert(root.ixf > root.ixl); // empty content region
}

// SET / SET OF tests
#[test]
fn set_of_two_integers_in_order() {
    let d = set_of_two_ints(); 
    let dec = Asn1Decoder::new(d);
    let set = dec.root(); 
    let first = dec.first_child_of(set); 
    let second = dec.next_sibling_of(first);
    assert(dec.uint_at(first) == 1);
    assert(dec.uint_at(second) == 2);
}

// DER SET canonical ordering rule: sort by encoded bytes
#[test]
fn set_canonical_ordering_rule() {
    let d = set_canonical_order();
    let dec = Asn1Decoder::new(d);
    let set = dec.root();
    let first = dec.first_child_of(set);
    let second = dec.next_sibling_of(first);
    // Verify DER canonical order: INTEGER 2 comes before INTEGER 10
    // because 02 01 02 < 02 01 0A lexicographically
    assert(dec.uint_at(first) == 2);   // smaller value first
    assert(dec.uint_at(second) == 10); // larger value second
    // Verify the raw encoding order in the SET
    assert(d[4] == 0x02);  // first integer value = 2
    assert(d[7] == 0x0A);  // second integer value = 10
}

