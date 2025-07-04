mod asn1_decode;
mod time_decode;
use asn1_decode::{Asn1Decoder, NodePtr};
use time_decode::TimeDecoder;

fn main(asn1_data: [u8; 256], data_length: pub u32) {
    // Create decoder with input data
    let decoder = Asn1Decoder::new(asn1_data);
    let root = decoder.root();
    
    // Parse based on the tag type
    let tag = asn1_data[root.ixs];
    
    if tag == 0x02 {
        // INTEGER
        let value = decoder.uint_at(root);
        // For demo, just assert value is non-zero
        assert(value != 0);
    } else if tag == 0x04 {
        // OCTET STRING
        let bytes = decoder.bytes_at(root);
        // Assert first byte is not zero
        assert(bytes[0] != 0);
    } else if tag == 0x03 {
        // BIT STRING
        let bits = decoder.bitstring_at(root);
        // Assert first byte is not zero
        assert(bits[0] != 0);
    } else if tag == 0x30 {
        // SEQUENCE - get first child
        let first_child = decoder.first_child_of(root);
        let child_tag = asn1_data[first_child.ixs];
        
        if child_tag == 0x02 {
            // First child is INTEGER
            let child_value = decoder.uint_at(first_child);
            assert(child_value != 0);
        }
    } else if (tag == 0x17) | (tag == 0x18) {
        //content bytes of the UTCTime / GeneralizedTime node
        let full   = decoder.bytes_at(root);          // slice with zero-padded tail
        let len    = root.ixl + 1 - root.ixf;         // actual content length

        // TimeDecoder only reads up to `len`, so we can pass `full` directly.
        let time   = TimeDecoder::new(full, len);
        let ts     = time.from_der_to_timestamp();

        assert(ts > 946684800); // after 2000-01-01
    }
}

fn create_test_array_integer() -> [u8; 256] {
    let mut result = [0; 256];
    result[0] = 0x02; // INTEGER tag
    result[1] = 0x01; // length 1
    result[2] = 0x05; // value 5
    result
}

fn create_test_array_sequence() -> [u8; 256] {
    let mut result = [0; 256];
    result[0] = 0x30; // SEQUENCE tag
    result[1] = 0x03; // length 3
    result[2] = 0x02; // INTEGER tag
    result[3] = 0x01; // length 1
    result[4] = 0x07; // value 7
    result
}

fn create_test_array_octet_string() -> [u8; 256] {
    let mut result = [0; 256];
    result[0] = 0x04; // OCTET STRING tag
    result[1] = 0x04; // length 4
    result[2] = 0x01; // data
    result[3] = 0x02;
    result[4] = 0x03;
    result[5] = 0x04;
    result
}

#[test]
fn test_parse_integer() {
    let test_data = create_test_array_integer();
    main(test_data, 3);
}

#[test]
fn test_parse_sequence() {
    let test_data = create_test_array_sequence();
    main(test_data, 5);
}

#[test]
fn test_parse_octet_string() {
    let test_data = create_test_array_octet_string();
    main(test_data, 6);
}