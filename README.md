# ASN.1 Certificate Verifier

A Noir library for parsing and verifying ASN.1 DER-encoded certificate structures.

## Features

- **ASN.1 DER Parsing**: Parse DER-encoded ASN.1 structures 
- **Time Handling**: Parse and validate UTCTime and GeneralizedTime formats

## Supported ASN.1 Types

- INTEGER (with proper DER padding)
- OCTET STRING, BIT STRING
- SEQUENCE, SET (with canonical ordering)
- OBJECT IDENTIFIER
- Time types (UTCTime, GeneralizedTime)
- String types (PrintableString, UTF8String, IA5String)
- Context-specific tags (EXPLICIT/IMPLICIT)
- Multi-byte length encoding

## Usage

```rust
use crate::asn1_decode::Asn1Decoder;
use crate::time_decode::TimeDecoder;

// Parse DER-encoded data
let decoder = Asn1Decoder::new(der_bytes);
let root = decoder.root();

// Navigate structure
let first_child = decoder.first_child_of(root);
let next_sibling = decoder.next_sibling_of(first_child);

// Extract values
let integer_value = decoder.uint_at(integer_node);
let octet_data = decoder.bytes_at(octet_node);

// Parse timestamps
let timestamp = TimeDecoder::new(time_bytes, length).from_der_to_timestamp();
```

## Testing

Run the comprehensive test suite:

```bash
nargo test
```

Tests covering DER compliance, edge cases, and all supported ASN.1 types.

## Structure

- `src/asn1_decode.nr` - Core ASN.1 parsing logic
- `src/time_decode.nr` - Time format parsing and validation
- `src/lib.nr` - Main library interface and tests 