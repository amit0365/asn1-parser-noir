// ASN.1 DER decoder for Noir

pub struct NodePtr {
    pub ixs: u32,  // first byte index
    pub ixf: u32,  // first content byte index  
    pub ixl: u32,  // last content byte index
}

impl NodePtr {
    pub fn new(ixs: u32, ixf: u32, ixl: u32) -> Self {
        NodePtr { ixs, ixf, ixl }
    }
}

pub struct Asn1Decoder {
    data: [u8],
}

impl Asn1Decoder {
    pub fn new(data: [u8]) -> Self {
        Asn1Decoder { data }
    }
    
    // Get the root node - first step in traversing an ASN1 structure
    pub fn root(self) -> NodePtr {
        self.read_node_length(0)
    }
    
    // Get the root node of an ASN1 structure that's within a bit string value
    pub fn root_of_bitstring_at(self, ptr: NodePtr) -> NodePtr {
        assert(self.data[ptr.ixs] == 0x03, "Not type BIT STRING");
        self.read_node_length(ptr.ixf + 1)
    }
    
    // Get the root node of an ASN1 structure that's within an octet string value
    pub fn root_of_octet_string_at(self, ptr: NodePtr) -> NodePtr {
        assert(self.data[ptr.ixs] == 0x04, "Not type OCTET STRING");
        self.read_node_length(ptr.ixf)
    }
    
    // Get the next sibling node
    pub fn next_sibling_of(self, ptr: NodePtr) -> NodePtr {
        self.read_node_length(ptr.ixl + 1)
    }
    
    // Get the first child node of the current node
    pub fn first_child_of(self, ptr: NodePtr) -> NodePtr {
        assert(self.data[ptr.ixs] & 0x20 == 0x20, "Not a constructed type");
        self.read_node_length(ptr.ixf)
    }
    
    // Check if one node is child of another
    pub fn is_child_of(i: NodePtr, j: NodePtr) -> bool {
        ((i.ixf <= j.ixs) & (j.ixl <= i.ixl)) | ((j.ixf <= i.ixs) & (i.ixl <= j.ixl))
    }
    
    // Extract value of node as byte slice
    pub fn bytes_at(self, ptr: NodePtr) -> [u8] {
        let mut result = [0; 256]; // Max reasonable size
        
        
        for i in 0..256 {
            if (ptr.ixf + i <= ptr.ixl) & (ptr.ixf + i < self.data.len()) {
                result[i] = self.data[ptr.ixf + i];
            }
        }
        
        result
    }
    
    // Extract entire node from DER-encoded structure  
    pub fn all_bytes_at(self, ptr: NodePtr) -> [u8] {
        let mut result = [0; 256]; // Max reasonable size
        
        
        for i in 0..256 {
            if (ptr.ixs + i <= ptr.ixl) & (ptr.ixs + i < self.data.len()) {
                result[i] = self.data[ptr.ixs + i];
            }
        }
        
        result
    }
    
    // Extract value of node as Field (for small integers)
    pub fn uint_at(self, ptr: NodePtr) -> Field {
        assert(self.data[ptr.ixs] == 0x02, "Not type INTEGER");
        assert(self.data[ptr.ixf] & 0x80 == 0, "Not positive");
        
        let mut result: Field = 0;
        
        for i in 0..32 {
            if (ptr.ixf + i <= ptr.ixl) & (ptr.ixf + i < self.data.len()) {
                result = result * 256 + (self.data[ptr.ixf + i] as Field);
            }
        }
        
        result
    }
    
    // Extract value of a positive integer node
    pub fn uint_bytes_at(self, ptr: NodePtr) -> [u8] {
        assert(self.data[ptr.ixs] == 0x02, "Not type INTEGER");
        assert(self.data[ptr.ixf] & 0x80 == 0, "Not positive");
        
        let mut result = [0; 256];
        
        
        if self.data[ptr.ixf] == 0 {
            // Skip leading zero
            for i in 0..256 {
                if (ptr.ixf + 1 + i <= ptr.ixl) & (ptr.ixf + 1 + i < self.data.len()) {
                    result[i] = self.data[ptr.ixf + 1 + i];
                }
            }
        } else {
            for i in 0..256 {
                if (ptr.ixf + i <= ptr.ixl) & (ptr.ixf + i < self.data.len()) {
                    result[i] = self.data[ptr.ixf + i];
                }
            }
        }
        
        result
    }
    
    // Extract value of bitstring node
    pub fn bitstring_at(self, ptr: NodePtr) -> [u8] {
        assert(self.data[ptr.ixs] == 0x03, "Not type BIT STRING");
        // Only 00 padded bitstr can be converted to bytestr!
        assert(self.data[ptr.ixf] == 0x00);
        
        let mut result = [0; 256];
        
        
        for i in 0..256 {
            if (ptr.ixf + 1 + i <= ptr.ixl) & (ptr.ixf + 1 + i < self.data.len()) {
                result[i] = self.data[ptr.ixf + 1 + i];
            }
        }
        
        result
    }
    
    // Private function to read node length
    fn read_node_length(self, ix: u32) -> NodePtr {
        let mut length: u32 = 0;
        let mut ix_first_content_byte: u32 = 0;
        let mut ix_last_content_byte: u32 = 0;
        
        if (self.data[ix + 1] & 0x80) == 0 {
            length = self.data[ix + 1] as u32;
            ix_first_content_byte = ix + 2;
            ix_last_content_byte = ix_first_content_byte + length - 1;
        } else {
            let length_bytes_length = (self.data[ix + 1] & 0x7F) as u32;
            
            if length_bytes_length == 1 {
                length = self.data[ix + 2] as u32;
            } else if length_bytes_length == 2 {
                length = ((self.data[ix + 2] as u32) << 8) + (self.data[ix + 3] as u32);
            } else {
                for i in 0..4 { // Max 4 bytes for u32
                    if (i < length_bytes_length) & (i < 4) {
                        length = (length << 8) + (self.data[ix + 2 + i] as u32);
                    }
                }
            }
            
            ix_first_content_byte = ix + 2 + length_bytes_length;
            ix_last_content_byte = ix_first_content_byte + length - 1;
        }
        
        NodePtr::new(ix, ix_first_content_byte, ix_last_content_byte)
    }
}

// Helper functions for common ASN.1 operations
pub fn parse_asn1_sequence(data: [u8]) -> NodePtr {
    let decoder = Asn1Decoder::new(data);
    decoder.root()
}

pub fn extract_integer_from_asn1(data: [u8], ptr: NodePtr) -> Field {
    let decoder = Asn1Decoder::new(data);
    decoder.uint_at(ptr)
}

pub fn extract_bitstring_from_asn1(data: [u8], ptr: NodePtr) -> [u8] {
    let decoder = Asn1Decoder::new(data);
    decoder.bitstring_at(ptr)
}

#[test]
fn test_asn1_basic() {
    // Test with a simple ASN.1 INTEGER: 02 01 05 (INTEGER, length 1, value 5)
    let test_data = [0x02, 0x01, 0x05];
    let decoder = Asn1Decoder::new(test_data);
    let root = decoder.root();
    
    assert(root.ixs == 0);
    assert(root.ixf == 2);
    assert(root.ixl == 2);
    
    let value = decoder.uint_at(root);
    assert(value == 5);
} 