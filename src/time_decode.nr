// Time/Date decoder for Noir

pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8
}

impl DateTime {
    pub fn new() -> Self {
        DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0
        }
    }
}

pub struct TimeDecoder {
    data: [u8],
    length: u32,
}

impl TimeDecoder {
    pub fn new(data: [u8], length: u32) -> Self {
        TimeDecoder { data, length }
    }
    
    // Convert DER encoded time to Unix timestamp
    pub fn from_der_to_timestamp(self) -> u32 {
        let mut dt = DateTime::new();
        let mut offset = 0;
        
        if self.length == 13 {
            // YYMMDDhhmmssZ format
            let first_digit: u8 = self.data[0] - 48;
            if first_digit < 5 {
                dt.year = 2000;
            } else {
                dt.year = 1900;
            }
        } else {
            // YYYYMMDDhhmmssZ format
            dt.year = ((self.data[0] - 48) as u16 * 1000 + (self.data[1] - 48) as u16 * 100);
            offset = 2;
        }

        dt.year += ((self.data[offset] - 48) * 10 + (self.data[offset + 1] - 48)) as u16;
        dt.month = (self.data[offset + 2] - 48) * 10 + (self.data[offset + 3] - 48);
        dt.day = (self.data[offset + 4] - 48) * 10 + (self.data[offset + 5] - 48);
        dt.hour = (self.data[offset + 6] - 48) * 10 + (self.data[offset + 7] - 48);
        dt.minute = (self.data[offset + 8] - 48) * 10 + (self.data[offset + 9] - 48);
        dt.second = (self.data[offset + 10] - 48) * 10 + (self.data[offset + 11] - 48);

        date_time_to_timestamp(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    }
    
    // Convert ISO 8601 time string to Unix timestamp
    pub fn from_iso_to_timestamp(self) -> u32 {
        assert(self.length == 20, "Invalid ISO string length");

        let mut dt = DateTime::new();

        // Parse YYYY-MM-DDTHH:mm:ssZ format
        dt.year = (self.data[0] - 48) as u16 * 1000 + (self.data[1] - 48) as u16 * 100 + 
                  (self.data[2] - 48) as u16 * 10 + (self.data[3] - 48) as u16;
        dt.month = (self.data[5] - 48) * 10 + (self.data[6] - 48);
        dt.day = (self.data[8] - 48) * 10 + (self.data[9] - 48);
        dt.hour = (self.data[11] - 48) * 10 + (self.data[12] - 48);
        dt.minute = (self.data[14] - 48) * 10 + (self.data[15] - 48);
        dt.second = (self.data[17] - 48) * 10 + (self.data[18] - 48);

        date_time_to_timestamp(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    }
}

// Convert date to days since Unix epoch
pub fn date_to_epoch_day(year: u16, month: u8, day: u8) -> u32 {
    let mut year: u32 = year as u32;
    if month < 3 {
        year = year - 1;
    }
    let doy: u32 = ((62719 * ((month as u32 + 9) % 12) + 769) / 2048) + day as u32;
    let yoe: u32 = year % 400;
    let doe: u32 = yoe * 365 + (yoe / 4) + doy - (yoe / 100);
    (year / 400) * 146097 + doe - 719469
}

// Convert date/time components to Unix timestamp
pub fn date_time_to_timestamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u32 {
    date_to_epoch_day(year, month, day) * 86400 + hour as u32 * 3600 + minute as u32 * 60 + second as u32
}

// Helper functions for common operations
pub fn parse_der_time(data: [u8], length: u32) -> u32 {
    let decoder = TimeDecoder::new(data, length);
    decoder.from_der_to_timestamp()
}

pub fn parse_iso_time(data: [u8]) -> u32 {
    let decoder = TimeDecoder::new(data, 20);
    decoder.from_iso_to_timestamp()
}

#[test]
fn test_der_time_yy_format() {
    // Test YYMMDDhhmmssZ format: "991231235959Z" (Dec 31, 1999 23:59:59)
    let test_data = [57, 57, 49, 50, 51, 49, 50, 51, 53, 57, 53, 57, 90]; // "991231235959Z"
    let decoder = TimeDecoder::new(test_data, 13);
    let timestamp = decoder.from_der_to_timestamp();
    
    // This should be close to 946684799 (Dec 31, 1999 23:59:59 UTC)
    assert(timestamp > 946684700);
    assert(timestamp < 946684800);
}

#[test]
fn test_iso_time() {
    // Test ISO format: "2023-12-31T23:59:59Z"
    let test_data = [50, 48, 50, 51, 45, 49, 50, 45, 51, 49, 84, 50, 51, 58, 53, 57, 58, 53, 57, 90];
    let decoder = TimeDecoder::new(test_data, 20);
    let timestamp = decoder.from_iso_to_timestamp();
    
    // This should be 1704067199 (Dec 31, 2023 23:59:59 UTC)
    assert(timestamp > 1704067100);
    assert(timestamp < 1704067200);
}

#[test]
fn test_epoch_day_calculation() {
    // Test epoch day calculation for Jan 1, 1970 (should be 0)
    let epoch_day = date_to_epoch_day(1970, 1, 1);
    assert(epoch_day == 0);
    
    // Test for Jan 1, 2000
    let y2k_day = date_to_epoch_day(2000, 1, 1);
    assert(y2k_day == 10957); 
} 