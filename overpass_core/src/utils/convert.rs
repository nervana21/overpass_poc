// ./src/utils/convert.rs

pub fn u64_to_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn u64_from_bytes(bytes: [u8; 8]) -> u64 {
    u64::from_be_bytes(bytes)
}

pub fn u32_to_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn u32_from_bytes(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

pub fn u16_to_bytes(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

pub fn u16_from_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

pub fn u8_to_bytes(value: u8) -> [u8; 1] {
    value.to_be_bytes()
}

pub fn u8_from_bytes(bytes: [u8; 1]) -> u8 {
    u8::from_be_bytes(bytes)
}

pub fn i64_to_bytes(value: i64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn i64_from_bytes(bytes: [u8; 8]) -> i64 {
    i64::from_be_bytes(bytes)
}

pub fn i32_to_bytes(value: i32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn i32_from_bytes(bytes: [u8; 4]) -> i32 {
    i32::from_be_bytes(bytes)
}

pub fn i16_to_bytes(value: i16) -> [u8; 2] {
    value.to_be_bytes()
}

pub fn i16_from_bytes(bytes: [u8; 2]) -> i16 {
    i16::from_be_bytes(bytes)
}

pub fn i8_to_bytes(value: i8) -> [u8; 1] {
    value.to_be_bytes()
}

pub fn i8_from_bytes(bytes: [u8; 1]) -> i8 {
    i8::from_be_bytes(bytes)
}

pub fn f64_to_bytes(value: f64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn f64_from_bytes(bytes: [u8; 8]) -> f64 {
    f64::from_be_bytes(bytes)
}

pub fn f32_to_bytes(value: f32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn f32_from_bytes(bytes: [u8; 4]) -> f32 {
    f32::from_be_bytes(bytes)
}   

pub fn bool_to_bytes(value: bool) -> [u8; 1] {
    [value as u8]
}
pub fn bool_from_bytes(bytes: [u8; 1]) -> bool {
    bytes[0] != 0
}

pub fn string_to_bytes(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

pub fn string_from_bytes(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}   

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
    u64_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_u32(bytes: &[u8]) -> u32 {
    u32_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_u16(bytes: &[u8]) -> u16 {
    u16_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_u8(bytes: &[u8]) -> u8 {
    u8_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_i64(bytes: &[u8]) -> i64 {
    i64_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_i32(bytes: &[u8]) -> i32 {
    i32_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_i16(bytes: &[u8]) -> i16 {
    i16_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_i8(bytes: &[u8]) -> i8 {
    i8_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_f64(bytes: &[u8]) -> f64 {
    f64_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_f32(bytes: &[u8]) -> f32 {
    f32_from_bytes(bytes.try_into().unwrap())
}

pub fn bytes_to_bool(bytes: &[u8]) -> bool {
    bool_from_bytes(bytes.try_into().unwrap())
}   

