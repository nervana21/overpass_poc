use rand::Error;
use rand::RngCore;

pub struct WasmRng;

impl WasmRng {
    pub fn new() -> Self {
        Self
    }
}

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("Failed to generate random bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(dest).map_err(|_| Error::new("Failed to generate random bytes"))
    }
}
