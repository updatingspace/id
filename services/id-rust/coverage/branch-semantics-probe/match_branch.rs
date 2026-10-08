#[inline(never)]
pub fn choose(value: Result<u8, ()>) -> u8 {
    match value {
        Ok(number) => number,
        Err(()) => 0,
    }
}
