#[inline(never)]
pub fn choose(value: bool) -> u8 {
    if value {
        1
    } else {
        0
    }
}
