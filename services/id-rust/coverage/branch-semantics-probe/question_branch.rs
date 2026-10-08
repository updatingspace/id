#[inline(never)]
pub fn choose(value: Result<u8, ()>) -> Result<u8, ()> {
    let number = value?;
    Ok(number)
}
