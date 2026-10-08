// Dependency-free reproduction of ensure!'s decision, not the anyhow crate.
macro_rules! ensure_value {
    ($condition:expr) => {
        if !$condition {
            return Err(());
        }
    };
}
#[inline(never)]
pub fn choose(value: bool) -> Result<(), ()> {
    ensure_value!(value);
    Ok(())
}
