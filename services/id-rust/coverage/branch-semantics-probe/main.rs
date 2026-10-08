mod ensure_branch;
mod if_branch;
mod match_branch;
mod question_branch;
fn main() {
    assert_eq!(if_branch::choose(true), 1);
    assert_eq!(if_branch::choose(false), 0);
    assert_eq!(match_branch::choose(Ok(1)), 1);
    assert_eq!(match_branch::choose(Err(())), 0);
    assert_eq!(question_branch::choose(Ok(1)), Ok(1));
    assert_eq!(question_branch::choose(Err(())), Err(()));
    assert_eq!(ensure_branch::choose(true), Ok(()));
    assert_eq!(ensure_branch::choose(false), Err(()));
}
