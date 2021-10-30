#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn basic_ptr() {
    let input = "ptr";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_ptr(), true);
    assert_eq!(m.is_pass(), true);
    assert_eq!(m.raw(), "ptr");
    assert_eq!(m.to_string(), input);
}
#[test]
fn with_pass() {
    let input = "+ptr";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_ptr(), true);
    assert_eq!(m.raw(), "ptr");
    assert_eq!(m.to_string(), "ptr");
}
#[test]
fn neutral_rrdata() {
    let input = "~ptr:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn default_rrdata() {
    let input = "ptr:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
