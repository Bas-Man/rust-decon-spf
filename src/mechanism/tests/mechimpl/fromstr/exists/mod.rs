#[cfg(test)]
use crate::mechanism::MechanismImpl;

#[test]
fn default() {
    let input = "exists:example.com";

    let m: MechanismImpl<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn with_pass() {
    let input = "+exists:example.com";

    let m: MechanismImpl<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), "exists:example.com");
}
#[test]
fn neutral() {
    let input = "~exists:example.com";

    let m: MechanismImpl<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
