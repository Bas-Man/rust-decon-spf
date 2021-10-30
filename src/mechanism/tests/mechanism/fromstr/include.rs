#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn default() {
    let input = "include:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_include(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn with_pass() {
    let input = "+include:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_include(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), "include:example.com");
}
#[test]
fn neutral() {
    let input = "~include:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_include(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), "~include:example.com");
}
