#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn default() {
    let input = "all";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_all(), true);
    assert_eq!(m.raw(), "all");
    assert_eq!(m.to_string(), input);
}
#[test]
fn with_plus() {
    let input = "+all";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_all(), true);
    assert_eq!(m.raw(), "all");
    assert_eq!(m.to_string(), "all");
}
#[test]
fn neutral() {
    let input = "~all";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_all(), true);
    assert_eq!(m.raw(), "all");
    assert_eq!(m.to_string(), input);
}
#[test]
fn fail() {
    let input = "-all";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_all(), true);
    assert_eq!(m.raw(), "all");
    assert_eq!(m.to_string(), input);
}
