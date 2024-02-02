#[cfg(test)]
use crate::mechanism::Mechanism;
use crate::mechanism::MechanismError;

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
#[test]
fn fail_with_slash() {
    let input = "include:example.com/";

    let m = input.parse::<Mechanism<String>>().unwrap_err();
    assert_eq!(m, MechanismError::InvalidMechanismFormat(input.to_string()));
}
#[test]
#[cfg(feature = "strict-dns")]
fn invalid_include_domain() {
    let input = "include:example.aa";
    let text = "example.aa";

    let m: MechanismError = input.parse::<Mechanism<String>>().unwrap_err();
    assert_eq!(m, MechanismError::InvalidDomainHost(text.to_string()));
}
