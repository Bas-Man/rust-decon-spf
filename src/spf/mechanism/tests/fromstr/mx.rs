use crate::spf::mechanism::Mechanism;

#[test]
fn default() {
    let input = "mx";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_mx(), true);
    assert_eq!(m.is_pass(), true);
    assert_eq!(m.raw(), "mx");
    assert_eq!(m.to_string(), input);
}
#[test]
fn mx_pass() {
    let input = "+mx";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_mx(), true);
    assert_eq!(m.raw(), "mx");
    assert_eq!(m.to_string(), "mx");
}
#[test]
fn neutral_rrdata() {
    let input = "~mx:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn mx_rrdata_slash() {
    let input = "mx:example.com/24";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "example.com/24");
    assert_eq!(m.to_string(), input);
}
#[test]
fn mx_slash() {
    let input = "mx/24";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "/24");
    assert_eq!(m.to_string(), input);
}
