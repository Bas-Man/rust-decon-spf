#[cfg(test)]
use crate::mechanism::Kind;

#[test]
fn match_on_mx_only() {
    let string = "mx";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::MX).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "mx");
    assert_eq!(mechanism.to_string(), "mx");
}
#[test]
fn match_on_mx_colon() {
    let string = "-mx:example.com";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::MX).unwrap();

    assert_eq!(mechanism.is_fail(), true);
    assert_eq!(mechanism.raw(), "example.com");
    assert_eq!(mechanism.to_string(), "-mx:example.com");
}
#[test]
fn match_on_mx_slash() {
    let string = "~mx/24";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::MX).unwrap();

    assert_eq!(mechanism.is_softfail(), true);
    assert_eq!(mechanism.raw(), "/24");
    assert_eq!(mechanism.to_string(), "~mx/24");
}
#[test]
fn match_on_mx_colon_slash() {
    let string = "+mx:example.com/24";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::MX).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "example.com/24");
    assert_eq!(mechanism.to_string(), "mx:example.com/24");
}
