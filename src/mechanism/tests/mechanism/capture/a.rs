#[cfg(test)]
use crate::mechanism::Kind;

#[test]
fn test_match_on_a_only() {
    let string = "a";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::A).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "a");
    assert_eq!(mechanism.to_string(), "a");
}
#[test]
fn test_match_on_a_colon() {
    let string = "-a:example.com";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::A).unwrap();

    assert_eq!(mechanism.is_fail(), true);
    assert_eq!(mechanism.raw(), "example.com");
    assert_eq!(mechanism.to_string(), "-a:example.com");
}
#[test]
fn test_match_on_a_slash() {
    let string = "~a/24";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::A).unwrap();

    assert_eq!(mechanism.is_softfail(), true);
    assert_eq!(mechanism.raw(), "/24");
    assert_eq!(mechanism.to_string(), "~a/24");
}
#[test]
fn test_match_on_a_colon_slash() {
    let string = "+a:example.com/24";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::A).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "example.com/24");
    assert_eq!(mechanism.to_string(), "a:example.com/24");
}
