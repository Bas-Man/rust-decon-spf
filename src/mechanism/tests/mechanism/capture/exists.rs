#[cfg(test)]
use crate::mechanism::Kind;

#[test]
fn basic() {
    let string = "exists:a.example.com";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::Exists).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "a.example.com");
    assert_eq!(mechanism.to_string(), "exists:a.example.com");
}
#[test]
fn basic_with_slash_error() {
    let string = "exists:a.example.com/";
    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::Exists).unwrap_err();

    assert_eq!(
        mechanism.to_string(),
        "a.example.com/ does not conform to Mechanism `exists:` format"
    );
}
#[test]
fn basic_with_slash_num_error() {
    let string = "exists:a.example.com/32";
    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::Exists).unwrap_err();

    assert_eq!(
        mechanism.to_string(),
        "a.example.com/32 does not conform to Mechanism `exists:` format"
    );
}
