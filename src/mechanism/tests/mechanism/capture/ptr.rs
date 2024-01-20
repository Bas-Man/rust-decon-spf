#[cfg(test)]
use crate::mechanism::Kind;

#[test]
fn match_on_ptr() {
    let string = "ptr";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::Ptr).unwrap();
    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "ptr");
    assert_eq!(mechanism.to_string(), "ptr");
}
#[test]
fn match_on_ptr_colon() {
    let string = "ptr:example.com";

    let mechanism = crate::core::spf_regex::capture_matches(&string, Kind::Ptr).unwrap();

    assert_eq!(mechanism.is_pass(), true);
    assert_eq!(mechanism.raw(), "example.com");
}
#[test]
fn match_on_ptr_colon_with_slash_error() {
    let string = "ptr:example.com/";

    let error = crate::core::spf_regex::capture_matches(&string, Kind::Ptr).unwrap_err();

    assert_eq!(
        error.to_string(),
        "ptr:example.com/ does not conform to any Mechanism format"
    );
}
