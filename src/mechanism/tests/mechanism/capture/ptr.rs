#[cfg(test)]
use crate::mechanism::Kind;
#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn match_on_ptr() {
    let string = "ptr";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::Ptr);
    assert!(option_test.is_some());

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "ptr");
    assert_eq!(test.to_string(), "ptr");
}
#[test]
fn match_on_ptr_colon() {
    let string = "ptr:example.com";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::Ptr);
    assert!(option_test.is_some());

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "example.com");
}
