#[cfg(test)]
use crate::mechanism::{Kind, Mechanism};

#[test]
fn basic() {
    let string = "exists:a.example.com";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::Exists);

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "a.example.com");
    assert_eq!(test.to_string(), "exists:a.example.com");
}
#[test]
fn basic_with_slash_error() {
    let string = "exists:a.example.com/";

    let option_test = crate::core::spf_regex::capture_matches(&string, Kind::Exists);

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "a.example.com/24");
    assert_eq!(test.to_string(), "exists:a.example.com/24");
}
