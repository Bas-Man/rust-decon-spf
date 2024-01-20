#[cfg(test)]
use crate::mechanism::{Kind, Mechanism};

#[test]
fn match_on_mx_only() {
    let string = "mx";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::MX);

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "mx");
    assert_eq!(test.to_string(), "mx");
}
#[test]
fn match_on_mx_colon() {
    let string = "-mx:example.com";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::MX);

    let test = option_test.unwrap();
    assert_eq!(test.is_fail(), true);
    assert_eq!(test.raw(), "example.com");
    assert_eq!(test.to_string(), "-mx:example.com");
}
#[test]
fn match_on_mx_slash() {
    let string = "~mx/24";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::MX);

    let test = option_test.unwrap();
    assert_eq!(test.is_softfail(), true);
    assert_eq!(test.raw(), "/24");
    assert_eq!(test.to_string(), "~mx/24");
}
#[test]
fn match_on_mx_colon_slash() {
    let string = "+mx:example.com/24";
    let option_test: Option<Mechanism<String>>;

    option_test = crate::core::spf_regex::capture_matches(&string, Kind::MX);

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "example.com/24");
    assert_eq!(test.to_string(), "mx:example.com/24");
}
