#[cfg(test)]
use crate::helpers;
#[cfg(test)]
use crate::mechanism::Kind;
#[cfg(test)]
use crate::mechanism::MechanismImpl;

#[test]
fn basic() {
    let string = "exists:a.example.com";
    let option_test: Option<MechanismImpl<String>>;

    option_test = helpers::capture_matches(&string, Kind::Exists);

    let test = option_test.unwrap();
    assert_eq!(test.is_pass(), true);
    assert_eq!(test.raw(), "a.example.com");
    assert_eq!(test.to_string(), "exists:a.example.com");
}
