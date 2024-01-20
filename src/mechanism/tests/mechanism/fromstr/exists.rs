#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn default() {
    let input = "exists:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);

    let input = "exists:%{i}._i.example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "%{i}._i.example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn with_pass() {
    let input = "+exists:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), "exists:example.com");
}
#[test]
fn failing_exists_slash() {
    let input = "+exists:example.com/";

    let m = input.parse::<Mechanism<String>>().unwrap_err();
    assert_eq!(
        m.to_string(),
        "+exists:example.com/ does not conform to any Mechanism format"
    );
}
#[test]
fn neutral() {
    let input = "~exists:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_exists(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
