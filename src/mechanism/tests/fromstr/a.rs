use crate::mechanism::Mechanism;

#[test]
fn basic_a() {
    let input = "a";

    assert_eq!(input.len(), 1);

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.raw(), "a");
    assert_eq!(m.to_string(), input);
}
#[test]
fn basic_pass_a() {
    let input = "+a";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "a");
    assert_eq!(m.to_string(), "a");
}
#[test]
fn basic_pass_a_rrdata() {
    let input = "+a:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), "a:example.com");
}
#[test]
fn basic_neutral_a() {
    let input = "~a";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "a");
    assert_eq!(m.to_string(), input);
}
#[test]
fn basic_neutral_a_rrdata() {
    let input = "~a:example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "example.com");
    assert_eq!(m.to_string(), input);
}
#[test]
fn pass_rrdata_with_slash() {
    let input = "~a:example.com/24";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "example.com/24");
    assert_eq!(m.to_string(), input);
}
#[test]
fn basic_pass_slash() {
    let input = "a/24";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "/24");
    assert_eq!(m.to_string(), input);
}
#[test]
//#[should_panic]
fn slash_num_over_128() {
    let input = "a/129";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_a(), true);
    assert_eq!(m.raw(), "/129");
    assert_eq!(m.to_string(), input);
}
