#[cfg(test)]
use crate::mechanism::Mechanism;

#[test]
fn default() {
    let input = "redirect=_spf.example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_redirect(), true);
    assert_eq!(m.raw(), "_spf.example.com");
    assert_eq!(m.to_string(), input);
}
