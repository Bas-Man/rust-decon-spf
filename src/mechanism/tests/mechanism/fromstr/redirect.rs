#[cfg(test)]
use crate::mechanism::Mechanism;
use crate::mechanism::MechanismError;

#[test]
fn default() {
    let input = "redirect=_spf.example.com";

    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_redirect(), true);
    assert_eq!(m.raw(), "_spf.example.com");
    assert_eq!(m.to_string(), input);
}

#[test]
#[cfg(not(feature = "strict-dns"))]
fn invalid_redirect_no_dns_check() {
    let input = "redirect=_spf.text.aa";
    let m: Mechanism<String> = input.parse().unwrap();
    assert_eq!(m.kind().is_redirect(), true);
    assert_eq!(m.raw(), "_spf.text.aa");
    assert_eq!(m.to_string(), input);
}

#[test]
#[cfg(feature = "strict-dns")]
fn invalid_redirect_dns_check() {
    let input = "redirect=_spf.text.aa";
    let m: MechanismError = input.parse::<Mechanism<String>>().unwrap_err();
    assert_eq!(m.to_string(), "Invalid DNS string: _spf.text.aa");
}
