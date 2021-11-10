#[cfg(test)]
use crate::spf::Spf;

#[test]
fn basic() {
    let input = "v=spf1 a mx -all";

    let spf: Spf = input.parse().unwrap();
    assert_eq!(spf.to_string(), "v=spf1 a mx -all");
}

#[test]
fn include_x2() {
    let input = "v=spf1 include:test.com include:example.com -all";

    let spf: Spf = input.parse().unwrap();
    assert_eq!(spf.includes().unwrap().len(), 2);
    assert_eq!(spf.to_string(), input);
}
#[test]
fn ip4_x3() {
    let input = "v=spf1 ip4:203.32.160.0/24 ip4:203.32.166.0/24 ip4:203.32.161.0/24 -all";

    let spf: Spf = input.parse().unwrap();
    assert_eq!(spf.to_string(), input);
}
