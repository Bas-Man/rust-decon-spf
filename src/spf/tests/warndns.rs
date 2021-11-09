#[cfg(feature = "warn-dns")]
#[cfg(test)]
use crate::spf::Spf;

#[cfg(feature = "warn-dns")]
#[test]
fn no_errors() {
    let input = "v=spf1 a mx -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_none(), true);
    assert_eq!(spf.has_warnings(), false);
}
#[cfg(feature = "warn-dns")]
#[test]
fn no_errors_a_slash() {
    let input = "v=spf1 a/24 mx -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_none(), true);
    assert_eq!(spf.has_warnings(), false);
}
#[cfg(feature = "warn-dns")]
#[test]
fn no_errors_mx_slash() {
    let input = "v=spf1 a/24 mx/24 -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_none(), true);
    assert_eq!(spf.has_warnings(), false);
}

#[cfg(feature = "warn-dns")]
#[test]
fn invalid_a() {
    let input = "v=spf1 a:ex.t mx -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_some(), true);
    assert_eq!(spf.has_warnings(), true);
    assert_eq!(spf.warnings.unwrap()[0], "ex.t");
}
#[cfg(feature = "warn-dns")]
#[test]
fn invalid_a_with_slash() {
    let input = "v=spf1 a:ex.t/23 mx -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_some(), true);
    assert_eq!(spf.has_warnings(), true);
    assert_eq!(spf.warnings().unwrap().len(), 1);
    let warnings = spf.warnings().unwrap().iter();
    for warning in warnings {
        assert_eq!(warning, "ex.t/23");
    }
    assert_eq!(spf.warnings.unwrap()[0], "ex.t/23");
}
#[cfg(feature = "warn-dns")]
#[test]
fn valid_a_slash() {
    let input = "v=spf1 a:test.com/24 mx -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_none(), true);
}

#[cfg(feature = "warn-dns")]
#[test]
fn invalid_mx() {
    let input = "v=spf1 a mx:test.e -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_some(), true);
    assert_eq!(spf.has_warnings(), true);
    assert_eq!(spf.warnings.unwrap()[0], "test.e");
}
#[cfg(feature = "warn-dns")]
#[test]
fn invalid_ptr() {
    let input = "v=spf1 a mx ptr:test.e -all";

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_some(), true);
    assert_eq!(spf.has_warnings(), true);
    assert_eq!(spf.warnings.unwrap()[0], "test.e");
}
#[cfg(feature = "warn-dns")]
#[test]
fn multiple_errors() {
    let input = "v=spf1 a:ex.t/23 mx:test.e -all";
    let err = vec!["ex.t/23", "test.e"];
    let mut i = 0;

    let spf: Spf = input.parse().unwrap();

    assert_eq!(spf.warnings.is_some(), true);
    assert_eq!(spf.has_warnings(), true);
    assert_eq!(spf.warnings().unwrap().len(), 2);
    let warnings = spf.warnings().unwrap().iter();
    for warning in warnings {
        assert_eq!(warning, err[i]);
        i = i + 1;
    }
    assert_eq!(spf.warnings.unwrap()[0], "ex.t/23");
}
