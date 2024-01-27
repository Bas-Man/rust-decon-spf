use crate::spf::Spf;

#[test]
fn mechanism() {
    let input = "v=spf1 a ~all";

    let spf: Spf = input.parse().unwrap();
    assert_eq!(spf.is_valid(), true);
    assert_eq!(spf.version(), "v=spf1");
    assert!(spf.a().is_some());
    assert_eq!(spf.a().unwrap()[0].qualifier().is_pass(), true);
    assert_eq!(spf.a().unwrap()[0].to_string(), "a");
    assert_eq!(spf.all().unwrap().qualifier().is_softfail(), true);
    assert_eq!(spf.all().unwrap().to_string(), "~all");
}
#[test]
fn mechanism_slash_cidr() {
    let input = "v=spf1 -a/24 ~all";

    let spf: Spf = input.parse().unwrap();
    assert!(spf.a().is_some());
    assert_eq!(spf.a().unwrap()[0].qualifier().is_fail(), true);
    assert_eq!(spf.a().unwrap()[0].to_string(), "-a/24");
}
#[test]
fn mechanism_colon_domain() {
    let input = "v=spf1 ?a:example.com ~all";

    let spf: Spf = input.parse().unwrap();
    assert!(spf.a().is_some());
    assert_eq!(spf.a().unwrap()[0].qualifier().is_neutral(), true);
    assert_eq!(spf.a().unwrap()[0].to_string(), "?a:example.com");
}
#[test]
fn mechanism_domain_cidr() {
    let input = "v=spf1 ~a:example.com/24 ~all";

    let spf: Spf = input.parse().unwrap();
    assert!(spf.a().is_some());
    assert_eq!(spf.a().unwrap()[0].qualifier().is_softfail(), true);
    assert_eq!(spf.a().unwrap()[0].to_string(), "~a:example.com/24");
}
mod invalid {
    use crate::mechanism::MechanismError;
    use crate::spf::{Spf, SpfError};

    #[test]
    fn invalid_with_colon_only() {
        let input = "v=spf1 a: -all";
        let err_mechanism = "a:";

        let err = input.parse::<Spf>().unwrap_err();
        assert_eq!(
            err,
            SpfError::InvalidMechanism(MechanismError::InvalidMechanismFormat(
                err_mechanism.to_string()
            ))
        )
    }
    #[test]
    fn invalid_with_slash_only() {
        let input = "v=spf1 a/ -all";
        let err_mechanism = "a/";

        let err = input.parse::<Spf>().unwrap_err();
        assert_eq!(
            err,
            SpfError::InvalidMechanism(MechanismError::InvalidMechanismFormat(
                err_mechanism.to_string()
            ))
        )
    }
}
