#[cfg(test)]
mod a {

    use crate::mechanism::{Kind, Mechanism, MechanismError, Qualifier};

    #[test]
    fn a() {
        let a_mechanism = Mechanism::a(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.kind(), &Kind::A);
        assert_eq!(a_mechanism.raw(), "a");
        assert_eq!(a_mechanism.to_string(), "-a");
    }
    #[test]
    fn a_with_rrdata() {
        let string = String::from("example.com");
        let a_mechanism = Mechanism::a(Qualifier::Fail).with_rrdata(&string);
        match a_mechanism {
            Ok(m) => {
                assert_eq!(m.is_fail(), true);
                assert_eq!(m.kind(), &Kind::A);
                assert_eq!(m.raw(), string);
                assert_eq!(m.to_string(), "-a:example.com");
            }
            Err(_) => {}
        }
    }
    #[test]
    fn a_with_bad_rrdata() {
        let a_mechanism = Mechanism::a(Qualifier::Fail).with_rrdata("example.xx");
        match a_mechanism {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e,
                    MechanismError::NotValidDomainHost("example.xx".to_string())
                );
            }
        }
    }
    #[test]
    fn a_with_bad_rrdata_2() {
        match Mechanism::a(Qualifier::Fail).with_rrdata("example.xx") {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e,
                    MechanismError::NotValidDomainHost("example.xx".to_string())
                );
            }
        }
    }
}

#[cfg(test)]
mod mx {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    use crate::mechanism::Qualifier;
    #[test]
    fn mx() {
        let mx = Mechanism::mx(Qualifier::Pass);
        assert_eq!(mx.is_pass(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "mx");
    }
    #[test]
    fn mx_with_rrdata() {
        let mx = Mechanism::mx(Qualifier::Neutral)
            .with_rrdata("example.com")
            .unwrap();
        assert_eq!(mx.is_neutral(), true);
        assert_eq!(mx.raw(), "example.com");
        assert_eq!(mx.to_string(), "?mx:example.com");
    }
    #[test]
    fn mx_with_rrdata_match() {
        let mx = Mechanism::mx(Qualifier::Neutral).with_rrdata("example.com");
        match mx {
            Ok(mx) => {
                assert_eq!(mx.is_neutral(), true);
                assert_eq!(mx.raw(), "example.com");
                assert_eq!(mx.to_string(), "?mx:example.com");
            }
            Err(_) => {}
        }
    }
    #[test]
    fn mx_with_bad_rrdata_match() {
        let mx = Mechanism::mx(Qualifier::Neutral).with_rrdata("example.xx");
        match mx {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e,
                    MechanismError::NotValidDomainHost("example.xx".to_string()),
                )
            }
        }
    }
    #[test]
    fn mx_with_rrdata_match2() {
        match Mechanism::mx(Qualifier::Neutral).with_rrdata("example.com") {
            Ok(mx) => {
                assert_eq!(mx.is_neutral(), true);
                assert_eq!(mx.raw(), "example.com");
                assert_eq!(mx.to_string(), "?mx:example.com");
            }
            Err(e) => {
                assert_eq!(
                    e,
                    MechanismError::NotValidDomainHost("example.xx".to_string()),
                )
            }
        }
    }
    #[test]
    fn mx_with_bad_rrdata_match2() {
        match Mechanism::mx(Qualifier::Neutral).with_rrdata("example.xx") {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(
                    e,
                    MechanismError::NotValidDomainHost("example.xx".to_string()),
                )
            }
        }
    }
}

#[cfg(test)]
mod exists {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn exists_pass() {
        let exists = Mechanism::exists(Qualifier::Neutral, "bogus.com").unwrap();
        assert_eq!(exists.is_neutral(), true);
        assert_eq!(exists.to_string(), "?exists:bogus.com");
    }
}

#[cfg(test)]
mod include {

    use crate::mechanism::Kind;
    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn include_pass() {
        let include = Mechanism::include(Qualifier::Pass, "_spf.test.com").unwrap();
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.kind(), &Kind::Include);
        assert_eq!(include.raw(), "_spf.test.com");
        assert_eq!(include.to_string(), "include:_spf.test.com");
    }
    #[test]
    fn include_fail() {
        let include = Mechanism::include(Qualifier::Fail, "_spf.test.com").unwrap();
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.to_string(), "-include:_spf.test.com");
    }
    #[test]
    fn include_softfail() {
        let include = Mechanism::include(Qualifier::SoftFail, "_spf.test.com").unwrap();
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.to_string(), "~include:_spf.test.com");
    }
    #[test]
    fn include_neutral() {
        let include = Mechanism::include(Qualifier::Neutral, "_spf.test.com").unwrap();
        assert_eq!(include.is_neutral(), true);
        assert_eq!(include.to_string(), "?include:_spf.test.com");
    }
}
#[cfg(test)]
mod ptr {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn ptr_without_mechanism() {
        let ptr = Mechanism::ptr(Qualifier::Pass);
        assert_eq!(ptr.is_pass(), true);
        assert_eq!(ptr.raw(), "ptr");
        assert_eq!(ptr.to_string(), "ptr");
    }
    #[test]
    fn ptr_with_mechanism() {
        let ptr = Mechanism::ptr(Qualifier::Neutral)
            .with_rrdata("example.com")
            .unwrap();
        assert_eq!(ptr.is_neutral(), true);
        assert_eq!(ptr.raw(), "example.com");
        assert_eq!(ptr.to_string(), "?ptr:example.com");
    }
}
#[cfg(test)]
mod redirect {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    use crate::mechanism::Qualifier;

    #[test]
    fn test_redirect() {
        let redirect = Mechanism::redirect(Qualifier::Pass, "_spf.example.com").unwrap();
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.raw(), "_spf.example.com");
        assert_eq!(redirect.to_string(), "redirect=_spf.example.com");
    }
    #[test]
    fn redirect_invalid_rrdata() {
        if let Err(redirect) = Mechanism::redirect(Qualifier::Pass, "_spf.example.") {
            assert_eq!(
                redirect,
                MechanismError::NotValidDomainHost("redirect=_spf.example.com".to_string())
            );
        }
    }
}
#[cfg(test)]
mod all {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn all() {
        let a_mechanism = Mechanism::all(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "all");
        assert_eq!(a_mechanism.to_string(), "-all");
    }
    #[test]
    fn all_with_rrdata_is_none() {
        let a_mechanism = Mechanism::all(Qualifier::Fail)
            .with_rrdata("example.com")
            .unwrap();
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "all");
        assert_eq!(a_mechanism.to_string(), "-all");
        assert_eq!(a_mechanism.rrdata, None);
    }
}
