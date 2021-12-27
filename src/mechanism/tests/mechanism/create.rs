#[cfg(test)]
mod a {

    use crate::mechanism::{Kind, Mechanism, MechanismError, Qualifier};

    #[test]
    fn create_a() {
        let a_mechanism = Mechanism::create_a(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.kind(), &Kind::A);
        assert_eq!(a_mechanism.raw(), "a");
        assert_eq!(a_mechanism.to_string(), "-a");
    }
    #[test]
    fn create_a_with_rrdata() {
        let a_mechanism =
            Mechanism::create_a(Qualifier::Fail).with_rrdata("example.com".to_string());
        match a_mechanism {
            Ok(m) => {
                assert_eq!(m.is_fail(), true);
                assert_eq!(m.kind(), &Kind::A);
                assert_eq!(m.raw(), "example.com");
                assert_eq!(m.to_string(), "-a:example.com");
            }
            Err(_) => {}
        }
    }
    #[test]
    fn create_a_with_bad_rrdata() {
        let a_mechanism =
            Mechanism::create_a(Qualifier::Fail).with_rrdata("example.xx".to_string());
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
    fn create_a_with_bad_rrdata_2() {
        match Mechanism::create_a(Qualifier::Fail).with_rrdata("example.xx".to_string()) {
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
    fn create_mx() {
        let mx = Mechanism::create_mx(Qualifier::Pass);
        assert_eq!(mx.is_pass(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "mx");
    }
    #[test]
    fn create_mx_with_rrdata() {
        let mx = Mechanism::create_mx(Qualifier::Neutral)
            .with_rrdata(String::from("example.com"))
            .unwrap();
        assert_eq!(mx.is_neutral(), true);
        assert_eq!(mx.raw(), "example.com");
        assert_eq!(mx.to_string(), "?mx:example.com");
    }
    #[test]
    fn create_mx_with_rrdata_match() {
        let mx = Mechanism::create_mx(Qualifier::Neutral).with_rrdata(String::from("example.com"));
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
    fn create_mx_with_bad_rrdata_match() {
        let mx = Mechanism::create_mx(Qualifier::Neutral).with_rrdata(String::from("example.xx"));
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
    fn create_mx_with_rrdata_match2() {
        match Mechanism::create_mx(Qualifier::Neutral).with_rrdata(String::from("example.com")) {
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
    fn create_mx_with_bad_rrdata_match2() {
        match Mechanism::create_mx(Qualifier::Neutral).with_rrdata(String::from("example.xx")) {
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
        let exists =
            Mechanism::create_exists(Qualifier::Neutral, String::from("bogus.com")).unwrap();
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
        let include =
            Mechanism::create_include(Qualifier::Pass, String::from("_spf.test.com")).unwrap();
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.kind(), &Kind::Include);
        assert_eq!(include.raw(), "_spf.test.com");
        assert_eq!(include.to_string(), "include:_spf.test.com");
    }
    #[test]
    fn include_fail() {
        let include =
            Mechanism::create_include(Qualifier::Fail, String::from("_spf.test.com")).unwrap();
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.to_string(), "-include:_spf.test.com");
    }
    #[test]
    fn include_softfail() {
        let include =
            Mechanism::create_include(Qualifier::SoftFail, String::from("_spf.test.com")).unwrap();
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.to_string(), "~include:_spf.test.com");
    }
    #[test]
    fn include_neutral() {
        let include =
            Mechanism::create_include(Qualifier::Neutral, String::from("_spf.test.com")).unwrap();
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
        let ptr = Mechanism::create_ptr(Qualifier::Pass);
        assert_eq!(ptr.is_pass(), true);
        assert_eq!(ptr.raw(), "ptr");
        assert_eq!(ptr.to_string(), "ptr");
    }
    #[test]
    fn ptr_with_mechanism() {
        let ptr = Mechanism::create_ptr(Qualifier::Neutral)
            .with_rrdata(String::from("example.com"))
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
        let redirect =
            Mechanism::create_redirect(Qualifier::Pass, String::from("_spf.example.com")).unwrap();
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.raw(), "_spf.example.com");
        assert_eq!(redirect.to_string(), "redirect=_spf.example.com");
    }
    #[test]
    fn redirect_invalid_rrdata() {
        if let Err(redirect) =
            Mechanism::create_redirect(Qualifier::Pass, String::from("_spf.example."))
        {
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
    fn create_all() {
        let a_mechanism = Mechanism::create_all(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "all");
        assert_eq!(a_mechanism.to_string(), "-all");
    }
    #[test]
    fn create_all_with_rrdata_is_none() {
        let a_mechanism = Mechanism::create_all(Qualifier::Fail)
            .with_rrdata(String::from("example.com"))
            .unwrap();
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "all");
        assert_eq!(a_mechanism.to_string(), "-all");
        assert_eq!(a_mechanism.rrdata, None);
    }
}
