mod fromstr;
mod mechanism {
    mod build {
        mod a {

            use crate::mechanism::{Kind, Mechanism, Qualifier};

            #[test]
            fn new_a_without_mechanism() {
                let a_mechanism = Mechanism::a(Qualifier::Fail);
                assert_eq!(a_mechanism.is_fail(), true);
                assert_eq!(a_mechanism.kind(), &Kind::A);
                assert_eq!(a_mechanism.raw(), "a");
                assert_eq!(a_mechanism.to_string(), "-a");
            }
        }

        mod mx {

            use crate::mechanism::Mechanism;
            use crate::mechanism::Qualifier;
            #[test]
            fn without_mechanism() {
                let mx = Mechanism::mx(Qualifier::Pass);
                assert_eq!(mx.is_pass(), true);
                assert_eq!(mx.raw(), "mx");
                assert_eq!(mx.to_string(), "mx");
            }
            #[test]
            fn without_mechanism_softfail() {
                let mx = Mechanism::mx(Qualifier::SoftFail);
                assert_eq!(mx.is_softfail(), true);
                assert_eq!(mx.raw(), "mx");
                assert_eq!(mx.to_string(), "~mx");
            }
        }

        mod ptr {

            use crate::mechanism::Mechanism;
            use crate::mechanism::Qualifier;

            #[test]
            fn without_mechanism() {
                let ptr = Mechanism::ptr(Qualifier::Pass);
                assert_eq!(ptr.is_pass(), true);
                assert_eq!(ptr.raw(), "ptr");
                assert_eq!(ptr.to_string(), "ptr");
            }
        }
        mod ip4 {

            use crate::mechanism::Mechanism;
            use crate::mechanism::MechanismError;
            mod valid {
                use super::*;
                #[test]
                fn from_string() {
                    let string = String::from("ip4:203.32.160.10/32");
                    let ip4 = Mechanism::ip_from_string(&string);
                    let unwrapped = ip4.unwrap();
                    assert_eq!(unwrapped.is_pass(), true);
                    assert_eq!(unwrapped.to_string(), "ip4:203.32.160.10/32");
                }
            }
            mod invalid {
                use super::*;
                #[test]
                fn from_string() {
                    let string = String::from("ip:203.32.160.10/32");
                    let ip4 = Mechanism::ip_from_string(&string);
                    let unwrapped = ip4.unwrap_err();
                    assert_eq!(
                        unwrapped,
                        MechanismError::InvalidMechanismFormat(String::from("ip:203.32.160.10/32"))
                    );
                }
            }
        }

        mod ip6 {

            use crate::mechanism::Mechanism;
            use crate::mechanism::MechanismError;

            mod valid {
                use super::*;
                #[test]
                fn from_string() {
                    let string = String::from("ip6:2001:4860:4000::/36");
                    let ip6 = Mechanism::ip_from_string(&string);
                    let unwrapped = ip6.unwrap();
                    assert_eq!(unwrapped.is_pass(), true);
                    assert_eq!(unwrapped.to_string(), "ip6:2001:4860:4000::/36");
                }
            }
            mod invalid {
                use super::*;
                #[test]
                fn from_string() {
                    let string = String::from("ip:2001:4860:4000::/36");
                    let ip6 = Mechanism::ip_from_string(&string);
                    let unwrapped = ip6.unwrap_err();
                    assert_eq!(
                        unwrapped,
                        MechanismError::InvalidMechanismFormat(String::from(
                            "ip:2001:4860:4000::/36"
                        ))
                    );
                }
            }
        }
        mod all {

            use crate::mechanism::Mechanism;
            use crate::mechanism::Qualifier;

            #[test]
            fn new_all() {
                let a_mechanism = Mechanism::all(Qualifier::Fail);
                assert_eq!(a_mechanism.is_fail(), true);
                assert_eq!(a_mechanism.raw(), "all");
                assert_eq!(a_mechanism.to_string(), "-all");
            }
        }
    }
}

mod create {
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
                        MechanismError::InvalidDomainHost("example.xx".to_string())
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
                        MechanismError::InvalidDomainHost("example.xx".to_string())
                    );
                }
            }
        }
    }

    mod mx {

        use crate::mechanism::Mechanism;
        use crate::mechanism::MechanismError;
        use crate::mechanism::Qualifier;
        #[test]
        fn default() {
            let mx = Mechanism::mx(Qualifier::Pass);
            assert_eq!(mx.is_pass(), true);
            assert_eq!(mx.raw(), "mx");
            assert_eq!(mx.to_string(), "mx");
        }
        #[test]
        fn with_rrdata() {
            let mx = Mechanism::mx(Qualifier::Neutral)
                .with_rrdata("example.com")
                .unwrap();
            assert_eq!(mx.is_neutral(), true);
            assert_eq!(mx.raw(), "example.com");
            assert_eq!(mx.to_string(), "?mx:example.com");
        }
        #[test]
        fn with_rrdata_match() {
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
        fn with_bad_rrdata_match() {
            let mx = Mechanism::mx(Qualifier::Neutral).with_rrdata("example.xx");
            match mx {
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(
                        e,
                        MechanismError::InvalidDomainHost("example.xx".to_string()),
                    )
                }
            }
        }
        #[test]
        fn with_rrdata_match2() {
            match Mechanism::mx(Qualifier::Neutral).with_rrdata("example.com") {
                Ok(mx) => {
                    assert_eq!(mx.is_neutral(), true);
                    assert_eq!(mx.raw(), "example.com");
                    assert_eq!(mx.to_string(), "?mx:example.com");
                }
                Err(e) => {
                    assert_eq!(
                        e,
                        MechanismError::InvalidDomainHost("example.xx".to_string()),
                    )
                }
            }
        }
        #[test]
        fn with_bad_rrdata_match2() {
            match Mechanism::mx(Qualifier::Neutral).with_rrdata("example.xx") {
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(
                        e,
                        MechanismError::InvalidDomainHost("example.xx".to_string()),
                    )
                }
            }
        }
    }

    mod exists {

        use crate::mechanism::Mechanism;
        use crate::mechanism::Qualifier;
        #[test]
        fn pass() {
            let exists = Mechanism::exists(Qualifier::Neutral, "bogus.com").unwrap();
            assert_eq!(exists.is_neutral(), true);
            assert_eq!(exists.to_string(), "?exists:bogus.com");
        }
    }

    mod include {

        use crate::mechanism::Kind;
        use crate::mechanism::Mechanism;
        use crate::mechanism::Qualifier;
        #[test]
        fn pass() {
            let include = Mechanism::include(Qualifier::Pass, "_spf.test.com").unwrap();
            assert_eq!(include.is_pass(), true);
            assert_eq!(include.kind(), &Kind::Include);
            assert_eq!(include.raw(), "_spf.test.com");
            assert_eq!(include.to_string(), "include:_spf.test.com");
        }
        #[test]
        fn fail() {
            let include = Mechanism::include(Qualifier::Fail, "_spf.test.com").unwrap();
            assert_eq!(include.is_fail(), true);
            assert_eq!(include.to_string(), "-include:_spf.test.com");
        }
        #[test]
        fn softfail() {
            let include = Mechanism::include(Qualifier::SoftFail, "_spf.test.com").unwrap();
            assert_eq!(include.is_softfail(), true);
            assert_eq!(include.to_string(), "~include:_spf.test.com");
        }
        #[test]
        fn neutral() {
            let include = Mechanism::include(Qualifier::Neutral, "_spf.test.com").unwrap();
            assert_eq!(include.is_neutral(), true);
            assert_eq!(include.to_string(), "?include:_spf.test.com");
        }
    }
    mod ptr {

        use crate::mechanism::Mechanism;
        use crate::mechanism::Qualifier;

        #[test]
        fn without_mechanism() {
            let ptr = Mechanism::ptr(Qualifier::Pass);
            assert_eq!(ptr.is_pass(), true);
            assert_eq!(ptr.raw(), "ptr");
            assert_eq!(ptr.to_string(), "ptr");
        }
        #[test]
        fn with_mechanism() {
            let ptr = Mechanism::ptr(Qualifier::Neutral)
                .with_rrdata("example.com")
                .unwrap();
            assert_eq!(ptr.is_neutral(), true);
            assert_eq!(ptr.raw(), "example.com");
            assert_eq!(ptr.to_string(), "?ptr:example.com");
        }
    }
    mod redirect {

        use crate::mechanism::Mechanism;
        use crate::mechanism::MechanismError;
        use crate::mechanism::Qualifier;

        #[test]
        fn redirect() {
            let redirect = Mechanism::redirect(Qualifier::Pass, "_spf.example.com").unwrap();
            assert_eq!(redirect.is_pass(), true);
            assert_eq!(redirect.raw(), "_spf.example.com");
            assert_eq!(redirect.to_string(), "redirect=_spf.example.com");
        }
        #[test]
        fn invalid_rrdata() {
            if let Err(redirect) = Mechanism::redirect(Qualifier::Pass, "_spf.example.") {
                assert_eq!(
                    redirect,
                    MechanismError::InvalidDomainHost("redirect=_spf.example.com".to_string())
                );
            }
        }
    }
    mod all {

        use crate::mechanism::Mechanism;
        use crate::mechanism::Qualifier;

        #[test]
        fn fault() {
            let a_mechanism = Mechanism::all(Qualifier::Fail);
            assert_eq!(a_mechanism.is_fail(), true);
            assert_eq!(a_mechanism.raw(), "all");
            assert_eq!(a_mechanism.to_string(), "-all");
        }
        #[test]
        fn with_rrdata_is_none() {
            let a_mechanism = Mechanism::all(Qualifier::Fail)
                .with_rrdata("example.com")
                .unwrap();
            assert_eq!(a_mechanism.is_fail(), true);
            assert_eq!(a_mechanism.raw(), "all");
            assert_eq!(a_mechanism.to_string(), "-all");
            assert_eq!(a_mechanism.rrdata, None);
        }
    }
}
mod parsedmechanism {
    mod ip {
        use crate::mechanism::ParsedMechanism;
        mod v4 {
            use super::*;
            #[test]
            fn ip4() {
                let m: ParsedMechanism = "ip4:203.32.160.0/24".parse().unwrap();
                assert_eq!(m.network().kind().is_ip(), true);
                assert_eq!(m.network().qualifier().is_pass(), true);
                assert_eq!(m.network().raw(), "203.32.160.0/24");
                assert_eq!(m.network().to_string(), "ip4:203.32.160.0/24");
                assert_eq!(m.is_network(), true);
                assert_eq!(m.network().as_network().prefix(), 24);
                assert_eq!(m.network().to_string(), "ip4:203.32.160.0/24");
            }

            mod invalid {
                use crate::mechanism::{MechanismError, ParsedMechanism};

                #[test]
                fn ip4() {
                    let m: MechanismError = "ip4:203.32.160.0/33"
                        .parse::<ParsedMechanism>()
                        .unwrap_err();
                    let ip = "203.32.160.0/33"
                        .parse::<ipnetwork::IpNetwork>()
                        .unwrap_err();
                    assert_eq!(m, MechanismError::InvalidIPNetwork(ip));
                }
            }
        }
        mod v6 {
            mod invalid {}
        }
    }
    mod a {
        use crate::mechanism::ParsedMechanism;

        #[test]
        fn make_mechanism() {
            let m: ParsedMechanism = "a".parse().unwrap();
            assert_eq!(m.txt().kind().is_a(), true);
            assert_eq!(m.txt().qualifier().is_pass(), true);
            assert_eq!(m.txt().raw(), "a");
            assert_eq!(m.txt().to_string(), "a");
        }
        #[test]
        fn make_mechanism_colon() {
            let m: ParsedMechanism = "?a:test.com".parse().unwrap();
            assert_eq!(m.txt().kind().is_a(), true);
            assert_eq!(m.txt().qualifier().is_neutral(), true);
            assert_eq!(m.txt().raw(), "test.com");
            assert_eq!(m.txt().to_string(), "?a:test.com");
        }
        #[test]
        fn make_mechanism_colon_slash() {
            let m: ParsedMechanism = "?a:test.com/24".parse().unwrap();
            assert_eq!(m.txt().kind().is_a(), true);
            assert_eq!(m.txt().qualifier().is_neutral(), true);
            assert_eq!(m.txt().raw(), "test.com/24");
            assert_eq!(m.txt().to_string(), "?a:test.com/24");
        }
        #[test]
        fn make_mechanism_slash() {
            let m: ParsedMechanism = "?a/24".parse().unwrap();
            assert_eq!(m.txt().kind().is_a(), true);
            assert_eq!(m.txt().qualifier().is_neutral(), true);
            assert_eq!(m.txt().raw(), "/24");
            assert_eq!(m.txt().to_string(), "?a/24");
        }
        mod invalid {
            use crate::mechanism::{MechanismError, ParsedMechanism};

            #[test]
            fn make_fail() {
                let m: Result<ParsedMechanism, MechanismError> = "ab".parse();
                assert_eq!(m.is_err(), true);
                let err = m.unwrap_err();
                assert_eq!(
                    err,
                    MechanismError::InvalidMechanismFormat("ab".to_string())
                );
            }
        }
        #[cfg(feature = "strict-dns")]
        mod strict_dns {
            use crate::mechanism::ParsedMechanism;

            #[test]
            fn check() {
                let input = "-a:example.xx";
                let m = ParsedMechanism::new(input);
                let err = m.unwrap_err();
                assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
            }
        }
    }

    mod redirect {
        use crate::mechanism::ParsedMechanism;

        #[test]
        fn parse_redirect() {
            let input = "redirect=_spf.example.com";
            let m = ParsedMechanism::new(input).unwrap();
            assert_eq!(m.txt().kind().is_redirect(), true);
            assert_eq!(m.txt().to_string(), "redirect=_spf.example.com");
        }
    }
    #[cfg(feature = "strict-dns")]
    mod mx {
        use crate::mechanism::ParsedMechanism;

        mod invalid {
            use super::*;
            #[test]
            fn check() {
                let input = "+mx:example.xx";
                let m = ParsedMechanism::new(input);
                let err = m.unwrap_err();
                assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
            }
        }
    }
    #[cfg(feature = "strict-dns")]
    mod include_invalid {
        use crate::mechanism::ParsedMechanism;

        #[test]
        fn check_a() {
            let input = "+include:example.xx";
            let m = ParsedMechanism::new(input);
            let err = m.unwrap_err();
            assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
        }
    }
    mod ptr {
        #[cfg(feature = "strict-dns")]
        mod invalid {
            use crate::mechanism::ParsedMechanism;

            #[test]
            fn check_a() {
                let input = "ptr:example.xx";
                let m = ParsedMechanism::new(input);
                let err = m.unwrap_err();
                assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
            }
        }
    }
    #[cfg(feature = "strict-dns")]
    mod exists_invalid {
        use crate::mechanism::ParsedMechanism;

        #[test]
        fn check() {
            let input = "exists:example.xx";
            let m = ParsedMechanism::new(input);
            let err = m.unwrap_err();
            assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
        }
    }
}
