use crate::spf::Spf;

mod default_checks {
    use super::*;
    use crate::SpfError;

    #[test]
    fn non_single_space() {
        // double space before -all
        let err = "v=spf1 a  -all".parse::<Spf<String>>().unwrap_err();
        assert_eq!(err, SpfError::WhiteSpaceSyntaxError);
    }
    #[test]
    fn space_at_end() {
        let err = "v=spf1 a -all ".parse::<Spf<String>>().unwrap_err();
        assert_eq!(err, SpfError::WhiteSpaceSyntaxError);
    }
}
mod a {
    use super::*;
    mod not_strict {
        use super::*;

        #[test]
        fn default() {
            let input = "v=spf1 a -all";
            let spf: Spf<String> = input.parse().unwrap();
            assert_eq!(spf.source, input);
            assert_eq!(spf.version, "v=spf1");
            assert_eq!(spf.version(), "v=spf1");
            assert_eq!(spf.is_v1(), true);
            assert_eq!(spf.mechanisms.len(), 2);
        }

        #[test]
        fn new() {
            let input = "v=spf1 a -all";
            let spf: Spf<String> = Spf::new(input).unwrap();
            assert_eq!(spf.source, input);
            assert_eq!(spf.mechanisms.len(), 2);
        }

        #[cfg(not(feature = "strict-dns"))]
        #[test]
        fn unchecked_domain() {
            let input = "v=spf1 a:example.xx -all";
            let spf: Spf<String> = input.parse().unwrap();
            assert_eq!(spf.source, input);
            assert_eq!(spf.mechanisms[0].raw(), "example.xx".to_string());
            assert_eq!(spf.mechanisms.len(), 2);
        }
    }

    #[cfg(feature = "strict-dns")]
    mod strict {
        use super::*;
        use crate::{MechanismError, SpfError};

        mod invalid {
            use super::*;
            #[test]
            fn checked_domain() {
                let input = "v=spf1 a:example.xx -all";
                let spf = input.parse::<Spf<String>>().unwrap_err();
                assert_eq!(
                    spf,
                    SpfError::InvalidMechanism(MechanismError::InvalidDomainHost(
                        "example.xx".to_string()
                    ))
                );
            }
        }
        mod valid {
            use super::*;
            #[test]
            fn valid_domain() {
                let input = "v=spf1 a:example.com -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.source, input);
                assert_eq!(spf.to_string(), input);
                assert_eq!(spf.mechanisms[0].raw(), "example.com".to_string());
                assert_eq!(spf.mechanisms.len(), 2);
            }
        }
    }
}
mod mx {
    mod not_strict {}
    mod strict {}
}
mod ip {
    use super::*;
    mod ip4 {
        use super::*;
        mod valid {
            use super::*;
            #[test]
            fn basic() {
                let input = "v=spf1 ip4:203.32.160.10 -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.mechanisms.len(), 2);
                dbg!(&spf);
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10");
            }
            #[test]
            fn basic_strip_prefix_32() {
                let input = "v=spf1 ip4:203.32.160.10/32 -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.mechanisms.len(), 2);
                dbg!(&spf);
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10");
            }
            #[test]
            fn with_prefix() {
                let input = "v=spf1 ip4:203.32.160.10/27 -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.mechanisms.len(), 2);
                dbg!(&spf);
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10/27");
            }
        }
        mod invalid {
            use super::*;
            use crate::MechanismError::InvalidIPNetwork;
            use crate::SpfError;
            use ipnetwork::IpNetwork;
            #[test]
            fn basic() {
                let input = "v=spf1 ip4:203.32.160.10/34 -all";
                let spf = input.parse::<Spf<String>>().unwrap_err();
                assert_eq!(
                    spf,
                    SpfError::InvalidMechanism(InvalidIPNetwork(
                        "203.32.160.10/34".parse::<IpNetwork>().unwrap_err()
                    ))
                );
            }
        }
    }
    mod ip6 {}
}
mod redirect {
    use super::*;

    mod valid {
        use super::*;
        use crate::Kind;
        #[test]
        fn redirect_final() {
            let input = "v=spf1 mx redirect=_spf.example.com";
            let spf: Spf<String> = input.parse().unwrap();
            assert_eq!(spf.version, "v=spf1");
            assert_eq!(spf.mechanisms[1].kind(), &Kind::Redirect);
            assert_eq!(spf.redirect_idx, 1);
            assert_eq!(spf.mechanisms.len(), 2);
        }
        #[test]
        fn redirect_final_2() {
            let input = "v=spf1 a mx redirect=_spf.example.com";
            let spf: Spf<String> = input.parse().unwrap();
            assert_eq!(spf.mechanisms[2].kind(), &Kind::Redirect);
        }
    }
    mod invalid {
        use super::*;
        use crate::{Kind, SpfError};

        #[test]
        fn redirect_not_final() {
            let input = "v=spf1 redirect=example.com mx";
            let spf: SpfError = input.parse::<Spf<String>>().unwrap_err();
            assert_eq!(spf, SpfError::RedirectNotFinalMechanism(0));
        }
        #[test]
        fn redirect_x2() {
            let input = "v=spf1 redirect=example.com redirect=test.com";
            let spf: SpfError = input.parse::<Spf<String>>().unwrap_err();
            assert_eq!(spf, SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
        }
    }
}
