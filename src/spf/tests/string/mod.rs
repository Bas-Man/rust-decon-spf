use crate::spf::Spf;

mod minus_all {
    use super::*;
    use crate::mechanism::{Kind, Mechanism, Qualifier};

    #[test]
    fn minimum_spf() {
        let spf = "v=spf1 -all".parse::<Spf<String>>().unwrap();
        assert_eq!(spf.version(), "v=spf1");
        let m: Mechanism<String> = Mechanism::new(Kind::All, Qualifier::Fail);
        assert_eq!(*spf.all().unwrap(), m);
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
            assert_eq!(spf.all().unwrap().to_string(), "-all");
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

        #[cfg(feature = "strict-dns")]
        mod strict {
            use super::*;
            use crate::{mechanism::MechanismError, SpfError};

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

    mod invalid {
        use super::*;
        use crate::mechanism::MechanismError;
        use crate::SpfError;

        #[test]
        fn invalid_with_colon_only() {
            let input = "v=spf1 a: -all";
            let err_mechanism = "a:";

            let err = input.parse::<Spf<String>>().unwrap_err();
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

            let err = input.parse::<Spf<String>>().unwrap_err();
            assert_eq!(
                err,
                SpfError::InvalidMechanism(MechanismError::InvalidMechanismFormat(
                    err_mechanism.to_string()
                ))
            )
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
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10");
            }

            #[test]
            fn basic_strip_prefix_32() {
                let input = "v=spf1 ip4:203.32.160.10/32 -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.mechanisms.len(), 2);
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10");
            }

            #[test]
            fn with_prefix() {
                let input = "v=spf1 ip4:203.32.160.10/27 -all";
                let spf: Spf<String> = input.parse().unwrap();
                assert_eq!(spf.mechanisms.len(), 2);
                assert_eq!(spf.mechanisms[0].to_string(), "ip4:203.32.160.10/27");
            }
        }

        mod invalid {
            use super::*;
            use crate::mechanism::MechanismError::InvalidIPNetwork;
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
        use crate::mechanism::{Kind, Mechanism, Qualifier};

        #[test]
        fn redirect_at_start() {
            let spf: Spf<String> = "v=spf1 redirect=example.com".parse().unwrap();
            let m: Mechanism<String> = Mechanism::redirect(Qualifier::Pass, "example.com").unwrap();
            assert_eq!(spf.redirect().unwrap(), &m);
        }
        #[test]
        fn redirect_final() {
            let input = "v=spf1 mx redirect=_spf.example.com";
            let spf: Spf<String> = input.parse().unwrap();
            assert_eq!(spf.version, "v=spf1");
            assert_eq!(
                spf.redirect().unwrap().rr_data().as_ref().unwrap(),
                "_spf.example.com"
            );
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
        use crate::{mechanism::Kind, SpfError};

        #[test]
        fn redirect_x2() {
            let input = "v=spf1 redirect=example.com redirect=test.com";
            let spf: SpfError = input.parse::<Spf<String>>().unwrap_err();
            assert_eq!(spf, SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
        }
    }
}

#[cfg(feature = "builder")]
mod spf_to_spf_builder {
    use crate::{mechanism::Mechanism, mechanism::Qualifier, Builder, Spf, SpfBuilder};

    #[test]
    fn basic() {
        let input = "v=spf1 a -all";
        let spf: Spf<String> = input.parse().unwrap();
        let builder_from: SpfBuilder<Builder> = spf.into();

        let mut builder_hand = SpfBuilder::new();
        builder_hand.set_v1(); // Needed for testing
        builder_hand.append_mechanism(Mechanism::a(Qualifier::Pass));
        builder_hand.append_mechanism(Mechanism::all());

        assert_eq!(builder_hand, builder_from);
    }
}

mod iter {
    use super::*;

    #[test]
    fn basic() {
        let input = "v=spf1 a mx -all";
        let spf: Spf<String> = input.parse().unwrap();
        let m_list = vec!["a", "mx", "-all"];
        assert_eq!(spf.version(), "v=spf1");
        let mut idx: usize = 0;
        for m in spf.iter() {
            assert_eq!(m.to_string(), m_list[idx]);
            idx = idx + 1;
        }
    }
}

#[cfg(feature = "serde")]
mod serde {
    use super::*;
    use serde_json;

    #[test]
    fn basic() {
        let input = "v=spf1 a -all";
        let spf: Spf<String> = input.parse().unwrap();
        let spf_as_json = serde_json::to_string(&spf).unwrap();
        assert_eq!(spf_as_json,
                   "{\"source\":\"v=spf1 a -all\",\"version\":\"v=spf1\",\"redirect_idx\":0,\"has_redirect\":false,\"all_idx\":1,\"lookup_count\":1,\"mechanisms\":[{\"kind\":\"A\",\"qualifier\":\"Pass\",\"rrdata\":null},{\"kind\":\"All\",\"qualifier\":\"Fail\",\"rrdata\":null}]}");
    }
}
