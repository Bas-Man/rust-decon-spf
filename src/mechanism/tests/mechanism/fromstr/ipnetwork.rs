mod ip4 {
    use crate::mechanism::Mechanism;
    use ipnetwork::IpNetwork;

    #[test]
    fn basic_str() {
        let input = "ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), "ip4:203.32.160.0/24")
    }

    #[test]
    fn basic_pass_tr() {
        let input = "ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.qualifier().is_pass(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), input);
    }

    #[test]
    fn basic_fail_str() {
        let input = "-ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.qualifier().is_fail(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), input);
    }

    mod invalid {
        use crate::mechanism::{Mechanism, MechanismError};
        use ipnetwork::IpNetwork;
        use ipnetwork::IpNetworkError::InvalidAddr;

        #[test]
        fn mechanism_name_malformed() {
            let input = "ip:203.32.160.0/24";

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::InvalidMechanismFormat(input.to_string()));
        }
        #[test]
        fn domain_as_ip() {
            let input = "ip4:example.com";
            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(
                m,
                MechanismError::InvalidIPNetwork(InvalidAddr("example.com".to_string()))
            );
            assert_eq!(
                m.to_string(),
                MechanismError::InvalidIPNetwork(InvalidAddr("example.com".to_string()))
                    .to_string()
            );
        }

        #[test]
        fn mechanism_ip_malformed() {
            let input = "ip4:203.32.160.0/33";
            let ip_error = "203.32.160.0/33"
                .parse::<ipnetwork::IpNetwork>()
                .unwrap_err();

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::InvalidIPNetwork(ip_error));
        }

        #[test]
        fn mechanism_ip6_as_ip4_malformed() {
            let input = "ip4:2001:4860:4000::/36";
            let ip = "2001:4860:4000::/36"
                .parse::<ipnetwork::IpNetwork>()
                .unwrap();

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::NotIP4Network(ip.to_string()));
        }
    }
}
mod ip6 {

    use crate::mechanism::Mechanism;
    use ipnetwork::IpNetwork;

    #[test]
    fn basic_ip_str() {
        let input = "ip6:2001:4860:4000::/36";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v6(), true);
        assert_eq!(m.qualifier().is_pass(), true);
        assert_eq!(m.to_string(), input);
    }

    #[test]
    fn basic_allow_ip_str() {
        let input = "+ip6:2001:4860:4000::/36";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v6(), true);
        assert_eq!(m.qualifier().is_pass(), true);
        assert_eq!(m.to_string(), "ip6:2001:4860:4000::/36");
    }

    #[test]
    fn basic_fail_ip_str() {
        let input = "-ip6:2001:4860:4000::/36";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v6(), true);
        assert_eq!(m.to_string(), input);
    }

    mod invalid {
        use crate::mechanism::{Mechanism, MechanismError};
        use ipnetwork::IpNetwork;

        #[test]
        fn basic_fail_ip_str() {
            let input = "p6:2001:4860:4000::/36";

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::InvalidMechanismFormat(input.to_string()));
        }

        #[test]
        fn mechanism_ip_malformed() {
            let input = "ip6:2001:4860:4000::/129";
            let ip_error = "2001:4860:4000::/129"
                .parse::<ipnetwork::IpNetwork>()
                .unwrap_err();

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::InvalidIPNetwork(ip_error));
        }

        #[test]
        fn mechanism_ip4_as_ip6_malformed() {
            let input = "ip6:203.32.160.0/24";
            let ip = "203.32.160.0/24".parse::<ipnetwork::IpNetwork>().unwrap();

            let m: MechanismError = input.parse::<Mechanism<IpNetwork>>().unwrap_err();
            assert_eq!(m, MechanismError::NotIP6Network(ip.to_string()));
        }
    }
}
