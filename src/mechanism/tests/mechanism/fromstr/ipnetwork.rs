#[cfg(test)]

mod valid_ip4 {

    use crate::mechanism::Mechanism;
    use ipnetwork::IpNetwork;

    #[test]
    fn basic_ip_str() {
        let input = "ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), "ip4:203.32.160.0/24")
    }

    #[test]
    fn basic_allow_ip_str() {
        let input = "ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.qualifier().is_pass(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), input);
    }
    #[test]
    fn basic_fail_ip_str() {
        let input = "-ip4:203.32.160.0/24";

        let m: Mechanism<IpNetwork> = input.parse().unwrap();
        assert_eq!(m.kind().is_ip_v4(), true);
        assert_eq!(m.qualifier().is_fail(), true);
        assert_eq!(m.mechanism().unwrap().to_string(), "203.32.160.0/24");
        assert_eq!(m.to_string(), input);
    }
}

#[cfg(test)]
mod invalid_ip4 {

    use crate::mechanism::{Mechanism, MechanismError};
    use ipnetwork::IpNetwork;

    #[test]
    fn mechanism_name_malformed() {
        let input = "ip:203.32.160.0/24";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "ip:203.32.160.0/24 does not conform to any Mechanism format"
        );
    }
    #[test]
    fn mechanism_ip_malformed() {
        let input = "ip4:203.32.160.0/33";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "invalid address: 203.32.160.0/33"
        );
    }
    #[test]
    fn mechanism_ip6_as_ip4_malformed() {
        let input = "ip4:2001:4860:4000::/36";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "2001:4860:4000::/36 is not an ip4 network"
        );
    }
}

#[cfg(test)]
mod valid_ip6 {

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
}

#[cfg(test)]
mod invalid_ip6 {

    use crate::mechanism::{Mechanism, MechanismError};
    use ipnetwork::IpNetwork;

    #[test]
    fn basic_fail_ip_str() {
        let input = "p6:2001:4860:4000::/36";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "p6:2001:4860:4000::/36 does not conform to any Mechanism format"
        );
    }

    #[test]
    fn mechanism_ip_malformed() {
        let input = "ip6:2001:4860:4000::/129";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "invalid address: 2001:4860:4000::/129"
        );
    }
    #[test]
    fn mechanism_ip4_as_ip6_malformed() {
        let input = "ip6:203.32.160.0/24";

        let m: Result<Mechanism<IpNetwork>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        assert_eq!(
            m.unwrap_err().to_string(),
            "203.32.160.0/24 is not an ip6 network"
        );
    }
}
