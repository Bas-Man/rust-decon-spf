#[doc(hidden)]
#[cfg(test)]
#[allow(non_snake_case)]
mod IpNetwork {

    use crate::spf::Qualifier;
    use crate::spf::SpfMechanism;

    #[test]
    fn test_ip4_pass() {
        let ip4_pass = SpfMechanism::new_ip4(Qualifier::Pass, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_pass.is_pass(), true);
        assert_eq!(ip4_pass.raw(), "203.32.160.10/32");
        assert_eq!(ip4_pass.string(), "ip4:203.32.160.10/32");
        assert_eq!(ip4_pass.mechanism().ip().to_string(), "203.32.160.10");
        assert_eq!(ip4_pass.mechanism().prefix().to_string(), "32");
        assert_eq!(ip4_pass.mechanism().network().to_string(), "203.32.160.10");
    }
    #[test]
    fn test_ip4_fail() {
        let ip4_fail = SpfMechanism::new_ip4(Qualifier::Fail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_fail.is_fail(), true);
        assert_eq!(ip4_fail.string(), "-ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_softfail() {
        let ip4_softfail =
            SpfMechanism::new_ip4(Qualifier::SoftFail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_softfail.is_softfail(), true);
        assert_eq!(ip4_softfail.string(), "~ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_neutral() {
        let ip4_neutral =
            SpfMechanism::new_ip4(Qualifier::Neutral, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_neutral.is_neutral(), true);
        assert_eq!(ip4_neutral.string(), "?ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip6_pass() {
        let ip_pass =
            SpfMechanism::new_ip6(Qualifier::Pass, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_pass.is_pass(), true);
        assert_eq!(ip_pass.raw(), "2001:4860:4000::/36");
        assert_eq!(ip_pass.string(), "ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_fail() {
        let ip_fail =
            SpfMechanism::new_ip6(Qualifier::Fail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_fail.is_fail(), true);
        assert_eq!(ip_fail.string(), "-ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_softfail() {
        let ip_softfail =
            SpfMechanism::new_ip6(Qualifier::SoftFail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_softfail.is_softfail(), true);
        assert_eq!(ip_softfail.string(), "~ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_neutral() {
        let ip_neutral =
            SpfMechanism::new_ip6(Qualifier::Neutral, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_neutral.is_neutral(), true);
        assert_eq!(ip_neutral.string(), "?ip6:2001:4860:4000::/36");
    }
}
