#[cfg(test)]
#[allow(non_snake_case)]
mod A {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismKind;
    use crate::mechanism::Qualifier;

    #[test]
    fn new_a_without_mechanism() {
        let a_mechanism = Mechanism::new_a_without_mechanism(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.kind(), &MechanismKind::A);
        assert_eq!(a_mechanism.raw(), "a");
        assert_eq!(a_mechanism.to_string(), "-a");
    }
    // Todo This needs review. How do I want to use new_a
    #[test]
    fn new_a_with_mechanism() {
        let a_mechanism =
            Mechanism::new_a_with_mechanism(Qualifier::Fail, "example.com".to_string());
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.kind(), &MechanismKind::A);
        assert_eq!(a_mechanism.raw(), "example.com");
        assert_eq!(a_mechanism.to_string(), "-a:example.com");
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod MX {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn new_mx_without_mechanism() {
        let mx = Mechanism::new_mx_without_mechanism(Qualifier::Pass);
        assert_eq!(mx.is_pass(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "mx");
    }
    #[test]
    fn new_mx_without_mechanism_softfail() {
        let mx = Mechanism::new_mx_without_mechanism(Qualifier::SoftFail);
        assert_eq!(mx.is_softfail(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "~mx");
    }
    #[test]
    fn new_mx_with_mechanism() {
        let mx = Mechanism::new_mx_with_mechanism(Qualifier::Neutral, String::from("example.com"));
        assert_eq!(mx.is_neutral(), true);
        assert_eq!(mx.raw(), "example.com");
        assert_eq!(mx.to_string(), "?mx:example.com");
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod EXISTS {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn exists_pass() {
        let exists = Mechanism::new_exists(Qualifier::Neutral, String::from("bogus.com"));
        assert_eq!(exists.is_neutral(), true);
        assert_eq!(exists.to_string(), "?exists:bogus.com");
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod INCLUDE {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismKind;
    use crate::mechanism::Qualifier;
    #[test]
    fn include_pass() {
        let include = Mechanism::new_include(Qualifier::Pass, String::from("_spf.test.com"));
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.kind(), &MechanismKind::Include);
        assert_eq!(include.raw(), "_spf.test.com");
        assert_eq!(include.to_string(), "include:_spf.test.com");
    }
    #[test]
    fn include_fail() {
        let include = Mechanism::new_include(Qualifier::Fail, String::from("_spf.test.com"));
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.to_string(), "-include:_spf.test.com");
    }
    #[test]
    fn include_softfail() {
        let include = Mechanism::new_include(Qualifier::SoftFail, String::from("_spf.test.com"));
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.to_string(), "~include:_spf.test.com");
    }
    #[test]
    fn include_neutral() {
        let include = Mechanism::new_include(Qualifier::Neutral, String::from("_spf.test.com"));
        assert_eq!(include.is_neutral(), true);
        assert_eq!(include.to_string(), "?include:_spf.test.com");
    }
}
#[cfg(test)]
#[allow(non_snake_case)]
mod PTR {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn ptr_without_mechanism() {
        let ptr = Mechanism::new_ptr_without_mechanism(Qualifier::Pass);
        assert_eq!(ptr.is_pass(), true);
        assert_eq!(ptr.raw(), "ptr");
        assert_eq!(ptr.to_string(), "ptr");
    }
    #[test]
    fn ptr_with_mechanism() {
        let ptr =
            Mechanism::new_ptr_with_mechanism(Qualifier::Neutral, String::from("example.com"));
        assert_eq!(ptr.is_neutral(), true);
        assert_eq!(ptr.raw(), "example.com");
        assert_eq!(ptr.to_string(), "?ptr:example.com");
    }
}
#[cfg(test)]
mod redirect {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn test_redirect() {
        let redirect = Mechanism::new_redirect(Qualifier::Pass, String::from("_spf.example.com"));
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.raw(), "_spf.example.com");
        assert_eq!(redirect.to_string(), "redirect=_spf.example.com");
    }
}
#[doc(hidden)]
#[cfg(test)]
#[allow(non_snake_case)]
mod Ip4 {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn ip4_pass() {
        let ip4_pass = Mechanism::new_ip4(Qualifier::Pass, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_pass.is_pass(), true);
        assert_eq!(ip4_pass.raw(), "203.32.160.10/32");
        assert_eq!(ip4_pass.to_string(), "ip4:203.32.160.10/32");
        assert_eq!(ip4_pass.as_network().ip().to_string(), "203.32.160.10");
        assert_eq!(ip4_pass.as_network().prefix().to_string(), "32");
        assert_eq!(ip4_pass.as_network().network().to_string(), "203.32.160.10");
    }
    #[test]
    fn ip4_fail() {
        let ip4_fail = Mechanism::new_ip4(Qualifier::Fail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_fail.is_fail(), true);
        assert_eq!(ip4_fail.to_string(), "-ip4:203.32.160.10/32");
    }
    #[test]
    fn ip4_softfail() {
        let ip4_softfail =
            Mechanism::new_ip4(Qualifier::SoftFail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_softfail.is_softfail(), true);
        assert_eq!(ip4_softfail.to_string(), "~ip4:203.32.160.10/32");
    }
    #[test]
    fn ip4_neutral() {
        let ip4_neutral =
            Mechanism::new_ip4(Qualifier::Neutral, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_neutral.is_neutral(), true);
        assert_eq!(ip4_neutral.to_string(), "?ip4:203.32.160.10/32");
    }
}

#[doc(hidden)]
#[cfg(test)]
#[allow(non_snake_case)]
mod ip6 {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn ip6_pass() {
        let ip_pass = Mechanism::new_ip6(Qualifier::Pass, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_pass.is_pass(), true);
        assert_eq!(ip_pass.raw(), "2001:4860:4000::/36");
        assert_eq!(ip_pass.to_string(), "ip6:2001:4860:4000::/36");
    }
    #[test]
    fn ip6_fail() {
        let ip_fail = Mechanism::new_ip6(Qualifier::Fail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_fail.is_fail(), true);
        assert_eq!(ip_fail.to_string(), "-ip6:2001:4860:4000::/36");
    }
    #[test]
    fn ip6_softfail() {
        let ip_softfail =
            Mechanism::new_ip6(Qualifier::SoftFail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_softfail.is_softfail(), true);
        assert_eq!(ip_softfail.to_string(), "~ip6:2001:4860:4000::/36");
    }
    #[test]
    fn ip6_neutral() {
        let ip_neutral =
            Mechanism::new_ip6(Qualifier::Neutral, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_neutral.is_neutral(), true);
        assert_eq!(ip_neutral.to_string(), "?ip6:2001:4860:4000::/36");
    }
}
#[cfg(test)]
#[allow(non_snake_case)]
mod all {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn new_all() {
        let a_mechanism = Mechanism::new_all(Qualifier::Fail);
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "all");
        assert_eq!(a_mechanism.to_string(), "-all");
    }
}
