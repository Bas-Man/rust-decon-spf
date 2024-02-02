#[allow(non_snake_case)]
mod A {

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

#[allow(non_snake_case)]
mod MX {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn new_mx_without_mechanism() {
        let mx = Mechanism::mx(Qualifier::Pass);
        assert_eq!(mx.is_pass(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "mx");
    }
    #[test]
    fn new_mx_without_mechanism_softfail() {
        let mx = Mechanism::mx(Qualifier::SoftFail);
        assert_eq!(mx.is_softfail(), true);
        assert_eq!(mx.raw(), "mx");
        assert_eq!(mx.to_string(), "~mx");
    }
}

#[allow(non_snake_case)]
mod PTR {

    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;

    #[test]
    fn ptr_without_mechanism() {
        let ptr = Mechanism::ptr(Qualifier::Pass);
        assert_eq!(ptr.is_pass(), true);
        assert_eq!(ptr.raw(), "ptr");
        assert_eq!(ptr.to_string(), "ptr");
    }
}
#[allow(non_snake_case)]
mod Ip4 {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    use crate::mechanism::Qualifier;

    #[test]
    fn ip4_from_string_valid() {
        let string = String::from("ip4:203.32.160.10/32");
        let ip4 = Mechanism::ip_from_string(&string);
        let unwrapped = ip4.unwrap();
        assert_eq!(unwrapped.is_pass(), true);
        assert_eq!(unwrapped.to_string(), "ip4:203.32.160.10/32");
    }
    #[test]
    fn ip4_from_string_invalid() {
        let string = String::from("ip:203.32.160.10/32");
        let ip4 = Mechanism::ip_from_string(&string);
        let unwrapped = ip4.unwrap_err();
        assert_eq!(
            unwrapped,
            MechanismError::InvalidMechanismFormat(String::from("ip:203.32.160.10/32"))
        );
    }
}

#[allow(non_snake_case)]
mod ip6 {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    use crate::mechanism::Qualifier;

    #[test]
    fn ip6_from_string_valid() {
        let string = String::from("ip6:2001:4860:4000::/36");
        let ip6 = Mechanism::ip_from_string(&string);
        let unwrapped = ip6.unwrap();
        assert_eq!(unwrapped.is_pass(), true);
        assert_eq!(unwrapped.to_string(), "ip6:2001:4860:4000::/36");
    }
    #[test]
    fn ip6_from_string_invalid() {
        let string = String::from("ip:2001:4860:4000::/36");
        let ip6 = Mechanism::ip_from_string(&string);
        let unwrapped = ip6.unwrap_err();
        assert_eq!(
            unwrapped,
            MechanismError::InvalidMechanismFormat(String::from("ip:2001:4860:4000::/36"))
        );
    }
}
#[allow(non_snake_case)]
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
