#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod a {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    #[cfg(feature = "strict-dns")]
    fn basic_pass_a_rrdata_invalid_domain() {
        let input = "+a:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod includes {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    #[cfg(feature = "strict-dns")]
    fn basic_pass_include_rrdata_invalid_domain() {
        let input = "+include:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod mx {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    #[cfg(feature = "strict-dns")]
    fn basic_pass_mx_rrdata_invalid_domain() {
        let input = "+mx:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod ptr {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    #[cfg(feature = "strict-dns")]
    fn basic_pass_ptr_rrdata_invalid_domain() {
        let input = "+ptr:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod exists {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    #[cfg(feature = "strict-dns")]
    fn basic_pass_exists_rrdata_invalid_domain() {
        let input = "+exists:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
