#[cfg(test)]

mod invalid_mechanism_str {

    use crate::mechanism::{Mechanism, MechanismError};

    #[test]
    fn unsupported_mechanism_str() {
        let input = "redirect:_spf.example.com";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
        assert_eq!(err.is_invalid_format(), true);
    }
}

#[cfg(test)]

mod redirect {

    use crate::mechanism::Mechanism;

    #[test]
    fn valid() {
        let input = "redirect=_spf.example.com";

        let m: Mechanism<String> = input.parse().unwrap();
        assert_eq!(m.kind().is_redirect(), true);
        assert_eq!(m.raw(), "_spf.example.com");
        assert_eq!(m.to_string(), "redirect=_spf.example.com");
    }
}

#[cfg(test)]
mod include {

    use crate::mechanism::Mechanism;

    #[test]
    fn valid() {
        let input = "include:example.com";

        let m: Mechanism<String> = input.parse().unwrap();
        assert_eq!(m.kind().is_include(), true);
        assert_eq!(m.raw(), "example.com");
        assert_eq!(m.to_string(), input);
    }
    #[test]
    fn valid_pass() {
        let input = "+include:example.com";

        let m: Mechanism<String> = input.parse().unwrap();
        assert_eq!(m.kind().is_include(), true);
        assert_eq!(m.raw(), "example.com");
        assert_eq!(m.to_string(), "include:example.com");
    }
    #[test]
    fn valid_neutral() {
        let input = "~include:example.com";

        let m: Mechanism<String> = input.parse().unwrap();
        assert_eq!(m.kind().is_include(), true);
        assert_eq!(m.raw(), "example.com");
        assert_eq!(m.to_string(), "~include:example.com");
    }
}
