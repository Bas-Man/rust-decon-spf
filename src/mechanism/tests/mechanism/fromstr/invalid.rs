#[cfg(test)]

mod general {

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
    #[test]
    fn unsupported_mechanism_str_a() {
        let input = "abc.com";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn unsupported_mechanism_str_mx() {
        let input = "+mx.com";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn supported_mechanism_str_ends_with_colon() {
        let input = "+mx:";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn supported_mechanism_str_ends_with_slash() {
        let input = "+a/";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn blank_exists() {
        let input = "exists";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn blank_exists_colon() {
        let input = "exists:";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
    #[test]
    fn blank_exists_slash() {
        let input = "exists:test.com/24";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(err.is_invalid_format(), true);
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat(input.to_string())
        );
    }
}
