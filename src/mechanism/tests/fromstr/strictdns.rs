mod a {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    fn basic_pass_rrdata_invalid_domain() {
        let input = "+a:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
    }
}
mod include {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    fn basic_pass_rrdata_invalid_domain() {
        let input = "+include:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
    }
}
mod mx {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    fn basic_pass_rrdata_invalid_domain() {
        let input = "+mx:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
    }
}
mod ptr {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    fn basic_pass_rrdata_invalid_domain() {
        let input = "+ptr:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
    }
}
mod exists {
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismError;
    #[test]
    fn basic_pass_rrdata_invalid_domain() {
        let input = "+exists:example.xx";

        let m: Result<Mechanism<String>, MechanismError> = input.parse();
        let err = m.unwrap_err();
        assert_eq!(err.to_string(), "Invalid DNS string: example.xx");
    }
}
