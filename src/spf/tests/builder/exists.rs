mod parse {
    use crate::mechanism::MechanismError;
    use crate::SpfBuilder;
    use crate::{Mechanism, Qualifier, SpfError};

    #[test]
    fn test_exist() {
        let mut spf: SpfBuilder = SpfBuilder::new();
        spf.set_v1()
            .append_string_mechanism(Mechanism::exists(Qualifier::Pass, "example.com").unwrap())
            .append_string_mechanism(Mechanism::all_with_qualifier(Qualifier::SoftFail).into());
        assert!(spf.exists().is_some());
        assert_eq!(spf.exists().unwrap()[0].qualifier().is_pass(), true);
        assert_eq!(spf.exists().unwrap()[0].raw(), "example.com");
        assert_eq!(spf.exists().unwrap()[0].to_string(), "exists:example.com");
    }

    mod invalid {
        use super::*;

        #[test]
        fn with_slash() {
            let input = "v=spf1 exists:example.com/ ~all";
            let invalid_str = "exists:example.com/";

            let err: SpfError = input.parse::<SpfBuilder>().unwrap_err();
            assert_eq!(
                err,
                SpfError::InvalidMechanism(MechanismError::InvalidMechanismFormat(
                    invalid_str.to_string()
                ))
            );
        }
    }
}
