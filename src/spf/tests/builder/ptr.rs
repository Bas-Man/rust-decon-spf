#[cfg(not(feature = "ptr"))]
mod parse {

    use crate::spf::SpfBuilder;
    #[test]
    fn test_exist() {
        let input = "v=spf1 ptr ~all";

        let spf: SpfBuilder = input.parse().unwrap();
        assert_eq!(spf.ptr().unwrap().qualifier().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().to_string(), "ptr");
    }
    #[test]
    fn test_exist_colon() {
        let input = "v=spf1 ptr:host.example.com ~all";

        let spf: SpfBuilder = input.parse().unwrap();
        assert_eq!(spf.ptr().unwrap().qualifier().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().to_string(), "ptr:host.example.com");
    }
    mod invalid {
        use super::*;
        use crate::mechanism::MechanismError;
        use crate::spf::SpfError;

        #[test]
        fn exists_with_slash() {
            let input = "v=spf1 ptr:host.example.com/23 -all";

            let err = input.parse::<SpfBuilder>().unwrap_err();
            assert_eq!(
                err,
                SpfError::InvalidMechanism(MechanismError::InvalidMechanismFormat(
                    "ptr:host.example.com/23".to_string()
                ))
            )
        }
    }
}
