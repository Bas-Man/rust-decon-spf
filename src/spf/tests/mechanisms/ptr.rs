#[cfg(test)]

mod capture {

    use crate::spf::helpers;
    use crate::spf::kinds;
    use crate::spf::mechanism::Mechanism;

    #[test]
    fn test_match_on_ptr() {
        let string = "ptr";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::Ptr);
        assert!(option_test.is_some());

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "ptr");
        assert_eq!(test.string(), "ptr");
    }
    #[test]
    fn test_match_on_ptr_colon() {
        let string = "ptr:example.com";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::Ptr);
        assert!(option_test.is_some());

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "example.com");
    }
}
