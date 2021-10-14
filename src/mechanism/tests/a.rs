#[cfg(test)]

mod capture {

    use crate::helpers;
    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismKind;

    #[test]
    fn test_match_on_a_only() {
        let string = "a";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "a");
        assert_eq!(test.to_string(), "a");
    }
    #[test]
    fn test_match_on_a_colon() {
        let string = "-a:example.com";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_fail(), true);
        assert_eq!(test.raw(), "example.com");
        assert_eq!(test.to_string(), "-a:example.com");
    }
    #[test]
    fn test_match_on_a_slash() {
        let string = "~a/24";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_softfail(), true);
        assert_eq!(test.raw(), "/24");
        assert_eq!(test.to_string(), "~a/24");
    }
    #[test]
    fn test_match_on_a_colon_slash() {
        let string = "+a:example.com/24";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "example.com/24");
        assert_eq!(test.to_string(), "a:example.com/24");
    }
}
