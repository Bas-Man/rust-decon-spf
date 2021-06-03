#[cfg(test)]

mod mx_capture {

    use crate::spf::helpers;
    use crate::spf::kinds;
    use crate::spf::mechanism::Mechanism;
    use regex::Regex;
    #[test]
    fn test_match_on_mx_only() {
        let string = "mx";
        let pattern = Regex::new(r"^(?P<qualifier>[+?~-])?mx(?P<mechanism>[:/]{0,1}.+)?").unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "mx");
        assert_eq!(test.string(), "mx");
    }
    #[test]
    fn test_match_on_mx_colon() {
        let string = "-mx:example.com";
        let pattern = Regex::new(r"^(?P<qualifier>[+?~-])?mx(?P<mechanism>[:/]{0,1}.+)?").unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_fail(), true);
        assert_eq!(test.raw(), ":example.com");
        assert_eq!(test.string(), "-mx:example.com");
    }
    #[test]
    fn test_match_on_mx_slash() {
        let string = "~mx/24";
        let pattern = Regex::new(r"^(?P<qualifier>[+?~-])?mx(?P<mechanism>[:/]{0,1}.+)?").unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_softfail(), true);
        assert_eq!(test.raw(), "/24");
        assert_eq!(test.string(), "~mx/24");
    }
    #[test]
    fn test_match_on_mx_colon_slash() {
        let string = "+mx:example.com/24";
        let pattern = Regex::new(r"^(?P<qualifier>[+?~-])?mx(?P<mechanism>[:/]{0,1}.+)?").unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), ":example.com/24");
        assert_eq!(test.string(), "mx:example.com/24");
    }
}
