#[cfg(test)]

mod capture {

    use crate::spf::helpers;
    use crate::spf::kinds;
    use crate::spf::mechanism::Mechanism;
    use crate::spf::MECHANISM_A_PATTERN;
    use regex::Regex;

    #[test]
    fn test_match_on_a_only() {
        let string = "a";
        let pattern = Regex::new(MECHANISM_A_PATTERN).unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "a");
        assert_eq!(test.string(), "a");
    }
    #[test]
    fn test_match_on_a_colon() {
        let string = "-a:example.com";
        let pattern = Regex::new(MECHANISM_A_PATTERN).unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_fail(), true);
        assert_eq!(test.raw(), ":example.com");
        assert_eq!(test.string(), "-a:example.com");
    }
    #[test]
    fn test_match_on_a_slash() {
        let string = "~a/24";
        let pattern = Regex::new(MECHANISM_A_PATTERN).unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_softfail(), true);
        assert_eq!(test.raw(), "/24");
        assert_eq!(test.string(), "~a/24");
    }
    #[test]
    fn test_match_on_a_colon_slash() {
        let string = "+a:example.com/24";
        let pattern = Regex::new(MECHANISM_A_PATTERN).unwrap();
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(pattern, &string, kinds::MechanismKind::A);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), ":example.com/24");
        assert_eq!(test.string(), "a:example.com/24");
        //assert!(test.kind.is_a());
    }
}
#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_a_mechanism() {
        let input = "v=spf1 a ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert_eq!(spf.version(), "v=spf1");
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_pass(), true);
        assert_eq!(spf.a().unwrap()[0].mechanism(), "a");
        assert_eq!(spf.a().unwrap()[0].string(), "a");
        assert_eq!(spf.all().unwrap().is_softfail(), true);
        //assert_eq!(spf.all().unwrap().mechanism(), "all");
        assert_eq!(spf.all().unwrap().string(), "~all");
    }
    #[test]
    fn test_a_mechanism_slash() {
        let input = "v=spf1 -a/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_fail(), true);
        assert_eq!(spf.a().unwrap()[0].mechanism(), "/24");
        assert_eq!(spf.a().unwrap()[0].string(), "-a/24");
    }
    #[test]
    fn test_a_mechanism_colon() {
        let input = "v=spf1 ?a:example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_neutral(), true);
        assert_eq!(spf.a().unwrap()[0].mechanism(), ":example.com");
        assert_eq!(spf.a().unwrap()[0].string(), "?a:example.com");
    }
    #[test]
    fn test_a_mechanism_colon_slash() {
        let input = "v=spf1 ~a:example.com/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_softfail(), true);
        assert_eq!(spf.a().unwrap()[0].mechanism(), ":example.com/24");
        assert_eq!(spf.a().unwrap()[0].string(), "~a:example.com/24");
    }
}
