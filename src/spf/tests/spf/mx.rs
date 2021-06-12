#[cfg(test)]

mod capture {

    use crate::spf::helpers;
    use crate::spf::kinds;
    use crate::spf::mechanism::Mechanism;
    #[test]
    fn test_match_on_mx_only() {
        let string = "mx";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "mx");
        assert_eq!(test.string(), "mx");
    }
    #[test]
    fn test_match_on_mx_colon() {
        let string = "-mx:example.com";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_fail(), true);
        assert_eq!(test.raw(), "example.com");
        assert_eq!(test.string(), "-mx:example.com");
    }
    #[test]
    fn test_match_on_mx_slash() {
        let string = "~mx/24";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_softfail(), true);
        assert_eq!(test.raw(), "/24");
        assert_eq!(test.string(), "~mx/24");
    }
    #[test]
    fn test_match_on_mx_colon_slash() {
        let string = "+mx:example.com/24";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, kinds::MechanismKind::MX);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "example.com/24");
        assert_eq!(test.string(), "mx:example.com/24");
    }
}
#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_mx_mechanism() {
        let input = "v=spf1 mx ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].is_pass(), true);
        assert_eq!(spf.mx().unwrap()[0].string(), "mx");
    }
    #[test]
    fn test_mx_mechanism_slash() {
        let input = "v=spf1 -mx/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].is_fail(), true);
        assert_eq!(spf.mx().unwrap()[0].string(), "-mx/24");
    }
    #[test]
    fn test_mx_mechanism_colon() {
        let input = "v=spf1 ?mx:example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].is_neutral(), true);
        assert_eq!(spf.mx().unwrap()[0].string(), "?mx:example.com");
    }
    #[test]
    fn test_mx_mechanism_colon_slash() {
        let input = "v=spf1 ~mx:example.com/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].is_softfail(), true);
        assert_eq!(spf.mx().unwrap()[0].string(), "~mx:example.com/24");
    }
}
