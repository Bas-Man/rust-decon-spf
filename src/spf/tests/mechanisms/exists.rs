#[cfg(test)]

mod capture {

    use crate::mechanism::Mechanism;
    use crate::mechanism::MechanismKind;
    use crate::spf::helpers;

    #[test]
    fn test_match_on_exists() {
        let string = "exists:a.example.com";
        let option_test: Option<Mechanism<String>>;

        option_test = helpers::capture_matches(&string, MechanismKind::Exists);

        let test = option_test.unwrap();
        assert_eq!(test.is_pass(), true);
        assert_eq!(test.raw(), "a.example.com");
        assert_eq!(test.to_string(), "exists:a.example.com");
    }
}
