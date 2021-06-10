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
        assert_eq!(test.raw(), ":example.com");
    }
}
#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_exist() {
        let input = "v=spf1 ptr ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().mechanism(), "ptr");
        assert_eq!(spf.ptr().unwrap().string(), "ptr");
    }
    #[test]
    fn test_exist_colon() {
        let input = "v=spf1 ptr:host.example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().mechanism(), ":host.example.com");
        assert_eq!(spf.ptr().unwrap().string(), "ptr:host.example.com");
    }
}
