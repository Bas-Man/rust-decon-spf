#[cfg(test)]
#[allow(non_snake_case)]
mod String {

    use crate::spf::Qualifier;
    use crate::spf::SpfMechanism;
    #[test]
    fn test_redirect() {
        let redirect =
            SpfMechanism::new_redirect(Qualifier::Pass, String::from("_spf.example.com"));
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.raw(), "_spf.example.com");
        assert_eq!(redirect.string(), "redirect=_spf.example.com");
    }
    #[test]
    fn test_include_pass() {
        let include = SpfMechanism::new_include(Qualifier::Pass, String::from("_spf.test.com"));
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.raw(), "_spf.test.com");
        assert_eq!(include.string(), "include:_spf.test.com");
    }
    #[test]
    fn test_include_fail() {
        let include = SpfMechanism::new_include(Qualifier::Fail, String::from("_spf.test.com"));
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.string(), "-include:_spf.test.com");
    }
    #[test]
    fn test_include_softfail() {
        let include = SpfMechanism::new_include(Qualifier::SoftFail, String::from("_spf.test.com"));
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.string(), "~include:_spf.test.com");
    }
    #[test]
    fn test_include_neutral() {
        let include = SpfMechanism::new_include(Qualifier::Neutral, String::from("_spf.test.com"));
        assert_eq!(include.is_neutral(), true);
        assert_eq!(include.string(), "?include:_spf.test.com");
    }
    #[test]
    fn test_new_a() {
        let a_mechanism = SpfMechanism::new_a(Qualifier::Fail, "a".to_string());
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "a");
    }
}
