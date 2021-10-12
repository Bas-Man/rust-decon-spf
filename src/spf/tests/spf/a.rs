#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_a_mechanism() {
        let input = "v=spf1 a ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let result = spf.parse();
        assert_eq!(result.is_ok(), true);
        assert_eq!(spf.version(), "v=spf1");
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_pass(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "a");
        assert_eq!(spf.all().unwrap().is_softfail(), true);
        assert_eq!(spf.all().unwrap().to_string(), "~all");
    }
    #[test]
    fn test_a_mechanism_slash() {
        let input = "v=spf1 -a/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_fail(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "-a/24");
    }
    #[test]
    fn test_a_mechanism_colon() {
        let input = "v=spf1 ?a:example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_neutral(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "?a:example.com");
    }
    #[test]
    fn test_a_mechanism_colon_slash() {
        let input = "v=spf1 ~a:example.com/24 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].is_softfail(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "~a:example.com/24");
    }
}
