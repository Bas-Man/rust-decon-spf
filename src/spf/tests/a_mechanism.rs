#[cfg(test)]

mod test_a_mechanism {

    use crate::spf::Spf;

    #[test]
    fn test_simple_a_mechanism() {
        let input = "v=spf1 a ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.a().as_ref().is_some());
        assert_eq!(spf.a().as_ref().unwrap()[0].is_pass(), true);
        assert_eq!(spf.a().as_ref().unwrap()[0].as_string(), "a");
        assert_eq!(spf.a().as_ref().unwrap()[0].as_mechanism(), "a");
    }
    #[test]
    fn test_a_mechanism_slash() {
        let input = "v=spf1 -a/24 ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.a().as_ref().is_some());
        assert_eq!(spf.a().as_ref().unwrap()[0].is_fail(), true);
        assert_eq!(spf.a().as_ref().unwrap()[0].as_string(), "a/24");
        assert_eq!(spf.a().as_ref().unwrap()[0].as_mechanism(), "-a/24");
    }
    #[test]
    fn test_a_mechanism_colon() {
        let input = "v=spf1 ?a:example.com ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.a().as_ref().is_some());
        assert_eq!(spf.a().as_ref().unwrap()[0].is_neutral(), true);
        assert_eq!(spf.a().as_ref().unwrap()[0].as_string(), "a:example.com");
        assert_eq!(
            spf.a().as_ref().unwrap()[0].as_mechanism(),
            "?a:example.com"
        );
    }
    #[test]
    fn test_a_mechanism_colon_slash() {
        let input = "v=spf1 ~a:example.com/24 ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.a().as_ref().is_some());
        assert_eq!(spf.a().as_ref().unwrap()[0].is_softfail(), true);
        assert_eq!(spf.a().as_ref().unwrap()[0].as_string(), "a:example.com/24");
        assert_eq!(
            spf.a().as_ref().unwrap()[0].as_mechanism(),
            "~a:example.com/24"
        );
    }
}
