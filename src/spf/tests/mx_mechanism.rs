#[cfg(test)]

mod mx_mechanism {

    use crate::spf::Spf;

    #[test]
    fn test_simple_mx_mechanism() {
        let input = "v=spf1 mx ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.mx().as_ref().is_some());
        assert_eq!(spf.mx().as_ref().unwrap()[0].is_pass(), true);
        assert_eq!(spf.mx().as_ref().unwrap()[0].as_string(), "mx");
        assert_eq!(spf.mx().as_ref().unwrap()[0].as_mechanism(), "mx");
    }
    #[test]
    fn test_mx_mechanism_slash() {
        let input = "v=spf1 -mx/24 ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.mx().as_ref().is_some());
        assert_eq!(spf.mx().as_ref().unwrap()[0].is_fail(), true);
        assert_eq!(spf.mx().as_ref().unwrap()[0].as_string(), "mx/24");
        assert_eq!(spf.mx().as_ref().unwrap()[0].as_mechanism(), "-mx/24");
    }
    #[test]
    fn test_mx_mechanism_colon() {
        let input = "v=spf1 ?mx:example.com ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.mx().as_ref().is_some());
        assert_eq!(spf.mx().as_ref().unwrap()[0].is_neutral(), true);
        assert_eq!(spf.mx().as_ref().unwrap()[0].as_string(), "mx:example.com");
        assert_eq!(
            spf.mx().as_ref().unwrap()[0].as_mechanism(),
            "?mx:example.com"
        );
    }
    #[test]
    fn test_mx_mechanism_colon_slash() {
        let input = "v=spf1 ~mx:example.com/24 ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert!(spf.mx().as_ref().is_some());
        assert_eq!(spf.mx().as_ref().unwrap()[0].is_softfail(), true);
        assert_eq!(
            spf.mx().as_ref().unwrap()[0].as_string(),
            "mx:example.com/24"
        );
        assert_eq!(
            spf.mx().as_ref().unwrap()[0].as_mechanism(),
            "~mx:example.com/24"
        );
    }
}
