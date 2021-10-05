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
