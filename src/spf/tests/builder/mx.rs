mod parse {

    use crate::SpfBuilder;

    #[test]
    fn test_mx_mechanism() {
        let input = "v=spf1 mx ~all";

        let spf: SpfBuilder<_> = input.parse().unwrap();

        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].qualifier().is_pass(), true);
        assert_eq!(spf.mx().unwrap()[0].to_string(), "mx");
    }
    #[test]
    fn test_mx_mechanism_slash() {
        let input = "v=spf1 -mx/24 ~all";

        let spf: SpfBuilder<_> = input.parse().unwrap();

        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].qualifier().is_fail(), true);
        assert_eq!(spf.mx().unwrap()[0].to_string(), "-mx/24");
    }
    #[test]
    fn test_mx_mechanism_colon() {
        let input = "v=spf1 ?mx:example.com ~all";

        let spf: SpfBuilder<_> = input.parse().unwrap();

        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].qualifier().is_neutral(), true);
        assert_eq!(spf.mx().unwrap()[0].to_string(), "?mx:example.com");
    }
    #[test]
    fn test_mx_mechanism_colon_slash() {
        let input = "v=spf1 ~mx:example.com/24 ~all";

        let spf: SpfBuilder<_> = input.parse().unwrap();

        assert!(spf.mx().is_some());
        assert_eq!(spf.mx().unwrap()[0].qualifier().is_softfail(), true);
        assert_eq!(spf.mx().unwrap()[0].to_string(), "~mx:example.com/24");
    }
    mod invalid {
        // needs fail tests : / only tests and strict-dns
    }
}
