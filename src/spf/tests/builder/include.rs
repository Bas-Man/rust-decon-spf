mod parse {

    use crate::SpfBuilder;

    #[test]
    fn test_include() {
        let input = "v=spf1 include:_spf.example.com ~all";

        let spf: SpfBuilder<_> = input.parse().unwrap();
        assert!(spf.includes().is_some());
        assert_eq!(spf.includes().unwrap()[0].qualifier().is_pass(), true);
        assert_eq!(spf.includes().unwrap()[0].raw(), "_spf.example.com");
        assert_eq!(
            spf.includes().unwrap()[0].to_string(),
            "include:_spf.example.com"
        );
    }
}
