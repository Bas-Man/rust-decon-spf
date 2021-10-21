#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_exist() {
        let input = "v=spf1 exists:example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.exists().is_some());
        assert_eq!(spf.exists().unwrap()[0].is_pass(), true);
        assert_eq!(spf.exists().unwrap()[0].raw(), "example.com");
        assert_eq!(spf.exists().unwrap()[0].to_string(), "exists:example.com");
    }
}