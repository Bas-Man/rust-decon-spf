#[cfg(test)]

mod exists_parse {

    use crate::spf::Spf;

    #[test]
    fn test_exist() {
        let input = "v=spf1 exists:example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        spf.parse();
        assert!(spf.exists().is_some());
        assert_eq!(spf.exists().unwrap()[0].is_pass(), true);
        assert_eq!(spf.exists().unwrap()[0].mechanism(), "example.com");
        assert_eq!(spf.exists().unwrap()[0].string(), "exists:example.com");
    }
}
