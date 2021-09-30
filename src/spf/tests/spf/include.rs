#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_include() {
        let input = "v=spf1 include:_spf.example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.includes().is_some());
        assert_eq!(spf.includes().unwrap()[0].is_pass(), true);
        assert_eq!(spf.includes().unwrap()[0].raw(), "_spf.example.com");
        assert_eq!(
            spf.includes().unwrap()[0].string(),
            "include:_spf.example.com"
        );
    }
}
