#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_exist() {
        let input = "v=spf1 ptr ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().string(), "ptr");
    }
    #[test]
    fn test_exist_colon() {
        let input = "v=spf1 ptr:host.example.com ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().string(), "ptr:host.example.com");
    }
}
