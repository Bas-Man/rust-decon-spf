#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_exist() {
        let input = "v=spf1 ptr ~all";

        let spf: Spf = input.parse().unwrap();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().to_string(), "ptr");
    }
    #[test]
    fn test_exist_colon() {
        let input = "v=spf1 ptr:host.example.com ~all";

        let spf: Spf = input.parse().unwrap();
        assert_eq!(spf.ptr().unwrap().is_pass(), true);
        assert_eq!(spf.ptr().unwrap().to_string(), "ptr:host.example.com");
    }
}
