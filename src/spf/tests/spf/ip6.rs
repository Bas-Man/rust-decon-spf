#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_ip6_valid() {
        let input = "v=spf1 ip6:2001:4860:4000::/36 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.ip6().is_some());
        assert_eq!(spf.ip6().unwrap()[0].is_pass(), true);
        assert_eq!(spf.ip6().unwrap()[0].raw(), "2001:4860:4000::/36");
        assert_eq!(spf.ip6().unwrap()[0].string(), "ip6:2001:4860:4000::/36");
    }
}
