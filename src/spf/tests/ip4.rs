#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_ip4_valid() {
        let input = "v=spf1 ip4:10.0.0.0/23 ~all";

        let spf: Spf = input.parse().unwrap();
        assert!(spf.ip4().is_some());
        assert_eq!(spf.ip4().unwrap()[0].qualifier().is_pass(), true);
        assert_eq!(spf.ip4().unwrap()[0].raw(), "10.0.0.0/23");
        assert_eq!(spf.ip4().unwrap()[0].to_string(), "ip4:10.0.0.0/23");
        assert_eq!(spf.ip4().unwrap()[0].as_network().prefix(), 23);
        assert_eq!(spf.to_string(), "v=spf1 ip4:10.0.0.0/23 ~all");
    }
}
