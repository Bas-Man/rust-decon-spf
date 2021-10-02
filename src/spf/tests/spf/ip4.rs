#[cfg(test)]

mod parse {

    use crate::spf::Spf;

    #[test]
    fn test_ip4_valid() {
        let input = "v=spf1 ip4:10.0.0.0/23 ~all";

        let mut spf = Spf::from_str(&input.to_string());
        let _ = spf.parse();
        assert!(spf.ip4().is_some());
        assert_eq!(spf.ip4().unwrap()[0].is_pass(), true);
        assert_eq!(spf.ip4().unwrap()[0].raw(), "10.0.0.0/23");
        assert_eq!(spf.ip4().unwrap()[0].string(), "ip4:10.0.0.0/23");
        //assert_eq!(spf.as_spf().unwrap(), "v=spf1 ip4:10.0.0.0/23 ~all");
    }
}
