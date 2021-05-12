#[cfg(test)]

mod spf {

    use crate::spf::Spf;

    #[test]
    fn test_redirect() {
        let input = "v=spf1 redirect=_spf.google.com";

        let mut spf = Spf::new(&input.to_string());
        assert_eq!(input, spf.source());
        spf.parse();
        assert_eq!(spf.is_redirect(), true);
        assert_eq!(spf.include.is_none(), true);
        assert_eq!(spf.a.is_none(), true);
        assert_eq!(spf.mx.is_none(), true);
        assert_eq!(spf.ip4.is_none(), true);
        assert_eq!(spf.ip6.is_none(), true);
    }
    #[test]
    fn test_hotmail() {
        let input = "v=spf1 ip4:157.55.9.128/25 include:spf.protection.outlook.com include:spf-a.outlook.com include:spf-b.outlook.com include:spf-a.hotmail.com include:_spf-ssg-b.microsoft.com include:_spf-ssg-c.microsoft.com ~all";

        let mut spf = Spf::new(&input.to_string());
        assert_eq!(input, spf.source());
        spf.parse();
        assert_eq!(spf.is_redirect(), false);
        assert_eq!(!spf.includes().as_ref().unwrap().is_empty(), true);
        assert_eq!(spf.includes().as_ref().unwrap().len(), 6);
        assert_eq!(
            spf.includes().as_ref().unwrap()[0].as_mechanism(),
            "include:spf.protection.outlook.com"
        );
        assert_eq!(spf.ip4().as_ref().unwrap().len(), 1);
        assert_eq!(
            spf.ip4().as_ref().unwrap()[0].as_mechanism(),
            "ip4:157.55.9.128/25"
        );
        assert_eq!(*spf.all(), '~');
    }
    #[test]
    fn test_netblocks2_google_com() {
        let input = "v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all";

        let mut spf = Spf::new(&input.to_string());
        spf.parse();
        assert_eq!(spf.includes().as_ref().is_none(), true);
        assert_eq!(spf.ip4().as_ref().is_none(), true);
        assert_eq!(!spf.ip6().as_ref().is_none(), true);
        assert_eq!(spf.ip6().as_ref().unwrap().len(), 6);
        assert_eq!(
            spf.ip6().as_ref().unwrap()[0].as_mechanism(),
            "ip6:2001:4860:4000::/36"
        );
        assert_eq!(*spf.all(), '~');
    }
}
