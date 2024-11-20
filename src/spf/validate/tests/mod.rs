mod string;

#[cfg(test)]
#[cfg(feature = "builder")]
mod validate {
    use crate::spf::builder::SpfBuilder;
    use crate::spf::mechanism::{Mechanism, Qualifier};
    use crate::spf::validate::SpfRfcStandard;

    #[test]
    fn validate() {
        let mut spf = SpfBuilder::new();
        spf.set_v1();
        spf.append_ip_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.append_ip_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        assert_eq!(
            spf.validate_to_string(SpfRfcStandard::Rfc4408).to_string(),
            "v=spf1 ip4:203.32.160.0/23 ip6:2001:5160:4000::/36".to_string()
        );
        let res = spf.validate(SpfRfcStandard::Rfc4408);
        assert_eq!(res.is_ok(), true);
        let res2 = res.unwrap();
        assert_eq!(
            res2.to_string(),
            "v=spf1 ip4:203.32.160.0/23 ip6:2001:5160:4000::/36".to_string()
        );
    }
    #[test]
    // todo: This needs to be fixed
    fn invalidate() {
        let mut spf = SpfBuilder::new();
        //spf.set_v1();
        spf.append_ip_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.append_ip_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        /*assert_eq!(
            spf.validate_to_string(SpfRfcStandard::Rfc4408).to_string(),
            "Source string not valid.".to_string()
        );
        let res = spf.validate(SpfRfcStandard::Rfc4408);
        assert_eq!(res.is_err(), true);
        let res2 = res.unwrap_err();
        assert_eq!(res2.to_string(), "Source string not valid.".to_string());

         */
    }
    /*
        #[test]
        #[cfg(feature = "ptr")]
        fn invalidate_with_ptr() {
            let input = "v=spf1 a ptr -all";
            let mut spf: SpfBuilder = input.parse().unwrap();

            let res = spf.validate(SpfRfcStandard::Rfc4408).unwrap_err();
            assert_eq!(res, SpfError::DeprecatedPtrPresent);
        }
        #[test]
        fn invalidate_redirect_all() {
            let input = "v=spf1 redirect=_spf.example.com -all";
            let mut spf: SpfBuilder = input.parse().unwrap();

            let res = spf.validate(SpfRfcStandard::Rfc4408).unwrap_err();
            assert_eq!(res, SpfError::RedirectWithAllMechanism);
        }
    */
}
