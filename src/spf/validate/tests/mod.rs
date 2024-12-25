mod string;

#[cfg(test)]
#[cfg(feature = "builder")]
mod validate {
    use crate::spf::builder::{Builder, SpfBuilder};
    use crate::spf::mechanism::{Mechanism, Qualifier};

    #[test]
    fn validate() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        let spf = spf.build().unwrap();
        assert!(spf.validate().is_ok());
    }
    #[test]
    // todo: This needs to be fixed
    fn invalidate() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        //spf.set_v1();
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.add_ip(Mechanism::ip(
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
