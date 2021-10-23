#[cfg(test)]
mod validate {
    use crate::mechanism::{MechanismImpl, Qualifier};
    use crate::spf::Spf;
    use crate::spf::SpfRfcStandard;

    #[test]
    fn validate() {
        let mut spf = Spf::new();
        spf.set_v1();
        spf.append_ip_mechanism(MechanismImpl::new_ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.append_ip_mechanism(MechanismImpl::new_ip(
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
        assert_eq!(res2.is_valid(), true);
        assert_eq!(
            res2.to_string(),
            "v=spf1 ip4:203.32.160.0/23 ip6:2001:5160:4000::/36".to_string()
        );
    }
    #[test]
    fn invalidate() {
        let mut spf = Spf::new();
        //spf.set_v1();
        spf.append_ip_mechanism(MechanismImpl::new_ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        spf.append_ip_mechanism(MechanismImpl::new_ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        assert_eq!(
            spf.validate_to_string(SpfRfcStandard::Rfc4408).to_string(),
            "Source string not valid.".to_string()
        );
        let res = spf.validate(SpfRfcStandard::Rfc4408);
        assert_eq!(res.is_err(), true);
        let res2 = res.unwrap_err();
        assert_eq!(res2.to_string(), "Source string not valid.".to_string());
    }
}
