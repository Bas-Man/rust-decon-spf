#[cfg(test)]
mod spf1 {

    use crate::spf::Spf;

    #[test]
    fn make_v1() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.version(), "v=spf1");
        assert_eq!(spf.is_v1(), true);
    }
}
#[cfg(test)]
mod spf2 {

    use crate::spf::Spf;

    #[test]
    fn make_v2_pra() {
        let mut spf = Spf::new();
        spf.set_v2_pra();
        assert_eq!(spf.version, "spf2.0/pra");
        assert_eq!(spf.is_v2(), true);
        assert_eq!(spf.version(), "spf2.0/pra")
    }
    #[test]
    fn make_v2_mfrom() {
        let mut spf = Spf::new();
        spf.set_v2_mfrom();
        assert_eq!(spf.version, "spf2.0/mfrom");
        assert_eq!(spf.is_v2(), true);
    }
    #[test]
    fn make_v2_mfrom_pra() {
        let mut spf = Spf::new();
        spf.set_v2_mfrom_pra();
        assert_eq!(spf.version, "spf2.0/mfrom,pra");
        assert_eq!(spf.is_v2(), true);
    }
    #[test]
    fn make_v2_pra_mfrom() {
        let mut spf = Spf::new();
        spf.set_v2_pra_mfrom();
        assert_eq!(spf.version, "spf2.0/pra,mfrom");
        assert_eq!(spf.is_v2(), true);
    }
}

#[cfg(test)]
mod build {

    use crate::spf::Mechanism;
    use crate::spf::Qualifier;
    use crate::spf::Spf;

    #[test]
    fn make_redirect() {
        let mut spf = Spf::new();
        spf.set_v1();
        spf.append_mechanism_of_redirect(Mechanism::new_redirect(
            Qualifier::Pass,
            String::from("_spf.example.com"),
        ));
        assert_eq!(
            spf.as_spf(),
            Some("v=spf1 redirect=_spf.example.com".to_string())
        );
        assert_eq!(spf.is_redirect(), true);
        spf.remove_mechanism_redirect();
        assert_eq!(spf.is_redirect(), false);
        assert_eq!(spf.redirect.is_none(), true);
    }

    #[test]
    fn make_a_all() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.is_v1(), true);
        spf.append_mechanism_of_a(Mechanism::new_a_without_mechanism(Qualifier::Pass));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Fail));
        assert_eq!(spf.as_spf(), Some("v=spf1 a -all".to_string()));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Pass));
        assert_eq!(spf.as_spf(), Some("v=spf1 a all".to_string()));
    }
    #[test]
    fn make_a_with_mx_all() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.is_v1(), true);
        spf.append_mechanism_of_a(Mechanism::new_a_without_mechanism(Qualifier::Pass));
        spf.append_mechanism_of_mx(Mechanism::new_mx_without_mechanism(Qualifier::Pass));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Fail));
        assert_eq!(spf.as_spf(), Some("v=spf1 a mx -all".to_string()));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Pass));
        assert_eq!(spf.as_spf(), Some("v=spf1 a mx all".to_string()));
    }
    #[test]
    fn make_a_with_mx_with_value_all() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.is_v1(), true);
        spf.append_mechanism_of_a(Mechanism::new_a_without_mechanism(Qualifier::Pass));
        spf.append_mechanism_of_mx(Mechanism::new_mx_with_mechanism(
            Qualifier::Pass,
            "test.com".to_string(),
        ));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Fail));
        assert_eq!(spf.as_spf(), Some("v=spf1 a mx:test.com -all".to_string()));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Pass));
        assert_eq!(spf.as_spf(), Some("v=spf1 a mx:test.com all".to_string()));
    }
    #[test]
    fn make_a_with_mx_with_value_x2_all() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.is_v1(), true);
        spf.append_mechanism_of_a(Mechanism::new_a_without_mechanism(Qualifier::Pass));
        spf.append_mechanism_of_mx(Mechanism::new_mx_with_mechanism(
            Qualifier::Pass,
            "test.com".to_string(),
        ));
        spf.append_mechanism_of_mx(Mechanism::new_mx_with_mechanism(
            Qualifier::Pass,
            "example.com".to_string(),
        ));
        spf.append_mechanism_of_all(Mechanism::new_all(Qualifier::Pass));
        assert_eq!(
            spf.as_spf(),
            Some("v=spf1 a mx:test.com mx:example.com all".to_string())
        );
    }
}
