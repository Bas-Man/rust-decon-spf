mod spf1 {
    use crate::spf::builder::Builder;
    use crate::SpfBuilder;

    #[test]
    fn make_v1() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        assert_eq!(spf.version(), "v=spf1");
    }
}

#[cfg(feature = "spf2")]
mod spf2 {
    use crate::{Builder, SpfBuilder};

    #[test]
    fn make_v2_pra() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v2_pra();
        assert_eq!(spf.version(), "spf2.0/pra");
        assert_eq!(spf.is_v2(), true);
        assert_eq!(spf.version(), "spf2.0/pra")
    }

    #[test]
    fn make_v2_mfrom() {
        let mut spf = SpfBuilder::<Builder>::new();
        spf.set_v2_mfrom();
        assert_eq!(spf.version(), "spf2.0/mfrom");
        assert_eq!(spf.is_v2(), true);
    }

    #[test]
    fn make_v2_mfrom_pra() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v2_mfrom_pra();
        assert_eq!(spf.version(), "spf2.0/mfrom,pra");
        assert_eq!(spf.is_v2(), true);
    }

    #[test]
    fn make_v2_pra_mfrom() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v2_pra_mfrom();
        assert_eq!(spf.version(), "spf2.0/pra,mfrom");
        assert_eq!(spf.is_v2(), true);
    }
}

#[allow(deprecated)]
mod build {
    use crate::spf::builder::Builder;
    use crate::spf::mechanism::{Mechanism, Qualifier};
    use crate::SpfBuilder;

    #[test]
    fn make_a_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::a(Qualifier::Pass));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Fail));
        assert_eq!(spf.to_string(), "v=spf1 a -all".to_string());
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
        assert_eq!(spf.to_string(), "v=spf1 a all".to_string());
    }

    #[test]
    fn make_ip4_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/24".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip4:203.32.160.0/24 all".to_string()
        );
    }

    #[test]
    fn make_ip4_x2_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "10.0.0.0/23".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/24".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip4:10.0.0.0/23 ip4:203.32.160.0/24 all".to_string()
        );
    }

    #[test]
    fn make_ip6_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "2001:4860:4000::/36".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip6:2001:4860:4000::/36 all".to_string()
        );
    }

    #[test]
    fn make_ip6_x2_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "2001:4860:4000::/36".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip6:2001:4860:4000::/36 ip6:2001:5160:4000::/36 all".to_string()
        );
    }

    #[test]
    fn make_ip4_by_append_ip_mechanism() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "10.0.0.0/23".parse().unwrap(),
        ));
        assert_eq!(spf.to_string(), "v=spf1 ip4:10.0.0.0/23".to_string());
    }

    #[test]
    fn make_ip4_x2_by_append_ip_mechanism() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "10.0.0.0/23".parse().unwrap(),
        ));
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "203.32.160.0/23".parse().unwrap(),
        ));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip4:10.0.0.0/23 ip4:203.32.160.0/23".to_string()
        );
    }

    #[test]
    fn make_ip6_by_append_ip_mechanism() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.add_ip(Mechanism::ip(
            Qualifier::Pass,
            "2001:5160:4000::/36".parse().unwrap(),
        ));
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip6:2001:5160:4000::/36".to_string()
        );
    }

    #[test]
    fn make_v1_a_mx_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append_mechanism(Mechanism::a(Qualifier::Pass));
        spf.append_mechanism(Mechanism::mx(Qualifier::Pass));
        spf.append_mechanism(Mechanism::all());
        assert_eq!(spf.to_string(), "v=spf1 a mx -all".to_string());
    }

    #[test]
    fn make_v1_ip4_ip6() {
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
        assert_eq!(
            spf.to_string(),
            "v=spf1 ip4:203.32.160.0/23 ip6:2001:5160:4000::/36".to_string()
        );
        let new_spf = spf.clone().build().unwrap();
        assert_eq!(new_spf.to_string(), spf.to_string());
    }
    #[test]
    fn b_to_redirect() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        let mut spf = spf.add_redirect(Mechanism::redirect(Qualifier::Pass, "test.com").unwrap());
        spf.add_mx(Mechanism::mx(Qualifier::Pass));
        let _spf = spf.build();
    }
    #[test]
    fn b_to_all() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        let mut spf = spf.add_all(Mechanism::all());
        spf.add_mx(Mechanism::mx(Qualifier::Pass));
        let _spf = spf.build();
    }
}
