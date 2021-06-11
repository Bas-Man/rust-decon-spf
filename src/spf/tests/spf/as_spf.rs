#[cfg(test)]
mod build {

    use crate::spf::Mechanism;
    use crate::spf::Qualifier;
    use crate::spf::Spf;

    #[test]
    fn make_a_all() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.is_v1(), true);
        spf.append_mechanism_of_a(Mechanism::new_a(Qualifier::Pass, String::new()));
        assert_eq!(spf.as_spf(), Some("v=spf1 a".to_string()));
    }
}
