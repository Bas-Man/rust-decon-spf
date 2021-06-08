#[cfg(test)]
mod construct {

    use crate::spf::Spf;

    #[test]
    fn make_v1() {
        let mut spf = Spf::new();
        spf.set_v1();
        assert_eq!(spf.version, "v=spf1");
        assert_eq!(spf.version(), "v=spf1");
        assert_eq!(spf.is_v1(), true);
    }
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
