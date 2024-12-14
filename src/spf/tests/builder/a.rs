use crate::mechanism::{Mechanism, Qualifier};
use crate::SpfBuilder;

mod valid {
    use super::*;
    use crate::spf::builder::{Append, Builder};

    #[test]
    fn default() {
        let mut spf = SpfBuilder::new_builder();
        spf.set_v1();
        spf.append_mechanism(Mechanism::a(Qualifier::Pass));
        spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::SoftFail));
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].qualifier().is_pass(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "a");
        assert_eq!(spf.all().unwrap().qualifier().is_softfail(), true);
        assert_eq!(spf.all().unwrap().to_string(), "~all");
        let new_spf = spf.build().unwrap();
        assert_eq!(new_spf.version, "v=spf1");
        assert_eq!(new_spf.mechanisms.len(), 2);
        assert_eq!(new_spf.mechanisms[0].to_string(), "a");
        assert_eq!(new_spf.mechanisms[1].to_string(), "~all");
        assert_eq!(new_spf.all_idx, 1);
    }

    #[test]
    fn mechanism_slash_cidr() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1();
        spf.append(Mechanism::a(Qualifier::Fail).with_rrdata("/24").unwrap());
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].qualifier().is_fail(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "-a/24");
        let new_spf = spf.build().unwrap();
        assert_eq!(new_spf.mechanisms[0].to_string(), "-a/24");
        assert_eq!(new_spf.mechanisms.len(), 1);
    }

    #[test]
    fn mechanism_colon_domain() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.append(
            Mechanism::a(Qualifier::Neutral)
                .with_rrdata("example.com")
                .unwrap(),
        );
        spf.append(Mechanism::all_with_qualifier(Qualifier::SoftFail));
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].qualifier().is_neutral(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "?a:example.com");
        let new_spf = spf.build().unwrap();
        assert_eq!(new_spf.mechanisms[0].to_string(), "?a:example.com");
        assert_eq!(new_spf.mechanisms[1].to_string(), "~all");
        assert_eq!(new_spf.mechanisms.len(), 2);
    }

    #[test]
    fn mechanism_appender() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.append_mechanism(
            Mechanism::a(Qualifier::Neutral)
                .with_rrdata("example.com")
                .unwrap(),
        );
        spf.append(Mechanism::all_with_qualifier(Qualifier::SoftFail));
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].qualifier().is_neutral(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "?a:example.com");
        let new_spf = spf.build().unwrap();
        assert_eq!(new_spf.mechanisms[0].to_string(), "?a:example.com");
        assert_eq!(new_spf.mechanisms[1].to_string(), "~all");
        assert_eq!(new_spf.mechanisms.len(), 2);
    }

    #[test]
    fn mechanism_domain_cidr() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
        spf.set_v1().append_string_mechanism(
            Mechanism::a(Qualifier::SoftFail)
                .with_rrdata("example.com/24")
                .unwrap(),
        );
        assert!(spf.a().is_some());
        assert_eq!(spf.a().unwrap()[0].qualifier().is_softfail(), true);
        assert_eq!(spf.a().unwrap()[0].to_string(), "~a:example.com/24");
        let new_spf = spf.build().unwrap();
        assert_eq!(new_spf.mechanisms[0].to_string(), "~a:example.com/24");
        assert_eq!(new_spf.mechanisms.len(), 1);
        dbg!(&new_spf);
    }
}
