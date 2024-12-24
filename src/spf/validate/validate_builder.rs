use crate::core::{DNS_LOOKUP_LIMIT, MAX_SPF_STRING_LENGTH};
use crate::spf::validate::Validate;
use crate::{SpfBuilder, SpfError};

impl<State> Validate for SpfBuilder<State> {
    fn validate_length(&self) -> Result<(), SpfError> {
        let mut length = 0;
        length += self.version().len();
        for _m in self.iter() {
            length += 1 + _m.raw().len();
        }
        match length > MAX_SPF_STRING_LENGTH {
            true => Err(SpfError::SourceLengthExceeded),
            false => Ok(()),
        }
    }

    #[cfg(feature = "ptr")]
    fn validate_ptr(&self) -> Result<(), SpfError> {
        match self.ptr().is_none() {
            true => Ok(()),
            false => Err(SpfError::DeprecatedPtrDetected),
        }
    }

    fn validate_redirect_all(&self) -> Result<(), SpfError> {
        if self.redirect().is_some() && self.all().is_some() {
            Err(SpfError::RedirectWithAllMechanism)
        } else {
            Ok(())
        }
    }
    fn validate_lookup_count(&self) -> Result<(), SpfError> {
        match self.get_lookup_count() <= DNS_LOOKUP_LIMIT {
            true => Ok(()),
            false => Err(SpfError::LookupLimitExceeded),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "builder")]
mod tests {
    use crate::mechanism::Qualifier;
    use crate::spf::validate::Validate;
    use crate::spf::Mechanism;
    use crate::{Builder, SpfBuilder, SpfError};
    use std::convert::TryInto;

    #[test]
    fn building() {
        let mut spf = SpfBuilder::new_builder();
        let input = ["a", "mx", "-all"];
        for m in input.iter() {
            spf.append_mechanism(m.parse::<Mechanism<String>>().unwrap());
        }
        spf.set_v1();
        assert_eq!(spf.version(), "v=spf1");
        assert!(spf.validate_length().is_ok());

        let mut spf2 = SpfBuilder::new_builder();
        spf2.set_v1().add_a(
            Mechanism::a(Qualifier::Pass)
                .with_rrdata("test.com")
                .unwrap(),
        );
        let spf2 = spf2.add_all(Mechanism::all_default());
        assert_eq!(spf2.to_string(), "v=spf1 a:test.com -all");
    }
    #[test]
    fn test_validate_version() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        assert!(spf.validate_version().is_ok());
    }
    #[test]
    fn test_validate_lookup_count_below_10() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:a.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:b.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:c.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:d.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:e.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:f.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:g.test.com".parse::<Mechanism<String>>().unwrap());
        assert!(matches!(spf.validate_lookup_count(), Ok(_)));
        let spf = spf.build().unwrap();
        assert_eq!(spf.lookup_count(), 9);
        assert_eq!(spf.source, "");
        assert_eq!(
            spf.to_string(),
            String::from("v=spf1 a mx mx:a.test.com mx:b.test.com mx:c.test.com mx:d.test.com mx:e.test.com mx:f.test.com mx:g.test.com")
        );
    }
    #[test]
    fn test_validate_lookup_count_above_10() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("a:test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:a.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:b.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:c.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:d.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:e.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:f.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:g.test.com".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx:h.test.com".parse::<Mechanism<String>>().unwrap());
        assert!(matches!(spf.validate_lookup_count(), Err(_)));
    }
    #[test]
    fn test_length_ok() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        let spf = spf.add_all(
            "-all"
                .parse::<Mechanism<String>>()
                .unwrap()
                .try_into()
                .expect("Should be All"),
        );
        assert_eq!(spf.validate_length(), Ok(()));
    }
    #[test]
    fn test_length_not_ok() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism(
            "a:testaasdfadadadsfaefdasdfadsfaf.dasdfadfadfafasdfadsfadadsfadf.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:sfgsfgsfgsbogusonetest.exsfgsfgsdfgsdgample.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonet235435ersfdgsfgsfest.exa345345wrgsdfgsfsfmple.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:adfalkjadsjflajdladbogusonetest.esfgsjlsjfdlsfgsfgxample.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonetessdfgsfgsdfgsfgsdfgsdfgt.exasfgsfgsfdgsfdgsfgsfgmple.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonetsfgs43sfsfsgs6sdgdest.examsfdgsfgsfsgfdgsfgple.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonetesiadsfadft.adfadsfadexample.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonetest123123132.adfffeasfexample.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism(
            "mx:bogusonetesadfadfwr134wadsft.eadfadfadfasdfasdfasdfaxample.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        let spf = spf.add_all(
            "-all"
                .parse::<Mechanism<String>>()
                .unwrap()
                .try_into()
                .expect("Should be All"),
        );
        assert_eq!(spf.validate_length(), Err(SpfError::SourceLengthExceeded));
    }
    #[test]
    #[cfg(feature = "ptr")]
    fn test_ptr_ok() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        let spf = spf.add_all(
            "-all"
                .parse::<Mechanism<String>>()
                .unwrap()
                .try_into()
                .expect("Should be All"),
        );
        assert_eq!(spf.validate_ptr(), Ok(()));
    }
    #[test]
    #[cfg(feature = "ptr")]
    fn test_ptr_not_ok() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("ptr".parse::<Mechanism<String>>().unwrap());
        let spf = spf.add_all(
            "-all"
                .parse::<Mechanism<String>>()
                .unwrap()
                .try_into()
                .expect("Should be All"),
        );
        assert_eq!(spf.validate_ptr(), Err(SpfError::DeprecatedPtrDetected));
    }
    #[test]
    fn test_redirect_all_ok() {
        let mut spf = SpfBuilder::new_builder();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        let spf = spf.add_all(
            "-all"
                .parse::<Mechanism<String>>()
                .unwrap()
                .try_into()
                .expect("Should be All"),
        );
        assert_eq!(spf.validate_redirect_all(), Ok(()));
    }
    #[test]
    #[ignore]
    // This test will fail with the current implementation.
    // Adding a `All` will quietly fail with the current code when a redirect is already
    // present.
    fn test_redirect_all_not_ok() {
        let mut spf: SpfBuilder<Builder> = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism(
            "redirect=test.example.com"
                .parse::<Mechanism<String>>()
                .unwrap(),
        );
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(
            spf.validate_redirect_all(),
            Err(SpfError::RedirectWithAllMechanism)
        );
    }
}
