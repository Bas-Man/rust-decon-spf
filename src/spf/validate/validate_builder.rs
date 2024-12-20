use crate::core::{DNS_LOOKUP_LIMIT, MAX_SPF_STRING_LENGTH};
use crate::spf::validate::Validate;
use crate::{SpfBuilder, SpfError};

impl Validate for SpfBuilder {
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
    use crate::spf::validate::Validate;
    use crate::spf::Mechanism;
    use crate::{SpfBuilder, SpfError};

    #[test]
    fn test_validate_version() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        assert!(spf.validate_version().is_ok());
    }
    #[test]
    fn test_validate_lookup_count_below_10() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        assert!(matches!(spf.validate_lookup_count(), Ok(_)));
        let spf = spf.build().unwrap();
        assert_eq!(spf.lookup_count(), 9);
        assert_eq!(spf.source, "");
        assert_eq!(
            spf.to_string(),
            String::from("v=spf1 a mx mx mx mx mx mx mx mx")
        );
    }
    #[test]
    fn test_validate_lookup_count_above_10() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        assert!(matches!(spf.validate_lookup_count(), Err(_)));
    }
    #[test]
    fn test_length_ok() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("mx".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(spf.validate_length(), Ok(()));
    }
    #[test]
    fn test_length_not_ok() {
        let mut spf = SpfBuilder::default();
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
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(spf.validate_length(), Err(SpfError::SourceLengthExceeded));
    }
    #[test]
    #[cfg(feature = "ptr")]
    fn test_ptr_ok() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(spf.validate_ptr(), Ok(()));
    }
    #[test]
    #[cfg(feature = "ptr")]
    fn test_ptr_not_ok() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("ptr".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(spf.validate_ptr(), Err(SpfError::DeprecatedPtrDetected));
    }
    #[test]
    fn test_redirect_all_ok() {
        let mut spf = SpfBuilder::default();
        spf.set_v1();
        spf.append_mechanism("a".parse::<Mechanism<String>>().unwrap());
        spf.append_mechanism("-all".parse::<Mechanism<String>>().unwrap());
        assert_eq!(spf.validate_redirect_all(), Ok(()));
    }
    #[test]
    #[ignore]
    // This test will fail with the current implementation.
    // Adding a `All` will quietly fail with the current code when a redirect is already
    // present.
    fn test_redirect_all_not_ok() {
        let mut spf = SpfBuilder::default();
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
