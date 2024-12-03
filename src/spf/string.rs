use crate::mechanism::{Kind, Mechanism};
use crate::spf::errors::SpfErrors;
use crate::spf::validate::{self, check_whitespaces, Validate};
use crate::{Spf, SpfError};
use ipnetwork::IpNetwork;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

impl Display for Spf<String> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !&self.source.is_empty() {
            write!(f, "{}", self.source)
        } else {
            let mut spf_string = String::new();
            spf_string.push_str(self.version().as_str());
            for m in self.iter() {
                spf_string.push_str(format!(" {}", m).as_str());
            }
            write!(f, "{}", spf_string)
        }
    }
}

/// Implement parse for `Spf<String>`
/// # Errors
/// - Invalid Version
/// - String length exceeds 512 octets (characters)
///
/// # Soft Errors
/// These will be found when calling `validate()` on `Spf<String>`
impl FromStr for Spf<String> {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;

        // Index of Redirect Mechanism
        let mut redirect_idx: usize = 0;
        // Index of All Mechanism
        let mut all_idx = 0;
        let mut idx = 0;
        let mut spf = Spf::default();
        let mechanisms = s.split_whitespace();
        for m in mechanisms {
            if m.contains(crate::core::SPF1) {
                spf.version = m.to_string();
            } else if m.contains(crate::core::IP4) || m.contains(crate::core::IP6) {
                let m_ip = m.parse::<Mechanism<IpNetwork>>()?;
                spf.mechanisms.push(m_ip.into());
            } else {
                let m_str = m.parse::<Mechanism<String>>()?;
                match *m_str.kind() {
                    Kind::Redirect => {
                        if !spf.has_redirect {
                            spf.has_redirect = true;
                            redirect_idx = idx;
                        } else {
                            return Err(SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
                        }
                    }
                    Kind::All => all_idx = idx,
                    _ => {}
                }
                spf.mechanisms.push(m_str);
                idx += 1;
            }
        }
        spf.source = s.to_string();
        spf.redirect_idx = redirect_idx;
        spf.all_idx = all_idx;
        Ok(spf)
    }
}

impl TryFrom<&str> for Spf<String> {
    type Error = SpfError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Spf::from_str(s)
    }
}

impl Spf<String> {
    /// Creates a `Spf<String>` from the passed str reference.
    /// This is basically a rapper around FromStr which has been implemented for `Spf<String>`
    #[allow(dead_code)]
    pub fn new(s: &str) -> Result<Self, SpfError> {
        s.parse::<Spf<String>>()
    }

    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains(crate::core::SPF1)
    }
    /// Give access to the redirect modifier if present
    pub fn redirect(&self) -> Option<&Mechanism<String>> {
        if self.redirect_idx == 0 {
            match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::Redirect => self.mechanisms.first(),
                _ => None,
            }
        } else {
            Some(&self.mechanisms[self.redirect_idx])
        }
    }
    /// Give access to the `all` mechanism if it is present.
    pub fn all(&self) -> Option<&Mechanism<String>> {
        if self.all_idx == 0 {
            match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::All => self.mechanisms.first(),
                _ => None,
            }
        } else {
            Some(&self.mechanisms[self.all_idx])
        }
    }

    /// Validation for `Spf<String>`
    /// # Examples
    /// ```rust
    /// use decon_spf::{Spf, SpfError, SpfErrors};
    /// let spf = "v=spf1 -all".parse::<Spf<String>>().unwrap();
    /// assert!(spf.validate().is_ok());
    /// let spf = "v=spf1 redirect=_spf.example.com -all".parse::<Spf<String>>().unwrap();
    /// assert!(spf.validate().is_err());
    /// assert_eq!(spf.validate().unwrap_err().errors()[0], SpfError::RedirectWithAllMechanism);
    /// ```
    /// # Returns
    /// Either Ok or a `Vec<SpfError>`
    /// # Errors: [SpfError]
    /// - Hard Errors
    ///     - [Invalid version](SpfError::InvalidVersion)
    ///     - [Source Length Exceeded](SpfError::SourceLengthExceeded)
    /// - Soft Errors
    ///     - [Deprecated PTR detected](SpfError::DeprecatedPtrDetected)
    ///     - [Lookup Count Exceeded](SpfError::LookupLimitExceeded)
    ///     - [Redirect & All](SpfError::RedirectWithAllMechanism)
    ///     - [Redirect Position](SpfError::RedirectNotFinalMechanism)
    pub fn validate(&self) -> Result<(), SpfErrors> {
        let mut errors = SpfErrors::new();

        // Handle hard errors that stop further validation
        for check in [self.validate_version(), self.validate_length()] {
            if let Err(e) = check {
                errors.register_source(self.source.clone());
                errors.register_error(e);
                return Err(errors);
            }
        }

        // Handle soft errors that allow continued validation
        let soft_checks = [
            self.validate_ptr(),
            self.validate_lookup_count(),
            self.validate_redirect_all(),
            // todo: Consider changing this to be part of Trait Validate??
            check_whitespaces(&self.source),
        ];

        for check in soft_checks {
            if let Err(e) = check {
                errors.register_error(e);
            }
        }
        // Return errors if any occurred
        if errors.errors().is_empty() {
            Ok(())
        } else {
            errors.register_source(self.source.clone());
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Spf;

    #[cfg(feature = "ptr")]
    use crate::SpfError;
    #[test]
    fn basic_disallow() {
        let spf = "v=spf1 -all".parse::<Spf<String>>().unwrap();
        assert!(!spf.source.is_empty());
        assert_eq!(spf.redirect(), None);
        assert_eq!(spf.has_redirect, false);
        assert_eq!(spf.all_idx, 0);
        assert_eq!(spf.all().unwrap().to_string(), "-all");
        let validation_result = spf.validate();
        assert!(validation_result.is_ok());
    }
    #[test]
    #[cfg(not(feature = "ptr"))]
    fn ptr_allowed_() {
        let spf = "v=spf1 ptr -all".parse::<Spf<String>>().unwrap();
        assert!(!spf.source.is_empty());
        assert_eq!(spf.redirect(), None);
        assert_eq!(spf.has_redirect, false);
        assert_eq!(spf.all_idx, 1);
        let validation_result = spf.validate();
        assert!(validation_result.is_ok());
    }
    #[test]
    #[cfg(feature = "ptr")]
    fn ptr_not_allowed_() {
        let spf = "v=spf1 ptr -all".parse::<Spf<String>>().unwrap();
        assert!(!spf.source.is_empty());
        assert_eq!(spf.redirect(), None);
        assert_eq!(spf.has_redirect, false);
        assert_eq!(spf.all_idx, 1);
        let validation_result_vec = spf.validate();
        assert!(validation_result_vec.is_err());
        let result = validation_result_vec.unwrap_err();
        assert_eq!(result.errors()[0], SpfError::DeprecatedPtrDetected);
    }

    mod hard_errors {
        use crate::mechanism::Kind;
        use crate::{Spf, SpfError};

        #[test]
        #[cfg(feature = "ptr")]
        fn multiple_redirects() {
            let spf = "v=spf1 redirect=_spf.example.com redirect=_spf.example.com"
                .parse::<Spf<String>>()
                .unwrap_err();
            assert_eq!(spf, SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
        }
    }
    mod soft_errors {
        use crate::{Spf, SpfError};

        #[test]
        #[cfg(feature = "ptr")]
        fn redirect_with_all() {
            let spf = "v=spf1 redirect=_spf.example.com -all"
                .parse::<Spf<String>>()
                .unwrap()
                .validate();

            assert_eq!(
                spf.unwrap_err().errors()[0],
                SpfError::RedirectWithAllMechanism
            );
        }
        #[test]
        #[cfg(feature = "ptr")]
        fn all_with_redirect() {
            let spf = "v=spf1 -all redirect=_spf.example.com"
                .parse::<Spf<String>>()
                .unwrap()
                .validate();
            assert_eq!(
                spf.unwrap_err().errors()[0],
                SpfError::RedirectWithAllMechanism
            );
        }

        #[cfg(feature = "strict-dns")]
        mod strict_dns {
            use crate::mechanism::MechanismError;
            use crate::{Spf, SpfError};

            #[test]
            fn test() {
                let spf = "v=spf1 redirect=_spf.example.xx -all"
                    .parse::<Spf<String>>()
                    .unwrap_err();
                assert!(matches!(
                    spf,
                    SpfError::InvalidMechanism(MechanismError::InvalidDomainHost(_))
                ))
            }
        }
    }
}
