use crate::core;
use crate::mechanism::Kind;
use crate::spf::validate::Validate;
use crate::{Spf, SpfError};

impl Validate for Spf<String> {
    /// Validate that the version is one that is of a known type.
    fn validate_version(&self) -> Result<(), SpfError> {
        if self.version.starts_with(crate::core::SPF1)
            || self.version.starts_with(crate::core::SPF2_PRA)
            || self.version.starts_with(crate::core::SPF2_MFROM)
            || self.version.starts_with(crate::core::SPF2_PRA_MFROM)
            || self.version.starts_with(crate::core::SPF2_MFROM_PRA)
        {
            Ok(())
        } else {
            Err(SpfError::InvalidVersion)
        }
    }

    /// Check that Spf length does not exceed 512 bytes.
    /// if this length is exceeded DNS packet may fail.
    fn validate_length(&self) -> Result<(), SpfError> {
        if self.source.len() > crate::core::MAX_SPF_STRING_LENGTH {
            return Err(SpfError::SourceLengthExceeded);
        };
        Ok(())
    }

    /// Check for the existence of a `ptr` mechanism.
    ///  Results:
    ///     Ok If 'ptr' is not present.
    ///     SpfError::DeprecatedPtrPresent if present.
    /// A 'ptr' should generally not be used according to RFC...
    #[cfg(feature = "ptr")]
    fn validate_ptr(&self) -> Result<(), SpfError> {
        for m in self.iter() {
            if m.kind() == &Kind::Ptr {
                return Err(SpfError::DeprecatedPtrDetected);
            }
        }
        Ok(())
    }

    fn validate_redirect_all(&self) -> Result<(), SpfError> {
        if self.all_idx == self.redirect_idx {
            return Ok(());
        } else if self.all().is_some() && self.has_redirect {
            return Err(SpfError::RedirectWithAllMechanism);
        } else if (self.redirect_idx != self.len() - 1) && self.has_redirect {
            return Err(SpfError::RedirectNotFinalMechanism);
        }
        Ok(())
    }

    /// Check that the number of looks up does not exceed the limit: 10
    fn validate_lookup_count(&self) -> Result<(), SpfError> {
        let mut count: usize = 0;
        for m in self.iter() {
            match m.kind() {
                Kind::A | Kind::MX | Kind::Redirect | Kind::Include | Kind::Exists => count += 1,
                _ => {}
            }
        }
        if count < core::DNS_LOOKUP_LIMIT {
            Ok(())
        } else {
            Err(SpfError::LookupLimitExceeded)
        }
    }
}
