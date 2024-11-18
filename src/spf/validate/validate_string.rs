use crate::mechanism::Kind;
use crate::spf::validate::Validate;
use crate::{Spf, SpfError};

impl Validate for Spf<String> {
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

    fn validate_length(&self) -> Result<(), SpfError> {
        if self.source.len() > crate::core::MAX_SPF_STRING_LENGTH {
            return Err(SpfError::SourceLengthExceeded);
        };
        Ok(())
    }

    #[cfg(feature = "ptr")]
    fn validate_ptr(&self) -> Result<(), SpfError> {
        for m in self.iter() {
            if m.kind() == &Kind::Ptr {
                return Err(SpfError::DeprecatedPtrPresent);
            }
        }
        Ok(())
    }

    fn validate_redirect_all(&self) -> Result<(), SpfError> {
        todo!()
    }

    fn validate_lookup_count(&self) -> Result<(), SpfError> {
        let mut count: u8 = 0;
        for m in self.iter() {
            match m.kind() {
                Kind::A | Kind::MX | Kind::Redirect | Kind::Include | Kind::Exists => count += 1,
                _ => {}
            }
        }
        if count < 10 {
            Ok(())
        } else {
            Err(SpfError::LookupLimitExceeded)
        }
    }
}
