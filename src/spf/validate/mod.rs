#[cfg(feature = "builder")]
pub(crate) mod builder_results;
#[cfg(feature = "builder")]
use crate::SpfBuilder;
#[cfg(test)]
mod tests;
#[cfg(feature = "builder")]
mod validate_builder;
mod validate_string;

use crate::core::{self, spf_check_whitespace};
use crate::spf::SpfError;

pub trait Validate {
    fn validate_version(&self) -> Result<(), SpfError> {
        Ok(())
    }
    fn validate_length(&self) -> Result<(), SpfError>;
    fn validate_ptr(&self) -> Result<(), SpfError> {
        Ok(())
    }
    fn validate_redirect_all(&self) -> Result<(), SpfError>;
    fn validate_lookup_count(&self) -> Result<(), SpfError>;
}

#[allow(dead_code)]
pub enum SpfRfcStandard {
    Rfc4408,
    // Add Rfc7208. I think this should be changed to a struct and then make traits
}

/// Checks that the spf record has the minimum start string of "v=spf1" or
/// "spf2.0"
/// Returns Ok() or and [`InvalidVersion`](SpfError::InvalidVersion)
pub(crate) fn check_start_of_spf(spf_string: &str) -> Result<(), SpfError> {
    if spf_string.starts_with(core::SPF1)
        || spf_string.starts_with(core::SPF2_PRA)
        || spf_string.starts_with(core::SPF2_MFROM)
        || spf_string.starts_with(core::SPF2_PRA_MFROM)
        || spf_string.starts_with(core::SPF2_MFROM_PRA)
    {
        Ok(())
    } else {
        Err(SpfError::InvalidVersion)
    }
}

#[test]
fn valid_versions() {
    let input = vec![
        core::SPF1,
        core::SPF2_PRA,
        core::SPF2_MFROM,
        core::SPF2_PRA_MFROM,
        core::SPF2_MFROM_PRA,
    ];
    for v in input.into_iter() {
        assert_eq!(check_start_of_spf(v), Ok(()))
    }
}

/// Checks for incorrect white spacing.
///
/// Returns Ok() if there are no issues. [`WhiteSpaceSyntaxError`](SpfError::WhiteSpaceSyntaxError) on error.
pub(crate) fn check_whitespaces(spf_string: &str) -> Result<(), SpfError> {
    if spf_check_whitespace(spf_string) {
        return Err(SpfError::WhiteSpaceSyntaxError);
    };
    Ok(())
}

/// Checks that the string length does not exceed SPF Max Length.
///
/// Returns [`SourceLengthExceeded`](SpfError::SourceLengthExceeded) on Error.
pub(crate) fn check_spf_length(spf_string: &str) -> Result<(), SpfError> {
    if spf_string.len() > core::MAX_SPF_STRING_LENGTH {
        return Err(SpfError::SourceLengthExceeded);
    };
    Ok(())
}

#[cfg(feature = "ptr")]
#[cfg(feature = "builder")]
pub(crate) fn check_ptr(spf: &SpfBuilder) -> Result<(), SpfError> {
    match spf.ptr() {
        Some(_) => Err(SpfError::DeprecatedPtrDetected),
        None => Ok(()),
    }
}
#[cfg(feature = "builder")]
/// Redirect should be the only mechanism present. Any additional values are not permitted.
/// This is wrong need to re-read rfc
pub(crate) fn check_redirect_all(spf: &SpfBuilder) -> Result<(), SpfError> {
    if spf.redirect().is_some() && spf.all().is_some() {
        return Err(SpfError::RedirectWithAllMechanism);
    }
    Ok(())
}

#[cfg(feature = "builder")]
pub(crate) fn check_lookup_count(spf: &SpfBuilder) -> usize {
    let mut lookup_count: usize = 0;

    if spf.redirect().is_some() {
        lookup_count += 1;
    }
    if let Some(a) = spf.a() {
        lookup_count += a.len();
    }
    if let Some(mx) = spf.mx() {
        lookup_count += mx.len();
    }
    if let Some(includes) = spf.includes() {
        lookup_count += includes.len();
    }
    lookup_count
}

#[cfg(feature = "builder")]
#[allow(dead_code)]
pub(crate) fn validate_rfc4408(spf: &mut SpfBuilder) -> Result<&SpfBuilder, SpfError> {
    if spf.is_valid {
        return Ok(spf);
    };
    #[cfg(feature = "ptr")]
    check_ptr(spf)?;
    check_redirect_all(spf)?;
    // Basic check of lookup limit
    if check_lookup_count(spf) > 10 {
        return Err(SpfError::LookupLimitExceeded);
    }
    spf.is_valid = true;
    Ok(spf)
}
