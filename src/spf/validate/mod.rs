#[cfg(feature = "builder")]
#[cfg(test)]
mod tests;

use crate::core::{self, spf_check_whitespace};
use crate::spf::{SpfBuilder, SpfError};

#[allow(dead_code)]
pub enum SpfRfcStandard {
    Rfc4408,
    // Add Rfc7208. I think this should be changed to a struct and then make traits
}

#[derive(Debug)]
pub enum SpfValidationResult<'a> {
    Valid(&'a SpfBuilder),
    InValid(SpfError),
}

impl<'a> std::fmt::Display for SpfValidationResult<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfValidationResult::Valid(obj) => write!(f, "{}", obj),
            SpfValidationResult::InValid(obj) => write!(f, "{}", obj),
        }
    }
}

/// Checks that the spf record has the minimum start string of "v=spf1" or
/// "spf2.0"
/// Returns Ok() or and [`InvalidSource`](SpfError::InvalidSource)
pub(crate) fn check_start_of_spf(spf_string: &str) -> Result<(), SpfError> {
    if spf_string.starts_with(core::VSPF1)
        || spf_string.starts_with(core::SPF2_PRA)
        || spf_string.starts_with(core::SPF2_MFROM)
        || spf_string.starts_with(core::SPF2_PRA_MFROM)
        || spf_string.starts_with(core::SPF2_MFROM_PRA)
    {
        Ok(())
    } else {
        Err(SpfError::InvalidSource)
    }
}

#[test]
fn valid_versions() {
    let input = vec![
        "v=spf1",
        "spf2.0/pra",
        "spf2.0/mfrom",
        "spf2.0/pra,mfrom",
        "spf2.0/mfrom,pra",
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
pub(crate) fn check_ptr(spf: &SpfBuilder) -> Result<(), SpfError> {
    if spf.ptr.is_some() {
        Err(SpfError::DeprecatedPtrPresent)
    } else {
        Ok(())
    }
}

/// Redirect should be the only mechanism present. Any additional values are not permitted.
/// This is wrong need to re-read rfc
pub(crate) fn check_redirect_all(spf: &SpfBuilder) -> Result<(), SpfError> {
    if spf.redirect().is_some() && spf.all().is_some() {
        return Err(SpfError::RedirectWithAllMechanism);
    }
    Ok(())
}

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
