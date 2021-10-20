mod tests;
use crate::helpers;
use crate::spf::{Spf, SpfError};
#[allow(dead_code)]
pub enum SpfRfcStandard {
    Rfc4408,
}

#[derive(Debug)]
pub enum SpfValidationResult<'a> {
    Valid(&'a Spf),
    InValid(SpfError),
}

impl<'a> std::fmt::Display for SpfValidationResult<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfValidationResult::Valid(obj) => write!(f, "{}", obj.to_string()),
            SpfValidationResult::InValid(obj) => write!(f, "{}", obj.to_string()),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn check_start_of_spf(spf_string: &str) -> Result<(), SpfError> {
    if !spf_string.starts_with("v=spf1") && !spf_string.starts_with("spf2.0") {
        return Err(SpfError::InvalidSource);
    };
    Ok(())
}

pub(crate) fn check_lookup_count(spf: &Spf) -> usize {
    let mut lookup_count: usize = 0;

    if spf.redirect().is_some() {
        lookup_count += 1;
    }
    if spf.a().is_some() {
        lookup_count += spf.a().unwrap().len();
    }
    if spf.mx().is_some() {
        lookup_count += spf.mx().unwrap().len();
    }
    if spf.includes().is_some() {
        lookup_count += spf.includes().unwrap().len();
    }
    lookup_count
}

#[allow(dead_code)]
pub(crate) fn validate_rfc4408(spf: &mut Spf) -> Result<&Spf, SpfError> {
    if spf.from_src && spf.was_parsed {
        return Ok(spf);
    };
    if spf.from_src {
        if spf.source.len() > 255 {
            return Err(SpfError::SourceLengthExceeded);
        };
        if !helpers::spf_has_consecutive_whitespace(&spf.to_string()) {
            return Err(SpfError::WhiteSpaceSyntaxError);
        }
    } else {
        if !spf.is_v1() && !spf.is_v2() {
            return Err(SpfError::InvalidSource);
        }
        // Rediect should be the only mechanism present. Any additional values are not permitted.
        // This is wrong need to re-read rfc
        if spf.redirect().is_some() && spf.all().is_some() {
            return Err(SpfError::RedirectWithAllMechanism);
        }
        // Basic check of lookup limit
        if check_lookup_count(&spf) > 10 {
            return Err(SpfError::LookupLimitExceeded);
        }
    }
    spf.was_validated = true;
    spf.is_valid = true;
    Ok(spf)
}
