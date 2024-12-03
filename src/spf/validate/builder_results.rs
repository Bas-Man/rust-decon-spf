use crate::{SpfBuilder, SpfError};

#[allow(dead_code)]
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
