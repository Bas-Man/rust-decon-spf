use crate::mechanism::{Kind, Mechanism, Qualifier};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct All;

/// The Default `Mechanism<All>` is set to have a `Qualifier` of `Fail`
impl Default for Mechanism<All> {
    fn default() -> Self {
        Self {
            kind: Kind::All,
            qualifier: Qualifier::Fail,
            rrdata: None,
        }
    }
}

impl Mechanism<All> {
    /// Create a `Mechanism<All>` with default `Qualifier` of `Fail`
    pub fn all_default() -> Self {
        Self::default()
    }
    /// Create a `Mechanism<All>` with a custom`Qualifier`
    pub fn all_with_qualifier(qualifier: Qualifier) -> Self {
        Self {
            kind: Kind::All,
            qualifier,
            rrdata: None,
        }
    }
    /// Return the mechanism stored. In this case it will be `all` as there is no rr_data
    ///  for this form of mechanism
    pub fn raw(&self) -> String {
        self.kind().to_string()
    }
}

impl Display for Mechanism<All> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{}all", self.qualifier))
    }
}
