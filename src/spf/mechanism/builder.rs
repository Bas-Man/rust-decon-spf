use crate::mechanism::{Kind, Mechanism, MechanismError, Qualifier};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
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

impl From<Mechanism<All>> for Mechanism<String> {
    fn from(m: Mechanism<All>) -> Self {
        Mechanism::new(*m.kind(), *m.qualifier())
    }
}

impl TryFrom<Mechanism<String>> for Mechanism<All> {
    type Error = MechanismError;

    fn try_from(m: Mechanism<String>) -> Result<Self, Self::Error> {
        match m.kind {
            Kind::All => Ok(Mechanism::all_with_qualifier(m.qualifier)),
            _ => Err(MechanismError::InvalidMechanismFormat(m.to_string())),
        }
    }
}

impl Display for Mechanism<All> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{}all", self.qualifier))
    }
}

#[cfg(test)]
mod into_new_mechanism {
    use crate::mechanism::*;
    #[cfg(feature = "serde")]
    use serde_json;
    #[test]
    fn mech_all_to_all_string() {
        let m = Mechanism::all_default();
        let m_pass = Mechanism::all_with_qualifier(Qualifier::Pass);
        assert_eq!(m_pass.to_string(), "all");
        assert_eq!(m.qualifier, Qualifier::Fail);
        assert_eq!(m.rrdata, None);
        assert_eq!(m.to_string(), "-all");
        let m_str: Mechanism<String> = m.clone().into();
        assert_eq!(m_str.kind, Kind::All);
        assert_eq!(m_str.rrdata, None);
        assert_eq!(m_str.to_string(), "-all");
        #[cfg(feature = "serde")]
        {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(
                json,
                "{\"kind\":\"All\",\"qualifier\":\"Fail\",\"rrdata\":null}"
            );
            let s_json = serde_json::to_string(&m_str).unwrap();
            assert_eq!(json, s_json);
        }
    }
}
