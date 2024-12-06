use crate::mechanism::builder::All;
use crate::mechanism::{Kind, Mechanism, MechanismError};
use std::convert::TryFrom;

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
