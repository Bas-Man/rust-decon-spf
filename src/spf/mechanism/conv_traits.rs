use crate::mechanism::builder::All;
use crate::mechanism::{Kind, Mechanism, MechanismError};
use ipnetwork::IpNetwork;
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

impl TryFrom<Mechanism<String>> for Mechanism<IpNetwork> {
    type Error = MechanismError;
    fn try_from(value: Mechanism<String>) -> Result<Self, Self::Error> {
        match value.kind {
            Kind::IpV4 | Kind::IpV6 => Ok(Mechanism::ip(
                value.qualifier,
                value.rrdata.expect("Missing RRData").parse::<IpNetwork>()?,
            )),
            _ => Err(MechanismError::InvalidMechanismFormat(value.to_string())),
        }
    }
}

#[cfg(test)]
mod string_ip_conversion {
    use crate::mechanism::Kind::{IpV4, A};
    use crate::mechanism::Qualifier::Pass;
    use crate::mechanism::*;
    use std::convert::TryInto;
    #[test]
    fn ip_to_string_mechanism() {
        let s = "ip4:192.168.0.1".parse::<Mechanism<IpNetwork>>().unwrap();
        let m = Mechanism::<IpNetwork>::ip(Qualifier::Pass, "192.168.0.1".parse().unwrap());
        assert_eq!(s, m);
        let s2: Mechanism<String> = s.into();
        assert_eq!("ip4:192.168.0.1", s2.to_string());
    }
    #[test]
    fn ip_to_string() {
        let s: Mechanism<String> =
            Mechanism::generic_inclusive(IpV4, Pass, Some("192.168.0.1".to_string()));
        let ip: Mechanism<IpNetwork> = s.try_into().expect("Expected string to be ip4/6:");
        assert_eq!(
            ip,
            Mechanism::<IpNetwork>::ip(Pass, "192.168.0.1".parse::<IpNetwork>().unwrap())
        );
    }
    #[test]
    fn ip_to_string_fail() {
        let s: Mechanism<String> =
            Mechanism::generic_inclusive(A, Pass, Some("host.example.com".to_string()));
        let res: Result<Mechanism<IpNetwork>, MechanismError> = s.try_into();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            MechanismError::InvalidMechanismFormat("a:host.example.com".to_string())
        );
    }
}

impl From<Mechanism<IpNetwork>> for Mechanism<String> {
    fn from(value: Mechanism<IpNetwork>) -> Self {
        Mechanism::generic_inclusive(
            *value.kind(),
            value.qualifier,
            Some(Mechanism::sanitize_ip_addr(
                value.rr_data().as_ref().expect("Not IpNetwork"),
            )),
        )
    }
}
